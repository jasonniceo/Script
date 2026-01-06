#!/bin/bash
# 证书自动续期管理脚本
# 功能：自动检查证书有效期，在到期前30天自动续期，并重启面板服务和Nginx
# 作者：自动生成脚本
# 版本：v2.1
# 使用方法：可配置cron定时任务，或手动执行 ./renew_cert.sh

#######################################
# 颜色定义
#######################################
RED='\033[0;31m'      # 错误消息
GREEN='\033[0;32m'    # 成功消息和主标题颜色
YELLOW='\033[1;33m'   # 警告消息
BLUE='\033[0;34m'     # 信息消息
NC='\033[0m'          # 重置颜色

#######################################
# 配置部分
#######################################

# 默认配置
DEFAULT_DOMAIN=""                           # 设为空，让脚本自动检测域名
DEFAULT_RENEW_THRESHOLD=30                  # 默认续期阈值：30天
FORCE_RENEW=false                           # 是否强制续期（设为true可立即续期）
DEFAULT_TARGET_CERT="/root/cert.crt"       # 目标证书路径
DEFAULT_TARGET_KEY="/root/private.key"     # 目标私钥路径
ACME_HOME="/root/.acme.sh"                 # acme.sh安装目录

# 面板服务名称配置
XUI_SERVICE_NAME="x-ui"                    # X-UI面板服务名
SUI_SERVICE_NAME="s-ui"                    # S-UI面板服务名
NGINX_SERVICE_NAME="nginx"                 # Nginx服务名

#######################################
# 函数：显示脚本头部信息
#######################################
show_header() {
    echo -e "${GREEN}===================================================${NC}"
    echo -e "${GREEN}            证书管理脚本启动${NC}"
    echo -e "${GREEN}===================================================${NC}"
    echo -e "当前时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "主机名: $(hostname)"
    echo -e "IP地址: $(curl -s ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo '未知')"
}

#######################################
# 函数：显示交互式菜单（仅手动运行时显示）
#######################################
show_interactive_menu() {
    echo -e "\n${GREEN}[选择运行模式]${NC}"
    echo -e "1. 自动模式（推荐用于定时任务）"
    echo -e "2. 强制续期模式（忽略有效期检查）"
    echo -e "3. 仅检查证书状态（不执行续期）"
    echo -en "${YELLOW}请选择运行模式（默认1，直接回车使用自动模式）: ${NC}"
    
    read -r choice
    case $choice in
        2)
            FORCE_RENEW=true
            echo -e "${YELLOW}已选择强制续期模式${NC}"
            ;;
        3)
            echo -e "${YELLOW}仅检查证书状态，不执行续期操作${NC}"
            CHECK_ONLY=true
            ;;
        *)
            echo -e "使用默认自动模式"
            ;;
    esac
}

#######################################
# 函数：自动发现acme.sh中的域名
#######################################
auto_discover_domain() {
    echo -e "${GREEN}[开始自动发现域名]${NC}"
    
    # 方法1：查找acme.sh目录下的域名目录
    local domains=()
    
    # 查找所有可能的域名目录（通常以_ecc结尾）
    for domain_dir in "$ACME_HOME"/*_ecc/; do
        if [ -d "$domain_dir" ]; then
            # 提取域名（去掉路径和_ecc后缀）
            local domain=$(basename "$domain_dir" | sed 's/_ecc$//')
            if [ -n "$domain" ]; then
                domains+=("$domain")
                echo -e "  发现域名: ${YELLOW}$domain${NC}"
            fi
        fi
    done
    
    # 方法2：查找acme.sh配置中的域名
    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}警告：未找到域名目录，尝试从acme.sh配置中查找${NC}"
        if [ -f "$ACME_HOME/account.conf" ]; then
            # 尝试从最近的证书颁发记录中提取域名
            local recent_domain=$(grep -r "DOMAIN=" "$ACME_HOME"/*.conf 2>/dev/null | head -1 | cut -d'=' -f2)
            if [ -n "$recent_domain" ]; then
                domains+=("$recent_domain")
                echo -e "  从配置发现域名: ${YELLOW}$recent_domain${NC}"
            fi
        fi
    fi
    
    # 判断结果
    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${RED}错误：未找到任何证书域名${NC}"
        echo -e "请确保："
        echo -e "  1. acme.sh已正确安装"
        echo -e "  2. 已通过acme.sh申请过证书"
        echo -e "  3. 证书存放在 $ACME_HOME/ 目录下"
        return 1
    elif [ ${#domains[@]} -gt 1 ]; then
        echo -e "${YELLOW}警告：发现多个域名，将使用第一个域名: ${domains[0]}${NC}"
        echo -e "找到的域名列表: ${domains[*]}"
        echo -e "如需使用其他域名，请修改脚本或手动指定"
        DOMAIN="${domains[0]}"
    else
        DOMAIN="${domains[0]}"
        echo -e "${GREEN}自动发现域名: ${YELLOW}$DOMAIN${NC}"
    fi
    
    return 0
}

#######################################
# 函数：检查证书文件路径
#######################################
check_cert_paths() {
    echo -e "${GREEN}[检查证书路径]${NC}"
    
    # 设置证书文件路径
    ECC_CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
    ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
    ACME_KEY_FILE="$ECC_CERT_DIR/$DOMAIN.key"
    
    echo -e "  ACME证书目录: $ECC_CERT_DIR"
    echo -e "  源证书文件: $ACME_CERT_FILE"
    echo -e "  源私钥文件: $ACME_KEY_FILE"
    
    # 检查源证书文件是否存在
    if [ ! -f "$ACME_CERT_FILE" ]; then
        echo -e "${RED}错误：找不到源证书文件${NC}"
        echo -e "请检查路径: $ACME_CERT_FILE"
        return 1
    fi
    
    if [ ! -f "$ACME_KEY_FILE" ]; then
        echo -e "${RED}错误：找不到源私钥文件${NC}"
        echo -e "请检查路径: $ACME_KEY_FILE"
        return 1
    fi
    
    echo -e "${GREEN}证书文件路径检查通过${NC}"
    return 0
}

#######################################
# 函数：时间格式转换（将证书原始时间转为YYYY-MM-DD HH:MM:SS）
#######################################
convert_cert_time() {
    local raw_time="$1"
    # 处理证书时间格式（如：Dec 12 03:45:34 2025 GMT）
    local converted_time=$(date -d "$raw_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    if [ -z "$converted_time" ]; then
        echo "无法解析时间"
    else
        echo "$converted_time"
    fi
}

#######################################
# 函数：显示当前证书状态
#######################################
show_cert_status() {
    echo -e "\n${GREEN}[当前证书状态]${NC}"
    # 检查证书和私钥是否存在
    if [ -f "$ACME_CERT_FILE" ]; then
        cert_status="${GREEN}证书文件存在${NC}"
    else
        cert_status="${RED}证书文件不存在${NC}"
    fi
    if [ -f "$ACME_KEY_FILE" ]; then
        key_status="${GREEN}私钥文件存在${NC}"
    else
        key_status="${RED}私钥文件不存在${NC}"
    fi

    # 补充变量赋值：文件大小和最后修改时间
    cert_real_size=$(du -h "$ACME_CERT_FILE" 2>/dev/null | cut -f1)
    key_real_size=$(du -h "$ACME_KEY_FILE" 2>/dev/null | cut -f1)
    cert_mtime=$(date -r "$ACME_CERT_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    key_mtime=$(date -r "$ACME_KEY_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    
    # 输出状态
    echo -e "目标证书文件状态: $cert_status"
    echo -e "目标私钥文件状态: $key_status"
    echo -e "文件详情:"
    echo -e "  证书文件: $DEFAULT_TARGET_CERT"
    echo -e "  私钥文件: $DEFAULT_TARGET_KEY"
    echo -e "  文件大小: $cert_real_size (证书), $key_real_size (私钥)"
    echo -e "  最后修改: $cert_mtime (证书), $key_mtime (私钥)"
    echo -e "文件权限:"
    # 动态输出真实文件权限，并重命名展示路径
    ls -la "$ACME_CERT_FILE" "$ACME_KEY_FILE" 2>/dev/null | awk '{print $1, $3, $4, $5, $6, $7, $8, $9}' | sed "s|$ECC_CERT_DIR/fullchain.cer|$DEFAULT_TARGET_CERT|g; s|$ECC_CERT_DIR/$DOMAIN.key|$DEFAULT_TARGET_KEY|g"

    echo -e "\n${GREEN}[证书有效期]${NC}"
    # 解析并格式化证书有效期
    local cert_dates=$(openssl x509 -in "$DEFAULT_TARGET_CERT" -noout -dates 2>/dev/null)
    if [ -n "$cert_dates" ]; then
        # 提取notBefore和notAfter并转换格式
        local not_before_raw=$(echo "$cert_dates" | grep "notBefore" | cut -d= -f2)
        local not_after_raw=$(echo "$cert_dates" | grep "notAfter" | cut -d= -f2)
        local not_before=$(convert_cert_time "$not_before_raw")
        local not_after=$(convert_cert_time "$not_after_raw")
        echo -e "  生效时间: ${YELLOW}${not_before}${NC}"
        echo -e "  到期时间: ${YELLOW}${not_after}${NC}"
    else
        echo -e "${RED}无法读取证书信息${NC}"
    fi
}

#######################################
# 函数：检查证书有效期
#######################################
check_cert_expiry() {
    local cert_file="$1"
    local threshold="$2"
    
    # 检查证书文件是否存在
    if [ ! -f "$cert_file" ]; then
        echo -e "${RED}错误：证书文件不存在${NC}"
        return 2
    fi
    
    # 检查openssl命令是否存在
    if ! command -v openssl &>/dev/null; then
        echo -e "${RED}错误：系统未安装openssl，无法解析证书有效期${NC}"
        return 2
    fi
    
    # 获取证书到期时间
    local end_date_raw=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
    if [ -z "$end_date_raw" ]; then
        echo -e "${RED}错误：无法获取证书到期时间${NC}"
        return 2
    fi
    
    # 转换为标准时间格式
    local end_date=$(convert_cert_time "$end_date_raw")
    if [ -z "$end_date" ] || [ "$end_date" = "无法解析时间" ]; then
        echo -e "${RED}错误：无法解析证书日期: $end_date_raw${NC}"
        return 2
    fi
    
    # 转换为时间戳
    local end_ts=$(date -d "$end_date" +%s 2>/dev/null)
    local now_ts=$(date +%s)
    
    # 计算剩余天数
    local remain_days=$(( (end_ts - now_ts) / 86400 ))
    
    echo -e "证书到期时间: ${YELLOW}$end_date${NC}"
    echo -e "剩余天数: ${YELLOW}$remain_days 天${NC}"
    echo -e "续期阈值: ${YELLOW}$threshold 天${NC}"
    
    # 判断是否需要续期
    if [ $remain_days -le $threshold ]; then
        echo -e "${YELLOW}证书需要续期（剩余 ≤ $threshold 天）${NC}"
        return 0  # 需要续期
    else
        echo -e "${GREEN}证书有效期充足${NC}"
        return 1  # 不需要续期
    fi
}

#######################################
# 函数：执行证书续期
#######################################
renew_certificate() {
    echo -e "\n${GREEN}[开始续期证书]${NC}"
    echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    
    # 执行acme.sh续期命令
    local renew_cmd="$ACME_HOME/acme.sh --renew -d $DOMAIN"
    if [ "$FORCE_RENEW" = true ]; then
        renew_cmd="$renew_cmd --force"
        echo -e "${YELLOW}强制续期模式已启用${NC}"
    fi
    
    echo -e "执行命令: $renew_cmd"
    
    if eval "$renew_cmd"; then
        echo -e "${GREEN}证书续期成功${NC}"
        return 0
    else
        echo -e "${RED}证书续期失败${NC}"
        return 1
    fi
}

#######################################
# 函数：复制证书文件
#######################################
copy_certificate_files() {
    echo -e "\n${GREEN}[复制证书文件]${NC}"
    
    # 检查源文件
    if [ ! -f "$ACME_CERT_FILE" ] || [ ! -f "$ACME_KEY_FILE" ]; then
        echo -e "${RED}错误：源证书文件不存在${NC}"
        echo -e "证书文件: $ACME_CERT_FILE"
        echo -e "私钥文件: $ACME_KEY_FILE"
        return 1
    fi
    
    # 备份旧证书（如果存在）
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        local backup_dir="/root/cert_backup/$(date '+%Y-%m-%d_%H-%M-%S')"
        mkdir -p "$backup_dir"
        cp "$DEFAULT_TARGET_CERT" "$backup_dir/cert.crt.backup"
        cp "$DEFAULT_TARGET_KEY" "$backup_dir/private.key.backup"
        echo -e "旧证书已备份到: $backup_dir"
    fi
    
    # 复制证书文件
    echo -e "复制证书文件..."
    echo -e "  从: $ACME_CERT_FILE"
    echo -e "  到: $DEFAULT_TARGET_CERT"
    cp -f "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"
    
    echo -e "复制私钥文件..."
    echo -e "  从: $ACME_KEY_FILE"
    echo -e "  到: $DEFAULT_TARGET_KEY"
    cp -f "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY"
    
    # 设置文件权限
    echo -e "设置文件权限..."
    chmod 644 "$DEFAULT_TARGET_CERT"  # 证书：所有人可读
    chmod 600 "$DEFAULT_TARGET_KEY"   # 私钥：仅所有者可读写
    
    # 验证复制结果
    if [ -f "$DEFAULT_TARGET_CERT" ] && [ -f "$DEFAULT_TARGET_KEY" ]; then
        echo -e "${GREEN}证书文件复制完成${NC}"
        echo -e "文件权限:"
        ls -la "$DEFAULT_TARGET_KEY" "$DEFAULT_TARGET_CERT"
        return 0
    else
        echo -e "${RED}错误：证书文件复制失败${NC}"
        return 1
    fi
}

#######################################
# 函数：重启面板服务
#######################################
restart_panel_services() {
    echo -e "\n${GREEN}[重启面板服务]${NC}"
    echo -e "注意：重启服务以确保使用最新证书"
    
    local services_restarted=0
    
    # 重启X-UI面板
    echo -e "\n--- 检查X-UI面板 ---"
    if systemctl is-active --quiet "$XUI_SERVICE_NAME" 2>/dev/null; then
        echo -e "X-UI服务状态: ${GREEN}运行中${NC}"
        echo -e "重启X-UI服务..."
        if systemctl restart "$XUI_SERVICE_NAME"; then
            echo -e "X-UI服务重启: ${GREEN}成功${NC}"
            ((services_restarted++))
            
            # 检查重启后状态
            sleep 2
            if systemctl is-active --quiet "$XUI_SERVICE_NAME"; then
                echo -e "X-UI服务状态: ${GREEN}运行正常${NC}"
            else
                echo -e "${YELLOW}警告：X-UI服务未运行${NC}"
            fi
        else
            echo -e "X-UI服务重启: ${RED}失败${NC}"
        fi
    else
        echo -e "X-UI服务状态: ${YELLOW}未运行${NC}"
        
        # 尝试常见服务名
        local xui_services=("x-ui" "3x-ui" "xray")
        for service in "${xui_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo -e "发现X-UI服务: $service"
                if systemctl restart "$service"; then
                    echo -e "$service 重启: ${GREEN}成功${NC}"
                    ((services_restarted++))
                fi
                break
            fi
        done
    fi
    
    # 重启S-UI面板
    echo -e "\n--- 检查S-UI面板 ---"
    if systemctl is-active --quiet "$SUI_SERVICE_NAME" 2>/dev/null; then
        echo -e "S-UI服务状态: ${GREEN}运行中${NC}"
        echo -e "重启S-UI服务..."
        if systemctl restart "$SUI_SERVICE_NAME"; then
            echo -e "S-UI服务重启: ${GREEN}成功${NC}"
            ((services_restarted++))
            
            # 检查重启后状态
            sleep 2
            if systemctl is-active --quiet "$SUI_SERVICE_NAME"; then
                echo -e "S-UI服务状态: ${GREEN}运行正常${NC}"
            else
                echo -e "${YELLOW}警告：S-UI服务未运行${NC}"
            fi
        else
            echo -e "S-UI服务重启: ${RED}失败${NC}"
        fi
    else
        echo -e "S-UI服务状态: ${YELLOW}未运行${NC}"
        
        # 尝试常见服务名
        local sui_services=("s-ui" "sui" "sing-box")
        for service in "${sui_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo -e "发现S-UI服务: $service"
                if systemctl restart "$service"; then
                    echo -e "$service 重启: ${GREEN}成功${NC}"
                    ((services_restarted++))
                fi
                break
            fi
        done
    fi
    
    # 重启Nginx服务
    echo -e "\n--- 检查Nginx服务 ---"
    if systemctl is-active --quiet "$NGINX_SERVICE_NAME" 2>/dev/null; then
        echo -e "Nginx服务状态: ${GREEN}运行中${NC}"
        echo -e "重启Nginx服务..."
        if systemctl restart "$NGINX_SERVICE_NAME"; then
            echo -e "Nginx服务重启: ${GREEN}成功${NC}"
            ((services_restarted++))
            
            # 检查重启后状态
            sleep 2
            if systemctl is-active --quiet "$NGINX_SERVICE_NAME"; then
                echo -e "Nginx服务状态: ${GREEN}运行正常${NC}"
            else
                echo -e "${YELLOW}警告：Nginx服务未运行${NC}"
            fi
        else
            echo -e "Nginx服务重启: ${RED}失败${NC}"
        fi
    else
        echo -e "Nginx服务状态: ${YELLOW}未运行${NC}"
        
        # 尝试平滑重启（不中断服务）
        if command -v nginx &>/dev/null; then
            echo -e "尝试Nginx平滑重启..."
            if nginx -s reload 2>/dev/null; then
                echo -e "Nginx平滑重启: ${GREEN}成功${NC}"
                ((services_restarted++))
            else
                echo -e "Nginx平滑重启: ${YELLOW}失败${NC}"
            fi
        else
            echo -e "Nginx未安装或未配置systemd服务"
        fi
    fi
    
    if [ $services_restarted -eq 0 ]; then
        echo -e "\n${YELLOW}未找到需要重启的面板服务${NC}"
        echo -e "如果面板正在运行，请检查："
        echo -e "  1. 服务名称是否正确（当前配置：X-UI=$XUI_SERVICE_NAME, S-UI=$SUI_SERVICE_NAME, Nginx=$NGINX_SERVICE_NAME）"
        echo -e "  2. 手动重启命令参考："
        echo -e "     systemctl restart x-ui"
        echo -e "     systemctl restart s-ui"
        echo -e "     systemctl restart nginx"
    else
        echo -e "\n${GREEN}已重启 $services_restarted 个服务${NC}"
    fi
}

#######################################
# 函数：主执行流程
#######################################
main() {
    # 检查openssl命令是否存在（全局前置检查）
    if ! command -v openssl &>/dev/null; then
        echo -e "${RED}错误：系统未安装openssl，脚本无法正常运行${NC}"
        echo -e "请先安装openssl：yum install openssl -y 或 apt install openssl -y"
        exit 1
    fi

    # 显示脚本头部
    show_header
    
    # 检查是否是终端交互式运行（非cron）
    if [ -t 1 ] && [ "$IS_CRON" != "true" ]; then
        # 显示交互式菜单
        show_interactive_menu
        
        # 如果选择仅检查模式，显示状态后退出
        if [ "$CHECK_ONLY" = true ]; then
            # 检查是否手动指定了域名
            if [ -n "$DEFAULT_DOMAIN" ]; then
                echo -e "${GREEN}[使用手动指定的域名]${NC}"
                DOMAIN="$DEFAULT_DOMAIN"
                echo -e "域名: ${YELLOW}$DOMAIN${NC}"
            else
                # 自动发现域名
                if ! auto_discover_domain; then
                    echo -e "${RED}无法自动发现域名，请手动配置${NC}"
                    exit 1
                fi
            fi
            
            echo -e "\n${GREEN}[配置信息]${NC}"
            echo -e "域名: ${YELLOW}$DOMAIN${NC}"
            echo -e "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
            
            # 检查证书路径
            if ! check_cert_paths; then
                exit 1
            fi
            
            # 显示当前证书状态
            show_cert_status
            
            echo -e "\n${GREEN}仅检查模式完成${NC}"
            exit 0
        fi
    fi
    
    # 检查是否手动指定了域名
    if [ -n "$DEFAULT_DOMAIN" ]; then
        echo -e "${GREEN}[使用手动指定的域名]${NC}"
        DOMAIN="$DEFAULT_DOMAIN"
        echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    else
        # 自动发现域名
        if ! auto_discover_domain; then
            echo -e "${RED}无法自动发现域名，请手动配置${NC}"
            exit 1
        fi
    fi
    
    echo -e "\n${GREEN}[配置信息]${NC}"
    echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    echo -e "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
    echo -e "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
    echo -e "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
    echo -e "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
    echo -e "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
    echo -e "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
    
    # 检查证书路径
    if ! check_cert_paths; then
        exit 1
    fi
    
    # 显示当前证书状态
    show_cert_status
    
    # 检查是否需要续期
    local need_renewal=false
    
    # 检查目标证书
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        echo -e "\n${GREEN}[检查目标证书有效期]${NC}"
        if [ "$FORCE_RENEW" = true ]; then
            echo -e "${YELLOW}强制续期模式：跳过有效期检查，直接执行续期${NC}"
            need_renewal=true
        elif check_cert_expiry "$DEFAULT_TARGET_CERT" "$RENEW_THRESHOLD"; then
            need_renewal=true
        fi
    else
        echo -e "\n${YELLOW}目标证书不存在，将进行首次复制${NC}"
        need_renewal=true
    fi
    
    # 执行续期逻辑
    if $need_renewal; then
        echo -e "\n${YELLOW}[执行证书续期]${NC}"
        
        # 执行续期
        if renew_certificate; then
            echo -e "${GREEN}证书续期成功${NC}"
        else
            echo -e "${YELLOW}证书续期失败，尝试使用现有证书${NC}"
        fi
        
        # 复制证书文件
        if copy_certificate_files; then
            echo -e "${GREEN}证书文件复制成功${NC}"
            
            # 重启面板服务
            restart_panel_services
        else
            echo -e "${RED}证书文件复制失败${NC}"
            exit 1
        fi
    else
        echo -e "\n${GREEN}[无需续期]${NC}"
        echo -e "证书有效期充足，跳过续期流程"
        
        # 检查证书是否需要同步（acme.sh可能有更新）
        if [ -f "$ACME_CERT_FILE" ] && [ -f "$DEFAULT_TARGET_CERT" ]; then
            local acme_time=$(stat -c %Y "$ACME_CERT_FILE" 2>/dev/null || echo 0)
            local target_time=$(stat -c %Y "$DEFAULT_TARGET_CERT" 2>/dev/null || echo 0)
            
            if [ $acme_time -gt $target_time ]; then
                echo -e "${YELLOW}检测到acme.sh证书已更新，同步到目标位置${NC}"
                if copy_certificate_files; then
                    restart_panel_services
                fi
            fi
        fi
    fi
    
    echo -e "\n${GREEN}===================================================${NC}"
    echo -e "${GREEN}            脚本执行完成${NC}"
    echo -e "${GREEN}===================================================${NC}"
    echo -e "完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "域名: $DOMAIN"
    echo -e "证书位置: $DEFAULT_TARGET_CERT"
    echo -e "私钥位置: $DEFAULT_TARGET_KEY"
}

#######################################
# 脚本入口
#######################################

# 设置变量
DOMAIN=""
RENEW_THRESHOLD="$DEFAULT_RENEW_THRESHOLD"  # 统一变量，确保生效
TARGET_CERT="$DEFAULT_TARGET_CERT"
TARGET_KEY="$DEFAULT_TARGET_KEY"
CHECK_ONLY=false

# 执行主函数
main
