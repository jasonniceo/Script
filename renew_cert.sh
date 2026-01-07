#!/bin/bash
# 证书自动续期管理脚本
# 功能：自动检查证书有效期，在到期前30天自动续期，并重启面板服务和Nginx
# 作者：自动生成脚本
# 版本：v2.1
# 使用方法：可配置cron定时任务，或手动执行 ./renew_cert.sh
# 排序规则：基础定义层 → 功能函数（按main调用顺序）→ main主函数 → 执行入口
# 日志说明：关键操作输出终端，核心流程自动记录时间戳，便于问题排查

#######################################
# 【基础定义层】颜色定义（标准化终端输出）
#######################################
# 基础字体颜色（统一输出风格，便于日志识别）
RED='\033[0;31m'      # 错误/失败/异常（日志中易识别）
GREEN='\033[0;32m'    # 成功/完成/主标题（核心流程标记）
YELLOW='\033[1;33m'   # 警告/提示/待确认（需关注的非错误信息）
NC='\033[0m'          # 颜色重置（避免终端颜色污染）

#######################################
# 【基础定义层】配置变量（可修改的核心参数）
#######################################
DEFAULT_DOMAIN=""                           # 手动指定域名（留空自动检测）
DEFAULT_RENEW_THRESHOLD=30                  # 续期阈值（剩余≤30天触发续期）
FORCE_RENEW=false                           # 强制续期开关（true=忽略有效期直接续期）
DEFAULT_TARGET_CERT="/root/cert.crt"        # 目标证书最终存放路径
DEFAULT_TARGET_KEY="/root/private.key"      # 目标私钥最终存放路径
ACME_HOME="/root/.acme.sh"                  # acme.sh安装根目录

# 面板服务名称配置（适配不同环境的服务名）
XUI_SERVICE_NAME="x-ui"                     # X-UI面板服务名
SUI_SERVICE_NAME="s-ui"                     # S-UI面板服务名
NGINX_SERVICE_NAME="nginx"                  # Nginx服务名

#######################################
# 【基础定义层】运行时变量（脚本内部使用，无需手动修改）
#######################################
DOMAIN=""                                   # 最终使用的域名（自动/手动赋值）
RENEW_THRESHOLD="$DEFAULT_RENEW_THRESHOLD"  # 续期阈值（同步默认配置）
TARGET_CERT="$DEFAULT_TARGET_CERT"          # 目标证书路径（同步默认配置）
TARGET_KEY="$DEFAULT_TARGET_KEY"            # 目标私钥路径（同步默认配置）
CHECK_ONLY=false                            # 仅检查模式开关
remain_days=0                               # 证书剩余有效天数（全局变量）
# 新增全局变量：解决证书时间在汇总时无法显示的问题
not_before=""                               # 证书生效时间（全局）
not_after=""                                # 证书到期时间（全局）
cert_real_size=""                           # 证书文件大小（全局）
key_real_size=""                            # 私钥文件大小（全局）
cert_mtime=""                               # 证书最后修改时间（全局）
key_mtime=""                                # 私钥最后修改时间（全局）

# 日志相关（修改：日志路径改为root下的renew_cert_logs文件夹，按日期分割）
LOG_DIR="./renew_cert_logs"             # 日志存储目录（root下的renew_cert_logs）
LOG_FILE="${LOG_DIR}/renew_cert_$(date +%Y-%m-%d).log" # 按日期分割日志
mkdir -p "$LOG_DIR"                         # 确保日志目录存在

#######################################
# 【功能函数】按main调用顺序排列 - 1. 显示脚本头部信息
#######################################
show_header() {
    # 输出脚本启动信息，同时写入日志
    local header_info="===================================================
            证书管理脚本启动
===================================================
当前时间: $(date '+%Y-%m-%d %H:%M:%S')
主机名: $(hostname)
IPv4地址: $(hostname -I 2>/dev/null | awk '{print $1}' || echo '未知')
IPv6地址: $(hostname -I 2>/dev/null | awk '{print $2}' || curl -s ifconfig.me 2>/dev/null || echo '未知')"
    
    # 终端彩色输出
    echo -e "${GREEN}${header_info}${NC}"
    # 写入日志（去除颜色符）
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 脚本启动\n${header_info}" >> "$LOG_FILE"
}

#######################################
# 【功能函数】按main调用顺序排列 - 2. 显示交互式菜单
#######################################
show_interactive_menu() {
    # 交互式选择运行模式，仅在终端执行时显示
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
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 选择强制续期模式" >> "$LOG_FILE"
            ;;
        3)
            CHECK_ONLY=true
            echo -e "${YELLOW}仅检查证书状态，不执行续期操作${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 选择仅检查模式" >> "$LOG_FILE"
            ;;
        *)
            echo -e "使用默认自动模式"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 选择默认自动模式" >> "$LOG_FILE"
            ;;
    esac
}

#######################################
# 【功能函数】按main调用顺序排列 - 3. 自动发现acme.sh中的域名
#######################################
auto_discover_domain() {
    echo -e "\n${GREEN}[开始自动发现域名]${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始自动发现域名" >> "$LOG_FILE"
    
    local domains=()
    
    # 优先查找ecc域名目录
    for domain_dir in "$ACME_HOME"/*_ecc/; do
        if [ -d "$domain_dir" ]; then
            local domain=$(basename "$domain_dir" | sed 's/_ecc$//')
            if [ -n "$domain" ]; then
                domains+=("$domain")
                echo -e "  发现域名: ${YELLOW}$domain${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 发现ECC域名：$domain" >> "$LOG_FILE"
            fi
        fi
    done
    
    # 备用：从配置文件查找域名
    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}警告：未找到域名目录，尝试从acme.sh配置中查找${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] 未找到ECC域名目录，尝试从配置查找" >> "$LOG_FILE"
        
        if [ -f "$ACME_HOME/account.conf" ]; then
            local recent_domain=$(grep -r "DOMAIN=" "$ACME_HOME"/*.conf 2>/dev/null | head -1 | cut -d'=' -f2)
            if [ -n "$recent_domain" ]; then
                domains+=("$recent_domain")
                echo -e "  从配置发现域名: ${YELLOW}$recent_domain${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 从配置发现域名：$recent_domain" >> "$LOG_FILE"
            fi
        fi
    fi
    
    # 结果判断
    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${RED}错误：未找到任何证书域名${NC}"
        echo -e "请确保："
        echo -e "  1. acme.sh已正确安装"
        echo -e "  2. 已通过acme.sh申请过证书"
        echo -e "  3. 证书存放在 $ACME_HOME/ 目录下"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 未找到任何证书域名" >> "$LOG_FILE"
        return 1
    elif [ ${#domains[@]} -gt 1 ]; then
        echo -e "${YELLOW}警告：发现多个域名，将使用第一个域名: ${domains[0]}${NC}"
        echo -e "找到的域名列表: ${domains[*]}"
        echo -e "如需使用其他域名，请修改脚本或手动指定"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] 发现多个域名，使用第一个：${domains[0]}" >> "$LOG_FILE"
        DOMAIN="${domains[0]}"
    else
        DOMAIN="${domains[0]}"
        echo -e "${GREEN}自动发现域名: ${YELLOW}$DOMAIN${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 自动发现域名：$DOMAIN" >> "$LOG_FILE"
    fi
    
    return 0
}

#######################################
# 【功能函数】按main调用顺序排列 - 4. 检查证书文件路径
#######################################
check_cert_paths() {
    echo -e "\n${GREEN}[检查证书路径]${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始检查证书路径" >> "$LOG_FILE"
    
    ECC_CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
    ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
    ACME_KEY_FILE="$ECC_CERT_DIR/$DOMAIN.key"
    
    echo -e "  ACME证书目录: $ECC_CERT_DIR"
    echo -e "  源证书文件: $ACME_CERT_FILE"
    echo -e "  源私钥文件: $ACME_KEY_FILE"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 检查路径：证书=$ACME_CERT_FILE，私钥=$ACME_KEY_FILE" >> "$LOG_FILE"
    
    if [ ! -f "$ACME_CERT_FILE" ]; then
        echo -e "${RED}错误：找不到源证书文件${NC}"
        echo -e "请检查路径: $ACME_CERT_FILE"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 源证书文件不存在：$ACME_CERT_FILE" >> "$LOG_FILE"
        return 1
    fi
    
    if [ ! -f "$ACME_KEY_FILE" ]; then
        echo -e "${RED}错误：找不到源私钥文件${NC}"
        echo -e "请检查路径: $ACME_KEY_FILE"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 源私钥文件不存在：$ACME_KEY_FILE" >> "$LOG_FILE"
        return 1
    fi
    
    echo -e "${GREEN}证书路径检查通过${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 证书路径检查通过" >> "$LOG_FILE"
    return 0
}

#######################################
# 【功能函数】辅助函数（被show_cert_status/check_cert_expiry调用）- 时间格式转换
#######################################
convert_cert_time() {
    # 转换openssl输出的时间格式为标准化格式
    local raw_time="$1"
    local converted_time=$(date -d "$raw_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    if [ -z "$converted_time" ]; then
        echo "无法解析时间"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] 无法解析时间：$raw_time" >> "$LOG_FILE"
    else
        echo "$converted_time"
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 5. 显示当前证书状态
#######################################
show_cert_status() {
    echo -e "\n${GREEN}[当前证书状态]${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始显示证书状态" >> "$LOG_FILE"
    
    # 检查文件存在性
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

    # 获取文件基础信息（赋值给全局变量）
    cert_real_size=$(du -h "$ACME_CERT_FILE" 2>/dev/null | cut -f1)
    key_real_size=$(du -h "$ACME_KEY_FILE" 2>/dev/null | cut -f1)
    cert_mtime=$(date -r "$ACME_CERT_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    key_mtime=$(date -r "$ACME_KEY_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    
    # 输出状态到终端
    echo -e "目标证书文件状态: $cert_status"
    echo -e "目标私钥文件状态: $key_status"
    echo -e "文件详情:"
    echo -e "  证书文件: $DEFAULT_TARGET_CERT"
    echo -e "  私钥文件: $DEFAULT_TARGET_KEY"
    echo -e "  文件大小: $cert_real_size (证书), $key_real_size (私钥)"
    echo -e "  最后修改: $cert_mtime (证书), $key_mtime (私钥)"
    echo -e "文件权限:"
    ls -la "$ACME_CERT_FILE" "$ACME_KEY_FILE" 2>/dev/null | awk '{print $1, $3, $4, $5, $6, $7, $8, $9}' | sed "s|$ECC_CERT_DIR/fullchain.cer|$DEFAULT_TARGET_CERT|g; s|$ECC_CERT_DIR/$DOMAIN.key|$DEFAULT_TARGET_KEY|g"

    # 输出状态到日志（去除颜色符）
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 证书状态：$cert_status，私钥状态：$key_status" >> "$LOG_FILE"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 文件详情：证书=$DEFAULT_TARGET_CERT（大小=$cert_real_size，修改时间=$cert_mtime），私钥=$DEFAULT_TARGET_KEY（大小=$key_real_size，修改时间=$key_mtime）" >> "$LOG_FILE"

    # 证书有效期解析（赋值给全局变量）
    echo -e "\n${GREEN}[证书有效期]${NC}"
    local cert_dates=$(openssl x509 -in "$DEFAULT_TARGET_CERT" -noout -dates 2>/dev/null)
    if [ -n "$cert_dates" ]; then
        local not_before_raw=$(echo "$cert_dates" | grep "notBefore" | cut -d= -f2)
        local not_after_raw=$(echo "$cert_dates" | grep "notAfter" | cut -d= -f2)
        not_before=$(convert_cert_time "$not_before_raw")
        not_after=$(convert_cert_time "$not_after_raw")
    else
        not_before="无法获取"
        not_after="无法获取"
    fi
    
    # 计算剩余天数
    local end_ts=$(date -d "$not_after" +%s 2>/dev/null)
    local now_ts=$(date +%s)
    remain_days=$(( (end_ts - now_ts) / 86400 ))
    
    # 输出有效期到终端
    echo -e "生效时间: ${YELLOW}$not_before${NC}"
    echo -e "到期时间: ${YELLOW}$not_after${NC}"
    echo -e "剩余天数: ${YELLOW}$remain_days 天${NC}"
    
    # 输出有效期到日志
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 证书有效期：生效=$not_before，到期=$not_after，剩余=$remain_days天" >> "$LOG_FILE"
}

#######################################
# 【功能函数】按main调用顺序排列 - 6. 检查证书有效期
#######################################
check_cert_expiry() {
    local cert_file="$1"
    local threshold="$2"
    
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 检查证书有效期：文件=$cert_file，阈值=$threshold天" >> "$LOG_FILE"
    
    if [ ! -f "$cert_file" ]; then
        echo -e "${RED}错误：证书文件不存在${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 检查有效期失败：证书文件不存在$cert_file" >> "$LOG_FILE"
        return 2
    fi
    
    if ! command -v openssl &>/dev/null; then
        echo -e "${RED}错误：系统未安装openssl，无法解析证书有效期${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 检查有效期失败：未安装openssl" >> "$LOG_FILE"
        return 2
    fi
    
    local end_date_raw=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
    if [ -z "$end_date_raw" ]; then
        echo -e "${RED}错误：无法获取证书到期时间${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 检查有效期失败：无法获取到期时间" >> "$LOG_FILE"
        return 2
    fi
    
    local end_date=$(convert_cert_time "$end_date_raw")
    if [ -z "$end_date" ] || [ "$end_date" = "无法解析时间" ]; then
        echo -e "${RED}错误：无法解析证书日期: $end_date_raw${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 检查有效期失败：无法解析日期$end_date_raw" >> "$LOG_FILE"
        return 2
    fi
    
    # 计算剩余天数
    local end_ts=$(date -d "$end_date" +%s 2>/dev/null)
    local now_ts=$(date +%s)
    remain_days=$(( (end_ts - now_ts) / 86400 ))
    
    # 输出检查结果到终端
    echo -e "剩余天数: ${YELLOW}$remain_days 天${NC}"
    echo -e "续期阈值: ${YELLOW}$threshold 天${NC}"
    
    # 判断是否需要续期
    if [ $remain_days -le $threshold ]; then
        echo -e "${YELLOW}证书需要续期（剩余 ≤ $threshold 天）${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 证书需要续期：剩余$remain_days天 ≤ 阈值$threshold天" >> "$LOG_FILE"
        return 0
    else
        echo -e "${GREEN}证书有效期充足${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 证书有效期充足：剩余$remain_days天 > 阈值$threshold天" >> "$LOG_FILE"
        return 1
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 7. 执行证书续期
#######################################
renew_certificate() {
    echo -e "\n${GREEN}[开始续期证书]${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始执行证书续期：域名=$DOMAIN" >> "$LOG_FILE"
    
    echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    
    local renew_cmd="$ACME_HOME/acme.sh --renew -d $DOMAIN"
    if [ "$FORCE_RENEW" = true ]; then
        renew_cmd="$renew_cmd --force"
        echo -e "${YELLOW}强制续期模式已启用${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 启用强制续期模式" >> "$LOG_FILE"
    fi
    
    echo -e "执行命令: $renew_cmd"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 执行续期命令：$renew_cmd" >> "$LOG_FILE"
    
    # 执行续期命令并捕获输出
    local renew_output
    renew_output=$(eval "$renew_cmd" 2>&1)
    echo -e "$renew_output"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 续期命令输出：$renew_output" >> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}证书续期成功${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] 证书续期成功：域名=$DOMAIN" >> "$LOG_FILE"
        return 0
    else
        echo -e "${RED}证书续期失败${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 证书续期失败：域名=$DOMAIN，命令输出=$renew_output" >> "$LOG_FILE"
        return 1
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 8. 复制证书文件
#######################################
copy_certificate_files() {
    echo -e "\n${GREEN}[复制证书文件]${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始复制证书文件" >> "$LOG_FILE"
    
    if [ ! -f "$ACME_CERT_FILE" ] || [ ! -f "$ACME_KEY_FILE" ]; then
        echo -e "${RED}错误：源证书文件不存在${NC}"
        echo -e "证书文件: $ACME_CERT_FILE"
        echo -e "私钥文件: $ACME_KEY_FILE"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 复制证书失败：源文件不存在" >> "$LOG_FILE"
        return 1
    fi
    
    # 备份旧证书
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        local backup_dir="/root/cert_backup/$(date '+%Y-%m-%d_%H-%M-%S')"
        mkdir -p "$backup_dir"
        cp "$DEFAULT_TARGET_CERT" "$backup_dir/cert.crt.backup"
        cp "$DEFAULT_TARGET_KEY" "$backup_dir/private.key.backup"
        echo -e "旧证书已备份到: $backup_dir"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 旧证书备份到：$backup_dir" >> "$LOG_FILE"
    fi
    
    # 复制证书文件到目标路径
    echo -e "复制证书文件..."
    echo -e "  从: $ACME_CERT_FILE"
    echo -e "  到: $DEFAULT_TARGET_CERT"
    cp -f "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 复制证书：$ACME_CERT_FILE → $DEFAULT_TARGET_CERT" >> "$LOG_FILE"
    
    echo -e "复制私钥文件..."
    echo -e "  从: $ACME_KEY_FILE"
    echo -e "  到: $DEFAULT_TARGET_KEY"
    cp -f "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 复制私钥：$ACME_KEY_FILE → $DEFAULT_TARGET_KEY" >> "$LOG_FILE"
    
    # 设置文件权限（安全加固）
    echo -e "设置文件权限..."
    chmod 644 "$DEFAULT_TARGET_CERT"  # 证书可读不可写
    chmod 600 "$DEFAULT_TARGET_KEY"   # 私钥仅所有者可读
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 设置权限：证书644，私钥600" >> "$LOG_FILE"
    
    # 验证复制结果
    if [ -f "$DEFAULT_TARGET_CERT" ] && [ -f "$DEFAULT_TARGET_KEY" ]; then
        echo -e "${GREEN}证书文件复制完成${NC}"
        echo -e "文件权限:"
        ls -la "$DEFAULT_TARGET_KEY" "$DEFAULT_TARGET_CERT"
        echo -e "${GREEN}证书文件复制成功${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] 证书文件复制成功" >> "$LOG_FILE"
        return 0
    else
        echo -e "${RED}错误：证书文件复制失败${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 证书文件复制失败" >> "$LOG_FILE"
        return 1
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 9. 重启面板服务
#######################################
restart_panel_services() {
    echo -e "\n${GREEN}[重启面板服务]${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始重启面板服务" >> "$LOG_FILE"
    echo -e "注意：重启服务以确保使用最新证书"
    
    local services_restarted=0  # 统计成功重启的服务数
    
    # 重启X-UI服务
    echo -e "\n--- 检查X-UI面板 ---"
    if systemctl is-active --quiet "$XUI_SERVICE_NAME" 2>/dev/null; then
        echo -e "X-UI服务状态: ${GREEN}运行中${NC}"
        echo -e "重启X-UI服务..."
        if systemctl restart "$XUI_SERVICE_NAME"; then
            echo -e "X-UI服务重启: ${GREEN}成功${NC}"
            ((services_restarted++))
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] X-UI服务重启成功" >> "$LOG_FILE"
            sleep 2  # 等待服务重启
            if systemctl is-active --quiet "$XUI_SERVICE_NAME"; then
                echo -e "X-UI服务状态: ${GREEN}运行正常${NC}"
            else
                echo -e "${YELLOW}警告：X-UI服务未运行${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] X-UI服务重启后未运行" >> "$LOG_FILE"
            fi
        else
            echo -e "X-UI服务重启: ${RED}失败${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] X-UI服务重启失败" >> "$LOG_FILE"
        fi
    else
        echo -e "X-UI服务状态: ${YELLOW}未运行${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] X-UI服务未运行，尝试兼容名" >> "$LOG_FILE"
        # 兼容不同X-UI服务名
        local xui_services=("x-ui" "3x-ui" "xray")
        for service in "${xui_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo -e "发现X-UI服务: $service"
                if systemctl restart "$service"; then
                    echo -e "$service 重启: ${GREEN}成功${NC}"
                    ((services_restarted++))
                    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $service服务重启成功" >> "$LOG_FILE"
                fi
                break
            fi
        done
    fi
    
    # 重启S-UI服务
    echo -e "\n--- 检查S-UI面板 ---"
    if systemctl is-active --quiet "$SUI_SERVICE_NAME" 2>/dev/null; then
        echo -e "S-UI服务状态: ${GREEN}运行中${NC}"
        echo -e "重启S-UI服务..."
        if systemctl restart "$SUI_SERVICE_NAME"; then
            echo -e "S-UI服务重启: ${GREEN}成功${NC}"
            ((services_restarted++))
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] S-UI服务重启成功" >> "$LOG_FILE"
            sleep 2
            if systemctl is-active --quiet "$SUI_SERVICE_NAME"; then
                echo -e "S-UI服务状态: ${GREEN}运行正常${NC}"
            else
                echo -e "${YELLOW}警告：S-UI服务未运行${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] S-UI服务重启后未运行" >> "$LOG_FILE"
            fi
        else
            echo -e "S-UI服务重启: ${RED}失败${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] S-UI服务重启失败" >> "$LOG_FILE"
        fi
    else
        echo -e "S-UI服务状态: ${YELLOW}未运行${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] S-UI服务未运行，尝试兼容名" >> "$LOG_FILE"
        # 兼容不同S-UI服务名
        local sui_services=("s-ui" "sui" "sing-box")
        for service in "${sui_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo -e "发现S-UI服务: $service"
                if systemctl restart "$service"; then
                    echo -e "$service 重启: ${GREEN}成功${NC}"
                    ((services_restarted++))
                    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $service服务重启成功" >> "$LOG_FILE"
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
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Nginx服务重启成功" >> "$LOG_FILE"
            sleep 2
            if systemctl is-active --quiet "$NGINX_SERVICE_NAME"; then
                echo -e "Nginx服务状态: ${GREEN}运行正常${NC}"
            else
                echo -e "${YELLOW}警告：Nginx服务未运行${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Nginx服务重启后未运行" >> "$LOG_FILE"
            fi
        else
            echo -e "Nginx服务重启: ${RED}失败${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Nginx服务重启失败" >> "$LOG_FILE"
        fi
    else
        echo -e "Nginx服务状态: ${YELLOW}未运行${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Nginx服务未运行，尝试平滑重启" >> "$LOG_FILE"
        if command -v nginx &>/dev/null; then
            echo -e "尝试Nginx平滑重启..."
            if nginx -s reload 2>/dev/null; then
                echo -e "Nginx平滑重启: ${GREEN}成功${NC}"
                ((services_restarted++))
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Nginx平滑重启成功" >> "$LOG_FILE"
            else
                echo -e "Nginx平滑重启: ${RED}失败${NC}"
                echo -e "Nginx未安装或未配置systemd服务"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Nginx平滑重启失败" >> "$LOG_FILE"
            fi
        else
            echo -e "Nginx未安装或未配置systemd服务"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Nginx未安装" >> "$LOG_FILE"
        fi
    fi
    
    # 输出重启结果统计
    if [ $services_restarted -eq 0 ]; then
        echo -e "\n${YELLOW}未找到需要重启的面板服务${NC}"
        echo -e "如果面板正在运行，请检查："
        echo -e "  1. 服务名称是否正确（当前配置：X-UI=$XUI_SERVICE_NAME, S-UI=$SUI_SERVICE_NAME, Nginx=$NGINX_SERVICE_NAME）"
        echo -e "  2. 手动重启命令参考："
        echo -e "     systemctl restart x-ui"
        echo -e "     systemctl restart s-ui"
        echo -e "     systemctl restart nginx"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] 未重启任何服务" >> "$LOG_FILE"
    else
        echo -e "\n${GREEN}已重启 $services_restarted 个服务${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 成功重启$services_restarted个服务" >> "$LOG_FILE"
    fi
}

#######################################
# 【主执行函数】main函数（核心逻辑，按流程调用上述函数）
#######################################
main() {
    # 前置检查：确保openssl已安装
    if ! command -v openssl &>/dev/null; then
        echo -e "${RED}错误：系统未安装openssl，脚本无法正常运行${NC}"
        echo -e "请先安装openssl：yum install openssl -y 或 apt install openssl -y"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] 未安装openssl，脚本退出" >> "$LOG_FILE"
        exit 1
    fi

    # 步骤1：显示脚本头部信息
    show_header
    
    # 步骤2：处理交互式模式（仅终端执行时生效）
    if [ -t 1 ] && [ "$IS_CRON" != "true" ]; then
        show_interactive_menu
        
        # 仅检查模式：执行检查后直接退出
        if [ "$CHECK_ONLY" = true ]; then
            if [ -n "$DEFAULT_DOMAIN" ]; then
                echo -e "${GREEN}[使用手动指定的域名]${NC}"
                DOMAIN="$DEFAULT_DOMAIN"
                echo -e "域名: ${YELLOW}$DOMAIN${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 仅检查模式：使用手动指定域名$DOMAIN" >> "$LOG_FILE"
            else
                if ! auto_discover_domain; then
                    echo -e "${RED}无法自动发现域名，请手动配置${NC}"
                    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 仅检查模式：自动发现域名失败" >> "$LOG_FILE"
                    exit 1
                fi
            fi
            
            # 输出配置信息
            echo -e "\n${GREEN}[配置信息]${NC}"
            echo -e "域名: ${YELLOW}$DOMAIN${NC}"
            echo -e "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
            echo -e "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
            echo -e "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
            echo -e "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
            echo -e "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
            echo -e "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
            echo -e "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 仅检查模式：输出配置信息完成" >> "$LOG_FILE"
            
            # 检查证书路径
            if ! check_cert_paths; then
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 仅检查模式：证书路径检查失败" >> "$LOG_FILE"
                exit 1
            fi
            
            # 显示证书状态
            show_cert_status
            
            echo -e "\n${GREEN}仅检查模式完成${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] 仅检查模式执行完成" >> "$LOG_FILE"
            exit 0
        fi
    fi
    
    # 步骤3：域名发现（自动/手动）
    if [ -n "$DEFAULT_DOMAIN" ]; then
        echo -e "${GREEN}[使用手动指定的域名]${NC}"
        DOMAIN="$DEFAULT_DOMAIN"
        echo -e "域名: ${YELLOW}$DOMAIN${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 使用手动指定域名：$DOMAIN" >> "$LOG_FILE"
    else
        if ! auto_discover_domain; then
            echo -e "${RED}无法自动发现域名，请手动配置${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 自动发现域名失败，脚本退出" >> "$LOG_FILE"
            exit 1
        fi
    fi
    
    # 步骤4：输出配置信息
    echo -e "\n${GREEN}[配置信息]${NC}"
    echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    echo -e "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
    echo -e "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
    echo -e "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
    echo -e "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
    echo -e "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
    echo -e "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 配置信息：域名=$DOMAIN，阈值=$RENEW_THRESHOLD天，强制续期=$FORCE_RENEW" >> "$LOG_FILE"
    
    # 步骤5：检查证书路径
    if ! check_cert_paths; then
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 证书路径检查失败，脚本退出" >> "$LOG_FILE"
        exit 1
    fi
    
    # 步骤6：显示证书状态
    show_cert_status
    
    # 步骤7：判断是否需要续期
    local need_renewal=false
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        if [ "$FORCE_RENEW" = true ]; then
            echo -e "${YELLOW}强制续期模式：跳过有效期检查，直接执行续期${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 强制续期模式，跳过有效期检查" >> "$LOG_FILE"
            need_renewal=true
        elif check_cert_expiry "$DEFAULT_TARGET_CERT" "$RENEW_THRESHOLD"; then
            need_renewal=true
        fi
    else
        echo -e "\n${YELLOW}目标证书不存在，将进行首次复制${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 目标证书不存在，需要首次复制" >> "$LOG_FILE"
        need_renewal=true
    fi
    
    # 步骤8：执行续期/复制/重启流程
    if $need_renewal; then
        echo -e "\n${YELLOW}[执行证书续期]${NC}"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 开始执行续期流程" >> "$LOG_FILE"
        
        if renew_certificate; then
            echo -e "${GREEN}证书续期成功${NC}"
        else
            echo -e "${YELLOW}证书续期失败，尝试使用现有证书${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [WARN] 续期失败，尝试使用现有证书" >> "$LOG_FILE"
        fi
        
        if copy_certificate_files; then
            echo -e "${GREEN}证书文件复制成功${NC}"
            restart_panel_services
        else
            echo -e "${RED}证书文件复制失败${NC}"
            echo -e "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 证书复制失败，脚本退出" >> "$LOG_FILE"
            exit 1
        fi
    else
        # 无需续期：检查是否需要同步最新证书
        echo -e "\n${GREEN}[是否续期]${NC}"
        echo -e "证书有效期充足，无需续期，跳过续期流程"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 证书有效期充足，无需续期" >> "$LOG_FILE"
        
        # 同步检查：acme证书更新但目标证书未更新的情况
        if [ -f "$ACME_CERT_FILE" ] && [ -f "$DEFAULT_TARGET_CERT" ]; then
            local acme_time=$(stat -c %Y "$ACME_CERT_FILE" 2>/dev/null || echo 0)
            local target_time=$(stat -c %Y "$DEFAULT_TARGET_CERT" 2>/dev/null || echo 0)
            if [ $acme_time -gt $target_time ]; then
                echo -e "${YELLOW}检测到acme.sh证书已更新，同步到目标位置${NC}"
                echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ACME证书已更新，同步到目标位置" >> "$LOG_FILE"
                if copy_certificate_files; then
                    restart_panel_services
                fi
            fi
        fi
    fi
    
    # 步骤9：脚本结束汇总
    echo -e "\n${GREEN}===================================================${NC}"
    echo -e "${GREEN}            脚本执行完成${NC}"
    echo -e "${GREEN}===================================================${NC}"
    echo -e "完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "域名: $DOMAIN"
    echo -e "证书位置: $DEFAULT_TARGET_CERT"
    echo -e "私钥位置: $DEFAULT_TARGET_KEY"
}

#######################################
# 【脚本执行入口】最后一行调用main函数
#######################################
main
