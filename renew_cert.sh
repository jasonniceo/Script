#!/bin/bash
# 证书自动续期管理脚本
# 核心功能：自动检查SSL证书有效期，到期前自动续期，复制证书并重启服务
# 版本：v2.5 终极执行顺序版（ECC专用、无乱警告、固定日志路径、防重复运行）
# 使用方法：手动执行./renew_cert.sh或快捷键 b 运行

# ==============================================
# 【第一步】基础定义：颜色代码
# ==============================================
RED='\033[0;31m'    # 红色（错误提示）
GREEN='\033[0;32m'  # 绿色（成功提示）
YELLOW='\033[1;33m' # 黄色（警告提示）
NC='\033[0m'        # 恢复默认颜色

# ==============================================
# 【第二步】核心配置：所有变量统一定义
# ==============================================
# 1. 域名与续期配置
DEFAULT_DOMAIN=""                  # 手动指定域名（留空则自动扫描）
DEFAULT_RENEW_THRESHOLD=30         # 证书剩余30天触发自动续期
FORCE_RENEW=false                  # 是否强制续期（默认关闭）

# 2. 证书路径配置
DEFAULT_TARGET_CERT="/root/cert.crt"  # 证书复制到的目标路径
DEFAULT_TARGET_KEY="/root/private.key" # 私钥复制到的目标路径
ACME_HOME="/root/.acme.sh"         # acme.sh脚本的安装目录

# 3. 服务名称配置
XUI_SERVICE_NAME="x-ui"            # x-ui 面板服务名称
SUI_SERVICE_NAME="s-ui"            # s-ui 面板服务名称
NGINX_SERVICE_NAME="nginx"          # nginx 网页服务名称

# 4. 自动清理配置
LOG_RETENTION_DAYS=30        # 日志保留天数
BACKUP_RETENTION_DAYS=30     # 证书备份保留天数

# 5. 固定目录与日志配置（路径统一管理）
LOG_DIR="/root/renew_cert_logs"                        # 日志存放根目录
LOG_FILE="${LOG_DIR}/renew_cert_$(date +%Y-%m-%d).log" # 按日期生成每日日志文件
BACKUP_DIR="/root/cert_backup"                         # 证书备份存放目录
mkdir -p "$LOG_DIR" "$BACKUP_DIR"                      # 自动创建日志/备份目录

# ==============================================
# 【第三步】脚本内部运行变量
# ==============================================
DOMAIN=""                                   # 最终使用的域名
RENEW_THRESHOLD="$DEFAULT_RENEW_THRESHOLD"  # 续期阈值（继承默认配置）
TARGET_CERT="$DEFAULT_TARGET_CERT"          # 目标证书文件路径（继承默认配置）
TARGET_KEY="$DEFAULT_TARGET_KEY"            # 目标私钥文件路径（继承默认配置）
CHECK_ONLY=false                            # 是否仅检查证书（不执行续期操作）
remain_days=0                               # 证书剩余有效天数
not_before=""                               # 证书生效时间
not_after=""                                # 证书过期时间
IS_CRON=false                               # 是否为定时任务（cron）运行模式
[ ! -t 1 ] && IS_CRON=true                  # 非终端运行时，自动判定为定时任务模式

# 脚本互斥锁（防止定时任务重复运行，导致冲突）
LOCK_FILE="/tmp/renew_cert.lock"

# ==============================================
# 【第四步】基础工具函数（最底层，所有功能依赖）
# 规则：先定义工具，后实现业务
# ==============================================
# 日志输出函数（统一管理所有打印/写入日志）
log_raw() {
    local content="$1"
    local clean_content=$(echo -e "$content" | sed -E 's/\x1B\[[0-9;]*[mG]//g')
    # 定时任务运行时：禁用颜色，避免日志乱码
    if [ "$IS_CRON" = true ]; then
        echo "$content"
    else
        echo -e "$content"
    fi
    # 日志文件：无时间戳、无颜色、纯文本
    echo -e "$clean_content" >> "$LOG_FILE"
}
log_info()  { log_raw "${GREEN}$1${NC}"; }    # 普通信息（绿色）
log_warn()  { log_raw "${YELLOW}$1${NC}"; }   # 警告信息（黄色）
log_error() { log_raw "${RED}$1${NC}"; }      # 错误信息（红色）
log_success(){ log_raw "${GREEN}$1${NC}"; }   # 成功信息（绿色）
log_plain() { log_raw "$1"; }                 # 普通纯文本

# 工具函数：获取文件信息（权限/归属/大小/时间）
get_file_info() {
    local file="$1"
    [ ! -f "$file" ] && return 1  # 文件不存在直接退出
    if command -v stat >/dev/null 2>&1; then
        if stat --version 2>&1 | grep -q GNU; then
            # Linux系统获取文件信息
            local perm=$(stat -c "%A" "$file" 2>/dev/null)
            local user=$(stat -c "%U" "$file" 2>/dev/null)
            local group=$(stat -c "%G" "$file" 2>/dev/null)
            local size=$(stat -c "%s" "$file" 2>/dev/null)
            local datetime=$(stat -c "%y" "$file" 2>/dev/null | cut -d'.' -f1)
        else
            # Mac系统获取文件信息
            local perm=$(stat -f "%Sp" "$file" 2>/dev/null)
            local user=$(stat -f "%Su" "$file" 2>/dev/null)
            local group=$(stat -f "%Sg" "$file" 2>/dev/null)
            local size=$(stat -f "%z" "$file" 2>/dev/null)
            local datetime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$file" 2>/dev/null)
        fi
    else
        return 1
    fi
    echo "$perm|$user|$group|$size|$datetime"
}

# 工具函数：打印对齐的表格（证书详情展示）
print_aligned_table() {
    local table_data="$1"
    if command -v column >/dev/null 2>&1; then
        local formatted_table=$(echo -e "$table_data" | column -t -s $'\t')
    else
        local formatted_table="$table_data"
    fi
    
    local max_line_length=0
    while IFS= read -r line; do
        local len=${#line}
        (( len > max_line_length )) && max_line_length=$len
    done <<< "$formatted_table"
    local separator=$(printf "%0.s-" $(seq 1 $max_line_length))
    log_plain "${YELLOW}$separator${NC}"
    echo "$formatted_table" | while IFS= read -r line; do
        log_plain "$line"
        [[ "$line" == *"权限"* ]] && log_plain "${YELLOW}$separator${NC}"
    done
    log_plain "${YELLOW}$separator${NC}"
}

# 工具函数：重启服务（自动判断服务是否运行，兼容别名）
restart_service() {
    local service_name="$1"
    local service_alias=("${@:2}")
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        log_plain "$service_name 服务状态: ${GREEN}运行中${NC}"
        log_plain "重启 $service_name 服务..."
        if systemctl restart "$service_name"; then
            log_plain "$service_name 服务重启: ${GREEN}成功${NC}"
            local wait_time=0
            while [ $wait_time -lt 10 ]; do
                if systemctl is-active --quiet "$service_name"; then
                    log_plain "$service_name 服务状态: ${GREEN}运行正常${NC}"
                    return 0
                fi
                sleep 1
                ((wait_time++))
            done
            log_warn "警告：$service_name 服务重启后未及时运行，请手动检查"
            return 1
        else
            log_plain "$service_name 服务重启: ${RED}失败${NC}"
            return 1
        fi
    else
        log_plain "$service_name 服务状态: ${YELLOW}未运行${NC}"
        for alias in "${service_alias[@]}"; do
            if systemctl is-active --quiet "$alias" 2>/dev/null; then
                log_plain "发现兼容服务: $alias"
                if systemctl restart "$alias"; then
                    log_plain "$alias 重启: ${GREEN}成功${NC}"
                    return 0
                fi
            fi
        done
    fi
    return 1
}

# 工具函数：计算证书剩余天数
calc_remain_days() {
    local end_date="$1"
    local end_ts=$(date -d "$end_date" +%s 2>/dev/null)  # 过期时间戳
    local now_ts=$(date +%s)                             # 当前时间戳
    local days=$(( (end_ts - now_ts) / 86400 ))          # 计算剩余天数
    echo $(( days < 0 ? 0 : days ))                      # 负数返回0
}

# 工具函数：转换证书时间格式
convert_cert_time() {
    local raw_time="$1"
    local converted_time=$(date -d "$raw_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    [ -z "$converted_time" ] && echo "无法解析时间" && return
    echo "$converted_time"
}

# ==============================================
# 【第五步】核心业务函数（依赖工具函数）
# ==============================================
# 核心功能：禁用acme.sh自动更新（防止乱改证书）
disable_acme_auto() {
    local acme_disable_flag="${ACME_HOME}/.acme_disabled"
    if [ ! -f "$acme_disable_flag" ] && [ -f "${ACME_HOME}/acme.sh" ]; then
        ${ACME_HOME}/acme.sh --disable-auto-upgrade --set-notify 0 --nocron --uninstall-cron >/dev/null 2>&1
        touch "$acme_disable_flag"
        log_info "已禁用acme自动更新/定时任务"
    fi
}

# 核心功能：创建全局快捷键 b（任意目录输入b运行脚本）
setup_shortcut() {
    local script_path
    if command -v readlink >/dev/null 2>&1 && readlink -f "$0" >/dev/null 2>&1; then
        script_path=$(readlink -f "$0")  # 获取脚本绝对路径
    else
        script_path=$(realpath "$0" 2>/dev/null || echo "$0")
    fi
    local link_path="/usr/bin/b"  # 快捷键命令

    if [ ! -e "$link_path" ]; then
        chmod +x "$script_path"    # 给脚本加执行权限
        ln -sf "$script_path" "$link_path"  # 创建软链接
        [ -x "$link_path" ] && log_success "快捷键 'b' 设置成功！(可以直接输入 b 运行)"
    fi
}

# 展示脚本启动头部信息
show_header() {
    local public_ipv4=$(curl -s4m 2 https://api.ipify.org || curl -s4m 2 https://icanhazip.com || curl -s4m 2 https://ifconfig.me || hostname -I | awk '{print $1}')
    local header_info="
===================================================
            证书管理脚本启动
===================================================
当前时间: $(date '+%Y-%m-%d %H:%M:%S')
主机名: $(hostname)
IPv4地址: ${public_ipv4:-未知}
IPv6地址: $(hostname -I 2>/dev/null | awk '{print $2}' || curl -s6m 2 ifconfig.me 2>/dev/null || echo '未知')"
    log_plain "${GREEN}${header_info}${NC}"
    log_info "脚本启动"
}

# 交互式菜单（手动运行时选择功能）
show_interactive_menu() {
    log_plain "\n${GREEN}[选择运行模式]${NC}"
    log_plain "1. 自动模式（推荐用于定时任务）"
    log_plain "2. 强制续期模式（忽略有效期检查）"
    log_plain "3. 仅检查证书状态（不执行续期）"
    log_plain "4. 更新脚本"
    log_plain "5. 退出"
    echo -en "${YELLOW}请选择运行模式（默认1，直接回车使用自动模式）: ${NC}"
    read -r choice
    case $choice in
        2) FORCE_RENEW=true; log_warn "已选择强制续期模式" ;;
        3) CHECK_ONLY=true; log_warn "仅检查证书状态，不执行续期操作" ;;
        4)
            log_plain "\n${GREEN}[更新脚本]${NC}"
            local backup_script="${0}.bak.$(date +%Y%m%d%H%M%S)"
            cp -f "$0" "$backup_script"
            if wget -O "$0" "https://raw.githubusercontent.com/jasmine2501/renew_cert/main/renew_cert.sh" && chmod +x "$0"; then
                log_success "更新完成，请重新运行"
                exit 0
            else
                log_error "更新失败，已恢复原脚本"
                mv -f "$backup_script" "$0"
                exit 1
            fi
            ;;
        5) log_success "已退出脚本"; exit 0 ;;
        *) log_info "使用默认自动模式" ;;
    esac
}

# 核心功能：读取ECC证书域名
auto_discover_domain() {
    log_plain "\n${GREEN}[域名自动识别]${NC}"
    local domains=()
    local acme_dir="${ACME_HOME}"

    # 仅读取_ecc后缀的目录，不扫描文件
    local ecc_dirs=$(ls -1 "${acme_dir}" | grep -v '^$' | grep '_ecc$' 2>/dev/null | head -1)

    if [ -z "$ecc_dirs" ]; then
        log_error "未找到任何ECC证书域名，请先签发证书"
        return 1
    fi

    DOMAIN="${ecc_dirs%_ecc}"  # 去除_ecc后缀，得到纯域名
    log_plain "自动发现域名: ${YELLOW}$DOMAIN${NC}"

    # 拼接ECC证书路径
    ECC_CERT_DIR="${ACME_HOME}/${DOMAIN}_ecc"
    ACME_CERT_FILE="${ECC_CERT_DIR}/fullchain.cer"
    ACME_KEY_FILE="${ECC_CERT_DIR}/${DOMAIN}.key"

    return 0
}

# 检查证书文件是否存在、读取证书有效期
check_cert_paths() {
    log_plain "\n${GREEN}[检查源证书]${NC}"
    ECC_CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
    ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
    ACME_KEY_FILE="$ECC_CERT_DIR/${DOMAIN}.key"
    
    log_plain "ACME证书目录: ${YELLOW}$ECC_CERT_DIR${NC}"
    log_plain "源证书文件: ${YELLOW}$(basename "$ACME_CERT_FILE")${NC}"
    log_plain "源私钥文件: ${YELLOW}$(basename "$ACME_KEY_FILE")${NC}"
    
    local cert_dates=$(openssl x509 -in "$ACME_CERT_FILE" -noout -dates 2>/dev/null)
    if [ -n "$cert_dates" ]; then
        local not_before_raw=$(echo "$cert_dates" | grep "notBefore" | cut -d= -f2)
        local not_after_raw=$(echo "$cert_dates" | grep "notAfter" | cut -d= -f2)
        local not_before=$(convert_cert_time "$not_before_raw")
        local not_after=$(convert_cert_time "$not_after_raw")
        local remain_days=$(calc_remain_days "$not_after")
        log_plain "生效时间: ${YELLOW}$not_before${NC}"
        log_plain "到期时间: ${YELLOW}$not_after${NC}"
        log_plain "剩余天数: ${YELLOW}$remain_days${NC} 天"
    fi

    # 证书/私钥不存在，脚本直接退出
    [ ! -f "$ACME_CERT_FILE" ] && log_error "错误：找不到源证书文件" && exit 1
    [ ! -f "$ACME_KEY_FILE" ] && log_error "错误：找不到源私钥文件" && exit 1
    return 0
}

# 展示证书详情表格
show_cert_status() {
    local cert_dates=$(openssl x509 -in "$ACME_CERT_FILE" -noout -dates 2>/dev/null)
    if [ -n "$cert_dates" ]; then
        local not_before_raw=$(echo "$cert_dates" | grep "notBefore" | cut -d= -f2)
        local not_after_raw=$(echo "$cert_dates" | grep "notAfter" | cut -d= -f2)
        not_before=$(convert_cert_time "$not_before_raw")
        not_after=$(convert_cert_time "$not_after_raw")
    else
        not_before="无法获取"
        not_after="无法获取"
    fi
    remain_days=$(calc_remain_days "$not_after")

    log_plain "\n${GREEN}目标证书详情:${NC}"
    # 新增【到期日期】列表头
    local table_data="权限\t所有者\t用户组\t生效日期\t到期日期\t文件路径"
    
    local cert_info=$(get_file_info "$DEFAULT_TARGET_CERT")
    local c_perm=$(echo "$cert_info" | cut -d'|' -f1)
    local c_user=$(echo "$cert_info" | cut -d'|' -f2)
    local c_group=$(echo "$cert_info" | cut -d'|' -f3)
    # 证书行追加到期日期数据
    table_data+="\n$c_perm\t$c_user\t$c_group\t$not_before\t$not_after\t$DEFAULT_TARGET_CERT"
    
    local key_info=$(get_file_info "$DEFAULT_TARGET_KEY")
    local k_perm=$(echo "$key_info" | cut -d'|' -f1)
    local k_user=$(echo "$key_info" | cut -d'|' -f2)
    local k_group=$(echo "$key_info" | cut -d'|' -f3)
    # 私钥行追加到期日期数据
    table_data+="\n$k_perm\t$k_user\t$k_group\t$not_before\t$not_after\t$DEFAULT_TARGET_KEY"

    print_aligned_table "$table_data"
}

# 检查证书是否需要续期
check_cert_expiry() {
    local cert_file="$1"
    local threshold="$2"
    [ ! -f "$cert_file" ] && log_error "错误：证书文件不存在" && return 2
    [ ! -x "$(command -v openssl)" ] && log_error "错误：系统未安装openssl" && return 2
    
    local end_date_raw=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
    [ -z "$end_date_raw" ] && log_error "错误：无法获取证书到期时间" && return 2
    
    local end_date=$(convert_cert_time "$end_date_raw")
    [ -z "$end_date" ] || [ "$end_date" = "无法解析时间" ] && log_error "错误：无法解析证书日期" && return 2
    
    remain_days=$(calc_remain_days "$end_date")
    if [ $remain_days -le $threshold ]; then
        return 0  # 需要续期
    else
        return 1  # 无需续期
    fi
}

# 核心功能：执行证书续期
renew_certificate() {
    log_plain "\n${GREEN}[开始续期证书]${NC}"
    log_info "开始执行证书续期：域名=$DOMAIN"
    log_plain "域名: ${YELLOW}$DOMAIN${NC}"
    log_plain "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    local renew_cmd="$ACME_HOME/acme.sh --renew -d $DOMAIN --ecc"
    [ "$FORCE_RENEW" = true ] && renew_cmd="$renew_cmd --force" && log_warn "强制续期模式已启用"
    
    log_plain "\n${GREEN}=== 证书续期执行流程 ==="
    log_plain "执行命令: $renew_cmd"
    log_plain "========================================"
    
    # 实时执行并输出acme.sh完整续期流程（关键修改）
    eval "$renew_cmd"
    local renew_code=$?

    log_plain "========================================${NC}"

    # 判断续期结果
    if [ $renew_code -eq 0 ]; then
        log_success "✅ 证书续期成功：域名=$DOMAIN"
        
        # ====================== 展示【新证书】信息 ======================
        log_plain "\n${GREEN}[续期成功 - 新证书信息]${NC}"
        local new_cert_dates=$(openssl x509 -in "$ACME_CERT_FILE" -noout -dates 2>/dev/null)
        if [ -n "$new_cert_dates" ]; then
            local new_not_before=$(convert_cert_time "$(echo "$new_cert_dates" | grep "notBefore" | cut -d= -f2)")
            local new_not_after=$(convert_cert_time "$(echo "$new_cert_dates" | grep "notAfter" | cut -d= -f2)")
            local new_remain_days=$(calc_remain_days "$new_not_after")
            log_plain "新生效时间: ${GREEN}$new_not_before${NC}"
            log_plain "新到期时间: ${GREEN}$new_not_after${NC}"
            log_plain "新剩余天数: ${GREEN}$new_remain_days${NC} 天"
        fi
        return 0
    else
        log_error "❌ 证书续期失败：域名=$DOMAIN"
        log_error "失败原因：acme.sh 续期命令执行错误（检查域名/网络/权限）"
        return 1
    fi
}

# 核心功能：复制新证书到目标路径，自动备份旧证书
copy_certificate_files() {
    log_plain "\n${GREEN}[复制证书文件]${NC}"
    [ ! -f "$ACME_CERT_FILE" ] || [ ! -f "$ACME_KEY_FILE" ] && log_error "错误：源证书文件不存在" && return 1
    
    # 证书无变化，不复制、不备份
    if [ -f "$DEFAULT_TARGET_CERT" ] && [ -f "$DEFAULT_TARGET_KEY" ]; then
        if diff "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT" >/dev/null 2>&1 && diff "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY" >/dev/null 2>&1; then
            log_info "证书文件无变化，无需复制和备份"
            return 0
        fi
        # 备份旧证书
        local backup_dir="${BACKUP_DIR}/$(date '+%Y-%m-%d_%H-%M-%S')"
        mkdir -p "$backup_dir"
        cp "$DEFAULT_TARGET_CERT" "$backup_dir/cert.crt.backup"
        cp "$DEFAULT_TARGET_KEY" "$backup_dir/private.key.backup"
        log_plain "旧证书已备份到: $backup_dir"
    fi
    
    # 复制新证书
    cp -f "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"
    cp -f "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY"
    
    # 设置证书权限（安全标准）
    [ "$(stat -c "%a" "$DEFAULT_TARGET_CERT" 2>/dev/null || echo "0")" != "644" ] && chmod 644 "$DEFAULT_TARGET_CERT"
    [ "$(stat -c "%a" "$DEFAULT_TARGET_KEY" 2>/dev/null || echo "0")" != "600" ] && chmod 600 "$DEFAULT_TARGET_KEY"
    
    log_success "证书文件复制完成"
    ls -la "$DEFAULT_TARGET_KEY" "$DEFAULT_TARGET_CERT"
    return 0
}

# 核心功能：重启面板/nginx服务
restart_panel_services() {
    log_plain "\n${GREEN}[重启面板服务]${NC}"
    local services_restarted=0
    
    log_plain "\n--- 检查X-UI面板 ---"
    restart_service "$XUI_SERVICE_NAME" "3x-ui" "xray" && ((services_restarted++))
    
    log_plain "\n--- 检查S-UI面板 ---"
    restart_service "$SUI_SERVICE_NAME" "sui" "sing-box" && ((services_restarted++))
    
    log_plain "\n--- 检查Nginx服务 ---"
    if restart_service "$NGINX_SERVICE_NAME"; then
        ((services_restarted++))
    else
        [ -x "$(command -v nginx)" ] && nginx -s reload 2>/dev/null && log_plain "Nginx平滑重启: 成功" && ((services_restarted++))
    fi
    
    if [ $services_restarted -eq 0 ]; then
        log_plain "\n${YELLOW}未找到需要重启的面板服务${NC}"
    else
        log_plain "\n${GREEN}已重启 $services_restarted 个服务${NC}"
    fi
}

# 自动清理30天前的日志
clean_old_logs() {
    log_plain "\n${GREEN}[日志清理]${NC}"
    local log_count=$(find "$LOG_DIR" -name "renew_cert_*.log" -type f -mtime +$LOG_RETENTION_DAYS 2>/dev/null | wc -l)
    if [ $log_count -gt 0 ]; then
        find "$LOG_DIR" -name "renew_cert_*.log" -type f -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null
        log_success "清理 $log_count 个过期日志"
    else
        log_info "没有发现超过 30 天的日志文件，无需清理"
    fi
}

# 自动清理30天前的证书备份
clean_old_backups() {
    log_plain "\n${GREEN}[备份清理]${NC}"
    local backup_count=$(find "$BACKUP_DIR" -type d -mtime +$BACKUP_RETENTION_DAYS 2>/dev/null | wc -l)
    if [ $backup_count -gt 0 ]; then
        find "$BACKUP_DIR" -type d -mtime +$BACKUP_RETENTION_DAYS -exec rm -rf {} \; 2>/dev/null
        log_success "清理 $backup_count 个过期备份"
    else
        log_info "没有发现超过 30 天的备份目录，无需清理"
    fi
}

# ==============================================
# 【第六步】主函数：总调度
# ==============================================
cleanup() {
    rm -f "$LOCK_FILE"
    # 可以在这里增加临时文件清理
}

main() {
    # 1. 更加稳健的防重复运行机制
    if [ -f "$LOCK_FILE" ]; then
        # 检查进程是否真的存在，防止死锁
        local old_pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [ -n "$old_pid" ] && ps -p "$old_pid" > /dev/null; then
            log_error "脚本已在运行 (PID: $old_pid)，退出"
            exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE"
    trap cleanup EXIT INT TERM  # 注册清理钩子：脚本退出/中断时自动删锁

    # 2. 检查基础环境组件 (curl/wget)
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        log_warn "缺少 curl/wget，尝试安装..."
        [ -x "$(command -v apt)" ] && apt update && apt install -y curl wget
        [ -x "$(command -v yum)" ] && yum install -y curl wget
    fi

    # 3. 依赖安装逻辑 (保持你原有的，但增加 acme.sh 绝对路径调用)
    if [ ! -d "$ACME_HOME" ]; then
        log_warn "未检测到 acme.sh，执行安装..."
        curl https://get.acme.sh | sh -s email=auto
        # 安装后立即校准变量，确保本次运行能找到它
        [ -f "/root/.acme.sh/acme.sh" ] && ACME_HOME="/root/.acme.sh"
    fi

    # 执行初始化
    setup_shortcut
    disable_acme_auto
    show_header

    # 4. 获取域名逻辑优化：显式检查结果
    if [ -n "$DEFAULT_DOMAIN" ]; then
        DOMAIN="$DEFAULT_DOMAIN"
    else
        auto_discover_domain
        if [ $? -ne 0 ]; then
            log_error "无法自动识别域名，请检查 $ACME_HOME 目录下是否存在 _ecc 结尾的证书文件夹"
            exit 1
        fi
    fi
    
    # 手动运行：展示菜单
    if [ -t 1 ] && [ "$IS_CRON" != "true" ]; then
        show_interactive_menu
        # 仅检查模式
        if [ "$CHECK_ONLY" = true ]; then
            log_plain "\n${GREEN}[配置信息]${NC}"
            log_plain "域名: ${YELLOW}$DOMAIN${NC}"
            log_plain "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
            log_plain "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
            log_plain "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
            log_plain "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
            log_plain "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
            log_plain "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
            log_plain "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
            ! check_cert_paths && exit 1
            show_cert_status
            log_plain "\n${GREEN}仅检查模式完成${NC}"
            exit 0
        fi
    fi

    # 配置信息打印 & 证书检测
    log_plain "\n${GREEN}[配置信息]${NC}"
    log_plain "域名: ${YELLOW}$DOMAIN${NC}"
    log_plain "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    log_plain "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
    log_plain "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
    log_plain "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
    log_plain "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
    log_plain "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
    log_plain "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
    ! check_cert_paths && exit 1

    # 判断是否需要续期
    local need_renewal=false
    [ "$FORCE_RENEW" = true ] && need_renewal=true
    check_cert_expiry "$ACME_CERT_FILE" "$RENEW_THRESHOLD" && need_renewal=true
    
    show_cert_status

    # 执行续期流程
    if $need_renewal; then
        log_plain "\n${YELLOW}[执行证书续期]${NC}"
        renew_certificate
        copy_certificate_files && restart_panel_services
    else
        log_plain "\n${GREEN}[是否续期]${NC}"
        log_plain "证书有效期充足，无需续期"
    fi

    # 自动清理
    clean_old_logs
    clean_old_backups
    
    # 脚本结束展示
    local end_info="
===================================================
            脚本执行完成
===================================================
完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    log_plain "${GREEN}$end_info${NC}"
}

# ==============================================
# 【第七步】启动脚本：调用主函数
# ==============================================
main
