#!/bin/bash
# 证书自动续期管理脚本 (优化版 v2.4)
# 修复：1. 解决日志重复写入问题
# 修复：2. 捕获 acme.sh 详细输出并写入日志
# 新增：3. 日志自动清理功能 (默认保留60天)

#######################################
# 【基础定义层】颜色与配置
#######################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置变量
DEFAULT_DOMAIN=""
DEFAULT_RENEW_THRESHOLD=30
FORCE_RENEW=false
DEFAULT_TARGET_CERT="/root/cert.crt"
DEFAULT_TARGET_KEY="/root/private.key"
ACME_HOME="/root/.acme.sh"

# 日志清理配置
LOG_RETENTION_DAYS=60  # 日志保留天数

# 服务名
XUI_SERVICE_NAME="x-ui"
SUI_SERVICE_NAME="s-ui"
NGINX_SERVICE_NAME="nginx"

# 运行时变量
DOMAIN=""
RENEW_THRESHOLD="$DEFAULT_RENEW_THRESHOLD"
TARGET_CERT="$DEFAULT_TARGET_CERT"
TARGET_KEY="$DEFAULT_TARGET_KEY"
CHECK_ONLY=false
remain_days=0
not_before=""
not_after=""

# 日志相关
LOG_DIR="./renew_cert_logs"
LOG_FILE="${LOG_DIR}/renew_cert_$(date +%Y-%m-%d).log"
mkdir -p "$LOG_DIR"

#######################################
# 【核心修复】统一日志函数 (解决重复+捕获第三方输出)
#######################################
# 通用输出函数：既打印到终端，也写入日志
_print_and_log() {
    local content="$1"
    local no_color="$2"
    
    # 1. 输出到终端 (带颜色)
    echo -e "$content"
    
    # 2. 写入日志文件 (去除颜色码)
    if [ -z "$no_color" ]; then
        echo -e "$content" | sed -r "s/\x1B\[[0-9;]*[mG]//g" >> "$LOG_FILE"
    else
        echo -e "$content" >> "$LOG_FILE"
    fi
}

# 带时间戳的日志
log_info() {
    local msg="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S') [INFO]"
    _print_and_log "${GREEN}[INFO]${NC} $msg"
    echo "$timestamp $msg" >> "$LOG_FILE" # 额外补充一行纯文本时间戳格式
}

log_warn() {
    local msg="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S') [WARN]"
    _print_and_log "${YELLOW}[WARN]${NC} $msg"
    echo "$timestamp $msg" >> "$LOG_FILE"
}

log_error() {
    local msg="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S') [ERROR]"
    _print_and_log "${RED}[ERROR]${NC} $msg"
    echo "$timestamp $msg" >> "$LOG_FILE"
}

log_success() {
    local msg="$1"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS]"
    _print_and_log "${GREEN}[SUCCESS]${NC} $msg"
    echo "$timestamp $msg" >> "$LOG_FILE"
}

# 普通打印 (不带 [INFO] 标签，但也要进日志，用于打印头部、分割线等)
log_print() {
    local content="$1"
    _print_and_log "$content"
}

# 专门用于捕获 acme.sh 这种第三方命令的输出
log_capture_output() {
    # 直接读取标准输入并逐行处理
    while IFS= read -r line; do
        # 简单的直接输出，同时写入日志
        echo "$line"
        echo "$line" >> "$LOG_FILE"
    done
}

#######################################
# 【功能】日志自动清理
#######################################
cleanup_old_logs() {
    echo ""
    log_print "${GREEN}[日志清理]${NC}"
    log_info "开始检查并清理 ${LOG_RETENTION_DAYS} 天前的旧日志..."
    
    # 查找并删除过期文件
    local deleted_count=$(find "$LOG_DIR" -type f -name "*.log" -mtime +$LOG_RETENTION_DAYS -print -delete | wc -l)
    
    if [ "$deleted_count" -gt 0 ]; then
        log_success "日志清理完成，共删除 $deleted_count 个旧日志文件"
    else
        log_info "没有发现超过 ${LOG_RETENTION_DAYS} 天的日志文件，无需清理"
    fi
}

#######################################
# 【功能函数】快捷键与环境检查
#######################################
setup_shortcut() {
    local script_path=$(readlink -f "$0")
    local link_path="/usr/bin/b"
    chmod +x "$script_path"
    if [ ! -e "$link_path" ]; then
        ln -sf "$script_path" "$link_path"
        if [ -x "$link_path" ]; then
            log_success "快捷键 'b' 设置成功！(可以直接输入 b 运行)"
        fi
    fi
}

check_openssl() {
    if ! command -v openssl &>/dev/null; then
        log_error "系统未安装openssl，脚本无法正常运行"
        log_print "请先安装openssl：yum install openssl -y 或 apt install openssl -y"
        exit 1
    fi
}

#######################################
# 【功能函数】显示头部与菜单
#######################################
show_header() {
    local public_ipv4=$(curl -s4m 2 https://api.ipify.org || curl -s4m 2 https://icanhazip.com || curl -s4m 2 https://ifconfig.me || hostname -I | awk '{print $1}')
    local header_info="===================================================
            证书管理脚本启动
===================================================
当前时间: $(date '+%Y-%m-%d %H:%M:%S')
主机名: $(hostname)
IPv4地址: ${public_ipv4:-未知}
IPv6地址: $(hostname -I 2>/dev/null | awk '{print $2}' || curl -s6m 2 ifconfig.me 2>/dev/null || echo '未知')"
    
    log_print "${GREEN}${header_info}${NC}"
}

show_interactive_menu() {
    if [ ! -t 1 ] || [ "$IS_CRON" = "true" ]; then return; fi

    echo ""
    log_print "${GREEN}[选择运行模式]${NC}"
    echo -e "1. 自动模式（推荐用于定时任务）"
    echo -e "2. 强制续期模式（忽略有效期检查）"
    echo -e "3. 仅检查证书状态（不执行续期）"
    echo -e "4. 更新脚本"
    echo -e "5. 退出"
    echo -en "${YELLOW}请选择运行模式（默认1，直接回车使用自动模式）: ${NC}"
    
    read -r choice
    case $choice in
        2) FORCE_RENEW=true; log_warn "已选择强制续期模式" ;;
        3) CHECK_ONLY=true; log_info "仅检查证书状态，不执行续期操作" ;;
        4) 
            echo ""
            log_print "${GREEN}[更新脚本]${NC}"
            log_print "${YELLOW}提示：正在从远程服务器获取最新版本...${NC}"
            wget -O "$0" "https://raw.githubusercontent.com/jasonniceo/Script/refs/heads/main/renew_cert.sh" && chmod +x "$0" && log_success "更新完成，请重新运行" && exit 0
            ;;
        5) log_success "已退出脚本"; exit 0 ;;
        *) log_info "使用默认自动模式" ;;
    esac
}

#######################################
# 【功能函数】域名发现与路径检查
#######################################
auto_discover_domain() {
    echo ""
    log_print "${GREEN}[开始自动发现域名]${NC}"
    log_info "开始自动发现域名"
    
    local domains=()
    for domain_dir in "$ACME_HOME"/*_ecc/; do
        if [ -d "$domain_dir" ]; then
            local domain=$(basename "$domain_dir" | sed 's/_ecc$//')
            if [ -n "$domain" ]; then
                domains+=("$domain")
                log_info "发现ECC域名：$domain"
            fi
        fi
    done
    
    if [ ${#domains[@]} -eq 0 ]; then
        log_warn "未找到域名目录，尝试从acme.sh配置中查找"
        if [ -f "$ACME_HOME/account.conf" ]; then
            local recent_domain=$(grep -r "DOMAIN=" "$ACME_HOME"/*.conf 2>/dev/null | head -1 | cut -d'=' -f2)
            [ -n "$recent_domain" ] && domains+=("$recent_domain") && log_info "从配置发现域名：$recent_domain"
        fi
    fi
    
    if [ ${#domains[@]} -eq 0 ]; then
        log_error "未找到任何证书域名"
        return 1
    elif [ ${#domains[@]} -gt 1 ]; then
        log_warn "发现多个域名，将使用第一个域名: ${domains[0]}"
        DOMAIN="${domains[0]}"
    else
        DOMAIN="${domains[0]}"
        log_info "自动发现域名：$DOMAIN"
    fi
    return 0
}

check_cert_paths() {
    echo ""
    log_print "${GREEN}[检查证书路径]${NC}"
    log_info "开始检查证书路径"
    
    ECC_CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
    ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
    ACME_KEY_FILE="$ECC_CERT_DIR/$DOMAIN.key"
    
    log_info "检查路径：证书=$ACME_CERT_FILE，私钥=$ACME_KEY_FILE"
    
    if [ ! -f "$ACME_CERT_FILE" ]; then log_error "源证书文件不存在：$ACME_CERT_FILE"; return 1; fi
    if [ ! -f "$ACME_KEY_FILE" ]; then log_error "源私钥文件不存在：$ACME_KEY_FILE"; return 1; fi
    
    log_success "证书路径检查通过"
    return 0
}

#######################################
# 【功能函数】证书状态与有效期
#######################################
convert_cert_time() {
    local raw_time="$1"
    local converted_time=$(date -d "$raw_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    [ -z "$converted_time" ] && echo "无法解析时间" || echo "$converted_time"
}

show_cert_status() {
    echo ""
    log_print "${GREEN}[当前证书状态]${NC}"
    log_info "开始显示证书状态"
    
    [ -f "$ACME_CERT_FILE" ] && cert_status="${GREEN}证书文件存在${NC}" || cert_status="${RED}证书文件不存在${NC}"
    [ -f "$ACME_KEY_FILE" ] && key_status="${GREEN}私钥文件存在${NC}" || key_status="${RED}私钥文件不存在${NC}"
    
    cert_real_size=$(du -h "$ACME_CERT_FILE" 2>/dev/null | cut -f1)
    key_real_size=$(du -h "$ACME_KEY_FILE" 2>/dev/null | cut -f1)
    cert_mtime=$(date -r "$ACME_CERT_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    key_mtime=$(date -r "$ACME_KEY_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    
    log_print "目标证书文件状态: $cert_status"
    log_print "目标私钥文件状态: $key_status"
    log_print "文件详情:"
    log_print "  证书文件: $DEFAULT_TARGET_CERT"
    log_print "  私钥文件: $DEFAULT_TARGET_KEY"
    log_print "  文件大小: $cert_real_size (证书), $key_real_size (私钥)"
    log_print "  最后修改: $cert_mtime (证书), $key_mtime (私钥)"
    
    echo ""
    log_print "${GREEN}[证书有效期]${NC}"
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        local cert_dates=$(openssl x509 -in "$DEFAULT_TARGET_CERT" -noout -dates 2>/dev/null)
        if [ -n "$cert_dates" ]; then
            not_before=$(convert_cert_time "$(echo "$cert_dates" | grep "notBefore" | cut -d= -f2)")
            not_after=$(convert_cert_time "$(echo "$cert_dates" | grep "notAfter" | cut -d= -f2)")
            local end_ts=$(date -d "$not_after" +%s 2>/dev/null)
            local now_ts=$(date +%s)
            remain_days=$(( (end_ts - now_ts) / 86400 ))
        fi
    fi
    
    log_print "生效时间: ${YELLOW}$not_before${NC}"
    log_print "到期时间: ${YELLOW}$not_after${NC}"
    log_print "剩余天数: ${YELLOW}$remain_days 天${NC}"
    log_info "证书有效期：生效=$not_before，到期=$not_after，剩余=$remain_days天"
}

check_cert_expiry() {
    local cert_file="$1"
    local threshold="$2"
    log_info "检查证书有效期：文件=$cert_file，阈值=$threshold天"
    
    if [ ! -f "$cert_file" ]; then log_error "证书文件不存在"; return 2; fi
    
    local end_date_raw=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
    [ -z "$end_date_raw" ] && log_error "无法获取到期时间" && return 2
    
    local end_date=$(convert_cert_time "$end_date_raw")
    local end_ts=$(date -d "$end_date" +%s 2>/dev/null)
    local now_ts=$(date +%s)
    remain_days=$(( (end_ts - now_ts) / 86400 ))
    
    log_print "剩余天数: ${YELLOW}$remain_days 天${NC}"
    log_print "续期阈值: ${YELLOW}$threshold 天${NC}"
    
    if [ $remain_days -le $threshold ]; then
        log_warn "证书需要续期：剩余$remain_days天 ≤ 阈值$threshold天"
        return 0
    else
        log_success "证书有效期充足：剩余$remain_days天 > 阈值$threshold天"
        return 1
    fi
}

#######################################
# 【核心修复】续期与复制
#######################################
renew_certificate() {
    echo ""
    log_print "${GREEN}[开始续期证书]${NC}"
    log_info "开始执行证书续期：域名=$DOMAIN"
    
    local renew_cmd="$ACME_HOME/acme.sh --renew -d $DOMAIN"
    [ "$FORCE_RENEW" = true ] && renew_cmd="$renew_cmd --force" && log_warn "启用强制续期模式"
    
    log_info "执行续期命令：$renew_cmd"
    
    # 【核心修复】使用 tee 命令同时输出到屏幕和日志，或者直接在子shell中处理
    # 这里我们用重定向结合管道来确保 acme.sh 的所有输出都被捕获
    local renew_exit_code=0
    {
        eval "$renew_cmd" 2>&1
    } | while IFS= read -r line; do
        # 打印并记录每一行 acme.sh 的输出
        echo "$line"
        echo "$line" >> "$LOG_FILE"
    done
    
    # 获取管道中最后一个命令的退出状态
    renew_exit_code=${PIPESTATUS[0]}

    if [ $renew_exit_code -eq 0 ]; then 
        log_success "证书续期成功"
        return 0
    else 
        log_error "证书续期失败"
        return 1
    fi
}

# 比较文件是否相同
files_are_different() {
    local file1="$1"
    local file2="$2"
    if [ ! -f "$file1" ] || [ ! -f "$file2" ]; then
        return 0
    fi
    if cmp -s "$file1" "$file2"; then
        return 1
    else
        return 0
    fi
}

copy_certificate_files() {
    echo ""
    log_print "${GREEN}[复制证书文件]${NC}"
    log_info "开始复制证书文件"
    
    if [ ! -f "$ACME_CERT_FILE" ] || [ ! -f "$ACME_KEY_FILE" ]; then
        log_error "源证书文件不存在"
        return 1
    fi

    local cert_changed=0
    local key_changed=0
    
    if files_are_different "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"; then
        cert_changed=1
        log_info "检测到证书内容有更新"
    fi
    
    if files_are_different "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY"; then
        key_changed=1
        log_info "检测到私钥内容有更新"
    fi

    if [ $cert_changed -eq 0 ] && [ $key_changed -eq 0 ]; then
        log_success "文件内容未发生变化，跳过复制操作"
        return 0
    fi

    # 备份旧证书
    if [ -f "$DEFAULT_TARGET_CERT" ] || [ -f "$DEFAULT_TARGET_KEY" ]; then
        local backup_dir="/root/cert_backup/$(date '+%Y-%m-%d_%H-%M-%S')"
        mkdir -p "$backup_dir"
        [ -f "$DEFAULT_TARGET_CERT" ] && cp "$DEFAULT_TARGET_CERT" "$backup_dir/cert.crt.backup"
        [ -f "$DEFAULT_TARGET_KEY" ] && cp "$DEFAULT_TARGET_KEY" "$backup_dir/private.key.backup"
        log_info "旧证书已备份到：$backup_dir"
    fi
    
    # 复制文件
    if [ $cert_changed -eq 1 ]; then
        log_info "复制证书：$ACME_CERT_FILE → $DEFAULT_TARGET_CERT"
        cp -f "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"
    fi
    
    if [ $key_changed -eq 1 ]; then
        log_info "复制私钥：$ACME_KEY_FILE → $DEFAULT_TARGET_KEY"
        cp -f "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY"
    fi

    chmod 644 "$DEFAULT_TARGET_CERT"
    chmod 600 "$DEFAULT_TARGET_KEY"
    log_success "证书文件同步完成"
    return 0
}

#######################################
# 【功能函数】重启服务
#######################################
restart_panel_services() {
    echo ""
    log_print "${GREEN}[重启面板服务]${NC}"
    log_info "开始重启面板服务"
    local services_restarted=0

    # X-UI
    echo ""
    log_print "--- 检查X-UI面板 ---"
    if systemctl is-active --quiet "$XUI_SERVICE_NAME" 2>/dev/null; then
        log_print "X-UI服务状态: ${GREEN}运行中${NC}"
        log_print "重启X-UI服务..."
        if systemctl restart "$XUI_SERVICE_NAME"; then
            log_success "X-UI服务重启成功"
            ((services_restarted++))
            sleep 2
            if systemctl is-active --quiet "$XUI_SERVICE_NAME"; then
                log_print "X-UI服务状态: ${GREEN}运行正常${NC}"
            fi
        fi
    else
        log_print "X-UI服务状态: ${YELLOW}未运行${NC}"
        local xui_services=("x-ui" "3x-ui" "xray")
        for service in "${xui_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_print "发现X-UI服务: $service"
                if systemctl restart "$service"; then
                    log_success "$service 重启成功"
                    ((services_restarted++))
                fi
                break
            fi
        done
    fi

    # S-UI
    echo ""
    log_print "--- 检查S-UI面板 ---"
    if systemctl is-active --quiet "$SUI_SERVICE_NAME" 2>/dev/null; then
        log_print "S-UI服务状态: ${GREEN}运行中${NC}"
        log_print "重启S-UI服务..."
        if systemctl restart "$SUI_SERVICE_NAME"; then
            log_success "S-UI服务重启成功"
            ((services_restarted++))
        fi
    fi

    # Nginx
    echo ""
    log_print "--- 检查Nginx服务 ---"
    if systemctl is-active --quiet "$NGINX_SERVICE_NAME" 2>/dev/null; then
        log_print "Nginx服务状态: ${GREEN}运行中${NC}"
        log_print "重启Nginx服务..."
        if systemctl restart "$NGINX_SERVICE_NAME"; then
            log_success "Nginx服务重启成功"
            ((services_restarted++))
        fi
    elif command -v nginx &>/dev/null; then
        log_print "尝试Nginx平滑重启..."
        if nginx -s reload 2>/dev/null; then
            log_success "Nginx平滑重启成功"
            ((services_restarted++))
        fi
    fi

    if [ $services_restarted -eq 0 ]; then
        log_warn "未找到需要重启的面板服务"
    else
        log_success "已重启 $services_restarted 个服务"
    fi
}

#######################################
# 【主执行函数】main
#######################################
main() {
    setup_shortcut
    check_openssl
    show_header
    show_interactive_menu

    # 仅检查模式
    if [ "$CHECK_ONLY" = true ]; then
        if [ -n "$DEFAULT_DOMAIN" ]; then DOMAIN="$DEFAULT_DOMAIN"; else auto_discover_domain || exit 1; fi
        echo ""
        log_print "${GREEN}[配置信息]${NC}"
        log_print "域名: ${YELLOW}$DOMAIN${NC}"
        check_cert_paths || exit 1
        show_cert_status
        log_success "仅检查模式完成"
        exit 0
    fi

    # 主流程
    if [ -n "$DEFAULT_DOMAIN" ]; then
        DOMAIN="$DEFAULT_DOMAIN"
        log_info "使用手动指定域名：$DOMAIN"
    else
        auto_discover_domain || exit 1
    fi

    echo ""
    log_print "${GREEN}[配置信息]${NC}"
    log_print "域名: ${YELLOW}$DOMAIN${NC}"
    check_cert_paths || exit 1
    show_cert_status

    local need_renewal=false
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        if [ "$FORCE_RENEW" = true ]; then
            need_renewal=true
        elif check_cert_expiry "$DEFAULT_TARGET_CERT" "$RENEW_THRESHOLD"; then
            need_renewal=true
        fi
    else
        log_warn "目标证书不存在，将进行首次复制"
        need_renewal=true
    fi

    if $need_renewal; then
        echo ""
        log_print "${YELLOW}[执行证书续期流程]${NC}"
        renew_certificate || log_warn "续期失败，尝试使用现有证书"
        if copy_certificate_files; then
            restart_panel_services
        fi
    else
        echo ""
        log_print "${GREEN}[无需续期]${NC}"
        log_info "证书有效期充足，跳过续期流程"
        
        # 同步检查
        if [ -f "$ACME_CERT_FILE" ] && [ -f "$DEFAULT_TARGET_CERT" ]; then
            local acme_time=$(stat -c %Y "$ACME_CERT_FILE" 2>/dev/null || echo 0)
            local target_time=$(stat -c %Y "$DEFAULT_TARGET_CERT" 2>/dev/null || echo 0)
            
            if [ $acme_time -gt $target_time ] && files_are_different "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"; then
                log_warn "检测到acme.sh证书内容已更新，同步到目标位置"
                if copy_certificate_files; then
                    restart_panel_services
                fi
            fi
        fi
    fi

    # 日志清理
    cleanup_old_logs

    echo ""
    log_print "${GREEN}===================================================${NC}"
    log_print "${GREEN}            脚本执行完成${NC}"
    log_print "${GREEN}===================================================${NC}"
}

main
