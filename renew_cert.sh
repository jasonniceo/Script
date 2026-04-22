#!/bin/bash
# 证书自动续期管理脚本
# 功能：自动检查证书有效期，在到期前30天自动续期，并重启面板服务和Nginx
# 作者：自动生成
# 版本：v2.3 无损优化版
# 使用方法：可配置cron定时任务，或手动执行 ./renew_cert.sh (或输入 b 运行)
# 排序规则：基础定义层 → 通用工具函数 → 功能函数（按main调用顺序）→ main主函数 → 执行入口
# 日志说明：关键操作输出终端，核心流程自动记录时间戳，便于问题排查

#######################################
# 【基础定义层】颜色定义（标准化终端输出）
#######################################
# 基础字体颜色（统一输出风格，便于日志识别）
RED='\033[0;31m'     # 错误/失败/异常（日志中易识别）
GREEN='\033[0;32m'   # 成功/完成/主标题（核心流程标记）
YELLOW='\033[1;33m'  # 警告/提示/待确认（需关注的非错误信息）
NC='\033[0m'         # 颜色重置（避免终端颜色污染）

#######################################
# 【基础定义层】配置变量（可修改的核心参数）
#######################################
DEFAULT_DOMAIN=""                          # 手动指定域名（留空自动检测）
DEFAULT_RENEW_THRESHOLD=30                 # 续期阈值（剩余≤30天触发续期）
FORCE_RENEW=false                          # 强制续期开关（true=忽略有效期直接续期）
DEFAULT_TARGET_CERT="/root/cert.crt"       # 目标证书最终存放路径
DEFAULT_TARGET_KEY="/root/private.key"     # 目标私钥最终存放路径
ACME_HOME="/root/.acme.sh"                 # acme.sh安装根目录

# 面板服务名称配置（适配不同环境的服务名）
XUI_SERVICE_NAME="x-ui"                    # X-UI面板服务名
SUI_SERVICE_NAME="s-ui"                    # S-UI面板服务名
NGINX_SERVICE_NAME="nginx"                 # Nginx服务名

# 日志清理配置
LOG_RETENTION_DAYS=30                       # 日志保留天数，超过此天数的日志将被自动清理

#######################################
# 【基础定义层】运行时变量（脚本内部使用，无需手动修改）
#######################################
DOMAIN=""                                  # 最终使用的域名（自动/手动赋值）
RENEW_THRESHOLD="$DEFAULT_RENEW_THRESHOLD" # 续期阈值（同步默认配置）
TARGET_CERT="$DEFAULT_TARGET_CERT"         # 目标证书路径（同步默认配置）
TARGET_KEY="$DEFAULT_TARGET_KEY"           # 目标私钥路径（同步默认配置）
CHECK_ONLY=false                           # 仅检查模式开关
remain_days=0                              # 证书剩余有效天数（全局变量）
# 全局变量：解决证书时间在汇总时无法显示的问题
not_before=""                              # 证书生效时间（全局）
not_after=""                               # 证书到期时间（全局）
cert_real_size=""                          # 证书文件大小（全局）
key_real_size=""                           # 私钥文件大小（全局）
cert_mtime=""                              # 证书最后修改时间（全局）
key_mtime=""                               # 私钥最后修改时间（全局）

# 日志：修改日志路径改为root下的renew_cert_logs文件夹，按日期分割
LOG_DIR="./renew_cert_logs"               # 日志存储目录（root下的renew_cert_logs）
LOG_FILE="${LOG_DIR}/renew_cert_$(date +%Y-%m-%d).log" # 按日期分割日志
mkdir -p "$LOG_DIR"                        # 确保日志目录存在

#######################################
# 封装统一日志函数，去重所有重复日志代码
# 功能：终端彩色输出 + 无颜色写入日志 + 自动时间戳
#######################################
log_raw() {
    local content="$1"
    echo -e "$content"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') $(echo -e "$content" | sed -r 's/\x1B\[[0-9;]*[mG]//g')" >> "$LOG_FILE"
}
log_info()  { log_raw "${GREEN}[INFO]${NC} $1"; }
log_warn()  { log_raw "${YELLOW}[WARN]${NC} $1"; }
log_error() { log_raw "${RED}[ERROR]${NC} $1"; }
log_success(){ log_raw "${GREEN}[SUCCESS]${NC} $1"; }
# 纯文本输出（保留原有头部/分割线格式）
log_plain() {
    local content="$1"
    echo -e "$content"
    echo -e "$content" | sed -r 's/\x1B\[[0-9;]*[mG]//g' >> "$LOG_FILE"
}

#######################################
# 【通用工具函数】获取文件权限/归属/大小/修改时间
# 功能：封装重复的stat命令，去重代码
#######################################
get_file_info() {
    local file="$1"
    if [ ! -f "$file" ]; then return 1; fi
    local perm=$(stat -c "%A" "$file")
    local user=$(stat -c "%U" "$file")
    local group=$(stat -c "%G" "$file")
    local size=$(stat -c "%s" "$file")
    local datetime=$(stat -c "%y" "$file" | cut -d'.' -f1)
    echo "$perm|$user|$group|$size|$datetime"
}

#######################################
# 【通用工具函数】生成自动对齐的表格+分隔线
# 功能：修复权限表格虚线错位，封装重复表格逻辑
#######################################
print_aligned_table() {
    local table_data="$1"
    local formatted_table=$(echo -e "$table_data" | column -t -s $'\t')
    # 计算表格最大宽度，生成等长分隔线
    local max_line_length=0
    while IFS= read -r line; do
        local len=${#line}
        (( len > max_line_length )) && max_line_length=$len
    done <<< "$formatted_table"
    local separator=$(printf "%0.s-" $(seq 1 $max_line_length))
    # 输出表格
    log_plain "${YELLOW}$separator${NC}"
    echo "$formatted_table" | while IFS= read -r line; do
        log_plain "$line"
        [[ "$line" == *"权限"* ]] && log_plain "${YELLOW}$separator${NC}"
    done
    log_plain "${YELLOW}$separator${NC}"
}

#######################################
# 【通用工具函数】通用服务重启逻辑
# 功能：封装重复的服务重启代码，不改变原有逻辑
#######################################
restart_service() {
    local service_name="$1"
    local service_alias=("${@:2}")
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        log_plain "$service_name 服务状态: ${GREEN}运行中${NC}"
        log_plain "重启 $service_name 服务..."
        if systemctl restart "$service_name"; then
            log_plain "$service_name 服务重启: ${GREEN}成功${NC}"
            sleep 2
            systemctl is-active --quiet "$service_name" && log_plain "$service_name 服务状态: ${GREEN}运行正常${NC}" || log_warn "警告：$service_name 服务未运行"
            return 0
        else
            log_plain "$service_name 服务重启: ${RED}失败${NC}"
            return 1
        fi
    else
        log_plain "$service_name 服务状态: ${YELLOW}未运行${NC}"
        log_info "$service_name 服务未运行，尝试兼容名"
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

#######################################
# 【通用工具函数】计算证书剩余天数
# 功能：封装重复的时间计算逻辑，去重代码
#######################################
calc_remain_days() {
    local end_date="$1"
    local end_ts=$(date -d "$end_date" +%s 2>/dev/null)
    local now_ts=$(date +%s)
    echo $(( (end_ts - now_ts) / 86400 ))
}

#######################################
# 【功能函数】自动配置快捷键，main流程最先调用）
# 功能：设置 'b' 为全局命令
#######################################
setup_shortcut() {
    # 动态获取当前脚本的绝对路径
    local script_path=$(readlink -f "$0")
    local link_path="/usr/bin/b"

    # 赋予脚本执行权限
    chmod +x "$script_path"

    # 使用软链接，确保全局生效
    if [ ! -e "$link_path" ]; then
        # 强制创建软链接指向当前脚本
        ln -sf "$script_path" "$link_path"
        
        if [ -x "$link_path" ]; then
            log_success "快捷键 'b' 设置成功！(可以直接输入 b 运行)"
        else
            log_warn "快捷键设置失败，请检查权限。"
        fi
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 1. 显示脚本头部信息
#######################################
show_header() {
    # 输出脚本启动信息，同时写入日志
    # 修改说明：IPv4 改为优先获取公网IP（多个接口保障），失败才回退内网
    local public_ipv4=$(curl -s4m 2 https://api.ipify.org || curl -s4m 2 https://icanhazip.com || curl -s4m 2 https://ifconfig.me || hostname -I | awk '{print $1}')
    
    local header_info="
===================================================
            证书管理脚本启动
===================================================
当前时间: $(date '+%Y-%m-%d %H:%M:%S')
主机名: $(hostname)
IPv4地址: ${public_ipv4:-未知}
IPv6地址: $(hostname -I 2>/dev/null | awk '{print $2}' || curl -s6m 2 ifconfig.me 2>/dev/null || echo '未知')"
    
    # 终端彩色输出
    log_plain "${GREEN}${header_info}${NC}"
    log_info "脚本启动"
}

#######################################
# 【功能函数】按main调用顺序排列 - 2. 显示交互式菜单
#######################################
show_interactive_menu() {
    # 交互式选择运行模式，仅在终端执行时生效
    log_plain "\n${GREEN}[选择运行模式]${NC}"
    log_plain "1. 自动模式（推荐用于定时任务）"
    log_plain "2. 强制续期模式（忽略有效期检查）"
    log_plain "3. 仅检查证书状态（不执行续期）"
    log_plain "4. 更新脚本"
    log_plain "5. 退出"
    echo -en "${YELLOW}请选择运行模式（默认1，直接回车使用自动模式）: ${NC}"
    
    read -r choice
    case $choice in
        2)
            FORCE_RENEW=true
            log_warn "已选择强制续期模式"
            ;;
        3)
            CHECK_ONLY=true
            log_warn "仅检查证书状态，不执行续期操作"
            ;;
        4)
            log_plain "\n${GREEN}[更新脚本]${NC}"
            log_plain "${YELLOW}提示：正在从远程服务器获取最新版本...${NC}"
            # 修改URL替换为您指定的renew_cert.sh地址
            wget -O "$0" "https://raw.githubusercontent.com/jasonniceo/Script/refs/heads/main/renew_cert.sh" && chmod +x "$0" && log_success "更新完成，请重新运行"
            exit 0
            ;;
        5)
            log_success "已退出脚本"
            exit 0
            ;;
        *)
            log_info "使用默认自动模式"
            ;;
    esac
}

#######################################
# 【功能函数】按main调用顺序排列 - 3. 自动发现acme.sh中的域名
#######################################
auto_discover_domain() {
    log_plain "\n${GREEN}[开始自动发现域名]${NC}"
    log_info "开始自动发现域名"
    
    local domains=()
    
    # 优先查找ecc域名目录
    for domain_dir in "$ACME_HOME"/*_ecc/; do
        if [ -d "$domain_dir" ]; then
            local domain=$(basename "$domain_dir" | sed 's/_ecc$//')
            if [ -n "$domain" ]; then
                domains+=("$domain")
                log_plain "  发现域名: ${YELLOW}$domain${NC}"
                log_info "发现ECC域名：$domain"
            fi
        fi
    done
    
    # 备用：从配置文件查找域名
    if [ ${#domains[@]} -eq 0 ]; then
        log_warn "  警告：未找到域名目录，尝试从acme.sh配置中查找"
        log_warn "未找到ECC域名目录，尝试从配置查找"
        
        if [ -f "$ACME_HOME/account.conf" ]; then
            local recent_domain=$(grep -r "DOMAIN=" "$ACME_HOME"/*.conf 2>/dev/null | head -1 | cut -d'=' -f2)
            if [ -n "$recent_domain" ]; then
                domains+=("$recent_domain")
                log_plain "  从配置发现域名: ${YELLOW}$recent_domain${NC}"
                log_info "从配置发现域名：$recent_domain"
            fi
        fi
    fi
    
    # 结果判断
    if [ ${#domains[@]} -eq 0 ]; then
        log_error "错误：未找到任何证书域名"
        log_plain "请确保："
        log_plain "  1. acme.sh已正确安装"
        log_plain "  2. 已通过acme.sh申请过证书"
        log_plain "  3. 证书存放在 $ACME_HOME/ 目录下"
        log_error "未找到任何证书域名"
        return 1
    elif [ ${#domains[@]} -gt 1 ]; then
        log_warn "警告：发现多个域名，将使用第一个域名: ${domains[0]}"
        log_plain "找到的域名列表: ${domains[*]}"
        log_plain "如需使用其他域名，请修改脚本或手动指定"
        DOMAIN="${domains[0]}"
        log_warn "发现多个域名，使用第一个：${domains[0]}"
    else
        DOMAIN="${domains[0]}"
        log_success "自动发现域名: ${YELLOW}$DOMAIN${NC}"
        log_info "自动发现域名：$DOMAIN"
    fi
    
    return 0
}

#######################################
# 【功能函数】按main调用顺序排列 - 4. 检查证书文件路径
#######################################
check_cert_paths() {
    log_plain "\n${GREEN}[检查证书路径]${NC}"
    log_info "开始检查证书路径"
    
    ECC_CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
    ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
    ACME_KEY_FILE="$ECC_CERT_DIR/$DOMAIN.key"
    
    log_plain "  ACME证书目录: $ECC_CERT_DIR"
    log_plain "  源证书文件: $ACME_CERT_FILE"
    log_plain "  源私钥文件: $ACME_KEY_FILE"
    log_info "检查路径：证书=$ACME_CERT_FILE，私钥=$ACME_KEY_FILE"
    
    if [ ! -f "$ACME_CERT_FILE" ]; then
        log_error "错误：找不到源证书文件"
        log_plain "请检查路径: $ACME_CERT_FILE"
        log_error "源证书文件不存在：$ACME_CERT_FILE"
        return 1
    fi
    
    if [ ! -f "$ACME_KEY_FILE" ]; then
        log_error "错误：找不到源私钥文件"
        log_plain "请检查路径: $ACME_KEY_FILE"
        log_error "源私钥文件不存在：$ACME_KEY_FILE"
        return 1
    fi
    
    log_success "证书路径检查通过"
    log_info "证书路径检查通过"
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
        log_warn "无法解析时间：$raw_time"
    else
        echo "$converted_time"
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 5. 显示当前证书状态
#######################################
show_cert_status() {
    log_plain "\n${GREEN}[当前证书状态]${NC}"
    log_info "开始显示证书状态"
    
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
    log_plain "目标证书文件状态: $cert_status"
    log_plain "目标私钥文件状态: $key_status"
    log_plain "文件详情:"
    log_plain "  证书文件: $DEFAULT_TARGET_CERT"
    log_plain "  私钥文件: $DEFAULT_TARGET_KEY"
    log_plain "  文件大小: $cert_real_size (证书), $key_real_size (私钥)"
    log_plain "  最后修改: $cert_mtime (证书), $key_mtime (私钥)"

    # ===================== 调用封装函数生成表格，修复对齐 =====================
    log_plain "\n${GREEN}文件权限详情:${NC}"
    local table_data="权限\t所有者\t用户组\t大小\t修改时间\t文件路径"
    for file in "$ACME_CERT_FILE" "$ACME_KEY_FILE"; do
        if [ -f "$file" ]; then
            local info=$(get_file_info "$file")
            local perm=$(echo "$info" | cut -d'|' -f1)
            local user=$(echo "$info" | cut -d'|' -f2)
            local group=$(echo "$info" | cut -d'|' -f3)
            local size=$(echo "$info" | cut -d'|' -f4)
            local datetime=$(echo "$info" | cut -d'|' -f5)
            local target_file="$DEFAULT_TARGET_CERT"
            [ "$file" = "$ACME_KEY_FILE" ] && target_file="$DEFAULT_TARGET_KEY"
            table_data+="\n$perm\t$user\t$group\t$size\t$datetime\t$target_file"
        fi
    done
    print_aligned_table "$table_data"

    # 证书有效期解析（赋值给全局变量）
    log_plain "\n${GREEN}[证书有效期]${NC}"
    # 读取源证书
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
    
    # 调用封装函数计算剩余天数
    remain_days=$(calc_remain_days "$not_after")
    
    # 输出有效期到终端（按你要求的顺序）
    log_plain "生效时间: ${YELLOW}$not_before${NC}"
    log_plain "到期时间: ${YELLOW}$not_after${NC}"
    log_plain "剩余天数: ${YELLOW}$remain_days 天${NC}"
    
    # 输出有效期到日志（保留一行INFO）
    log_info "证书有效期：生效=$not_before，到期=$not_after，剩余=$remain_days天"
}

#######################################
# 【功能函数】按main调用顺序排列 - 6. 检查证书有效期
#######################################
check_cert_expiry() {
    local cert_file="$1"
    local threshold="$2"
    
    log_info "检查证书有效期：文件=$cert_file，阈值=$threshold天"
    
    if [ ! -f "$cert_file" ]; then
        log_error "错误：证书文件不存在"
        log_error "检查有效期失败：证书文件不存在$cert_file"
        return 2
    fi
    
    if ! command -v openssl &>/dev/null; then
        log_error "错误：系统未安装openssl，无法解析证书有效期"
        log_error "检查有效期失败：未安装openssl"
        return 2
    fi
    
    local end_date_raw=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
    if [ -z "$end_date_raw" ]; then
        log_error "错误：无法获取证书到期时间"
        log_error "检查有效期失败：无法获取到期时间"
        return 2
    fi
    
    local end_date=$(convert_cert_time "$end_date_raw")
    if [ -z "$end_date" ] || [ "$end_date" = "无法解析时间" ]; then
        log_error "错误：无法解析证书日期: $end_date_raw"
        log_error "检查有效期失败：无法解析日期$end_date_raw"
        return 2
    fi
    
    # 调用封装函数计算剩余天数
    remain_days=$(calc_remain_days "$end_date")
    
    # 判断是否需要续期（删除多余的INFO日志）
    if [ $remain_days -le $threshold ]; then
        log_warn "证书需要续期（剩余 ≤ $threshold 天）"
        log_info "证书需要续期：剩余$remain_days天 ≤ 阈值$threshold天"
        return 0
    else
        log_success "证书有效期充足"
        return 1
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 7. 执行证书续期
#######################################
renew_certificate() {
    log_plain "\n${GREEN}[开始续期证书]${NC}"
    log_info "开始执行证书续期：域名=$DOMAIN"
    
    log_plain "域名: ${YELLOW}$DOMAIN${NC}"
    log_plain "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    
    local renew_cmd="$ACME_HOME/acme.sh --renew -d $DOMAIN"
    if [ "$FORCE_RENEW" = true ]; then
        renew_cmd="$renew_cmd --force"
        log_warn "强制续期模式已启用"
        log_info "启用强制续期模式"
    fi
    
    log_plain "执行命令: $renew_cmd"
    log_info "执行续期命令：$renew_cmd"
    
    # 执行续期命令并捕获输出
    local renew_output
    renew_output=$(eval "$renew_cmd" 2>&1)
    log_plain "$renew_output"
    
    if [ $? -eq 0 ]; then
        log_success "证书续期成功"
        log_success "证书续期成功：域名=$DOMAIN"
        return 0
    else
        log_error "证书续期失败"
        log_error "证书续期失败：域名=$DOMAIN，输出=$renew_output"
        return 1
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 8. 复制证书文件
#######################################
copy_certificate_files() {
    log_plain "\n${GREEN}[复制证书文件]${NC}"
    log_info "开始复制证书文件"
    
    if [ ! -f "$ACME_CERT_FILE" ] || [ ! -f "$ACME_KEY_FILE" ]; then
        log_error "错误：源证书文件不存在"
        log_plain "证书文件: $ACME_CERT_FILE"
        log_plain "私钥文件: $ACME_KEY_FILE"
        log_error "复制证书失败：源文件不存在"
        return 1
    fi
    
    # 备份旧证书
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        local backup_dir="/root/cert_backup/$(date '+%Y-%m-%d_%H-%M-%S')"
        mkdir -p "$backup_dir"
        cp "$DEFAULT_TARGET_CERT" "$backup_dir/cert.crt.backup"
        cp "$DEFAULT_TARGET_KEY" "$backup_dir/private.key.backup"
        log_plain "旧证书已备份到: $backup_dir"
        log_info "旧证书备份到：$backup_dir"
    fi
    
    # 复制证书文件到目标路径
    log_plain "复制证书文件..."
    log_plain "  从: $ACME_CERT_FILE"
    log_plain "  到: $DEFAULT_TARGET_CERT"
    cp -f "$ACME_CERT_FILE" "$DEFAULT_TARGET_CERT"
    log_info "复制证书：$ACME_CERT_FILE → $DEFAULT_TARGET_CERT"
    
    log_plain "复制私钥文件..."
    log_plain "  从: $ACME_KEY_FILE"
    log_plain "  到: $DEFAULT_TARGET_KEY"
    cp -f "$ACME_KEY_FILE" "$DEFAULT_TARGET_KEY"
    log_info "复制私钥：$ACME_KEY_FILE → $DEFAULT_TARGET_KEY"
    
    # 设置文件权限（安全加固）
    log_plain "设置文件权限..."
    chmod 644 "$DEFAULT_TARGET_CERT"  # 证书可读不可写
    chmod 600 "$DEFAULT_TARGET_KEY"   # 私钥仅所有者可读
    log_info "设置权限：证书644，私钥600"
    
    # 验证复制结果
    if [ -f "$DEFAULT_TARGET_CERT" ] && [ -f "$DEFAULT_TARGET_KEY" ]; then
        log_success "证书文件复制完成"
        log_plain "文件权限:"
        ls -la "$DEFAULT_TARGET_KEY" "$DEFAULT_TARGET_CERT"
        log_success "证书文件复制成功"
        log_success "证书文件复制成功"
        return 0
    else
        log_error "错误：证书文件复制失败"
        log_error "证书文件复制失败"
        return 1
    fi
}

#######################################
# 【功能函数】按main调用顺序排列 - 9. 重启面板服务
#######################################
restart_panel_services() {
    log_plain "\n${GREEN}[重启面板服务]${NC}"
    log_info "开始重启面板服务"
    log_plain "注意：重启服务以确保使用最新证书"
    
    local services_restarted=0  # 统计成功重启的服务数
    
    # 调用封装函数重启XUI服务
    log_plain "\n--- 检查X-UI面板 ---"
    restart_service "$XUI_SERVICE_NAME" "3x-ui" "xray" && ((services_restarted++))
    
    # 调用封装函数重启SUI服务
    log_plain "\n--- 检查S-UI面板 ---"
    restart_service "$SUI_SERVICE_NAME" "sui" "sing-box" && ((services_restarted++))
    
    # 调用封装函数重启Nginx服务
    log_plain "\n--- 检查Nginx服务 ---"
    if restart_service "$NGINX_SERVICE_NAME"; then
        ((services_restarted++))
    else
        log_info "Nginx未运行，尝试平滑重启"
        if command -v nginx &>/dev/null && nginx -s reload 2>/dev/null; then
            log_plain "Nginx平滑重启: ${GREEN}成功${NC}"
            ((services_restarted++))
        fi
    fi
    
    # 输出重启结果统计
    if [ $services_restarted -eq 0 ]; then
        log_plain "\n${YELLOW}未找到需要重启的面板服务${NC}"
        log_plain "如果面板正在运行，请检查："
        log_plain "  1. 服务名称是否正确（当前配置：X-UI=$XUI_SERVICE_NAME, S-UI=$SUI_SERVICE_NAME, Nginx=$NGINX_SERVICE_NAME）"
        log_plain "  2. 手动重启命令参考："
        log_plain "      systemctl restart x-ui"
        log_plain "      systemctl restart s-ui"
        log_plain "      systemctl restart nginx"
        log_warn "未找到需要重启的服务"
    else
        log_plain "\n${GREEN}已重启 $services_restarted 个服务${NC}"
        log_success "成功重启$services_restarted个服务"
    fi
}

#######################################
# 日志清理：删除超过LOG_RETENTION_DAYS天的旧日志
#######################################
clean_old_logs() {
    log_plain "\n${GREEN}[日志清理]${NC}"
    log_info "开始检查并清理 ${LOG_RETENTION_DAYS} 天前的旧日志文件..."
    
    # 查找超过保留天数的日志文件
    local old_logs=$(find "$LOG_DIR" -name "renew_cert_*.log" -type f -mtime +$LOG_RETENTION_DAYS 2>/dev/null)
    local log_count=$(find "$LOG_DIR" -name "renew_cert_*.log" -type f -mtime +$LOG_RETENTION_DAYS 2>/dev/null | wc -l)
    
    if [ $log_count -gt 0 ]; then
        log_info "发现 $log_count 个超过 ${LOG_RETENTION_DAYS} 天的旧日志文件，开始清理..."
        # 循环删除并记录每个文件
        while IFS= read -r log_file; do
            if [ -n "$log_file" ]; then
                rm -f "$log_file"
                log_info "已删除旧日志文件: $log_file"
            fi
        done <<< "$old_logs"
        log_success "日志清理完成，共删除 $log_count 个旧日志文件"
    else
        log_info "没有发现超过 ${LOG_RETENTION_DAYS} 天的日志文件，无需清理"
    fi
}

#######################################
# 【主执行函数】main函数（核心逻辑，按流程调用上述函数）
#######################################
main() {
    # 核心功能：自动配置快捷启动键 'b'
    setup_shortcut

    # 前置检查：确保openssl已安装
    if ! command -v openssl &>/dev/null; then
        log_error "错误：系统未安装openssl，脚本无法正常运行"
        log_plain "请先安装openssl：yum install openssl -y 或 apt install openssl -y"
        log_error "未安装openssl，脚本退出"
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
                log_plain "${GREEN}[使用手动指定的域名]${NC}"
                DOMAIN="$DEFAULT_DOMAIN"
                log_plain "域名: ${YELLOW}$DOMAIN${NC}"
                log_info "仅检查模式：使用手动指定域名$DOMAIN"
            else
                if ! auto_discover_domain; then
                    log_error "无法自动发现域名，请手动配置"
                    log_error "仅检查模式：自动发现域名失败"
                    exit 1
                fi
            fi
            
            # 输出配置信息
            log_plain "\n${GREEN}[配置信息]${NC}"
            log_plain "域名: ${YELLOW}$DOMAIN${NC}"
            log_plain "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
            log_plain "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
            log_plain "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
            log_plain "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
            log_plain "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
            log_plain "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
            log_plain "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
            log_info "仅检查模式：输出配置信息完成"
            
            # 检查证书路径
            if ! check_cert_paths; then
                log_error "仅检查模式：证书路径检查失败"
                exit 1
            fi
            
            # 显示证书状态
            show_cert_status
            
            log_plain "\n${GREEN}仅检查模式完成${NC}"
            log_success "仅检查模式执行完成"
            exit 0
        fi
    fi
    
    # 步骤3：域名发现（自动/手动）
    if [ -n "$DEFAULT_DOMAIN" ]; then
        log_plain "${GREEN}[使用手动指定的域名]${NC}"
        DOMAIN="$DEFAULT_DOMAIN"
        log_plain "域名: ${YELLOW}$DOMAIN${NC}"
        log_info "使用手动指定域名：$DOMAIN"
    else
        if ! auto_discover_domain; then
            log_error "无法自动发现域名，请手动配置"
            log_error "自动发现域名失败，脚本退出"
            exit 1
        fi
    fi
    
    # 步骤4：输出配置信息
    log_plain "\n${GREEN}[配置信息]${NC}"
    log_plain "域名: ${YELLOW}$DOMAIN${NC}"
    log_plain "续期阈值: ${YELLOW}$RENEW_THRESHOLD 天${NC}"
    log_plain "强制续期: ${YELLOW}$FORCE_RENEW${NC}"
    log_plain "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
    log_plain "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
    log_plain "X-UI服务名: ${YELLOW}$XUI_SERVICE_NAME${NC}"
    log_plain "S-UI服务名: ${YELLOW}$SUI_SERVICE_NAME${NC}"
    log_plain "Nginx服务名: ${YELLOW}$NGINX_SERVICE_NAME${NC}"
    log_info "配置信息：域名=$DOMAIN，阈值=$RENEW_THRESHOLD天，强制续期=$FORCE_RENEW"
    
    # 步骤5：检查证书路径
    if ! check_cert_paths; then
        log_error "证书路径检查失败，脚本退出"
        exit 1
    fi
    
    # 步骤6：显示证书状态
    show_cert_status
    
    # 步骤7：判断是否需要续期
    local need_renewal=false
    if [ -f "$DEFAULT_TARGET_CERT" ]; then
        if [ "$FORCE_RENEW" = true ]; then
            log_warn "强制续期模式：跳过有效期检查，直接执行续期"
            log_info "强制续期模式，跳过有效期检查"
            need_renewal=true
        elif check_cert_expiry "$DEFAULT_TARGET_CERT" "$RENEW_THRESHOLD"; then
            need_renewal=true
        fi
    else
        log_plain "\n${YELLOW}目标证书不存在，将进行首次复制${NC}"
        log_info "目标证书不存在，需要首次复制"
        need_renewal=true
    fi
    
    # 步骤8：执行续期/复制/重启流程
    if $need_renewal; then
        log_plain "\n${YELLOW}[执行证书续期]${NC}"
        log_info "开始执行续期流程"
        
        if renew_certificate; then
            log_success "证书续期成功"
        else
            log_warn "证书续期失败，尝试使用现有证书"
            log_warn "续期失败，使用现有证书"
        fi
        
        if copy_certificate_files; then
            log_success "证书文件复制成功"
            restart_panel_services
        else
            log_error "证书文件复制失败"
            log_error "证书复制失败，脚本退出"
            exit 1
        fi
    else
        # 无需续期：跳过所有同步操作
        log_plain "\n${GREEN}[是否续期]${NC}"
        log_plain "证书有效期充足，无需续期，跳过所有修改操作"
    fi

    # 步骤9：执行日志清理（每次脚本运行完成后自动执行）
    clean_old_logs
    
    # 步骤10：脚本结束汇总
local end_info="
===================================================
            脚本执行完成
===================================================
完成时间: $(date '+%Y-%m-%d %H:%M:%S')"

log_plain "${GREEN}${end_info}${NC}"
}
#######################################
# 【脚本执行入口】最后一行调用main函数
#######################################
main
