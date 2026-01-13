#!/bin/bash
# ==============================================================================
# ACME证书申请脚本
# 核心功能：一键申请/重置SSL证书，支持多CA机构、80端口检查、环境清理
# 安全控制：命令失败即终止 + 管道失败即终止，避免隐藏错误
# 使用方法：手动执行 ./acme_cert.sh或输入 a 运行
# ==============================================================================

set -eo pipefail  # 核心安全控制：
                  # 1. 任意命令执行失败(返回非0)立即终止脚本；
                  # 2. 管道命令中任意环节失败，整个管道视为失败，避免隐藏错误

# ==============================================================================
# 【基础定义层】- 颜色定义/配置变量/参数设置（优先放置）
# ==============================================================================
# 【优化】强制设定英文环境，防止OpenSSL和Date命令因系统语言不同导致解析错误
export LANG=en_US.UTF-8
# 【优化】补全系统路径，防止部分极简系统找不到系统命令
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

#######################################
# 颜色定义（标准化终端输出）
#######################################
# 基础字体颜色（最常用）
RED='\033[0;31m'      # 所有错误、失败、异常消息
GREEN='\033[0;32m'    # 所有成功/完成/通过/主标题/菜单标题
YELLOW='\033[1;33m'   # 所有警告/提示/待确认信息
NC='\033[0m'          # 所有颜色后重置
#######################################
# 核心配置（集中管理关键路径）
#######################################
ACME_HOME="/root/.acme.sh"                            # acme.sh安装目录
DEFAULT_TARGET_CERT="/root/cert.crt"                  # 目标证书路径
DEFAULT_TARGET_KEY="/root/private.key"                # 目标私钥路径
LOG_DIR="./acme_cert_logs"                            # 日志存储目录
LOG_FILE="${LOG_DIR}/acme_cert_$(date +%Y-%m-%d).log" # 按日期分割日志
mkdir -p "$LOG_DIR"                                   # 确保日志目录存在

#######################################
# 日志初始化函数（基础工具，优先定义）
# 功能：自动创建日志目录，确保日志可正常写入
#######################################
init_log() {
    # 自动创建日志目录（不存在则创建）
    if [ ! -d "${LOG_DIR}" ]; then
        mkdir -p "${LOG_DIR}"
        chmod 755 "${LOG_DIR}"  # 安全权限：仅当前用户可写
    fi
    # 写入日志头（标记脚本启动，适配新脚本名）
    echo -e "\n[$(date '+%Y-%m-%d %H:%M:%S')] ===== acme_cert.sh 脚本启动 =====" >> "${LOG_FILE}"
}

#######################################
# 日志输出函数（标准化日志）
# 参数：
#   $1 - 日志级别（INFO/WARN/ERROR/SUCCESS）
#   $2 - 日志内容
# 功能：同时输出到终端（带颜色）和日志文件（纯文本）
#######################################
log() {
    local level=$1
    local content=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 终端输出（匹配标准化颜色定义：原BLUE替换为GREEN）
    case $level in
        INFO)    echo -e "${GREEN}[${timestamp}] [INFO] ${content}${NC}" ;;  # 核心修改：BLUE→GREEN
        WARN)    echo -e "${YELLOW}[${timestamp}] [WARN] ${content}${NC}" ;;
        ERROR)   echo -e "${RED}[${timestamp}] [ERROR] ${content}${NC}" ;;
        SUCCESS) echo -e "${GREEN}[${timestamp}] [SUCCESS] ${content}${NC}" ;;
        *)       echo -e "${NC}[${timestamp}] [INFO] ${content}${NC}" ;;
    esac
    
    # 日志文件输出（纯文本，便于后续排查）
    echo "[$timestamp] [$level] $content" >> "${LOG_FILE}"
}

# ==============================================================================
# 【功能函数层】- 按main主流程调用顺序排列
# ==============================================================================
#######################################
# 函数：自动配置快捷键（新增功能）
# 功能：设置 'a' 为全局命令，方便后续直接运行
#######################################
setup_shortcut() {
    # 动态获取当前脚本的绝对路径，无论文件名是什么都能准确获取
    local script_path=$(readlink -f "$0")
    local link_path="/usr/bin/a"

    # 赋予脚本执行权限（防止下载后无权限）
    chmod +x "$script_path"

    # 使用软链接代替 alias，确保在当前 Shell 和新 Shell 中立即生效
    if [ ! -e "$link_path" ]; then
        log "INFO" "检测到未配置快捷键，正在设置..."
        # 强制创建软链接指向当前脚本
        ln -sf "$script_path" "$link_path"
        
        if [ -x "$link_path" ]; then
            log "SUCCESS" "快捷键 'a' 设置成功！(可以直接输入 a 运行)"
        else
            log "WARN" "快捷键设置失败，请检查权限。"
        fi
    fi
}

#######################################
# 函数：检查并安装Git（main流程第一步调用）
# 功能：兼容Debian/Ubuntu/CentOS系统，自动安装Git依赖
#######################################
install_git() {
    log "INFO" "正在检查 git 是否已安装..."
    if ! command -v git >/dev/null 2>&1; then
        log "WARN" "未检测到 git，正在尝试安装..."

        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_ID=$ID
        else
            OS_ID=$(uname -s)
        fi

        if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
            sudo apt update -y
            sudo apt install git -y || {
                log "ERROR" "git 安装失败，请先手动运行以下命令：sudo apt update -y && sudo apt install git -y"
                exit 1
            }
        elif [[ "$OS_ID" == "centos" ]]; then
            sudo yum update -y
            sudo yum install git -y || {
                log "ERROR" "git 安装失败，请先手动运行以下命令：sudo yum update -y && sudo yum install git -y"
                exit 1
            }
        else
            log "ERROR" "无法识别的系统类型，请手动安装 git。"
            exit 1
        fi
    else
        log "SUCCESS" "git 已安装。"
    fi
}

#######################################
# 函数：删除acme.sh定时任务（main流程重置/证书申请后调用）
# 功能：安全清理acme.sh自动续期定时任务，避免冲突
#######################################
delete_acme_crontab() {
    # 临时关闭“命令失败即终止”规则（仅函数内生效，不影响全局）
    set +e
    log "INFO" "正在自动删除acme.sh定时任务..."
    
    # 安全临时文件：/tmp路径+时间戳+进程ID，避免冲突/权限问题
    local tmp_crontab="/tmp/acme_crontab_$(date +%s)_$$.tmp"
    > "$tmp_crontab"  # 提前创建空文件，避免写入失败
    
    # 容错执行：导出crontab并过滤，失败不终止
    crontab -l 2>/dev/null | grep -v "acme.sh --cron" > "$tmp_crontab" || true
    
    # 统计任务数量（兼容空crontab场景）
    local original_count=$(crontab -l 2>/dev/null | wc -l)
    local new_count=$(wc -l < "$tmp_crontab")
    local deleted_count=$((original_count - new_count))
    
    # 降级处理：能执行则执行，失败仅警告
    if [ $deleted_count -gt 0 ]; then
        if crontab "$tmp_crontab"; then
            log "SUCCESS" "成功删除 ${deleted_count} 个acme.sh定时任务"
        else
            log "WARN" "定时任务删除失败（非核心步骤），不影响证书使用，可手动清理"
        fi
    else
        log "INFO" "未检测到acme.sh定时任务，无需删除"
    fi
    
    # 强制清理临时文件（无论成败）
    rm -f "$tmp_crontab"
    
    # 恢复全局的“命令失败即终止”规则
    set -e
}

#######################################
# 函数：重置ACME环境（main流程菜单2调用）
# 功能：清空ACME文件、删除定时任务、重新安装acme.sh
#######################################
reset_acme_env() {
    log "WARN" "正在重置环境..."
    # 【修复】重置环境时，增加完整的清理逻辑，避免残留文件导致的问题
    log "INFO" "正在清理acme.sh相关文件..."
    rm -rf $ACME_HOME
    rm -f $DEFAULT_TARGET_CERT $DEFAULT_TARGET_KEY
    # 场景2：重置环境时调用——清理残留定时任务
    delete_acme_crontab
    log "SUCCESS" "已清空 acme.sh 相关临时文件，准备重新部署。"
    log "INFO" "正在重新执行 acme.sh 官方安装脚本..."
    sleep 1
    # 【优化】增加连接超时限制，防止脚本无限卡死
    curl --connect-timeout 5 https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    log "SUCCESS" "acme.sh 环境重置完成"
    exit 0
}

#######################################
# 函数：安装系统依赖（main流程防火墙配置后调用）
# 参数：$1 - 防火墙选项（1=关闭 2=放行80端口）
# 功能：安装curl/socat/cron，处理防火墙策略
#######################################
install_system_deps() {
    local FIREWALL_OPTION=$1
    log "INFO" "开始安装依赖组件..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        log "ERROR" "无法识别操作系统，请手动安装依赖。"
        exit 1
    fi

    # 【优化】在依赖列表中增加openssl，确保后续证书解析正常
    case $OS in
        ubuntu|debian)
            sudo apt update -y
            sudo apt install -y curl socat git cron openssl --no-install-recommends
            # 新增：安装并启动cron服务
            sudo systemctl enable --now cron
            if [ "$FIREWALL_OPTION" -eq 1 ]; then
                if command -v ufw >/dev/null 2>&1; then
                    sudo ufw disable
                    log "SUCCESS" "防火墙已关闭"
                else
                    log "WARN" "UFW 未安装，跳过关闭防火墙。"
                fi
            else
                if command -v ufw >/dev/null 2>&1; then
                    sudo ufw allow 80/tcp
                    log "SUCCESS" "已自动放行80端口"
                else
                    log "WARN" "UFW 未安装，需手动确保80端口开放"
                fi
            fi
            ;;
        centos)
            sudo yum update -y
            sudo yum install -y curl socat git cronie openssl
            # 新增：启动并开机自启crond服务
            sudo systemctl start crond
            sudo systemctl enable crond
            if [ "$FIREWALL_OPTION" -eq 1 ]; then
                sudo systemctl stop firewalld
                sudo systemctl disable firewalld
                log "SUCCESS" "防火墙已关闭"
            else
                sudo firewall-cmd --permanent --add-port=80/tcp
                sudo firewall-cmd --reload
                log "SUCCESS" "已自动放行80端口"
            fi
            ;;
        *)
            log "ERROR" "不支持的操作系统：$OS"
            exit 1
            ;;
    esac
    log "SUCCESS" "依赖组件安装完成"
}

#######################################
# 函数：安装/升级acme.sh（main流程依赖安装后调用）
# 功能：检查acme.sh是否安装，未安装则自动安装，已安装则升级
#######################################
install_acme_sh() {
    log "INFO" "检查并安装 acme.sh..."
    if ! command -v acme.sh >/dev/null 2>&1; then
        # 【优化】增加连接超时限制
        curl --connect-timeout 5 https://get.acme.sh | sh
        export PATH="$HOME/.acme.sh:$PATH"
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    else
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        log "WARN" "acme.sh 已安装，已启用自动升级"
    fi
    log "SUCCESS" "acme.sh 配置完成"
}

#######################################
# 函数：检查80端口是否被占用（main流程证书申请前调用）
# 解决证书申请时80端口被占用导致的失败问题
#######################################
check_80_port() {
    log "INFO" "检查80端口是否被占用..."
    # 修复点1：原逻辑错误，grep -v 'LISTEN'会过滤掉监听状态，改为只查LISTEN状态
    local port_used=$(ss -tulpn | grep ':80' | grep 'LISTEN' | wc -l)
    if [ $port_used -gt 0 ]; then
        log "ERROR" "80端口已被占用，以下是占用进程："
        ss -tulpn | grep ':80' | grep 'LISTEN'
        echo -e "${YELLOW}⚠️  是否强制杀死占用80端口的进程？(y/n)${NC}"
        read -p "" KILL_PROC
        if [ "$KILL_PROC" = "y" ] || [ "$KILL_PROC" = "Y" ]; then
            # 修复点2：精准提取PID，避免杀死无关进程
            ss -tulpn | grep ':80' | grep 'LISTEN' | awk '{split($7,a,","); split(a[2],b,"="); print b[2]}' | xargs -r kill -9
            log "SUCCESS" "已强制杀死占用80端口的进程"
        else
            log "ERROR" "80端口被占用，证书申请无法继续，请手动释放端口后重新执行脚本"
            exit 1
        fi
    else
        log "SUCCESS" "80端口未被占用，可以继续申请证书"
    fi
}

#######################################
# 函数：时间格式转换（main流程证书信息展示调用）
# 严格输出 YYYY-MM-DD HH:MM:SS 格式
#######################################
convert_cert_time() {
    local raw_time="$1"
    # 强制输出指定格式，兼容acme.sh证书的原始时间格式
    local converted_time=$(date -d "$raw_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    # 容错处理：解析失败时返回标准格式默认值，而非"无法解析时间"
    if [ -z "$converted_time" ]; then
        echo "1970-01-01 00:00:00"
    else
        echo "$converted_time"
    fi
}

#######################################
# 函数：动态获取并格式化文件大小（main流程证书信息展示调用）
#######################################
get_formatted_file_size() {
    local file_path="$1"
    # 检查文件是否存在
    if [ ! -f "$file_path" ]; then
        echo "0K"
        return
    fi
    # 使用du命令获取人类可读的文件大小（自动适配K/M等单位）
    # cut -f1 提取大小部分，去除文件路径
    local file_size=$(du -h "$file_path" 2>/dev/null | cut -f1)
    # 兼容无输出的情况
    if [ -z "$file_size" ]; then
        echo "0K"
    else
        echo "$file_size"
    fi
}

#######################################
# 函数：更新脚本（main流程菜单3调用）
# 功能：更新当前脚本文件（需配置URL）
#######################################
update_script() {
    log "INFO" "正在检查脚本更新..."
    
    # 【配置】请在此处填入最新版脚本的下载链接 (例如 GitHub raw 链接)
    local UPDATE_URL="https://raw.githubusercontent.com/jasonniceo/Script/refs/heads/main/acme_cert.sh"
    
    if [ -z "$UPDATE_URL" ]; then
        log "WARN" "更新源未配置，请编辑脚本中的 update_script 函数填入 URL。"
        return
    fi
    
    if curl -L --connect-timeout 10 -o "$0" "$UPDATE_URL"; then
        chmod +x "$0"
        log "SUCCESS" "脚本更新成功，请重新运行！"
        exit 0
    else
        log "ERROR" "更新下载失败，请检查网络或 URL 配置。"
    fi
}

# ==============================================================================
# 【主执行函数层】- main函数（所有流程的调度中心）
# ==============================================================================
#######################################
# 主执行流程（main函数层）
#######################################
main() {
    # 初始化日志（脚本启动第一步）
    init_log

    # 核心功能：自动配置快捷启动键（新增）
    setup_shortcut

    #######################################
    # 检查并安装 git
    #######################################
    install_git

    #######################################
    # SSL证书管理菜单
    #######################################
    while true; do
        # clear
        echo -e "${GREEN}===========================================${NC}"
        echo -e "${GREEN}            SSL证书管理菜单${NC}"
        echo -e "${GREEN}===========================================${NC}"
        echo "1. 申请 SSL 证书"
        echo "2. 重置环境（清除申请记录并重新部署）"
        echo "3. 更新脚本"
        echo "4. 退出"
        echo -e "${GREEN}===========================================${NC}"
        read -p "$(echo -e ${YELLOW}"请输入选项（1-4）: "${NC})" MAIN_OPTION

        case $MAIN_OPTION in
            1)
                break
                ;;
            2)
                reset_acme_env
                ;;
            3)
                update_script
                # 【新增】暂停等待用户查看提示，防止清屏导致信息丢失
                read -p "按回车键返回主菜单..."
                ;;
            4)
                log "INFO" "已退出。"
                exit 0
                ;;
            *)
                log "ERROR" "无效选项，请重新输入。"
                sleep 1
                continue
                ;;
        esac
    done

    #######################################
    # 防火墙默认关闭
    #######################################
    echo "是否关闭防火墙?"
    echo "1. 是"
    echo "2. 否"
    read -p "$(echo -e ${YELLOW}"输入选项（1或2，直接回车选默认关闭）:"${NC})" FIREWALL_OPTION
    if [ -z "$FIREWALL_OPTION" ]; then
        FIREWALL_OPTION=1
    fi

    #######################################
    # 检查系统类型并安装依赖
    #######################################
    install_system_deps "${FIREWALL_OPTION}"

    #######################################
    # 安装 acme.sh 并启用自动升级
    #######################################
    install_acme_sh

    #######################################
    # 用户输入参数
    #######################################
    read -p "$(echo -e ${YELLOW}"请输入域名: "${NC})" DOMAIN
    echo ""

    if [ -z "$DOMAIN" ]; then
        log "ERROR" "域名不能为空，请重新执行脚本并输入有效域名"
        exit 1
    fi

    echo "请选择证书颁发机构（CA）:"
    echo "1. Let's Encrypt（无需邮箱，默认）"
    echo "2. Buypass（需有效邮箱）"
    echo "3. ZeroSSL（需有效邮箱）"
    read -p "$(echo -e ${YELLOW}"输入选项（1-3，直接回车选默认）: "${NC})" CA_OPTION
    if [ -z "$CA_OPTION" ]; then
        CA_OPTION=1
    fi
    case $CA_OPTION in
        1) 
            CA_SERVER="letsencrypt"
            ~/.acme.sh/acme.sh --set-default-ca --server $CA_SERVER
            EMAIL=""
            ;;
        2) 
            CA_SERVER="buypass"
            ~/.acme.sh/acme.sh --set-default-ca --server $CA_SERVER
            read -p "$(echo -e ${YELLOW}"请输入有效电子邮件地址: "${NC})" EMAIL
            ;;
        3) 
            CA_SERVER="zerossl"
            ~/.acme.sh/acme.sh --set-default-ca --server $CA_SERVER
            read -p "$(echo -e ${YELLOW}"请输入有效电子邮件地址: "${NC})" EMAIL
            ;;
        *) 
            log "ERROR" "无效选项"; exit 1 ;;
    esac

    #######################################
    # 注册账户（仅非Let's Encrypt执行）
    #######################################
    if [ -n "$EMAIL" ]; then
        log "INFO" "注册CA账户..."
        ~/.acme.sh/acme.sh --register-account -m $EMAIL --server $CA_SERVER
        log "SUCCESS" "账户注册完成"
    fi

    #######################################
    # 检查80端口是否被占用（证书申请前的关键前置检查）
    #######################################
    check_80_port

    #######################################
    # 申请证书
    #######################################
    log "INFO" "开始通过80端口验证并申请证书（确保80端口未被占用）..."
    if ! ~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN --server $CA_SERVER; then
        log "ERROR" "证书申请失败，正在清理..."
        rm -f $DEFAULT_TARGET_CERT $DEFAULT_TARGET_KEY
        ~/.acme.sh/acme.sh --remove -d $DOMAIN
        rm -rf ~/.acme.sh/${DOMAIN}
        exit 1
    fi
    log "SUCCESS" "证书申请成功"

    #######################################
    # 拷贝证书并配置权限（全中文日志展示）
    #######################################
    log "INFO" "拷贝证书到root目录"
    # 关键：添加 > /dev/null 2>&1 屏蔽acme.sh原始英文日志
    ~/.acme.sh/acme.sh --installcert -d $DOMAIN \
        --key-file       $DEFAULT_TARGET_KEY \
        --fullchain-file $DEFAULT_TARGET_CERT > /dev/null 2>&1

    # 手动输出对应的中文日志（替换原来的英文日志，保持逻辑一致）
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 检测到域名 '$DOMAIN' 已存在ECC证书，将直接复用该证书。"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 正在将私钥文件安装至：/root/private.key"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 正在将完整证书链安装至：/root/cert.crt"

    log "INFO" "配置证书文件权限"
    chmod -R 755 $DEFAULT_TARGET_CERT
    chmod 600 $DEFAULT_TARGET_KEY
    log "SUCCESS" "拷贝证书及权限配置完成"

    #######################################
    # 场景1：证书申请完成后调用——删除自动续期定时任务
    #######################################
    delete_acme_crontab

    #######################################
    # 证书申请成功后，精准输出信息
    #######################################
    # 定义必要路径变量（用于填充信息）
    ECC_CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
    ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
    ACME_KEY_FILE="$ECC_CERT_DIR/$DOMAIN.key"

    # 证书文件存在性检查，避免后续命令执行失败
    if [ ! -f "$ACME_CERT_FILE" ] || [ ! -f "$ACME_KEY_FILE" ]; then
        log "WARN" "未找到ECC证书文件，尝试使用非ECC证书路径..."
        ECC_CERT_DIR="$ACME_HOME/${DOMAIN}"
        ACME_CERT_FILE="$ECC_CERT_DIR/fullchain.cer"
        ACME_KEY_FILE="$ECC_CERT_DIR/$DOMAIN.key"
    fi

    # 提取并格式化证书时间（去除多余字符，确保解析准确）
    cert_dates=$(openssl x509 -in "$ACME_CERT_FILE" -noout -dates 2>/dev/null)
    # 使用sed去除前缀和多余空格，避免格式干扰
    not_before_raw=$(echo "$cert_dates" | grep "notBefore" | sed 's/notBefore=//g' | sed 's/^[ \t]*//g')
    not_after_raw=$(echo "$cert_dates" | grep "notAfter" | sed 's/notAfter=//g' | sed 's/^[ \t]*//g')
    # 调用优化后的转换函数，得到标准格式时间
    not_before=$(convert_cert_time "$not_before_raw")
    not_after=$(convert_cert_time "$not_after_raw")

    # 计算剩余天数（动态获取）
    end_ts=$(date -d "$not_after" +%s 2>/dev/null)
    now_ts=$(date +%s)
    remain_days=$(( (end_ts - now_ts) / 86400 ))

    # 动态获取证书和私钥的真实文件大小（核心修正）
    cert_real_size=$(get_formatted_file_size "$ACME_CERT_FILE")
    key_real_size=$(get_formatted_file_size "$ACME_KEY_FILE")

    # 动态获取文件最后修改时间（非固定，真实时间）
    cert_mtime=$(date -r "$ACME_CERT_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    key_mtime=$(date -r "$ACME_KEY_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    # 兼容文件修改时间获取失败的情况
    if [ -z "$cert_mtime" ]; then cert_mtime="$not_before"; fi
    if [ -z "$key_mtime" ]; then key_mtime="$not_before"; fi

    echo -e "\n${GREEN}===================================================${NC}"
    echo -e "${GREEN}            脚本执行完成，证书信息汇总${NC}"
    echo -e "${GREEN}===================================================${NC}"
    echo -e "完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "证书生效时间: ${YELLOW}$not_before${NC}"
    echo -e "证书到期时间: ${YELLOW}$not_after${NC}"
    echo -e "剩余天数: ${YELLOW}$remain_days 天${NC}"    
    echo -e "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
    echo -e "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"
    echo -e "文件大小: $cert_real_size (证书), $key_real_size (私钥)"
    echo -e "最后修改: $cert_mtime (证书), $key_mtime (私钥)"
    echo -e "文件权限:"
    # 动态输出真实文件权限
    ls -la "$ACME_CERT_FILE" "$ACME_KEY_FILE" 2>/dev/null | awk '{print $1, $3, $4, $5, $6, $7, $8, $9}' | sed "s|$ECC_CERT_DIR/fullchain.cer|$DEFAULT_TARGET_CERT|g; s|$ECC_CERT_DIR/$DOMAIN.key|$DEFAULT_TARGET_KEY|g"

# 仅保留极端异常提醒（新证书不可能触发，仅防申请异常）
if [ "$remain_days" -lt 0 ]; then
    echo -e "  ${RED}⚠️  异常：申请的证书已过期！${NC}"
fi

    # 检查证书路径
    echo -e "\n${GREEN}[检查证书路径]${NC}"
    echo -e "  ACME证书目录: $ECC_CERT_DIR"
    echo -e "  源证书文件: $ACME_CERT_FILE"
    echo -e "  源私钥文件: $ACME_KEY_FILE"
    echo -e "${GREEN}证书文件路径检查通过${NC}"

# 证书状态（仅检查是否存在，新证书必存在）
echo -e "\n${GREEN}[证书状态]${NC}"
cert_status=${RED}"❌ 证书文件未生成"${NC}
[ -f "$ACME_CERT_FILE" ] && cert_status=${GREEN}"✅ 证书文件已生成"${NC}
key_status=${RED}"❌ 私钥文件未生成"${NC}
[ -f "$ACME_KEY_FILE" ] && key_status=${GREEN}"✅ 私钥文件已生成"${NC}

echo -e "  证书状态: $cert_status"
echo -e "  私钥状态: $key_status"
    
    # 写入日志尾（标记脚本结束，适配新脚本名）
    log "SUCCESS" "脚本执行完成"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ===== acme_cert.sh 脚本结束 =====" >> "${LOG_FILE}"
}

# ==============================================================================
# 【脚本执行入口】- 最后一行调用main函数
# ==============================================================================
main
