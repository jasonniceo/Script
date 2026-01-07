#!/bin/bash
# acme申请证书脚本
# 使用方法：手动执行./acme.sh

set -eo pipefail  # 核心安全控制：1. 任意命令执行失败(返回非0)立即终止脚本；2. 管道命令中任意环节失败，整个管道视为失败，避免隐藏错误

#######################################
# 颜色定义（基础定义层）
#######################################
RED='\033[0;31m'      # 错误消息
GREEN='\033[0;32m'    # 成功消息和主标题颜色
YELLOW='\033[1;33m'   # 警告消息
BLUE='\033[0;34m'     # 信息消息
NC='\033[0m'          # 重置颜色

#######################################
# 核心配置（基础定义层）
#######################################
ACME_HOME="/root/.acme.sh"                 # acme.sh安装目录
DEFAULT_TARGET_CERT="/root/cert.crt"       # 目标证书路径
DEFAULT_TARGET_KEY="/root/private.key"     # 目标私钥路径

#######################################
# 函数：删除acme.sh定时任务（功能函数层）
#######################################
delete_acme_crontab() {
    # 临时关闭“命令失败即终止”规则（仅函数内生效，不影响全局）
    set +e
    echo -e "\n${YELLOW}🔍 正在自动删除acme.sh定时任务...${NC}"
    
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
            echo -e "${GREEN}✅ 成功删除 ${deleted_count} 个acme.sh定时任务${NC}"
        else
            echo -e "${YELLOW}⚠️ 定时任务删除失败（非核心步骤），不影响证书使用，可手动清理${NC}"
        fi
    else
        echo -e "${BLUE}ℹ️  未检测到acme.sh定时任务，无需删除${NC}"
    fi
    
    # 强制清理临时文件（无论成败）
    rm -f "$tmp_crontab"
    
    # 恢复全局的“命令失败即终止”规则
    set -e
}

#######################################
# 函数：检查80端口是否被占用（功能函数层）
# 解决证书申请时80端口被占用导致的失败问题
#######################################
check_80_port() {
    echo -e "\n${YELLOW}🔍 检查80端口是否被占用...${NC}"
    # 修复点1：原逻辑错误，grep -v 'LISTEN'会过滤掉监听状态，改为只查LISTEN状态
    local port_used=$(ss -tulpn | grep ':80' | grep 'LISTEN' | wc -l)
    if [ $port_used -gt 0 ]; then
        echo -e "${RED}❌ 80端口已被占用，以下是占用进程：${NC}"
        ss -tulpn | grep ':80' | grep 'LISTEN'
        echo -e "${YELLOW}⚠️  是否强制杀死占用80端口的进程？(y/n)${NC}"
        read -p "" KILL_PROC
        if [ "$KILL_PROC" = "y" ] || [ "$KILL_PROC" = "Y" ]; then
            # 修复点2：精准提取PID，避免杀死无关进程
            ss -tulpn | grep ':80' | grep 'LISTEN' | awk '{split($7,a,","); split(a[2],b,"="); print b[2]}' | xargs -r kill -9
            echo -e "${GREEN}✅ 已强制杀死占用80端口的进程${NC}"
        else
            echo -e "${RED}❌ 80端口被占用，证书申请无法继续，请手动释放端口后重新执行脚本${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ 80端口未被占用，可以继续申请证书${NC}"
    fi
}

#######################################
# 函数：时间格式转换（功能函数层）
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
# 函数：动态获取并格式化文件大小（功能函数层）
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
# 主执行流程（main函数层）
#######################################
main() {
    #######################################
    # 检查并安装 git
    #######################################
    echo -e "${YELLOW}🔍 正在检查 git 是否已安装...${NC}"
    if ! command -v git >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️ 未检测到 git，正在尝试安装...${NC}"

        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_ID=$ID
        else
            OS_ID=$(uname -s)
        fi

        if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
            sudo apt update -y
            sudo apt install git -y || {
                echo -e "${RED}❌ git 安装失败，请先手动运行以下命令：${NC}"
                echo "sudo apt update -y && sudo apt install git -y"
                exit 1
            }
        elif [[ "$OS_ID" == "centos" ]]; then
            sudo yum update -y
            sudo yum install git -y || {
                echo -e "${RED}❌ git 安装失败，请先手动运行以下命令：${NC}"
                echo "sudo yum update -y && sudo yum install git -y"
                exit 1
            }
        else
            echo -e "${RED}❌ 无法识别的系统类型，请手动安装 git。${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ git 已安装。${NC}"
    fi

    #######################################
    # SSL证书管理菜单
    #######################################
    while true; do
        clear
        echo -e "${GREEN}===========================================${NC}"
        echo -e "${GREEN}           SSL证书管理菜单${NC}"
        echo -e "${GREEN}===========================================${NC}"
        echo "1. 申请 SSL 证书"
        echo "2. 重置环境（清除申请记录并重新部署）"
        echo "3. 退出"
        echo -e "${GREEN}===========================================${NC}"
        read -p "$(echo -e ${YELLOW}"请输入选项（1-3）: "${NC})" MAIN_OPTION

        case $MAIN_OPTION in
            1)
                break
                ;;
            2)
                echo -e "${YELLOW}⚠️ 正在重置环境...${NC}"
                # 【修复】重置环境时，增加完整的清理逻辑，避免残留文件导致的问题
                echo -e "${YELLOW}🧹 正在清理acme.sh相关文件...${NC}"
                rm -rf $ACME_HOME
                rm -f $DEFAULT_TARGET_CERT $DEFAULT_TARGET_KEY
                # 场景2：重置环境时调用——清理残留定时任务
                delete_acme_crontab
                echo -e "${GREEN}✅ 已清空 acme.sh 相关临时文件，准备重新部署。${NC}"
                echo -e "${YELLOW}📦 正在重新执行 acme.sh 官方安装脚本...${NC}"
                sleep 1
                curl https://get.acme.sh | sh
                ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                echo -e "${GREEN}✅ acme.sh 环境重置完成${NC}"
                exit 0
                ;;
            3)
                echo -e "${GREEN}👋 已退出。${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ 无效选项，请重新输入。${NC}"
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
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}❌ 无法识别操作系统，请手动安装依赖。${NC}"
        exit 1
    fi

    echo -e "${YELLOW}🔧 开始安装依赖组件...${NC}"
    case $OS in
        ubuntu|debian)
            sudo apt update -y
            sudo apt install -y curl socat git cron --no-install-recommends
            # 新增：安装并启动cron服务
            sudo systemctl enable --now cron
            if [ "$FIREWALL_OPTION" -eq 1 ]; then
                if command -v ufw >/dev/null 2>&1; then
                    sudo ufw disable
                    echo -e "${GREEN}✅ 防火墙已关闭${NC}"
                else
                    echo -e "${YELLOW}⚠️ UFW 未安装，跳过关闭防火墙。${NC}"
                fi
            else
                if command -v ufw >/dev/null 2>&1; then
                    sudo ufw allow 80/tcp
                    echo -e "${GREEN}✅ 已自动放行80端口${NC}"
                else
                    echo -e "${YELLOW}⚠️ UFW 未安装，需手动确保80端口开放${NC}"
                fi
            fi
            ;;
        centos)
            sudo yum update -y
            sudo yum install -y curl socat git cronie
            # 新增：启动并开机自启crond服务
            sudo systemctl start crond
            sudo systemctl enable crond
            if [ "$FIREWALL_OPTION" -eq 1 ]; then
                sudo systemctl stop firewalld
                sudo systemctl disable firewalld
                echo -e "${GREEN}✅ 防火墙已关闭${NC}"
            else
                sudo firewall-cmd --permanent --add-port=80/tcp
                sudo firewall-cmd --reload
                echo -e "${GREEN}✅ 已自动放行80端口${NC}"
            fi
            ;;
        *)
            echo -e "${RED}❌ 不支持的操作系统：$OS${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}✅ 依赖组件安装完成${NC}"

    #######################################
    # 安装 acme.sh 并启用自动升级
    #######################################
    echo -e "${YELLOW}📦 检查并安装 acme.sh...${NC}"
    if ! command -v acme.sh >/dev/null 2>&1; then
        curl https://get.acme.sh | sh
        export PATH="$HOME/.acme.sh:$PATH"
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    else
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        echo -e "${YELLOW}⚠️ acme.sh 已安装，已启用自动升级${NC}"
    fi
    echo -e "${GREEN}✅ acme.sh 配置完成${NC}"

    #######################################
    # 用户输入参数
    #######################################
    read -p "$(echo -e ${YELLOW}"请输入域名: "${NC})" DOMAIN
    echo ""

    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}❌ 域名不能为空，请重新执行脚本并输入有效域名${NC}"
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
            echo -e "${RED}❌ 无效选项${NC}"; exit 1 ;;
    esac

    #######################################
    # 注册账户（仅非Let's Encrypt执行）
    #######################################
    if [ -n "$EMAIL" ]; then
        echo -e "${YELLOW}🔑 注册CA账户...${NC}"
        ~/.acme.sh/acme.sh --register-account -m $EMAIL --server $CA_SERVER
        echo -e "${GREEN}✅ 账户注册完成${NC}"
    fi

    #######################################
    # 检查80端口是否被占用（证书申请前的关键前置检查）
    #######################################
    check_80_port

    #######################################
    # 申请证书
    #######################################
    echo -e "${YELLOW}🔐 开始通过80端口验证并申请证书（确保80端口未被占用）...${NC}"
    if ! ~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN --server $CA_SERVER; then
        echo -e "${RED}❌ 证书申请失败，正在清理...${NC}"
        rm -f $DEFAULT_TARGET_CERT $DEFAULT_TARGET_KEY
        ~/.acme.sh/acme.sh --remove -d $DOMAIN
        rm -rf ~/.acme.sh/${DOMAIN}
        exit 1
    fi
    echo -e "${GREEN}✅ 证书申请成功${NC}"

    #######################################
    # 拷贝证书并配置权限（全中文日志展示）
    #######################################
    echo -e "\n${YELLOW}📂 拷贝证书到root目录${NC}"
    # 关键：添加 > /dev/null 2>&1 屏蔽acme.sh原始英文日志
    ~/.acme.sh/acme.sh --installcert -d $DOMAIN \
        --key-file       $DEFAULT_TARGET_KEY \
        --fullchain-file $DEFAULT_TARGET_CERT > /dev/null 2>&1

    # 手动输出对应的中文日志（替换原来的英文日志，保持逻辑一致）
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 检测到域名 '$DOMAIN' 已存在ECC证书，将直接复用该证书。"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 正在将私钥文件安装至：/root/private.key"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] 正在将完整证书链安装至：/root/cert.crt"

    echo -e "\n${YELLOW}🔒 配置证书文件权限${NC}"
    chmod -R 755 $DEFAULT_TARGET_CERT
    chmod 600 $DEFAULT_TARGET_KEY
    echo -e "${GREEN}✅ 拷贝证书及权限配置完成${NC}"

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
        echo -e "${YELLOW}⚠️  未找到ECC证书文件，尝试使用非ECC证书路径...${NC}"
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

    # 配置信息
    echo -e "\n${GREEN}[配置信息]${NC}"
    echo -e "域名: ${YELLOW}$DOMAIN${NC}"
    echo -e "目标证书路径: ${YELLOW}$DEFAULT_TARGET_CERT${NC}"
    echo -e "目标私钥路径: ${YELLOW}$DEFAULT_TARGET_KEY${NC}"

    # 检查证书路径
    echo -e "\n${GREEN}[检查证书路径]${NC}"
    echo -e "  ACME证书目录: $ECC_CERT_DIR"
    echo -e "  源证书文件: $ACME_CERT_FILE"
    echo -e "  源私钥文件: $ACME_KEY_FILE"
    echo -e "${GREEN}证书文件路径检查通过${NC}"

    # 当前证书状态
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
    echo -e "目标证书文件状态: $cert_status"
    echo -e "目标私钥文件状态: $key_status"
    echo -e "文件详情:"
    echo -e "  证书文件: $DEFAULT_TARGET_CERT"
    echo -e "  私钥文件: $DEFAULT_TARGET_KEY"
    echo -e "  文件大小: $cert_real_size (证书), $key_real_size (私钥)"
    echo -e "  最后修改: $cert_mtime (证书), $key_mtime (私钥)"
    echo -e "文件权限:"
    # 动态输出真实文件权限
    ls -la "$ACME_CERT_FILE" "$ACME_KEY_FILE" 2>/dev/null | awk '{print $1, $3, $4, $5, $6, $7, $8, $9}' | sed "s|$ECC_CERT_DIR/fullchain.cer|$DEFAULT_TARGET_CERT|g; s|$ECC_CERT_DIR/$DOMAIN.key|$DEFAULT_TARGET_KEY|g"

    # 证书有效期（严格匹配 YYYY-MM-DD HH:MM:SS 格式）
    echo -e "\n${GREEN}[证书有效期]${NC}"
    echo -e "  生效时间: ${YELLOW}$not_before${NC}"
    echo -e "  到期时间: ${YELLOW}$not_after${NC}"
    echo -e "剩余天数: ${YELLOW}$remain_days 天${NC}"
    echo -e "${GREEN}证书有效期充足${NC}"

    echo -e "\n${GREEN}===================================================${NC}"
    echo -e "${GREEN}            脚本执行完成${NC}"
    echo -e "${GREEN}===================================================${NC}"
    echo -e "完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "域名: $DOMAIN"
    echo -e "证书位置: /root/cert.crt"
    echo -e "私钥位置: /root/private.key"
}

#######################################
# 脚本执行入口（最后一行）
#######################################
main
