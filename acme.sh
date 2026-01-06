#!/bin/bash
# acme申请证书脚本
# 使用方法：可配置cron定时任务，或手动执行 .acme.sh
set -e

# ========= 定义颜色输出（增强提示）=========
RED='\033[0;31m'      # 错误消息
GREEN='\033[0;32m'    # 成功消息和主标题颜色
YELLOW='\033[1;33m'   # 警告消息
BLUE='\033[0;34m'     # 信息消息
NC='\033[0m'          # 重置颜色

# ========= 检查并安装 git =========
echo -e "${YELLOW}🔍 正在检查 git 是否已安装...${NC}"
if ! command -v git >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️ 未检测到 git，正在尝试安装...${NC}"

    # 判断系统类型
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

# ========= SSL证书管理菜单 =========
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
            echo -e "${GREEN}✅ 已清空 acme.sh 相关临时文件，准备重新部署。${NC}"
            echo -e "${YELLOW}📦 正在重新执行 acme.sh 官方安装脚本...${NC}"
            sleep 1
            curl https://get.acme.sh | sh
            ~/.acme.sh/acme.sh --upgrade --auto-upgrade
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

# ========= 用户输入参数 =========
read -p "$(echo -e ${YELLOW}"请输入域名: "${NC})" DOMAIN
# 域名输入后添加1个空行（小间隙）
echo ""

# 新增：域名非空验证（避免空域名申请）
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}❌ 域名不能为空，请重新执行脚本并输入有效域名${NC}"
    exit 1
fi

# 先选择CA，Let's Encrypt 设为默认选项（直接回车选中）
echo "请选择证书颁发机构（CA）:"
echo "1. Let's Encrypt（无需邮箱，默认）"
echo "2. Buypass（需有效邮箱）"
echo "3. ZeroSSL（需有效邮箱）"
read -p "$(echo -e ${YELLOW}"输入选项（1-3，直接回车选默认）: "${NC})" CA_OPTION
# 处理默认选项：输入为空则设为 1
if [ -z "$CA_OPTION" ]; then
    CA_OPTION=1
fi
case $CA_OPTION in
    1) 
        CA_SERVER="letsencrypt"
        # 设为默认CA
        ~/.acme.sh/acme.sh --set-default-ca --server $CA_SERVER
        # Let's Encrypt 跳过邮箱输入
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

# ========= 防火墙默认关闭 =========
echo "是否关闭防火墙?"
echo "1. 是"
echo "2. 否"
read -p "$(echo -e ${YELLOW}"输入选项（1或2，直接回车选默认关闭）:"${NC})" FIREWALL_OPTION
# 处理默认选项：输入为空则设为 1（关闭防火墙）
if [ -z "$FIREWALL_OPTION" ]; then
    FIREWALL_OPTION=1
fi

# ========= 检查系统类型并安装依赖 =========
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
        # 移除无用的 idn 工具安装（acme.sh 不支持 --idn，无需该工具）
        sudo apt install -y curl socat git cron --no-install-recommends
        if [ "$FIREWALL_OPTION" -eq 1 ]; then
            if command -v ufw >/dev/null 2>&1; then
                sudo ufw disable
                echo -e "${GREEN}✅ 防火墙已关闭${NC}"
            else
                echo -e "${YELLOW}⚠️ UFW 未安装，跳过关闭防火墙。${NC}"
            fi
        else
            # 未关闭防火墙时，自动放行80端口（证书申请必需）
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
        # 移除无用的 libidn 工具安装（acme.sh 不支持 --idn，无需该工具）
        sudo yum install -y curl socat git cronie
        sudo systemctl start crond
        sudo systemctl enable crond
        if [ "$FIREWALL_OPTION" -eq 1 ]; then
            sudo systemctl stop firewalld
            sudo systemctl disable firewalld
            echo -e "${GREEN}✅ 防火墙已关闭${NC}"
        else
            # 未关闭防火墙时，自动放行80端口（证书申请必需）
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

# ========= 安装 acme.sh 并启用自动升级 =========
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

# ========= 注册账户（仅非Let's Encrypt执行）=========
if [ -n "$EMAIL" ]; then
    echo -e "${YELLOW}🔑 注册CA账户...${NC}"
    ~/.acme.sh/acme.sh --register-account -m $EMAIL --server $CA_SERVER
    echo -e "${GREEN}✅ 账户注册完成${NC}"
fi

# ========= 申请证书 =========
echo -e "${YELLOW}📜 开始通过80端口验证并申请证书（确保80端口空闲）...${NC}"
# 核心修改：移除无效的 --idn 参数（acme.sh 不支持该参数，导致申请失败）
if ! ~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN --server $CA_SERVER; then
    echo -e "${RED}❌ 证书申请失败，正在清理...${NC}"
    rm -f /root/private.key /root/cert.crt
    ~/.acme.sh/acme.sh --remove -d $DOMAIN
    rm -rf ~/.acme.sh/${DOMAIN}
    exit 1
fi
echo -e "${GREEN}✅ 证书申请成功${NC}"

# ========= 部署证书并配置权限 =========
echo -e "${YELLOW}📂 部署证书到 /root 目录...${NC}"
~/.acme.sh/acme.sh --installcert -d $DOMAIN \
    --key-file       /root/private.key \
    --fullchain-file /root/cert.crt

# 配置证书权限（安全规范）
echo -e "${YELLOW}🔒 配置证书文件权限...${NC}"
chmod -R 755 /root/cert.crt
chmod 600 /root/private.key
echo -e "${GREEN}✅ 证书部署及权限配置完成${NC}"

# ========= 证书信息验证 =========
echo -e "${YELLOW}📋 验证证书信息...${NC}"
echo -e "${YELLOW}🔍 证书包含域名: ${NC}"
openssl x509 -in /root/cert.crt -noout -text | grep "DNS:"
echo -e "${YELLOW}📅 证书过期时间: ${NC}"
openssl x509 -in /root/cert.crt -noout -text | grep "Not After"
echo -e "${GREEN}✅ 证书信息验证完成${NC}"

# ========= 完成提示 =========
echo -e "\n${GREEN}🎉 SSL证书申请全流程完成!${NC}"
echo -e "${GREEN}📄 acme.sh 证书默认目录: ~/.acme.sh/${DOMAIN}${NC}"
echo -e "${GREEN}🔐 root目录私钥: /root/private.key${NC}"
echo -e "${GREEN}📄 root目录证书: /root/cert.crt${NC}"
