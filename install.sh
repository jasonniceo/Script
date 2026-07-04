#!/bin/bash
# Oracle Cloud Keep-Alive Script (OAlive) - 三合一终极版（支持安装/升级/卸载）

set -e

WORK_DIR="/opt/oalive"
LOG_DIR="/var/log/oalive"
LOG_FILE="$LOG_DIR/oalive.log"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误：请使用 root 用户或 sudo 权限运行此脚本！"
    exit 1
fi

# ================= 卸载逻辑 =================
do_uninstall() {
    echo "=========================================================="
    echo "正在卸载 OAlive 保活脚本并清理系统残留..."
    echo "=========================================================="
    
    # 1. 停止并禁用所有相关服务
    echo "=> 正在停止 Systemd 服务和定时器..."
    systemctl stop cpu-limit.service memory-limit.service bandwidth_occupier.timer bandwidth_occupier.service 2>/dev/null || true
    systemctl disable cpu-limit.service memory-limit.service bandwidth_occupier.timer 2>/dev/null || true
    
    # 2. 清理服务配置文件
    echo "=> 正在清理 Systemd 配置文件..."
    rm -f /etc/systemd/system/cpu-limit.service \
          /etc/systemd/system/memory-limit.service \
          /etc/systemd/system/bandwidth_occupier.service \
          /etc/systemd/system/bandwidth_occupier.timer
    systemctl daemon-reload
    
    # 3. 清理文件目录和锁
    echo "=> 正在删除安装文件、日志和原子锁..."
    rm -rf "$WORK_DIR"
    rm -rf "$LOG_DIR"
    rm -rf /var/lock/oalive
    
    echo "=========================================================="
    echo "卸载成功！所有 OAlive 残留已干净清除。"
    echo "=========================================================="
}

# ================= 主菜单界面 =================
echo "=========================================================="
echo "      Oracle Cloud Keep-Alive (OAlive) - 管理脚本"
echo "=========================================================="
echo " 1. 安装 OAlive 保活脚本"
echo " 2. 升级 / 覆盖安装 OAlive 保活脚本"
echo " 3. 卸载 OAlive 保活脚本"
echo " 4. 退出"
echo "=========================================================="
read -p "请输入数字选择功能 [1-4] (默认 1): " MENU_CHOICE </dev/tty
MENU_CHOICE=${MENU_CHOICE:-1}

case "$MENU_CHOICE" in
    2)
        echo "=> 检测到升级请求，正在自动清理旧版本服务..."
        systemctl stop cpu-limit.service memory-limit.service bandwidth_occupier.timer 2>/dev/null || true
        rm -rf /var/lock/oalive/*
        ;;
    3)
        do_uninstall
        exit 0
        ;;
    4)
        echo "已退出。"
        exit 0
        ;;
    *)
        # 默认或输入1，继续往下走安装流程
        ;;
esac

# ================= 1. 交互式获取用户配置 =================
echo ""
echo "直接按回车(Enter)即可使用推荐的默认值。"
echo ""

# CPU：2到4核机器默认 核心数*20%，其他机器默认 25%
CORES=$(nproc)
if [ "$CORES" -ge 2 ] && [ "$CORES" -le 4 ]; then
    DEFAULT_CPU_QUOTA=$((CORES * 20))
else
    DEFAULT_CPU_QUOTA=25
fi

read -p "1. 请输入 CPU 占用百分比 (默认 $DEFAULT_CPU_QUOTA): " INPUT_CPU_QUOTA </dev/tty
CPU_QUOTA=${INPUT_CPU_QUOTA:-$DEFAULT_CPU_QUOTA}

read -p "2. 请输入内存占用百分比 (默认 25): " INPUT_MEM_PCT </dev/tty
MEM_PCT=${INPUT_MEM_PCT:-25}

read -p "3. 请输入网络消耗触发间隔/分钟 (默认 60): " INPUT_NET_INTERVAL </dev/tty
NET_INTERVAL=${INPUT_NET_INTERVAL:-60}

read -p "4. 请输入网络下载持续时间/分钟 (默认 6): " INPUT_NET_DURATION </dev/tty
NET_DURATION=${INPUT_NET_DURATION:-2}
NET_DURATION_SEC=$((NET_DURATION * 60))

read -p "5. 请输入网络限速/mbps (默认 50): " INPUT_NET_LIMIT </dev/tty
NET_LIMIT_RAW=${INPUT_NET_LIMIT:-50}
NET_LIMIT=$(echo "$NET_LIMIT_RAW" | grep -oE '[0-9]+' || echo 10)

echo ""
echo "=> 正在使用以下配置进行安装："
echo "CPU 限额: ${CPU_QUOTA}% | 内存分配: ${MEM_PCT}% | 网络触发: 每 ${NET_INTERVAL} 分钟 | 下载时长: ${NET_DURATION} 分钟 | 限速: ${NET_LIMIT} Mbps"
echo "=========================================================="
sleep 2

# ================= 2. 初始化环境与公共库 =================
mkdir -p "$WORK_DIR/bin"
mkdir -p "$LOG_DIR"
mkdir -p /var/lock/oalive

cat << 'EOF' > "$WORK_DIR/bin/oalive-lib.sh"
#!/bin/bash
LOG_FILE="/var/log/oalive/oalive.log"

log_msg() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] - $msg" >> "$LOG_FILE"
    if [ -f "$LOG_FILE" ]; then
        local size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$size" -gt 131072 ]; then
            mv -f "$LOG_FILE" "${LOG_FILE}.1"
        fi
    fi
}

acquire_lock() {
    local lock_name="$1"
    if ! mkdir "/var/lock/oalive/$lock_name.lock" 2>/dev/null; then
        log_msg "Warning: 锁 $lock_name 已存在，跳过本次执行。"
        exit 0
    fi
}

release_lock() {
    local lock_name="$1"
    rm -rf "/var/lock/oalive/$lock_name.lock"
}
EOF

# ================= 3. 编写 CPU 守护逻辑 =================
cat << 'EOF' > "$WORK_DIR/bin/cpu-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "cpu"

PCT=$1
[ -z "$PCT" ] && PCT=25
log_msg "CPU worker started with ${PCT}% POSIX occupation logic."

RUN_SEC=$(awk "BEGIN {print $PCT / 100}")
SLEEP_SEC=$(awk "BEGIN {print 1 - $PCT / 100}")

worker() {
    while true; do :; done
}

worker &
PID=$!
trap "kill -9 $PID 2>/dev/null; release_lock 'cpu'; exit" EXIT TERM INT

while true; do
    kill -CONT $PID 2>/dev/null
    sleep $RUN_SEC
    kill -STOP $PID 2>/dev/null
    sleep $SLEEP_SEC
done
EOF

cat << EOF > /etc/systemd/system/cpu-limit.service
[Unit]
Description=OAlive CPU Limit Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $WORK_DIR/bin/cpu-worker.sh ${CPU_QUOTA}
Restart=always
RestartSec=10
CPUQuota=${CPU_QUOTA}%

[Install]
WantedBy=multi-user.target
EOF

# ================= 4. 编写内存分配逻辑 =================
cat << EOF > "$WORK_DIR/bin/mem-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "mem"
log_msg "Memory worker started."

MEM_TOTAL_KB=\$(awk '/MemTotal/ {print \$2}' /proc/meminfo)
TARGET_MB=\$((\$MEM_TOTAL_KB * ${MEM_PCT} / 100 / 1024))
MEM_FILE="/dev/shm/oalive_mem_occupy"

trap "rm -f \$MEM_FILE; release_lock 'mem'; exit" INT TERM EXIT

while true; do
    log_msg "Allocating \${TARGET_MB}MB memory..."
    AVAIL_MB=\$(df -m /dev/shm | awk 'NR==2 {print \$4}')
    if [ "\$TARGET_MB" -lt "\$AVAIL_MB" ]; then
        dd if=/dev/zero of="\$MEM_FILE" bs=1M count="\$TARGET_MB" 2>/dev/null
        log_msg "Memory allocated. Holding for 300s."
    else
        log_msg "Error: tmpfs space insufficient."
    fi
    sleep 300
    
    log_msg "Releasing memory. Resting for 300s."
    rm -f "\$MEM_FILE"
    sleep 300
done
EOF

cat << EOF > /etc/systemd/system/memory-limit.service
[Unit]
Description=OAlive Memory Limit Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $WORK_DIR/bin/mem-worker.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# ================= 5. 编写网络限流消耗逻辑 =================
cat << EOF > "$WORK_DIR/bin/net-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "net"
trap "release_lock 'net'; exit" INT TERM EXIT

TEST_URL="http://speedtest.tele2.net/100MB.zip"
log_msg "Network worker triggered."

LIMIT_BPS=\$((${NET_LIMIT} * 125000))
log_msg "Speed limit set to ${NET_LIMIT} Mbps (\${LIMIT_BPS} Bytes/s). Downloading for up to ${NET_DURATION} minutes."

timeout ${NET_DURATION_SEC} curl -s --limit-rate \${LIMIT_BPS} -o /dev/null "\$TEST_URL" || true
log_msg "Network consumption cycle finished."
EOF

cat << EOF > /etc/systemd/system/bandwidth_occupier.service
[Unit]
Description=OAlive Bandwidth Occupier Task
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $WORK_DIR/bin/net-worker.sh
EOF

cat << EOF > /etc/systemd/system/bandwidth_occupier.timer
[Unit]
Description=Timer for OAlive Bandwidth Occupier

[Timer]
OnBootSec=5min
OnUnitActiveSec=${NET_INTERVAL}min
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF

# ================= 6. 权限配置与系统激活 =================
chmod -R +x "$WORK_DIR/bin/"

echo "=> 重载 systemd 并启动所有 OAlive 服务..."
systemctl daemon-reload

systemctl enable cpu-limit.service
systemctl enable memory-limit.service
systemctl enable bandwidth_occupier.timer

systemctl restart cpu-limit.service
systemctl restart memory-limit.service
systemctl restart bandwidth_occupier.timer

echo "=========================================================="
echo "配置完成！服务已成功在后台运行/更新。"
echo "查看运行日志命令: tail -f $LOG_FILE"
echo "=========================================================="
