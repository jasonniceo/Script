#!/bin/bash
# Oracle Cloud Keep-Alive Script (OAlive) - 管道安全交互版

set -e

# ================= 0. 交互式获取用户配置 =================
echo "=========================================================="
echo "      Oracle Cloud Keep-Alive (OAlive) - 自定义安装"
echo "=========================================================="
echo "直接按回车(Enter)即可使用推荐的默认值。"
echo ""

# CPU 默认值计算：2-4核默认 核心数*20%，其余默认 25%
CORES=$(nproc)
if [ "$CORES" -ge 2 ] && [ "$CORES" -le 4 ]; then
    DEFAULT_CPU_QUOTA=$((CORES * 20))
else
    DEFAULT_CPU_QUOTA=25
fi

# </dev/tty 确保了通过 curl | bash 运行时，依然能捕获键盘输入
read -p "1. 请输入 CPU 占用百分比 (默认 $DEFAULT_CPU_QUOTA): " INPUT_CPU_QUOTA </dev/tty
CPU_QUOTA=${INPUT_CPU_QUOTA:-$DEFAULT_CPU_QUOTA}

read -p "2. 请输入内存占用百分比 (默认 25): " INPUT_MEM_PCT </dev/tty
MEM_PCT=${INPUT_MEM_PCT:-25}

read -p "3. 请输入网络消耗触发间隔/分钟 (默认 45): " INPUT_NET_INTERVAL </dev/tty
NET_INTERVAL=${INPUT_NET_INTERVAL:-45}

read -p "4. 请输入网络下载持续时间/分钟 (默认 6): " INPUT_NET_DURATION </dev/tty
NET_DURATION=${INPUT_NET_DURATION:-6}
NET_DURATION_SEC=$((NET_DURATION * 60))

read -p "5. 请输入网络限速百分比 (默认 30): " INPUT_NET_LIMIT </dev/tty
NET_LIMIT=${INPUT_NET_LIMIT:-30}

echo ""
echo "=> 正在使用以下配置进行安装："
echo "CPU 限额: ${CPU_QUOTA}% | 内存分配: ${MEM_PCT}% | 网络触发: 每 ${NET_INTERVAL} 分钟 | 下载时长: ${NET_DURATION} 分钟 | 限速: ${NET_LIMIT}%"
echo "=========================================================="
sleep 2

# ================= 1. 初始化环境与公共库 =================
WORK_DIR="/opt/oalive"
LOG_DIR="/var/log/oalive"
LOG_FILE="$LOG_DIR/oalive.log"

mkdir -p "$WORK_DIR/bin"
mkdir -p "$LOG_DIR"
mkdir -p /var/lock/oalive

# 使用 'EOF' 保持原有内部变量不被提早解析
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

# ================= 2. 编写 CPU 守护逻辑 =================
cat << 'EOF' > "$WORK_DIR/bin/cpu-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "cpu"
log_msg "CPU worker started."
while true; do
    dd if=/dev/urandom bs=1M count=1 2>/dev/null | sha256sum > /dev/null
done
EOF

# 写入带有用户配置的 systemd (注意这里使用 EOF 以便解析变量)
cat << EOF > /etc/systemd/system/cpu-limit.service
[Unit]
Description=OAlive CPU Limit Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $WORK_DIR/bin/cpu-worker.sh
Restart=always
RestartSec=10
CPUQuota=${CPU_QUOTA}%

[Install]
WantedBy=multi-user.target
EOF

# ================= 3. 编写内存分配逻辑 =================
# 动态注入用户配置的 MEM_PCT
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

# ================= 4. 编写网络测速及限流消耗逻辑 =================
cat << EOF > "$WORK_DIR/bin/net-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "net"
trap "release_lock 'net'; exit" INT TERM EXIT

TEST_URL="http://speedtest.tele2.net/100MB.zip"
log_msg "Network worker triggered. Starting speed test..."

SPEED_BPS=\$(curl -s -w "%{speed_download}" -m 15 -o /dev/null "\$TEST_URL" | cut -d'.' -f1)

if [ -z "\$SPEED_BPS" ] || [ "\$SPEED_BPS" -eq 0 ]; then
    log_msg "Speed test failed. Exiting."
    exit 0
fi

LIMIT_BPS=\$((\$SPEED_BPS * ${NET_LIMIT} / 100))
log_msg "Speed limit set to \${LIMIT_BPS} Bytes/s. Downloading for up to ${NET_DURATION} minutes."

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

# ================= 5. 权限配置与系统激活 =================
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
echo "安装完成且服务已在后台运行！"
echo "查看运行日志命令: tail -f $LOG_FILE"
echo "=========================================================="
