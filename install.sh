#!/bin/bash
# Oracle Cloud Keep-Alive Script (OAlive) - 终极完美版

set -e

WORK_DIR="/opt/oalive"
LOG_DIR="/var/log/oalive"
LOG_FILE="$LOG_DIR/oalive.log"

if [ "$EUID" -ne 0 ]; then echo "错误：请使用 root 用户运行！"; exit 1; fi

# ================= 卸载逻辑 =================
do_uninstall() {
    echo "=> 正在卸载..."
    systemctl stop cpu-limit.service memory-limit.service bandwidth_occupier.timer 2>/dev/null || true
    rm -f /etc/systemd/system/cpu-limit.service /etc/systemd/system/memory-limit.service /etc/systemd/system/bandwidth_occupier.service /etc/systemd/system/bandwidth_occupier.timer
    systemctl daemon-reload
    rm -rf "$WORK_DIR" "$LOG_DIR" /var/lock/oalive
    rm -f /dev/shm/oalive_mem_occupy
    echo "卸载成功。"
}

# ================= 主菜单 =================
echo "=========================================================="
echo "      Oracle Cloud Keep-Alive (OAlive) - 管理脚本"
echo "=========================================================="
echo " 1. 安装/更新 OAlive"
echo " 2. 卸载 OAlive"
echo " 3. 退出"
read -p "选择 [1-3] (默认 1): " MENU_CHOICE </dev/tty
MENU_CHOICE=${MENU_CHOICE:-1}
[[ "$MENU_CHOICE" == "2" ]] && do_uninstall && exit 0
[[ "$MENU_CHOICE" == "3" ]] && exit 0

# ================= 1. 获取配置 =================
read -p "1. CPU 目标占用百分比 (默认 25): " INPUT_CPU_QUOTA </dev/tty
CPU_QUOTA=${INPUT_CPU_QUOTA:-25}
read -p "2. 内存占用百分比 (默认 25): " INPUT_MEM_PCT </dev/tty
MEM_PCT=${INPUT_MEM_PCT:-25}
read -p "3. 网络触发间隔/分钟 (默认 60): " INPUT_NET_INTERVAL </dev/tty
NET_INTERVAL=${INPUT_NET_INTERVAL:-60}
read -p "4. 网络下载限速/mbps (默认 50): " INPUT_NET_LIMIT </dev/tty
NET_LIMIT=${INPUT_NET_LIMIT:-50}

mkdir -p "$WORK_DIR/bin" "$LOG_DIR" /var/lock/oalive

# ================= 2. 公共库 =================
cat << 'EOF' > "$WORK_DIR/bin/oalive-lib.sh"
log_msg() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "/var/log/oalive/oalive.log"; }
acquire_lock() { mkdir "/var/lock/oalive/$1.lock" 2>/dev/null || exit 0; }
release_lock() { rm -rf "/var/lock/oalive/$1.lock"; }
EOF

# ================= 3. CPU 守护 (随机波动) =================
cat << 'EOF' > "$WORK_DIR/bin/cpu-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "cpu"
trap "release_lock 'cpu'; exit" EXIT
while true; do
    # 生成上下 5% 的随机波动
    BASE=$1
    PCT=$((BASE - 5 + RANDOM % 11))
    RUN=$(awk "BEGIN {print $PCT / 100}")
    SLEEP=$(awk "BEGIN {print 1 - $PCT / 100}")
    worker() { while true; do :; done; }
    worker & PID=$!
    kill -CONT $PID 2>/dev/null; sleep $RUN; kill -STOP $PID 2>/dev/null; sleep $SLEEP
    kill -9 $PID 2>/dev/null
done
EOF

cat << EOF > /etc/systemd/system/cpu-limit.service
[Unit]
Description=OAlive CPU Limit Service
[Service]
Type=simple
ExecStartPre=-/bin/rm -rf /var/lock/oalive/cpu.lock
ExecStart=/bin/bash $WORK_DIR/bin/cpu-worker.sh ${CPU_QUOTA}
Restart=always
CPUQuota=${CPU_QUOTA}%
[Install]
WantedBy=multi-user.target
EOF

# ================= 4. 内存守护 =================
cat << EOF > "$WORK_DIR/bin/mem-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "mem"
MEM_TOTAL=\$(awk '/MemTotal/ {print \$2}' /proc/meminfo)
TARGET=\$((MEM_TOTAL * ${MEM_PCT} / 100 / 1024))
while true; do
    dd if=/dev/zero of=/dev/shm/oalive_mem_occupy bs=1M count=\$TARGET 2>/dev/null
    sleep 300; rm -f /dev/shm/oalive_mem_occupy; sleep 300
done
EOF

cat << EOF > /etc/systemd/system/memory-limit.service
[Unit]
Description=OAlive Memory Limit Service
[Service]
Type=simple
ExecStartPre=-/bin/rm -rf /var/lock/oalive/mem.lock
ExecStart=/bin/bash $WORK_DIR/bin/mem-worker.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# ================= 5. 网络守护 =================
cat << EOF > "$WORK_DIR/bin/net-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "net"
trap "release_lock 'net'" EXIT
timeout 360 curl -s --limit-rate ${NET_LIMIT}M -o /dev/null http://speedtest.tele2.net/100MB.zip || true
EOF

cat << EOF > /etc/systemd/system/bandwidth_occupier.service
[Unit]
Description=OAlive Network Task
[Service]
Type=oneshot
ExecStartPre=-/bin/rm -rf /var/lock/oalive/net.lock
ExecStart=/bin/bash $WORK_DIR/bin/net-worker.sh
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/bandwidth_occupier.timer
[Unit]
Description=Timer for OAlive Network
[Timer]
OnUnitActiveSec=${NET_INTERVAL}min
[Install]
WantedBy=timers.target
EOF

# ================= 6. 激活 =================
chmod -R +x "$WORK_DIR/bin/"
systemctl daemon-reload
systemctl restart cpu-limit.service memory-limit.service bandwidth_occupier.timer
systemctl enable cpu-limit.service memory-limit.service bandwidth_occupier.timer
echo "安装完成！日志: tail -f $LOG_FILE"
