#!/bin/bash
# OAlive- 双动态保底终极版 (双进程闭环补偿版)
# CPU动态补差额(真闭环反馈无盲区) + 内存动态补差额 | 支持安装/升级/卸载 | 自带死锁自愈

set -e

WORK_DIR="/opt/oalive"
LOG_DIR="/var/log/oalive"
LOG_FILE="$LOG_DIR/oalive.log"

if [ "$EUID" -ne 0 ]; then
    echo "错误：请使用 root 用户或 sudo 权限运行此脚本！"
    exit 1
fi

# ================= 卸载逻辑 =================
do_uninstall() {
    echo "=========================================================="
    echo "正在卸载 OAlive 保活脚本并清理系统残留..."
    echo "=========================================================="
    
    systemctl stop cpu-limit.service memory-limit.service bandwidth_occupier.timer bandwidth_occupier.service 2>/dev/null || true
    systemctl disable cpu-limit.service memory-limit.service bandwidth_occupier.timer 2>/dev/null || true
    
    rm -f /etc/systemd/system/cpu-limit.service \
          /etc/systemd/system/memory-limit.service \
          /etc/systemd/system/bandwidth_occupier.service \
          /etc/systemd/system/bandwidth_occupier.timer
    systemctl daemon-reload
    
    rm -rf "$WORK_DIR"
    rm -rf "$LOG_DIR"
    rm -rf /var/lock/oalive
    rm -f /dev/shm/oalive_mem_occupy
    rm -f /dev/shm/oalive_cpu_target
    
    echo "=========================================================="
    echo "卸载成功！所有 OAlive 残留已干净清除。"
    echo "=========================================================="
}

# ================= 主菜单界面 =================
echo "=========================================================="
echo "         OAlive - 管理脚本 (PID闭环补偿版)"
echo "         解决算力掉线死角 | 真实测算，自动追平"
echo "=========================================================="
echo " 1. 安装OAlive"
echo " 2. 升级覆盖安装OAlive"
echo " 3. 卸载OAlive"
echo " 4. 退出"
echo "=========================================================="
read -p "请输入数字选择功能 [1-4] (默认 1): " MENU_CHOICE </dev/tty
MENU_CHOICE=${MENU_CHOICE:-1}

case "$MENU_CHOICE" in
    2)
        echo "=> 检测到升级请求，正在自动清理旧版本服务..."
        systemctl stop cpu-limit.service memory-limit.service bandwidth_occupier.timer 2>/dev/null || true
        rm -rf /var/lock/oalive/*
        rm -f /dev/shm/oalive_mem_occupy
        rm -f /dev/shm/oalive_cpu_target
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
        ;;
esac

# ================= 1. 交互式获取用户配置 =================
echo ""
echo "直接按回车(Enter)即可使用推荐的默认值。"
echo ""

DEFAULT_CPU_LOW=25
DEFAULT_CPU_HIGH=35

read -p "1. 请输入 CPU 保底下限/整机百分比 (默认 $DEFAULT_CPU_LOW): " INPUT_CPU_LOW </dev/tty
CPU_LOW=${INPUT_CPU_LOW:-$DEFAULT_CPU_LOW}

read -p "   请输入 CPU 停止上限/整机百分比 (默认 $DEFAULT_CPU_HIGH): " INPUT_CPU_HIGH </dev/tty
CPU_HIGH=${INPUT_CPU_HIGH:-$DEFAULT_CPU_HIGH}

CORES=$(nproc)
SYSTEM_CPU_MAX=$((CORES * CPU_HIGH))

read -p "2. 请输入整机最低内存占用百分比 (默认 30): " INPUT_MEM_PCT </dev/tty
MEM_PCT=${INPUT_MEM_PCT:-30}

read -p "3. 请输入网络消耗触发间隔/分钟 (默认 60): " INPUT_NET_INTERVAL </dev/tty
NET_INTERVAL=${INPUT_NET_INTERVAL:-60}

read -p "4. 请输入网络下载持续时间/分钟 (默认 6): " INPUT_NET_DURATION </dev/tty
NET_DURATION=${INPUT_NET_DURATION:-6}
NET_DURATION_SEC=$((NET_DURATION * 60))

read -p "5. 请输入网络限速/mbps (默认 50): " INPUT_NET_LIMIT </dev/tty
NET_LIMIT_RAW=${INPUT_NET_LIMIT:-50}
NET_LIMIT=$(echo "$NET_LIMIT_RAW" | grep -oE '[0-9]+' || echo 10)

echo ""
echo "=> 正在使用以下配置进行安装："
echo "核心数: ${CORES} 核 | CPU 动态区间: ${CPU_LOW}% ~ ${CPU_HIGH}% (整机)"
echo "内存保底: 整机不低于 ${MEM_PCT}%"
echo "=========================================================="
sleep 2

# ================= 2. 初始化环境 =================
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
        if [ "$size" -gt 131072 ]; then mv -f "$LOG_FILE" "${LOG_FILE}.1"; fi
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

# ================= 3. 编写 CPU 守护逻辑（PID反馈闭环版） =================
cat << 'EOF' > "$WORK_DIR/bin/cpu-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "cpu"

CPU_LOW=$1
CPU_HIGH=$2
CORES=$(nproc)
[ -z "$CPU_LOW" ] && CPU_LOW=25
[ -z "$CPU_HIGH" ] && CPU_HIGH=35

log_msg "CPU Worker (Feedback loop) started. Target: ${CPU_LOW}% ~ ${CPU_HIGH}%, Cores: ${CORES}"

get_cpu_usage() {
    read -r -a cpu1 < /proc/stat
    sleep 2
    read -r -a cpu2 < /proc/stat
    local total1=$(( cpu1[1] + cpu1[2] + cpu1[3] + cpu1[4] + cpu1[5] + cpu1[6] + cpu1[7] ))
    local idle1=${cpu1[4]}
    local total2=$(( cpu2[1] + cpu2[2] + cpu2[3] + cpu2[4] + cpu2[5] + cpu2[6] + cpu2[7] ))
    local idle2=${cpu2[4]}
    local total_diff=$(( total2 - total1 ))
    local idle_diff=$(( idle2 - idle1 ))
    if [ "$total_diff" -eq 0 ]; then echo 0; return; fi
    local usage=$(( (total_diff - idle_diff) * 100 / total_diff ))
    echo "$usage"
}

PIDS=()
start_workers() {
    for i in $(seq 1 $CORES); do
        while true; do :; done &
        PIDS+=($!)
    done
}

pause_workers() {
    for p in "${PIDS[@]}"; do kill -STOP $p 2>/dev/null || true; done
}

resume_workers() {
    for p in "${PIDS[@]}"; do kill -CONT $p 2>/dev/null || true; done
}

# 进程解耦：独立的发力引擎，永远不会被测算过程阻塞
TARGET_FILE="/dev/shm/oalive_cpu_target"
echo "0 1" > "$TARGET_FILE"

load_maintainer() {
    while true; do
        if [ -f "$TARGET_FILE" ]; then
            read RUN_SEC SLEEP_SEC < "$TARGET_FILE"
        else
            RUN_SEC="0"; SLEEP_SEC="1"
        fi
        
        if [ "$RUN_SEC" == "0" ] || [ -z "$RUN_SEC" ]; then
            pause_workers
            sleep 1
        else
            resume_workers
            sleep $RUN_SEC
            pause_workers
            sleep $SLEEP_SEC
        fi
    done
}

cleanup() {
    kill -9 $MAINTAINER_PID 2>/dev/null || true
    for p in "${PIDS[@]}"; do kill -9 $p 2>/dev/null || true; done
    rm -f "$TARGET_FILE"
    release_lock 'cpu'
    exit
}

trap cleanup EXIT TERM INT

start_workers
pause_workers
load_maintainer &
MAINTAINER_PID=$!

CURRENT_ADDED=0

# 闭环测算引擎：根据真实反馈不断修剪油门
while true; do
    CURRENT_USAGE=$(get_cpu_usage)
    
    if [ "$CURRENT_USAGE" -lt "$CPU_LOW" ]; then
        DIFF=$(( CPU_LOW - CURRENT_USAGE ))
        CURRENT_ADDED=$(( CURRENT_ADDED + DIFF ))
        # 兜底防爆锁，内部油门最高踩到 90%
        [ "$CURRENT_ADDED" -gt 90 ] && CURRENT_ADDED=90
        log_msg "Current: ${CURRENT_USAGE}%. Too low. Throttle pushed to ${CURRENT_ADDED}%."
    elif [ "$CURRENT_USAGE" -gt "$CPU_HIGH" ]; then
        DIFF=$(( CURRENT_USAGE - CPU_HIGH ))
        CURRENT_ADDED=$(( CURRENT_ADDED - DIFF ))
        [ "$CURRENT_ADDED" -lt 0 ] && CURRENT_ADDED=0
        log_msg "Current: ${CURRENT_USAGE}%. Too high. Throttle reduced to ${CURRENT_ADDED}%."
    fi
    
    if [ "$CURRENT_ADDED" -gt 0 ]; then
        RUN_SEC=$(awk "BEGIN {printf \"%.3f\", $CURRENT_ADDED / 100}")
        SLEEP_SEC=$(awk "BEGIN {printf \"%.3f\", 1 - ($CURRENT_ADDED / 100)}")
        echo "$RUN_SEC $SLEEP_SEC" > "$TARGET_FILE"
    else
        echo "0 1" > "$TARGET_FILE"
    fi
    
    # 检测间隔缩短至 5 秒，让系统更灵敏
    sleep 5
done
EOF

cat << EOF > /etc/systemd/system/cpu-limit.service
[Unit]
Description=OAlive CPU Limit Service (Feedback Loop)
After=network.target

[Service]
Type=simple
ExecStartPre=-/bin/rm -rf /var/lock/oalive/cpu.lock
ExecStart=/bin/bash $WORK_DIR/bin/cpu-worker.sh ${CPU_LOW} ${CPU_HIGH}
Restart=always
RestartSec=10
CPUQuota=${SYSTEM_CPU_MAX}%

[Install]
WantedBy=multi-user.target
EOF

# ================= 4. 编写内存分配逻辑 =================
cat << EOF > "$WORK_DIR/bin/mem-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "mem"

MEM_TOTAL_KB=\$(awk '/MemTotal/ {print \$2}' /proc/meminfo)
TARGET_KB=\$((MEM_TOTAL_KB * ${MEM_PCT} / 100))
MEM_FILE="/dev/shm/oalive_mem_occupy"

trap "rm -f \$MEM_FILE; release_lock 'mem'; exit" INT TERM EXIT

while true; do
    MEM_AVAIL_KB=\$(awk '/MemAvailable/ {print \$2}' /proc/meminfo)
    USED_KB=\$((MEM_TOTAL_KB - MEM_AVAIL_KB))
    NEED_KB=\$((TARGET_KB - USED_KB))

    if [ "\$NEED_KB" -gt 1024 ]; then
        NEED_MB=\$((NEED_KB / 1024))
        AVAIL_MB=\$(df -m /dev/shm | awk 'NR==2 {print \$4}')
        if [ "\$NEED_MB" -lt "\$AVAIL_MB" ]; then
            rm -f "\$MEM_FILE"
            dd if=/dev/zero of="\$MEM_FILE" bs=1M count="\$NEED_MB" 2>/dev/null
        fi
    else
        if [ -f "\$MEM_FILE" ]; then
            rm -f "\$MEM_FILE"
        fi
    fi
    sleep 300
done
EOF

cat << EOF > /etc/systemd/system/memory-limit.service
[Unit]
Description=OAlive Memory Limit Service
After=network.target

[Service]
Type=simple
ExecStartPre=-/bin/rm -rf /var/lock/oalive/mem.lock
ExecStartPre=-/bin/rm -f /dev/shm/oalive_mem_occupy
ExecStart=/bin/bash $WORK_DIR/bin/mem-worker.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# ================= 5. 网络消耗逻辑 =================
cat << EOF > "$WORK_DIR/bin/net-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "net"
trap "release_lock 'net'; exit" INT TERM EXIT
LIMIT_BPS=\$((${NET_LIMIT} * 125000))
timeout ${NET_DURATION_SEC} curl -s --limit-rate \${LIMIT_BPS} -o /dev/null "http://speedtest.tele2.net/100MB.zip" || true
EOF

cat << EOF > /etc/systemd/system/bandwidth_occupier.service
[Unit]
Description=OAlive Bandwidth Task
[Service]
Type=oneshot
ExecStartPre=-/bin/rm -rf /var/lock/oalive/net.lock
ExecStart=/bin/bash $WORK_DIR/bin/net-worker.sh
EOF

cat << EOF > /etc/systemd/system/bandwidth_occupier.timer
[Unit]
Description=OAlive Bandwidth Timer
[Timer]
OnBootSec=5min
OnUnitActiveSec=${NET_INTERVAL}min
RandomizedDelaySec=120
[Install]
WantedBy=timers.target
EOF

# ================= 6. 激活 =================
chmod -R +x "$WORK_DIR/bin/"
systemctl daemon-reload
systemctl enable cpu-limit.service memory-limit.service bandwidth_occupier.timer
systemctl restart cpu-limit.service memory-limit.service bandwidth_occupier.timer

echo "=========================================================="
echo "配置完成！服务已成功在后台运行/更新。"
echo "核心数: ${CORES}核 (双进程引擎，告别断流)"
echo "查看运行日志命令: tail -f $LOG_FILE"
echo "=========================================================="
