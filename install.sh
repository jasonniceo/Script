#!/bin/bash
# OAlive- 双动态保底终极版
# CPU动态补差额 + 内存动态补差额 | 支持安装/升级/卸载 | 自带死锁自愈

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
    rm -f /dev/shm/oalive_mem_occupy
    
    echo "=========================================================="
    echo "卸载成功！所有 OAlive 残留已干净清除。"
    echo "=========================================================="
}

# ================= 主菜单界面 =================
echo "=========================================================="
echo "         OAlive - 管理脚本"
echo "         CPU+内存双动态保底 | 只补差额不叠加"
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

# CPU：默认整机 20%~25% 动态保底区间
DEFAULT_CPU_LOW=20
DEFAULT_CPU_HIGH=25

read -p "1. 请输入 CPU 保底下限/整机百分比 (默认 $DEFAULT_CPU_LOW): " INPUT_CPU_LOW </dev/tty
CPU_LOW=${INPUT_CPU_LOW:-$DEFAULT_CPU_LOW}

read -p "   请输入 CPU 停止上限/整机百分比 (默认 $DEFAULT_CPU_HIGH): " INPUT_CPU_HIGH </dev/tty
CPU_HIGH=${INPUT_CPU_HIGH:-$DEFAULT_CPU_HIGH}

# 换算单核心硬上限（systemd CPUQuota 使用）
CORES=$(nproc)
SINGLE_CPU_MAX=$((CORES * CPU_HIGH))

read -p "2. 请输入整机最低内存占用百分比 (默认 25): " INPUT_MEM_PCT </dev/tty
MEM_PCT=${INPUT_MEM_PCT:-25}

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
echo "CPU 动态区间: ${CPU_LOW}% ~ ${CPU_HIGH}% (整机) | 内存保底: 整机不低于 ${MEM_PCT}%"
echo "网络触发: 每 ${NET_INTERVAL} 分钟 | 下载时长: ${NET_DURATION} 分钟 | 限速: ${NET_LIMIT} Mbps"
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

# ================= 3. 编写 CPU 守护逻辑（动态补差，5分钟检测版） =================
cat << 'EOF' > "$WORK_DIR/bin/cpu-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "cpu"

CPU_LOW=$1
CPU_HIGH=$2
CORES=$(nproc)
[ -z "$CPU_LOW" ] && CPU_LOW=20
[ -z "$CPU_HIGH" ] && CPU_HIGH=25

log_msg "CPU worker started, target range: ${CPU_LOW}% ~ ${CPU_HIGH}% (total), cores: ${CORES}, check interval: 300s."

# 读取整机CPU使用率（基于/proc/stat，0.5秒采样平均）
get_cpu_usage() {
    read -r -a cpu1 < /proc/stat
    sleep 0.5
    read -r -a cpu2 < /proc/stat
    
    local total1=$(( cpu1[1] + cpu1[2] + cpu1[3] + cpu1[4] + cpu1[5] + cpu1[6] + cpu1[7] ))
    local idle1=${cpu1[4]}
    local total2=$(( cpu2[1] + cpu2[2] + cpu2[3] + cpu2[4] + cpu2[5] + cpu2[6] + cpu2[7] ))
    local idle2=${cpu2[4]}
    
    local total_diff=$(( total2 - total1 ))
    local idle_diff=$(( idle2 - idle1 ))
    
    if [ "$total_diff" -eq 0 ]; then
        echo 0
        return
    fi
    
    local usage=$(( (total_diff - idle_diff) * 100 / total_diff ))
    echo "$usage"
}

# 负载进程：纯死循环，靠信号控制启停
worker() {
    while true; do :; done
}

worker &
PID=$!
trap "kill -9 $PID 2>/dev/null; release_lock 'cpu'; exit" EXIT TERM INT

# 默认先挂起，检测后再决定是否运行
kill -STOP $PID 2>/dev/null
RUNNING=0
CYCLE_SEC=300

while true; do
    CURRENT_USAGE=$(get_cpu_usage)
    
    if [ "$CURRENT_USAGE" -lt "$CPU_LOW" ]; then
        # 低于下限：计算差额，补到下限
        NEED_PCT=$(( CPU_LOW - CURRENT_USAGE ))
        SINGLE_PCT=$(( NEED_PCT * CORES ))
        [ "$SINGLE_PCT" -gt 95 ] && SINGLE_PCT=95
        
        RUN_SEC=$(awk "BEGIN {print $SINGLE_PCT / 100}")
        SLEEP_SEC=$(awk "BEGIN {print 1 - $SINGLE_PCT / 100}")
        
        if [ "$RUNNING" -eq 0 ]; then
            log_msg "CPU usage ${CURRENT_USAGE}% < ${CPU_LOW}%, start filling, add ${NEED_PCT}%."
            RUNNING=1
        fi
        
        # 持续运行5分钟后重新检测
        START=$(date +%s)
        while [ $(( $(date +%s) - START )) -lt $CYCLE_SEC ]; do
            kill -CONT $PID 2>/dev/null
            sleep $RUN_SEC
            kill -STOP $PID 2>/dev/null
            sleep $SLEEP_SEC
        done
        
    elif [ "$CURRENT_USAGE" -gt "$CPU_HIGH" ]; then
        # 高于上限：完全停止占用
        if [ "$RUNNING" -eq 1 ]; then
            kill -STOP $PID 2>/dev/null
            log_msg "CPU usage ${CURRENT_USAGE}% > ${CPU_HIGH}%, stop filling."
            RUNNING=0
        fi
        sleep $CYCLE_SEC
    else
        # 中间区间：保持当前状态，5分钟后再复检
        if [ "$RUNNING" -eq 1 ]; then
            START=$(date +%s)
            while [ $(( $(date +%s) - START )) -lt $CYCLE_SEC ]; do
                kill -CONT $PID 2>/dev/null
                sleep $RUN_SEC
                kill -STOP $PID 2>/dev/null
                sleep $SLEEP_SEC
            done
        else
            sleep $CYCLE_SEC
        fi
    fi
done
EOF

cat << EOF > /etc/systemd/system/cpu-limit.service
[Unit]
Description=OAlive CPU Limit Service (Dynamic Fill)
After=network.target

[Service]
Type=simple
# 启动前自动清理残留死锁
ExecStartPre=-/bin/rm -rf /var/lock/oalive/cpu.lock
ExecStart=/bin/bash $WORK_DIR/bin/cpu-worker.sh ${CPU_LOW} ${CPU_HIGH}
Restart=always
RestartSec=10
# 单核心硬上限，防止异常超量
CPUQuota=${SINGLE_CPU_MAX}%

[Install]
WantedBy=multi-user.target
EOF

# ================= 4. 编写内存分配逻辑（动态保底补差额版） =================
cat << EOF > "$WORK_DIR/bin/mem-worker.sh"
#!/bin/bash
source /opt/oalive/bin/oalive-lib.sh
acquire_lock "mem"
log_msg "Memory worker started, target: ${MEM_PCT}% of total memory (dynamic fill)."

MEM_TOTAL_KB=\$(awk '/MemTotal/ {print \$2}' /proc/meminfo)
TARGET_KB=\$((MEM_TOTAL_KB * ${MEM_PCT} / 100))
MEM_FILE="/dev/shm/oalive_mem_occupy"

trap "rm -f \$MEM_FILE; release_lock 'mem'; exit" INT TERM EXIT

while true; do
    # 计算当前系统实际已用内存（与面板口径一致：总内存 - 可用内存）
    MEM_AVAIL_KB=\$(awk '/MemAvailable/ {print \$2}' /proc/meminfo)
    USED_KB=\$((MEM_TOTAL_KB - MEM_AVAIL_KB))
    NEED_KB=\$((TARGET_KB - USED_KB))

    if [ "\$NEED_KB" -gt 1024 ]; then
        # 当前占用未达标，计算需要补充的内存量
        NEED_MB=\$((NEED_KB / 1024))
        AVAIL_MB=\$(df -m /dev/shm | awk 'NR==2 {print \$4}')
        
        if [ "\$NEED_MB" -lt "\$AVAIL_MB" ]; then
            # 先删除旧文件，再创建对应大小的新文件
            rm -f "\$MEM_FILE"
            dd if=/dev/zero of="\$MEM_FILE" bs=1M count="\$NEED_MB" 2>/dev/null
            log_msg "Memory filled: current used \$((USED_KB/1024))MB, added \${NEED_MB}MB, total target ${MEM_PCT}%."
        else
            log_msg "Warning: tmpfs space insufficient, cannot fill memory."
        fi
    else
        # 当前占用已达标或超额，释放脚本占用的内存
        if [ -f "\$MEM_FILE" ]; then
            rm -f "\$MEM_FILE"
            log_msg "Memory already above ${MEM_PCT}%, released script occupied memory."
        fi
    fi

    sleep 300
done
EOF

cat << EOF > /etc/systemd/system/memory-limit.service
[Unit]
Description=OAlive Memory Limit Service (Dynamic Fill)
After=network.target

[Service]
Type=simple
# 启动前清理锁和内存残留文件
ExecStartPre=-/bin/rm -rf /var/lock/oalive/mem.lock
ExecStartPre=-/bin/rm -f /dev/shm/oalive_mem_occupy
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
# 启动前清理网络任务残留死锁
ExecStartPre=-/bin/rm -rf /var/lock/oalive/net.lock
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
echo "CPU 动态区间: ${CPU_LOW}% ~ ${CPU_HIGH}%（整机，只补差额不叠加）"
echo "内存动态保底: 整机不低于 ${MEM_PCT}%（系统占用达标自动停止）"
echo "查看运行日志命令: tail -f $LOG_FILE"
echo "=========================================================="
