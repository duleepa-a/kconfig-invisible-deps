#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null

echo "=== nf_nat build-witness test: net_conntrack=y, nf_nat=m ==="

echo "--- [stage 1] nf_nat NOT loaded, generating loopback traffic ---"
lsmod
ifconfig lo up 2>/dev/null || busybox ifconfig lo up
(nc -l -p 5555 &) 2>/dev/null
sleep 1
echo hello | nc -w1 127.0.0.1 5555
sleep 1
cat /proc/net/nf_conntrack 2>/dev/null | head -5
echo "--- dmesg tail after stage 1 ---"
dmesg | tail -20

echo "--- [stage 2] insmod nf_nat ---"
insmod /lib/modules/nf_nat.ko
echo "insmod exit: $?"
lsmod
echo "--- dmesg tail after insmod ---"
dmesg | tail -10

echo "--- [stage 3] traffic with nf_nat loaded ---"
(nc -l -p 5556 &) 2>/dev/null
sleep 1
echo hello2 | nc -w1 127.0.0.1 5556
sleep 1
dmesg | tail -10

echo "--- [stage 4] rmmod nf_nat ---"
rmmod nf_nat
echo "rmmod exit: $?"
lsmod
dmesg | tail -10

echo "--- [stage 5] traffic after rmmod (guard flipped back to NULL) ---"
(nc -l -p 5557 &) 2>/dev/null
sleep 1
echo hello3 | nc -w1 127.0.0.1 5557
sleep 1
dmesg | tail -20

echo "=== TEST COMPLETE ==="
poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger
sleep 5
