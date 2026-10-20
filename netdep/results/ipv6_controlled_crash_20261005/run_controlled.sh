#!/bin/sh
export SDL_VIDEODRIVER=dummy
export SDL_AUDIODRIVER=dummy
rm -f /work/controlled_serial.log /work/controlled_qemu.log
/usr/bin/qemu-system-x86_64 -accel tcg -m 512M -smp 2 -kernel /work/controlled_bzImage -initrd /work/controlled_initramfs.cpio -append "console=ttyS0 panic=1 oops=panic ipv6.disable=1 br_netfilter.test_force_daddr_change=1" -nographic -no-reboot -monitor none -serial file:/work/controlled_serial.log -vga none >/work/controlled_qemu.log 2>&1
printf "QEMU_EXIT=%s\n" "$?" >> /work/controlled_qemu.log