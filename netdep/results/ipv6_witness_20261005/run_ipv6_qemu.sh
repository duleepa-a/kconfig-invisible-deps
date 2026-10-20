#!/bin/sh
export SDL_VIDEODRIVER=dummy
export SDL_AUDIODRIVER=dummy
rm -f /work/ipv6_disabled.log /work/ipv6_disabled_qemu.log
/usr/bin/qemu-system-x86_64 -accel tcg -m 512M -smp 2 -kernel /work/witness2_bzImage -initrd /work/ipv6_disabled_initramfs.cpio -append 'console=ttyS0 panic=1 oops=panic' -nographic -no-reboot -monitor none -serial file:/work/ipv6_disabled.log -vga none >/work/ipv6_disabled_qemu.log 2>&1
printf 'QEMU_EXIT=%s\n' "$?" >> /work/ipv6_disabled_qemu.log