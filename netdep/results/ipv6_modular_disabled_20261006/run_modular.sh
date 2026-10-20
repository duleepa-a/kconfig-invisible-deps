#!/bin/sh
export SDL_VIDEODRIVER=dummy
export SDL_AUDIODRIVER=dummy
rm -f /work/modular_serial.log /work/modular_qemu.log
/usr/bin/qemu-system-x86_64 -accel tcg -m 512M -smp 2 \
  -kernel /work/ipv6_modular_disabled_artifacts/modular_bzImage \
  -initrd /work/ipv6_modular_disabled_artifacts/modular_initramfs.cpio \
  -append 'console=ttyS0 panic=1 oops=panic' \
  -nographic -no-reboot -monitor none \
  -serial file:/work/modular_serial.log -vga none \
  >/work/modular_qemu.log 2>&1
printf 'QEMU_EXIT=%s\n' "$?" >> /work/modular_qemu.log
