# VXLAN IPv6 module dependency witness

## Result

This experiment reproduced a NULL dereference in the unmodified Linux 4.18.20
VXLAN implementation using a build accepted by Kconfig:

```text
CONFIG_VXLAN=y
CONFIG_IPV6=m
CONFIG_VETH=y
CONFIG_NET_UDP_TUNNEL=y
CONFIG_INET=y
```

The kernel booted with no IPv6 module loaded. A VXLAN device was created with
route short-circuiting enabled (`rsc`), and a permanent router FDB entry was
added. Sending an IPv6 Ethernet frame through the VXLAN device reached
`route_shortcircuit()`, which dereferenced `ipv6_stub->nd_tbl` while
`ipv6_stub` was NULL.

The resulting transcript contains:

```text
BUG: unable to handle kernel NULL pointer dereference at 00000000000001b8
RIP: 0010:neigh_lookup+0x26/0x110
Call Trace:
  route_shortcircuit+0x91/0x390
  vxlan_xmit+0x67e/0xd90
Modules linked in:
CR2: 00000000000001b8
Kernel panic - not syncing: Fatal exception in interrupt
```

This is a genuine runtime witness for the historical VXLAN dependency gap,
not a test-only kernel hook or modified dereference.

## Why the path is reachable

The saved source file `vxlan.c` contains the unguarded operation:

```c
n = neigh_lookup(ipv6_stub->nd_tbl, &pip6->daddr, dev);
```

The call is reached when all of the following are true:

1. The VXLAN device has `VXLAN_F_RSC` enabled.
2. Its FDB entry has `NTF_ROUTER`.
3. The transmitted frame is IPv6.
4. The IPv6 provider has not been initialized.

The guest's FDB output records the router entry, and `/proc/modules` is empty.
The `send_ipv6` utility sends an IPv6 Ethernet frame directly to `vxlan0`.

## Reproduction

The artifacts were produced in the `netdep` Docker container using QEMU.
The exact kernel image, configuration, initramfs, source snapshot, injector,
and complete serial log are included in this directory.

1. Start Docker Desktop and ensure the `netdep` container is available.
2. Copy `bzImage`, `vxlan_initramfs.cpio`, and the saved command-line
   configuration into a working directory.
3. Boot with:

   ```text
   qemu-system-x86_64 -accel tcg -m 512M -smp 2 \
     -kernel bzImage \
     -initrd vxlan_initramfs.cpio \
     -append "console=ttyS0 panic=1 oops=panic" \
     -nographic -no-reboot -monitor none \
     -serial file:vxlan_serial.log -vga none
   ```

4. The initramfs automatically:
   - creates `vethA` and `veth0`;
   - creates `vxlan0` with `rsc`;
   - adds the router FDB entry;
   - confirms that `/proc/modules` has no IPv6 module;
   - invokes `/send_ipv6 vxlan0`.
5. Compare the serial output with `evidence_excerpt.txt`.

The expected termination is a kernel NULL-dereference panic in the
`route_shortcircuit -> vxlan_xmit` call chain.

## Important classification

The configuration is Kconfig-valid because VXLAN was allowed to be built in
while IPv6 was modular. The experiment does not load IPv6, so the provider
object and its `nd_tbl` state are unavailable at runtime. This directly
demonstrates why the missing dependency constraint was dangerous. It does not
claim that every `CONFIG_VXLAN=y, CONFIG_IPV6=m` boot will crash; the specific
RSC/router-FDB/IPv6 packet path is required.
