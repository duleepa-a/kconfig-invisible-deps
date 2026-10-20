IPv6 nf_ipv6_ops witness artifact bundle

Status: BUILD SUCCESSFUL; RUNTIME TRIGGER NOT REACHED. The Linux 4.18.20 witness kernel built successfully and booted under QEMU with CONFIG_IPV6=m and ipv6.ko intentionally not loaded. Runtime setup then failed before packet injection because bridge/NAT modules had unresolved dependencies without ipv6.ko.

Candidate: net/bridge/br_netfilter_ipv6.c: br_nf_pre_routing_finish_ipv6(), v6ops->route_input(skb) after PREROUTING DNAT changes the IPv6 destination.

Artifacts:
- witness2_bzImage: successfully rebuilt Linux 4.18.20 witness kernel
- ipv6_disabled_initramfs.cpio: uncompressed initramfs used by the disabled-state attempt
- ipv6_disabled.log: complete serial transcript
- ipv6_disabled_qemu.log: QEMU stderr/status
- init: exact guest init script
- run_ipv6_control.sh: QEMU runner; edit initramfs/boot parameter for variants
- send_ipv6.c and send_ipv6: raw Ethernet IPv6 injector
- witness2.config: exact kernel configuration
- source_excerpt.txt: candidate source and config-relevant excerpts
- hashes.sha256: SHA-256 hashes

Boot command used:
qemu-system-x86_64 -accel tcg -m 512M -smp 2 -kernel witness2_bzImage -initrd ipv6_disabled_initramfs.cpio -append "console=ttyS0 panic=1 oops=panic ipv6.disable=1" -nographic -no-reboot -monitor none -serial file:ipv6_disabled.log -vga none

Expected genuine trigger sequence after resolving module staging:
1. Boot with ipv6.disable=1, or use CONFIG_IPV6=m and do not load ipv6.ko.
2. Load bridge/br_netfilter and IPv6 netfilter NAT dependencies.
3. Create br0 with two veth ports.
4. Add ip6tables -t nat PREROUTING DNAT for 2001:db8::1 -> 2001:db8::2.
5. Inject an Ethernet IPv6 frame on a bridge port.
6. Capture serial output; a genuine crash should show an Oops/NULL dereference in br_nf_pre_routing_finish_ipv6.

The build result is successful. Do not claim a crash from this bundle: the runtime transcript explicitly records a pre-trigger module dependency failure, so the vulnerable packet path was not exercised.