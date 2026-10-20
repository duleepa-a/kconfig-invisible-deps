Controlled IPv6 nf_ipv6_ops crash witness

Result: CRASH REPRODUCED in an isolated QEMU guest.

The witness kernel is Linux 4.18.20 with:
- CONFIG_IPV6=y
- CONFIG_BRIDGE=y
- CONFIG_BRIDGE_NETFILTER=y
- CONFIG_VETH=y
- ipv6.disable=1

The original vulnerable dereference in
net/bridge/br_netfilter_ipv6.c was not changed:

    v6ops->route_input(skb);

The file controlled_hook.patch adds a test-only built-in parameter,
br_netfilter.test_force_daddr_change=1. When enabled, it changes only the
saved IPv6 destination metadata in br_nf_pre_routing_ipv6(), causing the
same daddr-changed branch normally selected by a PREROUTING DNAT rule. It
also logs entry into the bridge IPv6 PRE_ROUTING hook. This is a controlled
exact-path exercise, not a claim that the natural ip6tables module setup
worked in the earlier CONFIG_IPV6=m attempt.

Reproduction inside the netdep container:

    cd /work/ipv6_controlled_artifacts
    /work/run_controlled.sh

Equivalent QEMU command:

    qemu-system-x86_64 -accel tcg -m 512M -smp 2 \
      -kernel controlled_bzImage \
      -initrd controlled_initramfs.cpio \
      -append "console=ttyS0 panic=1 oops=panic ipv6.disable=1 br_netfilter.test_force_daddr_change=1" \
      -nographic -no-reboot -monitor none \
      -serial file:controlled_serial.log -vga none

The guest init script:
1. mounts proc/sysfs/devtmpfs;
2. creates a bridge and two veth interfaces;
3. enables bridge IPv6 netfilter;
4. injects an Ethernet IPv6 frame using send_ipv6;
5. enters br_nf_pre_routing_ipv6();
6. forces the existing destination-change branch;
7. reaches the unguarded v6ops->route_input(skb) dereference.

Evidence in controlled_serial.log:

    br_nf test: IPv6 bridge PRE_ROUTING reached
    br_nf test: forcing IPv6 destination-change branch
    BUG: unable to handle kernel NULL pointer dereference at 0000000000000008
    RIP: 0010:br_nf_pre_routing_finish_ipv6+0xaa/0x1f0
    Call Trace:
      br_nf_pre_routing_ipv6
      br_nf_pre_routing
      nf_hook_slow
      br_handle_frame
    Kernel panic - not syncing: Fatal exception in interrupt

The earlier CONFIG_IPV6=m run remains in the separate
ipv6_witness_20261005 directory. That run failed during runtime module
setup and never reached this path. The present bundle demonstrates the
exact vulnerable execution path with a controlled branch trigger.
