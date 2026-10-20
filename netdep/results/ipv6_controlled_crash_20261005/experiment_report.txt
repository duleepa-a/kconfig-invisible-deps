IPv6 nf_ipv6_ops NULL-Dereference Experiment Report
=====================================================

Date
----

2026-10-05

Purpose
-------

This report records the complete runtime investigation of the Linux IPv6
bridge/netfilter candidate involving an unguarded use of the
nf_ipv6_ops-derived pointer in:

    net/bridge/br_netfilter_ipv6.c
    br_nf_pre_routing_finish_ipv6()

The relevant operation is:

    v6ops->route_input(skb);

The objective was to build a kernel, exercise the relevant execution path,
and retain reproducible evidence of whether a NULL pointer dereference occurs.
This report is intentionally separate from the existing project README and
FINDINGS.md files. No changes to those files are required to understand or
repeat this experiment.

Candidate and expected path
---------------------------

The source-level path investigated was:

    br_nf_pre_routing()
      -> br_nf_pre_routing_ipv6()
        -> IPv6 NF_INET_PRE_ROUTING hook
          -> br_nf_pre_routing_finish_ipv6()
            -> br_nf_ipv6_daddr_was_changed()
              -> v6ops->route_input(skb)

The dereference is conditional. Ordinary bridged IPv6 traffic can take the
unchanged-destination path and avoid the dereference. The destination-change
branch is normally associated with an IPv6 PREROUTING operation such as DNAT
changing the packet destination before the bridge-netfilter continuation
runs.

Initial natural-runtime attempt
-------------------------------

The first attempt followed the intended module-retention model:

    CONFIG_IPV6=m
    bridge/br_netfilter support enabled
    IPv6 module intentionally absent or disabled at runtime

The kernel build itself completed successfully. The failure was later, during
runtime setup, before the packet could reach the candidate:

  * IPv6 conntrack/NAT-related modules reported unresolved symbols.
  * Bridge/veth setup was unreliable with the available BusyBox ip syntax.
  * ip6tables could not install the intended IPv6 NAT table.
  * The packet injector could not find the expected interface.
  * The log ended with "=== TRIGGER NOT REACHED ===".

This was a setup failure, not a kernel-build failure and not evidence that the
candidate does not exist.

The reason for the module problem was then checked in the Linux 4.18 Kconfig
and Makefiles. CONFIG_BRIDGE depends on "IPV6 || IPV6=n". With CONFIG_IPV6=m,
bridge support is consequently modular and bridge-related code imports IPv6
symbols. A bridge module cannot simply be loaded while ipv6.ko is absent in
the proposed configuration. Copying additional modules into the initramfs
does not make that dependency state valid.

Controlled experiment design
----------------------------

To isolate the candidate from the invalid module-dependency setup, a
test-only witness kernel was built with:

    CONFIG_IPV6=y
    CONFIG_BRIDGE=y
    CONFIG_BRIDGE_NETFILTER=y
    CONFIG_VETH=y

The kernel was booted with:

    ipv6.disable=1

This combination keeps the IPv6 and bridge-netfilter code present while
causing IPv6 initialization to exit before IPv6 netfilter initialization
publishes nf_ipv6_ops. The pointer therefore remains NULL during the test.

The original vulnerable dereference was not changed. A test-only parameter
was added:

    br_netfilter.test_force_daddr_change=1

When enabled, the test code:

  1. logs entry into IPv6 bridge PRE_ROUTING;
  2. copies the IPv6 destination into the existing bridge metadata;
  3. flips one bit only in that saved metadata copy;
  4. thereby makes the existing daddr-changed predicate true.

The test code does not replace, guard, or otherwise modify:

    v6ops->route_input(skb);

The exact source change is retained in controlled_hook.patch. This is a
controlled exact-path experiment. It demonstrates the behavior of the
candidate once its required branch is entered; it does not claim that the
unmodified natural ip6tables DNAT setup was successfully completed.

Kernel and guest build
----------------------

The built kernel is Linux 4.18.20, compiled in the netdep container. The
exact configuration is retained as controlled.config. The resulting kernel
image is controlled_bzImage.

The initramfs is an uncompressed cpio archive because the witness kernel did
not have gzip initramfs decompression enabled. It is retained as
controlled_initramfs.cpio.

The guest setup script performs these operations:

  1. mounts proc, sysfs, and devtmpfs;
  2. creates bridge brtest;
  3. creates a veth pair;
  4. attaches both veth interfaces to the bridge;
  5. brings the bridge and ports up;
  6. enables net.bridge.bridge-nf-call-ip6tables;
  7. sends one raw Ethernet IPv6 frame through the bridge.

The BusyBox-compatible interface sequence that worked was:

    ip link add brtest type bridge
    ip link add vethA type veth peer vethB
    brctl addif brtest vethA
    brctl addif brtest veth0

In this environment, BusyBox created the peer as veth0, so the script uses
vethA and veth0 rather than relying on the peer-name syntax supported by
full iproute2.

Runtime command
---------------

Inside the netdep container, the retained runner is:

    cd /work/ipv6_controlled_artifacts
    /work/run_controlled.sh

The equivalent QEMU invocation is:

    qemu-system-x86_64 -accel tcg -m 512M -smp 2 \
      -kernel controlled_bzImage \
      -initrd controlled_initramfs.cpio \
      -append "console=ttyS0 panic=1 oops=panic ipv6.disable=1 br_netfilter.test_force_daddr_change=1" \
      -nographic -no-reboot -monitor none \
      -serial file:controlled_serial.log -vga none

The runner sets SDL_VIDEODRIVER=dummy and SDL_AUDIODRIVER=dummy because QEMU
2.11.1 otherwise attempts to initialize unavailable display/audio devices.

Observed runtime result
-----------------------

The guest booted successfully and the bridge/veth setup completed. The raw
IPv6 frame then produced the following ordered evidence:

    === INJECTING IPv6 FRAME ===
    br_nf test: IPv6 bridge PRE_ROUTING reached
    br_nf test: forcing IPv6 destination-change branch
    BUG: unable to handle kernel NULL pointer dereference at 0000000000000008
    Oops: 0000 [#1] SMP NOPTI
    CPU: 0 PID: 114 Comm: send_ipv6 Not tainted 4.18.20+ #7
    RIP: 0010:br_nf_pre_routing_finish_ipv6+0xaa/0x1f0
    CR2: 0000000000000008

The call trace included:

    nf_hook_slow
    br_nf_pre_routing_ipv6
    br_nf_pre_routing
    nf_hook_slow
    br_handle_frame
    __netif_receive_skb_core
    process_backlog
    net_rx_action
    packet_sendmsg
    __sys_sendto
    __x64_sys_sendto

The guest ended with:

    Kernel panic - not syncing: Fatal exception in interrupt
    Rebooting in 1 seconds..

Interpretation
--------------

The observed result confirms all of the following for the controlled witness:

  * the kernel boots with the test configuration;
  * bridge IPv6 PRE_ROUTING is reached by an injected Ethernet IPv6 frame;
  * the destination-change branch can be entered while nf_ipv6_ops remains
    NULL under ipv6.disable=1;
  * the unguarded operation faults at the expected function;
  * the fault is a NULL-pointer dereference at address 0x8;
  * the resulting exception causes a kernel panic.

The RIP and CR2 values are consistent with dereferencing a member at offset
0x8 through a NULL function-operations pointer. The call trace also places
the fault in the expected bridge/netfilter receive path rather than in the
userspace packet generator.

What this does and does not prove
---------------------------------

It proves the fatal behavior of the candidate's exact vulnerable operation
when the destination-change branch is entered with nf_ipv6_ops unset.

It does not prove that a stock, unmodified CONFIG_IPV6=m configuration can
load bridge/netfilter while ipv6.ko remains absent. That state was blocked by
the Linux 4.18 Kconfig/module dependency relationship described above.

It also does not prove that a natural ip6tables IPv6 DNAT rule was the event
that selected the branch in this run. The branch was deliberately selected by
the test-only parameter so that the dereference could be validated without
changing the vulnerable statement or depending on the broken module setup.

Retained evidence
-----------------

This directory contains:

  controlled_bzImage
      Kernel image used by the successful crash run.
  controlled_initramfs.cpio
      Exact uncompressed initramfs used by QEMU.
  controlled.config
      Exact kernel configuration.
  br_netfilter_ipv6.c
      Source file used for the controlled build.
  controlled_hook.patch
      Test-only source diff relative to the original source.
  init
      Exact guest setup and packet-trigger script.
  run_controlled.sh
      Exact QEMU invocation wrapper.
  send_ipv6.c
      Raw Ethernet IPv6 injector source.
  send_ipv6
      Injector binary used in the guest.
  controlled_serial.log
      Full serial transcript, including boot and crash.
  crash_excerpt.txt
      Short evidence excerpt suitable for quick inspection.
  controlled_qemu.log
      QEMU stderr/status output.
  hashes.sha256
      SHA-256 manifest for the bundle.

A screenshot was captured from the concise crash excerpt showing the hook
entry, forced branch, NULL dereference, RIP, CR2, call trace, and kernel
panic. The text excerpt is retained as the durable, diffable evidence.

Reproducibility checks
----------------------

To verify the retained files before use:

    sha256sum -c hashes.sha256

Run this command from the artifact directory. The manifest was regenerated
after the report and evidence excerpt were added.

Final finding
-------------

The candidate is a genuine NULL-dereference condition in the tested
Linux 4.18 code path. The original natural module-retention setup was not a
valid runtime state for this tree, which explains the first unsuccessful
attempt. A corrected built-in/disabled-IPv6 witness then reached the exact
branch and reproduced a kernel panic. The strongest accurate research claim
is therefore:

    Controlled exact-path runtime reproduction confirmed.
    Natural DNAT-only runtime trigger remains separately unconfirmed.
