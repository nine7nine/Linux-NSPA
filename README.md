# Linux-NSPA:

![My Image](/images/linux-nspa-banner.png)

### Linux-NSPA: Real-Time Linux Kernel With A Twist

This repo contains my Real-Time Linux kernel sources that has additional 
customizations and out-of-tree patchwork.

### Features/Patchwork:

* PREEMPT_RT_FULL : Realtime Linux Patchset
* Multi-Gnerational LRU (https://lwn.net/Articles/856931/)
* Tunable WorkingSet Protection Mechanism 
* Winesync driver (Although currently Fsync/Futex_waitv is better)
* Subset of Intel Clear Linux Kernel patches
* Various Performance / interactivity related changes
* Wine-related patchwork
* Power management improvements
* Faster bootup
* Misc fixes

Archlinux packages can be found here: https://github.com/nine7nine/Linux-NSPA-pkgbuild
