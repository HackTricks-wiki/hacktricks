# Open vSwitch 转发 skb 标记剥除导致 ESP 页面缓存写入

{{#include ../../../banners/hacktricks-training.md}}

一种有用的 Linux kernel exploitation 模式是：**清除 skb 的所有权元数据，但不移除其外来片段**，然后将该 skb 路由到会原地写入的消费者。在 Open vSwitch (OVS) 场景中，userspace upcall 失败会清除仍然存活的 `MSG_ZEROCOPY` skb 上的 `SKBFL_SHARED_FRAG`；随后 ESP 直接在只读文件的页面缓存 folio 上解密。这可以实现确定性的本地页面缓存写入，相关问题已通过 CVE-2026-90049、CVE-2026-89487 和 CVE-2026-80977 进行跟踪。<sup>[[1]](#references)[[2]](#references)</sup>

这属于 Copy Fail/Dirty Frag 类问题，而非经典的内存破坏：不需要竞争条件或地址泄露，文件只需可读，修改后的字节存在于页面缓存中，而非磁盘上。<sup>[[2]](#references)[[3]](#references)</sup>

## 安全不变量：外来片段必须始终保留标记

`SKBFL_SHARED_FRAG` 用于告知原地消费者，skb 片段可能引用了它们并不独占的存储。只有当 `skb_has_shared_frag()` 返回 false 时，`esp_input()` 中的 ESP fast path 才能原地解密非线性、未克隆的 skb；否则，`skb_cow_data()` 会先创建私有存储。这个消费者端检查是在 Dirty Frag 之后添加的。<sup>[[5]](#references)</sup>

因此，该不变量包含两个相互独立的部分：<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. 原地写入者必须检查 `SKBFL_SHARED_FRAG`，并在修改前复制共享数据。
2. 只要外来页面仍然附着，每条克隆、合并、转移或转发路径都必须保留该标记。

Fragnesia 在 `skb_try_coalesce()` 中移动片段描述符时违反了第二条规则。OVS 路径则略有不同：它根本不转移片段，而是在原始 skb 上**直接清除标记，然后继续转发它**。<sup>[[2]](#references)[[4]](#references)</sup>

## 无特权用户可达的 OVS 攻击面

OVS 的 kernel datapath 通过 `ovs_datapath`、`ovs_vport`、`ovs_flow` 和 `ovs_packet` 等 generic-netlink families 进行控制。其修改操作使用支持 namespace 的 `GENL_UNS_ADMIN_PERM`，因此，在 `unshare -Urn` 下运行的进程可获得 `CAP_NET_ADMIN`，从而在自己的 network namespace 中创建 datapath、连接 veth 并安装 flow actions。解析 OVS family 时也可能自动加载 `openvswitch.ko`；此攻击面不需要 host `CAP_SYS_MODULE`、`ovs-vsctl` 或 `ovs-vswitchd`。<sup>[[2]](#references)[[7]](#references)</sup>

关键在于区分两种 upcall 类型：<sup>[[2]](#references)[[7]](#references)</sup>

- **flow miss** 会将数据包发送给 `ovs-vswitchd`；如果 upcall 失败，数据包通常会被丢弃。
- 显式的 `OVS_ACTION_ATTR_USERSPACE` action 会将一个借用的副本发送到指定的 port ID，然后在原始 skb 上执行后续 actions。

因此，攻击者可以安装如下形式的 flow：<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

没有监听器拥有所选的端口 ID，因此 userspace 操作会可预测地失败，而后续的 `OUTPUT` 操作会保持原始数据包存活。<sup>[[1]](#references)[[2]](#references)</sup>

## 根本原因：对仍然存活的数据包调用 `skb_tx_error()`

存在漏洞的 OVS upcall 错误处理路径会调用 `skb_tx_error(skb)`。该辅助函数原本用于发送失败且 skb 随后会被释放的情况；它通过 `skb_zcopy_clear()` 完成 zerocopy 记账，而其标志掩码历来还会移除 `SKBFL_SHARED_FRAG`。OVS 忽略了 userspace 操作错误，并继续执行操作列表，违反了该辅助函数的生命周期约定。<sup>[[1]](#references)[[2]](#references)</sup>

可利用的状态转换如下：<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

只有在 `skb_zcopy()` 找到 zerocopy 状态时，这种方式才有效。仅携带 `SKBFL_SHARED_FRAG` 的 fragment 并不足够；`MSG_ZEROCOPY` 很有用，因为它会创建 `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG`，并且还会设置 `SKBFL_DONT_ORPHAN`。后者会使 `skb_orphan_frags()` 在 OVS 用户空间复制期间跳过对外部页面的替换。<sup>[[2]](#references)[[3]](#references)</sup>

## 构建写入原语

端到端触发过程由以下部分组成。<sup>[[2]](#references)[[3]](#references)</sup>

1. 使用 `unshare -Urn` 进入私有用户和网络命名空间。
2. 使用 `PROT_READ | MAP_SHARED` 映射一个可读的目标文件。
3. 使用单独的 sender netns 和一对 veth；本地 loopback 会复制借用的页面，从而破坏该原语。
4. 构建 OVS datapath，以及会失败的 `USERSPACE` 后接 `OUTPUT` 的 flow。
5. 使用 `rfc4106(gcm(aes))` 和 UDP 端口 4500 安装 transport-mode ESP-in-UDP XFRM state。
6. 发送一个 `MSG_ZEROCOPY` datagram，其 iovec 结构为 `[ESP header | mapped file bytes | invalid ICV]`。

XFRM state 使用 20 字节的 AES-128-GCM 密钥材料：16 字节 AES 密钥后接四字节 RFC 4106 salt。对于选定的八字节显式 IV，payload 加密从计数器块 `salt || IV || be32(2)` 开始；计数器值 1 则用于掩蔽认证结果。<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

一旦 OVS 去除 marker，ESP 就会走 no-copy 路径，并对由文件支持的片段执行 `plaintext = ciphertext XOR keystream`。此变换之后才会检查认证，因此全零的无效 ICV 会使数据包以 `-EBADMSG` 失败，但此时 page-cache 中的字节已经发生变化。<sup>[[2]](#references)</sup>

### 将 GCM 转换为可选择的字节

对于当前字节 `C` 和目标字节 `P`，第一个 payload keystream 字节必须是 `C XOR P`。固定 AES 密钥和 salt 后，遍历 16 位的 explicit IV 后缀，并为每个可能的首个 keystream 字节预计算一个后缀：<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

公开实现将密文限制为 32 字节，并针对每个数据包将文件片段前移一个字节。选定的首字节会覆盖前一个数据包的首个附带字节；每个数据包发送前，`pread()` 都会刷新 `C`，相同字节会被跳过，最后一个数据包则会缩短，以确保写入不超出请求范围。因此，256 项查找表可将这一原语转化为按字节粒度写入指定内容到页缓存，每个不同字节大约需要一个数据包。<sup>[[2]](#references)[[3]](#references)</sup>

## 将页缓存写入用于提权至 root

一个实用目标是现有的 setuid-root 可执行文件。PoC 会用一个完整的静态 ELF 替换前 160 个字节。该 ELF 包含一个固定地址的、可读可执行的 `PT_LOAD`，没有 `PT_INTERP`，其代码会先调用 `setuid(0)`，再调用 `execve("/bin/sh", ...)`。这样就无需假设原始二进制文件的入口点、PIE 布局、动态加载器或重定位方式。<sup>[[2]](#references)[[3]](#references)</sup>

由于页缓存不受命名空间隔离，这项修改在用户命名空间之间也可见。被修改的 folio 不会被标记为脏页，因此不会写回磁盘；趁目标文件仍驻留在内存中时执行它，然后使用 `posix_fadvise(..., POSIX_FADV_DONTNEED)` 丢弃临时篡改内容，使后续读取重新从磁盘加载原始内容。<sup>[[2]](#references)[[3]](#references)</sup>

## 暴露面检查与缓解措施

首先检查实际使用的发行版内核。相关的暴露条件包括非特权用户命名空间、OVS 是否可用或已驻留，以及是否存在可用的 ESP 实现。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

升级到包含完整修复系列的 kernel；最终修复覆盖 recirculation 路径，并避免修改共享的 `skb_shinfo()` 状态，同时修复了 `skb_zerocopy()` 中相关的 strip 问题。<sup>[[1]](#references)[[2]](#references)</sup>

如果未使用 OVS，请使用 modprobe `install` 规则阻止通过别名和名称加载，而不要只依赖 `blacklist`。如果主机不终止 IPsec，且 ESP 是模块，同样的控制措施也能移除解密 sink。<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

这些规则在模块已经加载或功能已内置于内核时不起作用。禁用非特权用户命名空间也会移除命名空间能力来源，但可能导致浏览器、Flatpak、Podman 及其他沙箱/容器工作负载无法正常运行。<sup>[[2]](#references)</sup>

## Review lessons

审计 zero-copy networking 时，不要只搜索复制或移动 fragments 的 helpers。还要找出会清除成组标志的错误处理/完成处理 helpers，然后确认每个调用者都遵守文档规定的 skb 生命周期约定。即使清除代码从未直接访问 fragment，与 zerocopy 生命周期标志成组的页面所有权位仍然涉及安全问题。<sup>[[1]](#references)[[2]](#references)</sup>

稳健的修复必须涵盖 skb 可能存续的所有路径——包括 action continuation 和 recirculation——并考虑共享 `skb_shinfo()` 的 clones。在 consumer 侧，认证失败无法撤销原地 AEAD transform 已执行的明文写入，因此必须在开始解密前检查外部存储。<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev 修复系列：net：不要从转发的 skb 中剥除 zerocopy frag 标记](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec：Open vSwitch 转发的 skb 标记剥除可实现确定性的 ESP page-cache LPE](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` 概念验证](https://github.com/doyensec/ovs-pagecache-write)
- [4] [针对原始 Fragnesia 合并路径的 Linux 修复（`f84eca581739`）](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux ESP consumer 侧的共享 fragment 检查（`f4c50a4034e6`）](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106：在 IPsec ESP 中使用 Galois/Counter Mode（GCM）](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch 内核 datapath 文档](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
