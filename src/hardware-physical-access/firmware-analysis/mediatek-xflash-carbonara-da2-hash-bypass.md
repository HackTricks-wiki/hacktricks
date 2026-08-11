# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 摘要

“Carbonara”滥用 MediaTek 的 XFlash download path，即使 DA1 完整性检查存在，也能运行经过修改的 Download Agent stage 2（DA2）。DA1 会将 DA2 预期的 SHA-256 存储在 RAM 中，并在跳转前进行比较。在许多 loader 中，主机可以完全控制 DA2 的加载地址和大小，从而获得未经检查的内存写入能力，覆盖内存中的哈希值，并将执行流重定向到任意 payload（DA 负责处理 cache invalidation 的 pre-OS 上下文）。<sup>[[1]](#references)[[2]](#references)</sup>

## XFlash 中的信任边界（DA1 → DA2）

- **DA1** 由 BootROM/Preloader 签名并加载。当启用 Download Agent Authorization（DAA）时，只有经过签名的 DA1 才应运行。
- **DA2** 通过 USB 发送。DA1 接收 **size**、**load address** 和 **SHA-256**，并对接收到的 DA2 进行哈希计算，将结果与 **嵌入 DA1 的预期哈希**（已复制到 RAM）进行比较。
- **弱点：** 在未打补丁的 loader 中，DA1 不会清理 DA2 的加载地址/大小，并且会继续将内存中的预期哈希保持为可写状态，从而允许主机篡改检查过程。<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara 流程（“two BOOT_TO” trick）

1. **第一次 `BOOT_TO`：** 进入 DA1→DA2 staging flow（DA1 分配内存、准备 DRAM，并在 RAM 中暴露预期哈希缓冲区）。
2. **覆盖哈希槽：** 发送一个小型 payload，扫描 DA1 内存以查找存储的 DA2 预期哈希，并将其覆盖为攻击者修改后的 DA2 的 SHA-256。该过程利用用户可控的加载操作，使 payload 被写入哈希所在位置。
3. **第二次 `BOOT_TO` + digest：** 使用经过修改的 DA2 metadata 触发另一次 `BOOT_TO`，并发送与修改后 DA2 匹配的原始 32 字节 digest。DA1 重新计算接收到的 DA2 的 SHA-256，将其与已被修改的预期哈希进行比较，随后跳转成功并执行攻击者代码。

在受影响的 loader 中，未经检查的地址和大小可以提供由攻击者选择的 pre-OS 内存写入 primitive，其范围超出哈希槽。根据 SoC memory map 和后续 verification stages 的不同，这可以支持 early-boot implants、secure-boot-bypass helpers 或 rootkit-style payloads。仅获得 DA code execution 并不会自动提供 persistence 或完整的 secure-boot bypass；仍然需要单独的 persistence mechanism 和兼容的 verification chain。<sup>[[1]](#references)[[2]](#references)</sup>

## Minimal PoC pattern (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- 16 字节的 `payload` 复现了在付费工具工作流中观察到的 blob，并被已发布的实现用于修补预期哈希缓冲区。它是 loader 特定的，并非适用于每个 SoC 或 DA 的通用哈希槽修补方案。<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` 发送的是原始字节（而不是十六进制），这样 DA1 才会与修补后的缓冲区进行比较。
- 在存在漏洞且匹配的 loader 上，DA2 可以是攻击者构建的镜像，所选的加载元数据会控制其内存放置位置。传输前应验证 DA/SoC 组合，因为错误的地址可能导致目标挂起或损坏。<sup>[[3]](#references)</sup>

## Patch 现状（已加固的 loader）

- **观察到的缓解措施**：研究人员检查的已加固 DA 会将 DA2 加载地址强制设为 `0x40000000`，并忽略主机提供的地址，从而阻止向观察到的、位于 `0x200000` 附近的 DA1 哈希区域写入。应将这两个地址都视为实现特定值，而不是架构常量。
- **检测已修补的 DA**：mtkclient/penumbra 会扫描 DA1，查找表明地址已加固的模式；如果找到，则跳过 Carbonara。旧版 DA 会暴露可写的哈希槽（通常位于 V5 DA1 中类似 `0x22dea4` 的偏移处），因此仍可被利用。
- **V5 与 V6**：部分 V6（XML）loader 仍接受用户提供的地址；较新的 V6 二进制文件通常会强制使用固定地址，除非降级，否则不会受到 Carbonara 影响。<sup>[[2]](#references)[[3]](#references)</sup>

## Carbonara 之后（heapb8）说明

MediaTek 已修补 Carbonara；一个更新的漏洞 **heapb8** 针对已修补 V6 loader 中的 DA2 USB 文件下载处理程序，即使 `boot_to` 已加固，也能实现代码执行。它利用分块文件传输期间的堆溢出夺取 DA2 的控制流。该 exploit 已公开于 Penumbra/mtk-payloads 中，说明 Carbonara 的修复并未关闭 DA 的所有攻击面。<sup>[[4]](#references)</sup>

## 分析与加固注意事项

- 如果 DA2 的地址/大小未经过检查，并且 DA1 仍保留可写的预期哈希，则设备易受攻击。如果后续的 Preloader/DA 强制执行地址边界检查，或使哈希保持不可变，则 Carbonara 会得到缓解。
- 启用 DAA，并确保 DA1/Preloader 验证 BOOT_TO 参数（边界以及 DA2 的真实性），即可关闭这一原语。仅关闭哈希修补而不限制加载范围，仍会留下任意写入风险。

## References

- [1] [Carbonara：无人提供服务的 MediaTek exploit](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit 文档](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara 源代码](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8：利用已修补的 V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
