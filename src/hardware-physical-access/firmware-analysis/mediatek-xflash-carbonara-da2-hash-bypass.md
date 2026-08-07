# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 摘要

“Carbonara”利用 MediaTek 的 XFlash download path，在 DA1 integrity checks 存在的情况下运行经过修改的 Download Agent stage 2（DA2）。DA1 会将 DA2 预期的 SHA-256 存储在 RAM 中，并在跳转前进行比较。在许多 loader 中，host 完全控制 DA2 的 load address/size，因此存在未经检查的 memory write，可覆盖内存中的 hash，并将执行重定向到任意 payload（运行于 pre-OS context，cache invalidation 由 DA 处理）。<sup>[[1]](#references)[[2]](#references)</sup>

## XFlash 中的 trust boundary（DA1 → DA2）

- **DA1** 由 BootROM/Preloader 签名并加载。当启用 Download Agent Authorization（DAA）时，只应运行经过签名的 DA1。
- **DA2** 通过 USB 发送。DA1 接收 **size**、**load address** 和 **SHA-256**，并对接收的 DA2 进行 hash，然后将其与 **embedded in DA1** 的 **expected hash**（已复制到 RAM）进行比较。
- **Weakness：** 在未打补丁的 loader 中，DA1 不会 sanitize DA2 的 load address/size，并且会将 expected hash 保持为可写状态，从而允许 host 篡改该 check。<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow（“two BOOT_TO” trick）

1. **First `BOOT_TO`：** 进入 DA1→DA2 staging flow（DA1 分配内存、准备 DRAM，并在 RAM 中暴露 expected-hash buffer）。
2. **Hash-slot overwrite：** 发送一个 small payload，扫描 DA1 memory 中存储的 DA2-expected hash，并将其覆盖为 attacker-modified DA2 的 SHA-256。该过程利用 user-controlled load，将 payload 放置到 hash 所在的位置。
3. **Second `BOOT_TO` + digest：** 使用 patched DA2 metadata 触发另一次 `BOOT_TO`，并发送与 modified DA2 匹配的 raw 32-byte digest。DA1 对接收到的 DA2 重新计算 SHA-256，将其与现已 patched 的 expected hash 进行比较，随后成功跳转到 attacker code。

由于 load address/size 由 attacker 控制，同一 primitive 可以向 memory 中的任意位置写入（而不仅是 hash buffer），从而支持 early-boot implants、secure-boot bypass helpers 或 malicious rootkits。<sup>[[1]](#references)[[2]](#references)</sup>

## Minimal PoC pattern（mtkclient-style）
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
- `payload` 复现了付费工具中用于 patch DA1 内 expected-hash buffer 的 blob。
- `sha256(...).digest()` 发送 raw bytes（而不是 hex），因此 DA1 会将其与 patched buffer 进行比较。
- DA2 可以是攻击者构建的任意 image；通过选择 load address/size，可以实现任意内存放置，而 cache invalidation 由 DA 处理。<sup>[[3]](#references)</sup>

## Patch landscape（已加固的 loaders）

- **Mitigation**：更新后的 DAs 将 DA2 load address 硬编码为 `0x40000000`，并忽略 host 提供的 address，因此写入无法到达 DA1 hash slot（约为 `0x200000` 范围）。hash 仍会被计算，但攻击者无法再写入它。
- **Detecting patched DAs**：mtkclient/penumbra 会扫描 DA1 中表示 address-hardening 的 patterns；如果发现这些 patterns，则跳过 Carbonara。旧版 DAs 会暴露可写的 hash slots（通常位于 V5 DA1 中类似 `0x22dea4` 的 offsets），因此仍可被 exploit。
- **V5 vs V6**：部分 V6（XML）loaders 仍接受用户提供的 addresses；较新的 V6 binaries 通常会强制使用 fixed address，除非 downgrade，否则不会受到 Carbonara 影响。<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara（heapb8）说明

MediaTek 已修复 Carbonara；一个较新的 vulnerability **heapb8** 针对已 patch 的 V6 loaders 中的 DA2 USB file download handler，即使 `boot_to` 已加固，也能实现 code execution。它利用 chunked file transfers 期间的 heap overflow 来夺取 DA2 的 control flow。该 exploit 已公开于 Penumbra/mtk-payloads 中，并说明 Carbonara fixes 并未关闭所有 DA attack surface。<sup>[[4]](#references)</sup>

## Triage 和 hardening 注意事项

- 如果 DA2 address/size 未经检查，且 DA1 仍保留可写的 expected hash，则设备存在 vulnerability。如果后续的 Preloader/DA 强制执行 address bounds，或保持 hash immutable，则 Carbonara 已得到 mitigation。
- 启用 DAA，并确保 DA1/Preloader 验证 BOOT_TO parameters（bounds + DA2 的 authenticity），即可关闭该 primitive。仅关闭 hash patch 而不限制 load，仍会留下 arbitrary write risk。

## References

- [1] [Carbonara：无人提供的 MediaTek exploit](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8：exploit patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
