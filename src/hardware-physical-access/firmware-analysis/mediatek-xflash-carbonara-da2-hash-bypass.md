# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 摘要

"Carbonara" 利用 MediaTek 的 XFlash 下载路径，在绕过 DA1 完整性检查的情况下运行被修改的 Download Agent stage 2 (DA2)。DA1 在 RAM 中存储 DA2 的期望 SHA-256，并在跳转前进行比较。在许多 loader 上，host 完全控制 DA2 的加载地址/大小，从而允许一次未检查的内存写入，可以覆盖内存中的该哈希并将执行重定向到任意 payload（OS 启动前上下文，缓存失效由 DA 处理）。

## XFlash 的信任边界 (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** is sent over USB. DA1 receives **size**, **load address**, and **SHA-256** and hashes the received DA2, comparing it to an **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** On unpatched loaders, DA1 does not sanitize the DA2 load address/size and keeps the expected hash writable in memory, enabling the host to tamper with the check.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Enter the DA1→DA2 staging flow (DA1 allocates, prepares DRAM, and exposes the expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Send a small payload that scans DA1 memory for the stored DA2-expected hash and overwrites it with the SHA-256 of the attacker-modified DA2. This leverages the user-controlled load to land the payload where the hash resides.
3. **Second `BOOT_TO` + digest:** Trigger another `BOOT_TO` with the patched DA2 metadata and send the raw 32-byte digest matching the modified DA2. DA1 recomputes SHA-256 over the received DA2, compares it against the now-patched expected hash, and the jump succeeds into attacker code.

Because load address/size are attacker-controlled, the same primitive can write anywhere in memory (not just the hash buffer), enabling early-boot implants, secure-boot bypass helpers, or malicious rootkits.

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
- `payload` 复制了付费工具的二进制 blob，该 blob 在 DA1 内修补 expected-hash 缓冲区。
- `sha256(...).digest()` 发送原始字节（不是 hex），因此 DA1 会与被修补的缓冲区比较。
- DA2 可以是任意攻击者构建的镜像；选择加载地址/大小允许任意内存放置，缓存失效由 DA 处理。

## 补丁态势（已加固的 loaders）

- **缓解措施**：更新的 DAs 将 DA2 的加载地址硬编码为 `0x40000000` 并忽略主机提供的地址，因此写入无法到达 DA1 的 hash 槽（约 `0x200000` 范围）。哈希仍被计算，但不再可被攻击者写入。
- **检测已打补丁的 DAs**：mtkclient/penumbra 会扫描 DA1 是否有表明地址加固的模式；如果发现则会跳过 Carbonara。旧的 DAs 暴露可写的 hash 槽（常见于 V5 DA1 的偏移如 `0x22dea4`）并仍可被利用。
- **V5 vs V6**：一些 V6 (XML) loaders 仍接受用户提供的地址；较新的 V6 二进制通常强制固定地址并对 Carbonara 免疫，除非被降级。

## Carbonara 之后（heapb8）注记

MediaTek 修补了 Carbonara；一个更新的漏洞，**heapb8**，针对已打补丁的 V6 loaders 上的 DA2 USB 文件下载处理器，允许即使在 `boot_to` 被加固时也能执行代码。它利用分块文件传输期间的堆溢出夺取 DA2 的控制流。该利用在 Penumbra/mtk-payloads 上公开，表明 Carbonara 的修复并未关闭所有 DA 攻击面。

## 用于分级与加固的注意事项

- 在 DA2 地址/大小未被检查且 DA1 保持 expected hash 可写的设备上存在漏洞。如果后续的 Preloader/DA 强制地址边界或使 hash 不可变，则 Carbonara 得到缓解。
- 启用 DAA 并确保 DA1/Preloader 验证 BOOT_TO 参数（边界 + DA2 的真实性）可以关闭该原语。仅关闭 hash 修补而不限制加载边界仍会留下任意写入的风险。

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
