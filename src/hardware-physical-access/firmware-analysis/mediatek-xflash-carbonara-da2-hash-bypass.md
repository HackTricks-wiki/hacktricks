# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 摘要

"Carbonara" 滥用 MediaTek 的 XFlash 下载路径，在通过 DA1 完整性检查的情况下运行被修改的 Download Agent stage 2 (DA2)。DA1 将预期的 DA2 的 SHA-256 存储在 RAM 中并在跳转前进行比较。在许多 loader 上，host 完全控制 DA2 的加载地址/大小，从而提供了一个未检查的内存写入能力，可以覆盖内存中的该哈希并将执行重定向到任意 payload（在 OS 启动前上下文，DA 负责处理 cache invalidation）。

## XFlash 中的信任边界 (DA1 → DA2)

- **DA1** 由 BootROM/Preloader 签名/加载。当 Download Agent Authorization (DAA) 启用时，理论上只有签名的 DA1 会运行。
- **DA2** 通过 USB 发送。DA1 接收 **size**、**load address** 和 **SHA-256**，对接收到的 DA2 进行哈希，并将其与嵌入在 DA1 中的 **预期哈希**（复制到 RAM）进行比较。
- **弱点：** 在未修补的 loader 上，DA1 不会对 DA2 的 load address/size 进行清理，并且将预期哈希保留为可写，从而使 host 能够篡改该检查。

## Carbonara 流程（"two BOOT_TO" 技巧）

1. **First `BOOT_TO`:** 进入 DA1→DA2 的分阶段流程（DA1 分配、准备 DRAM，并在 RAM 中暴露预期哈希缓冲区）。
2. **Hash-slot overwrite:** 发送一个小型 payload，扫描 DA1 内存以定位存储的 DA2 预期哈希，并用攻击者修改后的 DA2 的 SHA-256 覆盖它。该步骤利用用户可控的加载，使 payload 落在哈希所在的位置。
3. **Second `BOOT_TO` + digest:** 触发另一次 `BOOT_TO` 并使用已打补丁的 DA2 元数据，发送与修改后 DA2 匹配的原始 32 字节 digest。DA1 对接收到的 DA2 重新计算 SHA-256，将其与现已被篡改的预期哈希比较，跳转成功进入攻击者代码。

由于 load address/size 由攻击者控制，同一原语可以写入内存中的任何位置（不仅限于哈希缓冲区），从而支持早期引导植入、secure-boot 绕过辅助工具或恶意 rootkit。

## 最小 PoC 模式 (mtkclient-style)
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
- `payload` 复制了付费工具的 blob，用来修补 DA1 内的 expected-hash 缓冲区。
- `sha256(...).digest()` 发送原始字节（不是十六进制），因此 DA1 会将其与已修补的缓冲区比较。
- DA2 可以是任意攻击者构建的镜像；选择加载地址/大小允许任意内存放置，缓存失效由 DA 处理。

## 排查与加固注意事项

- 如果设备未检查 DA2 的地址/大小 且 DA1 保持 expected hash 可写，则易受攻击。若后续的 Preloader/DA 强制地址边界或使 hash 不可变，则可缓解 Carbonara。
- 启用 DAA 并确保 DA1/Preloader 验证 BOOT_TO 参数（边界 + DA2 的真实性）可以关闭该原语。仅关闭 hash 修补而不限制加载边界仍然会留下任意写入风险。

## 参考资料

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
