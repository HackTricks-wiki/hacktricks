# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## XFlash における Trust boundary（DA1 → DA2）

- **DA1** は BootROM/Preloader によって署名・load されます。Download Agent Authorization（DAA）が有効な場合、署名済みの DA1 のみが実行されるべきです。
- **DA2** は USB 経由で送信されます。DA1 は **size**、**load address**、**SHA-256** を受け取り、受信した DA2 を hash して、DA1 に埋め込まれた **expected hash**（RAM にコピーされる）と比較します。
- **Weakness:** パッチ未適用の loader では、DA1 は DA2 の load address/size を sanitize せず、expected hash を memory 上で writable のまま保持します。これにより、host は check を tamper できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara の flow（"two BOOT_TO" trick）

1. **First `BOOT_TO`:** DA1→DA2 の staging flow に入ります（DA1 が memory を allocate し、DRAM を準備し、RAM 内の expected-hash buffer を公開します）。
2. **Hash-slot overwrite:** DA1 memory を scan して保存された DA2-expected hash を探し、attacker が変更した DA2 の SHA-256 で overwrite する小さな payload を送信します。これは、user-controlled な load を利用して、hash が存在する場所に payload を配置します。
3. **Second `BOOT_TO` + digest:** patched DA2 metadata を使用して別の `BOOT_TO` を trigger し、変更済み DA2 に一致する raw 32-byte digest を送信します。DA1 は受信した DA2 に対して SHA-256 を再計算し、現在は patched された expected hash と比較します。比較に成功すると、attacker code へ jump します。

load address/size は attacker が制御できるため、同じ primitive により memory 内の任意の場所（hash buffer に限らない）へ write できます。これにより、early-boot implant、secure-boot bypass helper、または malicious rootkit が可能になります。<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` は、DA1 内の expected-hash buffer にパッチを適用する有料ツールの blob を再現します。
- `sha256(...).digest()` は hex ではなく raw bytes を送信するため、DA1 はパッチ適用済みの buffer と比較します。
- DA2 は攻撃者が構築した任意の image にできます。load address/size を選択することで任意のメモリ配置が可能になり、cache invalidation は DA が処理します。<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **Mitigation**: 更新された DA は DA2 の load address を `0x40000000` に hardcode し、host が指定した address を無視します。そのため、書き込みは DA1 の hash slot（`0x200000` 付近）に到達できません。hash は引き続き計算されますが、攻撃者による書き換えはできなくなります。
- **Detecting patched DAs**: mtkclient/penumbra は、address-hardening を示すパターンを DA1 内で scan します。該当する場合、Carbonara は skip されます。古い DA は writable な hash slot（V5 DA1 の `0x22dea4` 付近など）を公開しており、引き続き exploit 可能です。
- **V5 vs V6**: 一部の V6（XML）loader は user-supplied address を引き続き受け付けます。より新しい V6 binary は通常 fixed address を強制するため、downgrade しない限り Carbonara の影響を受けません。<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek は Carbonara にパッチを適用しました。より新しい vulnerability である **heapb8** は、パッチ適用済み V6 loader の DA2 USB file download handler を標的とし、`boot_to` が hardened されている場合でも code execution を可能にします。これは chunked file transfer 中の heap overflow を悪用して、DA2 の control flow を奪取します。この exploit は Penumbra/mtk-payloads で公開されており、Carbonara の修正だけでは DA attack surface 全体を閉じられないことを示しています。<sup>[[4]](#references)</sup>

## Notes for triage and hardening

- DA2 の address/size が unchecked で、DA1 が expected hash を writable のまま保持している device は vulnerable です。後続の Preloader/DA が address bounds を enforce するか、hash を immutable に保持している場合、Carbonara は mitigated されます。
- DAA を有効化し、DA1/Preloader が BOOT_TO parameters（bounds + DA2 の authenticity）を validate するようにすることで、この primitive を閉じられます。hash patch だけを閉じて load を bound しない場合、arbitrary write risk は残ります。

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
