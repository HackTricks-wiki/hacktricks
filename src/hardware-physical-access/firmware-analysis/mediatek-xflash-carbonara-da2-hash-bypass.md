# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 概要

「Carbonara」は、MediaTek の XFlash download path を悪用し、DA1 の integrity checks を回避して、modified Download Agent stage 2（DA2）を実行します。DA1 は DA2 に対応する SHA-256 を RAM に保存し、branch する前に比較します。多くの loader では、host が DA2 の load address と size を完全に制御できるため、unchecked memory write によってメモリ上の hash を上書きし、任意の payload へ execution を redirect できます（DA による cache invalidation が処理される pre-OS context）。<sup>[[1]](#references)[[2]](#references)</sup>

## XFlash における trust boundary（DA1 → DA2）

- **DA1** は BootROM/Preloader によって signed/load されます。Download Agent Authorization（DAA）が有効な場合、実行できるのは signed DA1 のみです。
- **DA2** は USB 経由で送信されます。DA1 は **size**、**load address**、**SHA-256** を受け取り、受信した DA2 を hash して、DA1 に embedded された **expected hash**（RAM に copy される）と比較します。
- **Weakness:** unpatched loader では、DA1 が DA2 の load address/size を sanitize せず、expected hash を memory 上で writable のまま保持するため、host が check を tamper できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara の flow（「two BOOT_TO」trick）

1. **最初の `BOOT_TO`:** DA1→DA2 staging flow に入ります（DA1 が allocate し、DRAM を prepare して、RAM 内の expected-hash buffer を expose します）。
2. **Hash-slot overwrite:** DA1 memory を scan して stored DA2-expected hash を探し、attacker-modified DA2 の SHA-256 で上書きする small payload を送信します。これは user-controlled load を利用して、hash が存在する場所に payload を配置します。
3. **2 回目の `BOOT_TO` + digest:** patched DA2 metadata で別の `BOOT_TO` を trigger し、modified DA2 に一致する raw 32-byte digest を送信します。DA1 は受信した DA2 に対して SHA-256 を再計算し、現在は patched されている expected hash と比較します。比較が成功すると attacker code へ jump します。

影響を受ける loader では、unchecked address と size により、hash slot を超えた attacker-selected な pre-OS memory-write primitive が提供される可能性があります。SoC の memory map と後続の verification stages に応じて、これは early-boot implants、secure-boot-bypass helpers、または rootkit-style payloads に利用できます。DA code execution だけでは、自動的に persistence や完全な secure-boot bypass が得られるわけではありません。別途 persistence mechanism が必要であり、互換性のある verification chain も引き続き必要です。<sup>[[1]](#references)[[2]](#references)</sup>

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
- 16バイトの `payload` は、有料ツールのワークフローで観測された blob を再現し、公開されている実装が想定ハッシュバッファを patch するために使用します。これは loader 固有のものであり、すべての SoC や DA で使用できる汎用的な hash-slot patch ではありません。<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` は hex ではなく raw bytes を送信するため、DA1 は patch 済みのバッファと比較します。
- 脆弱で、かつ適合する loader では、DA2 を攻撃者が構築した image にでき、選択した load metadata によってメモリ配置を制御できます。誤ったアドレスは target をハングさせたり損傷させたりする可能性があるため、送信前に DA/SoC の組み合わせを検証してください。<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **観測された mitigation**: 研究者が調査した hardened DA は、DA2 の load address を `0x40000000` に強制し、host から指定された address を無視します。これにより、`0x200000` 付近で観測された DA1 hash region への書き込みを防止します。両方のアドレスを architectural constants ではなく、実装固有のものとして扱ってください。
- **patched DA の検出**: mtkclient/penumbra は DA1 を scan し、address-hardening を示す pattern を探します。見つかった場合、Carbonara は skip されます。古い DA は書き込み可能な hash slot（V5 DA1 の `0x22dea4` のような offset 付近が一般的）を公開しており、引き続き exploit 可能です。
- **V5 と V6**: 一部の V6 (XML) loader は依然として user-supplied address を受け入れます。新しい V6 binary は通常 fixed address を強制するため、downgrade しない限り Carbonara に対して immune です。<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek は Carbonara を patch しました。より新しい vulnerability である **heapb8** は、patched V6 loader の DA2 USB file download handler を target とし、`boot_to` が hardened されていても code execution を可能にします。これは chunked file transfer 中の heap overflow を悪用して、DA2 の control flow を奪取します。この exploit は Penumbra/mtk-payloads で公開されており、Carbonara の修正だけでは DA attack surface 全体を閉じられないことを示しています。<sup>[[4]](#references)</sup>

## Notes for triage and hardening

- DA2 の address/size が unchecked で、DA1 が想定ハッシュを writable のまま保持している device は vulnerable です。後続の Preloader/DA が address bounds を強制するか、hash を immutable に保持する場合、Carbonara は mitigated されます。
- DAA を有効にし、DA1/Preloader が BOOT_TO parameters（bounds + DA2 の authenticity）を validate することで、この primitive を閉じられます。hash patch だけを閉じて load を bound しない場合、arbitrary write risk は残ります。

## References

- [1] [Carbonara: 誰も提供しなかった MediaTek exploit](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit のドキュメント](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: patched V6 Download Agent の exploit](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
