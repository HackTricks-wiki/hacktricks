# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 概要

"Carbonara" は MediaTek の XFlash ダウンロード経路を悪用して、DA1 の整合性チェックをすり抜けて改変された Download Agent stage 2 (DA2) を実行させます。DA1 は期待される DA2 の SHA-256 を RAM に保存し、分岐する前に比較します。多くのローダーではホストが DA2 のロードアドレス/サイズを完全に制御できるため、検証されないメモリ書き込みによりその RAM 内ハッシュを書き換え、任意のペイロードへ実行をリダイレクトできます（プリOSコンテキストで、キャッシュの無効化は DA が処理します）。

## XFlash の信頼境界 (DA1 → DA2)

- **DA1** は BootROM/Preloader により署名されてロードされます。Download Agent Authorization (DAA) が有効な場合、署名された DA1 のみが実行されるはずです。
- **DA2** は USB 経由で送られます。DA1 は **size**、**load address**、および **SHA-256** を受け取り、受信した DA2 をハッシュ化して、DA1 に埋め込まれた **期待ハッシュ**（RAM にコピーされている）と比較します。
- **弱点:** 未修正のローダーでは、DA1 が DA2 のロードアドレス/サイズを検証せず、期待ハッシュをメモリ上で書き込み可能なままにしているため、ホストがチェックを書き換えることができます。

## Carbonara フロー ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 のステージングフローに入る（DA1 が DRAM を割り当て、準備し、期待ハッシュ用バッファを RAM に露出させる）。
2. **Hash-slot overwrite:** 小さなペイロードを送り、DA1 のメモリをスキャンして格納されている DA2 の期待ハッシュを見つけ、攻撃者が改変した DA2 の SHA-256 に上書きします。これは、ユーザ制御のロードを利用してペイロードをハッシュのある場所に配置する手法です。
3. **Second `BOOT_TO` + digest:** パッチ済みの DA2 メタデータで別の `BOOT_TO` を起動し、改変した DA2 に一致する生の32バイトダイジェストを送ります。DA1 は受信した DA2 に対して SHA-256 を再計算し、パッチされた期待ハッシュと比較し、ジャンプが成功して攻撃者コードが実行されます。

ロードアドレス/サイズが攻撃者に制御されているため、同じ原始操作によりハッシュバッファに限らず任意のメモリ位置に書き込みが可能で、早期ブートのインプラント、secure-boot バイパス補助、または悪意あるルートキットなどを実現できます。

## 最小 PoC パターン (mtkclient-style)
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
- `payload` は DA1 内の expected-hash バッファをパッチする有料ツールの blob を再現します。
- `sha256(...).digest()` は生バイト（hex ではない）を送るので DA1 はパッチ済みバッファと比較します。
- DA2 は攻撃者が作成した任意のイメージであり、ロードアドレス/サイズを選ぶことで任意のメモリ配置が可能になり、キャッシュ無効化は DA が処理します。

## Patch landscape (hardened loaders)

- **Mitigation**: 更新された DAs は DA2 のロードアドレスを `0x40000000` にハードコードし、ホストが渡すアドレスを無視するため、書き込みが DA1 のハッシュスロット（約 `0x200000` 範囲）に到達できなくなります。ハッシュは計算され続けますが、攻撃者が書き換えられなくなります。
- **Detecting patched DAs**: mtkclient/penumbra はアドレス強化を示すパターンを DA1 上でスキャンします；見つかれば Carbonara はスキップされます。古い DAs は書き込み可能なハッシュスロットを露出しており（V5 DA1 の `0x22dea4` のようなオフセット周辺に多い）、引き続き悪用可能です。
- **V5 vs V6**: 一部の V6 (XML) ローダーは依然としてユーザー指定のアドレスを受け入れます；新しい V6 バイナリは通常固定アドレスを強制し、ダウングレードされない限り Carbonara に対して免疫があります。

## Post-Carbonara (heapb8) note

MediaTek は Carbonara を修正しました；新しい脆弱性、**heapb8** はパッチ済みの V6 ローダーの DA2 USB ファイルダウンロードハンドラを標的とし、`boot_to` が強化されていてもコード実行を与えます。これはチャンク化されたファイル転送中のヒープオーバーフローを悪用して DA2 の制御フローを奪います。エクスプロイトは Penumbra/mtk-payloads で公開されており、Carbonara の修正がすべての DA 攻撃面を塞いでいないことを示しています。

## Notes for triage and hardening

- DA2 のアドレス/サイズが未検査で、DA1 が expected-hash を書き込み可能なままのデバイスは脆弱です。後の Preloader/DA がアドレス境界を強制する、あるいはハッシュを不変にする場合、Carbonara は緩和されます。
- DAA を有効にし、DA1/Preloader が BOOT_TO パラメータ（境界チェック＋DA2 の正当性）を検証するようにすれば、この原始的手段は閉じられます。ロードの境界チェックを行わずにハッシュパッチのみを閉じても、任意書き込みのリスクは残ります。

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
