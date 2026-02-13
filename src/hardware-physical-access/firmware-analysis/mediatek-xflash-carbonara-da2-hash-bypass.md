# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 概要

"Carbonara" は MediaTek の XFlash ダウンロード経路を悪用して、DA1 の整合性チェックがあっても改変した Download Agent stage 2 (DA2) を実行させます。DA1 は DA2 の期待される SHA-256 を RAM に保存し、分岐する前に比較します。多くの loader ではホストが DA2 のロードアドレス/サイズを完全に制御できるため、検査されないメモリ書き込みによりそのメモリ上のハッシュを書き換え、任意のペイロードへ実行をリダイレクトできます（pre-OS コンテキストで、cache invalidation は DA が処理）。

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** is sent over USB. DA1 receives **size**, **load address**, and **SHA-256** and hashes the received DA2, comparing it to an **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** On unpatched loaders, DA1 does not sanitize the DA2 load address/size and keeps the expected hash writable in memory, enabling the host to tamper with the check.

## Carbonara フロー ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 のステージングフローに入る（DA1 が DRAM を確保・準備し、期待ハッシュ用のバッファを RAM に露出させる）。
2. **Hash-slot overwrite:** 小さなペイロードを送り、DA1 のメモリをスキャンして格納された DA2 用期待ハッシュを見つけ出し、攻撃者が改変した DA2 の SHA-256 で上書きする。これは、ユーザ制御のロードを利用してハッシュが存在する場所にペイロードを配置することで実現する。
3. **Second `BOOT_TO` + digest:** パッチ済みの DA2 メタデータで別の `BOOT_TO` をトリガーし、改変した DA2 に一致する生の 32 バイトダイジェストを送る。DA1 は受信した DA2 の SHA-256 を再計算し、今やパッチされた期待ハッシュと比較し、ジャンプが攻撃者コードへ成功する。

ロードアドレス/サイズが攻撃者により制御されるため、同じプリミティブはハッシュバッファに限らずメモリ上の任意の場所を書き換え可能であり、early-boot implant、secure-boot bypass 補助、または悪意ある rootkits を仕込むことができます。

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
- `payload` は DA1 内の expected-hash バッファをパッチする有料ツールの blob を再現します。
- `sha256(...).digest()` は生バイト（hex ではなく）を送るため、DA1 はパッチ済みバッファと比較します。
- DA2 は攻撃者が作成した任意のイメージにでき、ロード先アドレス/サイズを選ぶことで任意のメモリ配置が可能になります（キャッシュ無効化は DA が処理します）。

## トリアージとハードニングの注意点

- DA2 のアドレス/サイズが検証されず、DA1 が expected-hash バッファを書き込み可能なままにしているデバイスは脆弱です。後続の Preloader/DA がアドレス境界を強制するかハッシュを不変に保てば、Carbonara は緩和されます。
- DAA を有効にし、DA1/Preloader が BOOT_TO パラメータ（境界と DA2 の真正性）を検証することを確実にすると、このプリミティブは封じられます。ロードの境界検査を行わずハッシュパッチだけを無効化しても、任意書き込みのリスクは残ります。

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
