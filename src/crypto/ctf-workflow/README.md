# Crypto CTF ワークフロー

{{#include ../../banners/hacktricks-training.md}}

## 初期確認チェックリスト

1. 手元にあるものを特定する: encoding、encryption、hash、signature、MACのどれか。
2. 何を制御できるかを確認する: plaintext/ciphertext、IV/nonce、key、oracle（padding/error/timing）、部分的な漏えい。
3. 分類する: symmetric（AES/CTR/GCM）、public-key（RSA/ECC）、hash/MAC（SHA/MD5/HMAC）、classical（Vigenere/XOR）。
4. 成功確率の高い確認から行う: decodeレイヤー、known-plaintext XOR、nonce再利用、modeの誤用、oracleの挙動。
5. 必要な場合に限り、高度な手法に進む: lattices（LLL/Coppersmith）、SMT/Z3、side-channel。

## オンラインリソースとユーティリティ

課題が識別やレイヤーの剥離を目的としている場合や、仮説をすばやく確認したい場合に役立ちます。

### Hashの照合

- challenge hashが合成されたもの、または公開されているものと分かっている場合は検索する。
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.orgの検索.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

実際のpassword hashや機密性のあるchallenge素材を、サードパーティの照合サービスに送信しないでください。情報開示、利用規約、競技ルールが懸念される場合は、オフラインのwordlist/rule攻撃を優先してください。

### 識別に役立つツール

- CyberChef（Magic、decoding、conversion）。<sup>[[7]](#references)</sup>
- dCode（cipher/encodingの実験用ツール）。<sup>[[8]](#references)</sup>
- Boxentriq（substitution solver）。<sup>[[9]](#references)</sup>

### 練習プラットフォーム / 参考資料

- CryptoHack（実践的なcryptographyの課題）。<sup>[[10]](#references)</sup>
- Cryptopals（現代的なcryptographyでよくある落とし穴）。<sup>[[11]](#references)</sup>

### 自動decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext（さまざまなbase/encodingを試す）。<sup>[[13]](#references)</sup>

## Encodingと古典暗号

### 手法

多くのCTF crypto課題は、base encoding + 単純なsubstitution + compressionのように、変換を重ねています。各レイヤーを特定し、安全に剥がしていくことが目的です。

### Encoding: さまざまなbaseを試す

encodingが重ねられていると思われる場合（base64 → base32 → …）は、次を試してください。

- CyberChef "Magic"
- `codext`（python-codext）: `codext <string>`

よくある特徴:

- Base64: `A-Za-z0-9+/=`（`=`によるpaddingがよく使われる）
- Base32: `A-Z2-7=`（`=`によるpaddingが多いことがある）
- Ascii85/Base85: 記号が密集していることが多い。`<~ ~>`で囲まれる場合もある

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Substituted Base32ファイル名をknown-plaintextで復元する

難読化されたファイル名が`a-z2-7`のみを使い、固定suffixを取り除いた後の長さが`ceil(8 * byte_length / 5)`文字程度で、同じplaintextからファイルごとに同じ出力が得られる場合は、**paddingなしのBase32に固定のsymbol substitutionを適用している**可能性を検証してください。これらの手がかりだけでは証明になりません。予測可能なファイル名とそのciphertextを集め、大文字・小文字を維持して各plaintextをBase32でencodeし、symbolを位置ごとに対応させます。繰り返し出現するplaintextのsymbolは、毎回同じciphertextのsymbolに対応しなければならず、逆向きの対応も一意でなければなりません。あるransomwareの事例では、`ntuser.ini`と`NTUSER.DAT`がそのようなペアとなり、ファイル名を復元できましたが、**ファイルの内容やencryption keyは復元できませんでした**。<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

ターゲットに未対応のシンボルが含まれている場合は、既知のペアをさらに取得するか、未使用のBase32シンボルの対応付けだけを入れ替えます。パディングを8文字単位に戻し、無効なBase32と印字可能でないデコード済みの名前を除外します。その後、候補を再エンコードして、元の暗号文全体と比較します。暗号文内の繰り返しブロックから、追加の手掛かりを得られることがあります。上記の例では、`3gpng2wv`をBase32の`gaydambq`に戻すと、ASCIIのゼロが5つデコードされました。印字可能な候補だけでは、一意の証明にはなりません。<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayukiの自動Caesar cipher解読ツール。<sup>[[15]](#references)</sup>
- RumkinのAtbashツール。<sup>[[16]](#references)</sup>

### Vigenère

- dCodeのVigenèreツール。<sup>[[8]](#references)</sup>
- GuballaのVigenère solver。<sup>[[17]](#references)</sup>

### Bacon cipher

5ビットまたは5文字のグループとして現れることがよくあります：

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runesは置換アルファベットであることが多いため、「futhark cipher」を検索して、対応表を試してください。

## チャレンジにおける圧縮

### Technique

圧縮は追加レイヤーとして頻繁に使われます（zlib/deflate/gzip/xz/zstd）。場合によっては入れ子になっています。出力がほぼ解析できそうなのに文字化けしている場合は、圧縮を疑ってください。

### 簡単な識別方法

- `file <blob>`
- マジックバイトを確認:
  - gzip: `1f 8b`
  - zlib: 一般的には `78 01`、`78 5e`、`78 9c`、または `78 da`（2バイト目は圧縮フラグによって異なります）
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChefには**Raw Deflate/Raw Inflate**があり、データが圧縮されているように見えるのに`zlib`で失敗する場合、これを使うのが最も手早いことがよくあります。

### 便利なCLI

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## CTFでよく使われるcryptoの構成要素

### テクニック

現実的な開発者のミスや、よく使われるライブラリの誤用であるため、頻繁に登場します。通常の目的は、パターンを見抜き、既知の抽出または再構築の手順を適用することです。

### Fernet

よくあるヒント: Base64文字列が2つ（token + key）。

- デコーダー/メモ: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Pythonの場合: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数のシェアがあり、しきい値 `t` が示されている場合は、Shamirである可能性が高いです。

- オンライン再構築ツール（機密情報ではないCTFのシェアのみ）。<sup>[[19]](#references)</sup>

### OpenSSLのsalt付き形式

CTFでは、`openssl enc` の出力が提供されることがあります（ヘッダーは多くの場合 `Salted__` で始まります）。

総当たり用ツール:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### 汎用ツールセット

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## 推奨するローカル環境

実用的なCTF環境:

- 対称暗号プリミティブと迅速なプロトタイピング向けのPythonと `pycryptodome`.<sup>[[25]](#references)</sup>
- モジュラー演算、CRT、格子、RSA/ECCの作業向けのSageMath.<sup>[[26]](#references)</sup>
- 制約ベースのチャレンジ向けのZ3（暗号の問題が制約に帰着する場合）。<sup>[[27]](#references)</sup>

推奨Pythonパッケージ:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org 検索](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode ツール](https://www.dcode.fr/tools-list)
- [9] [Boxentriq の暗号解読ツール](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - 自動 Caesar cipher 解読ツール](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère ソルバー](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet デコーダー](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing 復元ツール](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome ドキュメント](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – 暗号方式を楽に破る方法](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
