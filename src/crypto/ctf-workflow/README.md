# Crypto CTF ワークフロー

{{#include ../../banners/hacktricks-training.md}}

## トリアージチェックリスト

1. 手元にあるものを特定する: エンコーディング、暗号化、ハッシュ、署名、MAC のどれか。
2. 制御できるものを特定する: 平文/暗号文、IV/nonce、鍵、oracle（padding/error/timing）、部分的な漏えい。
3. 分類する: 対称鍵暗号（AES/CTR/GCM）、公開鍵暗号（RSA/ECC）、ハッシュ/MAC（SHA/MD5/HMAC）、古典暗号（Vigenere/XOR）。
4. 成功する可能性が最も高い確認から行う: エンコード層のデコード、既知平文 XOR、nonce の再利用、モードの誤用、oracle の挙動。
5. 必要な場合にのみ高度な手法に進む: 格子（LLL/Coppersmith）、SMT/Z3、サイドチャネル。

## オンラインリソースとユーティリティ

課題の種類を特定して層を剥がす場合や、仮説をすばやく確認したい場合に役立ちます。

### ハッシュ検索

- 合成または公開されていることが分かっている場合は、課題のハッシュを検索する。
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org の検索機能。<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

実際のパスワードハッシュや機密性のある課題資料を、サードパーティの検索サービスに送信しないこと。開示、利用規約、競技ルールが懸念される場合は、オフラインでのワードリスト/ルール攻撃を優先する。

### 識別に役立つツール

- CyberChef（Magic、デコード、変換）。<sup>[[7]](#references)</sup>
- dCode（暗号/エンコーディングのプレイグラウンド）。<sup>[[8]](#references)</sup>
- Boxentriq（換字暗号ソルバー）。<sup>[[9]](#references)</sup>

### 練習用プラットフォーム / リファレンス

- CryptoHack（実践的な暗号課題）。<sup>[[10]](#references)</sup>
- Cryptopals（現代暗号における古典的な落とし穴）。<sup>[[11]](#references)</sup>

### 自動デコード

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext（多数の基数/エンコーディングを試す）。<sup>[[13]](#references)</sup>

## エンコーディングと古典暗号

### 手法

多くのCTF暗号課題は、base encoding + 単純な換字 + 圧縮といった、複数の変換を重ねたものです。目的は、各層を特定し、安全に剥がしていくことです。

### エンコーディング: さまざまな基数を試す

複数のエンコーディングが重ねられている（base64 → base32 → …）と考えられる場合は、次を試します。

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

よくある特徴:

- Base64: `A-Za-z0-9+/=`（`=`によるpaddingがよく使われる）
- Base32: `A-Z2-7=`（`=`によるpaddingが多いことが多い）
- Ascii85/Base85: 記号が密集している。`<~ ~>`で囲まれる場合もある

### 換字 / 単一換字式

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

5ビットまたは5文字のグループで現れることがよくあります。

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### ルーン

ルーンは頻繁に換字アルファベットとして使われます。「futhark cipher」を検索し、対応表を試してみましょう。

## 課題における圧縮

### Technique

圧縮は追加レイヤーとして頻繁に登場します（zlib/deflate/gzip/xz/zstd）。場合によっては、複数の圧縮が入れ子になっています。出力がほぼ解析できそうなのに文字化けして見える場合は、圧縮を疑いましょう。

### すばやく判別する

- `file <blob>`
- マジックバイトを確認する:
  - gzip: `1f 8b`
  - zlib: 一般的には `78 01`、`78 5e`、`78 9c`、`78 da`（2バイト目は圧縮フラグによって異なります）
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChefには **Raw Deflate/Raw Inflate** があり、blobが圧縮されているように見えるのに `zlib` で失敗する場合、これが最も手早く解決できることがよくあります。

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

## CTF cryptoでよく使われる構成

### Technique

現実に起こりやすい開発者のミスや、誤った使い方をされた一般的なライブラリが原因で、よく登場します。通常の目的は、パターンを認識し、既知の抽出または再構築の手順を適用することです。

### Fernet

よくあるヒント: Base64文字列が2つ（token + key）。

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Pythonの場合: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数のshareがあり、threshold `t` に言及されている場合は、Shamirである可能性が高いです。

- オンライン再構築ツール（機密情報ではないCTFのshareに限る）。<sup>[[19]](#references)</sup>

### OpenSSLのsalt付きフォーマット

CTFでは、`openssl enc` の出力が渡されることがあります（ヘッダーは多くの場合 `Salted__` で始まります）。

Bruteforce用ヘルパー:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### 一般的なツールセット

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## 推奨するローカル環境

実用的なCTF用スタック:

- 対称プリミティブと高速なプロトタイピングには、Pythonと `pycryptodome`。<sup>[[25]](#references)</sup>
- modular arithmetic、CRT、lattice、RSA/ECCの作業には、SageMath。<sup>[[26]](#references)</sup>
- 制約ベースのチャレンジには、Z3（cryptoを制約に帰着できる場合）。<sup>[[27]](#references)</sup>

推奨Pythonパッケージ:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org 検索](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode ツール](https://www.dcode.fr/tools-list)
- [9] [Boxentriq 暗号解読ツール](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Caesar cipher 自動解読ツール](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing 再構成ツール](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome ドキュメント](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
