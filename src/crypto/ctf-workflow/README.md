# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## トリアージチェックリスト

1. 手元にあるものを特定する: encoding、encryption、hash、signature、MAC のいずれか。
2. 何が制御可能かを判断する: plaintext/ciphertext、IV/nonce、key、oracle（padding/error/timing）、部分的な漏えい。
3. 分類する: symmetric（AES/CTR/GCM）、public-key（RSA/ECC）、hash/MAC（SHA/MD5/HMAC）、classical（Vigenere/XOR）。
4. まず成功確率の高い確認から適用する: decode layer、known-plaintext XOR、nonce reuse、mode misuse、oracle behavior。
5. 必要な場合にのみ advanced method へ進む: lattices（LLL/Coppersmith）、SMT/Z3、side-channel。

## Online resources & utilities

これらは、task が identification と layer peeling の場合や、仮説をすばやく確認する必要がある場合に役立ちます。

### Hash lookups

- synthetic/public であることが分かっている challenge hash を検索する。
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

実際の password hash や confidential な challenge material を third-party lookup service に送信しないこと。情報開示、利用規約、または competition rule が懸念される場合は、offline wordlist/rule attack を優先する。

### Identification helpers

- CyberChef（Magic、decoding、conversion）。<sup>[[7]](#references)</sup>
- dCode（cipher/encoding playground）。<sup>[[8]](#references)</sup>
- Boxentriq（substitution solver）。<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack（hands-on cryptography challenge）。<sup>[[10]](#references)</sup>
- Cryptopals（modern cryptography における古典的な落とし穴）。<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext（多数の base/encoding を試行する）。<sup>[[13]](#references)</sup>

## Encodings & classical ciphers

### Technique

多くの CTF crypto task は、base encoding + simple substitution + compression のような layered transform である。目的は layer を特定し、安全に peel することだ。

### Encodings: try many bases

layered encoding（base64 → base32 → …）が疑われる場合は、次を試す:

- CyberChef "Magic"
- `codext`（python-codext）: `codext <string>`

典型的な特徴:

- Base64: `A-Za-z0-9+/=`（padding `=` が一般的）
- Base32: `A-Z2-7=`（`=` padding が多いことが多い）
- Ascii85/Base85: punctuation が密集している。`<~ ~>` で囲まれている場合もある

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

5 bits または 5 letters のグループとして現れることが多い:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### ルーン

Runes は頻繁に substitution alphabets です。"futhark cipher" を検索し、mapping tables を試してください。

## challenges における圧縮

### Technique

圧縮は追加レイヤー（zlib/deflate/gzip/xz/zstd）として頻繁に現れ、ときにはネストされています。出力がほぼ解析できそうなのに garbage のように見える場合は、圧縮を疑ってください。

### Quick identification

- `file <blob>`
- magic bytes を探します:
- gzip: `1f 8b`
- zlib: 通常は `78 01`、`78 5e`、`78 9c`、または `78 da`（2バイト目は compression flags によって異なります）
- zip: `50 4b 03 04`
- bzip2: `42 5a 68`（`BZh`）
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef には **Raw Deflate/Raw Inflate** があり、blob が圧縮されているように見えるものの `zlib` が失敗する場合に、最短で解決できることがよくあります。

### Useful CLI
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
## Common CTF crypto constructs

### Technique

これらは、現実的な開発者のミスや、一般的なライブラリの誤用であるため、頻繁に登場します。通常の目的は、既知の抽出または再構成ワークフローを認識して適用することです。

### Fernet

典型的なヒント: 2つのBase64文字列（token + key）。

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数のshareがあり、threshold `t` が言及されている場合は、Shamirである可能性が高いです。

- Online reconstructor（機密性のないCTFのshareのみ）。<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTFでは、`openssl enc` の出力（headerが `Salted__` で始まることが多い）が与えられる場合があります。

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### General toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Recommended local setup

実用的なCTF stack:

- 対称プリミティブと高速なプロトタイピング用のPythonおよび `pycryptodome`.<sup>[[25]](#references)</sup>
- modular arithmetic、CRT、lattice、RSA/ECC作業用のSageMath.<sup>[[26]](#references)</sup>
- constraint-based challenge用のZ3（cryptoがconstraintsに還元できる場合）。<sup>[[27]](#references)</sup>

推奨Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org ハッシュ検索](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode ツール](https://www.dcode.fr/tools-list)
- [9] [Boxentriq code-breaking ツール](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - 自動Caesar cipher breaker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome ドキュメント](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
