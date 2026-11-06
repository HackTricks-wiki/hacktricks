# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## トリアージチェックリスト

1. 対象を特定する: encoding、encryption、hash、signature、MACのどれか。
2. 制御可能な要素を特定する: plaintext/ciphertext、IV/nonce、key、oracle (padding/error/timing)、部分的なleakage。
3. 分類する: symmetric (AES/CTR/GCM)、public-key (RSA/ECC)、hash/MAC (SHA/MD5/HMAC)、classical (Vigenere/XOR)。
4. 成功確率が最も高いチェックから実施する: encodingのレイヤーをdecodeする、known-plaintext XOR、nonceの再利用、modeの誤用、oracleの挙動。
5. 必要な場合にのみ高度な手法に進む: lattices (LLL/Coppersmith)、SMT/Z3、side-channel。

## オンラインリソースとユーティリティ

課題の識別やレイヤーの分離、または仮説を手早く確認する必要がある場合に役立ちます。

### Hash検索

- 既知のsynthetic/publicなchallenge hashを検索する。
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

実際のpassword hashや機密性のあるchallenge素材を、サードパーティの検索サービスに送信しないでください。情報開示、利用規約、または競技ルールが懸念される場合は、オフラインのwordlist/rule攻撃を優先してください。

### 識別用ツール

- CyberChef (Magic、decoding、変換)。<sup>[[7]](#references)</sup>
- dCode (cipher/encodingの実験用ツール)。<sup>[[8]](#references)</sup>
- Boxentriq (substitution solver)。<sup>[[9]](#references)</sup>

### 練習プラットフォーム / 参考資料

- CryptoHack (実践的なcryptography challenge)。<sup>[[10]](#references)</sup>
- Cryptopals (現代的なcryptographyにおける典型的な落とし穴)。<sup>[[11]](#references)</sup>

### 自動decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (多数のbase/encodingを試す)。<sup>[[13]](#references)</sup>

難解な言語のソースコードやカスタムinterpreterの状態については、[Crypto CTF Misc](../ctf-misc/)を参照してください。

## Encodingsと古典暗号

### 手法

多くのCTF crypto課題は、base encoding + 単純なsubstitution + compressionのような、変換を重ねたものです。目標は各レイヤーを特定し、安全に分離することです。

### Encodings: さまざまなbaseを試す

複数レイヤーのencoding (base64 → base32 → …) が疑われる場合は、次を試してください。

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

よくある手がかり:

- Base64: `A-Za-z0-9+/=` (padding `=` がよく使われる)
- Base32: `A-Z2-7=` (padding `=` が多数付くことが多い)
- Ascii85/Base85: 記号が密集している。`<~ ~>` で囲まれている場合もある

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### 既知平文を使った、置換されたBase32ファイル名の復元

難読化されたファイル名に `a-z2-7` だけが使われ、固定サフィックスを削除した後の長さが約 `ceil(8 * byte_length / 5)` 文字になり、同じ平文からはファイルを問わず同じ出力が得られる場合は、**paddingなしのBase32の後に、固定の記号置換が施されている**可能性を検証してください。これらの手がかりだけでは証明になりません。予測可能なファイル名と対応するciphertextを集め、大文字小文字を保持したまま各平文をBase32でencodeし、記号を位置ごとに揃えます。同じ平文記号はすべて同じciphertext記号に対応し、逆向きの対応も一意でなければなりません。あるransomwareの事例では、`ntuser.ini` と `NTUSER.DAT` の組み合わせから、このような対応関係が得られました。この方法で復元できたのはファイル名であり、**ファイルの内容やencryption keyではありません**。<sup>[[28]](#references)</sup>

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

ターゲットに未対応のシンボルが含まれている場合は、既知のペアをさらに取得するか、未使用のBase32シンボルのマッピングだけを入れ替えます。パディングを8文字単位に戻し、無効なBase32と印字不可能なデコード後の名前を除外したうえで、残った候補を再エンコードし、元の暗号文全体と比較します。暗号文のブロックが繰り返されていれば、追加の推測に利用できます。上記の例では、`3gpng2wv`をBase32の`gaydambq`に戻すと、ASCIIのゼロが5つデコードされました。印字可能な候補だけでは、一意の証明にはなりません。<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayukiの自動Caesar cipher解読ツール。<sup>[[15]](#references)</sup>
- Rumkin Atbashツール。<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenèreツール。<sup>[[8]](#references)</sup>
- Guballa Vigenère solver。<sup>[[17]](#references)</sup>

### Bacon cipher

5ビットまたは5文字のグループとして現れることがよくあります。

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### ルーン文字

ルーン文字は置換アルファベットとして使われることがよくあります。「futhark cipher」で検索し、対応表を試してみましょう。

## チャレンジにおける圧縮

### 手法

圧縮（zlib/deflate/gzip/xz/zstd）は追加レイヤーとして頻繁に登場し、複数の圧縮が入れ子になっていることもあります。出力がほぼパースできそうなのに文字化けしている場合は、圧縮を疑いましょう。

### すばやく判別する方法

- `file <blob>`
- マジックバイトを確認する:
  - gzip: `1f 8b`
  - zlib: 一般的には `78 01`、`78 5e`、`78 9c`、または `78 da`（2バイト目は圧縮フラグによって異なります）
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef には **Raw Deflate/Raw Inflate** があり、データが圧縮されているように見えるのに `zlib` で失敗する場合、最も手早く解決できることがよくあります。

### 便利な CLI

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

## よくあるCTFの暗号構成

### 技法

現実的な開発者のミスや、誤った使い方をされがちな一般的なライブラリが関係するため、よく登場します。通常は、既知の抽出または再構築の手順を見分けて適用することが目的です。

### Fernet

典型的なヒント: 2つのBase64文字列（token + key）。

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Pythonの場合: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数のシェアがあり、しきい値 `t` に言及されている場合は、Shamirである可能性が高いです。

- オンライン再構築ツール（機密性のないCTFのシェアのみ）。<sup>[[19]](#references)</sup>

### OpenSSLのsalt付きフォーマット

CTFでは、`openssl enc` の出力が渡されることがあります（ヘッダーは多くの場合 `Salted__` で始まります）。

総当たり用ツール:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### 一般的なツールセット

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## 推奨するローカル環境

実用的なCTF環境:

- 対称暗号プリミティブと迅速なプロトタイピング用のPythonおよび `pycryptodome`.<sup>[[25]](#references)</sup>
- モジュラー算術、CRT、格子、RSA/ECC作業用のSageMath.<sup>[[26]](#references)</sup>
- 制約ベースの課題用のZ3（暗号の問題を制約に帰着できる場合）。<sup>[[27]](#references)</sup>

推奨Pythonパッケージ:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org検索](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCodeツール](https://www.dcode.fr/tools-list)
- [9] [Boxentriqの暗号解読ツール](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - 自動Caesar cipher解読ツール](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir秘密分散再構成ツール](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodomeドキュメント](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – 暗号方式を手軽に破る方法](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
