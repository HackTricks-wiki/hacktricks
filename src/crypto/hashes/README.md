# Hashes、MAC、KDF

{{#include ../../banners/hacktricks-training.md}}

## よくあるCTFパターン

- 「署名」が実際には `hash(secret || message)` → length extension。
- ソルトなしのパスワードハッシュ → 繰り返しのcrackingが高速化し、事前計算されたlookup attackが可能になる。
- hashとMACの混同（hash != authentication）。

## Hash length extension attack

### Technique

サーバーが次のような「署名」を計算している場合、length-extension attackが可能なことがあります。

`sig = HASH(secret || message)`

また、MD5、SHA-1、SHA-256などのMerkle-Damgård hashを使用している場合です。

次の情報が分かっていれば、

- `message`
- `sig`
- hash function
- `len(secret)`（または総当たりで推測できる）

secretを知らなくても、次のデータに対する有効な署名を計算できます。

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 重要な制限: HMACは影響を受けない

Length-extension attackは、`HASH(secret || message)`のような脆弱なprefix constructionに適用されます。別々のinnerおよびouter hash処理とkeyを組み合わせるHMAC（たとえばHMAC-SHA256）の構造は、この攻撃では暴かれません。<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)、HashPump length-extension toolのPython bindings<sup>[[7]](#references)</sup>

### 分かりやすい解説

[Hash length extension attackについて知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## パスワードのhashingとcracking

### 最初に確認すること<sup>[[4]](#references)</sup>

- **ソルト付き**か？（`salt$hash`形式を確認）
- **高速なhash**（MD5/SHA1/SHA256）か、**低速なKDF**（bcrypt/scrypt/argon2/PBKDF2）か？
- **形式のヒント**（hashcat mode / John format）はあるか？

### 実践的な手順<sup>[[5]](#references)[[6]](#references)</sup>

1. hashを特定する:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. ソルトなしで一般的な形式なら、オンラインDBとcrypto workflowセクションの識別ツールを試す。
3. それ以外はcrackする:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 悪用できるよくあるミス

- 複数ユーザー間で同じパスワードを再利用 → 1つをcrackして、別の対象へpivotする。
- 切り詰められたhash / 独自の変換 → 正規化して再試行する。
- KDFパラメーターが弱い（例: PBKDF2の反復回数が少ない） → それでもcrack可能。

### secretが末尾に付加される、入力指定可能なbcrypt oracle

`bcrypt(user_input || secret)`を返す呼び出し可能なhelperは、bcryptの実装が入力を72 **bytes**を超えて暗黙に切り詰める場合、付加されたsecretに関する情報を漏らす可能性があります。UTF-8 encoding前の文字数制限では、このbyte制限を保証できません。複数byte文字によってbcrypt入力が埋まり、secretの先頭部分だけが残ることがあるためです。入力指定と返されたhashを使えば、候補となるsuffixのbyteをオフラインで検証できる場合があります。これには、helperの入力を制御できること、正確な変換とencodingが分かること、そして実装が実際に入力を切り詰めることが必要です。helperが呼び出し可能であることやbcrypt hashだけでは、この一連の条件が成立するとは限りません。[pyca/bcryptのドキュメント](https://github.com/pyca/bcrypt#maximum-password-length)によると、現在の`hashpw`は72 bytesを超える入力に対してエラーを発生させますが、以前の動作では暗黙に切り詰められていました。他のwrapperは長い入力を事前hash化したり、拒否したりすることがあるため、切り詰めを前提とせず、インストールされている実装を確認してください。

復元したsecretを別のアカウントに対して使うには、公開されたhashが**同じ**secretと変換で生成された証拠に加え、別途credentialまたはlogin pathが必要です。rootで実行されるhashing helperをoracleとして検討するのは、低権限ユーザーが実効ポリシーのもとでそのhelperを呼び出せる場合に限ります。受動的なhost enumerationで、helperを呼び出したり、指定したパスワードを送信したりする必要はありません。

## References

- [1] [SkullSecurity - hash length-extension attackについて知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcatのサンプルhash](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripperのコマンドラインオプション](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump用の`hashpumpy` Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
