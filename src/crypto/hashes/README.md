# Hashes、MAC、KDF

{{#include ../../banners/hacktricks-training.md}}

## よくあるCTFパターン

- 「Signature」が実際には `hash(secret || message)` → length extension。
- ソルトなしのパスワードhash → 繰り返しのcrackingや事前計算済みlookup attackが高速化する。
- hashとMACの混同（hash != authentication）。

## Hash length extension attack

### Technique

サーバーが次のような「signature」を計算し、

`sig = HASH(secret || message)`

MD5、SHA-1、SHA-256などのMerkle-Damgård hashを使用している場合、length-extension attackが可能なことがあります。

次の情報が分かっている場合、

- `message`
- `sig`
- hash function
- `len(secret)`（または総当たり可能）

secretを知らなくても、次の内容に対する有効なsignatureを計算できます。

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 重要な制限: HMACは影響を受けない

Length-extension attackが適用されるのは、`HASH(secret || message)`のような脆弱なprefix構成です。HMAC構成（例: HMAC-SHA256）は対象外です。HMACでは、keyとinner・outerのhash処理を別々に組み合わせます。<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)、HashPump length-extension toolのPython bindings<sup>[[7]](#references)</sup>

### 分かりやすい解説

[Hash length extension attackについて知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## パスワードhashとcracking

### 最初に確認すること<sup>[[4]](#references)</sup>

- **salt付き**か？（`salt$hash`形式を探す）
- **fast hash**（MD5/SHA1/SHA256）か、**slow KDF**（bcrypt/scrypt/argon2/PBKDF2）か？
- **format hint**（hashcat mode / John format）があるか？

### 実践的な手順<sup>[[5]](#references)[[6]](#references)</sup>

1. hashを特定する:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. ソルトなしで一般的なものなら、オンラインDBとcrypto workflowセクションの識別ツールを試す。
3. それ以外はcrackする:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 悪用できるよくあるミス

- ユーザー間で同じパスワードを再利用している → 1つをcrackしてpivotする。
- hashの切り詰め / 独自の変換 → 正規化して再試行する。
- KDFパラメーターが弱い（例: PBKDF2のiteration数が少ない）→ それでもcrack可能。

### secretが末尾に付加されるbcrypt oracleへのChosen-input

`bcrypt(user_input || secret)`を返す呼び出し可能なhelperは、bcrypt実装が入力を72 **bytes**で黙って切り詰める場合、末尾に付加されたsecretに関する情報を漏らす可能性があります。UTF-8エンコード前の文字数制限では、このbyte数制限を保証できません。マルチバイト文字でbcrypt入力を埋めると、secretの先頭部分だけが入る余地が残ることがあります。Chosen inputと返されたhashを使えば、候補となるsuffix byteをオフラインで検証できる可能性があります。ただし、helperへの入力を制御でき、その正確な変換とencodingが分かり、実装が実際に切り詰めを行う必要があります。呼び出し可能なhelperやbcrypt hashがあるだけでは、この一連の条件が成立するとは限りません。[pyca/bcryptのドキュメント](https://github.com/pyca/bcrypt#maximum-password-length)によると、現在の`hashpw`は72 bytesを超える入力に対してエラーを返しますが、以前の動作では黙って切り詰めていました。他のwrapperは事前にhash化したり、長い入力を拒否したりする可能性があるため、切り詰めを前提とせず、インストール済みの実装を確認してください。

復元したsecretを別のアカウントに対して使うには、そのアカウントで公開されているhashが**同じ**secretと変換方式で生成された証拠に加え、別個のcredentialまたはlogin経路が必要です。root権限で実行されるhashing helperをoracleとして調査するのは、実効ポリシー上、権限の低いユーザーがそのhelperを呼び出せる場合に限るべきです。受動的なホスト調査では、helperを呼び出したり、chosen passwordを送信したりする必要はありません。

## References

- [1] [SkullSecurity - Hash length-extension attackについて知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP パスワード保存チートシート](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcatのexample hash](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripperのコマンドラインオプション](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` — HashPump用Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
