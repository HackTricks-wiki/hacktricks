# ハッシュ、MAC、KDF

{{#include ../../banners/hacktricks-training.md}}

## CTFでよくあるパターン

- 「Signature」が実際には `hash(secret || message)` → length extension。
- Saltなしのパスワードハッシュ → 繰り返しのcrackingや事前計算済みのlookup攻撃が高速化する。
- ハッシュとMACを混同している（hash != authentication）。

## 入力を選択したMD5ハッシュの検索

以下のPythonの例では、指定したMD5サフィックスと、`0e`で始まり、その後に数字だけが続くMD5値という、2種類の出力パターンを検索します。後者のパターンは、アプリケーションが数値文字列を緩く比較する場合に関係します。PHP固有の動作とバージョンごとの注意点については、[PHPの緩い比較](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling)を参照してください。

### MD5ハッシュサフィックスのbrute force

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### 緩い比較のための MD5 0e ハッシュ生成

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Technique

長さ拡張攻撃は、サーバーが次のような「署名」を計算し、

`sig = HASH(secret || message)`

MD5、SHA-1、SHA-256 などの Merkle-Damgård hash を使用している場合に可能なことがあります。

次の情報が分かっていれば、

- `message`
- `sig`
- hash function
- （またはブルートフォースで特定できる）`len(secret)`

secret を知らなくても、次のデータに対する有効な署名を計算できます。

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### 重要な制限: HMAC は影響を受けない

長さ拡張攻撃が適用されるのは、`HASH(secret || message)` のような脆弱な prefix 構造です。HMAC の構造（たとえば HMAC-SHA256）は影響を受けません。HMAC は、別々の inner hash と outer hash の処理を組み合わせています。<sup>[[1]](#references)[[2]](#references)</sup>

### ツール

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)、HashPump length-extension tool の Python bindings<sup>[[7]](#references)</sup>

### 分かりやすい解説

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 曖昧なタプルのハッシュ化と MAC

### Boundary-confusion attack

Incremental hash API は、呼び出しの境界を認証しません。`update(A); update(B)` でハッシュ化されるバイト列は、`update(A + B)` でハッシュ化されるものと同じです。そのため、raw concatenation をハッシュ化または MAC 化しても、タプルは認証されません。隣接するフィールドの長さが可変の場合、攻撃者は underlying hash で衝突を見つけなくても、バイト列を別のタプルに分割し直せます。<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

これは、検証側がダイジェストによってフィールドの意味まで束縛されていると考えている一方で、攻撃者が制御する入力が、異なる境界を割り当てる別のパーサーやプロトコル手順に渡る場合に悪用可能になります。コミットメントに別の開封方法が生じたり、Fiat-Shamir トランスクリプトが別のステートメントとして解釈されたりする可能性があります。HMAC は[hash length extension](#hash-length-extension-attack)を防ぎますが、`HMAC(K, A || B)` には依然としてこのタプル符号化の曖昧性があります。どちらのタプルも同じメッセージバイト列になるためです。<sup>[[8]](#references)[[9]](#references)</sup>

この監査ワークフローを使って、曖昧なタプル符号化がセキュリティ境界を越えるかどうかをテストしてください。<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`、`HMAC(K, A || B)`、および2つ以上のフィールドに対する連続した `update()`/`Write()` 呼び出しを探します。
2. 攻撃者が制御できるフィールドや可変長フィールドをすべて特定します。連結全体を変えずに、各境界をまたいでバイトを移動できるか試します。空のフィールドも含めます。
3. 区切り方式について、入力に含められる区切りバイト、エスケープ処理の不一致、一部のフィールドだけを長さ符号化する設計を確認します。
4. 認証されたバイト列を各コンシューマーがどのようにパースするか追跡します。別の分割によってセキュリティ上の判断、証明ステートメント、レコード、トランザクション、またはコミットメントの開封内容が変わる場合にのみ、その候補は意味を持ちます。固定長フィールド、または正準かつ単射なシリアライズを使えば、この特定の攻撃を防げます。
5. 同じ符号化済みダイジェストが、別のプロトコルバージョン、メッセージ型、ラウンド、またはアプリケーションでも受け入れられるか確認します。呼び出し元がそれらを分離すると期待するのではなく、これらのコンテキストを明示的に束縛してください。

### SequenceHash and SequenceMAC

SequenceHash は、バイト文字列のシーケンスに対応するハッシュアルゴリズム非依存の構成です。各 `add()` 操作はアトミックです。値と、固定長16バイトのリトルエンディアン形式の長さサフィックスを内部ハッシュに追加します。空の値も個別のオブジェクトとして扱われます。外部ハッシュによって、長さ拡張可能な内部状態が露出するのを防ぎ、オプションのカスタマイズ文字列によってドメイン分離を行います。`add()` を、基盤となるハッシュ API の通常の書き込み処理に置き換えないでください。<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

プロトコル定義の一部としてcustomizerを選び、アプリケーション、プロトコルのバージョン、メッセージ種別、ラウンドを区別できるだけの情報を含めてください。SequenceHashを使う場合も、すべての関係者がフィールドの順序、バイトエンコーディング、正規化シリアライズについて合意する必要があり、省略されたフィールドは保護できません。実装はC2SPの中間および最終テストベクトルと照合してください。<sup>[[8]](#references)[[11]](#references)</sup>

認証には、SequenceMACが同じatomic encodingとcustomizationインターフェースを提供します。少なくとも32バイトの鍵が必要です。HMACの鍵の前処理とは異なり、SequenceMACのヘッダーは鍵の正確な長さをコミットします。長い生鍵は、そのハッシュ値と同等ではなく、ゼロバイトを追加すると鍵が変わります。この違いは、コンポーネントごとに異なる鍵表現や長さメタデータを受け入れる場合に重要です。<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python APIと同等のGoおよびRust実装は参考資料として利用できますが、プロトコル実装では、この要約からエンコーディングを再現するのではなく、最新のC2SP仕様に従ってください。<sup>[[8]](#references)[[10]](#references)</sup>

## パスワードのハッシュ化とクラック

### まず確認すること<sup>[[4]](#references)</sup>

- **salt付き**か？（`salt$hash`形式か確認）
- **高速なhash**（MD5/SHA1/SHA256）か、**低速なKDF**（bcrypt/scrypt/argon2/PBKDF2）か？
- **形式のヒント**（hashcatのモード / Johnの形式）はあるか？

### 実践的なワークフロー<sup>[[5]](#references)[[6]](#references)</sup>

1. hashを特定する:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. saltなしで一般的なものなら、オンラインDBとcryptoワークフローのセクションにある識別ツールを試す。
3. それ以外はクラックする:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 悪用できるよくあるミス

- 複数のユーザーが同じパスワードを再利用している → 1つクラックして、そこを足がかりにする。
- hashの切り詰め / カスタム変換 → 正規化して再試行する。
- KDFのパラメーターが弱い（例: PBKDF2の反復回数が少ない） → それでもクラック可能。

### secretを追記する、入力指定可能なbcryptオラクル

`bcrypt(user_input || secret)`を返す呼び出し可能なヘルパーは、bcryptの実装が入力を72**バイト**以降で暗黙に切り詰める場合、追記されたsecretに関する情報を漏らす可能性があります。UTF-8エンコード前に文字数を制限しても、このバイト数の上限は保証されません。マルチバイト文字によってbcryptの入力が埋まり、secretの先頭部分だけがわずかに残ることがあるためです。入力を指定して得たhashを使えば、secret候補の接尾バイトをオフラインで検証できる場合があります。これには、ヘルパーの入力を制御できること、正確な変換とエンコーディングがわかっていること、そして実装が実際に切り詰めることが必要です。呼び出し可能なヘルパーやbcrypt hashがあるだけでは、この一連の条件が成立するとは限りません。[pyca/bcryptのドキュメント](https://github.com/pyca/bcrypt#maximum-password-length)によると、現在の`hashpw`は72バイトを超える入力でエラーを発生させますが、以前の動作では暗黙に切り詰めていました。他のwrapperは長い入力を事前にhash化したり拒否したりする場合があるため、切り詰めを前提とせず、インストール済みの実装を確認してください。

復元したsecretを別のアカウントで使うには、公開されたhashが**同じ**secretと変換を使って生成されたことを示す証拠に加え、別個の認証情報またはログイン経路が必要です。root権限で実行されるhash化ヘルパーをオラクルとして調べるのは、実効ポリシーの下で低権限ユーザーがそのヘルパーを呼び出せる場合に限るべきです。受動的なホスト列挙で、ヘルパーを呼び出したり、指定したパスワードを送信したりする必要はありません。

## References

- [1] [SkullSecurity - hash length-extension攻撃について知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcatのhash例](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripperのコマンドラインオプション](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump用の`hashpumpy` Pythonバインディング](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHashおよびSequenceMAC仕様](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: 誰でも使えるマルチハッシュ](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python実装](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHashテストベクトル](https://github.com/C2SP/CCTV/tree/main/sequencehash)
