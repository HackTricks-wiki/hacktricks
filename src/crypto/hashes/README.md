# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## よくあるCTFのパターン

- 「Signature」が実際には `hash(secret || message)` → length extension。
- Saltなしのパスワードhash → 繰り返し行うcrackingが高速化し、事前計算済みのlookup攻撃が可能になる。
- hashとMACの混同（hash != authentication）。

## 選択した入力によるMD5 hashの探索

以下のPythonの例では、2種類の出力パターンを探索します。指定したMD5 suffixと、`0e`で始まり、その後に数字だけが続くMD5値です。後者のパターンは、アプリケーションが数値文字列を緩く比較する場合に関係します。PHP特有の動作とバージョンに関する注意点については、[PHPの緩い比較](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling)を参照してください。

### MD5 hash suffixの総当たり探索

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

### 緩い比較用のMD5 0e hash生成

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

### 手法

length-extension attackは、サーバーが次のような「署名」を計算し、

`sig = HASH(secret || message)`

MD5、SHA-1、SHA-256などのMerkle-Damgård hashを使用している場合に可能となることがあります。

次の情報が分かっていれば、

- `message`
- `sig`
- hash function
- （または総当たりで推測できる）`len(secret)`

secretを知らなくても、次のデータに対する有効な署名を計算できます。

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 重要な制限: HMACは影響を受けない

length-extension attackが適用されるのは、`HASH(secret || message)`のような脆弱なprefix構成です。HMACの構成（たとえばHMAC-SHA256）は、keyと内側・外側で別々に行うhash処理を組み合わせるため、この攻撃では情報が漏えいしません。<sup>[[1]](#references)[[2]](#references)</sup>

Web APIでこれらの署名を見つけてテストする方法については、[Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures)を確認してください。

### ツール

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)、HashPump length-extension tool用のPython bindings<sup>[[7]](#references)</sup>

### 分かりやすい解説

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 曖昧なtupleのhash化とMAC

### Boundary-confusion attack

Incremental hash APIは、呼び出しの境界を認証しません。`update(A); update(B)`でhash化される内容は、`update(A + B)`でhash化される内容と同じbyte列です。したがって、raw concatenationをhash化またはMAC化しても、tupleは認証されません。隣接するフィールドの長さが可変の場合、攻撃者は基盤となるhashでcollisionを見つけることなく、byte列を異なるtupleに分割し直せます。<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

これは、検証側がダイジェストによってフィールドの意味が束縛されていると信じている一方で、攻撃者が制御する入力が、異なる境界を割り当てる別のパーサーやプロトコルの段階に到達できる場合に、悪用可能になります。Commitmentに別のopeningが生じたり、Fiat-Shamir transcriptが異なるstatementとして解釈されたりする可能性があります。HMACは[hash length extension](#hash-length-extension-attack)を防ぎますが、`HMAC(K, A || B)`にも、この2つのタプルが同じメッセージバイト列を生成するというタプルエンコーディングの曖昧さが残ります。<sup>[[8]](#references)[[9]](#references)</sup>

曖昧なタプルエンコーディングがセキュリティ境界を越えるかどうかをテストするには、次の監査手順を使います。<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`、`HMAC(K, A || B)`、および2つ以上のフィールドに対する連続した`update()`/`Write()`呼び出しを探します。
2. 攻撃者が制御できるフィールド、または可変長のフィールドをすべて特定します。完全な連結結果を変えずに、各境界をまたいでバイトを移動できるか試します。空のフィールドも含めます。
3. 区切り文字方式について、入力に含められる区切り文字バイト、エスケープ処理の不一致、一部のフィールドだけを長さエンコードする設計がないか確認します。
4. 認証されたバイト列を各コンシューマーがどのようにパースするか追跡します。別の分割によってセキュリティ上の判断、証明のstatement、レコード、トランザクション、またはcommitmentのopeningが変わる場合にのみ、その候補は意味を持ちます。固定長フィールド、または正規かつ単射なシリアライズを使えば、この特定の攻撃を防げます。
5. 同じエンコード済みダイジェストが、別のプロトコルバージョン、メッセージタイプ、ラウンド、またはアプリケーションでも受理されるか確認します。呼び出し側がそれらを分離しておくことに頼らず、こうしたコンテキストを明示的に束縛します。

### SequenceHashとSequenceMAC

SequenceHashは、バイト文字列のシーケンスを扱う、ハッシュ方式に依存しない構成です。各`add()`操作はアトミックです。値を追加し、その値の長さを示す固定16バイトのリトルエンディアンのサフィックスを内部ハッシュに付加します。空の値も個別のオブジェクトとして区別されます。外側のハッシュによって、長さ拡張可能な内部状態が露出するのを防ぎ、オプションのカスタマイズ文字列によってドメイン分離を行えます。`add()`を、基盤となるハッシュAPIの通常の書き込み処理に置き換えないでください。<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

プロトコル定義の一部としてカスタマイザーを選び、アプリケーション、プロトコルのバージョン、メッセージの種類、ラウンドを区別できるだけの情報を含めてください。SequenceHashを使う場合も、すべての当事者がフィールドの順序、バイトエンコーディング、正規シリアライズについて合意する必要があり、省略されたフィールドを保護することはできません。ポートはC2SPの中間および最終テストベクトルと照合してください。<sup>[[8]](#references)[[11]](#references)</sup>

認証には、SequenceMACも同じ原子的エンコーディングとカスタマイズ用インターフェースを提供します。少なくとも32バイトの鍵が必要です。HMACの鍵の前処理とは異なり、そのヘッダーは正確な鍵長をコミットします。長いraw鍵は、そのprehashと同等ではなく、ゼロバイトを追加すると鍵が変わります。コンポーネントごとに受け入れる鍵の表現や長さのメタデータが異なる場合、この違いが重要になります。<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python APIと同等のGoおよびRust実装は参考資料として利用できますが、プロトコル実装では、この要約からエンコーディングを再現するのではなく、最新のC2SP仕様に従ってください。<sup>[[8]](#references)[[10]](#references)</sup>

## パスワードのハッシュ化とクラック

### 最初に確認すること<sup>[[4]](#references)</sup>

- **ソルト付き**か？（`salt$hash`形式を確認）
- **高速なハッシュ**（MD5/SHA1/SHA256）か、**低速なKDF**（bcrypt/scrypt/argon2/PBKDF2）か？
- **形式のヒント**（hashcatのモード / Johnの形式）があるか？

### 実践的なワークフロー<sup>[[5]](#references)[[6]](#references)</sup>

1. ハッシュを特定する:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. ソルトなしで一般的な形式の場合: cryptoワークフローのセクションにあるオンラインDBや識別ツールを試す。
3. それ以外の場合はクラックする:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 悪用できるよくあるミス

- 複数ユーザー間で同じパスワードを再利用 → 1つをクラックして、そこから横展開する。
- 切り詰められたハッシュ / 独自の変換 → 正規化して再試行する。
- KDFパラメーターが弱い（例: PBKDF2の反復回数が少ない）→ それでもクラック可能。

### 秘密情報を末尾に付加する、入力を指定可能なbcrypt oracle

`bcrypt(user_input || secret)`を返す呼び出し可能なヘルパーは、bcryptの実装が入力を72**バイト**以降で暗黙に切り詰める場合、末尾に付加された秘密情報を漏えいさせる可能性があります。UTF-8エンコード前の文字数制限では、このバイト数制限を強制できません。マルチバイト文字によってbcrypt入力が埋まり、秘密情報のごく短いプレフィックスだけが入る余地が残る場合があります。その場合、入力を指定して得られたハッシュを使い、候補となる末尾バイトをオフラインで検証できる可能性があります。これには、ヘルパーへの入力を制御できること、正確な変換処理とエンコーディングが分かっていること、そして実装が実際に切り詰めることが必要です。呼び出し可能なヘルパーやbcryptハッシュがあるだけでは、この一連の条件が成立するとは限りません。[pyca/bcryptのドキュメント](https://github.com/pyca/bcrypt#maximum-password-length)によると、現在の`hashpw`は72バイトを超える入力に対してエラーを発生させますが、以前の動作では暗黙に切り詰められていました。他のラッパーは入力を事前ハッシュ化したり、長い入力を拒否したりする場合があるため、切り詰めを前提とせず、インストール済みの実装を確認してください。

別のアカウントに対して復元した秘密情報を使うには、そのアカウントで露出しているハッシュが**同じ**秘密情報と変換処理で生成されたという証拠に加え、別途利用可能な認証情報またはログイン経路が必要です。root権限で実行されるハッシュ化ヘルパーをoracleとして検討するのは、権限の低いユーザーが実効ポリシーの下でそれを呼び出せる場合に限るべきです。ホストの受動的な列挙で、ヘルパーを呼び出したり、入力を指定したパスワードを送信したりする必要はありません。

## References

- [1] [SkullSecurity - ハッシュ長拡張攻撃について知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 鍵付きハッシュメッセージ認証コード](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP パスワード保存チートシート](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcatのハッシュ例](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripperのコマンドラインオプション](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump用の`hashpumpy` Pythonバインディング](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHashおよびSequenceMACの仕様](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: 誰もが使えるマルチハッシュ](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHashのPython実装](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHashのテストベクトル](https://github.com/C2SP/CCTV/tree/main/sequencehash)
