# 哈希、MAC 与 KDF

{{#include ../../banners/hacktricks-training.md}}

## 常见 CTF 模式

- “签名”实际上是 `hash(secret || message)` → length extension。
- 未加盐的密码哈希 → 可更快地重复破解，并可使用预计算查找攻击。
- 混淆哈希与 MAC（hash != authentication）。

## 指定输入的 MD5 哈希搜索

以下 Python 示例搜索两种不同的输出模式：指定的 MD5 后缀，以及以 `0e` 开头且后面仅包含数字的 MD5 值。后一种模式与应用程序宽松地比较数字字符串有关；请参阅 [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling) 中有关 PHP 的特定行为和版本注意事项。

### MD5 哈希后缀暴力破解

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

### 用于宽松比较的 MD5 0e 哈希生成

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

当服务器使用 Merkle-Damgård 哈希（如 MD5、SHA-1 或 SHA-256）计算类似以下内容的“签名”时，可能会受到长度扩展攻击：

`sig = HASH(secret || message)`

如果你知道：

- `message`
- `sig`
- 哈希函数
- （或可以暴力破解）`len(secret)`

那么你无需知道 secret，就能为以下内容计算有效签名：

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### 重要限制：HMAC 不受影响

长度扩展攻击针对的是易受攻击的前缀构造，例如 `HASH(secret || message)`。它不会破解 HMAC 构造（例如 HMAC-SHA256），因为 HMAC 会将密钥与单独的内层和外层哈希运算结合起来。<sup>[[1]](#references)[[2]](#references)</sup>

如需了解如何在 Web API 中查找和测试这类签名，请参阅[请求和参数签名](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures)。

### 工具

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)，HashPump 长度扩展工具的 Python 绑定<sup>[[7]](#references)</sup>

### 优质讲解

[关于哈希长度扩展攻击，你需要了解的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 模糊元组哈希与 MAC

### Boundary-confusion attack

增量哈希 API 不会对调用边界进行身份验证。`update(A); update(B)` 与 `update(A + B)` 哈希的是同一个字节串。因此，对原始拼接内容进行哈希或 MAC 运算，并不能对元组进行身份验证。如果相邻字段长度可变，攻击者就能将字节重新划分为不同的元组，而无需在底层哈希中找到碰撞：<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

当验证方认为摘要绑定了字段含义，但攻击者可控的输入却能到达另一个解析器或协议步骤，并被赋予不同的边界时，就会产生可利用的问题。Commitments 可能出现其他有效开启方式，Fiat-Shamir transcripts 也可能被解释为不同的语句。HMAC 可防止 [hash length extension](#hash-length-extension-attack)，但 `HMAC(K, A || B)` 仍存在这种元组编码歧义，因为这两个元组会产生相同的消息字节。<sup>[[8]](#references)[[9]](#references)</sup>

使用以下审计流程，测试有歧义的元组编码是否跨越了安全边界。<sup>[[8]](#references)[[9]](#references)</sup>

1. 查找 `HASH(A || B)`、`HMAC(K, A || B)`，以及对两个或更多字段连续调用 `update()`/`Write()` 的情况。
2. 标记每个由攻击者控制或长度可变的字段。尝试在保持完整拼接结果不变的同时，将字节移过每个边界。包括空字段。
3. 检查分隔符方案是否存在输入可包含的分隔符字节、转义处理不一致的情况，以及仅对部分字段进行长度编码的设计。
4. 追踪每个使用方如何解析经过认证的字节。只有当另一种划分方式会改变安全决策、证明语句、记录、交易或 commitment 的开启方式时，候选情况才有意义。定长字段或规范且单射的序列化可以防止这种特定攻击。
5. 检查同一编码摘要是否会在另一个协议版本、消息类型、轮次或应用中被接受。应显式绑定这些上下文，而不要依赖调用方将它们分开处理。

### SequenceHash 和 SequenceMAC

SequenceHash 是一种与哈希算法无关的字节串序列构造。每次 `add()` 操作都是原子的：它会将该值以及固定的 16 字节小端长度后缀追加到内部哈希中。空值仍会被视为不同的对象。外层哈希可防止内部状态暴露出可进行长度扩展的状态，而可选的自定义字符串可提供域分离。不要用底层哈希 API 的常规写入操作替代 `add()`。<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

将 customizer 作为协议定义的一部分进行选择，并提供足够的信息来区分应用程序、协议版本、消息类型和轮次。SequenceHash 仍要求所有参与方对字段顺序、字节编码和规范序列化达成一致，而且无法保护被遗漏的字段。应使用 C2SP 中间和最终测试向量检查实现。<sup>[[8]](#references)[[11]](#references)</sup>

对于身份验证，SequenceMAC 提供相同的原子编码和定制接口。它要求密钥至少为 32 字节。与 HMAC 的密钥预处理不同，其头部会承诺确切的密钥长度：较长的原始密钥并不等同于其预哈希值，追加零字节也会改变密钥。当不同组件接受不同的密钥表示形式或长度元数据时，这一区别很重要。<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API 以及对应的 Go 和 Rust 实现可供参考，但协议实现应遵循最新的 C2SP 规范，而不是根据本摘要重新实现编码。<sup>[[8]](#references)[[10]](#references)</sup>

## 密码哈希与破解

### 首先要问的问题<sup>[[4]](#references)</sup>

- 是否**加盐**？（查找 `salt$hash` 格式）
- 是**快速哈希**（MD5/SHA1/SHA256），还是**慢速 KDF**（bcrypt/scrypt/argon2/PBKDF2）？
- 是否有**格式提示**（hashcat 模式 / John 格式）？

### 实用工作流程<sup>[[5]](#references)[[6]](#references)</sup>

1. 识别哈希：
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. 如果未加盐且较常见：尝试在线数据库以及 crypto workflow 部分中的识别工具。
3. 否则进行破解：
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 可利用的常见错误

- 多个用户重复使用同一密码 → 破解一个账户后横向转移。
- 哈希被截断 / 使用自定义变换 → 规范化后重试。
- KDF 参数较弱（例如 PBKDF2 迭代次数较低）→ 仍可破解。

### 带有附加 secret 的可选输入 bcrypt oracle

可调用的辅助程序若返回 `bcrypt(user_input || secret)`，而其 bcrypt 实现会静默地在 72 **字节**后截断输入，则可能泄露附加 secret 的信息。UTF-8 编码前的字符数限制无法强制执行该字节限制：多字节字符可能占满 bcrypt 输入，仅为 secret 留下很短的前缀空间。随后，可以利用选定的输入及其返回的哈希，在离线状态下验证候选后缀字节。这要求能够控制辅助程序的输入，了解其确切的变换和编码方式，并且其实现确实会截断；仅凭一个可调用的辅助程序或 bcrypt 哈希，无法证明这条攻击链成立。[pyca/bcrypt 文档](https://github.com/pyca/bcrypt#maximum-password-length)说明，当前版本的 `hashpw` 对超过 72 字节的输入会报错，而早期版本会静默截断。其他封装可能会先进行预哈希或拒绝过长输入，因此应核实已安装的实现，而不要假定它会截断。

要将恢复出的 secret 用于另一个账户，还需要证据证明该账户暴露的哈希是使用**相同**的 secret 和变换生成的，并且还需要独立的凭据或登录途径。只有当低权限用户能依据有效策略调用以 root 运行的哈希辅助程序时，才应将其视为 oracle；被动枚举主机不必调用它或提交选定的密码。

## References

- [1] [SkullSecurity - 哈希长度扩展攻击详解](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 带密钥的哈希消息认证码](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP 密码存储速查表](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 示例哈希](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 命令行选项](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI：HashPump 的 `hashpumpy` Python 绑定](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash 和 SequenceMAC 规范](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash：人人可用的多重哈希](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python 实现](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash 测试向量](https://github.com/C2SP/CCTV/tree/main/sequencehash)
