# 哈希、MAC 与 KDF

{{#include ../../banners/hacktricks-training.md}}

## 常见 CTF 模式

- “签名”实际上是 `hash(secret || message)` → length extension。
- 未加盐的密码哈希 → 更快地重复破解，并可进行预计算查找攻击。
- 将哈希与 MAC 混淆（哈希 != 身份验证）。

## MD5 哈希的选定输入搜索

这些 Python 示例会搜索两种不同的输出模式：指定后缀的 MD5，以及以 `0e` 开头且后面只包含数字的 MD5 值。后一种模式与应用程序进行数字字符串宽松比较时有关；请参阅 [PHP 宽松比较](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling)中关于 PHP 特定行为和版本注意事项的说明。

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

当服务器使用 Merkle-Damgård 哈希函数（如 MD5、SHA-1 或 SHA-256）计算类似以下内容的“签名”时，可能存在 length-extension attack：

`sig = HASH(secret || message)`

如果你知道：

- `message`
- `sig`
- 哈希函数
- （或能通过暴力破解得出）`len(secret)`

那么你无需知道 secret，就能计算出以下内容的有效签名：

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### 重要限制：HMAC 不受影响

Length-extension attack 适用于 `HASH(secret || message)` 这类易受攻击的前缀构造。它们无法破解 HMAC 构造（例如 HMAC-SHA256），因为 HMAC 会将密钥与独立的内层和外层哈希运算结合起来。<sup>[[1]](#references)[[2]](#references)</sup>

### 工具

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)，HashPump length-extension 工具的 Python 绑定<sup>[[7]](#references)</sup>

### 优质讲解

[你需要了解的关于哈希长度扩展攻击的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 模糊元组哈希与 MAC

### Boundary-confusion attack

增量哈希 API 不会对调用边界进行认证。`update(A); update(B)` 与 `update(A + B)` 哈希的是同一个字节串。因此，对原始拼接内容进行哈希或 MAC 运算，并不能对元组进行认证。如果相邻字段的长度可变，攻击者就能将字节重新划分为不同的元组，而无需在底层哈希中找到碰撞：<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

当验证者认为摘要绑定了字段含义，但攻击者可控的输入却能进入另一个解析器或协议步骤，并被赋予不同的边界时，这种情况就会变得可利用。承诺可能出现不同的开启方式，Fiat-Shamir transcript 也可能被解释为不同的陈述。HMAC 可防止 [hash length extension](#hash-length-extension-attack)，但 `HMAC(K, A || B)` 仍存在这种元组编码歧义，因为两个元组会产生相同的消息字节。<sup>[[8]](#references)[[9]](#references)</sup>

使用以下审计流程，测试有歧义的元组编码是否跨越了安全边界。<sup>[[8]](#references)[[9]](#references)</sup>

1. 查找 `HASH(A || B)`、`HMAC(K, A || B)`，以及对两个或更多字段连续调用 `update()`/`Write()` 的情况。
2. 标记所有由攻击者控制或长度可变的字段。尝试在每个边界之间移动字节，同时保持完整拼接结果不变。也要包括空字段。
3. 检查分隔符方案，确认输入是否可以包含分隔符字节、转义处理是否存在差异，以及设计是否只对部分字段进行长度编码。
4. 追踪每个使用方如何解析已认证的字节。只有当另一种分区方式会改变安全决策、证明陈述、记录、交易或承诺开启时，候选情况才有意义。定长字段或规范且单射的序列化可防止这种特定攻击。
5. 检查同一个编码后的摘要是否会在其他协议版本、消息类型、轮次或应用中被接受。应明确绑定这些上下文，而不是依赖调用方将它们分开。

### SequenceHash 和 SequenceMAC

SequenceHash 是一种与哈希算法无关、用于字节串序列的构造。每次 `add()` 操作都是原子的：它会将值及一个固定的 16 字节小端长度后缀追加到内部哈希中。空值仍是不同的对象。外层哈希可防止暴露可进行长度扩展的内部状态，而可选的定制字符串可提供域分离。不要用底层哈希 API 的普通写入操作替代 `add()`。<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

将 customizer 作为协议定义的一部分进行选择，并包含足够的信息以区分应用、协议版本、消息类型和轮次。SequenceHash 仍要求所有参与方就字段顺序、字节编码和规范序列化达成一致，而且无法保护被省略的字段。应使用 C2SP 中间和最终测试向量检查端口。<sup>[[8]](#references)[[11]](#references)</sup>

对于身份验证，SequenceMAC 提供相同的原子编码和 customization 接口。它要求密钥至少为 32 字节。与 HMAC 密钥预处理不同，其头部会绑定确切的密钥长度：较长的原始密钥不等同于其预哈希值，追加零字节也会改变密钥。当不同组件接受不同的密钥表示或长度元数据时，这一区别至关重要。<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API 以及对应的 Go 和 Rust 实现可供参考，但协议实现应遵循最新的 C2SP 规范，而不是根据此摘要重新实现编码。<sup>[[8]](#references)[[10]](#references)</sup>

## 密码哈希与破解

### 首先要问的问题<sup>[[4]](#references)</sup>

- 是否**加了盐**？（查找 `salt$hash` 格式）
- 这是**快速哈希**（MD5/SHA1/SHA256）还是**慢速 KDF**（bcrypt/scrypt/argon2/PBKDF2）？
- 是否有**格式提示**（hashcat 模式 / John 格式）？

### 实用工作流程<sup>[[5]](#references)[[6]](#references)</sup>

1. 识别哈希：
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. 如果未加盐且较常见：尝试在线数据库和 crypto 工作流程章节中的识别工具。
3. 否则进行破解：
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 可利用的常见错误

- 多个用户重复使用同一密码 → 破解一个后进行 pivot。
- 哈希被截断 / 使用自定义变换 → 规范化后重试。
- KDF 参数较弱（例如 PBKDF2 迭代次数低）→ 仍可破解。

### 追加 secret 的自选输入 bcrypt oracle

一个可调用的辅助程序若返回 `bcrypt(user_input || secret)`，而其 bcrypt 实现会在 72 **字节**后静默截断输入，则可能泄露追加的 secret 信息。在 UTF-8 编码前限制字符数，并不能确保符合该字节限制：多字节字符可能填满 bcrypt 输入，只给 secret 留下一小段空间。此时，自选输入及其返回的哈希可能用于离线检查候选后缀字节。这需要能够控制辅助程序的输入、了解其精确的转换和编码方式，并且其实现确实会截断；仅凭一个可调用的辅助程序或一个 bcrypt 哈希，无法确认整个攻击链成立。[pyca/bcrypt 文档](https://github.com/pyca/bcrypt#maximum-password-length)说明，当前版本的 `hashpw` 会对超过 72 字节的输入报错，而早期版本会静默截断。其他封装可能会预先哈希或拒绝过长输入，因此应核实已安装的实现，不要想当然地认为它会截断。

要将恢复出的 secret 用于另一个账户，还需要证据证明该账户暴露的哈希是使用**相同**的 secret 和转换方式生成的，并且还需要单独的凭据或登录路径。只有当低权限用户能根据有效策略调用以 root 身份运行的哈希辅助程序时，才应将其视为 oracle；被动枚举主机时不必调用它或提交自选密码。

## References

- [1] [SkullSecurity - 关于哈希长度扩展攻击，你需要知道的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 带密钥的哈希消息认证码](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP 密码存储速查表](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 示例哈希](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 命令行选项](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI：HashPump 的 `hashpumpy` Python 绑定](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash 和 SequenceMAC 规范](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash：人人都能用的多重哈希](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python 实现](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash 测试向量](https://github.com/C2SP/CCTV/tree/main/sequencehash)
