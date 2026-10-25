# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- "Signature" is actually `hash(secret || message)` → length extension.
- Unsalted password hashes → faster repeated cracking and precomputed lookup attacks.
- Confusing hash with MAC (hash != authentication).

## Chosen-input MD5 hash searches

These Python examples search for two different output patterns: a chosen MD5 suffix and an MD5 value starting with `0e` followed only by digits. The latter pattern is relevant when an application compares numeric strings loosely; see the PHP-specific behavior and version caveats in [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### MD5 hash suffix brute force

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

### MD5 0e hash generation for loose comparisons

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

A length-extension attack may be possible when a server computes a "signature" like:

`sig = HASH(secret || message)`

and uses a Merkle-Damgård hash such as MD5, SHA-1, or SHA-256.

If you know:

- `message`
- `sig`
- hash function
- (or can brute-force) `len(secret)`

Then you can compute a valid signature for:

`message || padding || appended_data`

without knowing the secret.<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length-extension attacks apply to vulnerable prefix constructions such as `HASH(secret || message)`. They do not expose the HMAC construction (for example, HMAC-SHA256), which combines a key with separate inner and outer hash applications.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings for the HashPump length-extension tool<sup>[[7]](#references)</sup>

### Good explanation

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Ambiguous tuple hashing and MACs

### Boundary-confusion attack

Incremental hash APIs do not authenticate call boundaries. `update(A); update(B)` hashes the same byte string as `update(A + B)`. Therefore, hashing or MACing raw concatenation does not authenticate a tuple. If adjacent fields have variable lengths, an attacker can repartition the bytes into a different tuple without finding a collision in the underlying hash:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

This becomes exploitable when the verifier believes the digest binds field meanings, but attacker-controlled input can reach a different parser or protocol step that assigns other boundaries. Commitments may gain alternate openings and Fiat-Shamir transcripts may be interpreted as different statements. HMAC prevents [hash length extension](#hash-length-extension-attack), but `HMAC(K, A || B)` still has this tuple-encoding ambiguity because both tuples produce the same message bytes.<sup>[[8]](#references)[[9]](#references)</sup>

Use this audit workflow to test whether an ambiguous tuple encoding crosses a security boundary.<sup>[[8]](#references)[[9]](#references)</sup>

1. Find `HASH(A || B)`, `HMAC(K, A || B)`, and consecutive `update()`/`Write()` calls over two or more fields.
2. Mark every attacker-controlled or variable-length field. Try moving bytes across each boundary while keeping the complete concatenation unchanged. Include empty fields.
3. Check delimiter schemes for delimiter bytes that inputs can contain, escaping disagreements, and designs that length-encode only some fields.
4. Trace how every consumer parses the authenticated bytes. A candidate is meaningful only if an alternate partition changes a security decision, proof statement, record, transaction, or commitment opening. Fixed-width fields or a canonical, injective serialization prevent this specific attack.
5. Check whether the same encoded digest is accepted in another protocol version, message type, round, or application. Bind these contexts explicitly rather than relying on callers to keep them separate.

### SequenceHash and SequenceMAC

SequenceHash is a hash-agnostic construction for sequences of byte strings. Each `add()` operation is atomic: it appends the value and a fixed 16-byte, little-endian length suffix to the inner hash. Empty values remain distinct objects. An outer hash prevents exposure of a length-extendable inner state, while an optional customization string provides domain separation. Do not replace `add()` with the underlying hash API's ordinary writes.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Choose the customizer as part of the protocol definition, including enough information to distinguish the application, protocol version, message type, and round. SequenceHash still requires all parties to agree on field order, byte encoding, and canonical serialization, and it cannot protect an omitted field. Ports should be checked against the C2SP intermediate and final test vectors.<sup>[[8]](#references)[[11]](#references)</sup>

For authentication, SequenceMAC provides the same atomic encoding and customization interface. It requires a key of at least 32 bytes. Unlike HMAC key preprocessing, its headers commit to the exact key length: a long raw key is not equivalent to its prehash, and appending zero bytes changes the key. This distinction matters when components accept different key representations or length metadata.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

The Python API and equivalent Go and Rust implementations are available as references, but protocol implementations should follow the live C2SP specification rather than recreating the encoding from this summary.<sup>[[8]](#references)[[10]](#references)</sup>

## Password hashing and cracking

### First questions<sup>[[4]](#references)</sup>

- Is it **salted**? (look for `salt$hash` formats)
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint** (hashcat mode / John format)?

### Practical workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Identify the hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. If unsalted and common: try online DBs and identification tooling from the crypto workflow section.
3. Otherwise crack:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

### Chosen-input bcrypt oracle with an appended secret

A callable helper that returns `bcrypt(user_input || secret)` can expose information about an appended secret if its bcrypt implementation silently truncates input after 72 **bytes**. A character-count limit before UTF-8 encoding does not enforce that byte limit: multibyte characters can fill the bcrypt input while leaving room for just a small prefix of the secret. Chosen inputs and their returned hashes may then allow offline checks of candidate suffix bytes. This requires control of the helper's input, knowledge of its exact transform and encoding, and an implementation that actually truncates; a callable helper or a bcrypt hash alone does not establish the chain. [pyca/bcrypt documents](https://github.com/pyca/bcrypt#maximum-password-length) that current `hashpw` raises an error for inputs over 72 bytes, whereas earlier behavior silently truncated them. Other wrappers may prehash or reject long inputs, so verify the installed implementation rather than assuming truncation.

Using a recovered secret against a different account also requires evidence that its exposed hash was generated with the **same** secret and transform, plus a separate credential or login path. A root-run hashing helper should be reviewed as an oracle only if the lower-privileged user can invoke it under the effective policy; passive host enumeration need not call it or submit chosen passwords.

## References

- [1] [SkullSecurity - Everything you need to know about hash length-extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - The Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings for HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash and SequenceMAC specification](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing for the rest of us](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python implementation](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash test vectors](https://github.com/C2SP/CCTV/tree/main/sequencehash)
