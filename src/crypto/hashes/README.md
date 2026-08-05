# Hash'ler, MAC'ler ve KDF'ler

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF kalıpları

- "Signature" aslında `hash(secret || message)` → length extension.
- Salt eklenmemiş password hash'leri → trivial cracking / lookup.
- Hash ile MAC'i karıştırmak (hash != authentication).

## Hash length extension attack

### Technique

Bir server aşağıdakine benzer bir "signature" hesaplıyorsa bunu sıklıkla exploit edebilirsiniz:

`sig = HASH(secret || message)`

ve bir Merkle–Damgård hash'i (klasik örnekler: MD5, SHA-1, SHA-256) kullanıyorsa.

Şunları biliyorsanız:

- `message`
- `sig`
- hash function
- (`len(secret)` değerini brute-force edebiliyorsanız)

şunu bilmeden geçerli bir signature hesaplayabilirsiniz:

`message || padding || appended_data`

secret.<sup>[[1]](#references)</sup>

### Önemli sınırlama: HMAC etkilenmez

Length extension attacks, Merkle–Damgård hash'leri için `HASH(secret || message)` gibi construction'lara uygulanır. Özellikle bu problem sınıfından kaçınmak üzere tasarlanmış **HMAC**'e (ör. HMAC-SHA256) uygulanmaz.<sup>[[1]](#references)</sup>

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### İyi bir açıklama

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### İlk sorular

- **Salt eklenmiş mi?** (`salt$hash` formatlarını arayın)
- **Fast hash** (MD5/SHA1/SHA256) mi, yoksa **slow KDF** (bcrypt/scrypt/argon2/PBKDF2) mi?
- Bir **format hint** (hashcat mode / John format) var mı?

### Pratik workflow

1. Hash'i identify edin:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt eklenmemiş ve yaygınsa: crypto workflow section'daki online DB'leri ve identification tooling'i deneyin.
3. Aksi takdirde crack edin:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Exploit edebileceğiniz yaygın hatalar

- Aynı password'ün users arasında yeniden kullanılması → birini crack edin, pivot yapın.
- Truncated hash'ler / custom transform'lar → normalize edin ve yeniden deneyin.
- Weak KDF parameters (ör. düşük PBKDF2 iteration sayısı) → yine de crack edilebilir.

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
