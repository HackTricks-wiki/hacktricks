# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF kalıpları

- "Signature" aslında `hash(secret || message)` → length extension.
- Salt eklenmemiş password hash'leri → daha hızlı tekrarlı cracking ve önceden hesaplanmış lookup saldırıları.
- Hash ile MAC'i karıştırmak (hash != authentication).

## Hash length extension attack

### Teknik

Bir sunucu şu şekilde bir "signature" hesapladığında length-extension attack mümkün olabilir:

`sig = HASH(secret || message)`

ve MD5, SHA-1 veya SHA-256 gibi bir Merkle-Damgård hash'i kullandığında.

Şunları biliyorsanız:

- `message`
- `sig`
- hash function
- `len(secret)` (veya brute-force edebiliyorsanız)

Şunu bilmeden geçerli bir signature hesaplayabilirsiniz:

`message || padding || appended_data`

secret.<sup>[[1]](#references)</sup>

### Önemli sınırlama: HMAC etkilenmez

Length-extension attacks, `HASH(secret || message)` gibi savunmasız prefix yapılarına uygulanır. Anahtarı ayrı inner ve outer hash uygulamalarıyla birleştiren HMAC yapısının (örneğin HMAC-SHA256) açığa çıkmasına neden olmazlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Araçlar

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool için Python bindings<sup>[[7]](#references)</sup>

### İyi bir açıklama

[Hash length extension attacks hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing ve cracking

### İlk sorular<sup>[[4]](#references)</sup>

- **Salt eklenmiş mi**? (`salt$hash` formatlarını arayın)
- **Fast hash** (MD5/SHA1/SHA256) mi, yoksa **slow KDF** (bcrypt/scrypt/argon2/PBKDF2) mi?
- Bir **format hint** (hashcat mode / John format) var mı?

### Pratik workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash'i belirleyin:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt eklenmemiş ve yaygınsa: crypto workflow section içindeki online DB'leri ve identification tooling'i deneyin.
3. Aksi durumda crack edin:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Exploit edebileceğiniz yaygın hatalar

- Aynı password'ün kullanıcılar arasında yeniden kullanılması → birini crack edin, pivot yapın.
- Truncated hash'ler / custom transforms → normalize edip yeniden deneyin.
- Weak KDF parameters (ör. düşük PBKDF2 iteration sayısı) → yine de crack edilebilir.

## References

- [1] [SkullSecurity - Hash length-extension attacks hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` için HashPump Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
