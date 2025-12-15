# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF patterns

- "Signature" aslında `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Hash ile MAC'i karıştırmak (hash != authentication).

## Hash length extension attack

### Teknik

Bunu genellikle şu şekilde bir "signature" hesaplayan bir sunucuda istismar edebilirsiniz:

`sig = HASH(secret || message)`

ve Merkle–Damgård hash kullandığında (klasik örnekler: MD5, SHA-1, SHA-256).

Eğer şunları biliyorsanız:

- `message`
- `sig`
- hash function
- (veya brute-force yapabiliyorsanız) `len(secret)`

O zaman secret'i bilmeden şu için geçerli bir signature hesaplayabilirsiniz:

`message || padding || appended_data`

### Önemli sınırlama: HMAC etkilenmez

Length extension attacks, Merkle–Damgård hash'leri için `HASH(secret || message)` gibi yapılarla ilgilidir. **HMAC** (ör. HMAC-SHA256) bu sınıf problemi önlemek için özel olarak tasarlanmıştır, bu yüzden etkilenmez.

### Araçlar

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### İyi açıklama

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### İlk sorular

- Is it **salted**? (look for `salt$hash` formats)
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint** (hashcat mode / John format)?

### Pratik iş akışı

1. Hash'i belirleyin:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Eğer unsalted ve yaygınsa: çevrimiçi DB'leri ve crypto workflow bölümündeki tanımlama araçlarını deneyin.
3. Aksi halde kırın:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### İstismar edebileceğiniz yaygın hatalar

- Aynı parola kullanıcılar arasında tekrar kullanılmış → birini kırın, pivot yapın.
- Truncated hashes / custom transforms → normalize edip tekrar deneyin.
- Zayıf KDF parametreleri (ör. düşük PBKDF2 iterasyon sayısı) → hâlâ kırılabilir.

{{#include ../../banners/hacktricks-training.md}}
