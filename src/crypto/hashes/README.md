# Hashes, MACs ve KDF'ler

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF kalıpları

- "Signature" aslında `hash(secret || message)` → length extension.
- Salt eklenmemiş password hash'leri → daha hızlı tekrarlı cracking ve önceden hesaplanmış lookup saldırıları.
- Hash ile MAC'i karıştırmak (hash != authentication).

## Hash length extension attack

### Teknik

Sunucu aşağıdaki gibi bir "signature" hesaplıyorsa:

`sig = HASH(secret || message)`

ve MD5, SHA-1 veya SHA-256 gibi bir Merkle-Damgård hash'i kullanıyorsa length-extension attack mümkün olabilir.

Şunları biliyorsanız:

- `message`
- `sig`
- hash function
- (veya brute-force uygulayarak) `len(secret)`

secret'ı bilmeden şu veri için geçerli bir signature hesaplayabilirsiniz:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Önemli sınırlama: HMAC etkilenmez

Length-extension attack'ler, `HASH(secret || message)` gibi savunmasız prefix yapılar için geçerlidir. Anahtarı ayrı inner ve outer hash uygulamalarıyla birleştiren HMAC yapısını (örneğin HMAC-SHA256) açığa çıkarmazlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Araçlar

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension aracı için Python bindings<sup>[[7]](#references)</sup>

### İyi bir açıklama

[Hash length extension attack'leri hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing ve cracking

### İlk sorular<sup>[[4]](#references)</sup>

- **Salt eklenmiş mi**? (`salt$hash` biçimlerini arayın)
- **Hızlı bir hash** mi (MD5/SHA1/SHA256), yoksa **yavaş bir KDF** mi (bcrypt/scrypt/argon2/PBKDF2)?
- **Biçim ipucunuz** var mı (hashcat mode / John format)?

### Uygulamalı iş akışı<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash'i tanımlayın:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt eklenmemiş ve yaygın bir hash ise: çevrimiçi DB'leri ve crypto workflow bölümündeki tanımlama araçlarını deneyin.
3. Aksi durumda crack edin:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### İstismar edebileceğiniz yaygın hatalar

- Aynı password'ün farklı kullanıcılar tarafından yeniden kullanılması → birini crack edin, ardından pivot yapın.
- Kısaltılmış hash'ler / özel dönüşümler → normalleştirip yeniden deneyin.
- Zayıf KDF parametreleri (ör. düşük PBKDF2 iteration sayısı) → yine de crack edilebilir.

### Sonuna secret eklenen, seçilen girdileri kabul eden bcrypt oracle

`bcrypt(user_input || secret)` döndüren ve çağrılabilen bir yardımcı program, bcrypt uygulaması girdiyi 72 **byte** sonrasında sessizce kısaltıyorsa sonuna eklenen secret hakkında bilgi açığa çıkarabilir. UTF-8 encoding öncesinde uygulanan karakter sayısı sınırı bu byte sınırını garanti etmez: çok byte'lı karakterler bcrypt girdisini doldururken secret'ın yalnızca kısa bir önekinin sığmasına yer bırakabilir. Ardından seçilen girdiler ve bunlara karşılık gelen hash'ler, aday suffix byte'larının offline olarak kontrol edilmesini sağlayabilir. Bunun için yardımcı programın girdisini kontrol edebilmek, kullandığı dönüşümü ve encoding'i tam olarak bilmek ve uygulamanın gerçekten kısaltma yapması gerekir; çağrılabilir bir yardımcı program veya tek başına bir bcrypt hash'i bu zinciri kanıtlamaz. [pyca/bcrypt belgelerine](https://github.com/pyca/bcrypt#maximum-password-length) göre güncel `hashpw`, 72 byte'ı aşan girdilerde hata verir; önceki davranış ise girdileri sessizce kısaltıyordu. Diğer wrapper'lar girdileri önceden hash'leyebilir veya uzun girdileri reddedebilir. Bu nedenle kısaltma yapıldığını varsaymak yerine kurulu uygulamayı doğrulayın.

Kurtarılan bir secret'ı farklı bir hesapta kullanmak için, o hesabın açığa çıkan hash'inin **aynı** secret ve dönüşümle üretildiğine dair kanıtın yanı sıra ayrı bir credential veya login yolu da gerekir. Root olarak çalışan bir hash'leme yardımcısı, yalnızca düşük ayrıcalıklı kullanıcı onu etkin politikaya göre çağırabiliyorsa oracle olarak değerlendirilmelidir; pasif host enumeration sırasında bu yardımcı programı çağırmak veya seçilmiş password'leri göndermek gerekmez.

## References

- [1] [SkullSecurity - Hash length-extension attack'leri hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Anahtarlı Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat örnek hash'leri](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper komut satırı seçenekleri](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump için `hashpumpy` Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
