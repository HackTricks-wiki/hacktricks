# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Yaygın CTF kalıpları

- "Signature", aslında `hash(secret || message)` şeklindedir → length extension.
- Salt eklenmemiş parola hash'leri → daha hızlı tekrarlı cracking ve önceden hesaplanmış lookup saldırıları.
- Hash ile MAC'i karıştırmak (hash != authentication).

## Hash length extension attack

### Teknik

Sunucu, aşağıdaki gibi bir "signature" hesapladığında:

`sig = HASH(secret || message)`

ve MD5, SHA-1 veya SHA-256 gibi bir Merkle-Damgård hash'i kullandığında length-extension attack mümkün olabilir.

Şunları biliyorsanız:

- `message`
- `sig`
- hash fonksiyonu
- (`len(secret)` değerini brute-force edebiliyorsanız)

Şunu bilmeden geçerli bir signature hesaplayabilirsiniz:

`message || padding || appended_data`

secret'ı bilmeden.<sup>[[1]](#references)</sup>

### Önemli kısıtlama: HMAC etkilenmez

Length-extension attack, `HASH(secret || message)` gibi güvenlik açığı barındıran prefix yapıları için geçerlidir. Ayrı inner ve outer hash uygulamalarıyla bir key'i birleştiren HMAC yapısını (örneğin, HMAC-SHA256) açığa çıkarmaz.<sup>[[1]](#references)[[2]](#references)</sup>

### Araçlar

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension aracı için Python bindings<sup>[[7]](#references)</sup>

### İyi bir açıklama

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Parola hashing ve cracking

### İlk sorular<sup>[[4]](#references)</sup>

- **Salt eklenmiş mi**? (`salt$hash` formatlarına bakın)
- **Hızlı bir hash** (MD5/SHA1/SHA256) mi, yoksa **yavaş bir KDF** (bcrypt/scrypt/argon2/PBKDF2) mi?
- Elinizde bir **format ipucu** (hashcat mode / John format) var mı?

### Uygulamalı iş akışı<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash'i tanımlayın:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt eklenmemiş ve yaygın bir hash ise: çevrimiçi DB'leri ve crypto workflow bölümündeki tanımlama araçlarını deneyin.
3. Aksi takdirde crack edin:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### İstismar edebileceğiniz yaygın hatalar

- Aynı parolanın kullanıcılar arasında tekrar kullanılması → birini crack edin, pivot edin.
- Kesilmiş hash'ler / özel dönüşümler → normalize edip yeniden deneyin.
- Zayıf KDF parametreleri (ör. düşük PBKDF2 iterasyon sayısı) → yine de crack edilebilir.

### Eklenmiş bir secret içeren, girdi seçilebilen bcrypt oracle

`bcrypt(user_input || secret)` döndüren çağrılabilir bir yardımcı, bcrypt uygulaması girdiyi 72 **byte** sonrasında sessizce kesiyorsa eklenmiş bir secret hakkında bilgi açığa çıkarabilir. UTF-8 kodlamasından önce karakter sayısına uygulanan bir limit, bu byte sınırını sağlamaz: çok baytlı karakterler bcrypt girdisini doldururken secret'ın yalnızca küçük bir ön eki için yer bırakabilir. Seçilen girdiler ve döndürülen hash'ler, aday son ek byte'larının çevrimdışı kontrol edilmesini sağlayabilir. Bunun için yardımcının girdisini kontrol edebilmeniz, tam dönüşümünü ve encoding'ini bilmeniz ve uygulamanın gerçekten kesme yapması gerekir; çağrılabilir bir yardımcı veya tek başına bir bcrypt hash'i bu zincirin varlığını kanıtlamaz. [pyca/bcrypt belgeleri](https://github.com/pyca/bcrypt#maximum-password-length), güncel `hashpw` işlevinin 72 byte'tan uzun girdilerde hata verdiğini, önceki davranışın ise bunları sessizce kestiğini belirtir. Diğer wrapper'lar girdiyi önceden hash'leyebilir veya uzun girdileri reddedebilir; bu nedenle kesme olduğunu varsaymak yerine kurulu uygulamayı doğrulayın.

Ele geçirilen bir secret'ı farklı bir hesapta kullanmak için, o hesabın açığa çıkan hash'inin **aynı** secret ve dönüşümle oluşturulduğuna dair kanıtın yanı sıra ayrı bir credential veya login yolu da gerekir. Root olarak çalışan bir hashing yardımcısı, yalnızca düşük yetkili kullanıcı yürürlükteki policy kapsamında onu çağırabiliyorsa oracle olarak değerlendirilmelidir; pasif host enumeration işleminin bu yardımcının çağrılmasını veya seçilen parolaların gönderilmesini gerektirmesi şart değildir.

## References

- [1] [SkullSecurity - Hash length-extension saldırıları hakkında bilmeniz gereken her şey](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Parola Depolama İpuçları](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat örnek hash'leri](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper komut satırı seçenekleri](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump için `hashpumpy` Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
