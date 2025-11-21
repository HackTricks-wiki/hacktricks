# Kriptografik/Sıkıştırma Algoritmaları

{{#include ../../banners/hacktricks-training.md}}

## Algoritmaların Tanımlanması

Eğer kodda **sağa ve sola shift'ler, xors ve çeşitli aritmetik işlemler** kullanılıyorsa, bunun bir **kriptografik algoritmanın** uygulanması olması yüksek ihtimaldir. Burada her adımı tersine çevirmeye gerek kalmadan kullanılan algoritmayı **tanımlamanın** bazı yolları gösterilecektir.

### API functions

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, hangi **algoritmanın kullanıldığını** ikinci parametrenin değerini kontrol ederek bulabilirsiniz:

![](<../../images/image (156).png>)

Olası algoritmalar ve onlara atanmış değerlerin tablosunu buradan kontrol edin: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Verilen bir veri buffer'ını sıkıştırır ve açar.

**CryptAcquireContext**

Dokümanlardan: The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Başlangıç olarak bir veri akışının hashing'ini başlatır. Bu fonksiyon kullanılıyorsa, hangi **algoritmanın kullanıldığını** ikinci parametrenin değerini kontrol ederek bulabilirsiniz:

![](<../../images/image (549).png>)

\
Olası algoritmalar ve onlara atanmış değerlerin tablosunu buradan kontrol edin: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Bazen bir algoritmayı tanımlamak çok kolaydır çünkü özel ve benzersiz bir değeri kullanması gerekir.

![](<../../images/image (833).png>)

Eğer ilk sabiti Google'da ararsanız şu sonucu elde edersiniz:

![](<../../images/image (529).png>)

Böylece decompile edilmiş fonksiyonun bir **sha256 hesaplayıcısı** olduğunu varsayabilirsiniz.\
Diğer sabitlerden herhangi birini ararsanız muhtemelen aynı sonucu alırsınız.

### data info

Eğer kodda anlamlı bir sabit yoksa, .data bölümünden bilgi yüklüyor olabilir.\
O verilere erişip, **ilk dword'u gruplayabilir** ve daha önceki bölümde yaptığımız gibi Google'da arayabilirsiniz:

![](<../../images/image (531).png>)

Bu durumda, **0xA56363C6** değerini ararsanız bunun **AES algoritmasının tablolarıyla** ilişkili olduğunu bulabilirsiniz.

## RC4 **(Simetrik Kriptografi)**

### Özellikler

3 ana bölümden oluşur:

- **Initialization stage/**: 0x00'dan 0xFF'e kadar değerlerden oluşan bir tablo oluşturur (toplam 256 byte, 0x100). Bu tablo genellikle Substitution Box (veya SBox) olarak adlandırılır.
- **Scrambling stage**: Önceden oluşturulan tablo üzerinde (yeniden 0x100 iterasyonluk döngü) döner ve her değeri yarı-rasgele baytlarla değiştirerek oluşturur. Bu yarı-rasgele baytları oluşturmak için RC4 **key** kullanılır. RC4 **keys** uzunluk olarak 1 ile 256 byte arasında olabilir; ancak genellikle 5 bytten uzun olması önerilir. Yaygın olarak, RC4 key'leri 16 byte uzunluğundadır.
- **XOR stage**: Son olarak, düz metin veya şifrelenmiş metin daha önce oluşturulan değerlerle **XOR'lanır**. Şifreleme ve deşifreleme fonksiyonu aynıdır. Bunun için oluşturulan 256 byte üzerinde gerektiği kadar döngü yapılır. Bu genellikle decompiled kodda bir **%256 (mod 256)** ile tanınır.

> [!TIP]
> **Bir disassembly/decompiled kodda RC4'ü tanımlamak için 0x100 boyutunda 2 döngü (key kullanılarak) ve ardından giriş verisinin önceki 2 döngüde oluşturulan 256 değerle XOR'lanmasını, muhtemelen %256 (mod 256) kullanılarak kontrol edebilirsiniz.**

### **Initialization stage/Substitution Box:** (Sayaç olarak kullanılan 256 sayısına ve 256 karakterin her bir yerine 0 yazılmasına dikkat edin)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Simetrik Kriptografi)**

### **Özellikler**

- **substitution box'lar ve lookup tabloları** kullanımı
- Belirli lookup tablo değerlerinin (sabitlerin) kullanımı sayesinde AES'i **ayrıştırmak** mümkündür. _Not: **sabit** ikili içinde **saklanmış** veya **dinamik olarak oluşturulmuş** olabilir._
- **encryption key** 16'ya bölünebilir olmalıdır (genellikle 32B) ve genellikle 16B uzunluğunda bir **IV** kullanılır.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Simetrik Kriptografi)**

### Özellikler

- Malware'lerde nadiren görülür ama örnekler vardır (Ursnif)
- Uzunluğu (aşırı uzun fonksiyon) sayesinde Serpent olup olmadığını tespit etmek basittir

### Tanımlama

Aşağıdaki görüntüde **0x9E3779B9** sabitinin nasıl kullanıldığına dikkat edin (bu sabit aynı zamanda **TEA** - Tiny Encryption Algorithm gibi diğer kripto algoritmaları tarafından da kullanılır).\
Ayrıca döngü **boyutuna** (**132**) ve disassembly talimatlarındaki ve kod örneğindeki **XOR işlemi sayısına** dikkat edin:

![](<../../images/image (547).png>)

Daha önce belirtildiği gibi, bu kod herhangi bir decompiler içinde **çok uzun bir fonksiyon** olarak görüntülenebilir çünkü içinde **jumplar yoktur**. Decompile edilmiş kod şu şekilde görünebilir:

![](<../../images/image (513).png>)

Bundan dolayı, bu algoritmayı **sihirli sayıyı** ve **ilk XOR'ları** kontrol ederek, çok uzun bir fonksiyon görerek ve uzun fonksiyondaki bazı **talimatları** (örneğin 7 ile sola shift ve 22 ile rotate left) bir implementasyonla **karşılaştırarak** tanımlamak mümkündür.

## RSA **(Asimetrik Kriptografi)**

### Özellikler

- Simetrik algoritmalardan daha karmaşıktır
- Sabitler yoktur! (özel implementasyonları belirlemek zordur)
- KANAL (a crypto analyzer) sabitlere dayandığı için RSA hakkında ipuçları gösteremez.

### Karşılaştırmayla tanımlama

![](<../../images/image (1113).png>)

- Satır 11 (sol)da `+7) >> 3` ifadesi var; bu satır 35 (sağ) ile aynıdır: `+7) / 8`
- Satır 12 (sol) `modulus_len < 0x040` kontrolünü yapıyor ve satır 36 (sağ) `inputLen+11 > modulusLen` kontrolünü yapıyor

## MD5 & SHA (hash)

### Özellikler

- 3 fonksiyon: Init, Update, Final
- Benzer başlatma fonksiyonları

### Tanımlama

**Init**

Her ikisini de sabitleri kontrol ederek tanımlayabilirsiniz. sha_init'in MD5'te olmayan 1 sabiti olduğunu unutmayın:

![](<../../images/image (406).png>)

**MD5 Transform**

Daha fazla sabit kullanımına dikkat edin

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Daha küçük ve daha etkilidir çünkü amacı verideki kazara oluşan değişiklikleri bulmaktır
- Lookup tabloları kullanır (dolayısıyla sabitleri tanımlayabilirsiniz)

### Tanımlama

**lookup table sabitlerini** kontrol edin:

![](<../../images/image (508).png>)

Bir CRC hash algoritması şu şekilde görünür:

![](<../../images/image (391).png>)

## APLib (Compression)

### Özellikler

- Tanınabilir sabitler yok
- Algoritmayı python'da yazmayı deneyip benzer şeyleri çevrimiçi arayabilirsiniz

### Tanımlama

Graf oldukça büyük:

![](<../../images/image (207) (2) (1).png>)

Tanımak için **3 karşılaştırmayı** kontrol edin:

![](<../../images/image (430).png>)

## Eliptik Eğri İmza Uygulama Hataları

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2, HashEdDSA doğrulayıcılarının bir imzayı `sig = R || s` olarak bölmesini ve `n` grup düzeni olmak üzere `s \geq n` olan herhangi bir skalerı reddetmesini gerektirir. `elliptic` JS kütüphanesi bu sınır kontrolünü atladı; bu yüzden geçerli bir çift `(msg, R || s)` bilen herhangi bir saldırgan alternatif imzalar `s' = s + k·n` üretebilir ve `sig' = R || s'` olarak tekrar kodlamaya devam edebilir.
- Doğrulama rutinleri yalnızca `s mod n` değerini kullandığından, `s` ile kongruent olan tüm `s'` değerleri farklı byte dizileri olsalar bile kabul edilir. İmzaları canonical token olarak ele alan sistemler (blockchain consensus, replay cache'leri, DB anahtarları vb.) sıkı uygulamalar tarafından `s'` reddedileceği için senkronizasyon dışı kalabilir.
- Diğer HashEdDSA kodlarını denetlerken, parser'ın hem nokta `R` hem de skaler uzunluğunu doğruladığından emin olun; doğrulayıcının kapalı başarısızlık verdiğini doğrulamak için bilinen iyi bir `s` değerine `n`'in katlarını eklemeyi deneyin.

### ECDSA truncation vs. leading-zero hashes

- ECDSA doğrulayıcıları, mesaj hash'i `H`'in yalnızca en solundaki `log2(n)` bitlerini kullanmalıdır. `elliptic` içinde truncation yardımcı fonksiyonu `delta = (BN(msg).byteLength()*8) - bitlen(n)` hesaplıyordu; `BN` yapıcısı baştaki sıfır oktetleri düşürdüğü için, secp192r1 (192-bit düzen) gibi eğrilerde ≥4 sıfır byte ile başlayan herhangi bir hash 256 yerine yalnızca 224 bitmiş gibi görünüyordu.
- Doğrulayıcı 64 yerine 32 bit kaydırdı ve bu, signer tarafından kullanılan değerle eşleşmeyen bir `E` üretti. Bu nedenle bu hash'ler üzerindeki geçerli imzalar SHA-256 girdileri için ≈`2^-32` olasılıkla başarısız olur.
- Hem “her şey iyi” vektörünü hem de baştaki sıfır varyantlarını (ör. Wycheproof `ecdsa_secp192r1_sha256_test.json` vaka `tc296`) hedef implementasyona verin; doğrulayıcı signer ile uyuşmuyorsa, sömürülebilir bir truncation hatası buldunuz.

### Wycheproof vektörlerini kütüphaneler üzerinde çalıştırma
- Wycheproof, bozuk noktalar, malleable skalerler, alışılmadık hash'ler ve diğer köşe durumlarını kodlayan JSON test setleri gönderir. `elliptic` (veya herhangi bir crypto kütüphanesi) etrafında bir harness oluşturmak basittir: JSON'u yükleyin, her test case'i deserialize edin ve implementasyonun beklenen `result` bayrağı ile eşleştiğini doğrulayın.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Hatalar, spesifikasyon ihlalleri ile yanlış pozitifleri ayırt edecek şekilde sınıflandırılmalı ve önceliklendirilmelidir. Yukarıdaki iki hata için, başarısız olan Wycheproof vakaları hemen eksik skaler aralık kontrollerine (EdDSA) ve hatalı hash kısaltmasına (ECDSA) işaret etti.
- Harness'i CI'ye entegre edin, böylece skaler ayrıştırma, hash işleme veya koordinat geçerliliğiyle ilgili gerilemeler, ortaya çıktıkları anda testleri tetikler. Bu, ince bignum dönüşümlerinin kolayca yanlış yapılabildiği yüksek seviyeli diller (JS, Python, Go) için özellikle faydalıdır.

## Referanslar

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
