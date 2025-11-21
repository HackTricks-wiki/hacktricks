# Kriptografik/Sıkıştırma Algoritmaları

{{#include ../../banners/hacktricks-training.md}}

## Algoritmaların Tanımlanması

Bir kodda **sağa/sola kaydırma, xor'lar ve çeşitli aritmetik işlemler** kullanılıyorsa, bunun bir **kriptografik algoritma** uygulaması olması yüksek olasılıktadır. Burada, **her adımı tersine çevirmeye gerek kalmadan hangi algoritmanın kullanıldığını** tanımlamanın bazı yolları gösterilecektir.

### API fonksiyonları

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, hangi **algoritmanın kullanıldığını** ikinci parametrenin değerine bakarak bulabilirsiniz:

![](<../../images/image (156).png>)

Muhtemel algoritmalar ve atanan değerlerin tablosunu burada kontrol edin: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Verilen bir veri buffer'ını sıkıştırır ve açar.

**CryptAcquireContext**

Dokümanlara göre: **CryptAcquireContext** fonksiyonu, belirli bir cryptographic service provider (CSP) içindeki belirli bir anahtar konteynerine bir handle edinmek için kullanılır. **Bu döndürülen handle, seçilen CSP'yi kullanan CryptoAPI çağrılarında kullanılır.**

**CryptCreateHash**

Bir veri akışının hash'lenmesini başlatır. Bu fonksiyon kullanılıyorsa, hangi **algoritmanın kullanıldığını** ikinci parametrenin değerine bakarak bulabilirsiniz:

![](<../../images/image (549).png>)

\
Muhtemel algoritmalar ve atanan değerlerin tablosunu burada kontrol edin: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kod sabitleri

Bazen bir algoritmayı tanımlamak çok kolaydır çünkü özel ve benzersiz bir değer kullanması gerekir.

![](<../../images/image (833).png>)

İlk sabiti Google'da ararsanız şunu elde edersiniz:

![](<../../images/image (529).png>)

Buna göre, decompile edilmiş fonksiyonun bir **sha256 hesaplayıcısı** olduğunu varsayabilirsiniz.\
Diğer sabitlerden herhangi birini ararsanız muhtemelen aynı sonucu alırsınız.

### veri bilgisi

Kodda anlamlı bir sabit yoksa, **.data bölümünden bilgi yüklüyor** olabilir.\
Bu verilere erişip, **ilk dword'u gruplayabilir** ve daha önceki bölümde yaptığımız gibi Google'da arayabilirsiniz:

![](<../../images/image (531).png>)

Bu durumda, **0xA56363C6** değerini ararsanız bunun **AES algoritmasının tablolarıyla** ilişkili olduğunu bulabilirsiniz.

## RC4 **(Symmetric Crypt)**

### Özellikler

3 ana kısımdan oluşur:

- **Initialization stage/**: 0x00'dan 0xFF'e kadar değerlerden oluşan bir tablo oluşturur (toplam 256byte, 0x100). Bu tablo genellikle **Substitution Box** (veya SBox) olarak adlandırılır.
- **Scrambling stage**: Önceden oluşturulan tablo üzerinde **döngüye girer** (yine 0x100 iterasyonluk döngü) ve her değeri **yarı-rastgele** byte'larla değiştirir. Bu yarı-rastgele byte'ları oluşturmak için RC4 **key**'i kullanılır. RC4 **key**'leri **1 ile 256 byte** arasında olabilir; ancak genellikle 5 bytten uzun olması tavsiye edilir. Yaygın olarak, RC4 key'leri 16 byte uzunluğundadır.
- **XOR stage**: Son olarak, düz metin veya şifre metin daha önce oluşturulan değerlerle **XOR'lanır**. Şifreleme ve şifre çözme fonksiyonu aynıdır. Bunun için oluşturulan 256 byte üzerinde gerektiği kadar tekrar eden bir **döngü** yürütülür. Decompile edilmiş kodda bu genellikle **%256 (mod 256)** ile tanınır.

> [!TIP]
> **Bir disassembly/decompile edilmiş kodda RC4'ü tanımlamak için 0x100 boyutunda 2 döngü (key kullanımı ile) ve ardından giriş verisinin önceki 2 döngüde oluşturulan 256 değer ile XOR'lanması, muhtemelen %256 (mod 256) kullanılarak, aranabilir.**

### **Initialization stage/Substitution Box:** (Sayaç olarak kullanılan 256 sayısına ve 256 karakterin her yerine nasıl 0 yazıldığına dikkat edin)

![](<../../images/image (584).png>)

### **Scrambling Aşaması:**

![](<../../images/image (835).png>)

### **XOR Aşaması:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Özellikler**

- **substitution box'lar ve lookup tabloları** kullanımı
- Belirli **lookup tablo** değerlerinin kullanımı sayesinde AES'i ayırt etmek mümkündür (sabitler). _Sabitin ikili dosyada **saklanabileceğini** veya **dinamik olarak oluşturulabileceğini** unutmayın._
- **Şifreleme key'i** 16'ya bölünebilir olmalıdır (genellikle 32B) ve genellikle 16B boyutunda bir **IV** kullanılır.

### SBox sabitleri

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Özellikler

- Bazı kötü amaçlı yazılımlarda kullanılması nadirdir ama örnekleri vardır (Ursnif)
- Bir algoritmanın Serpent olup olmadığını uzunluğuna bakarak belirlemek basittir (aşırı uzun fonksiyon)

### Tanımlama

Aşağıdaki görüntüde **0x9E3779B9** sabitinin nasıl kullanıldığına dikkat edin (bu sabitin **TEA** - Tiny Encryption Algorithm gibi diğer kripto algoritmalarında da kullanıldığını unutmayın).\
Ayrıca **döngü boyuna** (**132**) ve **disassembly** talimatlarındaki ve **kod** örneğindeki XOR operasyonu sayısına dikkat edin:

![](<../../images/image (547).png>)

Daha önce bahsedildiği gibi, bu kod herhangi bir decompiler içinde **çok uzun bir fonksiyon** olarak görülebilir çünkü içinde **atlamalar (jumps)** yoktur. Decompile edilmiş kod aşağıdaki gibi görünebilir:

![](<../../images/image (513).png>)

Bu nedenle, **magic number'ı** ve **ilk XOR'ları** kontrol ederek, **çok uzun bir fonksiyon** görerek ve uzun fonksiyonun bazı **talimatlarını** (ör. 7 ile sola kaydırma ve 22 ile rotate sol) bir **implementasyonla karşılaştırarak** bu algoritmayı tanımlamak mümkündür.

## RSA **(Asymmetric Crypt)**

### Özellikler

- Symmetric algoritmalardan daha karmaşıktır
- Sabitler yoktur! (özelleştirilmiş implementasyonları belirlemek zordur)
- KANAL (bir crypto analyzer) RSA hakkında ipuçları göstermede başarısız olur çünkü sabitlere dayanır.

### Karşılaştırmalarla tanımlama

![](<../../images/image (1113).png>)

- Sol taraftaki 11. satırda `+7) >> 3` var, bu sağdaki 35. satırdaki `+7) / 8` ile aynıdır.
- Sol taraftaki 12. satır `modulus_len < 0x040` kontrolü yapıyor ve sağdaki 36. satır `inputLen+11 > modulusLen` kontrolünü yapıyor.

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

- Amacı verideki kazara değişiklikleri bulmak olduğundan daha küçük ve daha verimlidir
- Lookup tabloları kullanır (dolayısıyla sabitleri tanımlayabilirsiniz)

### Tanımlama

Lookup tablo sabitlerini kontrol edin:

![](<../../images/image (508).png>)

Bir CRC hash algoritması şöyle görünür:

![](<../../images/image (391).png>)

## APLib (Compression)

### Özellikler

- Tanınabilir sabitler yok
- Algoritmayı python'da yazmayı deneyebilir ve benzer şeyleri çevrimiçi arayabilirsiniz

### Tanımlama

Graf oldukça büyük:

![](<../../images/image (207) (2) (1).png>)

Tanımak için **3 karşılaştırmaya** bakın:

![](<../../images/image (430).png>)

## Elliptik Eğri İmza Uygulama Hataları

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2, HashEdDSA doğrulayıcılarının bir imzayı `sig = R || s` olarak ayırmalarını ve `n` grup düzeni olmak üzere `s \geq n` olan herhangi bir skaler değeri reddetmelerini gerektirir. `elliptic` JS kütüphanesi bu sınır kontrolünü atlamıştı; bu yüzden bir saldırgan, geçerli `(msg, R || s)` çiftini biliyorsa alternatif imzalar `s' = s + k·n` üretebilir ve `sig' = R || s'` olarak yeniden kodlamaya devam edebilir.
- Doğrulama rutini yalnızca `s mod n` değerini kullanır; bu nedenle farklı byte dizileri olsalar bile `s` ile kongruent olan tüm `s'` değerleri kabul edilir. İmzaları canonical token olarak işleyen sistemler (blockchain consensus, replay caches, DB keys, vb.) katı implementasyonlar `s'`'yi reddedeceği için senkronizasyon dışı kalabilir.
- Diğer HashEdDSA kodlarını denetlerken, parser'ın hem `R` noktasını hem de skaler uzunluğunu doğruladığından emin olun; doğrulayıcının kapalı (fail closed) davrandığını teyit etmek için bilinen doğrulanmış bir `s`'ye `n`'in katlarını eklemeyi deneyin.

### ECDSA truncation vs. leading-zero hashes

- ECDSA doğrulayıcıları mesaj hash'i `H`'in yalnızca en sol `log2(n)` bitini kullanmalıdır. `elliptic`'te truncation yardımcı fonksiyonu `delta = (BN(msg).byteLength()*8) - bitlen(n)` şeklinde hesaplanıyordu; `BN` yapıcısı baştaki sıfır oktetleri düşürdüğünden, secp192r1 (192-bit düzen) gibi eğrilerde ≥4 sıfır byte ile başlayan herhangi bir hash 256 yerine yalnızca 224 bit olarak görünüyordu.
- Doğrulayıcı 64 yerine 32 bit sağa kaydırma yaptı ve bu da imzalayan tarafından kullanılan değerle eşleşmeyen bir `E` üretti. Bu nedenle bu hash'lere ait geçerli imzalar, SHA-256 girdileri için ≈`2^-32` ihtimalle başarısız olur.
- Hedef implementasyona hem “her şey iyi” vektörünü hem de baştaki sıfırlı varyantları (ör. Wycheproof `ecdsa_secp192r1_sha256_test.json` vaka `tc296`) verin; doğrulayıcı ile imzalayan farklı düşünüyorsa, tespit edilebilir bir kırpma hatası buldunuz.

### Kütüphanelere karşı Wycheproof vektörlerini uygulama
- Wycheproof, bozuk noktaları, değiştirilebilir skalerleri, sıra dışı hash'leri ve diğer köşe durumlarını kodlayan JSON test setleri sağlar. `elliptic` (veya herhangi bir kripto kütüphanesi) etrafında bir harness oluşturmak basittir: JSON'u yükleyin, her test vakasını deserialize edin ve implementasyonun beklenen `result` bayrağıyla eşleştiğini doğrulayın.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Hatalar, spesifikasyon ihlallerini yanlış pozitiflerden ayırt etmek üzere sınıflandırılmalıdır. Yukarıdaki iki hata için, başarısız Wycheproof vakaları hemen eksik skaler aralık kontrollerine (EdDSA) ve hatalı hash kırpılmasına (ECDSA) işaret etti.
- Test harness'ı CI'ye entegre edin, böylece skaler ayrıştırma, hash işleme veya koordinat geçerliliğiyle ilgili gerilemeler ortaya çıkar çıkmaz testler tetiklenir. Bu, ince bignum dönüşümlerinin kolayca yanlış yapıldığı yüksek seviyeli diller (JS, Python, Go) için özellikle faydalıdır.

## Referanslar

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
