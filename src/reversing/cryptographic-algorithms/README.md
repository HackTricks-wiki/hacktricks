# Kriptografik/Sıkıştırma Algoritmaları

## Kriptografik/Sıkıştırma Algoritmaları

{{#include ../../banners/hacktricks-training.md}}

## Algoritmaları Tanımlama

Eğer bir kod **sağ ve sol kaydırmalar, XOR'lar ve çeşitli aritmetik işlemler** kullanıyorsa, bunun bir **kriptografik algoritmanın** uygulanması olması oldukça olasıdır. Burada, **her adımı tersine çevirmeden kullanılan algoritmayı tanımlamanın bazı yolları** gösterilecektir.

### API fonksiyonları

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek hangi **algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../images/image (375) (1) (1) (1) (1).png>)

Olası algoritmalar ve atanan değerleri içeren tabloya buradan bakın: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Verilen bir veri tamponunu sıkıştırır ve açar.

**CryptAcquireContext**

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): **CryptAcquireContext** fonksiyonu, belirli bir kriptografik hizmet sağlayıcısı (CSP) içindeki belirli bir anahtar konteynerine bir tanıtıcı almak için kullanılır. **Bu döndürülen tanıtıcı, seçilen CSP'yi kullanan CryptoAPI** fonksiyonlarına yapılan çağrılarda kullanılır.

**CryptCreateHash**

Bir veri akışının hash'lenmesini başlatır. Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek hangi **algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../images/image (376).png>)

\
Olası algoritmalar ve atanan değerleri içeren tabloya buradan bakın: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kod sabitleri

Bazen, bir algoritmayı tanımlamak gerçekten kolaydır çünkü özel ve benzersiz bir değer kullanması gerekir.

![](<../../images/image (370).png>)

Eğer ilk sabiti Google'da ararsanız, bu sonucu alırsınız:

![](<../../images/image (371).png>)

Bu nedenle, decompile edilmiş fonksiyonun bir **sha256 hesaplayıcı** olduğunu varsayabilirsiniz.\
Diğer sabitlerden herhangi birini arayabilirsiniz ve (muhtemelen) aynı sonucu alırsınız.

### veri bilgisi

Eğer kodda herhangi bir önemli sabit yoksa, bu **.data bölümünden bilgi yüklüyor olabilir**.\
Bu veriye erişebilir, **ilk dword'u gruplandırabilir** ve önceki bölümde yaptığımız gibi Google'da arama yapabilirsiniz:

![](<../../images/image (372).png>)

Bu durumda, eğer **0xA56363C6**'yı ararsanız, bunun **AES algoritmasının tablolarıyla** ilişkili olduğunu bulabilirsiniz.

## RC4 **(Simetrik Kriptografi)**

### Özellikler

3 ana bölümden oluşur:

- **Başlatma aşaması/**: **0x00'dan 0xFF'e kadar değerler içeren bir tablo oluşturur** (toplam 256 bayt, 0x100). Bu tablo genellikle **Yer Değiştirme Kutusu** (veya SBox) olarak adlandırılır.
- **Karıştırma aşaması**: Daha önce oluşturulan tabloyu **döngü ile geçer** (0x100 yine döngüsü) ve her değeri **yarı rastgele** baytlarla değiştirir. Bu yarı rastgele baytları oluşturmak için RC4 **anahtarı kullanılır**. RC4 **anahtarları** **1 ile 256 bayt arasında** olabilir, ancak genellikle 5 bayttan fazla olması önerilir. Genellikle, RC4 anahtarları 16 bayt uzunluğundadır.
- **XOR aşaması**: Son olarak, düz metin veya şifreli metin, **önceki değerlerle XOR'lanır**. Şifreleme ve şifre çözme fonksiyonu aynıdır. Bunun için, oluşturulan 256 bayt üzerinden gerekli olduğu kadar döngü yapılacaktır. Bu genellikle decompile edilmiş kodda **%256 (mod 256)** ile tanınır.

> [!NOTE]
> **Bir disassembly/decompile edilmiş kodda RC4'ü tanımlamak için 0x100 boyutunda 2 döngü kontrol edebilir ve ardından giriş verisinin 2 döngüde oluşturulan 256 değerle XOR'lanmasını kontrol edebilirsiniz, muhtemelen %256 (mod 256) kullanarak**

### **Başlatma aşaması/Yer Değiştirme Kutusu:** (Sayac olarak kullanılan 256 sayısını ve 256 karakterin her yerinde nasıl 0 yazıldığını not edin)

![](<../../images/image (377).png>)

### **Karıştırma Aşaması:**

![](<../../images/image (378).png>)

### **XOR Aşaması:**

![](<../../images/image (379).png>)

## **AES (Simetrik Kriptografi)**

### **Özellikler**

- **yer değiştirme kutuları ve arama tabloları** kullanımı
- **Belirli arama tablo değerlerinin** (sabitlerin) kullanımı sayesinde AES'i **ayırmak mümkündür**. _Not edin ki **sabit** ikili **ya da dinamik olarak** _**oluşturulabilir**._
- **Şifreleme anahtarı** **16'ya** (genellikle 32B) **tam bölünebilir** olmalıdır ve genellikle 16B'lik bir **IV** kullanılır.

### SBox sabitleri

![](<../../images/image (380).png>)

## Serpent **(Simetrik Kriptografi)**

### Özellikler

- Bunu kullanan bazı kötü amaçlı yazılımlar bulmak nadirdir ama örnekler vardır (Ursnif)
- Bir algoritmanın Serpent olup olmadığını belirlemek basittir, uzunluğuna (son derece uzun fonksiyon) dayanarak

### Tanımlama

Aşağıdaki görüntüde **0x9E3779B9** sabitinin nasıl kullanıldığına dikkat edin (bu sabitin ayrıca **TEA** -Küçük Şifreleme Algoritması gibi diğer kripto algoritmalarında da kullanıldığını not edin).\
Ayrıca **döngünün boyutunu** (**132**) ve **disassembly** talimatlarındaki ve **kod** örneğindeki **XOR işlemleri** sayısını not edin:

![](<../../images/image (381).png>)

Daha önce belirtildiği gibi, bu kod herhangi bir decompiler içinde **çok uzun bir fonksiyon** olarak görselleştirilebilir çünkü içinde **atlamalar** yoktur. Decompile edilmiş kod aşağıdaki gibi görünebilir:

![](<../../images/image (382).png>)

Bu nedenle, bu algoritmayı tanımlamak, **büyülü sayıyı** ve **ilk XOR'ları** kontrol ederek, **çok uzun bir fonksiyon** görerek ve uzun fonksiyonun bazı **talimatlarını** bir **uygulama** ile **karşılaştırarak** mümkündür (örneğin, 7'ye sola kaydırma ve 22'ye sola döndürme).

## RSA **(Asimetrik Kriptografi)**

### Özellikler

- Simetrik algoritmalardan daha karmaşık
- Sabit yok! (özel uygulamaların belirlenmesi zordur)
- KANAL (bir kripto analizörü) RSA hakkında ipuçları gösteremiyor çünkü sabitlere dayanıyor.

### Karşılaştırmalarla Tanımlama

![](<../../images/image (383).png>)

- 11. satırda (solda) `+7) >> 3` var, bu sağdaki 35. satırda da aynı: `+7) / 8`
- 12. satır (solda) `modulus_len < 0x040` kontrol ediyor ve 36. satırda (sağda) `inputLen+11 > modulusLen` kontrol ediliyor.

## MD5 & SHA (hash)

### Özellikler

- 3 fonksiyon: Init, Update, Final
- Benzer başlatma fonksiyonları

### Tanımlama

**Init**

Her ikisini de sabitleri kontrol ederek tanımlayabilirsiniz. sha_init'in MD5'de olmayan 1 sabiti olduğunu not edin:

![](<../../images/image (385).png>)

**MD5 Dönüşümü**

Daha fazla sabit kullanıldığına dikkat edin

![](<../../images/image (253) (1) (1) (1).png>)

## CRC (hash)

- Daha küçük ve daha verimli, çünkü işlevi verilerdeki kazara değişiklikleri bulmaktır
- Sabitleri tanımlamak için arama tabloları kullanır

### Tanımlama

**arama tablo sabitlerini** kontrol edin:

![](<../../images/image (387).png>)

Bir CRC hash algoritması şöyle görünür:

![](<../../images/image (386).png>)

## APLib (Sıkıştırma)

### Özellikler

- Tanınabilir sabit yok
- Algoritmayı Python'da yazmayı deneyebilir ve çevrimiçi benzer şeyler arayabilirsiniz

### Tanımlama

Grafik oldukça büyük:

![](<../../images/image (207) (2) (1).png>)

Bunu tanımak için **3 karşılaştırmaya** bakın:

![](<../../images/image (384).png>)

{{#include ../../banners/hacktricks-training.md}}
