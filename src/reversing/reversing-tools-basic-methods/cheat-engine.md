# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için yararlı bir programdır.\
İndirdiğinizde ve çalıştırdığınızda, aracı nasıl kullanacağınızı gösteren bir **eğitim** ile **karşılaşırsınız**. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız, bunu tamamlamanız şiddetle tavsiye edilir.

## Ne arıyorsunuz?

![](<../../images/image (762).png>)

Bu araç, bir programın belleğinde **bir değerin** (genellikle bir sayı) **nerede saklandığını** bulmak için çok yararlıdır.\
**Genellikle sayılar** **4bayt** formatında saklanır, ancak bunları **double** veya **float** formatlarında da bulabilirsiniz veya **bir sayıdan farklı** bir şey aramak isteyebilirsiniz. Bu nedenle, neyi **arama** yapmak istediğinizi **seçtiğinizden** emin olmalısınız:

![](<../../images/image (324).png>)

Ayrıca **farklı** türde **arama** seçenekleri de belirtebilirsiniz:

![](<../../images/image (311).png>)

Belleği tararken **oyunu durdurmak için** kutucuğu işaretleyebilirsiniz:

![](<../../images/image (1052).png>)

### Kısayollar

_**Düzenle --> Ayarlar --> Kısayollar**_ bölümünde, **oyunu durdurma** gibi farklı amaçlar için farklı **kısayollar** ayarlayabilirsiniz (bu, belleği taramak istediğinizde oldukça kullanışlıdır). Diğer seçenekler de mevcuttur:

![](<../../images/image (864).png>)

## Değeri değiştirme

Aradığınız **değerin** nerede olduğunu **bulduğunuzda** (bununla ilgili daha fazla bilgi sonraki adımlarda) değeri **değiştirmek için** üzerine çift tıklayarak, ardından değerine çift tıklayarak değiştirebilirsiniz:

![](<../../images/image (563).png>)

Ve son olarak, bellekteki değişikliği gerçekleştirmek için **onay kutusunu işaretleyerek**:

![](<../../images/image (385).png>)

**Bellekteki değişiklik** hemen **uygulanacaktır** (oyun bu değeri tekrar kullanmadığı sürece değer **oyunda güncellenmeyecektir**).

## Değeri arama

Öyleyse, geliştirmek istediğiniz önemli bir değer (kullanıcınızın hayatı gibi) olduğunu varsayıyoruz ve bu değeri bellekte arıyorsunuz.

### Bilinen bir değişim aracılığıyla

100 değerini aradığınızı varsayalım, bu değeri aramak için bir **tarama** gerçekleştiriyorsunuz ve birçok eşleşme buluyorsunuz:

![](<../../images/image (108).png>)

Sonra, **değerin değişmesi için** bir şey yapıyorsunuz ve oyunu **durdurup** **bir sonraki taramayı** gerçekleştiriyorsunuz:

![](<../../images/image (684).png>)

Cheat Engine, **100'den yeni değere** geçen **değerleri** arayacaktır. Tebrikler, aradığınız değerin **adresini buldunuz**, şimdi bunu değiştirebilirsiniz.\
_Eğer hala birkaç değer varsa, o değeri tekrar değiştirmek için bir şey yapın ve adresleri filtrelemek için bir "sonraki tarama" gerçekleştirin._

### Bilinmeyen Değer, bilinen değişim

Değeri **bilmiyorsanız** ama **değişmesini nasıl sağlayacağınızı** biliyorsanız (ve hatta değişim değerini de biliyorsanız) numaranızı arayabilirsiniz.

Öyleyse, "**Bilinmeyen başlangıç değeri**" türünde bir tarama yaparak başlayın:

![](<../../images/image (890).png>)

Sonra, değerin değişmesini sağlayın, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve bir **sonraki tarama** gerçekleştirin:

![](<../../images/image (371).png>)

Seçilen şekilde **değiştirilen tüm değerler** size sunulacaktır:

![](<../../images/image (569).png>)

Değerinizi bulduğunuzda, onu değiştirebilirsiniz.

Birçok **mümkün değişim** olduğunu ve sonuçları filtrelemek için bu **adımları istediğiniz kadar** yapabileceğinizi unutmayın:

![](<../../images/image (574).png>)

### Rastgele Bellek Adresi - Kodu Bulma

Şimdiye kadar bir değeri saklayan bir adres bulmayı öğrendik, ancak **oyunun farklı çalıştırmalarında bu adresin bellekte farklı yerlerde olma olasılığı yüksektir**. Bu nedenle, bu adresi her zaman nasıl bulacağımızı öğrenelim.

Bahsedilen bazı ipuçlarını kullanarak, mevcut oyununuzun önemli değeri sakladığı adresi bulun. Sonra (isterseniz oyunu durdurarak) bulunan **adrese sağ tıklayın** ve "**Bu adrese erişenleri bul**" veya "**Bu adrese yazanları bul**" seçeneğini seçin:

![](<../../images/image (1067).png>)

**İlk seçenek**, bu **adresin** hangi **kod parçaları** tarafından **kullanıldığını** bilmek için yararlıdır (bu, oyunun kodunu **nerede değiştirebileceğinizi** bilmek gibi daha fazla şey için yararlıdır).\
**İkinci seçenek** daha **özeldir** ve bu durumda **değerin nereden yazıldığını** bilmekle ilgilendiğimiz için daha faydalı olacaktır.

Bu seçeneklerden birini seçtiğinizde, **hata ayıklayıcı** programa **bağlanacak** ve yeni bir **boş pencere** açılacaktır. Şimdi, **oyunu oynayın** ve **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren** **adreslerle** **doldurulmalıdır**:

![](<../../images/image (91).png>)

Artık değeri değiştiren adresi bulduğunuza göre, kodu istediğiniz gibi **değiştirebilirsiniz** (Cheat Engine, bunu NOP'lar için hızlıca değiştirmenize izin verir):

![](<../../images/image (1057).png>)

Artık kodu, sayınızı etkilemeyecek şekilde veya her zaman olumlu bir şekilde etkileyecek şekilde değiştirebilirsiniz.

### Rastgele Bellek Adresi - Göstergeleri Bulma

Önceki adımları takip ederek, ilgilendiğiniz değerin nerede olduğunu bulun. Sonra, "**Bu adrese yazanları bul**" seçeneğini kullanarak bu değeri yazan adresi bulun ve üzerine çift tıklayarak ayrıştırma görünümünü alın:

![](<../../images/image (1039).png>)

Sonra, **"\[]"** arasındaki hex değerini aramak için yeni bir tarama gerçekleştirin (bu durumda $edx'in değeri):

![](<../../images/image (994).png>)

(_Birden fazla görünüyorsa genellikle en küçük adres olanı almanız gerekir_)\
Artık, **ilgilendiğimiz değeri değiştirecek göstericiyi bulduk**.

"**Adres Ekle**" seçeneğine tıklayın:

![](<../../images/image (990).png>)

Şimdi, "Gösterici" onay kutusuna tıklayın ve metin kutusuna bulunan adresi ekleyin (bu senaryoda, önceki resimde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![](<../../images/image (392).png>)

(İlk "Adresin", girdiğiniz gösterici adresinden otomatik olarak doldurulduğuna dikkat edin)

Tamam'a tıklayın ve yeni bir gösterici oluşturulacaktır:

![](<../../images/image (308).png>)

Artık, o değeri değiştirdiğinizde, değerin bulunduğu bellek adresi farklı olsa bile **önemli değeri değiştiriyorsunuz**.

### Kod Enjeksiyonu

Kod enjeksiyonu, hedef işleme bir kod parçası enjekte etme tekniğidir ve ardından kodun yürütülmesini kendi yazdığınız koddan geçirecek şekilde yönlendirme yapar (örneğin, puan vermek yerine puan düşürmek).

Öyleyse, oyuncunuzun hayatından 1 çıkaran adresi bulduğunuzu hayal edin:

![](<../../images/image (203).png>)

**Ayrıştırıcı kodu** almak için Ayrıştırıcıyı göster'e tıklayın.\
Sonra, **CTRL+a** tuşlarına basarak Otomatik derleme penceresini açın ve _**Şablon --> Kod Enjeksiyonu**_ seçeneğini seçin:

![](<../../images/image (902).png>)

Değiştirmek istediğiniz **talimatın adresini** doldurun (bu genellikle otomatik olarak doldurulur):

![](<../../images/image (744).png>)

Bir şablon oluşturulacaktır:

![](<../../images/image (944).png>)

Bu nedenle, yeni assembly kodunuzu "**newmem**" bölümüne ekleyin ve orijinal kodu "**originalcode**" bölümünden kaldırın, eğer çalıştırılmasını istemiyorsanız. Bu örnekte, enjekte edilen kod 1 çıkarmak yerine 2 puan ekleyecektir:

![](<../../images/image (521).png>)

**Uygula'ya tıklayın ve kodunuz programda enjekte edilerek işlevselliğin davranışını değiştirmelidir!**

## Cheat Engine 7.x (2023-2025) Gelişmiş Özellikler

Cheat Engine, 7.0 sürümünden bu yana gelişmeye devam etti ve modern yazılımları (sadece oyunları değil!) analiz ederken son derece kullanışlı olan birçok yaşam kalitesi ve *saldırgan tersine mühendislik* özelliği eklendi. Aşağıda, kırmızı takım/CTF çalışmaları sırasında en muhtemel kullanacağınız eklemelere dair **çok yoğun bir saha kılavuzu** bulunmaktadır.

### Göstergeler Tarayıcı 2 iyileştirmeleri
* `Göstergeler belirli ofsetlerle bitmelidir` ve yeni **Sapma** kaydırıcı (≥7.4), bir güncellemeden sonra yeniden tarama yaptığınızda yanlış pozitifleri büyük ölçüde azaltır. Bunu çoklu harita karşılaştırmasıyla birlikte kullanarak (`.PTR` → *Diğer kaydedilmiş gösterici haritasıyla sonuçları karşılaştır*) sadece birkaç dakikada **tek bir dayanıklı temel gösterici** elde edebilirsiniz.
* Toplu filtre kısayolu: ilk taramadan sonra `Ctrl+A → Boşluk` tuşlarına basarak her şeyi işaretleyin, ardından `Ctrl+I` (ters) tuşuna basarak yeniden taramayı geçemeyen adresleri seçimi kaldırın.

### Ultimap 3 – Intel PT izleme
*7.5'ten itibaren eski Ultimap, **Intel İşlemci İzleme (IPT)** üzerine yeniden uygulanmıştır. Bu, artık hedefin aldığı **her** dalı **tek adım atma olmadan** kaydedebileceğiniz anlamına gelir (sadece kullanıcı modu, çoğu anti-hata ayıklama cihazını tetiklemez).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Birkaç saniye sonra yakalamayı durdurun ve **sağ tıklayın → Çalıştırma listesini dosyaya kaydet**. Yüksek frekanslı oyun mantığı sıcak noktalarını çok hızlı bir şekilde bulmak için dal adreslerini `Bu talimat hangi adreslere erişiyor bul` oturumu ile birleştirin.

### 1-byte `jmp` / otomatik yamanma şablonları
Versiyon 7.5, bir SEH işleyicisi kuran ve orijinal konumda bir INT3 yerleştiren *bir baytlık* JMP stub'ı (0xEB) tanıttı. 5 baytlık göreli atlama ile yamanamayan talimatlar üzerinde **Otomatik Montajcı → Şablon → Kod Enjeksiyonu** kullandığınızda otomatik olarak üretilir. Bu, paketlenmiş veya boyut kısıtlı rutinler içinde “sıkı” kancaların mümkün olmasını sağlar.

### Kernel düzeyinde gizlilik ile DBVM (AMD & Intel)
*DBVM*, CE’nin yerleşik Tip-2 hipervizörüdür. Son sürümler nihayet **AMD-V/SVM desteği** ekledi, böylece Ryzen/EPYC ana bilgisayarlarda `Sürücü → DBVM Yükle` çalıştırabilirsiniz. DBVM ile:
1. Ring-3/anti-debug kontrollerine görünmez donanım kesme noktaları oluşturabilirsiniz.
2. Kullanıcı modu sürücüsü devre dışı olsa bile sayfalı veya korumalı çekirdek bellek bölgelerini okuyup yazabilirsiniz.
3. VM-EXIT'siz zamanlama saldırısı atlamaları gerçekleştirebilirsiniz (örneğin, hipervizörden `rdtsc` sorgulamak).

**İpucu:** DBVM, Windows 11'de HVCI/Bellek Bütünlüğü etkin olduğunda yüklemeyi reddedecektir → kapatın veya özel bir VM ana bilgisayarına önyükleme yapın.

### Uzaktan / çapraz platform hata ayıklama ile **ceserver**
CE artık *ceserver*'ın tam bir yeniden yazımını gönderiyor ve **Linux, Android, macOS & iOS** hedeflerine TCP üzerinden bağlanabiliyor. Popüler bir çatal, dinamik enstrümantasyonu CE’nin GUI'si ile birleştirmek için *Frida*'yı entegre ediyor – bir telefonda çalışan Unity veya Unreal oyunlarını yamanmanız gerektiğinde ideal:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida köprüsü için GitHub'da `bb33bb/frida-ceserver`'a bakın.

### Diğer dikkate değer araçlar
* **Patch Scanner** (MemView → Tools) – yürütülebilir bölümlerde beklenmedik kod değişikliklerini tespit eder; kötü amaçlı yazılım analizi için kullanışlıdır.
* **Structure Dissector 2** – bir adres sürükleyin → `Ctrl+D`, ardından *Guess fields* ile C-yapılarını otomatik olarak değerlendirin.
* **.NET & Mono Dissector** – geliştirilmiş Unity oyun desteği; yöntemleri doğrudan CE Lua konsolundan çağırın.
* **Big-Endian özel türler** – tersine çevrilmiş bayt sırası tarama/düzenleme (konsol emülatörleri ve ağ paket tamponları için yararlıdır).
* **Autosave & sekmeler** AutoAssembler/Lua pencereleri için, ayrıca çok satırlı talimat yeniden yazımı için `reassemble()`.

### Kurulum & OPSEC notları (2024-2025)
* Resmi yükleyici, InnoSetup **reklam teklifleri** (`RAV` vb.) ile sarılmıştır. **Her zaman *Reddet* butonuna tıklayın** *veya kaynak kodundan derleyin* PUP'lerden kaçınmak için. AV'ler hala `cheatengine.exe`'yi *HackTool* olarak işaretleyecektir, bu beklenmektedir.
* Modern anti-hile sürücüleri (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) CE’nin pencere sınıfını yeniden adlandırılsa bile tespit eder. Tersine çevirme kopyanızı **tek kullanımlık bir VM içinde** veya ağ oyununu devre dışı bıraktıktan sonra çalıştırın.
* Sadece kullanıcı modu erişimine ihtiyacınız varsa **`Settings → Extra → Kernel mode debug = off`** seçeneğini seçin, bu CE’nin imzasız sürücüsünü yüklemekten kaçınmak için, bu Windows 11 24H2 Secure-Boot'ta BSOD'ya neden olabilir.

---

## **Referanslar**

- [Cheat Engine 7.5 sürüm notları (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver çoklu platform köprüsü](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine eğitimi, Cheat Engine ile nasıl başlayacağınızı öğrenmek için tamamlayın**

{{#include ../../banners/hacktricks-training.md}}
