# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için yararlı bir programdır.\
İndirdiğinizde ve çalıştırdığınızda, aracı nasıl kullanacağınızı gösteren bir **eğitim** ile **karşılaşırsınız**. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız, bunu tamamlamanız şiddetle tavsiye edilir.

## Ne arıyorsunuz?

![](<../../images/image (762).png>)

Bu araç, bir programın belleğinde **bir değerin** (genellikle bir sayı) **nerede saklandığını** bulmak için çok yararlıdır.\
**Genellikle sayılar** **4byte** formatında saklanır, ancak bunları **double** veya **float** formatlarında da bulabilirsiniz veya **bir sayıdan farklı bir şey** aramak isteyebilirsiniz. Bu nedenle, neyi **arama** yapmak istediğinizi **seçtiğinizden** emin olmalısınız:

![](<../../images/image (324).png>)

Ayrıca **farklı** türde **arama** seçenekleri de belirtebilirsiniz:

![](<../../images/image (311).png>)

Belleği tararken **oyunu durdurmak için** kutucuğu işaretleyebilirsiniz:

![](<../../images/image (1052).png>)

### Kısayollar

_**Düzenle --> Ayarlar --> Kısayollar**_ bölümünde, **oyunu durdurma** gibi farklı amaçlar için farklı **kısayollar** ayarlayabilirsiniz (bu, belleği taramak istediğinizde oldukça kullanışlıdır). Diğer seçenekler de mevcuttur:

![](<../../images/image (864).png>)

## Değeri Değiştirme

Aradığınız **değerin** nerede olduğunu **bulduğunuzda** (bununla ilgili daha fazla bilgi sonraki adımlarda) üzerine çift tıklayarak **değiştirebilirsiniz**, ardından değerine çift tıklayın:

![](<../../images/image (563).png>)

Ve son olarak, bellekteki değişikliği gerçekleştirmek için **onay kutusunu işaretleyin**:

![](<../../images/image (385).png>)

**Bellekteki değişiklik** hemen **uygulanacaktır** (oyun bu değeri tekrar kullanmadığı sürece değer **oyunda güncellenmeyecektir**).

## Değeri Arama

Öyleyse, geliştirmek istediğiniz önemli bir değer (kullanıcınızın hayatı gibi) olduğunu varsayıyoruz ve bu değeri bellekte arıyorsunuz.

### Bilinen bir değişim yoluyla

100 değerini aradığınızı varsayalım, bu değeri aramak için bir **tarama** yapıyorsunuz ve birçok eşleşme buluyorsunuz:

![](<../../images/image (108).png>)

Sonra, **değerin değişmesi için** bir şey yapıyorsunuz ve oyunu **durdurup** **bir sonraki taramayı** yapıyorsunuz:

![](<../../images/image (684).png>)

Cheat Engine, **100'den yeni değere** geçen **değerleri** arayacaktır. Tebrikler, aradığınız değerin **adresini buldunuz**, şimdi bunu değiştirebilirsiniz.\
_Eğer hala birkaç değer varsa, o değeri tekrar değiştirmek için bir şey yapın ve adresleri filtrelemek için bir "sonraki tarama" yapın._

### Bilinmeyen Değer, bilinen değişim

Değeri **bilmediğiniz** ancak **değişmesini nasıl sağlayacağınızı** bildiğiniz (ve hatta değişim değerini) bir senaryoda, numaranızı arayabilirsiniz.

Öyleyse, "**Bilinmeyen başlangıç değeri**" türünde bir tarama yaparak başlayın:

![](<../../images/image (890).png>)

Sonra, değerin değişmesini sağlayın, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve **bir sonraki taramayı** yapın:

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
**İkinci seçenek** daha **özeldir** ve bu durumda, **bu değerin nereden yazıldığını** bilmekle ilgilendiğimiz için daha faydalı olacaktır.

Bu seçeneklerden birini seçtiğinizde, **hata ayıklayıcı** programa **bağlanacak** ve yeni bir **boş pencere** açılacaktır. Şimdi, **oyunu oynayın** ve **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren** **adreslerle** **doldurulmalıdır**:

![](<../../images/image (91).png>)

Artık değeri değiştiren adresi bulduğunuza göre, kodu istediğiniz gibi **değiştirebilirsiniz** (Cheat Engine, bunu NOP'lar için hızlıca değiştirmenize izin verir):

![](<../../images/image (1057).png>)

Artık kodu, sayınızı etkilemeyecek şekilde veya her zaman olumlu bir şekilde etkileyecek şekilde değiştirebilirsiniz.

### Rastgele Bellek Adresi - Pointer Bulma

Önceki adımları takip ederek, ilgilendiğiniz değerin nerede olduğunu bulun. Sonra, "**Bu adrese yazanları bul**" seçeneğini kullanarak bu değeri yazan adresi bulun ve üzerine çift tıklayarak ayrıştırma görünümünü alın:

![](<../../images/image (1039).png>)

Sonra, **"\[]"** arasındaki hex değerini aramak için yeni bir tarama yapın (bu durumda $edx'in değeri):

![](<../../images/image (994).png>)

(_Birden fazla görünüyorsa genellikle en küçük adres olanı almanız gerekir_)\
Artık **ilgilendiğimiz değeri değiştirecek pointer'ı bulduk**.

"**Adresi Manuel Olarak Ekle**" seçeneğine tıklayın:

![](<../../images/image (990).png>)

Şimdi, "Pointer" onay kutusuna tıklayın ve metin kutusuna bulunan adresi ekleyin (bu senaryoda, önceki resimde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![](<../../images/image (392).png>)

(İlk "Adres"in, girdiğiniz pointer adresinden otomatik olarak doldurulduğuna dikkat edin)

Tamam'a tıklayın ve yeni bir pointer oluşturulacaktır:

![](<../../images/image (308).png>)

Artık o değeri her değiştirdiğinizde, **değerin bulunduğu bellek adresi farklı olsa bile önemli değeri değiştiriyorsunuz.**

### Kod Enjeksiyonu

Kod enjeksiyonu, hedef işleme bir kod parçası enjekte etme ve ardından kodun yürütülmesini kendi yazdığınız koddan geçirecek şekilde yönlendirme tekniğidir (örneğin, size puan vermek yerine puan almanızı sağlamak).

Öyleyse, oyuncunuzun hayatından 1 çıkaran adresi bulduğunuzu hayal edin:

![](<../../images/image (203).png>)

**Dizilimi göster** seçeneğine tıklayarak **dizilim kodunu** alın.\
Sonra, **CTRL+a** tuşlarına basarak Otomatik dizilim penceresini açın ve _**Şablon --> Kod Enjeksiyonu**_ seçeneğini seçin:

![](<../../images/image (902).png>)

**Değiştirmek istediğiniz talimatın adresini** doldurun (bu genellikle otomatik olarak doldurulur):

![](<../../images/image (744).png>)

Bir şablon oluşturulacaktır:

![](<../../images/image (944).png>)

Bu nedenle, yeni assembly kodunuzu "**newmem**" bölümüne ekleyin ve **çalıştırılmasını istemiyorsanız** "**originalcode**" bölümündeki orijinal kodu kaldırın. Bu örnekte, enjekte edilen kod 1 çıkarmak yerine 2 puan ekleyecektir:

![](<../../images/image (521).png>)

**Uygula'ya tıklayın ve kodunuz programda enjekte edilerek işlevselliğin davranışını değiştirmelidir!**

## **Referanslar**

- **Cheat Engine eğitimi, Cheat Engine ile başlamayı öğrenmek için tamamlayın**

{{#include ../../banners/hacktricks-training.md}}
