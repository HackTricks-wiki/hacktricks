# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır.\
İndirip çalıştırdığınızda, araçla nasıl kullanılacağına dair bir **tutorial** ile karşılaşırsınız. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız bunu tamamlamanız kesinlikle önerilir.

## Ne arıyorsunuz?

![Cheat Engine - Ne arıyorsunuz?: Ne arıyorsunuz?](<../../images/image (762).png>)

Bu araç, bir programın **belleğinde bazı değerlerin** (genellikle bir sayının) **nerede saklandığını** bulmak için oldukça kullanışlıdır.\
**Sayılar genellikle** **4bytes** biçiminde saklanır; ancak bunları **double** veya **float** formatlarında da bulabilirsiniz ya da **sayıdan farklı** bir şey aramak isteyebilirsiniz. Bu nedenle **aramak istediğiniz şeyi** **seçtiğinizden** emin olmanız gerekir:

![Cheat Engine - Ne arıyorsunuz?: Sayılar genellikle 4bytes biçiminde saklanır; ancak double veya float formatlarında da bulunabilirler ya da farklı bir şey aramak isteyebilirsiniz...](<../../images/image (324).png>)

Ayrıca farklı **arama** türlerini de belirtebilirsiniz:

![Cheat Engine - Ne arıyorsunuz?: Ayrıca farklı arama türlerini de belirtebilirsiniz](<../../images/image (311).png>)

Bellek taranırken **oyunu durdurmak** için kutuyu işaretleyebilirsiniz:

![Cheat Engine - Ne arıyorsunuz?: Bellek taranırken oyunu durdurmak için kutuyu da işaretleyebilirsiniz](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ bölümünde, **oyunu durdurmak** gibi farklı amaçlar için farklı **hotkeys** ayarlayabilirsiniz (bu, özellikle bir noktada belleği taramak istediğinizde oldukça kullanışlıdır). Başka seçenekler de mevcuttur:

![Ne arıyorsunuz? - Hotkeys: Edit -- Settings -- Hotkeys bölümünde, oyunu durdurmak gibi farklı amaçlar için farklı hotkeys ayarlayabilirsiniz (bu, özellikle bir noktada...](<../../images/image (864).png>)

## Değeri değiştirme

Aradığınız **değerin** nerede olduğunu **bulduktan** sonra (bununla ilgili daha fazla bilgi aşağıdaki adımlardadır), değere çift tıklayıp ardından değerinin üzerine çift tıklayarak **değiştirebilirsiniz**:

![Hotkeys - Değeri değiştirme: Aradığınız değerin nerede olduğunu bulduktan sonra (bununla ilgili daha fazla bilgi aşağıdaki adımlardadır), değere çift tıklayıp ardından değerinin üzerine çift tıklayarak...](<../../images/image (563).png>)

Son olarak, değişikliğin bellekte uygulanması için **onay kutusunu işaretleyin**:

![Hotkeys - Değeri değiştirme: Son olarak, değişikliğin bellekte uygulanması için onay kutusunu işaretleyin](<../../images/image (385).png>)

**Bellekteki** **değişiklik** hemen **uygulanır** (oyun bu değeri tekrar kullanana kadar değerin **oyunda güncellenmeyeceğini** unutmayın).

## Değeri arama

Şimdi, geliştirmek istediğiniz önemli bir değer (örneğin kullanıcınızın canı) olduğunu ve bu değeri bellekte aradığınızı varsayalım.

### Bilinen bir değişiklik üzerinden

100 değerini aradığınızı varsayalım. Bu değeri arayan bir **tarama gerçekleştirirsiniz** ve birçok eşleşme bulursunuz:

![Değeri arama - Bilinen bir değişiklik üzerinden: 100 değerini aradığınızı varsayalım. Bu değeri arayan bir tarama gerçekleştirirsiniz ve birçok eşleşme bulursunuz](<../../images/image (108).png>)

Ardından **değerin değişmesini** sağlayacak bir şey yapar, oyunu **durdurur** ve bir **sonraki taramayı** gerçekleştirirsiniz:

![Değeri arama - Bilinen bir değişiklik üzerinden: Ardından değerin değişmesini sağlayacak bir şey yapar, oyunu durdurur ve bir sonraki taramayı gerçekleştirirsiniz](<../../images/image (684).png>)

Cheat Engine, **100'den yeni değere geçen değerleri** arar. Tebrikler, aradığınız değerin **adresini** **buldunuz**; artık onu değiştirebilirsiniz.\
_Hâlâ birden fazla değer varsa, ilgili değeri tekrar değiştirecek bir şey yapın ve adresleri filtrelemek için başka bir "next scan" gerçekleştirin._

### Bilinmeyen değer, bilinen değişiklik

**Değeri bilmediğiniz**, ancak **onu nasıl değiştireceğinizi** (hatta değişimin miktarını) bildiğiniz senaryolarda sayınızı arayabilirsiniz.

Öncelikle "**Unknown initial value**" türünde bir tarama gerçekleştirin:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Öncelikle " Unknown initial value " türünde bir tarama gerçekleştirin](<../../images/image (890).png>)

Ardından değeri değiştirin, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve bir **sonraki taramayı** gerçekleştirin:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Ardından değeri değiştirin, değerin nasıl değiştiğini belirtin (benim durumumda 1 azaldı) ve bir sonraki taramayı gerçekleştirin](<../../images/image (371).png>)

Seçtiğiniz şekilde değiştirilen **tüm değerler** size gösterilir:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Seçtiğiniz şekilde değiştirilen tüm değerler size gösterilir](<../../images/image (569).png>)

Değerinizi bulduktan sonra onu değiştirebilirsiniz.

Birçok **olası değişiklik** olduğunu ve sonuçları filtrelemek için bu **adımları** istediğiniz kadar tekrarlayabileceğinizi unutmayın:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Birçok olası değişiklik olduğunu ve sonuçları filtrelemek için bu adımları istediğiniz kadar tekrarlayabileceğinizi unutmayın](<../../images/image (574).png>)

### Rastgele bellek adresi - Kodu bulma

Şimdiye kadar bir değeri saklayan adresi nasıl bulacağımızı öğrendik; ancak oyunun **farklı çalıştırmalarında bu adresin belleğin farklı yerlerinde bulunması** oldukça olasıdır. Şimdi bu adresi her zaman nasıl bulacağımıza bakalım.

Bahsedilen yöntemlerden bazılarını kullanarak, mevcut oyununuzun önemli değeri sakladığı adresi bulun. Ardından (isterseniz oyunu durdurarak) bulunan **adrese** **sağ tıklayın** ve "**Find out what accesses this address**" veya "**Find out what writes to this address**" seçeneğini seçin:

![Bilinmeyen değer, bilinen değişiklik - Rastgele bellek adresi - Kodu bulma: Bahsedilen yöntemlerden bazılarını kullanarak, mevcut oyununuzun önemli değeri sakladığı adresi bulun. Ardından...](<../../images/image (1067).png>)

**İlk seçenek**, bu **adresi kullanan kodun hangi bölümlerinin** bulunduğunu öğrenmek için kullanışlıdır (oyunun **kodunu nerede değiştirebileceğinizi öğrenmek** gibi başka amaçlar için de yararlıdır).\
**İkinci seçenek** daha **özeldir** ve bu durumda daha faydalı olacaktır; çünkü bu değerin **nereden yazıldığını** öğrenmek istiyoruz.

Bu seçeneklerden birini seçtiğinizde **debugger** programa **eklenir** ve yeni bir **boş pencere** açılır. Şimdi **oyunu oynayın** ve bu **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren adreslerle** doldurulmalıdır:

![Bilinmeyen değer, bilinen değişiklik - Rastgele bellek adresi - Kodu bulma: Bu seçeneklerden birini seçtiğinizde debugger programa eklenecek ve yeni bir boş pencere açılacaktır...](<../../images/image (91).png>)

Değeri değiştiren adresi artık bulduğunuza göre **kodu istediğiniz şekilde değiştirebilirsiniz** (Cheat Engine, bunu NOP'lar için çok hızlı biçimde yapmanıza izin verir):

![Bilinmeyen değer, bilinen değişiklik - Rastgele bellek adresi - Kodu bulma: Değeri değiştiren adresi artık bulduğunuza göre kodu istediğiniz şekilde değiştirebilirsiniz (Cheat Engine...](<../../images/image (1057).png>)

Artık kodu, sayınızı etkilemeyecek veya her zaman olumlu yönde etkileyecek şekilde değiştirebilirsiniz.

### Rastgele bellek adresi - Pointer'ı bulma

Önceki adımları izleyerek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından "**Find out what writes to this address**" seçeneğini kullanarak bu değeri hangi adresin yazdığını bulun ve disassembly görünümünü açmak için üzerine çift tıklayın:

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: Önceki adımları izleyerek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından " Find out...](<../../images/image (1039).png>)

Ardından, **"\[]"** arasındaki hex değerini arayan yeni bir tarama gerçekleştirin (bu durumda $edx değeri):

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: Ardından, " ()" arasındaki hex değerini arayan yeni bir tarama gerçekleştirin (bu durumda $edx değeri)](<../../images/image (994).png>)

(_Birden fazla sonuç çıkarsa genellikle en küçük adresi kullanmanız gerekir_)\
Artık ilgilendiğimiz değeri değiştirecek **pointer'ı bulduk**.

"**Add Address Manually**" seçeneğine tıklayın:

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: " Add Address Manually " seçeneğine tıklayın](<../../images/image (990).png>)

Şimdi "Pointer" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda, önceki görselde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: Şimdi "Pointer" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda,...](<../../images/image (392).png>)

(Girdiğiniz pointer adresinden ilk "Address"in otomatik olarak doldurulduğuna dikkat edin.)

OK'e tıklayın; yeni bir pointer oluşturulur:

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: OK'e tıklayın; yeni bir pointer oluşturulur](<../../images/image (308).png>)

Artık bu değeri her değiştirdiğinizde, değerin bulunduğu bellek adresi farklı olsa bile **önemli değeri değiştirmiş olursunuz**.

### Code Injection

Code injection, hedef sürece bir kod parçası enjekte ettiğiniz ve ardından kodun yürütülmesini kendi yazdığınız koddan geçecek şekilde yönlendirdiğiniz bir tekniktir (örneğin puanlarınızı azaltmak yerine artırmak).

Örneğin, oyuncunuzun canından 1 çıkaran adresi bulduğunuzu varsayalım:

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Oyuncunuzun canından 1 çıkaran adresi bulduğunuzu varsayalım](<../../images/image (203).png>)

**Disassemble code** elde etmek için Show disassembler'a tıklayın.\
Ardından Auto assemble penceresini açmak için **CTRL+a** tuşlarına basın ve _**Template --> Code Injection**_ seçeneğini belirleyin.

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Auto assemble penceresini açmak için CTRL+a tuşlarına basın ve Template -- Code Injection seçeneğini belirleyin](<../../images/image (902).png>)

**Değiştirmek istediğiniz instruction'ın adresini** girin (bu genellikle otomatik olarak doldurulur):

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Değiştirmek istediğiniz instruction'ın adresini girin (bu genellikle otomatik olarak doldurulur)](<../../images/image (744).png>)

Bir template oluşturulur:

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Bir template oluşturulur](<../../images/image (944).png>)

Şimdi yeni assembly kodunuzu "**newmem**" bölümüne ekleyin ve yürütülmesini istemiyorsanız özgün kodu "**originalcode**" bölümünden kaldırın**.** Bu örnekte enjekte edilen kod, 1 çıkarmak yerine 2 puan ekleyecektir:

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Şimdi yeni assembly kodunuzu " newmem " bölümüne ekleyin ve yürütülmesini istemiyorsanız özgün kodu " originalcode " bölümünden kaldırın...](<../../images/image (521).png>)

**Execute'a ve devamındaki seçeneklere tıklayın; kodunuz programa enjekte edilerek işlevin davranışını değiştirmelidir!**

## Cheat Engine 7.x'teki gelişmiş özellikler (2023-2025)

Cheat Engine, 7.0 sürümünden bu yana gelişmeye devam etti ve modern software'i (yalnızca oyunları değil!) analiz ederken son derece kullanışlı olan çeşitli quality-of-life ve *offensive-reversing* özellikleri eklendi. Aşağıda, red-team/CTF çalışmaları sırasında büyük olasılıkla kullanacağınız eklemelere ilişkin **çok kısa bir saha kılavuzu** yer almaktadır.<sup>[[1]](#references)</sup>

### Pointer Scanner 2 iyileştirmeleri
* `Pointers must end with specific offsets` ve yeni **Deviation** slider'ı (≥7.4), bir güncellemeden sonra yeniden tarama yaptığınızda false positive sonuçlarını büyük ölçüde azaltır. Bunu multi-map karşılaştırmasıyla (`.PTR` → *Compare results with other saved pointer map*) birlikte kullanarak yalnızca birkaç dakika içinde **dayanıklı tek bir base-pointer** elde edebilirsiniz.
* Toplu filtreleme kısayolu: İlk taramadan sonra her şeyi işaretlemek için `Ctrl+A → Space` tuşlarına basın; ardından yeniden taramada başarısız olan adreslerin seçimini kaldırmak için `Ctrl+I` tuşlarına basın.

### Ultimap 3 – Intel PT tracing
*7.5 sürümünden itibaren eski Ultimap, **Intel Processor-Trace (IPT)** üzerine yeniden uygulanmıştır.* Bu, hedefin aldığı **her branch'i**, **single-stepping** yapmadan kaydedebileceğiniz anlamına gelir (yalnızca user-mode; çoğu anti-debug gadget'ını tetiklemez).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Birkaç saniye sonra yakalamayı durdurun ve **right-click → Save execution list to file** seçeneğini kullanın. Dal adreslerini bir `Find out what addresses this instruction accesses` oturumuyla birleştirerek yüksek frekanslı oyun mantığı hotspot'larını son derece hızlı bir şekilde bulun.

### 1-byte `jmp` / auto-patch şablonları
Version 7.5, bir SEH handler yükleyen ve orijinal konuma bir INT3 yerleştiren *one-byte* JMP stub'ı (0xEB) kullanıma sundu. Bu stub, 5-byte relative jump ile patch uygulanamayan talimatlarda **Auto Assembler → Template → Code Injection** kullandığınızda otomatik olarak oluşturulur. Böylece packed veya boyut kısıtlamalı rutinlerin içinde “tight” hook'lar oluşturmak mümkün olur.<sup>[[1]](#references)</sup>

### DBVM ile kernel-level stealth (AMD ve Intel)
*DBVM*, CE'nin yerleşik Type-2 hypervisor'ıdır. Güncel build'ler nihayet **AMD-V/SVM support** ekledi; böylece Ryzen/EPYC host'larında `Driver → Load DBVM` çalıştırabilirsiniz. DBVM şunları yapmanızı sağlar:
1. Ring-3/anti-debug kontrollerinden gizlenen hardware breakpoint'ler oluşturmak.
2. User-mode driver devre dışı olsa bile pageable veya korumalı kernel memory bölgelerini okumak/yazmak.
3. VM-EXIT-less timing-attack bypass'ları gerçekleştirmek (ör. hypervisor'dan `rdtsc` sorgulamak).

**İpucu:** Windows 11'de HVCI/Memory-Integrity etkin olduğunda DBVM yüklenmeyi reddeder → bunu devre dışı bırakın veya özel bir VM-host ile boot edin.

### **ceserver** ile remote / cross-platform debugging
CE artık *ceserver*'ın tamamen yeniden yazılmış bir sürümüyle birlikte geliyor ve **Linux, Android, macOS ve iOS** hedeflerine TCP üzerinden attach olabilir. Popüler bir fork, *Frida*'yı CE'nin GUI'siyle birleştirir; bu, telefonda çalışan Unity veya Unreal oyunlarına patch uygulamanız gerektiğinde idealdir:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridge için GitHub'da `bb33bb/frida-ceserver` adresine bakın.<sup>[[1]](#references)[[2]](#references)</sup>

### Dikkate değer diğer özellikler
* **Patch Scanner** (MemView → Tools) – executable sections içindeki beklenmeyen code değişikliklerini algılar; malware analysis için kullanışlıdır.
* **Structure Dissector 2** – bir adrese sürükleyin → `Ctrl+D`, ardından C-structures'ı otomatik olarak değerlendirmek için *Guess fields* seçeneğini kullanın.
* **.NET & Mono Dissector** – geliştirilmiş Unity game desteği; method'ları doğrudan CE Lua console üzerinden çağırın.
* **Big-Endian custom types** – ters çevrilmiş byte order tarama/düzenleme (console emulator'ları ve network packet buffer'ları için kullanışlıdır).
* AutoAssembler/Lua window'ları için **Autosave & tabs** ve çok satırlı instruction yeniden yazımı için `reassemble()`.<sup>[[1]](#references)</sup>

### Installation ve OPSEC notları (2024-2025)
* Resmi installer, InnoSetup **ad-offers** (`RAV` vb.) ile paketlenmiştir. PUP'ları önlemek için **her zaman *Decline* seçeneğine tıklayın** *veya source code'dan compile edin*. AV'ler `cheatengine.exe` dosyasını beklenen bir durum olarak *HackTool* şeklinde işaretlemeye devam eder.
* Modern anti-cheat driver'ları (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys), yeniden adlandırıldığında bile CE'nin window class'ını algılar. Reversing kopyanızı **disposable VM içinde** veya network play'i devre dışı bıraktıktan sonra çalıştırın.
* Yalnızca user-mode access'e ihtiyacınız varsa, Windows 11 24H2 Secure-Boot'ta BSOD'a neden olabilecek CE unsigned driver'ının yüklenmesini önlemek için **`Settings → Extra → Kernel mode debug = off`** seçeneğini kullanın.

---

## Kaynaklar

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
