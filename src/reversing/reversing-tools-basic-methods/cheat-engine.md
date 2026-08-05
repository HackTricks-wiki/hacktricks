# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır.\
Programı indirip çalıştırdığınızda, araçla nasıl kullanılacağını anlatan bir **tutorial** ile karşılaşırsınız. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız bunu tamamlamanız kesinlikle önerilir.<sup>[[3]](#references)</sup>

## Neyi arıyorsunuz?

![Cheat Engine - Neyi arıyorsunuz?: Neyi arıyorsunuz?](<../../images/image (762).png>)

Bu araç, bir programın belleğinde **bir değerin** (genellikle bir sayının) **nerede saklandığını** bulmak için çok kullanışlıdır.\
**Sayılar genellikle** **4bytes** biçiminde saklanır, ancak bunları **double** veya **float** formatlarında da bulabilirsiniz ya da **sayıdan farklı** bir şey aramak isteyebilirsiniz. Bu nedenle **aramak** istediğiniz şeyi **seçtiğinizden** emin olmanız gerekir:

![Cheat Engine - Neyi arıyorsunuz?: Sayılar genellikle 4bytes biçiminde saklanır, ancak bunları double veya float formatlarında da bulabilirsiniz ya da farklı bir şey aramak isteyebilirsiniz...](<../../images/image (324).png>)

Ayrıca **farklı** **arama** türlerini belirtebilirsiniz:

![Cheat Engine - Neyi arıyorsunuz?: Ayrıca farklı arama türlerini belirtebilirsiniz](<../../images/image (311).png>)

Belleği tararken **oyunu durdurmak** için kutuyu da işaretleyebilirsiniz:

![Cheat Engine - Neyi arıyorsunuz?: Belleği tararken oyunu durdurmak için kutuyu da işaretleyebilirsiniz](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ bölümünde, **oyunu durdurmak** gibi farklı amaçlar için farklı **hotkeys** ayarlayabilirsiniz (bu, bazı durumlarda belleği taramak istediğinizde oldukça kullanışlıdır). Başka seçenekler de mevcuttur:

![Neyi arıyorsunuz? - Hotkeys: Edit -- Settings -- Hotkeys bölümünde, oyunu durdurmak gibi farklı amaçlar için farklı hotkeys ayarlayabilirsiniz (bu, bazı durumlarda...](<../../images/image (864).png>)

## Değeri değiştirme

Aradığınız **değerin** nerede olduğunu **bulduğunuzda** (bununla ilgili daha fazla bilgi aşağıdaki adımlardadır), değere çift tıklayıp ardından değerinin üzerine çift tıklayarak **değiştirebilirsiniz**:

![Hotkeys - Değeri değiştirme: Aradığınız değerin nerede olduğunu bulduğunuzda (bununla ilgili daha fazla bilgi aşağıdaki adımlardadır), değere çift tıklayıp ardından...](<../../images/image (563).png>)

Son olarak, bellekte değişikliği gerçekleştirmek için **işaretleme kutusunu** seçin:

![Hotkeys - Değeri değiştirme: Son olarak, bellekte değişikliği gerçekleştirmek için işaretleme kutusunu seçin](<../../images/image (385).png>)

**Bellekteki** **değişiklik** hemen **uygulanır** (oyun bu değeri tekrar kullanana kadar değerin **oyunda güncellenmeyeceğini** unutmayın).

## Değeri arama

Önemli bir değeri (kullanıcınızın canı gibi) artırmak istediğinizi ve bu değeri bellekte aradığınızı varsayalım.

### Bilinen bir değişiklik üzerinden

100 değerini aradığınızı varsayalım. Bu değeri aramak için bir **scan gerçekleştirirsiniz** ve birçok eşleşme bulursunuz:

![Değeri arama - Bilinen bir değişiklik üzerinden: 100 değerini aradığınızı varsayalım. Bu değeri aramak için bir scan gerçekleştirirsiniz ve birçok eşleşme bulursunuz](<../../images/image (108).png>)

Ardından **değerin değişmesini** sağlayacak bir işlem yapar, oyunu **durdurur** ve bir **next scan gerçekleştirirsiniz**:

![Değeri arama - Bilinen bir değişiklik üzerinden: Ardından değerin değişmesini sağlayacak bir işlem yapar, oyunu durdurur ve bir next scan gerçekleştirirsiniz](<../../images/image (684).png>)

Cheat Engine, **100'den yeni değere değişen** **değerleri** arar. Tebrikler, aradığınız değerin **adresini** **buldunuz**; artık değeri değiştirebilirsiniz.\
_Hâlâ birden fazla değer varsa, bu değeri tekrar değiştirecek bir işlem yapın ve adresleri filtrelemek için başka bir "next scan" gerçekleştirin._

### Bilinmeyen Değer, bilinen değişiklik

**Değeri bilmediğiniz**, ancak **değişmesini nasıl sağlayacağınızı** (hatta değişimin miktarını) bildiğiniz senaryolarda sayınızı arayabilirsiniz.

Öncelikle "**Unknown initial value**" türünde bir scan gerçekleştirin:

![Bilinen bir değişiklik üzerinden - Bilinmeyen Değer, bilinen değişiklik: Öncelikle " Unknown initial value " türünde bir scan gerçekleştirin](<../../images/image (890).png>)

Ardından değeri değiştirin, **değerin** **nasıl değiştiğini** belirtin (benim durumumda 1 azaltıldı) ve bir **next scan gerçekleştirin**:

![Bilinen bir değişiklik üzerinden - Bilinmeyen Değer, bilinen değişiklik: Ardından değeri değiştirin, değerin nasıl değiştiğini belirtin (benim durumumda 1 azaltıldı) ve bir next scan gerçekleştirin](<../../images/image (371).png>)

Seçtiğiniz şekilde değiştirilen **tüm değerler** gösterilir:

![Bilinen bir değişiklik üzerinden - Bilinmeyen Değer, bilinen değişiklik: Seçtiğiniz şekilde değiştirilen tüm değerler gösterilir](<../../images/image (569).png>)

Değerinizi bulduktan sonra onu değiştirebilirsiniz.

Birçok **olası değişiklik** olduğunu ve sonuçları filtrelemek için bu **adımları istediğiniz kadar** tekrarlayabileceğinizi unutmayın:

![Bilinen bir değişiklik üzerinden - Bilinmeyen Değer, bilinen değişiklik: Birçok olası değişiklik olduğunu ve sonuçları filtrelemek için bu adımları istediğiniz kadar tekrarlayabileceğinizi unutmayın](<../../images/image (574).png>)

### Rastgele Bellek Adresi - Kodu bulma

Şimdiye kadar bir değeri saklayan adresi bulmayı öğrendik, ancak **oyunun farklı çalıştırılmalarında bu adresin belleğin farklı yerlerinde bulunması** oldukça olasıdır. Şimdi bu adresi her zaman nasıl bulacağımızı görelim.

Bahsedilen yöntemlerden bazılarını kullanarak mevcut oyununuzun önemli değeri sakladığı adresi bulun. Ardından (isterseniz oyunu durdurarak) bulunan **adrese** **sağ tıklayın** ve "**Find out what accesses this address**" veya "**Find out what writes to this address**" seçeneğini seçin:

![Bilinmeyen Değer, bilinen değişiklik - Rastgele Bellek Adresi - Kodu bulma: Bahsedilen yöntemlerden bazılarını kullanarak mevcut oyununuzun önemli değeri sakladığı adresi bulun. Ardından...](<../../images/image (1067).png>)

**İlk seçenek**, **kodun** hangi **bölümlerinin** bu **adresi kullandığını** öğrenmek için faydalıdır (oyunun **kodunu nerede değiştirebileceğinizi öğrenmek** gibi başka amaçlar için de kullanışlıdır).\
**İkinci seçenek** daha **özeldir** ve bu durumda daha faydalı olacaktır; çünkü bu değerin **nereden yazıldığını** öğrenmek istiyoruz.

Bu seçeneklerden birini seçtiğinizde **debugger** programa **bağlanır** ve yeni, **boş bir pencere** açılır. Şimdi **oyunu oynayın** ve bu **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren** **adreslerle** doldurulmalıdır:

![Bilinmeyen Değer, bilinen değişiklik - Rastgele Bellek Adresi - Kodu bulma: Bu seçeneklerden birini seçtiğinizde debugger programa bağlanır ve yeni, boş bir pencere açılır. Ardından...](<../../images/image (91).png>)

Artık değeri değiştiren adresi bulduğunuza göre **kodu istediğiniz gibi değiştirebilirsiniz** (Cheat Engine, NOP'lar için hızlıca değişiklik yapmanıza olanak tanır):

![Bilinmeyen Değer, bilinen değişiklik - Rastgele Bellek Adresi - Kodu bulma: Artık değeri değiştiren adresi bulduğunuza göre kodu istediğiniz gibi değiştirebilirsiniz (Cheat Engine...](<../../images/image (1057).png>)

Böylece kodu, sayınızı etkilemeyecek veya her zaman olumlu yönde etkileyecek şekilde değiştirebilirsiniz.

### Rastgele Bellek Adresi - Pointer'ı bulma

Önceki adımları izleyerek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından "**Find out what writes to this address**" seçeneğini kullanarak bu değeri hangi adresin yazdığını bulun ve disassembly görünümünü açmak için üzerine çift tıklayın:

![Rastgele Bellek Adresi - Kodu bulma - Rastgele Bellek Adresi - Pointer'ı bulma: Önceki adımları izleyerek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından " Find out...](<../../images/image (1039).png>)

Ardından **"\[]" arasındaki hex değerini arayarak** yeni bir scan gerçekleştirin (bu durumda $edx'in değeri):

![Rastgele Bellek Adresi - Kodu bulma - Rastgele Bellek Adresi - Pointer'ı bulma: Ardından " ()" arasındaki hex değerini arayarak yeni bir scan gerçekleştirin (bu durumda $edx'in değeri)](<../../images/image (994).png>)

(_Birden fazla sonuç çıkarsa genellikle en küçük adresi seçmeniz gerekir_)\
Şimdi ilgilendiğimiz değeri değiştirecek **pointer'ı bulduk**.

"**Add Address Manually**" seçeneğine tıklayın:

![Rastgele Bellek Adresi - Kodu bulma - Rastgele Bellek Adresi - Pointer'ı bulma: " Add Address Manually " seçeneğine tıklayın](<../../images/image (990).png>)

Şimdi "Pointer" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda önceki görselde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![Rastgele Bellek Adresi - Kodu bulma - Rastgele Bellek Adresi - Pointer'ı bulma: Şimdi "Pointer" onay kutusuna tıklayın ve bulunan adresi metin kutusuna ekleyin (bu senaryoda...](<../../images/image (392).png>)

İlk "Address" alanının, girdiğiniz pointer adresinden otomatik olarak doldurulduğuna dikkat edin.

OK'e tıklayın; yeni bir pointer oluşturulur:

![Rastgele Bellek Adresi - Kodu bulma - Rastgele Bellek Adresi - Pointer'ı bulma: OK'e tıklayın; yeni bir pointer oluşturulur](<../../images/image (308).png>)

Artık bu değeri her değiştirdiğinizde, değerin bulunduğu bellek adresi farklı olsa bile **önemli değeri değiştirmiş olursunuz**.

### Code Injection

Code injection, hedef sürece bir kod parçası enjekte ettiğiniz ve ardından kodun çalışmasını kendi yazdığınız koddan geçecek şekilde yönlendirdiğiniz bir tekniktir (örneğin puanları azaltmak yerine size puan vermek).

Oyuncunuzun canından 1 çıkaran adresi bulduğunuzu varsayalım:

![Rastgele Bellek Adresi - Pointer'ı bulma - Code Injection: Oyuncunuzun canından 1 çıkaran adresi bulduğunuzu varsayalım](<../../images/image (203).png>)

**Disassemble code**'u görmek için Show disassembler seçeneğine tıklayın.\
Ardından Auto assemble penceresini açmak için **CTRL+a** tuşlarına basın ve _**Template --> Code Injection**_ seçeneğini seçin.

![Rastgele Bellek Adresi - Pointer'ı bulma - Code Injection: Auto assemble penceresini açmak için CTRL+a tuşlarına basın ve Template -- Code Injection seçeneğini seçin](<../../images/image (902).png>)

**Değiştirmek istediğiniz talimatın adresini** girin (bu alan genellikle otomatik olarak doldurulur):

![Rastgele Bellek Adresi - Pointer'ı bulma - Code Injection: Değiştirmek istediğiniz talimatın adresini girin (bu alan genellikle otomatik olarak doldurulur)](<../../images/image (744).png>)

Bir template oluşturulur:

![Rastgele Bellek Adresi - Pointer'ı bulma - Code Injection: Bir template oluşturulur](<../../images/image (944).png>)

Yeni assembly kodunuzu "**newmem**" bölümüne ekleyin ve çalıştırılmasını istemiyorsanız özgün kodu "**originalcode**" bölümünden kaldırın**.** Bu örnekte enjekte edilen kod, 1 çıkarmak yerine 2 puan ekleyecektir:

![Rastgele Bellek Adresi - Pointer'ı bulma - Code Injection: Yeni assembly kodunuzu " newmem " bölümüne ekleyin ve çalıştırılmasını istemiyorsanız özgün kodu " originalcode " bölümünden kaldırın...](<../../images/image (521).png>)

**Execute'a tıklayın ve kodunuz programa enjekte edilerek işlevin davranışını değiştirsin!**

## Cheat Engine 7.x'teki gelişmiş özellikler (2023-2025)

Cheat Engine, 7.0 sürümünden bu yana gelişmeye devam etti ve modern yazılımları (yalnızca oyunları değil!) analiz ederken son derece kullanışlı olan çeşitli kullanım kolaylığı ve *offensive-reversing* özellikleri eklendi. Aşağıda, red-team/CTF çalışmalarında büyük olasılıkla kullanacağınız eklemelere ilişkin **çok yoğunlaştırılmış bir saha rehberi** yer alıyor.<sup>[[1]](#references)</sup>

### Pointer Scanner 2 iyileştirmeleri
* `Pointers must end with specific offsets` ve yeni **Deviation** slider'ı (≥7.4), bir güncellemeden sonra yeniden scan gerçekleştirdiğinizde false positive sonuçlarını büyük ölçüde azaltır. Bunu, yalnızca birkaç dakika içinde **tek ve dayanıklı bir base-pointer** elde etmek için multi-map karşılaştırmasıyla (`.PTR` → *Compare results with other saved pointer map*) birlikte kullanın.
* Toplu filtreleme kısayolu: İlk scan'den sonra her şeyi işaretlemek için `Ctrl+A → Space` tuşlarına basın, ardından yeniden scan'i geçemeyen adreslerin seçimini kaldırmak için `Ctrl+I` tuşlarına basın.

### Ultimap 3 – Intel PT tracing
*7.5 sürümünden itibaren eski Ultimap, **Intel Processor-Trace (IPT)** temel alınarak yeniden uygulandı.* Bu, artık hedefin gerçekleştirdiği **her branch'i**, **single-stepping** yapmadan kaydedebileceğiniz anlamına gelir (yalnızca user-mode; çoğu anti-debug gadget'ını tetiklemez).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Birkaç saniye sonra capture işlemini durdurun ve **sağ tıklayın → Save execution list to file**. Branch adreslerini bir `Find out what addresses this instruction accesses` oturumuyla birleştirerek yüksek frekanslı game-logic hotspot'larını son derece hızlı şekilde bulun.

### 1-byte `jmp` / auto-patch templates
Version 7.5, bir SEH handler yükleyen ve orijinal konuma bir INT3 yerleştiren *one-byte* JMP stub'ı (0xEB) kullanıma sundu. Bu stub, 5-byte relative jump ile patch edilemeyen instruction'lar üzerinde **Auto Assembler → Template → Code Injection** kullandığınızda otomatik olarak oluşturulur. Bu, packed veya boyut kısıtlamalı routine'lerin içinde “tight” hook'ların oluşturulmasını mümkün kılar.

### DBVM ile kernel-level stealth (AMD ve Intel)
*DBVM*, CE'nin yerleşik Type-2 hypervisor'ıdır. Güncel build'ler sonunda **AMD-V/SVM support** ekledi; böylece Ryzen/EPYC host'larında `Driver → Load DBVM` çalıştırabilirsiniz. DBVM şunları yapmanıza olanak tanır:
1. Ring-3/anti-debug kontrolleri tarafından görünmeyen hardware breakpoint'ler oluşturmak.
2. User-mode driver devre dışı olsa bile pageable veya protected kernel memory bölgelerini okumak/yazmak.
3. VM-EXIT-less timing-attack bypass'ları gerçekleştirmek (ör. hypervisor üzerinden `rdtsc` sorgulamak).

**İpucu:** Windows 11'de HVCI/Memory-Integrity etkin olduğunda DBVM yüklenmeyi reddeder → bunu devre dışı bırakın veya özel bir VM-host başlatın.

### **ceserver** ile Remote / cross-platform debugging
CE artık *ceserver*'ın tamamen yeniden yazılmış sürümüyle birlikte geliyor ve **Linux, Android, macOS ve iOS** hedeflerine TCP üzerinden attach olabilir. Popüler bir fork, dynamic instrumentation'ı CE'nin GUI'siyle birleştirmek için *Frida* entegrasyonu sunuyor; bu, telefonda çalışan Unity veya Unreal oyunlarını patch etmeniz gerektiğinde idealdir:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridge için GitHub'da `bb33bb/frida-ceserver` adresine bakın.<sup>[[2]](#references)</sup>

### Dikkate değer diğer özellikler
* **Patch Scanner** (MemView → Tools) – executable bölümlerindeki beklenmeyen code değişikliklerini algılar; malware analysis için kullanışlıdır.
* **Structure Dissector 2** – bir adresi sürükleyip bırakın → `Ctrl+D`, ardından C-structures'ı otomatik olarak değerlendirmek için *Guess fields* seçeneğini kullanın.
* **.NET & Mono Dissector** – geliştirilmiş Unity game desteği; method'ları doğrudan CE Lua console'dan çağırın.
* **Big-Endian custom types** – ters byte sırası tarama/düzenleme (console emulator'ları ve network packet buffer'ları için kullanışlıdır).
* AutoAssembler/Lua window'ları için **Autosave & tabs** ve çok satırlı instruction yeniden yazımı için `reassemble()`.

### Installation & OPSEC notları (2024-2025)
* Resmi installer, InnoSetup **ad-offers** (`RAV` vb.) ile paketlenmiştir. PUP'ları önlemek için **her zaman *Decline* seçeneğine tıklayın** *veya source code'dan compile edin*. AV'ler `cheatengine.exe` dosyasını beklenen bir durum olarak *HackTool* şeklinde işaretlemeye devam eder.
* Modern anti-cheat driver'ları (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys), yeniden adlandırıldığında bile CE'nin window class'ını algılar. Reversing kopyanızı **disposable bir VM içinde** veya network play'i devre dışı bıraktıktan sonra çalıştırın.
* Yalnızca user-mode erişimine ihtiyacınız varsa, Windows 11 24H2 Secure-Boot'ta BSOD'a neden olabilecek CE'nin unsigned driver'ını yüklemekten kaçınmak için **`Settings → Extra → Kernel mode debug = off`** seçeneğini belirleyin.

---

## References

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, Cheat Engine ile nasıl başlanacağını öğrenmek için tamamlayın

{{#include ../../banners/hacktricks-training.md}}
