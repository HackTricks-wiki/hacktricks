# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır.\
İndirip çalıştırdığınızda, araçla nasıl kullanılacağına dair bir **tutorial** ile **karşılaşırsınız**. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız bunu tamamlamanız şiddetle önerilir.

## Ne arıyorsunuz?

![Cheat Engine - Ne arıyorsunuz?: Ne arıyorsunuz?](<../../images/image (762).png>)

Bu araç, bir programın **belleğinde bazı değerlerin** (genellikle bir sayının) **nerede saklandığını** bulmak için oldukça kullanışlıdır.\
**Sayılar genellikle** **4bytes** biçiminde saklanır, ancak bunları **double** veya **float** formatlarında da bulabilirsiniz ya da **sayıdan farklı** bir şey aramak isteyebilirsiniz. Bu nedenle **aramak istediğiniz şeyi** **seçtiğinizden** emin olmanız gerekir:

![Cheat Engine - Ne arıyorsunuz?: Sayılar genellikle 4bytes biçiminde saklanır, ancak bunları double veya float formatlarında da bulabilirsiniz ya da başka bir şey aramak isteyebilirsiniz...](<../../images/image (324).png>)

Ayrıca farklı **arama** türlerini de belirtebilirsiniz:

![Cheat Engine - Ne arıyorsunuz?: Ayrıca farklı arama türlerini de belirtebilirsiniz](<../../images/image (311).png>)

Belleği tararken **oyunu durdurmak** için kutuyu da işaretleyebilirsiniz:

![Cheat Engine - Ne arıyorsunuz?: Belleği tararken oyunu durdurmak için kutuyu da işaretleyebilirsiniz](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ bölümünde, **oyunu durdurmak** gibi farklı amaçlar için farklı **hotkeys** ayarlayabilirsiniz (bu, bir noktada belleği taramak istediğinizde oldukça kullanışlıdır). Başka seçenekler de mevcuttur:

![Ne arıyorsunuz? - Hotkeys: Edit -- Settings -- Hotkeys bölümünde, oyunu durdurmak gibi farklı amaçlar için farklı hotkeys ayarlayabilirsiniz (bu, bir noktada...](<../../images/image (864).png>)

## Değeri değiştirme

Aradığınız **değerin** nerede olduğunu **bulduktan** sonra (bununla ilgili daha fazla bilgi aşağıdaki adımlarda verilmektedir), değere çift tıklayıp ardından değerinin üzerine çift tıklayarak **değiştirebilirsiniz**:

![Hotkeys - Değeri değiştirme: Aradığınız değerin nerede olduğunu bulduktan sonra (bununla ilgili daha fazla bilgi aşağıdaki adımlarda verilmektedir), değere çift tıklayıp ardından...](<../../images/image (563).png>)

Son olarak bellekte değişikliğin yapılması için **onay kutusunu** işaretleyin:

![Hotkeys - Değeri değiştirme: Son olarak bellekte değişikliğin yapılması için onay kutusunu işaretleyin](<../../images/image (385).png>)

**Bellekteki** **değişiklik** hemen **uygulanır** (oyun bu değeri tekrar kullanana kadar değerin **oyunda güncellenmeyeceğini** unutmayın).

## Değeri arama

Önemli bir değerin (kullanıcınızın canı gibi) bulunduğunu ve bu değeri geliştirmek istediğinizi varsayalım; şimdi bu değeri bellekte arıyorsunuz.

### Bilinen bir değişiklik üzerinden

100 değerini aradığınızı varsayalım. Bu değeri arayarak bir **tarama gerçekleştirirsiniz** ve çok sayıda eşleşme bulursunuz:

![Değeri arama - Bilinen bir değişiklik üzerinden: 100 değerini aradığınızı varsayalım. Bu değeri arayarak bir tarama gerçekleştirirsiniz ve çok sayıda eşleşme bulursunuz](<../../images/image (108).png>)

Ardından **değerin değişmesini** sağlayacak bir şey yapar, **oyunu durdurur** ve **bir sonraki taramayı** gerçekleştirirsiniz:

![Değeri arama - Bilinen bir değişiklik üzerinden: Ardından değerin değişmesini sağlayacak bir şey yapar, oyunu durdurur ve bir sonraki taramayı gerçekleştirirsiniz](<../../images/image (684).png>)

Cheat Engine, **100'den yeni değere değişen değerleri** arar. Tebrikler, aradığınız değerin **adresini buldunuz**; artık bunu değiştirebilirsiniz.\
_Hâlâ birden fazla değer varsa, o değeri tekrar değiştirecek bir şey yapın ve adresleri filtrelemek için başka bir "next scan" gerçekleştirin._

### Bilinmeyen değer, bilinen değişiklik

**Değeri bilmediğiniz**, ancak **onu nasıl değiştireceğinizi** (hatta değişikliğin miktarını) bildiğiniz senaryolarda numaranızı arayabilirsiniz.

Öncelikle "**Unknown initial value**" türünde bir tarama gerçekleştirerek başlayın:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Öncelikle "Unknown initial value" türünde bir tarama gerçekleştirerek başlayın](<../../images/image (890).png>)

Ardından değeri değiştirin, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaltılmıştı) ve **bir sonraki taramayı** gerçekleştirin:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Ardından değeri değiştirin, değerin nasıl değiştiğini belirtin (benim durumumda 1 azaltılmıştı) ve bir sonraki taramayı gerçekleştirin](<../../images/image (371).png>)

Seçtiğiniz şekilde değiştirilen **tüm değerler** gösterilir:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Seçtiğiniz şekilde değiştirilen tüm değerler gösterilir](<../../images/image (569).png>)

Değerinizi bulduktan sonra onu değiştirebilirsiniz.

Filtrelemek için **çok sayıda olası değişiklik** bulunduğunu ve bu **adımları istediğiniz kadar** tekrarlayabileceğinizi unutmayın:

![Bilinen bir değişiklik üzerinden - Bilinmeyen değer, bilinen değişiklik: Çok sayıda olası değişiklik bulunduğunu ve sonuçları filtrelemek için bu adımları istediğiniz kadar tekrarlayabileceğinizi unutmayın](<../../images/image (574).png>)

### Rastgele bellek adresi - Kodu bulma

Şimdiye kadar bir değeri saklayan adresi nasıl bulacağımızı öğrendik, ancak **oyunun farklı çalıştırmalarında bu adresin belleğin farklı yerlerinde bulunması** oldukça olasıdır. Bu nedenle bu adresi her zaman nasıl bulacağımızı öğrenelim.

Bahsedilen yöntemlerden bazılarını kullanarak, mevcut oyununuzun önemli değeri sakladığı adresi bulun. Ardından (isterseniz oyunu durdurarak) bulunan **adrese** **sağ tıklayın** ve "**Find out what accesses this address**" veya "**Find out what writes to this address**" seçeneğini seçin:

![Bilinmeyen değer, bilinen değişiklik - Rastgele bellek adresi - Kodu bulma: Bahsedilen yöntemlerden bazılarını kullanarak, mevcut oyununuzun önemli değeri sakladığı adresi bulun. Ardından...](<../../images/image (1067).png>)

**İlk seçenek**, bu **adresi kullanan kodun hangi bölümleri** olduğunu öğrenmek için kullanışlıdır (oyunun **kodunu nerede değiştirebileceğinizi öğrenmek** gibi başka amaçlar için de yararlıdır).\
**İkinci seçenek** daha **özeldir** ve bu durumda daha faydalı olacaktır; çünkü bu değerin **nereden yazıldığını** öğrenmek istiyoruz.

Bu seçeneklerden birini seçtiğinizde **debugger** programa **bağlanır** ve yeni bir **boş pencere** açılır. Şimdi **oyunu oynayın** ve bu **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren adreslerle** doldurulmalıdır:

![Bilinmeyen değer, bilinen değişiklik - Rastgele bellek adresi - Kodu bulma: Bu seçeneklerden birini seçtiğinizde debugger programa bağlanır ve yeni bir boş pencere...](<../../images/image (91).png>)

Artık değeri değiştiren adresi bulduğunuza göre **kodu istediğiniz şekilde değiştirebilirsiniz** (Cheat Engine, bunu NOP'lar için oldukça hızlı biçimde yapmanıza olanak tanır):

![Bilinmeyen değer, bilinen değişiklik - Rastgele bellek adresi - Kodu bulma: Artık değeri değiştiren adresi bulduğunuza göre kodu istediğiniz şekilde değiştirebilirsiniz (Cheat Engine...](<../../images/image (1057).png>)

Böylece, kodun numaranızı etkilememesini veya onu her zaman olumlu yönde etkilemesini sağlayacak şekilde değiştirebilirsiniz.

### Rastgele bellek adresi - Pointer'ı bulma

Önceki adımları izleyerek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından "**Find out what writes to this address**" seçeneğini kullanarak bu değeri hangi adresin yazdığını bulun ve disassembly görünümünü açmak için üzerine çift tıklayın:

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: Önceki adımları izleyerek ilgilendiğiniz değerin nerede olduğunu bulun. Ardından " Find out...](<../../images/image (1039).png>)

Ardından **"\[]" arasındaki hex değerini arayarak** yeni bir tarama gerçekleştirin (bu durumda $edx değerini):

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: Ardından " ()" arasındaki hex değerini arayarak yeni bir tarama gerçekleştirin (bu durumda $edx değerini)](<../../images/image (994).png>)

(_Birden fazla sonuç çıkarsa genellikle en küçük adresi seçmeniz gerekir_)\
Artık **ilgilendiğimiz değeri değiştirecek pointer'ı bulduk**.

"**Add Address Manually**" seçeneğine tıklayın:

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: " Add Address Manually " seçeneğine tıklayın](<../../images/image (990).png>)

Şimdi "Pointer" onay kutusuna tıklayın ve bulduğunuz adresi metin kutusuna ekleyin (bu senaryoda, önceki görselde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: Şimdi "Pointer" onay kutusuna tıklayın ve bulduğunuz adresi metin kutusuna ekleyin (bu senaryoda,...](<../../images/image (392).png>)

(İlk "Address" alanının, girdiğiniz pointer adresiyle otomatik olarak doldurulduğuna dikkat edin.)

OK'a tıklayın; yeni bir pointer oluşturulacaktır:

![Rastgele bellek adresi - Kodu bulma - Rastgele bellek adresi - Pointer'ı bulma: OK'a tıklayın; yeni bir pointer oluşturulacaktır](<../../images/image (308).png>)

Artık bu değeri her değiştirdiğinizde, değerin bulunduğu bellek adresi farklı olsa bile **önemli değeri değiştirmiş olursunuz**.

### Code Injection

Code injection, hedef prosese bir kod parçası enjekte ettiğiniz ve ardından kodun yürütülmesini kendi yazdığınız koddan geçecek şekilde yönlendirdiğiniz bir tekniktir (örneğin puanları azaltmak yerine size puan vermek).

Oyuncunuzun canından 1 çıkaran adresi bulduğunuzu varsayalım:

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Oyuncunuzun canından 1 çıkaran adresi bulduğunuzu varsayalım](<../../images/image (203).png>)

**Disassemble kodunu** görmek için Show disassembler seçeneğine tıklayın.\
Ardından Auto assemble penceresini açmak için **CTRL+a** tuşlarına basın ve _**Template --> Code Injection**_ seçeneğini seçin.

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Auto assemble penceresini açmak için CTRL+a tuşlarına basın ve Template -- Code Injection seçeneğini seçin](<../../images/image (902).png>)

**Değiştirmek istediğiniz instruction'ın adresini** girin (bu genellikle otomatik olarak doldurulur):

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Değiştirmek istediğiniz instruction'ın adresini girin (bu genellikle otomatik olarak doldurulur)](<../../images/image (744).png>)

Bir template oluşturulur:

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Bir template oluşturulur](<../../images/image (944).png>)

Yeni assembly kodunuzu "**newmem**" bölümüne ekleyin ve yürütülmesini istemiyorsanız "**originalcode**" bölümündeki orijinal kodu kaldırın**.** Bu örnekte enjekte edilen kod, 1 çıkarmak yerine 2 puan ekleyecektir:

![Rastgele bellek adresi - Pointer'ı bulma - Code Injection: Yeni assembly kodunuzu " newmem " bölümüne ekleyin ve yürütülmesini istemiyorsanız " originalcode " bölümündeki orijinal kodu kaldırın...](<../../images/image (521).png>)

**Execute'a ve benzeri seçeneklere tıklayın; kodunuz programa enjekte edilerek işlevin davranışını değiştirmelidir!**

## AOB signatures ile relocation-safe code injection

`game.exe+123456` adresini hook'layan bir script, ASLR veya bir software update sonrasında bozulabilir. Bir **Array of Bytes (AOB) signature**, instruction'ı doğrudan çevresindeki machine code'dan bulur. Aramayı tek bir module ile sınırlamak için `aobscanmodule` kullanın. Tek bir eşleşme döndürecek kadar uzun bir signature oluşturun. Relocation byte'larını, adresleri ve değişebilecek diğer byte'ları wildcard olarak belirtin. Restore etmeniz gereken instruction'ın tamamını wildcard olarak belirtmeyin.<sup>[[4]](#references)</sup>

Memory View'da instruction'ı seçin ve **Tools → Auto Assemble → Template → AOB Injection** seçeneklerini kullanın. Oluşturulan `[DISABLE]` bloğu önemlidir. Üzerine yazılan her byte'ı restore etmeli ve allocation'ı free etmelidir.<sup>[[4]](#references)</sup>

<details>
<summary>Minimal x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Script'i etkinleştirmeden önce şu noktaları doğrulayın:

1. AOB **tek bir adres** döndürmelidir. Birden fazla adres döndürüyorsa her iki tarafa da kararlı talimatlar ekleyin.
2. Jump, tam talimatların yerini almalıdır. Bir talimatı asla bölmeyin.
3. Ayrılan code cave, oluşturulan jump ile erişilebilir olmalıdır. x64'te uzak bir allocation, 14 baytlık bir jump gerektirebilir.
4. Inject edilen kod, özgün fonksiyonun beklediği register'ları, flag'leri ve stack hizalamasını korumalıdır.
5. Disable bloğu, özgün baytları eksiksiz şekilde geri yüklemelidir. Table'ı kaydetmeden önce etkinleştirme ve devre dışı bırakma işlemlerini birkaç kez test edin.

## Güvenilir pointer workflow

Bir çalıştırmada bulunan pointer yalnızca bir adaydır. Birkaç yeni çalıştırmada pointer map'leri oluşturun ve hepsine karşı yeniden tarama yapın. ASLR ve heap allocation'ları değişsin diye yakalamalar arasında hedefi yeniden başlatın. Base'i bir module veya başka bir kararlı symbol olan path'leri tercih edin. Yalnızca tek bir save, level veya object instance ile çalışan path'leri reddedin.

**The pointer must end with specific offsets** filtresi ve deviation seçeneği, yakındaki bir field build'ler arasında taşındığında kullanışlı path'leri koruyabilir. 7.5 sürümü bu deviation kontrolünü de ekledi. Bu bir filtredir; bir pointer chain'in kararlı olduğunun kanıtı değildir.<sup>[[1]](#references)</sup>

Bir structure pointer scanning için çok sık taşınıyorsa, ona erişen instruction'ı hook'layın. Live object pointer'ını bir register'dan allocated symbol'a aktarın. Bu yöntem, entity list'leri ve managed object'ler için genellikle daha güvenilirdir.

## Değerleri taramak yerine code tracing

Değer doğrudan değiştirildiğinde **Find out what writes to this address** seçeneğini kullanın. Sahip olan object'e ihtiyaç duyduğunuzda veya write işlemi kopyalanmış veriler üzerinden gerçekleştiğinde **Find out what accesses this address** seçeneğini kullanın. Hedefte yalnızca tek bir action tetikleyin. Ardından hit count'u ve register durumunu karşılaştırın.

**Ultimap 2**, desteklenen Intel CPU'larda Intel Processor Trace kullanır. Her instruction'ı tek tek step etmekten daha az kesintiyle yürütülen control flow'u kaydeder. İlgi çekici action gerçekleşirken yürütülen code'u filtreleyin ve idle capture sırasında da yürütülen code'u kaldırın. Intel PT bir stealth özelliği değildir. Hedef, tracing'i, zamanlama değişikliklerini veya Cheat Engine'in kendisini hâlâ tespit edebilir.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 ayrıca Windows tarafından sağlanan bir Intel PT interface'i ekledi. Eski DBVM destekli Ultimap modu ile Intel PT modu farklı hardware ve OS gereksinimlerine sahiptir. DBVM destekleyen bir CPU'nun Intel PT'yi de desteklediğini varsaymayın.<sup>[[1]](#references)</sup>

## Debugger ve breakpoint seçimi

Çalışan en az müdahaleci debugger'ı seçin:

- **Windows debugger** basittir ancak normal debug event'leri oluşturur. Anti-debugging kontrolleri bunu tespit edebilir.
- **VEH debugger**, breakpoint'leri vectored exception handler üzerinden işler. Bazı temel debugger kontrollerini atlatır ancak görünmez değildir.
- **Hardware breakpoints**, instruction byte'larını patch'lemez; ancak x86/x64 yalnızca az sayıda debug-register slot'u sağlar.
- **Software breakpoints**, bir byte'ı `INT3` ile değiştirir. Kolayca tespit edilebilir ve integrity check'leriyle çakışabilir.
- **DBVM debugger**, bazı işlemleri guest OS'nin altına taşır. Çok daha fazla privilege'e sahiptir ve yanlış yapılandırılırsa host'u çökertebilir.

Cheat Engine 7.5, normal relative jump için yeterli alan olmadığında exception handler ve `INT3` tabanlı tek baytlık bir jump kullanabilir. Buna bir software breakpoint gibi davranın. Exception flow'u doğrulayın ve anti-tamper kontrollerini atladığını varsaymayın.<sup>[[1]](#references)</sup>

DBVM bir hypervisor'dır; genel amaçlı bir invisibility switch değildir. Yalnızca disposable bir lab'de kullanın. Control interface'ini güvenilmeyen code'a açmayın. Kernel anti-cheat ve endpoint ürünleri driver'ı, hypervisor state'ini veya değiştirilmiş memory'yi hâlâ tespit edebilir.

## Managed runtime'lar ve 7.6/7.7'deki yeni özellikler

Mono, IL2CPP, .NET ve Java hedeflerinde, mevcut olduğunda blind scan yerine runtime metadata'yı tercih edin. **Mono → Activate mono features** veya ilgili runtime information window'unu açın. Önce class, field veya method'u bulun. Ardından managed method JIT-compile edildiğinde native disassembly'yi kullanın.

7.6 serisi, yalnızca executable memory için signature'lar sunan `AOBSCANEX`'i, bir `gdbserver` debugger interface'ini, Java metadata inspection'ını, daha hızlı IL2CPP enumeration'ını ve ARM memory tagging tarafından kullanılan üst pointer byte'ını yok sayan bir pointer-scan seçeneğini ekledi. 7.7 serisi native Linux build'lerini, `HOOK`/`UNHOOK`'u, `aobscanfunction`'ı, daha iyi generic Mono method lookup'ını, geliştirilmiş PDB structure desteğini ve temel Unreal Engine structure dissection'ını ekledi.<sup>[[3]](#references)</sup>

Bu eklemeler kullanışlı bir workflow sağlar:

1. Managed method'u veya static field'ı metadata'dan çözümleyin.
2. Bu method için üretilen native code'u trace edin veya disassemble edin.
3. Kararlı bir executable signature bulmak için `AOBSCANEX` veya `aobscanfunction` kullanın.
4. Geri alınabilir bir hook oluşturun. Özgün instruction'ları koruyun ve disable path'ini doğrulayın.
5. Her target update'inden sonra signature'ı yeniden kontrol edin. Başarılı bir eşleşme, çevredeki logic'in hâlâ aynı anlama geldiğini garanti etmez.

## `ceserver` ile remote target'lar

`ceserver`, process enumeration, memory access ve debugging işlemlerini Cheat Engine GUI'sine sunar. Resmî build'ler Linux ve Android'i kapsar. Hedefte eşleşen architecture'ı çalıştırın ve **Network** tab'ı üzerinden bağlanın. Android'de varsayılan portu forward etmek, portun network'e açılmasını önler:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Üçüncü taraf `frida-ceserver` bridge'i, iOS hedefleri için Cheat Engine uyumlu bir arayüz sağlayabilir. Bu, resmi `ceserver` değildir ve desteklediği işlemler farklılık gösterebilir.<sup>[[2]](#references)</sup>

Protokolün debugger düzeyinde erişim sağladığını varsayın. Bunu loopback'e bağlayın veya bir SSH/ADB tünelinin arkasına yerleştirin. TCP 52736'yı güvenilmeyen bir ağa asla açmayın. Oturum sona erdiğinde server'ı durdurun.

## Operasyonel güvenlik

Yalnızca sahibi olduğunuz veya test etme yetkinizin bulunduğu yazılımlara attach olun. Cheat Engine'i online game veya production endpoint yanında çalıştırmayın. Bellek yazma işlemleri, enjekte edilen kod, driver'lar ve DBVM hedefin çökmesine veya bozulmasına neden olabilir.<sup>[[3]](#references)</sup>

Build'leri resmi siteden indirin veya yayımlanmış source code'u derleyin. Security product'ları memory editor'lerini, debugger'ları ve driver'larını sıklıkla hack tools olarak sınıflandırır. Host protection'ı global olarak devre dışı bırakmayın. Dedicated bir VM veya lab host kullanın ve çalıştırmadan önce artifact'ı doğrulayın.<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5 sürüm notları](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Uzak hedefler için frida-ceserver bridge'i](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine resmi sürüm haberleri](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
