# Protections des Identifiants Windows

## Protections des Identifiants

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Le protocole [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introduit avec Windows XP, est conçu pour l'authentification via le protocole HTTP et est **activé par défaut sur Windows XP jusqu'à Windows 8.0 et Windows Server 2003 jusqu'à Windows Server 2012**. Ce paramètre par défaut entraîne **le stockage des mots de passe en texte clair dans LSASS** (Service de sous-système de sécurité local). Un attaquant peut utiliser Mimikatz pour **extraire ces identifiants** en exécutant :
```bash
sekurlsa::wdigest
```
Pour **désactiver ou activer cette fonctionnalité**, les clés de registre _**UseLogonCredential**_ et _**Negotiate**_ dans _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ doivent être définies sur "1". Si ces clés sont **absentes ou définies sur "0"**, WDigest est **désactivé** :
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protection LSA

À partir de **Windows 8.1**, Microsoft a amélioré la sécurité de LSA pour **bloquer les lectures de mémoire non autorisées ou les injections de code par des processus non fiables**. Cette amélioration entrave le fonctionnement typique de commandes comme `mimikatz.exe sekurlsa:logonpasswords`. Pour **activer cette protection améliorée**, la valeur _**RunAsPPL**_ dans _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ doit être ajustée à 1 :
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Il est possible de contourner cette protection en utilisant le pilote Mimikatz mimidrv.sys :

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, une fonctionnalité exclusive aux **Windows 10 (Enterprise et Education editions)**, renforce la sécurité des identifiants de machine en utilisant **Virtual Secure Mode (VSM)** et **Virtualization Based Security (VBS)**. Il exploite les extensions de virtualisation du CPU pour isoler des processus clés dans un espace mémoire protégé, loin de l'accès du système d'exploitation principal. Cette isolation garantit que même le noyau ne peut pas accéder à la mémoire dans VSM, protégeant ainsi efficacement les identifiants contre des attaques comme **pass-the-hash**. L'**Autorité de Sécurité Locale (LSA)** fonctionne dans cet environnement sécurisé en tant que trustlet, tandis que le processus **LSASS** dans le système d'exploitation principal agit simplement comme un communicateur avec le LSA de VSM.

Par défaut, **Credential Guard** n'est pas actif et nécessite une activation manuelle au sein d'une organisation. Il est crucial pour améliorer la sécurité contre des outils comme **Mimikatz**, qui sont entravés dans leur capacité à extraire des identifiants. Cependant, des vulnérabilités peuvent encore être exploitées par l'ajout de **Security Support Providers (SSP)** personnalisés pour capturer des identifiants en texte clair lors des tentatives de connexion.

Pour vérifier l'état d'activation de **Credential Guard**, la clé de registre _**LsaCfgFlags**_ sous _**HKLM\System\CurrentControlSet\Control\LSA**_ peut être inspectée. Une valeur de "**1**" indique une activation avec **UEFI lock**, "**2**" sans verrou, et "**0**" signifie qu'il n'est pas activé. Cette vérification de registre, bien qu'indicative, n'est pas la seule étape pour activer Credential Guard. Des conseils détaillés et un script PowerShell pour activer cette fonctionnalité sont disponibles en ligne.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Pour une compréhension complète et des instructions sur l'activation de **Credential Guard** dans Windows 10 et son activation automatique dans les systèmes compatibles de **Windows 11 Enterprise et Education (version 22H2)**, visitez [la documentation de Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Des détails supplémentaires sur la mise en œuvre de SSP personnalisés pour la capture de credentials sont fournis dans [ce guide](../active-directory-methodology/custom-ssp.md).

## Mode RestrictedAdmin RDP

**Windows 8.1 et Windows Server 2012 R2** ont introduit plusieurs nouvelles fonctionnalités de sécurité, y compris le _**mode Restricted Admin pour RDP**_. Ce mode a été conçu pour améliorer la sécurité en atténuant les risques associés aux attaques de [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Traditionnellement, lors de la connexion à un ordinateur distant via RDP, vos credentials sont stockés sur la machine cible. Cela pose un risque de sécurité significatif, surtout lors de l'utilisation de comptes avec des privilèges élevés. Cependant, avec l'introduction du _**mode Restricted Admin**_, ce risque est considérablement réduit.

Lors de l'initiation d'une connexion RDP en utilisant la commande **mstsc.exe /RestrictedAdmin**, l'authentification à l'ordinateur distant est effectuée sans stocker vos credentials dessus. Cette approche garantit que, en cas d'infection par un malware ou si un utilisateur malveillant accède au serveur distant, vos credentials ne sont pas compromises, car elles ne sont pas stockées sur le serveur.

Il est important de noter qu'en **mode Restricted Admin**, les tentatives d'accès aux ressources réseau depuis la session RDP n'utiliseront pas vos credentials personnelles ; au lieu de cela, l'**identité de la machine** est utilisée.

Cette fonctionnalité marque un pas en avant significatif dans la sécurisation des connexions de bureau à distance et la protection des informations sensibles contre une exposition en cas de violation de la sécurité.

![](../../images/RAM.png)

Pour des informations plus détaillées, visitez [cette ressource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credentials mises en cache

Windows sécurise les **credentials de domaine** via l'**Autorité de Sécurité Locale (LSA)**, prenant en charge les processus de connexion avec des protocoles de sécurité tels que **Kerberos** et **NTLM**. Une caractéristique clé de Windows est sa capacité à mettre en cache les **dix dernières connexions de domaine** pour garantir que les utilisateurs peuvent toujours accéder à leurs ordinateurs même si le **contrôleur de domaine est hors ligne**—un avantage pour les utilisateurs d'ordinateurs portables souvent éloignés du réseau de leur entreprise.

Le nombre de connexions mises en cache est ajustable via une **clé de registre ou une stratégie de groupe** spécifique. Pour afficher ou modifier ce paramètre, la commande suivante est utilisée :
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accès à ces informations d'identification mises en cache est strictement contrôlé, seul le compte **SYSTEM** ayant les autorisations nécessaires pour les consulter. Les administrateurs ayant besoin d'accéder à ces informations doivent le faire avec des privilèges d'utilisateur SYSTEM. Les informations d'identification sont stockées à : `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** peut être utilisé pour extraire ces informations d'identification mises en cache en utilisant la commande `lsadump::cache`.

Pour plus de détails, la [source](http://juggernaut.wikidot.com/cached-credentials) originale fournit des informations complètes.

## Utilisateurs protégés

L'appartenance au **groupe des Utilisateurs protégés** introduit plusieurs améliorations de sécurité pour les utilisateurs, garantissant des niveaux de protection plus élevés contre le vol et l'utilisation abusive des informations d'identification :

- **Délégation d'informations d'identification (CredSSP)** : Même si le paramètre de stratégie de groupe **Autoriser la délégation des informations d'identification par défaut** est activé, les informations d'identification en texte clair des Utilisateurs protégés ne seront pas mises en cache.
- **Windows Digest** : À partir de **Windows 8.1 et Windows Server 2012 R2**, le système ne mettra pas en cache les informations d'identification en texte clair des Utilisateurs protégés, quel que soit l'état de Windows Digest.
- **NTLM** : Le système ne mettra pas en cache les informations d'identification en texte clair des Utilisateurs protégés ni les fonctions unidirectionnelles NT (NTOWF).
- **Kerberos** : Pour les Utilisateurs protégés, l'authentification Kerberos ne générera pas de **DES** ou de clés **RC4**, ni ne mettra en cache les informations d'identification en texte clair ou les clés à long terme au-delà de l'acquisition initiale du Ticket-Granting Ticket (TGT).
- **Connexion hors ligne** : Les Utilisateurs protégés n'auront pas de vérificateur mis en cache créé lors de la connexion ou du déverrouillage, ce qui signifie que la connexion hors ligne n'est pas prise en charge pour ces comptes.

Ces protections sont activées dès qu'un utilisateur, membre du **groupe des Utilisateurs protégés**, se connecte à l'appareil. Cela garantit que des mesures de sécurité critiques sont en place pour protéger contre diverses méthodes de compromission des informations d'identification.

Pour des informations plus détaillées, consultez la [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) officielle.

**Tableau provenant de** [**la documentation**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
