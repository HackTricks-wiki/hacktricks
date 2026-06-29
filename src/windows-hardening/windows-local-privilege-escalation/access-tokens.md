# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Chaque **utilisateur connecté** au système **possède un access token avec des informations de sécurité** pour cette session de connexion. Le système crée un access token lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **a une copie de l'access token**. Le token identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un token contient aussi un logon SID (Security Identifier) qui identifie la session de connexion en cours.

Vous pouvez voir ces informations en exécutant `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
ou en utilisant _Process Explorer_ de Sysinternals (sélectionnez le process et accédez à l’onglet "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Lorsqu’un local administrator se connecte, **deux access tokens sont créés** : un avec des droits admin et un autre avec des droits normaux. **Par défaut**, lorsque cet utilisateur exécute un process, celui avec des droits **regular** (non-administrator) **est utilisé**. Lorsque cet utilisateur essaie **d’exécuter** quoi que ce soit **en tant qu’administrator** ("Run as Administrator" par exemple), le **UAC** est utilisé pour demander une autorisation.\
Si vous voulez [**en savoir plus sur le UAC, lisez cette page**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

En pratique, cela signifie qu’un **shell admin non élevé** s’exécute généralement avec un filtered token. C’est pourquoi `whoami /groups` affiche souvent **`BUILTIN\Administrators` comme `Deny only`** jusqu’à ce que le process soit élevé. En interne, Windows conserve un **linked elevated token** (`TokenLinkedToken`) et suit l’état avec des champs tels que `TokenElevationType`.

### Credentials user impersonation

Si vous avez des **valid credentials de tout autre user**, vous pouvez **create** une **new logon session** avec ces credentials :
```
runas /user:domain\username cmd.exe
```
Le **access token** a aussi une **référence** des sessions de logon dans le **LSASS**, ce qui est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des identifiants différents pour accéder aux services réseau** en utilisant :
```
runas /user:domain\username /netonly cmd.exe
```
C’est utile si vous avez des credentials utiles pour accéder à des objets dans le réseau, mais que ces credentials ne sont pas valides sur l’hôte actuel car ils ne vont être utilisés que dans le réseau (sur l’hôte actuel, vos privilèges d’utilisateur courants seront utilisés).

#### Détails de `runas /netonly`

`runas /netonly` (et des aides C2 telles que `make_token`) crée un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. C’est très utile à comprendre lors de lateral movement car :

- **Localement**, le nouveau processus conserve la **même identité locale**, les groupes, le niveau d’intégrité, et la plupart des mêmes décisions d’accès que le token actuel.
- **À distance**, l’authentification sortante peut utiliser les **credentials fournis** pour SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Par conséquent, `whoami` peut toujours afficher l’**utilisateur local d’origine** pendant que l’accès réseau s’effectue en tant que **compte alternatif**.

C’est une excellente option lorsque les credentials sont valides dans le domaine ou sur un autre hôte, mais que l’utilisateur **ne peut pas ou ne doit pas se connecter localement** à la machine actuelle.

### Types de tokens

Il existe deux types de tokens disponibles :

- **Primary Token** : Il sert de représentation des credentials de sécurité d’un processus. La création et l’association de primary tokens aux processus sont des actions qui nécessitent des privilèges élevés, ce qui met en avant le principe de séparation des privilèges. En général, un service d’authentification est responsable de la création du token, tandis qu’un service de logon gère son association avec le shell du système d’exploitation de l’utilisateur. Il est à noter que les processus héritent du primary token de leur processus parent à la création.
- **Impersonation Token** : Permet à une application serveur d’adopter temporairement l’identité du client pour accéder à des objets sécurisés. Ce mécanisme est réparti en quatre niveaux de fonctionnement :
- **Anonymous** : Accorde un accès serveur similaire à celui d’un utilisateur non identifié.
- **Identification** : Permet au serveur de vérifier l’identité du client sans l’utiliser pour l’accès aux objets.
- **Impersonation** : Permet au serveur d’opérer sous l’identité du client.
- **Delegation** : Similaire à Impersonation mais avec la capacité d’étendre cette prise d’identité à des systèmes distants avec lesquels le serveur interagit, en garantissant la conservation des credentials.

#### Impersonate Tokens

En utilisant le module _**incognito**_ de metasploit, si vous avez suffisamment de privilèges, vous pouvez facilement **lister** et **impersonate** d’autres **tokens**. Cela peut être utile pour effectuer des **actions comme si vous étiez l’autre utilisateur**. Vous pouvez aussi **escalate privileges** avec cette technique.

Quelques notes pratiques faciles à oublier pendant l’opération :

- **`CreateProcessWithTokenW`** nécessite **`SeImpersonatePrivilege`** chez l’appelant et le nouveau processus s’exécutera dans la **session de l’appelant**.
- **`CreateProcessAsUserW`** est généralement le recours de secours quand `CreateProcessWithTokenW` échoue avec `1314`, ou quand vous devez lancer le processus dans la **session référencée par le token**.
- Si un token provient de **`LogonUser(LOGON32_LOGON_NETWORK)`**, c’est généralement un **impersonation token**, donc vous devez utiliser **`DuplicateTokenEx(..., TokenPrimary, ...)`** avant d’essayer de lancer un processus avec.
- Tous les impersonation tokens ne sont pas aussi utiles : **`SecurityIdentification`** vous permet d’inspecter l’utilisateur mais **pas d’agir en son nom**. Si un primitive de coercition ou un client pipe/RPC vous donne seulement un token de niveau identification, vérifiez **`TokenImpersonationLevel`** et passez à une primitive qui fournit **`SecurityImpersonation`** ou mieux.

#### Vol de token sans toucher LSASS

Si vous avez déjà un contexte **service** ou **SYSTEM** et qu’un **utilisateur privilégié est connecté**, voler ou dupliquer le token de cet utilisateur est souvent plus discret que dumper **LSASS**. Dans de nombreuses intrusions réelles, cela suffit pour :

- exécuter des actions locales en tant que cet utilisateur
- accéder à des ressources distantes en tant que cet utilisateur
- effectuer des opérations AD sans extraire d’abord des credentials réutilisables

Pour des exemples de **session/user token hijacking** depuis un contexte privilégié, consultez [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Rappelez-vous que des APIs comme **`WTSQueryUserToken`** sont destinées aux **services hautement fiables** et nécessitent normalement **`LocalSystem` + `SeTcbPrivilege`**, donc elles sont surtout utiles une fois que vous contrôlez déjà un contexte de niveau service. Pour des moyens spécifiques aux privilèges d’obtenir d’abord **SYSTEM**, consultez les pages ci-dessous.

### Token Privileges

Apprenez quels **token privileges peuvent être abusés pour escalate privileges :**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Jetez un œil à [**tous les token privileges possibles et quelques définitions sur cette page externe**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
