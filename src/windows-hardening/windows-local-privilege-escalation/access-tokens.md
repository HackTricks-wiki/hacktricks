# Jetons d'accès

{{#include ../../banners/hacktricks-training.md}}

## Jetons d'accès

Chaque **utilisateur connecté** au système **détient un jeton d'accès contenant des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **possède une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (Security Identifier) qui identifie la session de connexion actuelle.

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
ou en utilisant _Process Explorer_ de Sysinternals (sélectionnez le processus et accédez à l’onglet "Security") :

![Access Tokens - Access Tokens : ou en utilisant Process Explorer de Sysinternals (sélectionnez le processus et accédez à l’onglet "Security")](<../../images/image (772).png>)

### Administrateur local

Lorsqu’un administrateur local se connecte, **deux jetons d’accès sont créés** : l’un avec les droits d’administrateur et l’autre avec des droits normaux. **Par défaut**, lorsque cet utilisateur exécute un processus, celui avec des **droits** **normaux** (non administrateur) est utilisé. Lorsque cet utilisateur essaie d’**exécuter** quelque chose **en tant qu’administrateur** ("Run as Administrator", par exemple), l’**UAC** est utilisé pour demander une autorisation.\
Si vous souhaitez [**en savoir plus sur l’UAC, consultez cette page**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

En pratique, cela signifie qu’un **shell administrateur non élevé s’exécute généralement avec un jeton filtré**. C’est pourquoi `whoami /groups` affiche souvent **`BUILTIN\Administrators` comme `Deny only`** jusqu’à ce que le processus soit élevé. En interne, Windows conserve un **jeton élevé lié** (`TokenLinkedToken`) et suit l’état à l’aide de champs tels que `TokenElevationType`.

### Impersonation d’utilisateur avec des identifiants

Si vous disposez d’**identifiants valides d’un autre utilisateur**, vous pouvez **créer** une **nouvelle session de connexion** avec ces identifiants :
```
runas /user:domain\username cmd.exe
```
L’**access token** contient également une **référence** aux sessions de connexion dans **LSASS**, ce qui est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des identifiants différents pour accéder aux services réseau** à l’aide de :
```
runas /user:domain\username /netonly cmd.exe
```
Ceci est utile si vous disposez de credentials valides pour accéder à des objets sur le réseau, mais que ces credentials ne sont pas valides sur l’hôte actuel, car ils seront uniquement utilisés sur le réseau (sur l’hôte actuel, les privilèges de votre utilisateur actuel seront utilisés).

#### Détails de `runas /netonly`

`runas /netonly` (ainsi que les helpers C2 tels que `make_token`) crée un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Il est très utile de comprendre ce fonctionnement lors du lateral movement, car :<sup>[[3]](#references)</sup>

- **Localement**, le nouveau processus conserve la **même identité locale**, les mêmes groupes, le même niveau d’intégrité et la plupart des mêmes décisions d’accès que le token actuel.
- **À distance**, l’authentification sortante peut utiliser les **credentials fournies** pour SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Par conséquent, `whoami` peut toujours afficher l’**utilisateur local d’origine**, tandis que l’accès réseau s’effectue avec le **compte alternatif**.

Il s’agit d’une excellente option lorsque les credentials sont valides dans le domaine ou sur un autre hôte, mais que l’utilisateur **ne peut pas ou ne doit pas se connecter localement** à la machine actuelle.

### Types de tokens

Il existe deux types de tokens disponibles :

- **Primary Token** : Il sert de représentation des credentials de sécurité d’un processus. La création et l’association de primary tokens aux processus sont des actions qui nécessitent des privilèges élevés, ce qui souligne le principe de séparation des privilèges. Généralement, un service d’authentification est responsable de la création du token, tandis qu’un service de logon gère son association avec le shell du système d’exploitation de l’utilisateur. Il convient de noter que les processus héritent du primary token de leur processus parent lors de leur création.
- **Impersonation Token** : Il permet à une application serveur d’adopter temporairement l’identité du client afin d’accéder à des objets sécurisés. Ce mécanisme est organisé en quatre niveaux de fonctionnement :
- **Anonymous** : Accorde au serveur un accès similaire à celui d’un utilisateur non identifié.
- **Identification** : Permet au serveur de vérifier l’identité du client sans l’utiliser pour accéder aux objets.
- **Impersonation** : Permet au serveur de fonctionner sous l’identité du client.
- **Delegation** : Similaire à Impersonation, mais permet également de transmettre cette identité aux systèmes distants avec lesquels le serveur interagit, tout en préservant les credentials.

#### Impersonate Tokens

En utilisant le module _**incognito**_ de metasploit, si vous disposez de suffisamment de privilèges, vous pouvez facilement **lister** et **impersonate** d’autres **tokens**. Cela peut être utile pour effectuer des **actions comme si vous étiez l’autre utilisateur**. Vous pouvez également **escalate privileges** avec cette technique.

Quelques remarques pratiques faciles à oublier pendant les opérations :<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** nécessite **`SeImpersonatePrivilege`** chez l’appelant, et le nouveau processus s’exécutera dans la **session de l’appelant**.
- **`CreateProcessAsUserW`** est le fallback habituel lorsque `CreateProcessWithTokenW` échoue avec `1314`, ou lorsque vous devez lancer le processus dans la **session référencée par le token**.
- Si un token provient de **`LogonUser(LOGON32_LOGON_NETWORK)`**, il s’agit généralement d’un **impersonation token** ; vous devez donc utiliser **`DuplicateTokenEx(..., TokenPrimary, ...)`** avant d’essayer de lancer un processus avec celui-ci.
- Tous les impersonation tokens ne sont pas aussi utiles les uns que les autres : **`SecurityIdentification`** permet d’inspecter l’utilisateur, mais **pas d’agir en son nom**. Si une primitive de coercion ou un client pipe/RPC ne vous fournit qu’un token de niveau identification, vérifiez **`TokenImpersonationLevel`** et utilisez une primitive qui fournit **`SecurityImpersonation`** ou un niveau supérieur.

#### Vol de token sans toucher à LSASS

Si vous disposez déjà d’un contexte **service** ou **SYSTEM** et qu’un **utilisateur privilégié est connecté**, voler ou dupliquer le token de cet utilisateur est souvent plus discret que de dumper **LSASS**. Dans de nombreuses intrusions réelles, cela suffit à :<sup>[[2]](#references)</sup>

- exécuter des actions locales en tant que cet utilisateur
- accéder à des ressources distantes en tant que cet utilisateur
- effectuer des opérations AD sans extraire au préalable de credentials réutilisables

Pour obtenir des exemples de **session/user token hijacking** depuis un contexte privilégié, consultez [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Gardez à l’esprit que des API telles que **`WTSQueryUserToken`** sont destinées aux **services hautement approuvés** et nécessitent normalement **`LocalSystem` + `SeTcbPrivilege`** ; elles sont donc principalement utiles une fois que vous contrôlez déjà un contexte de niveau service. Pour connaître les méthodes spécifiques aux privilèges permettant d’obtenir d’abord **SYSTEM**, consultez les pages ci-dessous.

### Privilèges des tokens

Découvrez quels **privilèges de token peuvent être exploités pour escalate privileges :**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consultez [**tous les privilèges de token possibles ainsi que certaines définitions sur cette page externe**](https://github.com/gtworek/Priv2Admin).

## Références

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
