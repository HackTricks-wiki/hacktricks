# Jetons d’accès

{{#include ../../banners/hacktricks-training.md}}

## Jetons d’accès

Chaque processus possède un **jeton d’accès principal** qui définit son contexte de sécurité. Un thread utilise normalement ce jeton, mais il peut aussi disposer temporairement d’un **jeton d’emprunt d’identité**. Les jetons contiennent le SID de l’utilisateur, les SID des groupes, les privilèges, les informations d’intégrité et un SID de connexion pour la session de connexion. Les processus héritent généralement d’une référence au jeton principal du processus parent ; ils ne reçoivent pas de copie indépendante de son contenu.<sup>[[4]](#references)</sup>

Vous pouvez afficher ces informations en exécutant `whoami /all`

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

ou en utilisant _Process Explorer_ de Sysinternals (sélectionnez le processus et ouvrez l’onglet « Security ») :

![Jetons d’accès - Jetons d’accès : ou en utilisant Process Explorer de Sysinternals (sélectionnez le processus et ouvrez l’onglet « Security »)](<../../images/image (772).png>)

### Administrateur local

Lorsque le **mode Approbation administrateur de l’UAC** s’applique à un administrateur, la connexion interactive crée un jeton d’administrateur complet et un jeton filtré. Par défaut, Explorer et les processus enfants ordinaires utilisent le jeton filtré. Une demande d’élévation, telle que **Exécuter en tant qu’administrateur**, demande à l’UAC de lancer le programme avec le jeton complet. Le comportement exact varie pour le compte Administrateur intégré et lorsque le mode Approbation administrateur est désactivé.<sup>[[5]](#references)</sup>

Consultez la [**page dédiée à l’UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) pour connaître les techniques de contournement et les détails des stratégies.

En pratique, cela signifie qu’un **shell d’administrateur non élevé s’exécute généralement avec un jeton filtré**. C’est pourquoi `whoami /groups` affiche souvent **`BUILTIN\Administrators` avec l’attribut `Deny only`** jusqu’à ce que le processus soit élevé. En interne, Windows conserve un **jeton élevé associé** (`TokenLinkedToken`) et suit l’état à l’aide de champs tels que `TokenElevationType`.

### Usurpation d’identité d’un utilisateur avec des identifiants

Si vous disposez d’**identifiants valides d’un autre utilisateur**, vous pouvez **créer** une **nouvelle session de connexion** avec ces identifiants :

```
runas /user:domain\username cmd.exe
```

L’**access token** possède également une **référence** aux sessions d’ouverture de session dans **LSASS** ; cela est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des identifiants différents pour accéder aux services réseau** à l’aide de :

```
runas /user:domain\username /netonly cmd.exe
```

C'est utile si vous disposez d'identifiants valides pour accéder à des objets sur le réseau, mais qu'ils ne sont pas valides sur l'hôte actuel, car ils ne seront utilisés que sur le réseau (sur l'hôte actuel, ce sont les privilèges de l'utilisateur courant qui seront utilisés).

#### Détails de `runas /netonly`

`runas /netonly` (et les utilitaires C2 tels que `make_token`) crée un jeton **`LOGON32_LOGON_NEW_CREDENTIALS`**. C'est très utile à comprendre lors d'un lateral movement, car :<sup>[[3]](#references)</sup>

- **Localement**, le nouveau processus conserve la **même identité locale**, les mêmes groupes, le même niveau d'intégrité et la plupart des mêmes décisions d'accès que le jeton actuel.
- **À distance**, l'authentification sortante peut utiliser les **identifiants fournis** pour SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Par conséquent, `whoami` peut toujours afficher **l'utilisateur local d'origine**, tandis que l'accès au réseau s'effectue sous le **compte alternatif**.

C'est une excellente option lorsque les identifiants sont valides dans le domaine ou sur un autre hôte, mais que l'utilisateur **ne peut pas ou ne devrait pas ouvrir de session localement** sur la machine actuelle.

### Types de jetons

Il existe deux types de jetons disponibles :<sup>[[4]](#references)[[6]](#references)</sup>

- **Jeton principal** : Représente le contexte de sécurité d'un processus. Un enfant hérite normalement du jeton principal de son parent, tandis que les API de création de processus utilisant un jeton explicite imposent leurs propres exigences en matière d'accès au jeton et de privilèges de l'appelant.
- **Jeton d'impersonation** : Permet à un thread serveur d'utiliser temporairement le contexte de sécurité d'un client pour les contrôles d'accès. Il existe quatre niveaux :
  - **Anonyme** : Accorde au serveur un accès similaire à celui d'un utilisateur non identifié.
  - **Identification** : Permet au serveur de vérifier l'identité du client sans l'utiliser pour accéder aux objets.
  - **Impersonation** : Permet au serveur d'opérer sous l'identité du client.
  - **Délégation** : Permet au serveur d'usurper l'identité du client sur des systèmes distants lorsque le mécanisme d'authentification et la configuration du compte autorisent la délégation.

#### Évaluer un jeton capturé avant de l'utiliser

Ne sélectionnez pas un jeton uniquement en fonction du nom d'utilisateur. Un même compte peut avoir plusieurs jetons avec des sessions d'ouverture de session, des SID de service, des privilèges, des niveaux d'intégrité, des restrictions et des identifiants réseau différents.<sup>[[9]](#references)</sup> Interrogez au minimum **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** et **`TokenStatistics.AuthenticationId`** avec `GetTokenInformation`.<sup>[[7]](#references)</sup>

Un jeton restreint peut contenir des SID en refus uniquement, des privilèges supprimés et des SID de restriction. Lorsque des SID de restriction sont présents, Windows effectue un contrôle d'accès avec les SID activés, puis un autre avec les SID de restriction ; **les deux contrôles doivent autoriser l'accès**. Par conséquent, un SID d'utilisateur attrayant ou un groupe activé dans la sortie ne prouve pas à lui seul que le jeton peut accéder à l'objet cible.<sup>[[8]](#references)</sup>

Suivez ce processus décisionnel pour respecter les exigences documentées relatives aux jetons et à la création de processus :<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Un **jeton principal** doit disposer d'un handle avec `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` avant de pouvoir être fourni à `CreateProcessWithTokenW` ou `CreateProcessAsUserW`.
2. Convertissez un **jeton d'impersonation** avec `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Les jetons de niveau Identification peuvent exposer des données d'identité, mais ne peuvent pas effectuer de contrôles d'accès en tant que ce client.
3. `CreateProcessWithTokenW` nécessite `SeImpersonatePrivilege` et lance le processus enfant dans la session de l'appelant. `CreateProcessAsUserW` utilise plutôt la session du jeton, mais nécessite généralement `SeIncreaseQuotaPrivilege` et peut nécessiter `SeAssignPrimaryTokenPrivilege`. Si des identifiants sont disponibles et que ces privilèges manquent, `CreateProcessWithLogonW` est l'alternative documentée.

#### Rechercher les handles de jeton, pas uniquement les propriétaires de processus

Ouvrir le jeton principal de chaque processus peut faire manquer des **jetons d'impersonation conservés comme handles ordinaires** dans les services et les processus broker. Une méthode réutilisable pour examiner les tables de handles consiste à énumérer les handles système, filtrer les objets jeton, ouvrir chaque propriétaire avec `PROCESS_DUP_HANDLE`, dupliquer le handle candidat dans le processus actuel, puis interroger les champs ci-dessus. Vérifiez que le handle dupliqué inclut `TOKEN_QUERY` et `TOKEN_DUPLICATE` ; la présence d'un handle de jeton ne signifie pas qu'il peut être dupliqué en un jeton principal utilisable. Les processus protégés et les DACL des processus peuvent toujours empêcher l'ouverture du handle du processus propriétaire.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatise l'énumération des jetons principaux de processus et des handles de jeton conservés. `list_token` conserve un candidat privilégié par nom d'utilisateur, tandis que `list_all_token` affiche tous les candidats. Un PID limite l'énumération à un seul processus propriétaire.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Pour l’inspection manuelle et la vérification des accès, **TokenUniverse** peut ouvrir les tokens de processus/thread, rechercher des handles de token existants, inspecter les restrictions et les sessions d’ouverture de session, dupliquer des tokens et tester plusieurs méthodes de création de processus.<sup>[[13]](#references)</sup> Pour le mécanisme sous-jacent de handle interprocessus, consultez :

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

En utilisant le module _**incognito**_ de metasploit, si vous disposez de privilèges suffisants, vous pouvez facilement **lister** et **impersonate** d’autres **tokens**. Cela peut être utile pour effectuer des **actions comme si vous étiez l’autre utilisateur**. Vous pouvez également **escalader vos privilèges** grâce à cette technique.

Quelques remarques pratiques qu’il est facile d’oublier pendant les opérations :<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** nécessite **`SeImpersonatePrivilege`** chez l’appelant et le nouveau processus s’exécutera dans la **session de l’appelant**.
- **`CreateProcessAsUserW`** est une solution de repli possible lorsque `CreateProcessWithTokenW` échoue avec l’erreur `1314`, uniquement si l’appelant satisfait aux exigences de privilèges de cette fonction. C’est également le bon choix lorsque le processus enfant doit s’exécuter dans la **session référencée par le token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Si un token provient de **`LogonUser(LOGON32_LOGON_NETWORK)`**, il s’agit généralement d’un **token d’impersonation**. Vous devez donc utiliser **`DuplicateTokenEx(..., TokenPrimary, ...)`** avant d’essayer de créer un processus avec ce token.
- Les tokens d’impersonation ne sont pas tous aussi utiles : **`SecurityIdentification`** vous permet d’inspecter l’utilisateur, mais **pas d’agir en son nom**. Si un primitive de coercition ou un client pipe/RPC ne vous fournit qu’un token de niveau identification, vérifiez **`TokenImpersonationLevel`** et utilisez une primitive qui fournit **`SecurityImpersonation`** ou un niveau supérieur.

#### Vol de tokens sans toucher à LSASS

Si vous disposez déjà d’un contexte **service** ou **SYSTEM** et qu’un **utilisateur privilégié est connecté**, voler ou dupliquer le token de cet utilisateur est souvent plus discret que de dumper **LSASS**. Dans de nombreuses intrusions réelles, cela suffit pour :<sup>[[2]](#references)</sup>

- effectuer des actions locales en tant que cet utilisateur
- accéder à des ressources distantes en tant que cet utilisateur
- effectuer des opérations AD sans extraire d’abord des identifiants réutilisables

Pour des exemples de **détournement de tokens de session/utilisateur** depuis un contexte privilégié, consultez [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). N’oubliez pas que des API telles que **`WTSQueryUserToken`** sont destinées à des **services hautement fiables** et nécessitent généralement **`LocalSystem` + `SeTcbPrivilege`**. Elles sont donc surtout utiles une fois que vous contrôlez déjà un contexte de niveau service. Pour connaître les méthodes permettant d’obtenir d’abord **SYSTEM** selon les privilèges requis, consultez les pages ci-dessous.

### Privilèges des tokens

Découvrez quels **privilèges de token peuvent être exploités pour escalader des privilèges :**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consultez [**la liste de tous les privilèges de token possibles, avec quelques définitions, sur cette page externe**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Comprendre et abuser des access tokens — Partie II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abuser des tokens Windows pour compromettre Active Directory sans toucher à LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Élucider la commande « make_token » de Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Fonctionnement du contrôle de compte d’utilisateur - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Niveaux d’impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Énumération TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens restreints - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Fonction CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Fonction CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Fonction DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
