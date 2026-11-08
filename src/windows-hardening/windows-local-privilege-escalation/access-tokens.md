# Jetons d’accès

{{#include ../../banners/hacktricks-training.md}}

## Jetons d’accès

Chaque processus possède un **jeton d’accès primaire** qui définit son contexte de sécurité. Un thread utilise normalement ce jeton, mais il peut également disposer temporairement d’un **jeton d’impersonation**. Les jetons contiennent le SID de l’utilisateur, les SID des groupes, les privilèges, les informations d’intégrité et un SID de connexion pour la session d’ouverture de session. Les processus héritent généralement d’une référence au jeton primaire du processus parent ; ils ne reçoivent pas de copie indépendante de son contenu.<sup>[[4]](#references)</sup>

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

ou en utilisant _Process Explorer_ de Sysinternals (sélectionnez le processus, puis accédez à l’onglet « Security ») :

![Jetons d’accès - Jetons d’accès : ou en utilisant Process Explorer de Sysinternals (sélectionnez le processus, puis accédez à l’onglet « Security »)](<../../images/image (772).png>)

### Administrateur local

Lorsque le **mode d’approbation administrateur UAC** s’applique à un administrateur, l’ouverture de session interactive crée un jeton d’administrateur complet et un jeton filtré. Par défaut, Explorer et les processus enfants ordinaires utilisent le jeton filtré. Une demande d’élévation telle que **Exécuter en tant qu’administrateur** demande à UAC de démarrer le programme avec le jeton complet. Le comportement exact diffère pour le compte Administrateur intégré et lorsque le mode d’approbation administrateur est désactivé.<sup>[[5]](#references)</sup>

Consultez la [**page UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) dédiée pour connaître les techniques de contournement et les détails des stratégies.

En pratique, cela signifie qu’un **shell administrateur non élevé s’exécute généralement avec un jeton filtré**. C’est pourquoi `whoami /groups` affiche souvent **`BUILTIN\Administrators` avec l’attribut `Deny only`** jusqu’à ce que le processus soit élevé. En interne, Windows conserve un **jeton élevé lié** (`TokenLinkedToken`) et suit cet état à l’aide de champs tels que `TokenElevationType`.

### Usurpation d’identité avec les identifiants d’un utilisateur

Si vous disposez des **identifiants valides d’un autre utilisateur**, vous pouvez **créer** une **nouvelle session d’ouverture de session** avec ces identifiants :

```
runas /user:domain\username cmd.exe
```

L’**access token** contient également une **référence** aux sessions de connexion dans **LSASS**. Cela est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des identifiants différents pour accéder aux services réseau** à l’aide de :

```
runas /user:domain\username /netonly cmd.exe
```

Cela est utile si vous disposez d’identifiants valides pour accéder à des objets sur le réseau, mais qu’ils ne sont pas valides sur l’hôte actuel, car ils ne seront utilisés que sur le réseau (sur l’hôte actuel, les privilèges de l’utilisateur courant seront utilisés).

#### Détails de `runas /netonly`

`runas /netonly` (et des helpers C2 tels que `make_token`) crée un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Il est très utile de le comprendre lors d’un mouvement latéral, car :<sup>[[3]](#references)</sup>

- **Localement**, le nouveau processus conserve la **même identité locale**, les mêmes groupes, le même niveau d’intégrité et la plupart des mêmes décisions d’accès que le token actuel.
- **À distance**, l’authentification sortante peut utiliser les **identifiants fournis** pour SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Ainsi, `whoami` peut toujours afficher **l’utilisateur local d’origine**, tandis que l’accès réseau s’effectue sous le **compte alternatif**.

C’est une excellente option lorsque les identifiants sont valides dans le domaine ou sur un autre hôte, mais que l’utilisateur **ne peut pas ou ne devrait pas ouvrir de session localement** sur la machine actuelle.

### Types de tokens

Il existe deux types de tokens :<sup>[[4]](#references)[[6]](#references)</sup>

- **Token primaire** : représente le contexte de sécurité d’un processus. Un processus enfant hérite généralement du token primaire de son parent, tandis que les API de création de processus avec token explicite imposent leurs propres exigences en matière d’accès au token et de privilèges de l’appelant.
- **Token d’impersonation** : permet à un thread serveur d’utiliser temporairement le contexte de sécurité d’un client pour les contrôles d’accès. Il en existe quatre niveaux :
  - **Anonyme** : accorde au serveur un accès similaire à celui d’un utilisateur non identifié.
  - **Identification** : permet au serveur de vérifier l’identité du client sans l’utiliser pour accéder aux objets.
  - **Impersonation** : permet au serveur d’agir sous l’identité du client.
  - **Délégation** : permet au serveur d’usurper l’identité du client sur des systèmes distants lorsque le mécanisme d’authentification et la configuration du compte autorisent la délégation.

#### Évaluer un token capturé avant de l’utiliser

Ne sélectionnez pas un token uniquement en fonction du nom d’utilisateur. Un même compte peut avoir plusieurs tokens associés à différentes sessions d’ouverture de session, différents SID de service, privilèges, niveaux d’intégrité, restrictions et identifiants réseau.<sup>[[9]](#references)</sup> Interrogez au minimum **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** et **`TokenStatistics.AuthenticationId`** avec `GetTokenInformation`.<sup>[[7]](#references)</sup>

Un token restreint peut contenir des SID en refus uniquement, des privilèges supprimés et des SID de restriction. Lorsque des SID de restriction sont présents, Windows effectue un contrôle d’accès avec les SID activés, puis un autre avec les SID de restriction ; **les deux contrôles doivent autoriser l’accès**. Par conséquent, un SID utilisateur intéressant ou un groupe activé dans la sortie ne prouve pas à lui seul que le token peut accéder à l’objet cible.<sup>[[8]](#references)</sup>

Suivez ce processus de décision pour respecter les exigences documentées concernant les tokens et la création de processus :<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Un **token primaire** nécessite un handle avec `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` avant de pouvoir être fourni à `CreateProcessWithTokenW` ou `CreateProcessAsUserW`.
2. Convertissez un **token d’impersonation** avec `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Les tokens de niveau Identification peuvent exposer les données d’identité, mais ne peuvent pas effectuer de contrôles d’accès en tant que ce client.
3. `CreateProcessWithTokenW` nécessite `SeImpersonatePrivilege` et démarre le processus enfant dans la session de l’appelant. `CreateProcessAsUserW` utilise plutôt la session du token, mais nécessite généralement `SeIncreaseQuotaPrivilege` et peut nécessiter `SeAssignPrimaryTokenPrivilege`. Si des identifiants sont disponibles et que ces privilèges manquent, `CreateProcessWithLogonW` est l’alternative documentée.

#### Rechercher les handles de token, pas seulement les propriétaires de processus

Ouvrir le token primaire de chaque processus peut faire manquer des **tokens d’impersonation conservés en tant que handles ordinaires** dans des services et des processus broker. Une méthode réutilisable basée sur les tables de handles consiste à énumérer les handles du système, filtrer les objets token, ouvrir chaque propriétaire avec `PROCESS_DUP_HANDLE`, dupliquer le handle candidat dans le processus actuel, puis interroger les champs ci-dessus. Vérifiez que le handle dupliqué inclut `TOKEN_QUERY` et `TOKEN_DUPLICATE` ; la présence d’un handle de token ne signifie pas qu’il peut être dupliqué en un token primaire utilisable. Les processus protégés et les DACL de processus peuvent tout de même empêcher l’accès au handle du processus propriétaire.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatise l’énumération des tokens primaires de processus et des handles de token conservés. `list_token` conserve un candidat privilégié par nom d’utilisateur, tandis que `list_all_token` affiche tous les candidats. Un PID limite l’énumération à un seul processus propriétaire.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Pour l’inspection manuelle et la vérification des accès, **TokenUniverse** peut ouvrir les tokens de processus/thread, rechercher des handles de token existants, inspecter les restrictions et les sessions d’ouverture de session, dupliquer des tokens et tester plusieurs méthodes de création de processus.<sup>[[13]](#references)</sup> Pour connaître la primitive sous-jacente de handle interprocessus, voir :

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Repérer les tokens d’usurpation actifs des threads

Un thread de service peut temporairement usurper l’identité d’un client, même lorsque le **token principal du processus** appartient au compte du service. Les analyses du propriétaire du processus peuvent donc passer à côté du contexte client.<sup>[[4]](#references)</sup> TokenUniverse peut répertorier les tokens de processus/thread accessibles ; dans System Informer, consultez l’onglet **Threads** d’un processus et sa colonne **Impersonation** pour repérer les threads candidats.<sup>[[13]](#references)[[14]](#references)</sup>

Pour vérifier l’API de manière ciblée, prenez un instantané `TH32CS_SNAPTHREAD`, filtrez `THREADENTRY32.th32OwnerProcessID` selon le PID du service, puis appelez `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` et `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` pour chaque thread accessible.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` fait en sorte que la vérification d’accès à l’ouverture du token utilise le contexte du **processus** appelant, ce qui importe si le scanner lui-même usurpe une identité au niveau identification.<sup>[[17]](#references)</sup> Interrogez l’utilisateur, le type, le niveau d’usurpation et l’ID de session d’ouverture de session du token avant d’essayer le flux de duplication/création de processus décrit plus haut.<sup>[[7]](#references)</sup> Un thread peut cesser l’usurpation entre son énumération et son ouverture ; l’absence de token, les tokens anonymes, les threads protégés, les DACL des threads et les DACL des tokens peuvent empêcher la collecte.<sup>[[16]](#references)[[17]](#references)</sup> Contrairement à l’analyse des handles de token conservés par un service, cette méthode vérifie le **token actuellement attribué au thread**.

Pour découvrir une piste d’attaque qui obtient un token de thread en faisant connecter un client privilégié à votre pipe, plutôt qu’en analysant les threads existants, consultez [l’usurpation d’identité d’un client de named pipe](named-pipe-client-impersonation.md).

#### Usurper des tokens

Si vous disposez de privilèges suffisants, le module _**incognito**_ de metasploit permet facilement de **répertorier** et **d’usurper** d’autres **tokens**. Cela peut être utile pour effectuer des **actions comme si vous étiez l’autre utilisateur**. Cette technique peut également vous permettre une **élévation de privilèges**.

Quelques remarques pratiques faciles à oublier pendant une opération :<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** nécessite **`SeImpersonatePrivilege`** chez l’appelant, et le nouveau processus s’exécutera dans la **session de l’appelant**.
- **`CreateProcessAsUserW`** peut servir de solution de repli lorsque `CreateProcessWithTokenW` échoue avec `1314`, uniquement si l’appelant satisfait aux exigences de privilèges de cette fonction. C’est aussi le bon choix si le processus enfant doit s’exécuter dans la **session référencée par le token**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** renvoie un **token d’usurpation**. Convertissez-le avec **`DuplicateTokenEx(..., TokenPrimary, ...)`** avant de créer un processus. Même après la conversion, le processus obtenu ne peut pas utiliser cette ouverture de session réseau pour accéder à des partages ou imprimantes distants nécessitant une authentification : ce type d’ouverture de session ne met pas les identifiants en cache. Si vous disposez d’identifiants et avez besoin d’un accès réseau ultérieur, utilisez une ouverture de session interactive ou de type network-cleartext ; ne confondez pas cela avec `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), qui conserve l’identité locale tout en fournissant des identifiants sortants.<sup>[[18]](#references)</sup>
- Tous les tokens d’usurpation ne se valent pas : **`SecurityIdentification`** permet d’inspecter l’utilisateur, mais **pas d’agir en son nom**. Si une primitive de coercition ou un client pipe/RPC ne vous fournit qu’un token de niveau identification, vérifiez **`TokenImpersonationLevel`** et utilisez une primitive qui fournit au moins **`SecurityImpersonation`**.

#### Vol de token sans toucher à LSASS

Si vous disposez déjà d’un contexte **service** ou **SYSTEM** et qu’un **utilisateur privilégié est connecté**, voler ou dupliquer le token de cet utilisateur est souvent plus discret que de dumper **LSASS**. Dans de nombreuses intrusions réelles, cela suffit pour :<sup>[[2]](#references)</sup>

- exécuter des actions locales en tant que cet utilisateur
- accéder à des ressources distantes en tant que cet utilisateur
- effectuer des opérations AD sans extraire au préalable des identifiants réutilisables

Pour des exemples de **détournement de tokens de session/utilisateur** depuis un contexte privilégié, consultez [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). N’oubliez pas que les API telles que **`WTSQueryUserToken`** sont destinées aux **services hautement fiables** et nécessitent normalement **`LocalSystem` + `SeTcbPrivilege`** ; elles sont donc principalement utiles une fois que vous contrôlez déjà un contexte au niveau service. Pour connaître les méthodes d’obtention de **SYSTEM** liées à des privilèges spécifiques, consultez les pages ci-dessous.

### Privilèges des tokens

Découvrez quels **privilèges de token peuvent être exploités pour une élévation de privilèges :**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consultez [**la liste de tous les privilèges de token possibles et quelques définitions sur cette page externe**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Comprendre et exploiter les access tokens — Partie II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Exploiter les tokens de Windows pour compromettre Active Directory sans toucher à LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Démystifier la commande « make_token » de Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Fonctionnement du contrôle de compte d’utilisateur - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Niveaux d’usurpation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Énumération TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens restreints - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Fonction CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Fonction CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Fonction DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Demande de fonctionnalité de token de thread System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Parcourir la liste des threads - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
