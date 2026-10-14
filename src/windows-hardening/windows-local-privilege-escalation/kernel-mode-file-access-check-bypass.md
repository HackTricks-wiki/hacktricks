# Contournements des contrôles d’accès aux fichiers en mode kernel

{{#include ../../banners/hacktricks-training.md}}

## Schéma de pilote vulnérable

Un pilote ne préserve pas la frontière de sécurité d’un appelant simplement en usurpant son identité. Les ouvertures d’objets en mode kernel contournent normalement les contrôles d’accès. `OBJ_KERNEL_HANDLE` rend uniquement le handle obtenu accessible depuis le mode kernel. Lorsqu’un pilote ouvre ou manipule un objet pour le compte du mode utilisateur, il doit également utiliser `OBJ_FORCE_ACCESS_CHECK` afin que l’Object Manager évalue l’accès demandé par rapport au token effectif.<sup>[[3]](#references)[[4]](#references)</sup>

Examinez les IOCTL de gestion des fichiers et les callbacks de création à la recherche de cette séquence :<sup>[[3]](#references)[[4]](#references)</sup>

1. Le mode utilisateur fournit un chemin, un handle source, l’accès souhaité ou le type d’opération.
2. Le pilote usurpe l’identité de l’appelant, mais appelle `IoCreateFileEx`, `ZwCreateFile` ou une routine similaire sans `OBJ_FORCE_ACCESS_CHECK`.
3. Un handle de fichier ou de répertoire réservé au kernel est enregistré dans l’état associé au handle.
4. Une opération ultérieure décide s’il faut usurper l’identité à partir d’un état influencé par l’attaquant, comme le masque d’accès demandé lors de la première ouverture.
5. La branche privilégiée effectue un renommage ou une création de lien avec une classe d’informations `BypassAccessCheck`.

Il s’agit d’une **primitive de confused deputy sur les fichiers**, et pas nécessairement d’une corruption mémoire. Une inversion d’état particulièrement dangereuse consiste à « usurper l’identité si une écriture est demandée ; rester privilégié si aucune écriture n’est demandée ». Dans cette conception, demander délibérément un accès en lecture seule peut ouvrir la voie la plus puissante.<sup>[[3]](#references)</sup>

## Exemple vSMB : racine privilégiée et renommage privilégié

`storvsp.sys` implémente Virtual Server Message Block (vSMB). Lorsque la fonctionnalité **Virtual Machine Platform** est activée, le mode utilisateur peut accéder à `\Device\STORVSP` via `\\.\STORVSP`. Un chemin de système de fichiers vSMB a la forme `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 et CVE-2025-64673 ont montré comment deux décisions de contrôle d’accès incohérentes pouvaient transformer cette interface en élévation de privilèges locale.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

La correspondance entre les fonctions de la source et les CVE provient de la rétro-ingénierie du binaire corrigé, et non du code source de Microsoft. Les chercheurs avertissent que les deux identifiants pourraient correspondre aux fonctions opposées.<sup>[[3]](#references)</sup>

### 1. Créer un partage en lecture seule dont la racine est un répertoire protégé

Le chemin de création vulnérable enregistrait les droits demandés dans des indicateurs persistants tels que `HasReadAccess`, `HasWriteAccess` et `HasAppendAccess`. Il ouvrait ensuite le chemin sous-jacent avec `OBJ_KERNEL_HANDLE`, mais sans `OBJ_FORCE_ACCESS_CHECK`. L’usurpation d’identité tentée ne garantissait donc pas que l’ouverture du fichier respecte les permissions NTFS de l’appelant.<sup>[[3]](#references)[[4]](#references)</sup>

Demandez uniquement `FILE_READ_DATA`. Cela laisse `HasWriteAccess` désactivé tout en obtenant un partage dont la racine interne est un répertoire protégé :<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

L’artefact important n’est pas un handle de répertoire System32 en mode utilisateur. Il s’agit d’un handle de périphérique vSMB associé à l’état du driver, qui contient un handle racine du kernel privilégié.<sup>[[3]](#references)</sup>

### 2. Exploiter le décalage d’état pour remplacer un fichier protégé

L’IOCTL `0x240330` acceptait un handle de fichier source, une classe d’informations et un buffer d’informations de longueur variable :<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Le handler vulnérable acceptait `FileRenameInformation`, `FileLinkInformation` et `FileRenameInformationEx`. Pour un chemin de renommage normal, il séparait le chemin du répertoire parent du composant final, puis ouvrait le répertoire parent relativement au handle racine stocké. Cette ouverture utilisait à nouveau `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE`, sans `OBJ_FORCE_ACCESS_CHECK`. Un `RootDirectory` non nul fourni par l’attaquant dans la structure de renommage était rejeté ; le pilote fournissait donc son propre handle de répertoire privilégié.<sup>[[3]](#references)</sup>

La branche exploitable était sélectionnée en **ne demandant pas l’accès en écriture pendant l’étape 1** :<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1` : usurper le contexte de sécurité racine enregistré.
- `HasWriteAccess == 0` : ignorer l’usurpation d’identité et convertir `FileRenameInformation` ou `FileRenameInformationEx` en sa variante `BypassAccessCheck`.

Le handler dupliquait le handle source fourni par l’attaquant dans `PsInitialSystemProcess`, le référençait comme objet fichier, installait le handle de répertoire cible privilégié dans la structure de renommage, puis appelait `ZwSetInformationFile`. Avec `ReplaceIfExists = TRUE`, un fichier contrôlé par l’appelant pouvait donc remplacer un fichier existant sous la racine protégée.<sup>[[3]](#references)</sup>

Lors de l’analyse d’un handler similaire, suivez **à la fois la provenance des handles et le contexte de sécurité** dans chaque branche. La validation des entrées, les vérifications de dépassement d’entier, `IO_STOP_ON_SYMLINK` et la restriction des classes d’informations acceptées ne compensent pas la combinaison d’un handle racine privilégié et d’une opération qui contourne les vérifications d’accès.<sup>[[3]](#references)</sup>

## De l’écriture protégée à l’exécution en SYSTEM

Un mécanisme de remplacement de fichier protégé permet l’exécution de code lorsqu’un processus privilégié charge ensuite le module remplacé. Dans la chaîne présentée, la destination était `C:\Windows\System32\wuapi.dll`. L’activation de la classe COM de serveur local `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` pour l’interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}`, suivie de l’appel à `IWaaSRemediation::LaunchDetectionOnly()`, amenait un processus SYSTEM à charger cette DLL.<sup>[[3]](#references)</sup>

Cet appel COM est un **déclencheur d’activation**, et non du [COM registry hijacking](com-hijacking.md). Le mécanisme d’écriture de fichier fournit le module placé, et le chargeur privilégié fournit l’exécution. Pour d’autres chaînes reposant sur une écriture protégée, identifiez l’image exacte, le chemin de la DLL, la politique de signature, l’architecture, les fonctions exportées et le déclencheur fiable avant de choisir une cible. Consultez [l’enchaînement d’une écriture de fichier arbitraire avec le DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) pour la méthode générale d’analyse du chargeur.<sup>[[3]](#references)</sup>

### Transférer un token de Session 0 vers le bureau interactif

Une charge utile chargée par un service s’exécute normalement dans la Session 0. Pour créer un processus interactif, elle peut obtenir la session de la console active avec `WTSGetActiveConsoleSessionId`, activer les privilèges requis du token, dupliquer le token SYSTEM actuel en tant que token principal et définir son `TokenSessionId` sur la session active. `CreateProcessAsUserW` utilise ensuite ce token avec `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` est requis pour définir l’ID de session d’un token dans ce scénario. La station de fenêtres interactive et le bureau doivent également accorder l’accès au token. Voir [duplication de token depuis la Session 0](sedebug-+-seimpersonate-copy-token.md) pour le workflow plus général de copie de token.<sup>[[3]](#references)[[5]](#references)</sup>

## Conseils de correctif et de revue

Les mises à jour de Microsoft de décembre 2025 ont corrigé la chaîne présentée. La rétro-ingénierie a révélé que le chemin de création vSMB corrigé rejette les appelants non fiables qui demandent la racine d’un partage sans `FILE_WRITE_DATA`. Des contrôles d’accès forcés ont également été ajoutés aux opérations concernées. Cela bloque l’inversion d’état avant qu’un appelant non privilégié puisse obtenir la racine privilégiée.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Pour le code des drivers, appliquez ces règles :<sup>[[3]](#references)[[4]](#references)</sup>

- Ajoutez `OBJ_FORCE_ACCESS_CHECK` chaque fois qu’un objet est ouvert à la demande d’une requête en mode utilisateur. Ne considérez pas `OBJ_KERNEL_HANDLE` comme un mécanisme de contrôle d’autorisation.<sup>[[4]](#references)</sup>
- Capturez et validez le mode du demandeur ainsi que le contexte de sécurité effectif. Ne laissez pas les droits demandés sélectionner une branche d’exécution plus privilégiée.
- Validez les handles utilisateur avec le type d’objet, le masque d’accès et `UserMode` appropriés. Dupliquer un handle dans le processus système ne valide pas l’autorité de l’opération demandée.
- Faites en sorte que la résolution de la cible soit relative à un handle de confiance, mais assurez-vous que ce handle de confiance a lui-même été ouvert avec le contrôle d’accès imposé au demandeur.
- Évitez les classes `File*BypassAccessCheck` pour les opérations déclenchées par l’utilisateur. Si le code interne en a réellement besoin, protégez ce chemin par une décision d’autorisation indépendante des indicateurs d’accès contrôlés par l’utilisateur.
- Appliquez les correctifs aux systèmes concernés. La surface vulnérable est pertinente lorsque Virtual Machine Platform charge `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Du partage virtuel au shell physique : exploiter le contrôle d’accès incohérent de Windows pour une LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Handles d’objet](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Fonction CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
