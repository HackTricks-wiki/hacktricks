# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ va charger automatiquement chaque DLL de plugin trouvée dans ses sous-dossiers `plugins` au démarrage. Déposer un plugin malveillant dans n'importe quelle **installation Notepad++ inscriptible** permet l'exécution de code dans `notepad++.exe` à chaque démarrage de l'éditeur, ce qui peut être abusé pour la **persistence**, une **initial execution** discrète, ou comme **in-process loader** si l'éditeur est lancé avec des privilèges élevés.

## Writable plugin locations
- Installation standard: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (requiert généralement des droits administrateur pour écrire).
- Options écriturables pour utilisateurs à faible privilège:
- Utiliser le **portable Notepad++ build** dans un dossier écrivable par l'utilisateur.
- Copier `C:\Program Files\Notepad++` vers un chemin contrôlé par l'utilisateur (par ex., `%LOCALAPPDATA%\npp\`) et lancer `notepad++.exe` depuis là.
- Chaque plugin obtient son propre sous-dossier sous `plugins` et est chargé automatiquement au démarrage ; les entrées de menu apparaissent sous **Plugins**.

## Plugin load points (execution primitives)
Notepad++ attend des **fonctions exportées** spécifiques. Celles-ci sont toutes appelées durant l'initialisation, fournissant plusieurs surfaces d'exécution :
- **`DllMain`** — s'exécute immédiatement lors du chargement de la DLL (premier point d'exécution).
- **`setInfo(NppData)`** — appelé une fois au chargement pour fournir les handles de Notepad++; endroit typique pour enregistrer les éléments de menu.
- **`getName()`** — retourne le nom du plugin affiché dans le menu.
- **`getFuncsArray(int *nbF)`** — retourne les commandes du menu ; même si vide, elle est appelée au démarrage.
- **`beNotified(SCNotification*)`** — reçoit les événements de l'éditeur (ouverture/modification de fichier, événements UI) pour des déclencheurs continus.
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestionnaire de messages, utile pour des échanges de données volumineux.
- **`isUnicode()`** — drapeau de compatibilité vérifié au chargement.

La plupart des exports peuvent être implémentés comme des **stubs** ; l'exécution peut se produire depuis `DllMain` ou n'importe quel callback ci-dessus pendant l'autoload.

## Minimal malicious plugin skeleton
Compilez une DLL avec les exports attendus et placez-la dans `plugins\\MyNewPlugin\\MyNewPlugin.dll` sous un dossier Notepad++ écrivable :
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Compiler la DLL (Visual Studio/MinGW).
2. Créer le sous-dossier de plugin sous `plugins` et y déposer la DLL.
3. Redémarrer Notepad++; la DLL est chargée automatiquement, exécutant `DllMain` et les callbacks suivants.

## Reflective loader plugin pattern
Un plugin malveillant peut transformer Notepad++ en un **reflective DLL loader** :
- Présenter une interface utilisateur/menu minimal (par ex., "LoadDLL").
- Accepter un **chemin de fichier** ou une **URL** pour récupérer une DLL payload.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Avantage : réutiliser un processus GUI apparemment bénin au lieu de lancer un nouveau loader ; le payload hérite de l'intégrité de `notepad++.exe` (y compris les contextes élevés).
- Inconvénients : déposer une **unsigned plugin DLL** sur le disque est bruyant ; envisager de se greffer sur des plugins de confiance existants si présents.

## Notes de détection et de durcissement
- Bloquer ou surveiller les **écritures dans les répertoires de plugins de Notepad++** (y compris les copies portables dans les profils utilisateur) ; activer Controlled Folder Access ou l'application allowlisting.
- Alerter sur les **nouvelles DLLs non signées** sous `plugins` et sur une activité inhabituelle de **processus enfants / réseau** provenant de `notepad++.exe`.
- Imposer l'installation de plugins via **Plugins Admin** uniquement, et restreindre l'exécution des copies portables depuis des chemins non approuvés.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
