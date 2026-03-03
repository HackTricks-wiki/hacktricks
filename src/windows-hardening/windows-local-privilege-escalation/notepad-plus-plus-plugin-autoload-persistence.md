# Notepad++ Autoload des plugins Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ va **autoload every plugin DLL found under its `plugins` subfolders`** au démarrage. Déposer un plugin malveillant dans toute **writable Notepad++ installation** donne une exécution de code à l'intérieur de `notepad++.exe` à chaque démarrage de l'éditeur, ce qui peut être abusé pour **persistence**, une **initial execution** discrète, ou comme un **in-process loader** si l'éditeur est lancé avec des privilèges élevés.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (généralement nécessite des droits administrateur pour écrire).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ attend des **exported functions** spécifiques. Celles-ci sont toutes appelées durant l'initialisation, offrant plusieurs surfaces d'exécution :
- **`DllMain`** — s'exécute immédiatement au chargement de la DLL (premier point d'exécution).
- **`setInfo(NppData)`** — appelé une fois au chargement pour fournir les handles de Notepad++; endroit typique pour enregistrer des éléments de menu.
- **`getName()`** — retourne le nom du plugin affiché dans le menu.
- **`getFuncsArray(int *nbF)`** — retourne les commandes de menu ; même si vide, elle est appelée au démarrage.
- **`beNotified(SCNotification*)`** — reçoit les événements de l'éditeur (ouverture/modification de fichier, événements UI) pour des déclencheurs continus.
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestionnaire de messages, utile pour des échanges de données plus volumineux.
- **`isUnicode()`** — flag de compatibilité vérifié au chargement.

La plupart des exports peuvent être implémentés comme des **stubs** ; l'exécution peut survenir depuis `DllMain` ou n'importe quel callback ci‑dessus lors de l'autoload.

## Minimal malicious plugin skeleton
Compilez une DLL avec les exports attendus et placez-la dans `plugins\\MyNewPlugin\\MyNewPlugin.dll` sous un dossier Notepad++ inscriptible :
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
2. Créez un sous-dossier pour le plugin dans `plugins` et déposez-y la DLL.
3. Redémarrez Notepad++; la DLL est chargée automatiquement, exécutant `DllMain` et les callbacks subséquents.

## Reflective loader plugin pattern
Un plugin malveillant peut transformer Notepad++ en un **reflective DLL loader** :
- Présenter une UI minimale/une entrée de menu (p. ex., "LoadDLL").
- Accepter un **chemin de fichier** ou une **URL** pour récupérer une payload DLL.
- Mapper la DLL de façon reflectif dans le processus courant et invoquer un point d'entrée exporté (p. ex., une fonction loader à l'intérieur de la DLL récupérée).
- Avantage : réutiliser un processus GUI apparemment bénin au lieu de lancer un nouveau loader ; le payload hérite de l'intégrité de `notepad++.exe` (y compris les contextes élevés).
- Inconvénients : déposer une **unsigned plugin DLL** sur le disque est bruyant ; envisager de se greffer sur des plugins de confiance existants si présents.

## Notes de détection et de durcissement
- Bloquer ou surveiller les **écritures dans les répertoires de plugin de Notepad++** (y compris les copies portables dans les profils utilisateur) ; activer Controlled Folder Access ou l'allowlisting d'applications.
- Alerter sur les **nouvelles unsigned DLLs** sous `plugins` et sur les **processus enfants/activité réseau** inhabituels émanant de `notepad++.exe`.
- Imposer l'installation des plugins uniquement via **Plugins Admin**, et restreindre l'exécution des copies portables depuis des chemins non fiables.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
