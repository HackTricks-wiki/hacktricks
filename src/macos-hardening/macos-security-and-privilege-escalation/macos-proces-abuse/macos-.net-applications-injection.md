# Injection dans les applications .Net de macOS

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé de l'article [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Consultez-le pour plus de détails !**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 et les versions ultérieures prennent en charge la variable d'environnement `DOTNET_STARTUP_HOOKS`. Chaque chemin doit identifier un managed assembly contenant un type global `StartupHook` avec une méthode `public static void Initialize()`. Le host charge les assemblies et appelle leurs initializers de manière synchrone avant le point d'entrée `Main` de l'application, ce qui fournit un contrôle de l'environnement ainsi qu'une primitive directe d'exécution de code pre-main via une DLL lisible.<sup>[[2]](#references)</sup>
```csharp
// StartupHook.cs — compile as a class-library assembly.
using System.IO;

internal class StartupHook
{
public static void Initialize()
{
File.WriteAllText("/tmp/dotnet-startup-hook-executed", "executed\n");
}
}
```

```bash
dotnet new classlib -n StartupHookPayload -f net8.0
cp StartupHook.cs StartupHookPayload/Class1.cs
dotnet build StartupHookPayload -c Release

DOTNET_STARTUP_HOOKS="$PWD/StartupHookPayload/bin/Release/net8.0/StartupHookPayload.dll" \
dotnet /path/to/TargetApplication.dll
```
L’assembly du hook doit être compatible avec le runtime et les dépendances de l’application. Les chemins relatifs contenant des séparateurs de répertoires sont rejetés ; utilisez un chemin absolu ou un nom d’assembly pouvant être résolu depuis le contexte de chargement par défaut. Les startup hooks sont désactivés par défaut dans les applications trimmed, et les custom native hosts peuvent fournir directement les propriétés du runtime au lieu d’hériter de l’environnement.<sup>[[2]](#references)</sup>

Les launchers défensifs doivent effacer `DOTNET_STARTUP_HOOKS`, empêcher les écritures non fiables dans les chemins des assemblies de l’application et des assemblies partagés, et tester séparément les déploiements self-contained et trimmed.

## Débogage .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Établissement d’une session de débogage** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestion de la communication entre le debugger et le debuggee dans .NET est assurée par [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ce composant configure deux named pipes par processus .NET, comme indiqué dans [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), lesquels sont initialisés via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ces pipes portent les suffixes **`-in`** et **`-out`**.

En consultant le **`$TMPDIR`** de l’utilisateur, il est possible de trouver les FIFO de débogage disponibles pour le débogage des applications .NET.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) est chargé de gérer la communication provenant d’un debugger. Pour initier une nouvelle session de débogage, un debugger doit envoyer un message via le pipe `out` commençant par une structure `MessageHeader`, détaillée dans le code source .NET :
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Pour demander une nouvelle session, cette structure est renseignée comme suit, en définissant le type de message sur `MT_SessionRequest` et la version du protocole sur la version actuelle :
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Cet en-tête est ensuite envoyé à la cible à l’aide de l’appel système `write`, suivi de la structure `sessionRequestData` contenant un GUID pour la session :
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Une opération de lecture sur le pipe `out` confirme la réussite ou l’échec de l’établissement de la session de débogage :
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lecture de la mémoire

Une fois qu’une session de debugging est établie, la mémoire peut être lue à l’aide du type de message [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La fonction readMemory est détaillée et effectue les étapes nécessaires pour envoyer une requête de lecture et récupérer la réponse :
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
La preuve de concept complète (POC) est disponible [ici](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Écriture en mémoire

De même, il est possible d’écrire en mémoire à l’aide de la fonction `writeMemory`. Le processus consiste à définir le type de message sur `MT_WriteMemory`, à spécifier l’adresse et la longueur des données, puis à envoyer les données :
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
The associated POC est disponible [ici](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Pour exécuter du code, il faut identifier une région mémoire avec des permissions rwx, ce qui peut être fait à l’aide de vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Localiser un emplacement où écraser un pointeur de fonction est nécessaire. Dans .NET Core, cela peut être fait en ciblant la **Dynamic Function Table (DFT)**. Cette table, détaillée dans [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), est utilisée par le runtime pour les fonctions helper de compilation JIT.

Sur les systèmes x64, le signature hunting peut être utilisé pour trouver une référence au symbole `_hlpDynamicFuncTable` dans `libcorclr.dll`.

La fonction de débogage `MT_GetDCB` fournit des informations utiles, notamment l’adresse d’une fonction helper, `m_helperRemoteStartAddr`, indiquant l’emplacement de `libcorclr.dll` dans la mémoire du processus. Cette adresse est ensuite utilisée pour commencer une recherche de la DFT et écraser un pointeur de fonction avec l’adresse du shellcode.

Le code POC complet pour l’injection dans PowerShell est accessible [ici](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Injection macOS via des frameworks tiers](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Conception du host startup hook de .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
