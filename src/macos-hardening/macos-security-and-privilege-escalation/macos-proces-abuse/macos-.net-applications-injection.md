# Injection d'applications .Net sur macOS

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé de l'article [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Consultez-le pour plus de détails !**<sup>[[1]](#references)</sup>

## Débogage de .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Établissement d'une session de débogage** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestion de la communication entre le debugger et le processus débogué dans .NET est assurée par [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ce composant configure deux named pipes par processus .NET, comme indiqué dans [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), lesquels sont initialisés via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ces pipes portent les suffixes **`-in`** et **`-out`**.

En consultant le **`$TMPDIR`** de l'utilisateur, il est possible de trouver les FIFO de débogage disponibles pour le débogage des applications .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) est chargé de gérer la communication provenant d'un debugger. Pour initialiser une nouvelle session de débogage, un debugger doit envoyer un message via le pipe `out` en commençant par une structure `MessageHeader`, détaillée dans le code source de .NET :
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
Pour demander une nouvelle session, cette structure est remplie comme suit, en définissant le type de message sur `MT_SessionRequest` et la version du protocole sur la version actuelle :
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
Une opération de lecture sur le pipe `out` confirme la réussite ou l’échec de l’établissement de la session de debugging :
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lecture de la mémoire

Une fois qu’une session de débogage est établie, la mémoire peut être lue à l’aide du type de message [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La fonction readMemory est détaillée ci-dessous et effectue les étapes nécessaires pour envoyer une requête de lecture et récupérer la réponse :
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
La preuve de concept (POC) complète est disponible [ici](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

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
Le POC associé est disponible [ici](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Pour exécuter du code, il faut identifier une région mémoire disposant de permissions rwx, ce qui peut être effectué à l’aide de vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Il est nécessaire de trouver un emplacement où écraser un pointeur de fonction et, dans .NET Core, cela peut être réalisé en ciblant la **Dynamic Function Table (DFT)**. Cette table, détaillée dans [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), est utilisée par le runtime pour les fonctions helper de compilation JIT.

Sur les systèmes x64, le signature hunting peut être utilisé pour trouver une référence au symbole `_hlpDynamicFuncTable` dans `libcorclr.dll`.

La fonction de debugging `MT_GetDCB` fournit des informations utiles, notamment l'adresse d'une fonction helper, `m_helperRemoteStartAddr`, indiquant l'emplacement de `libcorclr.dll` dans la mémoire du processus. Cette adresse est ensuite utilisée pour commencer la recherche de la DFT et écraser un pointeur de fonction avec l'adresse du shellcode.

Le code POC complet pour l'injection dans PowerShell est accessible [ici](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Références

- [1] [Adam Chester (xpnsec) - Injection macOS via des frameworks tiers](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
