# Mythic

{{#include ../banners/hacktricks-training.md}}

## O que é o Mythic?

Mythic é um framework open-source, modular e colaborativo de command and control (C2), projetado para red teaming. Ele permite que os operadores gerenciem e implantem agents (payloads) em diferentes sistemas operacionais, incluindo Windows, Linux e macOS. O Mythic fornece uma interface de navegador para tasking de múltiplos operadores, gerenciamento de arquivos, gerenciamento de SOCKS/rpfwd e geração de payloads.

Diferentemente dos frameworks monolíticos, o próprio repositório do Mythic **não** inclui tipos de payload ou C2 profiles. Agents, wrappers e C2 profiles normalmente são instalados como componentes externos e podem ser atualizados independentemente do Mythic core.

### Instalação

Para instalar o Mythic, siga as instruções no **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Um bootstrap comum a partir do diretório do Mythic é:
```bash
sudo make
sudo ./mythic-cli start
```
Se o Mythic já estiver em execução, normalmente você pode adicionar um novo agent ou profile com `./mythic-cli install github ...` e, em seguida, reiniciar o Mythic ou simplesmente iniciar o novo componente diretamente.

### Agents

O Mythic oferece suporte a vários agents, que são os **payloads que executam tarefas nos sistemas comprometidos**. Cada agent pode ser adaptado a necessidades específicas e executado em diferentes sistemas operacionais.

Por padrão, o Mythic não tem nenhum agent instalado. Os agents da comunidade open-source estão em [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e a [**matriz de recursos da comunidade**](https://mythicmeta.github.io/overview/agent_matrix.html) é útil para verificar rapidamente os sistemas operacionais compatíveis, os formatos de payload, os wrappers e os perfis C2.

Para instalar um agent dessa organização, execute:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
A forma `sudo -E` é útil quando você está instalando a partir de um ambiente que não é root. Você pode adicionar novos agents com o comando anterior mesmo que o Mythic já esteja em execução.

### Perfis C2

Os perfis C2 no Mythic definem **como os agents se comunicam com o servidor Mythic**. Eles especificam o protocolo de comunicação, os métodos de criptografia e outras configurações. Você pode criar e gerenciar perfis C2 pela interface web do Mythic.

Por padrão, o Mythic é instalado sem perfis. No entanto, é possível baixar alguns perfis do repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) executando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Perfis atualmente relevantes para operadores:

- [`http`](https://github.com/MythicC2Profiles/http): tráfego assíncrono básico GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfego HTTP mais flexível, com múltiplos domínios de callback, rotação de fail-over/round-robin, cabeçalhos/parâmetros de consulta personalizados e transforms de mensagens (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) posicionados em cookies, cabeçalhos, parâmetros de consulta ou corpo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): configuração de mensagens HTTP orientada por JSON/TOML quando o profile estático `http` é facilmente reconhecível.

### Observações atuais sobre a plataforma

- Muitos agents e profiles públicos agora são instalados com imagens de container remotas pré-criadas.
Se você fizer fork de um componente ou aplicar um patch localmente e o Mythic continuar usando o comportamento antigo, inspecione as entradas `.env` geradas para `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; habilitar
`*_USE_BUILD_CONTEXT="true"` geralmente faz o Mythic reconstruir usando o contexto Docker local, em vez de reutilizar silenciosamente a imagem remota.
- Browser scripts são um dos recursos de maior valor do Mythic para melhorar a experiência dos operadores:
eles podem transformar a saída bruta de comandos em tabelas, visualizadores de screenshots, links de download, links de pesquisa e botões que emitem tasking subsequente diretamente pela UI. As builds atuais do Mythic permitem que cada operador mantenha seus próprios scripts, os ative ou desative globalmente ou por task, e obtenha os melhores resultados quando os agents retornam JSON estruturado em vez de plaintext. Isso é especialmente útil para workflows repetitivos de `ls`, `ps`, triagem e file-browser.
- Builds mais recentes do Mythic também oferecem suporte a tasking interativo e padrões de Push C2 que reduzem a necessidade de polling com `sleep 0` durante operações intensivas em PTY/SOCKS/rpfwd. Quando um agent/profile oferece suporte a isso, normalmente há menos overhead do que sobrecarregar o server com check-ins constantes apenas para manter um canal interativo utilizável.
- Os builders atuais do Mythic da era 3.4 têm mais consciência de contexto do que writeups antigos sugerem: os parâmetros de build agora podem ser agrupados ou ocultados com base no OS selecionado ou em outras opções de build, os payload types podem declarar se oferecem suporte a múltiplos C2 profiles ou a múltiplas instâncias do mesmo C2 em uma única build, e as divergências de parâmetros de C2 permitem que um agent oculte campos que ele realmente não implementa. Isso é importante ao alternar entre `http`, `httpx`, `smb`,
`tcp` e `websocket`, pois a superfície de build segura/válida não é mais um formulário estático e plano.
- Se você estiver criando um par customizado de agent/profile e não quiser o formato de mensagem JSON do Mythic nem a criptografia padrão no wire, use um
`translation_container`: o Mythic remove o UUID, entrega o blob criptografado e o material da chave ao translator via gRPC e espera receber bytes nativos do agent de volta. Essa é a forma adequada de oferecer suporte a protocolos binários, framing personalizado ou criptografia no lado do agent sem reescrever todo o server.
- Lembre-se de que callbacks linked/P2P não servem apenas para transportar tasking. O fluxo `get_tasking` do Mythic também pode transportar respostas, além de dados `delegates`,
`socks`, `rpfwd` e `interactive`. Na prática, um callback de egress pode atender callbacks internos e canais de pivot no mesmo loop de polling; se os child agents realizarem seus próprios check-ins periódicos, `get_delegate_tasks=false` impede que o parent consuma acidentalmente os jobs enfileirados do callback interno.

### Wrapper payloads

Wrapper payloads permitem manter a mesma lógica do agent enquanto alteram a representação em disco entregue ou persistida.

- `service_wrapper`: transforma outro payload em um executável de Windows service, o que é útil quando o caminho de execução exige um service binary válido.
- `scarecrow_wrapper`: encapsula shellcode compatível com o loader ScareCrow para gerar outputs baseados em loader, como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo é um agent de Windows escrito em C# usando o 4.0 .NET Framework, projetado para ser usado nas ofertas de treinamento da SpecterOps.

Instale-o com:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Notas atuais de build/profile

- Apollo pode atualmente emitir payloads `WinExe`, `Shellcode`, `Service` e `Source`.
- Os profiles Apollo mais usados são `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` geralmente é a opção mais flexível quando você precisa de rotação de domínio, suporte a proxy, posicionamento de mensagens personalizado e transforms de mensagens, em vez do profile `http` estático mais antigo.
- Apollo é um dos agents comunitários mais completos em recursos e atualmente expõe integrações do lado do Mythic, como browser scripts, visualizações do file/process browser, screenshots, keylogging, SOCKS, rpfwd, Push C2 e roteamento P2P.
- Apollo suporta wrapper payloads como `service_wrapper` e `scarecrow_wrapper`.
- Apollo suporta carregamento dinâmico de commands, permitindo manter o payload inicial enxuto e carregar commands adicionais ou módulos Forge posteriormente, em vez de compilar todas as capacidades de post-exploitation no primeiro build.
- Ao gerar output de shellcode, o builder atual do Apollo também expõe opções de formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) e comportamentos de bypass do Donut (`None`, `Abort on fail`, `Continue on fail`). Isso é útil se o objetivo final for reencapsular o shellcode com `service_wrapper`, `scarecrow_wrapper` ou um loader personalizado.
- `register_file` e `register_assembly` são os staging primitives para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nos builds atuais do Apollo, esses artefatos staged são armazenados no cache client-side como blobs AES256 protegidos por DPAPI.
- Os resultados de `ls` e `ps` integram-se especialmente bem com os browser scripts e o file/process browser do Mythic, tornando a triagem do operador consideravelmente mais rápida em operações colaborativas.
- Os jobs fork-and-run herdam as configurações do sacrificial process de `spawnto_x86` / `spawnto_x64`, herdam a seleção do processo pai de `ppid` e então usam o injection primitive atualmente selecionado. Na prática, isso significa que seu ajuste de OPSEC para um command frequentemente afeta `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn` ao mesmo tempo.
- Os injection backends documentados atualmente para o Apollo incluem `CreateRemoteThread`, `QueueUserAPC` (no estilo early-bird) e `NtCreateThreadEx` via syscalls. Use `get_injection_techniques` antes de realizar post-exploitation ruidosa e `set_injection_technique` se precisar trocar um primitive que entre em conflito com o alvo ou com o command que deseja executar.
- `blockdlls` afeta apenas os sacrificial processes criados para jobs de post-exploitation. Combinado com um alvo `spawnto_x64` menos suspeito que o `rundll32.exe` simples padrão, essa é uma das mudanças mais fáceis do lado do Apollo para fazer antes de executar tasking intenso de assembly/PowerShell.

Este agent possui muitos commands, o que o torna muito semelhante ao Beacon do Cobalt Strike, com alguns extras. Entre eles, ele suporta:

### Ações comuns

- `cat`: Exibe o conteúdo de um arquivo
- `cd`: Altera o diretório de trabalho atual
- `cp`: Copia um arquivo de um local para outro
- `ls`: Lista arquivos e diretórios no diretório atual ou no path especificado
- `ifconfig`: Obtém adaptadores e interfaces de rede
- `netstat`: Obtém informações sobre conexões TCP e UDP
- `pwd`: Exibe o diretório de trabalho atual
- `ps`: Lista os processos em execução no sistema-alvo (com informações adicionais)
- `jobs`: Lista todos os jobs em execução associados a tasking de longa duração
- `download`: Faz o download de um arquivo do sistema-alvo para a máquina local
- `upload`: Faz o upload de um arquivo da máquina local para o sistema-alvo
- `reg_query`: Consulta registry keys e values no sistema-alvo
- `reg_write_value`: Grava um novo value em uma registry key especificada
- `sleep`: Altera o intervalo de sleep do agent, que determina com que frequência ele faz check-in com o servidor Mythic
- E muitos outros; use `help` para ver a lista completa de commands disponíveis.

### Escalonamento de privilégios

- `getprivs`: Habilita o maior número possível de privilégios no token da thread atual
- `getsystem`: Abre um handle para o winlogon e duplica o token, escalando efetivamente os privilégios para o nível SYSTEM
- `make_token`: Cria uma nova sessão de logon e aplica-a ao agent, permitindo a impersonation de outro usuário
- `steal_token`: Rouba um primary token de outro processo, permitindo que o agent faça impersonation do usuário desse processo
- `pth`: Ataque Pass-the-Hash, permitindo que o agent se autentique como um usuário usando seu hash NTLM, sem precisar da senha em plaintext
- `mimikatz`: Executa commands do Mimikatz para extrair credenciais, hashes e outras informações sensíveis da memória ou do banco de dados SAM
- `rev2self`: Reverte o token do agent para seu primary token, removendo efetivamente os privilégios de volta ao nível original
- `ppid`: Altera o processo pai dos jobs de post-exploitation especificando um novo process ID, permitindo maior controle sobre o contexto de execução do job
- `printspoofer`: Executa commands do PrintSpoofer para contornar medidas de segurança do print spooler, permitindo escalonamento de privilégios ou execução de código
- `dcsync`: Sincroniza as chaves Kerberos de um usuário com a máquina local, permitindo password cracking offline ou outros ataques
- `ticket_cache_add`: Adiciona um ticket Kerberos à sessão de logon atual ou a uma sessão especificada, permitindo a reutilização do ticket ou impersonation

### Execução de processos

- `assembly_inject`: Permite injetar um .NET assembly loader em um processo remoto
- `blockdlls`: Impede o carregamento de DLLs não assinadas pela Microsoft nos jobs de post-exploitation
- `execute_assembly`: Executa um .NET assembly no contexto do agent
- `execute_coff`: Executa um arquivo COFF em memória, permitindo a execução in-memory de código compilado
- `execute_pe`: Executa um executável unmanaged (PE)
- `keylog_inject`: Injeta um keylogger em outro processo e transmite as teclas pressionadas de volta para a visualização de keylog do Mythic
- `screenshot` / `screenshot_inject`: Captura o desktop atual diretamente ou
injeta um screenshot assembly em um processo/sessão-alvo
- `get_injection_techniques`: Exibe as injection techniques disponíveis e a atualmente selecionada
- `inline_assembly`: Executa um .NET assembly em um AppDomain descartável, permitindo a execução temporária de código sem afetar o processo principal do agent
- `register_assembly`: Registra um .NET assembly para execução posterior
- `register_file`: Registra um arquivo no cache do agent para execução posterior por `execute_*` ou tasking de PowerShell
- `run`: Executa um binary no sistema-alvo, usando o PATH do sistema para localizar o executável
- `set_injection_technique`: Altera o injection primitive usado pelos jobs de post-exploitation
- `shinject`: Injeta shellcode em um processo remoto, permitindo a execução in-memory de código arbitrário
- `inject`: Injeta o shellcode do agent em um processo remoto, permitindo a execução in-memory do código do agent
- `spawn`: Inicia uma nova sessão do agent no executável especificado, permitindo a execução de shellcode em um novo processo
- `spawnto_x64` e `spawnto_x86`: Alteram o binary padrão usado nos jobs de post-exploitation para um path especificado, em vez de usar `rundll32.exe` sem parâmetros, que é muito ruidoso.

### Mythic Forge

Isso permite **carregar arquivos COFF/BOF** do Mythic Forge, que é um repositório de payloads e tools pré-compilados que podem ser executados no sistema-alvo. Com todos os commands que podem ser carregados, será possível realizar ações comuns executando-os no processo atual do agent como BOFs (geralmente com OPSEC melhor do que iniciar um processo separado).

Comece instalando-os com:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Em seguida, use `forge_collections` para mostrar os módulos COFF/BOF do Mythic Forge, permitindo selecioná-los e carregá-los na memória do agent para execução. Por padrão, as 2 coleções a seguir são adicionadas no Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Depois que um módulo é carregado, ele aparecerá na lista como outro comando, como `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Para BOFs, lembre-se de que o Forge **não** simplesmente passa uma única string de argumentos
para o Apollo. Ele mapeia os parâmetros do BOF para o formato de array tipado do Mythic e então
os encaminha para o fluxo `execute_coff` do Apollo. Se um BOF carregado pelo Forge apresentar
um comportamento estranho, verifique os tipos de argumentos / entrypoint esperados pelo BOF,
em vez de considerar apenas a linha de comando digitada. Observe também que o loader de BOF
mais recente do Apollo alterou o tratamento de argumentos em relação a builds muito mais antigas
da era 2.3.1; portanto, BOFs desatualizados ou coleções antigas podem falhar simplesmente porque
as expectativas de marshaling foram alteradas.

### Execução de PowerShell e scripting

- `powershell_import`: Importa um novo script PowerShell (.ps1) para o cache do agent para execução posterior
- `powershell`: Executa um comando PowerShell no contexto do agent, permitindo scripting e automação avançados
- `powerpick`: Injeta um assembly loader de PowerShell em um processo sacrificial e executa um comando PowerShell (sem logging do powershell).
- `psinject`: Executa PowerShell em um processo especificado, permitindo a execução direcionada de scripts no contexto de outro processo
- `shell`: Executa um comando de shell no contexto do agent, de forma semelhante à execução de um comando no cmd.exe

### Lateral Movement

- `jump_psexec`: Usa a técnica PsExec para realizar Lateral Movement para um novo host, copiando primeiro o executável do agent Apollo (apollo.exe) e executando-o.
- `jump_wmi`: Usa a técnica WMI para realizar Lateral Movement para um novo host, copiando primeiro o executável do agent Apollo (apollo.exe) e executando-o.
- `link` e `unlink`: Criam e encerram links P2P (por exemplo, via SMB/TCP) entre callbacks.
- `wmiexecute`: Executa um comando no sistema local ou remoto especificado usando WMI, com credenciais opcionais para impersonation.
- `net_dclist`: Recupera uma lista de domain controllers do domínio especificado, útil para identificar possíveis alvos para Lateral Movement.
- `net_localgroup`: Lista os grupos locais no computador especificado, usando localhost por padrão quando nenhum computador é especificado.
- `net_localgroup_member`: Recupera os membros de um grupo local especificado no computador local ou remoto, permitindo a enumeração de usuários em grupos específicos.
- `net_shares`: Lista os compartilhamentos remotos e sua acessibilidade no computador especificado, útil para identificar possíveis alvos para Lateral Movement.
- `socks`: Habilita um proxy compatível com SOCKS 5 na rede-alvo, permitindo o tunneling de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `rpfwd`: Começa a escutar em uma porta especificada no host-alvo e encaminha o tráfego através do Mythic para um IP e uma porta remotos, permitindo o acesso remoto a serviços na rede-alvo.
- `listpipes`: Lista todos os named pipes no sistema local, o que pode ser útil para Lateral Movement ou privilege escalation por meio da interação com mecanismos IPC.

Para as primitivas de execução WMI de baixo nível usadas por `jump_wmi` ou `wmiexecute`, consulte [WmiExec](lateral-movement/wmiexec.md). Para padrões mais amplos de pivoting, consulte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos diversos
- `help`: Exibe informações detalhadas sobre comandos específicos ou informações gerais sobre todos os comandos disponíveis no agent.
- `clear`: Marca as tasks como 'cleared', para que não possam ser coletadas pelos agents. Você pode especificar `all` para limpar todas as tasks ou `task Num` para limpar uma task específica.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon é um agent em Golang que compila para executáveis **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Observações atuais sobre build/profile

- Os builds atuais do Poseidon têm como alvo Linux e macOS em `x86_64` e `arm64`.
- Os formatos de saída suportados incluem executáveis nativos, além de formatos no estilo de bibliotecas compartilhadas, como `dylib` e `so`.
- O Poseidon suporta `http`, `websocket`, `tcp` e `dynamichttp`, e os builders atuais expõem configurações de multi-egress, como `egress_order` e limites de failover.
- Os metadados atuais de capabilities do Poseidon também anunciam browser scripts, integração com browser de arquivos/processos, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd e P2P, permitindo que ele funcione como um verdadeiro nó de pivot Linux/macOS, em vez de apenas um remote shell simples.
- Vale verificar opções em tempo de build, como `proxy_bypass` e `garble`, quando você precisar de um comportamento de rede mais limpo ou de obfuscation adicional do binário Go.
- `pty` é um dos comandos mais úteis adicionados recentemente para melhorar a qualidade de vida em operações Linux/macOS, pois abre um PTY interativo e pode expor uma porta do lado do Mythic para uma interação mais completa com o terminal, sem recorrer ao antigo workaround `sleep 0` + SOCKS.
- A documentação atual do Poseidon é especialmente interessante para tradecraft voltado a macOS: `jxa` executa JavaScript for Automation em memória, `screencapture` captura o desktop do usuário logado, `clipboard_monitor` transmite alterações no pasteboard, `execute_library` carrega uma dylib local e chama uma função dela, e `libinject` força um processo remoto a carregar uma dylib armazenada em disco.
- Para jobs de longa duração, lembre-se de que o Poseidon executa atividades de post-exploitation em goroutines/threads cooperativas, que não podem ser encerradas à força. A documentação também observa explicitamente que atualmente não há obfuscation integrada do agent, portanto o tradecraft no nível de build/profile é mais importante do que em implants comerciais fortemente obfuscados.

Para tradecraft específico de macOS em operações baseadas no Mythic, abuso de JAMF ou ideias de MDM-as-C2, consulte [Red Teaming de macOS](../macos-hardening/macos-red-teaming/README.md).

Quando usado em Linux ou macOS, ele possui alguns comandos interessantes:

### Ações comuns

- `cat`: Exibe o conteúdo de um arquivo
- `cd`: Altera o diretório de trabalho atual
- `chmod`: Altera as permissões de um arquivo
- `config`: Exibe a configuração atual e informações do host
- `cp`: Copia um arquivo de um local para outro
- `curl`: Executa uma única requisição web com headers e método opcionais
- `upload`: Faz upload de um arquivo para o alvo
- `download`: Faz download de um arquivo do sistema-alvo para a máquina local
- E muitos outros

### Buscar informações sensíveis

- `triagedirectory`: Encontra arquivos interessantes dentro de um diretório em um host, como arquivos sensíveis ou credenciais.
- `getenv`: Obtém todas as variáveis de ambiente atuais.

### Tradecraft específico de macOS

- `jxa`: Executa JavaScript for Automation em memória via `OSAScript`, sendo útil para post-exploitation nativa de macOS sem criar arquivos de script separados.
- `clipboard_monitor`: Consulta o pasteboard e reporta as alterações ao Mythic, sendo útil para workflows de roubo de credenciais/tokens que dependem de copiar/colar.
- `screencapture`: Captura o desktop do usuário no macOS.
- `execute_library`: Carrega uma dylib do disco e chama uma função exportada específica.
- `libinject`: Injeta um stub de shellcode que força outro processo do macOS a carregar uma dylib do disco.
- `persist_launchd`: Cria persistência de LaunchAgent / LaunchDaemon diretamente a partir do agent.

### Movimentação lateral

- `ssh`: Conecta-se via SSH ao host usando as credenciais designadas e abre um PTY sem iniciar o ssh.
- `sshauth`: Conecta-se via SSH aos hosts especificados usando as credenciais designadas. Você também pode usá-lo para executar um comando específico nos hosts remotos via SSH ou para copiar arquivos usando SCP.
- `link_tcp`: Estabelece um link com outro agent via TCP, permitindo comunicação direta entre agents.
- `link_webshell`: Estabelece um link com um agent usando o perfil P2P webshell, permitindo acesso remoto à interface web do agent.
- `rpfwd`: Inicia ou interrompe um Reverse Port Forward, permitindo acesso remoto a serviços na rede-alvo.
- `socks`: Inicia ou interrompe um proxy SOCKS5 na rede-alvo, permitindo o tunneling de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `portscan`: Faz a varredura de hosts em busca de portas abertas, sendo útil para identificar possíveis alvos para movimentação lateral ou outros ataques.

### Execução de processos

- `shell`: Executa um único comando shell via /bin/sh, permitindo a execução direta de comandos no sistema-alvo.
- `run`: Executa um comando a partir do disco com argumentos, permitindo a execução de binários ou scripts no sistema-alvo.
- `pty`: Abre um PTY interativo, permitindo a interação direta com o shell no sistema-alvo.






## Referências

- [Matriz de capabilities dos Agents da Comunidade Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [README do Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Destaques do Mythic v3.2: Interactive Tasking, Push C2 e Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Documentação do Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Atualizações do Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transformando operações de Red Team com os recursos ocultos do Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
