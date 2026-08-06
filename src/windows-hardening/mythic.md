# Mythic

{{#include ../banners/hacktricks-training.md}}

## O que é o Mythic?

Mythic é um framework open-source, modular e colaborativo de command and control (C2), desenvolvido para red teaming. Ele permite que operadores gerenciem e implantem agentes (payloads) em diferentes sistemas operacionais, incluindo Windows, Linux e macOS. O Mythic fornece uma UI no navegador para tasking multioperador, gerenciamento de arquivos, gerenciamento de SOCKS/rpfwd e geração de payloads.

Diferentemente dos frameworks monolíticos, o próprio repositório do Mythic **não** inclui tipos de payload ou perfis de C2. Agentes, wrappers e perfis de C2 normalmente são instalados como componentes externos e podem ser atualizados independentemente do Mythic core.

### Instalação

Para instalar o Mythic, siga as instruções no **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Um bootstrap comum a partir do diretório do Mythic é:
```bash
sudo make
sudo ./mythic-cli start
```
Se o Mythic já estiver em execução, normalmente você pode adicionar um novo agent ou profile com `./mythic-cli install github ...` e, em seguida, reiniciar o Mythic ou iniciar diretamente apenas o novo componente.

### Agents

O Mythic oferece suporte a vários agents, que são os **payloads que executam tarefas nos sistemas comprometidos**. Cada agent pode ser adaptado a necessidades específicas e executado em diferentes sistemas operacionais.

Por padrão, o Mythic não possui agents instalados. Os agents da comunidade open-source estão em [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e a [**matriz de recursos da comunidade**](https://mythicmeta.github.io/overview/agent_matrix.html) é útil para verificar rapidamente os sistemas operacionais, formatos de payload, wrappers e perfis C2 compatíveis.<sup>[[1]](#references)</sup>

Para instalar um agent dessa organização, execute:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
A forma `sudo -E` é útil quando você está instalando a partir de um ambiente que não é root. Você pode adicionar novos agents com o comando anterior mesmo que o Mythic já esteja em execução.

### C2 Profiles

Os C2 profiles no Mythic definem **como os agents se comunicam com o servidor Mythic**. Eles especificam o protocolo de comunicação, os métodos de encryption e outras configurações. Você pode criar e gerenciar C2 profiles pela interface web do Mythic.

Por padrão, o Mythic é instalado sem profiles, no entanto, é possível baixar alguns profiles do repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) executando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Perfis atualmente relevantes para operadores a serem considerados:

- [`http`](https://github.com/MythicC2Profiles/http): tráfego assíncrono GET/POST básico.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfego HTTP mais flexível, com vários domínios de callback, rotação de fail-over/round-robin, cabeçalhos/parâmetros de consulta personalizados e transformações de mensagem (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inseridas em cookies, cabeçalhos, parâmetros de consulta ou corpo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): modelagem de mensagens HTTP orientada por JSON/TOML quando o perfil estático `http` é muito reconhecível.

### Observações atuais sobre a plataforma

- Muitos agents e perfis públicos agora são instalados com imagens de container remotas pré-compiladas.
Se você fizer fork de um componente ou aplicar um patch localmente e o Mythic continuar usando o comportamento antigo, inspecione as entradas `.env` geradas para `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; habilitar
`*_USE_BUILD_CONTEXT="true"` normalmente faz o Mythic recompilar usando o contexto Docker local, em vez de reutilizar silenciosamente a imagem remota.
- Browser scripts são um dos recursos de maior valor do Mythic para melhorar a experiência dos operadores: eles podem transformar a saída bruta de comandos em tabelas, visualizadores de screenshots, links de download, links de pesquisa e botões que emitem tasking subsequente diretamente pela UI. As compilações atuais do Mythic permitem que cada operador mantenha seus próprios scripts, ative-os globalmente ou por task, e obtenha os melhores resultados quando os agents retornam JSON estruturado em vez de plaintext. Isso é especialmente útil para fluxos de trabalho repetitivos envolvendo `ls`, `ps`, triage e file-browser.<sup>[[4]](#references)[[6]](#references)</sup>
- As compilações mais recentes do Mythic também oferecem suporte a interactive tasking e padrões Push C2, reduzindo a necessidade de polling com `sleep 0` durante operações intensivas em PTY/SOCKS/rpfwd. Quando um agent/profile oferece suporte a isso, normalmente há menos overhead do que bombardear o servidor com check-ins constantes apenas para manter um canal interativo utilizável.<sup>[[3]](#references)</sup>
- Os builders atuais do Mythic da era 3.4 têm mais consciência de contexto do que writeups antigos indicam: os parâmetros de build agora podem ser agrupados ou ocultados com base no sistema operacional selecionado ou em outras opções de build; os tipos de payload podem declarar se oferecem suporte a vários perfis C2 ou a várias instâncias do mesmo C2 em um único build; e as divergências de parâmetros C2 permitem que um agent oculte campos que ele não implementa de fato. Isso é importante ao alternar entre `http`, `httpx`, `smb`,
`tcp` e `websocket`, pois a superfície de build segura/válida não é mais um formulário estático e plano.<sup>[[5]](#references)</sup>
- Se você estiver criando um par customizado de agent/profile e não quiser o formato de mensagem JSON do Mythic ou a criptografia padrão no wire, use um
`translation_container`: o Mythic remove o UUID, entrega o blob criptografado e o material de chave ao translator via gRPC e espera receber bytes nativos do agent de volta. Essa é a maneira adequada de oferecer suporte a protocolos binários, framing customizado ou criptografia no lado do agent sem reescrever todo o servidor.
- Lembre-se de que callbacks linked/P2P não servem apenas para transportar tasking. O fluxo `get_tasking` do Mythic também pode transportar responses, além de `delegates`,
`socks`, `rpfwd` e dados `interactive`. Na prática, um callback de egress pode atender callbacks internos e canais de pivot no mesmo loop de polling; se os child agents realizarem seus próprios check-ins periódicos, `get_delegate_tasks=false` impede que o parent consuma acidentalmente os jobs enfileirados do callback interno.

### Payloads Wrapper

Wrapper payloads permitem manter a mesma lógica do agent enquanto alteram a representação em disco que é entregue ou persistida.

- `service_wrapper`: transforma outro payload em um executável de Windows na forma de um serviço, o que é útil quando o caminho de execução exige um service binary válido.
- `scarecrow_wrapper`: encapsula shellcode compatível com o loader ScareCrow para gerar outputs baseados em loader, como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo é um agent para Windows escrito em C# usando o .NET Framework 4.0, projetado para ser usado nas ofertas de treinamento da SpecterOps.<sup>[[2]](#references)</sup>

Instale-o com:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Notas atuais de build/profile

- Apollo pode atualmente emitir payloads `WinExe`, `Shellcode`, `Service` e `Source`.
- Os profiles Apollo mais usados são `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` geralmente é a opção mais flexível quando você precisa de rotação de domínio, suporte a proxy, posicionamento de mensagens personalizado e transforms de mensagens, em vez do antigo profile `http` estático.
- Apollo é um dos agents comunitários mais completos em termos de recursos e atualmente expõe integrações do lado do Mythic, como browser scripts, visualizações do file/process browser, screenshots, keylogging, SOCKS, rpfwd, Push C2 e roteamento P2P.
- Apollo suporta wrapper payloads, como `service_wrapper` e `scarecrow_wrapper`.
- Apollo suporta carregamento dinâmico de comandos, permitindo manter o payload inicial enxuto e carregar comandos ou módulos Forge adicionais posteriormente, em vez de compilar todas as capacidades de post-exploitation no primeiro build.
- Ao gerar uma saída shellcode, o builder atual do Apollo também expõe opções de formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) e comportamento de bypass do Donut (`None`, `Abort on fail`, `Continue on fail`). Isso é útil se o objetivo final for reencapsular o shellcode com `service_wrapper`, `scarecrow_wrapper` ou um loader personalizado.
- `register_file` e `register_assembly` são as primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nos builds atuais do Apollo, esses artefatos staged são armazenados em cache no cliente como blobs AES256 protegidos por DPAPI.
- Os resultados de `ls` e `ps` integram-se especialmente bem com os browser scripts e o file/process browser do Mythic, tornando a triagem do operador consideravelmente mais rápida em operações colaborativas.
- Os jobs fork-and-run herdam as configurações do processo sacrificial de `spawnto_x86` / `spawnto_x64`, herdam a seleção do processo pai de `ppid` e, em seguida, usam a primitive de injeção atualmente selecionada. Na prática, isso significa que seu ajuste de OPSEC para um comando frequentemente afeta `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn` ao mesmo tempo.
- Os backends de injeção do Apollo atualmente documentados incluem `CreateRemoteThread`, `QueueUserAPC` (no estilo early-bird) e `NtCreateThreadEx` via syscalls. Use `get_injection_techniques` antes de executar post-exploitation mais ruidoso e `set_injection_technique` se precisar trocar uma primitive que entre em conflito com o alvo ou com o comando que você deseja executar.
- `blockdlls` afeta apenas processos sacrificiais criados para jobs de post-exploitation. Combinado com um alvo `spawnto_x64` menos suspeito que o `rundll32.exe` simples padrão, essa é uma das mudanças mais fáceis do lado do Apollo para realizar antes de executar tasking pesado de assembly/PowerShell.

Este agent possui muitos comandos que o tornam muito semelhante ao Beacon do Cobalt Strike, com alguns extras. Entre eles, ele suporta:

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
- `download`: Baixa um arquivo do sistema-alvo para a máquina local
- `upload`: Envia um arquivo da máquina local para o sistema-alvo
- `reg_query`: Consulta chaves e valores do registry no sistema-alvo
- `reg_write_value`: Grava um novo valor em uma chave do registry especificada
- `sleep`: Altera o intervalo de sleep do agent, que determina a frequência com que ele se comunica com o servidor Mythic
- E muitos outros; use `help` para ver a lista completa de comandos disponíveis.

### Escalada de privilégios

- `getprivs`: Habilita o máximo possível de privilégios no token da thread atual
- `getsystem`: Abre um handle para o winlogon e duplica o token, escalando efetivamente os privilégios para o nível SYSTEM
- `make_token`: Cria uma nova sessão de logon e aplica-a ao agent, permitindo a impersonation de outro usuário
- `steal_token`: Rouba um token primário de outro processo, permitindo que o agent faça impersonation do usuário desse processo
- `pth`: Ataque Pass-the-Hash, permitindo que o agent se autentique como um usuário usando seu hash NTLM sem precisar da senha em texto claro
- `mimikatz`: Executa comandos do Mimikatz para extrair credenciais, hashes e outras informações sensíveis da memória ou do banco de dados SAM
- `rev2self`: Reverte o token do agent para seu token primário, removendo efetivamente os privilégios de volta ao nível original
- `ppid`: Altera o processo pai dos jobs de post-exploitation especificando um novo ID de processo pai, permitindo maior controle sobre o contexto de execução do job
- `printspoofer`: Executa comandos do PrintSpoofer para contornar medidas de segurança do print spooler, permitindo escalada de privilégios ou execução de código
- `dcsync`: Sincroniza as chaves Kerberos de um usuário com a máquina local, permitindo cracking offline de senhas ou ataques adicionais
- `ticket_cache_add`: Adiciona um ticket Kerberos à sessão de logon atual ou a uma sessão especificada, permitindo reutilização de tickets ou impersonation

### Execução de processos

- `assembly_inject`: Permite injetar um .NET assembly loader em um processo remoto
- `blockdlls`: Impede o carregamento de DLLs não assinadas pela Microsoft nos jobs de post-exploitation
- `execute_assembly`: Executa um .NET assembly no contexto do agent
- `execute_coff`: Executa um arquivo COFF em memória, permitindo a execução em memória de código compilado
- `execute_pe`: Executa um executável não gerenciado (PE)
- `keylog_inject`: Injeta um keylogger em outro processo e transmite as teclas pressionadas de volta para a visualização de keylog do Mythic
- `screenshot` / `screenshot_inject`: Captura a área de trabalho atual diretamente ou
injeta um screenshot assembly em um processo/sessão-alvo
- `get_injection_techniques`: Exibe as técnicas de injeção disponíveis e a atualmente selecionada
- `inline_assembly`: Executa um .NET assembly em um AppDomain descartável, permitindo a execução temporária de código sem afetar o processo principal do agent
- `register_assembly`: Registra um .NET assembly para execução posterior
- `register_file`: Registra um arquivo no cache do agent para uso posterior em tasking `execute_*` ou PowerShell
- `run`: Executa um binário no sistema-alvo, usando o PATH do sistema para localizar o executável
- `set_injection_technique`: Altera a primitive de injeção usada pelos jobs de post-exploitation
- `shinject`: Injeta shellcode em um processo remoto, permitindo a execução em memória de código arbitrário
- `inject`: Injeta o shellcode do agent em um processo remoto, permitindo a execução em memória do código do agent
- `spawn`: Inicia uma nova sessão do agent no executável especificado, permitindo a execução de shellcode em um novo processo
- `spawnto_x64` e `spawnto_x86`: Alteram o binário padrão usado nos jobs de post-exploitation para um path especificado, em vez de usar `rundll32.exe` sem parâmetros, que é muito ruidoso.

### Mythic Forge

Isso permite **carregar arquivos COFF/BOF** do Mythic Forge, que é um repositório de payloads e tools pré-compilados que podem ser executados no sistema-alvo. Com todos os comandos que podem ser carregados, será possível realizar ações comuns executando-os no processo atual do agent como BOFs (geralmente com OPSEC melhor do que iniciar um processo separado).

Comece a instalá-los com:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Em seguida, use `forge_collections` para mostrar os módulos COFF/BOF do Mythic Forge, permitindo selecioná-los e carregá-los na memória do agente para execução. Por padrão, as 2 coleções a seguir são adicionadas no Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Depois que um módulo for carregado, ele aparecerá na lista como outro comando, como `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Para BOFs, lembre-se de que o Forge **não** passa simplesmente uma única string plana de argumentos para o Apollo. Ele mapeia os parâmetros do BOF para o formato de array tipado do Mythic e os encaminha para o fluxo `execute_coff` do Apollo. Se um BOF carregado pelo Forge apresentar um comportamento estranho, verifique os tipos de argumentos BOF esperados e o entrypoint, em vez de analisar apenas a linha de comando digitada. Observe também que o loader de BOF mais recente do Apollo alterou o tratamento de argumentos em relação a builds muito mais antigas da era 2.3.1; portanto, BOFs antigos ou collections antigas podem falhar simplesmente porque as expectativas de marshaling foram alteradas.

### Execução de PowerShell e scripting

- `powershell_import`: Importa um novo script PowerShell (.ps1) para o cache do agente para execução posterior
- `powershell`: Executa um comando PowerShell no contexto do agente, permitindo scripting avançado e automação
- `powerpick`: Injeta um assembly loader de PowerShell em um processo sacrificial e executa um comando PowerShell (sem PowerShell logging).
- `psinject`: Executa PowerShell em um processo especificado, permitindo a execução direcionada de scripts no contexto de outro processo
- `shell`: Executa um comando shell no contexto do agente, de forma semelhante à execução de um comando no cmd.exe

### Movimento Lateral

- `jump_psexec`: Usa a técnica PsExec para realizar movimento lateral para um novo host, primeiro copiando o executável do agente Apollo (apollo.exe) e executando-o.
- `jump_wmi`: Usa a técnica WMI para realizar movimento lateral para um novo host, primeiro copiando o executável do agente Apollo (apollo.exe) e executando-o.
- `link` e `unlink`: Criam e encerram links P2P (por exemplo, via SMB/TCP) entre callbacks.
- `wmiexecute`: Executa um comando no sistema local ou remoto especificado usando WMI, com credenciais opcionais para impersonation.
- `net_dclist`: Recupera uma lista de domain controllers para o domínio especificado, útil para identificar possíveis alvos para movimento lateral.
- `net_localgroup`: Lista os grupos locais no computador especificado, usando localhost por padrão se nenhum computador for especificado.
- `net_localgroup_member`: Recupera os membros de um grupo local especificado no computador local ou remoto, permitindo a enumeração de usuários em grupos específicos.
- `net_shares`: Lista os compartilhamentos remotos e sua acessibilidade no computador especificado, útil para identificar possíveis alvos para movimento lateral.
- `socks`: Habilita um proxy compatível com SOCKS 5 na rede-alvo, permitindo o tunneling do tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `rpfwd`: Começa a escutar em uma porta especificada no host-alvo e encaminha o tráfego através do Mythic para um IP e uma porta remotos, permitindo o acesso remoto a serviços na rede-alvo.
- `listpipes`: Lista todos os named pipes no sistema local, o que pode ser útil para movimento lateral ou privilege escalation por meio da interação com mecanismos IPC.

Para as primitivas de execução WMI de nível inferior usadas por `jump_wmi` ou `wmiexecute`, consulte [WmiExec](lateral-movement/wmiexec.md). Para padrões mais amplos de pivoting, consulte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos Diversos
- `help`: Exibe informações detalhadas sobre comandos específicos ou informações gerais sobre todos os comandos disponíveis no agente.
- `clear`: Marca as tasks como 'cleared', para que não possam ser coletadas pelos agentes. Você pode especificar `all` para limpar todas as tasks ou `task Num` para limpar uma task específica.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon é um agente Golang que compila para executáveis **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notas atuais sobre builds/perfis

- As builds atuais do Poseidon têm como alvo Linux e macOS em `x86_64` e `arm64`.
- Os formatos de saída compatíveis incluem executáveis nativos e formatos semelhantes a bibliotecas compartilhadas, como `dylib` e `so`.
- O Poseidon oferece suporte a `http`, `websocket`, `tcp` e `dynamichttp`, e os builders atuais expõem configurações de multi-egress, como `egress_order` e limites de failover.
- Os metadados atuais de capacidades do Poseidon também anunciam browser scripts, integração com file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd e P2P. Assim, ele pode funcionar como um verdadeiro pivot node de Linux/macOS, em vez de apenas um simples remote shell.
- Vale verificar opções em tempo de build, como `proxy_bypass` e `garble`, quando você precisar de um comportamento de rede mais limpo ou de obfuscação adicional do binário Go.
- `pty` é um dos comandos mais úteis e recentes para melhorar a experiência em operações de Linux/macOS, pois abre um PTY interativo e pode expor uma porta no Mythic para uma interação mais completa com o terminal, sem recorrer ao antigo workaround `sleep 0` + SOCKS.
- A documentação atual do Poseidon é especialmente interessante para tradecraft focado em macOS: `jxa` executa JavaScript for Automation em memória, `screencapture` captura a área de trabalho do usuário conectado, `clipboard_monitor` transmite alterações no pasteboard, `execute_library` carrega uma dylib local e chama uma função dela, e `libinject` força um processo remoto a carregar uma dylib armazenada no disco.
- Para jobs de longa duração, lembre-se de que o Poseidon executa atividades de post-exploitation em goroutines/threads cooperativas, que não podem ser encerradas à força. A documentação também observa explicitamente que atualmente não há obfuscação integrada do agent, portanto o tradecraft no nível de build/profile é mais importante do que em implants comerciais fortemente obfuscados.

Para tradecraft específico de macOS em operações baseadas no Mythic, abuso de JAMF ou ideias de MDM-as-C2, consulte [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Quando usado em Linux ou macOS, ele oferece alguns comandos interessantes:

### Ações comuns

- `cat`: Exibe o conteúdo de um arquivo
- `cd`: Altera o diretório de trabalho atual
- `chmod`: Altera as permissões de um arquivo
- `config`: Exibe a configuração atual e as informações do host
- `cp`: Copia um arquivo de um local para outro
- `curl`: Executa uma única solicitação web com headers e método opcionais
- `upload`: Faz upload de um arquivo para o alvo
- `download`: Faz download de um arquivo do sistema alvo para a máquina local
- E muitos outros

### Buscar informações sensíveis

- `triagedirectory`: Encontra arquivos interessantes dentro de um diretório em um host, como arquivos sensíveis ou credenciais.
- `getenv`: Obtém todas as variáveis de ambiente atuais.

### Tradecraft específico de macOS

- `jxa`: Executa JavaScript for Automation em memória via `OSAScript`, sendo útil para post-exploitation nativa de macOS sem criar arquivos de script separados.
- `clipboard_monitor`: Consulta o pasteboard e informa as alterações ao Mythic, sendo útil em workflows de roubo de credenciais/tokens que dependem de copiar e colar.
- `screencapture`: Captura a área de trabalho do usuário no macOS.
- `execute_library`: Carrega uma dylib do disco e chama uma função exportada específica.
- `libinject`: Injeta um stub de shellcode que força outro processo do macOS a carregar uma dylib do disco.
- `persist_launchd`: Cria persistência de LaunchAgent / LaunchDaemon diretamente a partir do agent.

### Mover-se lateralmente

- `ssh`: Usa SSH para acessar um host com as credenciais designadas e abre um PTY sem iniciar o ssh.
- `sshauth`: Usa SSH para acessar o(s) host(s) especificado(s) com as credenciais designadas. Você também pode usá-lo para executar um comando específico nos hosts remotos via SSH ou para usar SCP para transferir arquivos.
- `link_tcp`: Cria um link com outro agent via TCP, permitindo comunicação direta entre agents.
- `link_webshell`: Cria um link com um agent usando o perfil P2P de webshell, permitindo acesso remoto à interface web do agent.
- `rpfwd`: Inicia ou interrompe um Reverse Port Forward, permitindo acesso remoto a serviços na rede alvo.
- `socks`: Inicia ou interrompe um proxy SOCKS5 na rede alvo, permitindo o tunelamento de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `portscan`: Analisa host(s) em busca de portas abertas, sendo útil para identificar possíveis alvos para movimento lateral ou ataques adicionais.

### Execução de processos

- `shell`: Executa um único comando de shell via /bin/sh, permitindo a execução direta de comandos no sistema alvo.
- `run`: Executa um comando a partir do disco com argumentos, permitindo a execução de binários ou scripts no sistema alvo.
- `pty`: Abre um PTY interativo, permitindo a interação direta com o shell no sistema alvo.

## Referências

- [1] [Matriz de recursos dos agents da comunidade Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README do Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Destaques do Mythic v3.2: Interactive Tasking, Push C2 e Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Documentação do Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Atualizações do Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transformando operações de Red Team com os recursos ocultos do Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
