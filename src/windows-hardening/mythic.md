# Mythic

{{#include ../banners/hacktricks-training.md}}

## O que é Mythic?

Mythic é um framework de command and control (C2) open-source, modular e colaborativo, projetado para red teaming. Ele permite que operadores gerenciem e implantem agents (payloads) em diferentes sistemas operacionais, incluindo Windows, Linux e macOS. Mythic fornece uma interface de navegador para tasking com múltiplos operadores, manipulação de arquivos, gerenciamento de SOCKS/rpfwd e geração de payloads.

Ao contrário de frameworks monolíticos, o próprio repositório do Mythic **não** inclui payload types nem perfis de C2. Agents, wrappers e perfis de C2 normalmente são instalados como componentes externos e podem ser atualizados independentemente do core do Mythic.

### Instalação

Para instalar o Mythic, siga as instruções no **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Um bootstrap comum a partir do diretório do Mythic é:
```bash
sudo make
sudo ./mythic-cli start
```
Se Mythic já estiver em execução, normalmente você pode adicionar um novo agent ou profile com `./mythic-cli install github ...` e então reiniciar o Mythic ou apenas iniciar o novo componente diretamente.

### Agents

Mythic suporta múltiplos agents, que são os **payloads que executam tarefas nos sistemas comprometidos**. Cada agent pode ser adaptado para necessidades específicas e pode ser executado em diferentes sistemas operacionais.

Por padrão, o Mythic não tem nenhum agent instalado. Os agents open-source da comunidade estão em [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) é útil para verificar rapidamente sistemas operacionais suportados, formatos de payload, wrappers e profiles de C2.

Para instalar um agent dessa organização, você pode executar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
O formato `sudo -E` é útil quando você está instalando a partir de um ambiente não-root. Você pode adicionar novos agentes com o comando anterior mesmo se o Mythic já estiver em execução.

### C2 Profiles

Os C2 profiles no Mythic definem **como os agents se comunicam com o Mythic server**. Eles especificam o protocolo de comunicação, os métodos de criptografia e outras configurações. Você pode criar e gerenciar C2 profiles pela interface web do Mythic.

Por padrão, o Mythic é instalado sem profiles, no entanto, é possível baixar alguns profiles do repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) executando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- Many public agents and profiles now install with pre-built remote container images.
If you fork a component or patch it locally and Mythic keeps using the old
behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
`*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
for operators: they can turn raw command output into tables, screenshot
viewers, download links, and buttons that issue follow-on tasking directly
from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
operations. When an agent/profile supports it, this is usually lower-overhead
than hammering the server with constant check-ins just to keep an interactive
channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Observações atuais de build/profile

- Apollo atualmente pode emitir payloads `WinExe`, `Shellcode`, `Service` e `Source`.
- Os profiles do Apollo mais usados são `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` geralmente é a opção mais flexível quando você precisa de rotação de domínio, suporte a proxy, posicionamento customizado de mensagem e transforms de mensagem, em vez do profile `http` estático mais antigo.
- Apollo suporta wrapper payloads como `service_wrapper` e `scarecrow_wrapper`.
- `register_file` e `register_assembly` são as primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nas builds atuais do Apollo, esses artefatos staged ficam em cache no client como blobs AES256 protegidos por DPAPI.
- Resultados de `ls` e `ps` integram especialmente bem com os browser scripts do Mythic e com o browser de file/process, o que torna a triagem do operador visivelmente mais rápida em operações colaborativas.
- Os jobs fork-and-run do Apollo herdam as configurações de sacrificial process de
`spawnto_x86` / `spawnto_x64`, herdam a seleção de parent de `ppid` e
então usam a primitive de injection atualmente selecionada. Na prática, isso significa
que seu ajuste de OPSEC para um comando muitas vezes afeta
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn` ao
mesmo tempo.
- Os backends de injection do Apollo documentados atualmente incluem
`CreateRemoteThread`, `QueueUserAPC` (estilo early-bird) e `NtCreateThreadEx` via syscalls. Use
`get_injection_techniques` antes de post-exploitation barulhento e
`set_injection_technique` se precisar trocar de uma primitive que
entre em conflito com o target ou com o comando que você quer executar.
- `blockdlls` afeta apenas processos sacrificial criados para jobs de post-exploitation.
Combinado com um target `spawnto_x64` menos suspeito do que o `rundll32.exe` padrão em
estado puro, essa é uma das mudanças mais fáceis de fazer no Apollo antes de
rodar tasking pesado em assembly/PowerShell.

Este agent tem muitos commands que o tornam muito semelhante ao Beacon do Cobalt Strike, com alguns extras. Entre eles, ele suporta:

### Ações comuns

- `cat`: Imprime o conteúdo de um arquivo
- `cd`: Altera o diretório de trabalho atual
- `cp`: Copia um arquivo de um local para outro
- `ls`: Lista arquivos e diretórios no diretório atual ou no path especificado
- `ifconfig`: Obtém adapters e interfaces de rede
- `netstat`: Obtém informações de conexão TCP e UDP
- `pwd`: Imprime o diretório de trabalho atual
- `ps`: Lista processos em execução no sistema target (com info adicional)
- `jobs`: Lista todos os jobs em execução associados a tasking de longa duração
- `download`: Baixa um arquivo do sistema target para a máquina local
- `upload`: Envia um arquivo da máquina local para o sistema target
- `reg_query`: Consulta chaves e valores do registry no sistema target
- `reg_write_value`: Escreve um novo valor em uma chave de registry especificada
- `sleep`: Altera o intervalo de sleep do agent, que determina com que frequência ele faz check-in com o servidor Mythic
- E muitos outros, use `help` para ver a lista completa de commands disponíveis.

### Escalada de privilégio

- `getprivs`: Habilita o maior número possível de privilégios no token da thread atual
- `getsystem`: Abre um handle para winlogon e duplica o token, escalando efetivamente privilégios para nível SYSTEM
- `make_token`: Cria uma nova sessão de logon e a aplica ao agent, permitindo impersonation de outro usuário
- `steal_token`: Rouba um token primário de outro processo, permitindo que o agent impersonate o usuário desse processo
- `pth`: Pass-the-Hash attack, permitindo que o agent autentique como um usuário usando seu hash NTLM sem precisar da plaintext password
- `mimikatz`: Executa commands do Mimikatz para extrair credentials, hashes e outras informações sensíveis da memória ou do banco SAM
- `rev2self`: Reverte o token do agent para seu token primário, efetivamente reduzindo os privilégios de volta ao nível original
- `ppid`: Altera o parent process para jobs de post-exploitation especificando um novo parent process ID, permitindo melhor controle sobre o contexto de execução do job
- `printspoofer`: Executa commands do PrintSpoofer para contornar medidas de segurança do print spooler, permitindo escalada de privilégio ou code execution
- `dcsync`: Sincroniza as Kerberos keys de um usuário para a máquina local, permitindo cracking offline de password ou ataques adicionais
- `ticket_cache_add`: Adiciona um ticket Kerberos à sessão de logon atual ou a uma especificada, permitindo reuse de ticket ou impersonation

### Execução de processos

- `assembly_inject`: Permite injetar um loader de assembly .NET em um processo remoto
- `blockdlls`: Bloqueia DLLs não assinadas pela Microsoft de carregarem em jobs de post-exploitation
- `execute_assembly`: Executa um assembly .NET no contexto do agent
- `execute_coff`: Executa um arquivo COFF na memória, permitindo execução in-memory de code compilado
- `execute_pe`: Executa um executável unmanaged (PE)
- `keylog_inject`: Injeta um keylogger em outro processo e transmite as teclas de volta para a visão de keylog do Mythic
- `screenshot` / `screenshot_inject`: Captura a área de trabalho atual diretamente ou
injetando um assembly de screenshot em um processo/sessão target
- `get_injection_techniques`: Mostra as técnicas de injection disponíveis e a atualmente selecionada
- `inline_assembly`: Executa um assembly .NET em um AppDomain descartável, permitindo execução temporária de code sem afetar o processo principal do agent
- `register_assembly`: Registra um assembly .NET para execução posterior
- `register_file`: Registra um arquivo no cache do agent para `execute_*` posterior ou tasking PowerShell
- `run`: Executa um binary no sistema target, usando o PATH do sistema para encontrar o executable
- `set_injection_technique`: Altera a primitive de injection usada pelos jobs de post-exploitation
- `shinject`: Injeta shellcode em um processo remoto, permitindo execução in-memory de code arbitrário
- `inject`: Injeta shellcode do agent em um processo remoto, permitindo execução in-memory do code do agent
- `spawn`: Cria uma nova sessão de agent no executable especificado, permitindo a execução de shellcode em um novo processo
- `spawnto_x64` e `spawnto_x86`: Alteram o binary padrão usado em jobs de post-exploitation para um path especificado em vez de usar `rundll32.exe` sem params, que é muito barulhento.

### Mythic Forge

Isso permite **carregar arquivos COFF/BOF** da Mythic Forge, que é um repositório de payloads e ferramentas pré-compilados que podem ser executados no sistema target. Com todos os commands que podem ser carregados, será possível realizar ações comuns executando-os no processo atual do agent como BOFs (geralmente com melhor OPSEC do que iniciar um processo separado).

Comece a instalá-los com:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Então, use `forge_collections` para mostrar os módulos COFF/BOF do Mythic Forge e poder selecioná-los e carregá-los na memória do agente para execução. Por padrão, as 2 collections a seguir são adicionadas no Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Depois que um módulo é carregado, ele aparecerá na lista como outro comando, como `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Para BOFs, lembre-se de que o Forge **não** apenas passa uma string simples de argumentos
para o Apollo. Ele mapeia os parâmetros do BOF para o formato de array tipado do Mythic e então
os encaminha para o fluxo `execute_coff` do Apollo. Se um BOF carregado pelo Forge se comportar
de forma estranha, verifique os tipos esperados dos argumentos do BOF / ponto de entrada em vez de apenas
a linha de comando que você digitou.

### PowerShell & scripting execution

- `powershell_import`: Importa um novo script PowerShell (.ps1) para o cache do agente para execução posterior
- `powershell`: Executa um comando PowerShell no contexto do agente, permitindo scripting e automação avançados
- `powerpick`: Injeta uma assembly loader PowerShell em um processo sacrificial e executa um comando PowerShell (sem logging do powershell).
- `psinject`: Executa PowerShell em um processo especificado, permitindo execução direcionada de scripts no contexto de outro processo
- `shell`: Executa um comando shell no contexto do agente, semelhante a executar um comando no cmd.exe

### Lateral Movement

- `jump_psexec`: Usa a técnica PsExec para mover lateralmente para um novo host copiando primeiro o executável do agente Apollo (apollo.exe) e executando-o.
- `jump_wmi`: Usa a técnica WMI para mover lateralmente para um novo host copiando primeiro o executável do agente Apollo (apollo.exe) e executando-o.
- `link` e `unlink`: Criam e removem links P2P (por exemplo via SMB/TCP) entre callbacks.
- `wmiexecute`: Executa um comando no sistema local ou remoto especificado usando WMI, com credenciais opcionais para personificação.
- `net_dclist`: Recupera uma lista de controladores de domínio para o domínio especificado, útil para identificar possíveis alvos para lateral movement.
- `net_localgroup`: Lista grupos locais no computador especificado, usando localhost por padrão se nenhum computador for especificado.
- `net_localgroup_member`: Recupera a associação de grupos locais para um grupo especificado no computador local ou remoto, permitindo a enumeração de usuários em grupos específicos.
- `net_shares`: Lista shares remotas e sua acessibilidade no computador especificado, útil para identificar possíveis alvos para lateral movement.
- `socks`: Habilita um proxy compatível com SOCKS 5 na rede alvo, permitindo tunnel de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `rpfwd`: Inicia a escuta em uma porta especificada no host alvo e encaminha o tráfego através do Mythic para um IP e porta remotos, permitindo acesso remoto a serviços na rede alvo.
- `listpipes`: Lista todos os named pipes no sistema local, o que pode ser útil para lateral movement ou privilege escalation ao interagir com mecanismos IPC.

Para os primitivos de execução WMI de nível mais baixo usados por baixo de `jump_wmi` ou `wmiexecute`, veja [WmiExec](lateral-movement/wmiexec.md). Para padrões mais amplos de pivoting, veja [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Exibe informações detalhadas sobre comandos específicos ou informações gerais sobre todos os comandos disponíveis no agente.
- `clear`: Marca tarefas como 'cleared' para que não possam ser assumidas pelos agentes. Você pode especificar `all` para limpar todas as tarefas ou `task Num` para limpar uma tarefa específica.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon é um agente Golang que compila para executáveis **Linux and macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.
- `pty` is one of the most useful newer-quality-of-life commands for Linux/macOS
operations because it opens an interactive PTY and can expose a Mythic-side
port for fuller terminal interaction without resorting to the older `sleep 0`
+ SOCKS workaround.
- Poseidon's current docs are especially interesting for macOS-heavy
tradecraft: `jxa` executes JavaScript for Automation in-memory,
`screencapture` grabs the logged-in desktop, `clipboard_monitor` streams
pasteboard changes, `execute_library` loads a local dylib and calls a
function from it, and `libinject` forces a remote process to load an on-disk
dylib.
- For long-running jobs, remember that Poseidon executes post-exploitation work
in goroutines/threads that are cooperative rather than hard-killable. The
docs also explicitly note that there is currently no built-in agent
obfuscation, so build/profile-level tradecraft matters more than with heavily
obfuscated commercial implants.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: Imprimir o conteúdo de um arquivo
- `cd`: Alterar o diretório de trabalho atual
- `chmod`: Alterar as permissões de um arquivo
- `config`: Ver a config atual e as informações do host
- `cp`: Copiar um arquivo de um local para outro
- `curl`: Executar uma única requisição web com headers e método opcionais
- `upload`: Enviar um arquivo para o alvo
- `download`: Baixar um arquivo do sistema alvo para a máquina local
- And many more

### Search Sensitive Information

- `triagedirectory`: Encontrar arquivos interessantes dentro de um diretório em um host, como arquivos sensíveis ou credentials.
- `getenv`: Obter todas as variáveis de ambiente atuais.

### macOS-specific tradecraft

- `jxa`: Executar JavaScript for Automation em memória via `OSAScript`, o que é
útil para post-exploitation nativo no macOS sem soltar arquivos de script
separados.
- `clipboard_monitor`: Consultar o pasteboard e reportar alterações de volta ao Mythic,
o que é útil para fluxos de trabalho de theft de credentials/token que dependem de copy/paste.
- `screencapture`: Capturar a área de trabalho do usuário no macOS.
- `execute_library`: Carregar um dylib do disco e chamar uma função exportada específica.
- `libinject`: Injetar um shellcode stub que força outro processo do macOS a carregar um dylib do disco.
- `persist_launchd`: Criar persistência de LaunchAgent / LaunchDaemon diretamente a partir do agent.

### Move laterally

- `ssh`: Fazer SSH no host usando as credentials designadas e abrir um PTY sem iniciar ssh.
- `sshauth`: Fazer SSH para o(s) host(s) especificado(s) usando as credentials designadas. Você também pode usar isso para executar um comando específico nos hosts remotos via SSH ou para usar SCP para arquivos.
- `link_tcp`: Vincular a outro agent via TCP, permitindo comunicação direta entre agents.
- `link_webshell`: Vincular a um agent usando o perfil P2P webshell, permitindo acesso remoto à interface web do agent.
- `rpfwd`: Iniciar ou parar um Reverse Port Forward, permitindo acesso remoto a serviços na rede alvo.
- `socks`: Iniciar ou parar um proxy SOCKS5 na rede alvo, permitindo tunneling de tráfego através do host comprometido. Compatível com tools como proxychains.
- `portscan`: Fazer scan de host(s) em busca de portas abertas, útil para identificar potenciais alvos para movimentação lateral ou ataques adicionais.

### Process execution

- `shell`: Executar um único shell command via /bin/sh, permitindo execução direta de commands no sistema alvo.
- `run`: Executar um command do disco com argumentos, permitindo a execução de binaries ou scripts no sistema alvo.
- `pty`: Abrir um PTY interativo, permitindo interação direta com o shell no sistema alvo.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
