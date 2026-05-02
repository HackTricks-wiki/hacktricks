# Mythic

{{#include ../banners/hacktricks-training.md}}

## O que é Mythic?

Mythic é um framework open-source, modular e colaborativo de command and control (C2) projetado para red teaming. Ele permite que operadores gerenciem e implantem agents (payloads) em diferentes sistemas operacionais, incluindo Windows, Linux e macOS. Mythic fornece uma UI baseada em navegador para tasking multi-operator, tratamento de arquivos, gerenciamento de SOCKS/rpfwd e geração de payloads.

Ao contrário de frameworks monolíticos, o repositório Mythic em si **não** inclui tipos de payload ou perfis de C2. Agents, wrappers e perfis de C2 normalmente são instalados como componentes externos e podem ser atualizados independentemente do core do Mythic.

### Instalação

Para instalar o Mythic, siga as instruções no **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Um bootstrap comum a partir do diretório Mythic é:
```bash
sudo make
sudo ./mythic-cli start
```
Se Mythic já estiver em execução, normalmente você pode adicionar um novo agent ou profile com `./mythic-cli install github ...` e então reiniciar o Mythic ou apenas iniciar o novo componente diretamente.

### Agents

Mythic suporta múltiplos agents, que são os **payloads que executam tarefas nos sistemas comprometidos**. Cada agent pode ser ajustado para necessidades específicas e pode rodar em diferentes sistemas operacionais.

Por padrão, o Mythic não tem nenhum agent instalado. Os agents da comunidade open-source ficam em [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) é útil para verificar rapidamente sistemas operacionais suportados, formatos de payload, wrappers e C2 profiles.

Para instalar um agent dessa org, você pode executar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
A forma `sudo -E` é útil quando você está instalando a partir de um ambiente não-root. Você pode adicionar novos agents com o comando anterior mesmo se o Mythic já estiver em execução.

### C2 Profiles

C2 profiles no Mythic definem **como os agents se comunicam com o servidor Mythic**. Eles especificam o protocolo de comunicação, os métodos de criptografia e outras configurações. Você pode criar e gerenciar C2 profiles através da interface web do Mythic.

Por padrão, o Mythic é instalado sem profiles; no entanto, é possível baixar alguns profiles do repositório [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) executando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

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
### Notas atuais de build/profile

- Apollo can currently emit `WinExe`, `Shellcode`, `Service`, and `Source` payloads.
- Os perfis Apollo mais usados são `http`, `httpx`, `smb`, `tcp`, e `websocket`.
- `httpx` normalmente é a opção mais flexível quando você precisa de rotação de domain, suporte a proxy, custom message placement, e message transforms em vez do perfil `http` mais antigo e estático.
- Apollo suporta wrapper payloads como `service_wrapper` e `scarecrow_wrapper`.
- `register_file` e `register_assembly` são as staging primitives para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, e `powerpick`. Nas builds atuais do Apollo, esses staged artifacts são cacheados no client como blobs AES256 protegidos por DPAPI.
- Resultados de `ls` e `ps` se integram especialmente bem com os browser scripts do Mythic e com o file/process browser, o que torna a triagem do operator visivelmente mais rápida em operações colaborativas.

Este agent tem muitos comandos que o deixam muito parecido com o Beacon do Cobalt Strike, com alguns extras. Entre eles, ele suporta:

### Ações comuns

- `cat`: Exibe o conteúdo de um arquivo
- `cd`: Altera o diretório de trabalho atual
- `cp`: Copia um arquivo de um local para outro
- `ls`: Lista arquivos e diretórios no diretório atual ou no path especificado
- `ifconfig`: Obtém os adaptadores e interfaces de rede
- `netstat`: Obtém informações de conexões TCP e UDP
- `pwd`: Exibe o diretório de trabalho atual
- `ps`: Lista processos em execução no sistema alvo (com info adicional)
- `jobs`: Lista todos os jobs em execução associados a tasking de longa duração
- `download`: Faz download de um arquivo do sistema alvo para a máquina local
- `upload`: Faz upload de um arquivo da máquina local para o sistema alvo
- `reg_query`: Consulta chaves e valores do registry no sistema alvo
- `reg_write_value`: Escreve um novo valor em uma chave de registry especificada
- `sleep`: Altera o intervalo de sleep do agent, que determina com que frequência ele faz check-in com o servidor Mythic
- E muitos outros; use `help` para ver a lista completa de comandos disponíveis.

### Escalada de privilégio

- `getprivs`: Habilita o máximo possível de privilégios no token da thread atual
- `getsystem`: Abre um handle para o winlogon e duplica o token, efetivamente escalando privilégios para nível SYSTEM
- `make_token`: Cria uma nova sessão de logon e a aplica ao agent, permitindo impersonation de outro usuário
- `steal_token`: Rouba um token primário de outro processo, permitindo que o agent impersonate o usuário desse processo
- `pth`: Ataque Pass-the-Hash, permitindo que o agent autentique como um usuário usando seu hash NTLM sem precisar da senha em texto puro
- `mimikatz`: Executa comandos do Mimikatz para extrair credenciais, hashes e outras informações sensíveis da memória ou do banco SAM
- `rev2self`: Reverte o token do agent para seu token primário, efetivamente reduzindo os privilégios de volta ao nível original
- `ppid`: Altera o processo pai para jobs de post-exploitation especificando um novo ID de processo pai, permitindo melhor controle sobre o contexto de execução do job
- `printspoofer`: Executa comandos do PrintSpoofer para contornar medidas de segurança do print spooler, permitindo escalada de privilégio ou code execution
- `dcsync`: Sincroniza as Kerberos keys de um usuário para a máquina local, permitindo cracking offline de senha ou ataques adicionais
- `ticket_cache_add`: Adiciona um ticket Kerberos à sessão de logon atual ou a uma especificada, permitindo reutilização de ticket ou impersonation

### Execução de processos

- `assembly_inject`: Permite injetar um loader de assembly .NET em um processo remoto
- `blockdlls`: Bloqueia DLLs não assinadas pela Microsoft de serem carregadas em jobs de post-exploitation
- `execute_assembly`: Executa um assembly .NET no contexto do agent
- `execute_coff`: Executa um arquivo COFF em memória, permitindo code execution de código compilado em memória
- `execute_pe`: Executa um executável unmanaged (PE)
- `get_injection_techniques`: Mostra as técnicas de injeção disponíveis e a atualmente selecionada
- `inline_assembly`: Executa um assembly .NET em um AppDomain descartável, permitindo execução temporária de código sem afetar o processo principal do agent
- `register_assembly`: Registra um assembly .NET para execução posterior
- `register_file`: Registra um arquivo no cache do agent para posterior `execute_*` ou tasking PowerShell
- `run`: Executa um binário no sistema alvo, usando o PATH do sistema para encontrar o executável
- `set_injection_technique`: Altera a primitive de injeção usada pelos jobs de post-exploitation
- `shinject`: Injeta shellcode em um processo remoto, permitindo execução em memória de código arbitrário
- `inject`: Injeta shellcode do agent em um processo remoto, permitindo execução em memória do código do agent
- `spawn`: Cria uma nova sessão do agent no executável especificado, permitindo a execução de shellcode em um novo processo
- `spawnto_x64` and `spawnto_x86`: Altera o binário padrão usado em jobs de post-exploitation para um path especificado em vez de usar `rundll32.exe` sem params, o que é muito ruidoso.

### Mythic Forge

Isso permite **load COFF/BOF** files from the Mythic Forge, que é um repositório de payloads e tools pré-compilados que podem ser executados no sistema alvo. Com todos os comandos que podem ser carregados, será possível realizar ações comuns executando-os no processo atual do agent como BOFs (geralmente com melhor OPSEC do que iniciar um processo separado).

Comece a instalá-los com:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Então, use `forge_collections` para mostrar os módulos COFF/BOF do Mythic Forge e poder selecioná-los e carregá-los na memória do agente para execução. Por padrão, as 2 coleções a seguir são adicionadas no Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Depois que um módulo é carregado, ele aparecerá na lista como outro comando, como `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

### Execução de PowerShell & scripting

- `powershell_import`: Importa um novo script PowerShell (.ps1) para o cache do agente para execução posterior
- `powershell`: Executa um comando PowerShell no contexto do agente, permitindo scripting avançado e automação
- `powerpick`: Injeta uma assembly carregadora de PowerShell em um processo sacrificial e executa um comando PowerShell (sem logging do powershell).
- `psinject`: Executa PowerShell em um processo especificado, permitindo execução direcionada de scripts no contexto de outro processo
- `shell`: Executa um comando shell no contexto do agente, semelhante a executar um comando no cmd.exe

### Movimento lateral

- `jump_psexec`: Usa a técnica PsExec para mover lateralmente para um novo host copiando primeiro o executável do agente Apollo (apollo.exe) e executando-o.
- `jump_wmi`: Usa a técnica WMI para mover lateralmente para um novo host copiando primeiro o executável do agente Apollo (apollo.exe) e executando-o.
- `link` and `unlink`: Cria e desfaz links P2P (por exemplo, via SMB/TCP) entre callbacks.
- `wmiexecute`: Executa um comando no sistema local ou remoto especificado usando WMI, com credenciais opcionais para impersonation.
- `net_dclist`: Recupera uma lista de controladores de domínio para o domínio especificado, útil para identificar possíveis alvos para movimento lateral.
- `net_localgroup`: Lista grupos locais no computador especificado, usando localhost por padrão se nenhum computador for especificado.
- `net_localgroup_member`: Recupera a associação de grupos locais para um grupo especificado no computador local ou remoto, permitindo a enumeração de usuários em grupos específicos.
- `net_shares`: Lista shares remotos e sua acessibilidade no computador especificado, útil para identificar possíveis alvos para movimento lateral.
- `socks`: Habilita um proxy compatível com SOCKS 5 na rede alvo, permitindo o tunelamento de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `rpfwd`: Inicia a escuta em uma porta especificada no host alvo e encaminha o tráfego através do Mythic para um IP e porta remotos, permitindo acesso remoto a serviços na rede alvo.
- `listpipes`: Lista todos os named pipes no sistema local, o que pode ser útil para movimento lateral ou privilege escalation ao interagir com mecanismos IPC.

Para as primitivas de execução WMI de nível mais baixo usadas internamente por `jump_wmi` ou `wmiexecute`, consulte [WmiExec](lateral-movement/wmiexec.md). Para padrões mais amplos de pivoting, consulte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos diversos
- `help`: Exibe informações detalhadas sobre comandos específicos ou informações gerais sobre todos os comandos disponíveis no agente.
- `clear`: Marca tarefas como 'cleared' para que não possam ser capturadas por agentes. Você pode especificar `all` para limpar todas as tarefas ou `task Num` para limpar uma tarefa específica.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon é um agente em Golang que compila para executáveis **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: Exibir o conteúdo de um arquivo
- `cd`: Mudar o diretório de trabalho atual
- `chmod`: Alterar as permissões de um arquivo
- `config`: Ver a config atual e as informações do host
- `cp`: Copiar um arquivo de um local para outro
- `curl`: Executar uma única requisição web com headers e método opcionais
- `upload`: Enviar um arquivo para o alvo
- `download`: Baixar um arquivo do sistema alvo para a máquina local
- E muitos mais

### Search Sensitive Information

- `triagedirectory`: Encontrar arquivos interessantes dentro de um diretório em um host, como arquivos sensíveis ou credentials.
- `getenv`: Obter todas as variáveis de ambiente atuais.

### Move laterally

- `ssh`: Fazer SSH para o host usando as credentials designadas e abrir um PTY sem iniciar ssh.
- `sshauth`: Fazer SSH para os hosts especificados usando as credentials designadas. Você também pode usar isso para executar um comando específico nos hosts remotos via SSH ou para usar SCP para arquivos.
- `link_tcp`: Conectar-se a outro agent via TCP, permitindo comunicação direta entre agents.
- `link_webshell`: Conectar-se a um agent usando o webshell P2P profile, permitindo acesso remoto à interface web do agent.
- `rpfwd`: Iniciar ou parar um Reverse Port Forward, permitindo acesso remoto a serviços na rede alvo.
- `socks`: Iniciar ou parar um proxy SOCKS5 na rede alvo, permitindo tunneling do tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `portscan`: Escanear host(s) em busca de portas abertas, útil para identificar possíveis alvos para movimento lateral ou ataques adicionais.

### Process execution

- `shell`: Executar um único comando de shell via /bin/sh, permitindo execução direta de comandos no sistema alvo.
- `run`: Executar um comando do disco com argumentos, permitindo a execução de binaries ou scripts no sistema alvo.
- `pty`: Abrir um PTY interativo, permitindo interação direta com o shell no sistema alvo.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
