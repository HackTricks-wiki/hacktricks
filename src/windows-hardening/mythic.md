# Mythic

## O que é Mythic?

Mythic é um framework de comando e controle (C2) modular e de código aberto, projetado para red teaming. Ele permite que profissionais de segurança gerenciem e implantem vários agentes (payloads) em diferentes sistemas operacionais, incluindo Windows, Linux e macOS. Mythic fornece uma interface web amigável para gerenciar agentes, executar comandos e coletar resultados, tornando-se uma ferramenta poderosa para simular ataques do mundo real em um ambiente controlado.

### Instalação

Para instalar o Mythic, siga as instruções no **[repositório oficial do Mythic](https://github.com/its-a-feature/Mythic)**.

### Agentes

Mythic suporta múltiplos agentes, que são os **payloads que realizam tarefas nos sistemas comprometidos**. Cada agente pode ser adaptado a necessidades específicas e pode ser executado em diferentes sistemas operacionais.

Por padrão, o Mythic não tem nenhum agente instalado. No entanto, ele oferece alguns agentes de código aberto em [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Para instalar um agente desse repositório, você só precisa executar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Você pode adicionar novos agentes com o comando anterior, mesmo que o Mythic já esteja em execução.

### Perfis C2

Os perfis C2 no Mythic definem **como os agentes se comunicam com o servidor Mythic**. Eles especificam o protocolo de comunicação, métodos de criptografia e outras configurações. Você pode criar e gerenciar perfis C2 através da interface web do Mythic.

Por padrão, o Mythic é instalado sem perfis, no entanto, é possível baixar alguns perfis do repositório [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) executando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo é um agente do Windows escrito em C# usando o .NET Framework 4.0, projetado para ser usado nas ofertas de treinamento da SpecterOps.

Instale-o com:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Este agente possui muitos comandos que o tornam muito semelhante ao Beacon do Cobalt Strike, com alguns extras. Entre eles, suporta:

### Ações comuns

- `cat`: Imprimir o conteúdo de um arquivo
- `cd`: Mudar o diretório de trabalho atual
- `cp`: Copiar um arquivo de um local para outro
- `ls`: Listar arquivos e diretórios no diretório atual ou no caminho especificado
- `pwd`: Imprimir o diretório de trabalho atual
- `ps`: Listar processos em execução no sistema alvo (com informações adicionais)
- `download`: Baixar um arquivo do sistema alvo para a máquina local
- `upload`: Fazer upload de um arquivo da máquina local para o sistema alvo
- `reg_query`: Consultar chaves e valores do registro no sistema alvo
- `reg_write_value`: Escrever um novo valor em uma chave de registro especificada
- `sleep`: Alterar o intervalo de sono do agente, que determina com que frequência ele se conecta ao servidor Mythic
- E muitos outros, use `help` para ver a lista completa de comandos disponíveis.

### Escalação de privilégios

- `getprivs`: Habilitar o máximo de privilégios possível no token da thread atual
- `getsystem`: Abrir um handle para winlogon e duplicar o token, efetivamente escalando privilégios para o nível SYSTEM
- `make_token`: Criar uma nova sessão de logon e aplicá-la ao agente, permitindo a impersonação de outro usuário
- `steal_token`: Roubar um token primário de outro processo, permitindo que o agente impersonifique o usuário desse processo
- `pth`: Ataque Pass-the-Hash, permitindo que o agente se autentique como um usuário usando seu hash NTLM sem precisar da senha em texto claro
- `mimikatz`: Executar comandos Mimikatz para extrair credenciais, hashes e outras informações sensíveis da memória ou do banco de dados SAM
- `rev2self`: Reverter o token do agente para seu token primário, efetivamente reduzindo privilégios de volta ao nível original
- `ppid`: Alterar o processo pai para trabalhos de pós-exploração especificando um novo ID de processo pai, permitindo melhor controle sobre o contexto de execução do trabalho
- `printspoofer`: Executar comandos PrintSpoofer para contornar medidas de segurança do spooler de impressão, permitindo escalonamento de privilégios ou execução de código
- `dcsync`: Sincronizar as chaves Kerberos de um usuário para a máquina local, permitindo quebra de senha offline ou ataques adicionais
- `ticket_cache_add`: Adicionar um ticket Kerberos à sessão de logon atual ou a uma especificada, permitindo reutilização de tickets ou impersonação

### Execução de processos

- `assembly_inject`: Permite injetar um carregador de assembly .NET em um processo remoto
- `execute_assembly`: Executa um assembly .NET no contexto do agente
- `execute_coff`: Executa um arquivo COFF na memória, permitindo a execução em memória de código compilado
- `execute_pe`: Executa um executável não gerenciado (PE)
- `inline_assembly`: Executa um assembly .NET em um AppDomain descartável, permitindo a execução temporária de código sem afetar o processo principal do agente
- `run`: Executa um binário no sistema alvo, usando o PATH do sistema para encontrar o executável
- `shinject`: Injeta shellcode em um processo remoto, permitindo a execução em memória de código arbitrário
- `inject`: Injeta shellcode do agente em um processo remoto, permitindo a execução em memória do código do agente
- `spawn`: Cria uma nova sessão de agente no executável especificado, permitindo a execução de shellcode em um novo processo
- `spawnto_x64` e `spawnto_x86`: Alterar o binário padrão usado em trabalhos de pós-exploração para um caminho especificado em vez de usar `rundll32.exe` sem parâmetros, que é muito barulhento.

### Mithic Forge

Isso permite **carregar arquivos COFF/BOF** do Mythic Forge, que é um repositório de payloads e ferramentas pré-compilados que podem ser executados no sistema alvo. Com todos os comandos que podem ser carregados, será possível realizar ações comuns executando-os no processo atual do agente como BOFs (geralmente mais discretos).

Comece a instalá-los com:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Então, use `forge_collections` para mostrar os módulos COFF/BOF do Mythic Forge para poder selecioná-los e carregá-los na memória do agente para execução. Por padrão, as seguintes 2 coleções são adicionadas no Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Depois que um módulo é carregado, ele aparecerá na lista como outro comando, como `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

### Execução de Powershell e scripts

- `powershell_import`: Importa um novo script PowerShell (.ps1) para o cache do agente para execução posterior
- `powershell`: Executa um comando PowerShell no contexto do agente, permitindo scripting avançado e automação
- `powerpick`: Injeta um assembly loader do PowerShell em um processo sacrificial e executa um comando PowerShell (sem registro de logs do PowerShell).
- `psinject`: Executa PowerShell em um processo especificado, permitindo a execução direcionada de scripts no contexto de outro processo
- `shell`: Executa um comando de shell no contexto do agente, semelhante a executar um comando no cmd.exe

### Movimento Lateral

- `jump_psexec`: Usa a técnica PsExec para se mover lateralmente para um novo host, copiando primeiro o executável do agente Apollo (apollo.exe) e executando-o.
- `jump_wmi`: Usa a técnica WMI para se mover lateralmente para um novo host, copiando primeiro o executável do agente Apollo (apollo.exe) e executando-o.
- `wmiexecute`: Executa um comando no sistema local ou remoto especificado usando WMI, com credenciais opcionais para impersonação.
- `net_dclist`: Recupera uma lista de controladores de domínio para o domínio especificado, útil para identificar alvos potenciais para movimento lateral.
- `net_localgroup`: Lista grupos locais no computador especificado, default para localhost se nenhum computador for especificado.
- `net_localgroup_member`: Recupera a associação de grupos locais para um grupo especificado no computador local ou remoto, permitindo a enumeração de usuários em grupos específicos.
- `net_shares`: Lista compartilhamentos remotos e sua acessibilidade no computador especificado, útil para identificar alvos potenciais para movimento lateral.
- `socks`: Habilita um proxy compatível com SOCKS 5 na rede alvo, permitindo o tunelamento de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `rpfwd`: Começa a escutar em uma porta especificada no host alvo e encaminha o tráfego através do Mythic para um IP e porta remotos, permitindo acesso remoto a serviços na rede alvo.
- `listpipes`: Lista todos os pipes nomeados no sistema local, o que pode ser útil para movimento lateral ou escalonamento de privilégios interagindo com mecanismos IPC.

### Comandos Diversos
- `help`: Exibe informações detalhadas sobre comandos específicos ou informações gerais sobre todos os comandos disponíveis no agente.
- `clear`: Marca tarefas como 'limpas' para que não possam ser retomadas por agentes. Você pode especificar `all` para limpar todas as tarefas ou `task Num` para limpar uma tarefa específica.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon é um agente Golang que compila em executáveis **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Quando o usuário está no linux, ele tem alguns comandos interessantes:

### Ações comuns

- `cat`: Imprimir o conteúdo de um arquivo
- `cd`: Mudar o diretório de trabalho atual
- `chmod`: Alterar as permissões de um arquivo
- `config`: Ver a configuração atual e informações do host
- `cp`: Copiar um arquivo de um local para outro
- `curl`: Executar uma única solicitação web com cabeçalhos e método opcionais
- `upload`: Fazer upload de um arquivo para o alvo
- `download`: Baixar um arquivo do sistema alvo para a máquina local
- E muitos mais

### Buscar Informações Sensíveis

- `triagedirectory`: Encontrar arquivos interessantes dentro de um diretório em um host, como arquivos sensíveis ou credenciais.
- `getenv`: Obter todas as variáveis de ambiente atuais.

### Mover lateralmente

- `ssh`: SSH para o host usando as credenciais designadas e abrir um PTY sem gerar ssh.
- `sshauth`: SSH para host(s) especificados usando as credenciais designadas. Você também pode usar isso para executar um comando específico nos hosts remotos via SSH ou usá-lo para SCP arquivos.
- `link_tcp`: Link para outro agente via TCP, permitindo comunicação direta entre agentes.
- `link_webshell`: Link para um agente usando o perfil P2P do webshell, permitindo acesso remoto à interface web do agente.
- `rpfwd`: Iniciar ou parar um Reverso Port Forward, permitindo acesso remoto a serviços na rede alvo.
- `socks`: Iniciar ou parar um proxy SOCKS5 na rede alvo, permitindo o tunelamento de tráfego através do host comprometido. Compatível com ferramentas como proxychains.
- `portscan`: Escanear host(s) em busca de portas abertas, útil para identificar alvos potenciais para movimento lateral ou ataques adicionais.

### Execução de processos

- `shell`: Executar um único comando shell via /bin/sh, permitindo a execução direta de comandos no sistema alvo.
- `run`: Executar um comando do disco com argumentos, permitindo a execução de binários ou scripts no sistema alvo.
- `pty`: Abrir um PTY interativo, permitindo interação direta com o shell no sistema alvo.
