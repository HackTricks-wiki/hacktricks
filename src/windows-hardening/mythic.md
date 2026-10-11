# Mythic

{{#include ../banners/hacktricks-training.md}}

## O que é o Mythic?

Mythic é um framework open source, modular e colaborativo de command and control (C2), projetado para red teaming. Ele permite que operadores gerenciem e implantem agents (payloads) em diferentes sistemas operacionais, incluindo Windows, Linux e macOS. O Mythic oferece uma interface de navegador para gerenciamento de tarefas por vários operadores, manipulação de arquivos, gerenciamento de SOCKS/rpfwd e geração de payloads.

Ao contrário dos frameworks monolíticos, o próprio repositório do Mythic **não** inclui tipos de payload ou perfis de C2. Agents, wrappers e perfis de C2 são normalmente instalados como componentes externos e podem ser atualizados independentemente do núcleo do Mythic.

### Instalação

Para instalar o Mythic, siga as instruções no **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Um procedimento comum de bootstrap a partir do diretório do Mythic é:

```bash
sudo make
sudo ./mythic-cli start
```

Se o Mythic já estiver em execução, normalmente você pode adicionar um novo agent ou profile com `./mythic-cli install github ...` e, em seguida, reiniciar o Mythic ou iniciar o novo componente diretamente.

### Agents

O Mythic oferece suporte a vários agents, que são os **payloads que executam tarefas nos sistemas comprometidos**. Cada agent pode ser personalizado para necessidades específicas e executado em diferentes sistemas operacionais.

Por padrão, o Mythic não tem nenhum agent instalado. Os agents da comunidade de código aberto estão em [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e a [**matriz de recursos da comunidade**](https://mythicmeta.github.io/overview/agent_matrix.html) é útil para verificar rapidamente os sistemas operacionais, formatos de payload, wrappers e profiles de C2 compatíveis.<sup>[[1]](#references)</sup>

Para instalar um agent dessa organização, você pode executar:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

A forma `sudo -E` é útil quando você está instalando a partir de um ambiente que não é root. Você pode adicionar novos agents com o comando anterior mesmo que o Mythic já esteja em execução.

### C2 Profiles

Os C2 profiles no Mythic definem **como os agents se comunicam com o servidor Mythic**. Eles especificam o protocolo de comunicação, os métodos de criptografia e outras configurações. Você pode criar e gerenciar C2 profiles pela interface web do Mythic.

Por padrão, o Mythic é instalado sem profiles. No entanto, é possível baixar alguns profiles do repositório [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) executando:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Perfis relevantes para o operador a ter em mente:

- [`http`](https://github.com/MythicC2Profiles/http): tráfego GET/POST assíncrono básico.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfego HTTP mais flexível, com vários domínios de callback, rotação fail-over/round-robin, cabeçalhos/parâmetros de consulta personalizados e transformações de mensagem (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inseridas em cookies, cabeçalhos, parâmetros de consulta ou corpo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): personalização de mensagens HTTP orientada por JSON/TOML quando o perfil estático `http` é fácil demais de reconhecer.

### Observações sobre a plataforma atual

- Muitos agents e profiles públicos agora são instalados com imagens de contêiner remotas pré-compiladas.
  Se você fizer um fork de um componente ou aplicar um patch localmente, mas o Mythic continuar usando o comportamento antigo, inspecione as entradas `.env` geradas para `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; habilitar
  `*_USE_BUILD_CONTEXT="true"` geralmente faz o Mythic recompilar usando o contexto Docker local, em vez de reutilizar silenciosamente a imagem remota.
- Os scripts de navegador são um dos recursos de qualidade de vida mais valiosos do Mythic para operadores: eles podem transformar a saída bruta de comandos em tabelas, visualizadores de capturas de tela, links para downloads, links de busca e botões que enviam tarefas subsequentes diretamente pela interface. As versões atuais do Mythic permitem que cada operador mantenha seus próprios scripts, os habilite ou desabilite globalmente ou por tarefa e obtenha os melhores resultados quando os agents retornam JSON estruturado em vez de texto simples. Isso é especialmente útil para fluxos de trabalho repetitivos de `ls`, `ps`, triagem e navegação de arquivos.<sup>[[4]](#references)[[6]](#references)</sup>
- Versões mais recentes do Mythic também oferecem suporte a tasking interativo e padrões de Push C2 que reduzem a necessidade de polling com `sleep 0` durante operações intensivas em PTY/SOCKS/rpfwd. Quando um agent/profile oferece suporte a isso, normalmente há menos sobrecarga do que martelar o servidor com check-ins constantes apenas para manter um canal interativo utilizável.<sup>[[3]](#references)</sup>
- Os builders atuais do Mythic da era 3.4 têm mais consciência de contexto do que sugerem textos mais antigos: os parâmetros de build agora podem ser agrupados ou ocultados com base no sistema operacional selecionado ou em outras opções de build; os tipos de payload podem declarar se oferecem suporte a vários perfis C2 ou a várias instâncias do mesmo C2 em um único build; e as divergências de parâmetros C2 permitem que um agent oculte campos que não implementa de fato. Isso é importante quando você alterna entre `http`, `httpx`, `smb`,
  `tcp` e `websocket`, pois o conjunto de opções de build seguras/válidas deixou de ser um formulário estático e uniforme.<sup>[[5]](#references)</sup>
- Se você estiver criando um par personalizado de agent/profile e não quiser usar o formato de mensagem JSON do Mythic ou a criptografia padrão na rede, use um
  `translation_container`: o Mythic remove o UUID, envia o blob criptografado e o material da chave ao tradutor por gRPC e espera receber bytes nativos do agent. Essa é a maneira mais limpa de oferecer suporte a protocolos binários, enquadramento personalizado ou criptografia no lado do agent sem reescrever o servidor inteiro.
- Lembre-se de que callbacks vinculados/P2P não apenas transportam tarefas. O fluxo `get_tasking` do Mythic também pode transportar respostas e dados `delegates`,
  `socks`, `rpfwd` e `interactive`. Na prática, um callback de saída pode atender callbacks internos e canais de pivot na mesma rotina de polling; se os agents filhos fizerem seus próprios check-ins periódicos, `get_delegate_tasks=false` impede que o pai consuma acidentalmente os jobs enfileirados para o callback interno.

### Payloads wrapper

Payloads wrapper permitem manter a mesma lógica do agent enquanto se altera a representação em disco que é entregue ou persistida.

- `service_wrapper`: transforma outro payload em um executável de serviço do Windows, o que é útil quando o caminho de execução exige um binário de serviço válido.
- `scarecrow_wrapper`: encapsula shellcode compatível com o loader ScareCrow para gerar saídas carregadas por loader, como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo é um agent para Windows escrito em C# usando o .NET Framework 4.0, projetado para ser usado nas ofertas de treinamento da SpecterOps.<sup>[[2]](#references)</sup>

Instale-o com:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Observações sobre builds/perfis atuais

- Atualmente, o Apollo pode gerar payloads `WinExe`, `Shellcode`, `Service` e `Source`.
- Os perfis Apollo mais usados são `http`, `httpx`, `smb`, `tcp` e `websocket`.
- O `httpx` costuma ser a opção mais flexível quando você precisa de rotação de domínios, suporte a proxy, posicionamento personalizado de mensagens e transformações de mensagens, em vez do perfil `http` estático mais antigo.
- O Apollo é um dos agentes comunitários com mais recursos e atualmente oferece integrações do lado do Mythic, como scripts de navegador, visualizações de navegação de arquivos/processos, capturas de tela, keylogging, SOCKS, rpfwd, Push C2 e roteamento P2P.
- O Apollo oferece suporte a payloads wrapper, como `service_wrapper` e `scarecrow_wrapper`.
- O Apollo oferece carregamento dinâmico de comandos, permitindo manter o payload inicial enxuto e carregar comandos adicionais ou módulos Forge posteriormente, em vez de compilar todos os recursos de post-exploitation no primeiro build.
- Ao gerar saída em shellcode, o builder atual do Apollo também oferece opções de formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) e comportamentos de bypass do Donut (`None`, `Abort on fail`, `Continue on fail`). Isso é útil se o objetivo final for encapsular novamente o shellcode com `service_wrapper`, `scarecrow_wrapper` ou um loader personalizado.
- `register_file` e `register_assembly` são as primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nos builds atuais do Apollo, esses artefatos em staging são armazenados em cache no lado do cliente como blobs AES256 protegidos por DPAPI.
- Os resultados de `ls` e `ps` integram-se especialmente bem aos scripts de navegador e ao navegador de arquivos/processos do Mythic, agilizando significativamente a triagem do operador em operações colaborativas.
- Os jobs fork-and-run herdam as configurações do processo sacrificial de
  `spawnto_x86` / `spawnto_x64`, herdam a seleção do processo pai de `ppid` e,
  em seguida, usam a primitiva de injeção atualmente selecionada. Na prática, isso significa
  que seu ajuste de OPSEC para um comando frequentemente afeta `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn` ao
  mesmo tempo.
- Os backends de injeção Apollo atualmente documentados incluem `CreateRemoteThread`,
  `QueueUserAPC` (no estilo early-bird) e `NtCreateThreadEx` via syscalls. Use
  `get_injection_techniques` antes de atividades de post-exploitation ruidosas e
  `set_injection_technique` se precisar trocar uma primitiva que entre em conflito com o alvo ou com o comando que deseja executar.
- `blockdlls` afeta apenas processos sacrificiais criados para jobs de post-exploitation. Combinada com um destino `spawnto_x64` menos suspeito do que o `rundll32.exe` simples padrão, essa é uma das mudanças mais fáceis no Apollo para fazer antes de executar tarefas que dependam muito de assembly/PowerShell.

### Pipeline de build de agente .NET ciente de detecção

Um fork do Apollo ciente de detecção deve ser tratado como um **problema de sistema de build completo**, não como uma etapa final de `obfuscate.exe`. Este estudo de caso complementa a [metodologia geral de evasão de AV](av-bypass.md) e as [ferramentas de inspeção .NET](../reversing/reversing-tools-basic-methods/README.md): alterações nos identificadores de wire, metadados IL, empacotamento de dependências, reflexão e tarefas compiladas dinamicamente formam um limite de compatibilidade.<sup>[[8]](#references)</sup>

#### Mutação de protocolo ciente de YARA

Audite regras públicas de arquivos/memória antes de alterar o código. Por exemplo, a regra `Multi_Trojan_Mythic_4beb7e17` da Elastic corresponde quando quaisquer **7 de 11** strings JSON/de ação do Mythic estão presentes, incluindo `task_id`, `post_response`, `c2_profile`, `get_tasking` e `get_delegate_tasks`. Renomear campos suficientes pode contornar esse limiar, mas esses valores fazem parte do protocolo, não são símbolos cosméticos: o agente e a implementação correspondente do servidor/perfil precisam ser alterados em conjunto.<sup>[[7]](#references)[[8]](#references)</sup>

Isso remove apenas um conjunto de características estáticas. A periodicidade de check-in, o formato das mensagens, o fluxo de tarefas/respostas e a reconstrução de strings em tempo de execução ainda podem ser indicadores comportamentais ou de memória; portanto, valide tanto o artefato compilado quanto um callback exercitado, em vez de considerar uma varredura de strings limpa como sucesso.<sup>[[8]](#references)</sup>

#### Faça merge antes de aplicar transformações globais

A incorporação de recursos com ferramentas como Costura deixa assemblies auxiliares como recursos comprimidos. Um ofuscador que visita apenas o módulo externo não detecta, portanto, seus nomes de tipos e metadados; ofuscar cada DLL de forma independente pode, em vez disso, atribuir nomes incompatíveis a contratos entre assemblies. Faça merge das saídas do build primeiro, no nível de IL (por exemplo, com [ILRepack](https://github.com/gluck/il-repack)), e depois aplique um único mapa de renomeação ao módulo resultante.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Uma pass personalizada pode usar [dnlib](https://github.com/0xd4d/dnlib) para transformações de IL/metadata gerenciado e [AsmResolver](https://github.com/Washi1337/AsmResolver) para aplicar patches em PE/recursos após a gravação. No estudo de caso, as instruções `ldstr` elegíveis foram convertidas em chamadas a tokens inteiros/descriptografadores, com o suporte de uma nova chave rolling-XOR de 16 bytes, enquanto símbolos e namespaces foram mapeados para nomes plausíveis no estilo empresarial, em vez de identificadores sequenciais curtos. Outras passagens removeram atributos selecionados de compilador/depurador, eliminaram referências a ferramentas de mesclagem/incorporação, renomearam recursos e aplicaram patches às informações de versão. Gere novamente nomes, dead code e material de criptografia para cada build independente: alterar o texto cifrado remove bytes estáveis, mas um descriptografador estável ou um padrão de transformação reconhecível é, por si só, uma assinatura.<sup>[[8]](#references)</sup>

#### Mantenha as tarefas dinâmicas sincronizadas com o payload

Apollo pode compilar o código-fonte das tarefas no servidor, enviar os bytes da DLL e carregá-los com `Assembly.Load()`. Depois que os tipos públicos do agent base forem renomeados, tarefas posteriores compiladas com a API original deixarão de resolvê-los. Trate o mapa de renomeação exportado como um artefato ABI específico do payload:<sup>[[8]](#references)</sup>

1. Vincule o mapa e o contexto de tipos ao identificador exato do payload/build.
2. Para cada build de tarefa, recupere esse mapa e reescreva uma árvore de código-fonte temporária.
3. Reescreva apenas referências resolvidas a namespaces, tipos, tipos aninhados/genéricos, campos e propriedades; em seguida, compile em relação ao assembly mesclado obfuscado.
4. Rejeite mapas ausentes ou incompatíveis antes da entrega da tarefa e execute um teste de inicialização após a compilação.

A substituição global às cegas é insegura porque um identificador também pode aparecer em uma string, declaração local, acesso a membro, tipo de framework ou namespace não relacionado. Se um reescritor de texto/regex for mantido, proteja explicitamente esses contextos e faça testes de regressão sempre que o esquema do mapa ou uma pass de renomeação mudar.<sup>[[8]](#references)</sup>

#### Torne os contratos de reflection independentes de namespace

O código de descoberta que verifica `t.FullName.StartsWith("Tasks.")` torna o namespace essencial e falha após o remapeamento de namespaces. Em vez disso, descubra os tipos por uma relação estável, preservando os nomes das classes de comandos se o dispatch ainda usar `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Mantenha uma allowlist explícita de nomes visíveis por reflection, campos do serializer, entry points e APIs entre assemblies que não devem ser renomeados. Por fim, decompile o resultado com ILSpy/dnSpy, examine as representações em arquivo e em memória e teste todos os caminhos de comando/loader em um laboratório de EDR; um build que inicia corretamente ainda pode conter tarefas quebradas pela renomeação ou comportamentos detectados apenas durante a execução.<sup>[[8]](#references)</sup>

Este agent tem muitos comandos, o que o torna muito parecido com o Beacon do Cobalt Strike, mas com alguns extras. Entre eles, há suporte para:

### Ações comuns

- `cat`: Exibe o conteúdo de um arquivo
- `cd`: Altera o diretório de trabalho atual
- `cp`: Copia um arquivo de um local para outro
- `ls`: Lista arquivos e diretórios no diretório atual ou no caminho especificado
- `ifconfig`: Obtém adaptadores e interfaces de rede
- `netstat`: Obtém informações sobre conexões TCP e UDP
- `pwd`: Exibe o diretório de trabalho atual
- `ps`: Lista os processos em execução no sistema de destino (com informações adicionais)
- `jobs`: Lista todos os jobs em execução associados a tarefas de longa duração
- `download`: Baixa um arquivo do sistema de destino para a máquina local
- `upload`: Envia um arquivo da máquina local para o sistema de destino
- `reg_query`: Consulta chaves e valores do registry no sistema de destino
- `reg_write_value`: Grava um novo valor em uma chave especificada do registry
- `sleep`: Altera o intervalo de sleep do agent, que determina com que frequência ele se comunica com o servidor Mythic
- E muitos outros; use `help` para ver a lista completa de comandos disponíveis.

### Escalação de privilégios

- `getprivs`: Habilita o maior número possível de privilégios no token da thread atual
- `getsystem`: Abre um handle para winlogon e duplica o token, escalando efetivamente os privilégios para o nível SYSTEM
- `make_token`: Cria uma nova sessão de logon e a aplica ao agent, permitindo a impersonation de outro usuário
- `steal_token`: Rouba um token primário de outro processo, permitindo que o agent faça impersonation do usuário desse processo
- `pth`: Ataque Pass-the-Hash, que permite ao agent autenticar como um usuário usando seu hash NTLM, sem precisar da senha em texto claro
- `mimikatz`: Executa comandos do Mimikatz para extrair credenciais, hashes e outras informações confidenciais da memória ou do banco de dados SAM
- `rev2self`: Reverte o token do agent para seu token primário, removendo efetivamente os privilégios e retornando ao nível original
- `ppid`: Altera o processo pai dos jobs de post-exploitation, especificando um novo ID de processo pai para controlar melhor o contexto de execução do job
- `printspoofer`: Executa comandos do PrintSpoofer para contornar as medidas de segurança do print spooler, permitindo a escalação de privilégios ou a execução de código
- `dcsync`: Sincroniza as chaves Kerberos de um usuário com a máquina local, permitindo a quebra de senha offline ou outros ataques
- `ticket_cache_add`: Adiciona um ticket Kerberos à sessão de logon atual ou a uma sessão especificada, permitindo reutilizar o ticket ou fazer impersonation

### Execução de processos

- `assembly_inject`: Permite injetar um loader de assembly .NET em um processo remoto
- `blockdlls`: Impede o carregamento de DLLs não assinadas pela Microsoft nos jobs de post-exploitation
- `execute_assembly`: Executa um assembly .NET no contexto do agent
- `execute_coff`: Executa um arquivo COFF em memória, permitindo a execução em memória de código compilado
- `execute_pe`: Executa um executável não gerenciado (PE)
- `keylog_inject`: Injeta um keylogger em outro processo e transmite as teclas digitadas de volta para a visualização de keylog do Mythic
- `screenshot` / `screenshot_inject`: Captura a área de trabalho atual diretamente ou
  injetando um assembly de screenshot em um processo/sessão de destino
- `get_injection_techniques`: Mostra as técnicas de injection disponíveis e a atualmente selecionada
- `inline_assembly`: Executa um assembly .NET em um AppDomain descartável, permitindo a execução temporária de código sem afetar o processo principal do agent
- `register_assembly`: Registra um assembly .NET para execução posterior
- `register_file`: Registra um arquivo no cache do agent para uso posterior em tarefas `execute_*` ou PowerShell
- `run`: Executa um binário no sistema de destino, usando o PATH do sistema para localizar o executável
- `set_injection_technique`: Altera a primitiva de injection usada pelos jobs de post-exploitation
- `shinject`: Injeta shellcode em um processo remoto, permitindo a execução em memória de código arbitrário
- `inject`: Injeta shellcode do agent em um processo remoto, permitindo a execução em memória do código do agent
- `spawn`: Inicia uma nova sessão do agent no executável especificado, permitindo a execução de shellcode em um novo processo
- `spawnto_x64` e `spawnto_x86`: Altera o binário padrão usado nos jobs de post-exploitation para um caminho especificado, em vez de usar `rundll32.exe` sem parâmetros, o que gera muito ruído.

### Mythic Forge

Isso permite **carregar arquivos COFF/BOF** do Mythic Forge, que é um repositório de payloads e ferramentas pré-compilados que podem ser executados no sistema de destino. Com todos os comandos que podem ser carregados, será possível realizar ações comuns executando-os no processo atual do agent como BOFs (geralmente com melhor OPSEC do que iniciar um processo separado).

Comece instalando-os com:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Em seguida, use `forge_collections` para exibir os módulos COFF/BOF do Mythic Forge e poder selecioná-los e carregá-los na memória do agent para execução. Por padrão, as 2 coleções a seguir são adicionadas ao Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Depois que um módulo for carregado, ele aparecerá na lista como outro comando, por exemplo, `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Para BOFs, lembre-se de que o Forge **não** apenas passa uma única string plana de argumentos para o Apollo. Ele mapeia os parâmetros do BOF para o formato de array tipado do Mythic e, em seguida, os encaminha ao fluxo `execute_coff` do Apollo. Se um BOF carregado pelo Forge se comportar de forma estranha, verifique os tipos de argumentos / entrypoint esperados pelo BOF, em vez de conferir apenas a linha de comando digitada. Observe também que o loader de BOF mais recente do Apollo alterou o tratamento de argumentos em relação a builds muito mais antigos da era 2.3.1; portanto, BOFs desatualizados ou coleções antigas podem falhar simplesmente porque as expectativas de marshaling mudaram.

### Execução de PowerShell e scripts

- `powershell_import`: Importa um novo script PowerShell (.ps1) para o cache do agent, para execução posterior
- `powershell`: Executa um comando PowerShell no contexto do agent, permitindo scripting e automação avançados
- `powerpick`: Injeta um assembly loader do PowerShell em um processo sacrificial e executa um comando PowerShell (sem logging do PowerShell).
- `psinject`: Executa PowerShell em um processo especificado, permitindo a execução direcionada de scripts no contexto de outro processo
- `shell`: Executa um comando de shell no contexto do agent, de forma semelhante à execução de um comando no cmd.exe

### Movimento lateral

- `jump_psexec`: Usa a técnica PsExec para se mover lateralmente para um novo host, primeiro copiando o executável do agent Apollo (apollo.exe) e executando-o.
- `jump_wmi`: Usa a técnica WMI para se mover lateralmente para um novo host, primeiro copiando o executável do agent Apollo (apollo.exe) e executando-o.
- `link` e `unlink`: Criam e encerram links P2P (por exemplo, via SMB/TCP) entre callbacks.
- `wmiexecute`: Executa um comando no sistema local ou em um sistema remoto especificado usando WMI, com credenciais opcionais para impersonation.
- `net_dclist`: Recupera uma lista de controladores de domínio do domínio especificado, útil para identificar possíveis alvos para movimento lateral.
- `net_localgroup`: Lista os grupos locais no computador especificado; por padrão, usa localhost se nenhum computador for especificado.
- `net_localgroup_member`: Recupera os membros de um grupo local especificado no computador local ou remoto, permitindo a enumeração de usuários em grupos específicos.
- `net_shares`: Lista os compartilhamentos remotos e sua acessibilidade no computador especificado, útil para identificar possíveis alvos para movimento lateral.
- `socks`: Ativa um proxy compatível com SOCKS 5 na rede de destino, permitindo encapsular o tráfego pelo host comprometido. Compatível com ferramentas como proxychains.
- `rpfwd`: Começa a escutar em uma porta especificada no host de destino e encaminha o tráfego pelo Mythic para um IP e uma porta remotos, permitindo o acesso remoto a serviços na rede de destino.
- `listpipes`: Lista todos os named pipes do sistema local, o que pode ser útil para movimento lateral ou escalonamento de privilégios por meio da interação com mecanismos IPC.

Para conferir as primitivas de execução WMI de baixo nível usadas por `jump_wmi` ou `wmiexecute`, consulte [WmiExec](lateral-movement/wmiexec.md). Para padrões mais amplos de pivoting, consulte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos diversos
- `help`: Exibe informações detalhadas sobre comandos específicos ou informações gerais sobre todos os comandos disponíveis no agent.
- `clear`: Marca tarefas como 'cleared' para que não possam ser obtidas pelos agents. Você pode especificar `all` para limpar todas as tarefas ou `task Num` para limpar uma tarefa específica.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon é um agent em Golang que compila para executáveis **Linux e macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Notas atuais de build/profile

- Os builds atuais do Poseidon têm como alvo Linux e macOS em `x86_64` e `arm64`.
- Os formatos de saída compatíveis incluem executáveis nativos e saídas no estilo de bibliotecas compartilhadas, como `dylib` e `so`.
- O Poseidon é compatível com `http`, `websocket`, `tcp` e `dynamichttp`, e os builders atuais expõem configurações multi-egress, como `egress_order` e limites de failover.
- Os metadados atuais de capacidade do Poseidon também anunciam browser scripts, integração de navegador de arquivos/processos, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd e P2P. Assim, ele pode atuar como um verdadeiro nó de pivot em Linux/macOS, em vez de ser apenas um shell remoto simples.
- Vale verificar opções de build, como `proxy_bypass` e `garble`, quando você precisar de um comportamento de rede mais limpo ou de ofuscação adicional do binário Go.
- `pty` é um dos comandos mais úteis entre as melhorias recentes de qualidade de vida para operações em Linux/macOS, pois abre um PTY interativo e pode expor uma porta no Mythic para uma interação mais completa com o terminal, sem recorrer à antiga alternativa de `sleep 0` + SOCKS.
- A documentação atual do Poseidon é especialmente interessante para tradecraft voltado a macOS: `jxa` executa JavaScript for Automation em memória, `screencapture` captura a área de trabalho do usuário conectado, `clipboard_monitor` transmite alterações no pasteboard, `execute_library` carrega uma dylib local e chama uma função dela, e `libinject` força um processo remoto a carregar uma dylib do disco.
- Para tarefas de longa duração, lembre-se de que o Poseidon executa o trabalho de pós-exploração em goroutines/threads cooperativas, que não podem ser encerradas à força. A documentação também observa explicitamente que, atualmente, não há ofuscação integrada do agent; por isso, o tradecraft no nível de build/profile é mais importante do que em implants comerciais fortemente ofuscados.

Para tradecraft específico de macOS em operações baseadas no Mythic, abuso de JAMF ou ideias de MDM como C2, consulte [Red Teaming em macOS](../macos-hardening/macos-red-teaming/README.md).

Quando usado em Linux ou macOS, ele tem alguns comandos interessantes:

### Ações comuns

- `cat`: Exibir o conteúdo de um arquivo
- `cd`: Alterar o diretório de trabalho atual
- `chmod`: Alterar as permissões de um arquivo
- `config`: Exibir a configuração atual e as informações do host
- `cp`: Copiar um arquivo de um local para outro
- `curl`: Executar uma única requisição web com cabeçalhos e método opcionais
- `upload`: Enviar um arquivo para o alvo
- `download`: Baixar um arquivo do sistema alvo para a máquina local
- E muitos outros

### Buscar informações sensíveis

- `triagedirectory`: Encontrar arquivos interessantes em um diretório de um host, como arquivos sensíveis ou credenciais.
- `getenv`: Obter todas as variáveis de ambiente atuais.

### Tradecraft específico de macOS

- `jxa`: Executar JavaScript for Automation em memória via `OSAScript`, o que é útil para pós-exploração nativa em macOS sem gravar arquivos de script separados.
- `clipboard_monitor`: Verificar o pasteboard e enviar as alterações de volta ao Mythic, algo útil em fluxos de trabalho de roubo de credenciais/tokens que dependem de copiar e colar.
- `screencapture`: Capturar a área de trabalho do usuário no macOS.
- `execute_library`: Carregar uma dylib do disco e chamar uma função exportada específica.
- `libinject`: Injetar um stub de shellcode que força outro processo do macOS a carregar uma dylib do disco.
- `persist_launchd`: Criar persistência de LaunchAgent / LaunchDaemon diretamente pelo agent.

### Mover-se lateralmente

- `ssh`: Conectar-se a um host via SSH usando as credenciais designadas e abrir um PTY sem iniciar o ssh.
- `sshauth`: Conectar-se aos hosts especificados via SSH usando as credenciais designadas. Você também pode usá-lo para executar um comando específico nos hosts remotos via SSH ou para copiar arquivos com SCP.
- `link_tcp`: Conectar-se a outro agent via TCP, permitindo comunicação direta entre agents.
- `link_webshell`: Conectar-se a um agent usando o perfil P2P webshell, permitindo acesso remoto à interface web do agent.
- `rpfwd`: Iniciar ou parar um Reverse Port Forward, permitindo acesso remoto a serviços na rede alvo.
- `socks`: Iniciar ou parar um proxy SOCKS5 na rede alvo, permitindo tunelar tráfego pelo host comprometido. Compatível com ferramentas como proxychains.
- `portscan`: Procurar portas abertas em hosts, útil para identificar possíveis alvos para movimento lateral ou ataques adicionais.

### Execução de processos

- `shell`: Executar um único comando de shell via /bin/sh, permitindo a execução direta de comandos no sistema alvo.
- `run`: Executar um comando do disco com argumentos, permitindo executar binários ou scripts no sistema alvo.
- `pty`: Abrir um PTY interativo, permitindo interagir diretamente com o shell no sistema alvo.

## References

- [1] [Matriz de recursos de agents da comunidade Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README do Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Destaques do Mythic v3.2: Interactive Tasking, Push C2 e Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Documentação do Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Atualizações do Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transformando operações de Red Team com os recursos ocultos do Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: regras YARA Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [De fork a framework: o que modificar o Apollo nos ensinou sobre invasão de agents](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
