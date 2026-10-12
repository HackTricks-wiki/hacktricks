# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Em **mutational grammar fuzzing**, as entradas são mutadas mantendo-se **válidas segundo a gramática**. No modo guiado por coverage, apenas as amostras que acionam **nova coverage** são salvas como seeds do corpus. Para **alvos de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de fluxo de dados**, nas quais a saída de uma construção se torna a entrada de outra.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o fluxo de dados encadeado**, então a amostra “mais próxima do bug” é descartada porque não adiciona coverage. Com **3 ou mais etapas dependentes**, a recombinação aleatória fica cara, e o feedback de coverage não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **combinar fases mutacionais e generativas** ou dar preferência a padrões de **encadeamento de funções** durante a geração (não apenas à coverage).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por coverage é **gulosa**: uma amostra com nova coverage é salva imediatamente, muitas vezes preservando grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas**, com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil; por isso, um meio-termo prático é a **minimização ciente da gramática**, que **para ao atingir um limite mínimo de tokens** (reduzindo o ruído sem remover tanta estrutura ao redor a ponto de prejudicar as mutações).<sup>[[1]](#references)</sup>

Uma regra prática para o corpus em mutational fuzzing é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximize a coverage** a um grande acúmulo de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do alvo).
- Reduza-as usando **minimização de corpus baseada em coverage**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos relevantes, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após mudanças importantes no harness/instrumentação, pois o corpus “ideal” muda quando a capacidade de alcançar o código muda.

## Mutação Ciente de Comparações para Valores Mágicos

Um motivo comum para os fuzzers estagnarem não é a sintaxe, mas sim **comparações difíceis**: bytes mágicos, verificações de comprimento, strings de enum, checksums ou valores de dispatch do parser protegidos por `memcmp`, tabelas `switch` ou comparações encadeadas. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses alvos, use **rastreamento de comparações** (por exemplo, `CMPLOG` do AFL++ ou fluxos de trabalho no estilo Redqueen) para que o fuzzer possa observar os operandos das comparações malsucedidas e direcionar as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Observações práticas:**

- Isso é especialmente útil quando o alvo restringe a lógica profunda com base em **assinaturas de arquivo**, **verbos de protocolo**, **tags de tipo** ou **bits de funcionalidades dependentes da versão**.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de depuração. Um dicionário pequeno com tokens gramaticais, nomes de chunks, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo realizar muitas verificações sequenciais, resolva primeiro as comparações de “magic” mais iniciais e, em seguida, minimize novamente o corpus resultante para que as etapas posteriores comecem com prefixos já válidos.

## Feedback mais rico quando a cobertura de arestas agrupa caminhos diferentes

A cobertura normal de arestas não consegue distinguir duas execuções que percorrem o mesmo helper a partir de diferentes chamadores ou seguem diferentes combinações de desvios dentro de uma função. Isso importa em decodificadores compartilhados, despachantes de protocolo e helpers de interpretadores, onde o **caminho** até uma aresta determina o estado ativo. Rastrear ingenuamente todos os contextos de chamada também é perigoso: o mapa de cobertura e a fila podem crescer demais. Portanto, pesquisas sobre fuzzing sensível ao contexto recomendam refinar apenas contextos promissores, em vez de tratar todo o grafo de chamadas como sensível ao contexto.<sup>[[14]](#references)</sup>

Versões recentes do AFL++ oferecem **cobertura de caminhos por função Ball-Larus**, além da cobertura normal de arestas. Ela atribui um recurso a cada caminho acíclico por uma função; as arestas de retorno de loops são removidas, então esse feedback distingue combinações de desvios, mas **não a quantidade de iterações do loop**. Comece com o nível relaxado `1` e, em seguida, aplique modos mais rigorosos apenas a código suspeito de parser/máquina de estados, pois o número de caminhos pode crescer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para um helper chamado a partir de muitos locais relevantes para a segurança, o modo LTO pode combinar cada caminho da função com o local de chamada imediato:<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**Orientações para a campanha:** aplique feedback mais rico de forma conservadora e monitore seu custo em coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Execute em paralelo uma instância comum de edge coverage; o feedback mais rico só é útil se o custo adicional de queue/map não reduzir a quantidade de execuções por segundo.
- Use `AFL_LLVM_ALLOWLIST` para restringir a instrumentação de caminhos/callers quando bibliotecas grandes, com muitos templates, ou código utilitário genérico dominarem o map.
- Funções com caminhos acíclicos em excesso podem ser ignoradas pelo AFL++; avisos durante a compilação indicam que o alvo precisa de allowlisting ou de um nível menos rigoroso.
- A cobertura de caller + path oferece suporte a apenas um nível de caller. Não a combine com stacks de contexto mais profundos.
- Os IDs de path podem mudar entre versões principais do LLVM. Mantenha a toolchain fixa durante a campanha e não sincronize corpora baseados em PATH como se seus feature IDs fossem estáveis entre builds.
- Esse feedback complementa `CMPLOG`: o tracing de comparações resolve **qual valor passa por uma guard**, enquanto o feedback de path/caller preserva **qual rota e combinação de branches levou até ela**.

## Fuzzing com estado: sequências são Seeds

Para **protocolos**, **workflows autenticados** e **parsers de vários estágios**, a unidade interessante geralmente não é um único blob, mas uma **sequência de mensagens**. Concatenar toda a transcrição em um arquivo e mutá-la às cegas costuma ser ineficiente, pois o fuzzer muta cada etapa igualmente, mesmo quando apenas a mensagem posterior alcança o estado frágil.<sup>[[4]](#references)</sup>

Um padrão mais eficaz é tratar a **própria sequência como seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos de objetos retornados) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha estáveis as **mensagens de prefixo válidas** e concentre as mutações na mensagem que **aciona a transição**.
- Armazene em cache os identificadores e valores gerados pelo servidor nas respostas anteriores quando a etapa seguinte depender deles.
- Prefira mutações/splicing por mensagem em vez de mutar toda a transcrição serializada como um blob opaco.
- Se o protocolo expuser códigos de resposta significativos, use-os como um **oráculo de estado barato** para priorizar sequências que avancem mais.

É por isso que bugs autenticados, transições ocultas ou bugs de parser que ocorrem “somente após o handshake” muitas vezes passam despercebidos no fuzzing comum no estilo de arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

### Binder do Android: fuzzing de driver com vários clientes

Uma alta edge coverage ainda pode deixar passar bugs no driver IPC, pois a cobertura não descreve **propriedade de objetos, contagens de referências, mensagens pendentes, ordem de limpeza ou intercalações entre threads**. A página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) aborda o modelo de objetos do driver; este exemplo se concentra no harness do fuzzer. O Android Binder é um modelo útil: alcançar os caminhos de alocação e liberação não basta se o fuzzer não conseguir fazer vários processos operarem sobre o mesmo objeto do kernel na ordem necessária.<sup>[[15]](#references)</sup>

#### Modele o protocolo, não buffers `ioctl` isolados

Represente um caso de teste como uma gramática ordenada de **identidade do cliente + operação + argumentos estruturados**. O fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, com um cliente persistente de gerenciador de contexto e dois clientes comuns. Um harness semântico preserva as relações que a mutação cega de bytes destruiria.<sup>[[15]](#references)</sup>

- Armazene em cache os valores retornados por operações anteriores. Por exemplo, `BC_FREE_BUFFER` deve reutilizar um ponteiro para buffer de transação retornado por um `ioctl` anterior.
- Gere respostas padrão válidas para que transações síncronas possam terminar e operações posteriores continuem acessíveis.
- Rejeite transições impossíveis, como transações de um cliente para si mesmo ou várias transações pendentes para o mesmo destino.
- Mantenha o estado singleton de inicialização fora do reset por entrada. O Binder permite apenas um registro `BINDER_SET_CONTEXT_MGR` por inicialização; portanto, destruir e recriar repetidamente esse cliente invalidaria as entradas posteriores.

Um modelo útil para condições de corrida de ciclo de vida consiste em fazer um cliente transferir um objeto, iniciar a limpeza de uma thread ou processo e, ao mesmo tempo, fazer o cliente receptor liberar o buffer de transação. No exemplo CVE-2020-0423, uma transferência `BINDER_TYPE_WEAK_BINDER` seguida de `BINDER_THREAD_EXIT` em disputa com `BC_FREE_BUFFER` podia liberar um `binder_work` incorporado enquanto o caminho de limpeza da thread em encerramento ainda o utilizava.<sup>[[15]](#references)</sup>

#### Reintroduza intercalações controladas em um kernel em espaço de usuário

A [Linux Kernel Library (LKL)](https://github.com/lkl/linux) vincula o código real do kernel a um harness em espaço de usuário e expõe sua interface de chamadas de sistema por meio de `lkl_syscall`. Isso facilita coordenar protobuf, cobertura e KASAN em um único processo. No entanto, normalmente o LKL executa uma chamada de sistema sem que outra thread do kernel a interrompa. Para campanhas de race, insira pontos `schedule()` em torno de limites selecionados de lock/unlock e de ciclo de vida, e então deixe o harness escolher aleatoriamente o próximo cliente a cada yield. Mantenha esses pontos direcionados, pois cada um multiplica o espaço de busca de escalonamentos. O scheduler aleatório descrito pelos pesquisadores **não** faz parte do fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compile e reproduza seeds de regressão serializadas

O harness upstream fixa uma versão compatível de `libprotobuf-mutator`, habilita a instrumentação de fuzzing do LKL e o KASAN com `LKL_FUZZING=1`, e habilita `CONFIG_MMU` para o Binder com `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Depois de conferir uma revisão deliberadamente vulnerável ou aplicar os patches de rollback documentados upstream, uma seed serializada pode reproduzir toda a transição de estado multi-cliente sem reconstruí-la em uma prova de conceito C improvisada:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trate o use-after-free do KASAN resultante como confirmação de que a seed alcançou o caminho vulnerável do ciclo de vida. Isso **não** demonstra as primitivas posteriores necessárias para a execução de código no kernel ou a escalada de privilégios.<sup>[[16]](#references)</sup>

## Truque de diversidade em uma única máquina (estilo Jackalope)

Uma forma prática de combinar **novidade generativa** com **reutilização de cobertura** é reiniciar workers de curta duração contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos com o corpus combinado, sincroniza novamente e, então, termina. Isso gera **estruturas novas a cada geração**, aproveitando a cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

**Servidor:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers sequenciais (loop de exemplo):**

<details>
<summary>Loop de reinicialização do worker Jackalope</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Observações:**

- `-in empty` força um **corpus novo** a cada geração.
- `-server_update_interval T` aproxima uma **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo grammar fuzzing, a **sincronização inicial com o servidor é ignorada por padrão** (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do alvo**; geralmente funciona melhor fazer a mudança depois que o worker encontra a maior parte da cobertura “fácil”.

## Snapshot Fuzzing Para Alvos Difíceis de Preparar

Quando o código que você quer testar só se torna acessível **após um grande custo de preparação** (inicializar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é **snapshot fuzzing**: capturar o estado pronto do processo ou da VM, injetar cada caso de teste no caminho de entrada do alvo, executar até ocorrer um crash/timeout e restaurar o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **alvos somente binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o alvo até que o estado desejado esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada modificada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer um crash/timeout/reset.
5. Restaure o snapshot; para alvos de VM, restaure apenas as **páginas sujas**, quando houver suporte, e repita.

Posicione o snapshot o mais perto possível da primeira etapa custosa de análise/dispatch, como após um `recv`/`read` ou um ponto de desserialização de pacotes, e registre o buffer de entrada usado pelo alvo. Isso segue o princípio de posicionamento adaptativo: mover o snapshot para mais adiante no processamento da entrada, evitando repetir trabalho.<sup>[[11]](#references)</sup>

## Exploração de Condições de Corrida do Kernel Linux com MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforma condições de corrida sensíveis ao timing no kernel Linux em sequências repetíveis de acesso à memória. Ele pode enumerar automaticamente execuções **A-B-A** em dois contextos ou permitir que um analista imponha restrições de ordem em uma interface de terminal/UI/GUI. É uma ferramenta de pesquisa experimental, não um fuzzer de concorrência completo: atualmente, requer LLVM 23+ e o kernel corrigido do projeto, as ferramentas de linha de comando oferecem suporte a duas threads de teste, e a camada de fuzzing proposta para userspace ainda não foi implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Coletar pontos de comunicação entre contextos

Compile o kernel instrumentado com callbacks KASAN outline e o suporte corrigido do KCOV para registro de memória. O README do projeto também recomenda desativar a otimização de sibling-call para que as pilhas de chamadas continuem utilizáveis.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

O modo outline do KASAN (`asan-instrumentation-with-call-threshold=0`) converte os acessos instrumentados em chamadas auxiliares. Os patches do kernel MAccConc desativam `asan-opt-same-temp` para que acessos consecutivos não sejam mesclados; desative também a otimização `asan-opt-globals` quando for necessário que as condições de corrida em variáveis globais fiquem visíveis. O KCOV transporta os registros resultantes para o espaço de usuário. Compare acessos de diferentes contextos de execução e mantenha os pares cujas faixas de bytes se sobrepõem e em que pelo menos um dos lados escreve; modele `kfree()` como uma escrita para que transições de ciclo de vida também se tornem candidatas.<sup>[[17]](#references)</sup>

Para trabalhos que escapam da tarefa que os iniciou, como processamento de pacotes ou callbacks de RCU, o subsistema precisa propagar um identificador de cobertura remota do KCOV. O KCOV remoto upstream é opt-in e não fica disponível automaticamente para trabalhos arbitrários em segundo plano; portanto, a falta de propagação pode tornar invisível uma interação real.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifique o mesmo acesso dinâmico em todas as execuções

Não reproduza usando um endereço concreto do heap, que pode mudar após cada alocação, nem apenas usando um endereço de instrução, que é ambíguo dentro de helpers como `memcpy()` e `spin_lock()`. O MAccConc usa um **stack trace aumentado com contagens**: cada frame identifica um callee e a contagem de invocações dentro de seu caller, e o elemento final identifica a instrução de acesso à memória. Os registros de entrada e saída de funções do SanitizerCoverage permitem que o espaço de usuário reconstrua esse identificador dinâmico, que permanece estável apesar de mudanças de endereço e de ruídos de fluxo de controle não relacionados.<sup>[[17]](#references)</sup>

### Converta pares candidatos em escalonamentos forçados

O ioctl `KCOV_SET_DI` com patch associa um identificador de acesso aumentado com contagens a uma ação de sinalizador compartilhado.<sup>[[17]](#references)</sup>

| Ação | Semântica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Define o sinalizador *N* imediatamente antes do acesso selecionado. |
| `DI_STACK_WAIT` | Antes do acesso selecionado, aguarda em loop até que o sinalizador *N* seja definido ou o limite configurado expire. |
| `DI_STACK_WAKE_POST` | Define o sinalizador *N* imediatamente após o acesso selecionado. |

Para uma restrição parcial **A-happens-before-B**, associe `DI_STACK_WAKE_POST` a A e `DI_STACK_WAIT` a B usando o mesmo sinalizador. Para um escalonamento totalmente especificado entre dois contextos, inicie B bloqueado; em seguida, faça A despertar B e aguarde no primeiro ponto de transferência. B executa a operação inversa na próxima transferência. O segundo método funciona como uma troca determinística de contexto e é o usado pelo explorador automático A-B-A.<sup>[[17]](#references)</sup>

Uma campanha mínima consiste em compilar o caso de teste com quatro hooks (`test_setup`, duas funções de thread e `test_end`) como uma biblioteca compartilhada, coletar um trace sem restrições e, em seguida, enumerar candidatos A-B-A ou adicionar restrições manuais em torno de acessos suspeitos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprete os timeouts separadamente dos reordenamentos bem-sucedidos: a ordem solicitada pode ser impossível porque um lock ou uma dependência de inicialização/publicação impede que o segundo contexto alcance seu ponto de injeção. Tenha também em mente os pontos cegos do KASAN: acessos diretos à stack geralmente não são instrumentados, a menos que possam ultrapassar os limites; variáveis globais são omitidas com a otimização padrão; e os compiladores atuais não conseguem emitir hooks de ASAN e TSAN simultaneamente. Por fim, o protótipo perde seu buffer KCOV quando uma máquina virtual convidada entra em panic, portanto, mantenha um console/oráculo de crash independente.<sup>[[17]](#references)</sup>

Para fuzzing futuro guiado por concorrência, registre resumos de acessos à memória por entrada ou syscall, combine operações que formariam pontos de comunicação entre contextos e, em seguida, explore apenas essas combinações. Snapshots de VMs estabilizam o estado global e os endereços; sem snapshots, metadados do local de alocação podem abstrair objetos entre execuções. Esta é uma extensão proposta, não um recurso das ferramentas userspace atuais do MAccConc.<sup>[[17]](#references)</sup>

## Introspecção do Harness: Identifique Fuzzers Superficiais Cedo

Quando uma campanha estagna, o problema geralmente não está no mutator, mas no **harness**. Use a **introspecção de alcançabilidade/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do alvo de fuzzing, mas raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um de três problemas.<sup>[[12]](#references)</sup>

- O harness entra no alvo tarde ou cedo demais.
- O corpus de seeds não contém uma família inteira de funcionalidades.
- O alvo realmente precisa de um **segundo harness**, em vez de um único harness enorme que “faz tudo”.

Se você usa fluxos de trabalho no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a alcançabilidade estática com a cobertura em tempo de execução e gerar relatórios a partir de uma execução cronometrada ou de um corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus para um recurso específico ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de alvos de fuzzing com grafo em primeiro lugar e triagem de mutações

Se você já tem **resultados de análise estática**, **mutantes sobreviventes aos testes de mutação** e **relatórios de cobertura**, não os analise como listas independentes. Primeiro, construa um **grafo de chamadas**, anote os nós com **complexidade ciclomática**, **alcance a partir de pontos de entrada/entrada não confiável** e quaisquer descobertas externas, depois investigue o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade podem ser alcançadas a partir de entradas não confiáveis?
- Quais mutantes sobreviventes estão em caminhos de parsers/handlers até código crítico para a segurança?
- Quais funções são gargalos arquiteturais com um **raio de impacto** excepcionalmente alto?

Isso geralmente revela alvos de fuzzing melhores do que apenas escolher o item com a "menor cobertura". Um parser/decoder com **alta complexidade** e **alcance externo confirmado** é um candidato a harness mais forte do que um helper interno isolado, com pouca cobertura, mas sem um caminho controlado por um atacante.

### Fluxo de trabalho prático para triagem

1. Construa um **grafo do código** a partir da base de código e extraia métricas de complexidade/ramificações por função.
2. Enumere os **pontos de entrada** que aceitam dados controlados por um atacante: handlers de requisições, decoders, importers, parsers de protocolos, leitores de CLI/arquivos.
3. Execute consultas de caminho a partir desses pontos de entrada até as funções candidatas para separar a superfície de ataque alcançável do código morto/interno.
4. Priorize os nós que combinam:
   - alta **complexidade ciclomática**
   - **alcance confirmado a partir de entradas não confiáveis**
   - alto **raio de impacto** ou muitos dependentes downstream
   - evidências que corroborem, como resultados de **SARIF**, notas de auditoria ou mutantes sobreviventes
5. Escreva harnesses focados primeiro para os nós com as melhores pontuações, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/mensagens.

### Mutantes sobreviventes: equivalentes ou acionáveis

Os testes de mutação frequentemente produzem uma lista ruidosa de mutantes sobreviventes. Antes de tratar cada sobrevivente como uma lacuna de segurança, use o grafo para perguntar:

- A função modificada pode ser alcançada a partir de um ponto de entrada controlado por um atacante?
- Todos os caminhos de chamada estão sujeitos a invariantes mais fortes do que a verificação modificada?
- O nó está em código morto, lógica que afeta apenas a formatação ou em um caminho de alto impacto relacionado a aritmética/parsing?

Mutantes sobreviventes que continuam inalcançáveis ou estruturalmente restritos costumam ser **mutantes equivalentes**. Mutantes sobreviventes que continuam **alcançáveis** e afetam **condições de limite**, **caminhos de overflow/carry** ou **aritmética/parsing crítico para a segurança** devem ser promovidos a:

- novos harnesses de fuzzing
- testes diretos de propriedades/invariantes
- vetores direcionados para casos extremos

### Correlacione descobertas externas com o grafo

Se o seu pipeline de SAST exporta **SARIF**, projete as descobertas nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para ampliar a análise de impacto.<sup>[[6]](#references)</sup>

- calcule o **raio de impacto** da função sinalizada
- verifique se a descoberta está em algum caminho a partir de um ponto de entrada
- agrupe descobertas próximas que convergem para o mesmo gargalo

Isso é útil ao decidir se vale a pena dedicar tempo de fuzzing a uma função específica: um nó **alcançável**, **complexo** e que já tem **resultados de SAST** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho controlado por um atacante.

Exemplo de fluxo de trabalho com Trailmark.<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher alvos de fuzzing com o maior valor de segurança esperado e, em seguida, use os sobreviventes das mutações para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing em Go com gosentry: mecanismo mais robusto, entradas tipadas e verificações diferenciais

Se um alvo em Go já tiver um harness nativo `testing.F`, um caminho prático de atualização é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), um toolchain de Go derivado que mantém `go test -fuzz`, mas substitui o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Isso é útil quando o fuzzer nativo do Go fica preso em **comparações difíceis**, **entradas tipadas** ou **formatos com parsers complexos**. A metodologia continua a mesma:

- Continue usando `f.Add(...)` para as seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com agendamento e mutação do LibAFL e detectores complementares melhores.

### Transformar falhas silenciosas em achados do fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos muitas vezes **não** causam crash por padrão. Com o gosentry, você pode transformar várias classes de estados “ruins, mas silenciosos” em achados.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram o erro e continuam).
- `--catch-races=true` para reproduzir novas entradas descobertas na fila usando o detector de race do Go.
- `--catch-leaks=true` para reproduzir novas entradas da fila com `goleak` e interromper a execução em caso de leaks de goroutines.
- O tratamento de hangs do LibAFL para manter **loops infinitos / entradas muito lentas** como achados do fuzzing, em vez de deixá-los desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos em que o impacto na segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **hang que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing de structs para APIs tipadas do Go

O fuzzing nativo do Go espera principalmente valores escalares, como `[]byte`, `string` e números. Se o código sob teste consome objetos tipados, o gosentry pode fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, pointers), continuando a mutar os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

Use isso quando criar um formato de wire falso apenas para fuzzing esconderia bugs de lógica por trás de código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolo

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **fuzzing de gramática Nautilus** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre a metodologia:

- Use o modo grammar quando mutações em nível de byte morrem principalmente nas verificações sintáticas iniciais.
- Mantenha a grammar focada no **subconjunto da linguagem/protocolo relevante para a segurança**, em vez de modelar toda a especificação.
- Use valores de limite grandes em terminais/não terminais para testar os limites de inteiros, comprimentos e máquinas de estado.
- O modo grammar mantém as entradas válidas segundo a grammar, mas o alvo ainda recebe **bytes/strings**; portanto, a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: compare implementações, não apenas crashes

Um padrão eficaz em ecossistemas Go é o **grammar-based differential fuzzing**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou mecanismos de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

Considere os seguintes casos como findings:

- uma implementação entra em panic, enquanto a outra rejeita a entrada corretamente
- divergências entre entradas aceitas e rejeitadas
- árvores de análise ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Esta é uma forma prática de encontrar **divergências de consenso**, **ambiguidades de parser** e **divergências entre especificação e implementação** que o fuzzing focado apenas em crashes muitas vezes não detecta.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilize o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Execute o comando no **mesmo pacote** e com o mesmo alvo `-fuzz` para que o gosentry resolva o estado em cache da campanha correto.



## References

- [1] [Fuzzing gramatical mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing com AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Faltava metade do kit de ferramentas ao fuzzing do Go. Fizemos um fork da toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede com estado usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: rumo ao fuzzing do kernel Linux sem descrições de chamadas de sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptáveis e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentação LLVM do AFL++: cobertura de caminhos e chamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing preditivo sensível ao contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de segurança ofensiva do Android - Fuzzing do Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer do Binder do LKL para Android - documentação de compilação e seeds de regressão](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: explorando condições de corrida no kernel Linux com intercalações controladas de acessos à memória](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
