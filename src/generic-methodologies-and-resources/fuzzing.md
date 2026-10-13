# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Cobertura vs. Semântica

No **fuzzing de gramática mutacional**, as entradas são mutadas enquanto permanecem **válidas segundo a gramática**. No modo guiado por cobertura, apenas as amostras que acionam **nova cobertura** são salvas como seeds do corpus. Para **alvos de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de fluxo de dados**, nas quais a saída de uma construção se torna a entrada de outra.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o fluxo de dados encadeado**, então a amostra “mais próxima do bug” é descartada porque não adiciona cobertura. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna custosa, e o feedback de cobertura não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **combinar fases mutacionais e generativas** ou direcionar a geração para padrões de **encadeamento de funções** (não apenas para cobertura).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por cobertura é **gulosa**: uma amostra com nova cobertura é salva imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas** com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil; portanto, um compromisso prático é a **minimização com reconhecimento de gramática**, que **para após um limite mínimo de tokens** (reduzindo o ruído e mantendo estrutura ao redor suficiente para facilitar mutações).<sup>[[1]](#references)</sup>

Uma regra prática para corpora de fuzzing mutacional é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximize a cobertura** a um grande acúmulo de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do alvo).
- Refine-as com **minimização de corpus baseada em cobertura**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos relevantes, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após mudanças importantes no harness/instrumentação, pois o “melhor” corpus muda quando a alcançabilidade muda.

## Mutação Orientada a Comparações para Valores Mágicos

Um motivo comum para os fuzzers estagnarem não é a sintaxe, mas as **comparações rígidas**: bytes mágicos, verificações de comprimento, strings de enum, checksums ou valores de despacho do parser protegidos por `memcmp`, tabelas switch ou comparações em cascata. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses alvos, use **rastreamento de comparações** (por exemplo, workflows no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar os operandos de comparações malsucedidas e direcionar as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>

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

**Notas práticas:**

- Isso é especialmente útil quando o alvo protege a lógica mais profunda com **assinaturas de arquivo**, **verbos de protocolo**, **tags de tipo** ou **bits de funcionalidade dependentes da versão**.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de depuração. Um dicionário pequeno com tokens de gramática, nomes de blocos, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo executar muitas verificações sequenciais, resolva primeiro as comparações “magic” mais iniciais e depois reduza novamente o corpus resultante para que as etapas seguintes comecem com prefixos já válidos.

## Fazer fuzzing de APIs de arquivos que ocultam uma linguagem de nomes de arquivo

Um parâmetro chamado `filename`, `path` ou `URL` pode ser um ponto de entrada para um interpretador, em vez de uma busca literal por arquivo. Por exemplo, a Extended Filename Syntax (EFS) do CFITSIO avalia seletores entre colchetes, expressões de linha/pixel, colunas calculadas, histogramas e transformações antes de retornar o objeto aberto; algumas formas também criam cópias temporárias. Ao mapear a superfície de ataque, classifique cada API de abertura/importação como **caminho literal** ou **caminho interpretado** e, em seguida, faça fuzzing do ponto de entrada de produção que as aplicações realmente chamam.<sup>[[20]](#references)[[22]](#references)</sup>

Para os primitivos de SSRF, cópia de arquivos e manipulador de protocolo resultantes — e para APIs de caminho literal mais seguras — consulte [Minilinguagens de nomes de arquivo como primitivos de SSRF/arquivo](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantenha o objeto subjacente separado do programa submetido a fuzzing

Quando a gramática está em um sufixo do nome do arquivo, mutar apenas os bytes do arquivo referenciado não alcança o parser. Em vez disso, um harness pequeno pode ler um testcase como string e passá-lo à API de abertura interpretada; a campanha do CFITSIO alcançou a maioria dos parsers e avaliadores de EFS chamando `fits_open_file()` em modo somente leitura. Mantenha arquivos válidos disponíveis separadamente para que as mutações possam se concentrar na linguagem de seletores/expressões, sem corromper continuamente o caminho base.<sup>[[22]](#references)</sup>

Use seeds que alcancem, cada um, uma família gramatical diferente e, em seguida, derive um dicionário compacto tanto da especificação quanto do código-fonte do lexer/parser. Se a cobertura estagnar enquanto as entradas falham repetidamente no mesmo caminho de erro de sintaxe, preserve prefixos válidos e adicione delimitadores, operadores, palavras-chave, nomes de funções e nomes de campos representativos, em vez de apenas aumentar o tempo de mutação aleatória.<sup>[[22]](#references)</sup>

Execute o harness com o dicionário da gramática, por exemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Conter efeitos colaterais do harness "read-only"

Uma flag de biblioteca read-only não garante que um testcase não tenha efeitos colaterais: a linguagem de nomes de arquivo pode reescrever a entrada, criar arquivos de saída ou materializar objetos temporários. A campanha com CFITSIO inicialmente destruiu arquivos-semente e deixou arquivos inesperados pelo sistema de arquivos, por isso foram necessários limpeza e isolamento.<sup>[[22]](#references)</sup>

- Dê a cada worker um diretório de trabalho descartável e um diretório temporário privado.
- Disponibilize cópias dos arquivos de referência canônicos; nunca permita que o alvo modifique a única cópia do corpus.
- Desative o acesso à rede, a menos que backends remotos sejam o alvo pretendido, e restrinja os caminhos graváveis com um container, mount namespace ou sandbox equivalente.
- Redefina o diretório após cada execução ou lote de workers e trate alterações inesperadas no sistema de arquivos como descobertas adicionais.

### Ciclo de crash a patch e fuzzing

Agrupe os crashes antes de corrigi-los para que milhares de artefatos não se tornem milhares de tarefas de patch. Na avaliação do CFITSIO, o AFLTriage reduziu o conjunto inicial de crashes a algumas causas-raiz; o advisory resultante mostra falhas distintas, incluindo verificações incorretas do tamanho do destino, ponteiros obsoletos após `realloc()`, erros aritméticos e caminhos inseguros de limpeza do parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimize uma entrada representativa de cada grupo e reproduza-a com AddressSanitizer.
2. Registre o acesso exato que falhou, a localização no código-fonte, o histórico de alocações e liberações e o estado do parser que tornou a invariante falsa.
3. Aplique um patch candidato de escopo restrito e recompile com a mesma instrumentação de cobertura e sanitizer.
4. Reproduza o caso original **e todas as entradas do grupo**; habilite também a detecção de leaks, pois uma correção de segurança de memória pode prejudicar o gerenciamento de recursos em um caminho de erro.
5. Execute testes funcionais com arquivos reais e, em seguida, retome a partir da queue acumulada (ou reimporte essa queue se o engine exigir um diretório de saída novo após a alteração do binário).
6. Repita: remover o primeiro crash superficial muitas vezes permite que as seeds existentes avancem para um estado mais profundo do parser.

Um LLM pode acelerar a etapa 2 e elaborar um rascunho para a etapa 3 quando recebe a entrada que causa o crash, o relatório do sanitizer, o harness e o código-fonte relevante, mas seu patch continua não confiável. A reprodução com sanitizer e os critérios de regressão — não a explicação do modelo — determinam se a correção é aceita.<sup>[[22]](#references)</sup>

## Feedback Mais Rico Quando a Cobertura de Arestas Colapsa Caminhos Diferentes

A cobertura normal de arestas não distingue duas execuções que percorrem o mesmo helper por callers diferentes ou seguem combinações diferentes de branches dentro de uma função. Isso importa em decoders compartilhados, dispatchers de protocolo e helpers de interpretadores, onde a **rota** até uma aresta determina o estado ativo. Rastrear ingenuamente todos os contextos de chamada também é perigoso: o mapa de cobertura e a queue podem explodir. Por isso, pesquisas sobre fuzzing sensível ao contexto recomendam refinar apenas contextos promissores, em vez de tratar todo o grafo de chamadas como sensível ao contexto.<sup>[[14]](#references)</sup>

Versões recentes do AFL++ oferecem **cobertura de caminhos por função Ball-Larus**, além da cobertura normal de arestas. Ela atribui um recurso a cada caminho acíclico por uma função; as arestas de retorno dos loops são removidas, então esse feedback distingue combinações de branches, mas **não a quantidade de iterações do loop**. Comece com o nível relaxado `1` e, em seguida, aplique modos mais estritos apenas a código suspeito de parser ou máquina de estados, pois o número de caminhos pode crescer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para um helper chamado em muitos locais relevantes para a segurança, o modo LTO pode combinar cada caminho de função com seu local de chamada imediato:<sup>[[13]](#references)</sup>

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

**Orientação para a campanha:** aplique feedback mais rico de forma conservadora e monitore o custo de coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Execute em paralelo uma instância comum de edge-coverage; feedback mais rico só é útil se o custo adicional de queue/map não reduzir as execuções por segundo.
- Use `AFL_LLVM_ALLOWLIST` para restringir a instrumentação de path/caller quando bibliotecas grandes e cheias de templates ou código utilitário genérico dominarem o map.
- Funções com caminhos acíclicos excessivos podem ser ignoradas pelo AFL++; avisos durante a compilação indicam que o alvo precisa de allowlisting ou de um nível menos rigoroso.
- Caller + path coverage suporta apenas uma profundidade de caller. Não combine com stacks de contexto mais profundos.
- Os IDs de path podem mudar entre versões principais do LLVM. Mantenha a toolchain fixa durante a campanha e não sincronize corpora baseados em PATH como se os IDs de seus recursos fossem estáveis entre builds.
- Esse feedback complementa o `CMPLOG`: o tracing de comparações resolve **qual valor passa por uma guard**, enquanto o feedback de path/caller preserva **qual rota e combinação de branches levou até ela**.

## Fuzzing com estado: sequências são seeds

Para **protocolos**, **fluxos de trabalho autenticados** e **parsers em várias etapas**, a unidade interessante geralmente não é um único blob, mas uma **sequência de mensagens**. Concatenar toda a transcrição em um único arquivo e mutá-la às cegas costuma ser ineficiente, pois o fuzzer altera cada etapa igualmente, mesmo quando apenas a mensagem posterior chega ao estado frágil.<sup>[[4]](#references)</sup>

Um padrão mais eficaz é tratar a **própria sequência como seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos de objetos retornados) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha estáveis as **mensagens de prefixo válidas** e concentre as mutações na mensagem que **impulsiona a transição**.
- Armazene em cache os identificadores e valores gerados pelo servidor nas respostas anteriores quando a etapa seguinte depender deles.
- Prefira mutação/splicing por mensagem, em vez de mutar toda a transcrição serializada como um blob opaco.
- Se o protocolo expuser códigos de resposta relevantes, use-os como um **oráculo de estado barato** para priorizar sequências que avancem mais.

É por isso que bugs autenticados, transições ocultas ou bugs de parser que só ocorrem “após o handshake” muitas vezes passam despercebidos no fuzzing convencional no estilo de arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de driver com vários clientes

Uma alta edge coverage ainda pode deixar passar bugs no driver IPC, pois a cobertura não descreve **propriedade de objetos, contagens de referências, mensagens pendentes, ordem de limpeza ou intercalamentos de threads**. A página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) aborda o modelo de objetos do driver; este exemplo se concentra no harness do fuzzer. Android Binder é um modelo útil: alcançar tanto os caminhos de alocação quanto os de liberação não basta se o fuzzer não conseguir fazer vários processos operarem no mesmo objeto do kernel na ordem necessária.<sup>[[15]](#references)</sup>

#### Modele o protocolo, não buffers `ioctl` isolados

Represente um caso de teste como uma gramática ordenada de **identidade do cliente + operação + argumentos estruturados**. O fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, com um cliente gerenciador de contexto persistente e dois clientes comuns. Em seguida, um harness semântico preserva as relações que a mutação cega de bytes destruiria.<sup>[[15]](#references)</sup>

- Armazene em cache os valores retornados por operações anteriores. Por exemplo, `BC_FREE_BUFFER` precisa reutilizar um ponteiro para o buffer de transação retornado por um `ioctl` anterior.
- Gere respostas padrão válidas para permitir que transações síncronas sejam concluídas e que operações posteriores continuem alcançáveis.
- Rejeite transições impossíveis, como transações para o próprio cliente ou várias transações pendentes para o mesmo destino.
- Mantenha o estado singleton de inicialização fora do reset por entrada. Binder permite apenas um registro `BINDER_SET_CONTEXT_MGR` por boot, então destruir e recriar repetidamente esse cliente invalidaria as entradas posteriores.

Um modelo útil para uma corrida de ciclo de vida é fazer um cliente transferir um objeto, iniciar a limpeza de uma thread ou processo e, simultaneamente, fazer o cliente receptor liberar o buffer de transação. No exemplo CVE-2020-0423, uma transferência `BINDER_TYPE_WEAK_BINDER`, seguida por `BINDER_THREAD_EXIT` concorrendo com `BC_FREE_BUFFER`, podia liberar um `binder_work` embutido enquanto o caminho de limpeza da thread em encerramento ainda o usava.<sup>[[15]](#references)</sup>

#### Reintroduza intercalamentos controlados em um kernel em espaço de usuário

A [Linux Kernel Library (LKL)](https://github.com/lkl/linux) vincula o código real do kernel a um harness em espaço de usuário e expõe sua interface de chamadas de sistema por meio de `lkl_syscall`. Isso facilita coordenar protobuf, cobertura e KASAN em um único processo. No entanto, normalmente a LKL executa uma chamada de sistema sem que outra thread do kernel a interrompa. Para campanhas de corrida, insira pontos `schedule()` em torno de limites selecionados de lock/unlock e ciclo de vida, e então deixe o harness escolher aleatoriamente o próximo cliente a cada yield. Mantenha esses pontos direcionados, pois cada um multiplica o espaço de busca do escalonamento. O escalonador aleatório descrito pelos pesquisadores **não** faz parte do fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compile e reproduza seeds de regressão serializadas

O harness upstream fixa uma versão compatível de `libprotobuf-mutator`, habilita a instrumentação de fuzzing da LKL e o KASAN com `LKL_FUZZING=1`, e habilita `CONFIG_MMU` para Binder com `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Depois de conferir uma revisão intencionalmente vulnerável ou aplicar os patches de rollback documentados no upstream, uma semente serializada pode reproduzir toda a transição de estado entre vários clientes sem reconstruí-la em uma prova de conceito improvisada em C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trate o use-after-free resultante no KASAN como confirmação de que o seed alcançou o caminho vulnerável do ciclo de vida. Isso **não** demonstra as primitivas posteriores necessárias para executar código no kernel ou escalar privilégios.<sup>[[16]](#references)</sup>

## Truque de diversidade em máquina única (estilo Jackalope)

Uma maneira prática de combinar **novidade generativa** com **reutilização de cobertura** é **reiniciar workers de curta duração** contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos usando o corpus combinado, sincroniza novamente e então encerra. Isso gera **estruturas novas a cada geração** e ainda aproveita a cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

**Servidor:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers sequenciais (exemplo de loop):**

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
- No modo de grammar fuzzing, a **sincronização inicial com o servidor é ignorada por padrão** (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do alvo**; em geral, funciona melhor mudar depois que o worker encontra a maior parte da cobertura “fácil”.

## Snapshot Fuzzing Para Alvos Difíceis de Instrumentar

Quando o código que você quer testar só fica acessível **após um custo elevado de preparação** (inicializar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é o **snapshot fuzzing**: capturar o estado do processo ou da VM quando estiver pronto, injetar cada caso de teste no caminho de entrada do alvo, executar até ocorrer um crash/timeout e restaurar o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **alvos somente binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o alvo até que o estado desejado esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada mutada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer um crash/timeout/reset.
5. Restaure o snapshot; para alvos em VM, restaure apenas as **páginas sujas**, quando houver suporte, e repita.

Posicione o snapshot o mais perto possível da primeira etapa dispendiosa de análise/dispatch, como após um `recv`/`read` ou um ponto de desserialização de pacotes, e registre o buffer de entrada usado pelo alvo. Isso segue o princípio de posicionamento adaptativo: mover o snapshot para mais perto do processamento da entrada, evitando repetir trabalho.<sup>[[11]](#references)</sup>

## Exploração de Race Conditions no Kernel Linux com MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforma race conditions sensíveis ao timing no kernel Linux em sequências repetíveis de acessos à memória. Ele pode enumerar automaticamente execuções **A-B-A** em dois contextos ou permitir que um analista imponha restrições de ordem em uma interface de terminal/GUI. É uma ferramenta experimental de pesquisa, não um concurrency fuzzer completo: atualmente, requer LLVM 23+ e o kernel corrigido do projeto; as ferramentas de linha de comando oferecem suporte a duas threads de teste; e a camada proposta de fuzzing em userspace ainda não foi implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Coletar pontos de comunicação entre contextos

Compile o kernel instrumentado com callbacks outline do KASAN e o suporte corrigido de registro de memória do KCOV. O README do projeto também recomenda desativar a otimização de sibling calls para manter utilizáveis as pilhas de chamadas.<sup>[[17]](#references)[[18]](#references)</sup>

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

O modo outline do KASAN (`asan-instrumentation-with-call-threshold=0`) converte os acessos instrumentados em chamadas auxiliares. Os patches do kernel MAccConc desabilitam `asan-opt-same-temp` para que acessos consecutivos não sejam combinados; desabilite também a otimização `asan-opt-globals` quando for necessário tornar visíveis as corridas em variáveis globais. O KCOV transporta os registros resultantes para o espaço do usuário. Compare acessos de diferentes contextos de execução e retenha os pares cujos intervalos de bytes se sobrepõem e em que pelo menos um lado grava; modele `kfree()` como uma gravação para que as transições de ciclo de vida também se tornem candidatas.<sup>[[17]](#references)</sup>

Para trabalhos que escapam da tarefa que os iniciou, como processamento de pacotes ou callbacks de RCU, o subsistema precisa propagar um identificador de cobertura remota do KCOV. O KCOV remoto upstream é opt-in e não fica automaticamente disponível para trabalhos arbitrários em segundo plano; portanto, a falta de propagação pode tornar uma interação real invisível.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifique o mesmo acesso dinâmico em cada execução

Não reproduza usando um endereço concreto do heap, que pode mudar após cada alocação, nem apenas usando um endereço de instrução, que é ambíguo dentro de auxiliares como `memcpy()` e `spin_lock()`. O MAccConc usa um **rastreamento de pilha aumentado com contagens**: cada frame identifica uma função chamada e a contagem de invocações dentro da função chamadora, e o elemento final identifica a instrução de acesso à memória. Os registros de entrada/saída de funções do SanitizerCoverage permitem que o espaço do usuário reconstrua esse identificador dinâmico, que permanece estável apesar de mudanças de endereço e ruídos de fluxo de controle não relacionados.<sup>[[17]](#references)</sup>

### Converta pares candidatos em escalonamentos forçados

O ioctl corrigido `KCOV_SET_DI` associa um identificador de acesso aumentado com contagens a uma ação de flag compartilhada.<sup>[[17]](#references)</sup>

| Ação | Semântica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Define a flag *N* imediatamente antes do acesso selecionado. |
| `DI_STACK_WAIT` | Antes do acesso selecionado, aguarda em loop até que a flag *N* seja definida ou o limite configurado expire. |
| `DI_STACK_WAKE_POST` | Define a flag *N* imediatamente após o acesso selecionado. |

Para uma restrição parcial **A acontece antes de B**, associe `DI_STACK_WAKE_POST` a A e `DI_STACK_WAIT` a B usando a mesma flag. Para um escalonamento totalmente especificado entre dois contextos, inicie B bloqueado; em seguida, faça A desbloquear B e aguardar no primeiro ponto de transferência. B executa a operação inversa no próximo ponto de transferência. Isso funciona como uma troca determinística de contexto e é o que o explorador automático A-B-A usa.<sup>[[17]](#references)</sup>

Uma campanha mínima consiste em compilar o caso de teste de quatro hooks (`test_setup`, duas funções de thread e `test_end`) como uma biblioteca compartilhada, coletar um rastreamento sem restrições e, então, enumerar candidatos A-B-A ou adicionar restrições manuais em torno de acessos suspeitos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprete os timeouts separadamente dos reordenamentos bem-sucedidos: a ordem solicitada pode ser impossível porque um lock ou uma dependência de inicialização/publicação impede que o segundo contexto alcance seu ponto de injeção. Tenha em mente também os pontos cegos do KASAN: acessos diretos à stack geralmente não são instrumentados, a menos que possam estar fora dos limites; variáveis globais são omitidas com a otimização padrão; e os compiladores atuais não conseguem emitir hooks do ASAN e do TSAN simultaneamente. Por fim, o protótipo perde seu buffer do KCOV quando uma VM guest entra em panic, então mantenha um console/oráculo de crash independente.<sup>[[17]](#references)</sup>

Para fuzzing guiado por concorrência no futuro, registre resumos de acessos à memória por entrada ou por syscall, emparelhe operações que formariam pontos de comunicação entre contextos e, em seguida, explore apenas essas combinações. Snapshots de VM estabilizam o estado global e os endereços; sem snapshots, os metadados dos locais de alocação podem abstrair objetos entre execuções. Esta é uma extensão proposta, não um recurso das ferramentas userspace atuais do MAccConc.<sup>[[17]](#references)</sup>

## Introspecção do Harness: Encontre Fuzzers Rasos Cedo

Quando uma campanha estagna, muitas vezes o problema não está no mutator, mas no **harness**. Use a **introspecção de alcançabilidade/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do alvo de fuzzing, mas raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um de três problemas.<sup>[[12]](#references)</sup>

- O harness entra no alvo tarde demais ou cedo demais.
- O corpus de seeds não contém uma família inteira de funcionalidades.
- O alvo realmente precisa de um **segundo harness**, em vez de um único harness enorme que “faz tudo”.

Se você usa fluxos de trabalho no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a alcançabilidade estática com a cobertura em tempo de execução e gerar relatórios a partir de uma execução cronometrada ou de um corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus para um recurso específico ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de alvos de fuzzing com prioridade para grafos e triagem de mutações

Se você já tem **achados de análise estática**, **sobreviventes de testes de mutação** e **relatórios de cobertura**, não os faça triagem como listas independentes. Primeiro, construa um **grafo de chamadas**, anote os nós com a **complexidade ciclomática**, a **alcançabilidade a partir de pontos de entrada/entradas não confiáveis** e quaisquer achados externos, depois faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade podem ser alcançadas a partir de entradas não confiáveis?
- Quais sobreviventes de mutação estão nos caminhos entre parsers/handlers e código crítico para a segurança?
- Quais funções são pontos de estrangulamento arquiteturais com um **blast radius** excepcionalmente grande?

Isso geralmente revela alvos de fuzzing melhores do que apenas escolher os de "menor cobertura". Um parser/decoder com **alta complexidade** e **alcançabilidade externa** confirmada é um candidato a harness mais forte do que um helper interno isolado com baixa cobertura, mas sem um caminho controlado pelo atacante.

### Fluxo prático de triagem

1. Construa um **grafo de código** a partir da base de código e extraia métricas de complexidade/ramificações por função.
2. Enumere os **pontos de entrada** que aceitam entradas controladas pelo atacante: handlers de requisição, decoders, importadores, parsers de protocolo, leitores de CLI/arquivos.
3. Execute consultas de caminho a partir desses pontos de entrada até as funções candidatas para separar a superfície de ataque alcançável do código morto/somente interno.
4. Priorize nós que combinem:
   - alta **complexidade ciclomática**
   - **alcançabilidade a partir de entrada não confiável** confirmada
   - **blast radius** elevado ou muitos dependentes downstream
   - evidências corroborantes, como achados **SARIF**, notas de auditoria ou sobreviventes de mutação
5. Escreva harnesses focados primeiro para os nós com as melhores pontuações, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensagens.

### Sobreviventes de mutação: equivalentes vs. acionáveis

Os testes de mutação costumam produzir uma lista ruidosa de sobreviventes. Antes de tratar cada sobrevivente como uma falha de segurança, use o grafo para perguntar:

- A função mutada pode ser alcançada a partir de um ponto de entrada controlado pelo atacante?
- Todos os caminhos de chamada são restringidos por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica apenas de formatação ou em um caminho de aritmética/parser de alto impacto?

Sobreviventes que continuam inacessíveis ou estruturalmente restringidos costumam ser **mutantes equivalentes**. Sobreviventes que permanecem **alcançáveis** e afetam **condições de limite**, **caminhos de overflow/carry** ou **aritmética/parsing críticos para a segurança** devem ser promovidos a:

- novos fuzz harnesses
- testes diretos de propriedades/invariantes
- vetores direcionados de casos extremos

### Correlacione achados externos com o grafo

Se seu pipeline de SAST exporta **SARIF**, projete os achados nos nós do grafo usando **arquivo + intervalo de linhas** e use o grafo para ampliar a avaliação do impacto.<sup>[[6]](#references)</sup>

- calcule o **blast radius** da função sinalizada
- verifique se o achado está em algum caminho a partir de um ponto de entrada
- agrupe achados próximos que convergem para o mesmo ponto de estrangulamento

Isso é útil ao decidir se vale a pena dedicar tempo de fuzzing a uma função específica: um nó **alcançável**, **complexo** e que já tenha **achados de SAST** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho controlado pelo atacante.

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

A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher os alvos de fuzzing com maior valor esperado para a segurança e, em seguida, use os sobreviventes de mutação para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing em Go com gosentry: mecanismo mais forte, entradas tipadas e verificações diferenciais

Se um alvo em Go já tiver um harness nativo `testing.F`, um caminho prático de atualização é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), uma toolchain de Go derivada que mantém `go test -fuzz`, mas troca o backend para **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Isso é útil quando o fuzzer nativo do Go fica preso em **comparações difíceis**, **entradas tipadas** ou **formatos com muitos parsers**. A metodologia continua a mesma:

- Continue usando `f.Add(...)` para as sementes e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com agendamento/mutação do LibAFL e detectores adicionais mais eficazes.

### Transformar falhas silenciosas em achados de fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos muitas vezes **não** causam falhas por padrão. Com o gosentry, você pode transformar várias classes de estados “ruins, mas silenciosos” em achados.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer caminhos selecionados de logging/erro se comportarem como falhas (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram o erro e continuam).
- `--catch-races=true` para reexecutar entradas recém-descobertas da fila com o detector de condições de corrida do Go.
- `--catch-leaks=true` para reexecutar novas entradas da fila com `goleak` e interromper a execução quando houver vazamentos de goroutines.
- O tratamento de travamentos do LibAFL mantém **loops infinitos / entradas muito lentas** como achados de fuzzing, em vez de deixá-los desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos cujo impacto na segurança decorre de uma **falha de parser sem panic**, de um **bug de concorrência** ou de um **travamento que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing com reconhecimento de structs para APIs Go tipadas

O fuzzing nativo do Go espera principalmente escalares como `[]byte`, `string` e números. Se o código em teste consumir objetos tipados, o gosentry pode fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, pointers), enquanto continua mutando os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Use isso quando criar um formato wire falso apenas para fuzzing ocultaria bugs de lógica por trás de código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolo

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **fuzzing gramatical Nautilus** com base no LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas de metodologia:

- Use grammar mode quando mutações no nível de byte morrem principalmente em verificações sintáticas iniciais.
- Mantenha a gramática focada no **subconjunto da linguagem/protocolo relevante para a segurança**, em vez de modelar toda a especificação.
- Use valores de limite grandes em terminais/não terminais para estressar limites de inteiros, comprimentos e máquinas de estado.
- Grammar mode mantém as entradas válidas segundo a gramática, mas o alvo ainda recebe **bytes/strings**, então a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: compare implementações, não apenas crashes

Um padrão eficaz nos ecossistemas Go é o **fuzzing diferencial baseado em gramática**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou mecanismos de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>

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

- uma implementação entra em panic enquanto a outra rejeita a entrada corretamente
- divergências entre entradas aceitas e rejeitadas
- árvores de análise ou objetos decodificados diferentes
- divergências nas transições de estado, nonces, saldos ou raízes de estado

Esta é uma forma prática de encontrar **divergências de consenso**, **ambiguidades de parser** e **desvios entre a especificação e a implementação** que o fuzzing focado apenas em crashes costuma não detectar.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilizar o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Execute o comando do **mesmo pacote** e com o mesmo alvo `-fuzz` para que o gosentry resolva o estado em cache da campanha correto.



## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing com AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Faltava metade das ferramentas para o fuzzing em Go. Fizemos um fork do toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
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
- [20] [Sintaxe de nomes de arquivo estendidos do CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Comunicado da Doyensec: CFITSIO, quarto trimestre de 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing da sintaxe de nomes de arquivo estendidos do CFITSIO: 16 vulnerabilidades de segurança de memória e triagem assistida pelo Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
