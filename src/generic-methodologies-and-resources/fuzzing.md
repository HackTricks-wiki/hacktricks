# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Cobertura vs. Semântica

No **mutational grammar fuzzing**, as entradas são mutadas mantendo-se **válidas segundo a gramática**. No modo guiado por cobertura, apenas amostras que acionam **nova cobertura** são salvas como seeds do corpus. Para **alvos de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de fluxo de dados**, nas quais a saída de uma construção se torna a entrada de outra.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o fluxo de dados encadeado**; assim, a amostra “mais próxima do bug” é descartada porque não adiciona cobertura. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna custosa e o feedback de cobertura não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **combinar fases mutacionais e generativas** ou favorecer padrões de **encadeamento de funções** durante a geração (não apenas a cobertura).<sup>[[1]](#references)</sup>

## Armadilhas da diversidade do corpus

A mutação guiada por cobertura é **gulosa**: uma amostra que gera nova cobertura é salva imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas**, com baixa diversidade estrutural. Uma minimização agressiva pode remover contexto útil; por isso, um compromisso prático é a **minimização ciente da gramática**, que **para após atingir um limite mínimo de tokens** (reduzindo o ruído sem remover estrutura circundante suficiente para continuar favorecendo mutações).<sup>[[1]](#references)</sup>

Uma regra prática para o corpus de mutational fuzzing é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximize a cobertura** a uma grande pilha de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do alvo).
- Depure-as com **minimização de corpus baseada em cobertura**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos relevantes, em vez de gastar a maioria dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após grandes mudanças no harness/instrumentação, pois o “melhor” corpus muda quando a alcançabilidade muda.

## Programas grandes gerados e viés de timeout

No fuzzing de compiladores e interpretadores, uma entrada pode precisar ultrapassar um **limite de tamanho do código gerado**, em vez de alcançar um novo ramo do parser. No exemplo de [offset do manipulador de exceções](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size) do V8, um testcase válido precisava ultrapassar 256 MiB de bytecode antes que o offset truncado do manipulador tivesse efeito. Construções `yield*` repetidas podiam atingir esse limite, mas compilar o testcase levava segundos em uma build de debug. Preferências por entradas pequenas e timeouts curtos de execução podem desfavorecer essa classe, mesmo quando a cobertura da gramática é alta. Ao auditar offsets compactados ou outros metadados sensíveis ao comprimento, considere separadamente os limites de tamanho e a política de timeout; essa recomendação para campanhas é uma inferência baseada no modo de falha relatado.<sup>[[29]](#references)</sup>

## Mutação ciente de comparações para valores mágicos

Um motivo comum para os fuzzers estagnarem não é a sintaxe, mas as **comparações difíceis**: bytes mágicos, verificações de comprimento, strings de enumeração, checksums ou valores de dispatch do parser protegidos por `memcmp`, tabelas `switch` ou comparações em cascata. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses alvos, use **rastreamento de comparações** (por exemplo, fluxos de trabalho no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar os operandos de comparações que falharam e direcionar as mutações a valores que as satisfaçam.<sup>[[3]](#references)</sup>

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

- Isso é especialmente útil quando o alvo protege a lógica interna com **assinaturas de arquivo**, **verbos de protocolo**, **tags de tipo** ou **bits de recursos dependentes da versão**.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de depuração. Um dicionário pequeno com tokens gramaticais, nomes de chunks, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo executar muitas verificações sequenciais, resolva primeiro as comparações “mágicas” iniciais e depois minimize novamente o corpus resultante para que os estágios seguintes comecem com prefixos já válidos.

## Fuzzing de APIs de arquivo que ocultam uma linguagem de nomes de arquivo

Um parâmetro chamado `filename`, `path` ou `URL` pode ser um ponto de entrada para um interpretador, em vez de uma busca literal por arquivo. Por exemplo, a CFITSIO Extended Filename Syntax (EFS) avalia seletores entre colchetes, expressões de linhas/pixels, colunas calculadas, histogramas e transformações antes de retornar o objeto aberto; algumas formas também criam cópias temporárias. Durante o mapeamento da superfície de ataque, classifique cada API de abertura/importação como **caminho literal** ou **caminho interpretado** e, em seguida, aplique fuzzing ao ponto de entrada de produção que os aplicativos realmente chamam.<sup>[[20]](#references)[[22]](#references)</sup>

Para ver as primitivas de SSRF, cópia de arquivos e manipuladores de protocolo resultantes — e APIs de caminho literal mais seguras — consulte [Minilinguagens de nomes de arquivo como primitivas de SSRF/arquivo](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantenha o objeto de suporte separado do programa submetido ao fuzzing

Quando a gramática está em um sufixo do nome de arquivo, modificar apenas os bytes do arquivo referenciado não alcança o parser. Em vez disso, um harness pequeno pode ler um testcase como string e passá-lo à API de abertura interpretada; a campanha da CFITSIO alcançou a maioria dos parsers e avaliadores de EFS chamando `fits_open_file()` em modo somente leitura. Mantenha arquivos de suporte válidos disponíveis separadamente para que as mutações possam se concentrar na linguagem de seletores/expressões, em vez de danificar continuamente o caminho base.<sup>[[22]](#references)</sup>

Use seeds que alcancem famílias gramaticais diferentes e, em seguida, derive um dicionário compacto tanto da especificação quanto do código-fonte do lexer/parser. Se a cobertura estagnar enquanto as entradas falham repetidamente no mesmo caminho de erro de sintaxe, preserve prefixos válidos e adicione delimitadores, operadores, palavras-chave, nomes de funções e nomes de campos representativos, em vez de apenas aumentar o tempo de mutação aleatória.<sup>[[22]](#references)</sup>

Execute o harness com o dicionário gramatical, por exemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Conter efeitos colaterais do harness "read-only"

Uma flag de biblioteca read-only não garante um testcase sem efeitos colaterais: a linguagem de nomes de arquivo pode reescrever a entrada, criar arquivos de saída ou materializar objetos temporários. A campanha com CFITSIO inicialmente destruiu arquivos seed e deixou arquivos inesperados pelo sistema de arquivos, tornando necessária a limpeza e o isolamento.<sup>[[22]](#references)</sup>

- Dê a cada worker um diretório de trabalho descartável e um diretório temporário privado.
- Disponibilize cópias dos arquivos canônicos de suporte; nunca permita que o alvo modifique a única cópia do corpus.
- Desative o acesso à rede, a menos que backends remotos sejam o alvo pretendido, e restrinja os caminhos graváveis com um container, mount namespace ou sandbox equivalente.
- Redefina o diretório após cada execução ou lote de workers e trate alterações inesperadas no sistema de arquivos como descobertas adicionais.

### Loop de crash a patch e fuzzing

Agrupe os crashes antes de corrigi-los para que milhares de artefatos não se transformem em milhares de tarefas de patch. Na avaliação do CFITSIO, AFLTriage reduziu o conjunto inicial de crashes a algumas causas-raiz; o advisory resultante mostra falhas distintas, incluindo verificações incorretas do tamanho do destino, ponteiros obsoletos após `realloc()`, falhas aritméticas e caminhos inseguros de limpeza do parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimize uma entrada representativa de cada grupo e reproduza-a com AddressSanitizer.
2. Registre o acesso exato que falhou, a localização no código-fonte, o histórico de alocação/liberação e o estado do parser que tornou falsa a invariante.
3. Aplique um patch candidato de escopo restrito e recompile com a mesma instrumentação de coverage e sanitizer.
4. Reproduza o caso original **e todas as entradas do grupo**; habilite também a detecção de leaks, pois uma correção de segurança de memória pode comprometer o gerenciamento de ownership em um caminho de erro.
5. Execute testes funcionais com arquivos reais e retome a partir da queue acumulada (ou importe essa queue novamente, caso o engine exija um diretório de saída novo após a alteração do binário).
6. Repita: remover o primeiro crash superficial geralmente permite que os seeds existentes avancem para um estado mais profundo do parser.

Um LLM pode acelerar a etapa 2 e elaborar um rascunho para a etapa 3 quando recebe a entrada que causa o crash, o relatório do sanitizer, o harness e o código-fonte relevante, mas seu patch continua não sendo confiável. A reprodução com sanitizer e os critérios de regressão — não a explicação do modelo — determinam se a correção é aceita.<sup>[[22]](#references)</sup>

## Feedback mais rico quando Edge Coverage colapsa caminhos diferentes

A edge coverage normal não consegue distinguir duas execuções que percorrem o mesmo helper por callers diferentes ou seguem combinações de branches diferentes dentro de uma função. Isso importa em decoders compartilhados, dispatchers de protocolo e helpers de interpretadores, nos quais a **rota** até uma edge determina o estado ativo. Rastrear ingenuamente todo contexto de chamada também é perigoso: o mapa de coverage e a queue podem crescer demais. Por isso, pesquisas sobre fuzzing sensível a contexto recomendam refinar apenas contextos promissores, em vez de tratar todo o call graph como sensível a contexto.<sup>[[14]](#references)</sup>

Versões recentes do AFL++ oferecem **coverage de caminhos Ball-Larus por função**, além da edge coverage normal. Esse recurso atribui uma feature a cada caminho acíclico por uma função; as back-edges de loops são removidas, então esse feedback distingue combinações de branches, mas **não a quantidade de iterações do loop**. Comece com o nível relaxado `1` e depois aplique modos mais estritos apenas ao código suspeito do parser ou da máquina de estados, pois o número de caminhos pode crescer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para um helper chamado a partir de muitos locais relevantes para a segurança, o modo LTO pode combinar cada caminho da função com seu local de chamada imediato:<sup>[[13]](#references)</sup>

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

**Orientações para a campanha:** aplique feedback mais rico com cautela e monitore o custo de coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Execute em paralelo uma instância comum de edge coverage; o feedback mais rico só é útil se o custo adicional de queue/map não reduzir as execuções por segundo.
- Use `AFL_LLVM_ALLOWLIST` para restringir a instrumentação de paths/callers quando bibliotecas grandes com muitos templates ou código utilitário genérico dominarem o map.
- Funções com caminhos acíclicos excessivos podem ser ignoradas pelo AFL++; avisos durante a compilação indicam que o alvo precisa de allowlisting ou de um nível menos rigoroso.
- Caller + path coverage suporta apenas um nível de caller. Não combine com stacks de contexto mais profundos.
- Os IDs de path podem mudar entre versões principais do LLVM. Mantenha a toolchain fixa durante a campanha e não sincronize corpora baseados em PATH como se os IDs de suas features fossem estáveis entre builds.
- Esse feedback complementa o `CMPLOG`: o rastreamento de comparações resolve **qual valor passa por uma condição**, enquanto o feedback de path/caller preserva **qual rota e combinação de branches chegou até ela**.

## Fuzzing com estado: sequências são seeds

Para **protocolos**, **workflows autenticados** e **parsers de várias etapas**, a unidade interessante muitas vezes não é um blob isolado, mas uma **sequência de mensagens**. Concatenar toda a transcrição em um único arquivo e mutá-la às cegas costuma ser ineficiente, pois o fuzzer muta todas as etapas por igual, mesmo quando só a mensagem posterior alcança o estado vulnerável.<sup>[[4]](#references)</sup>

Uma abordagem mais eficaz é tratar a **própria sequência como seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos de objetos retornados) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha estáveis as **mensagens válidas do prefixo** e concentre as mutações na mensagem que **aciona a transição**.
- Armazene em cache os identificadores e valores gerados pelo servidor nas respostas anteriores quando a etapa seguinte depender deles.
- Prefira mutação/splicing por mensagem em vez de mutar toda a transcrição serializada como um blob opaco.
- Se o protocolo expuser códigos de resposta relevantes, use-os como um **oráculo de estado barato** para priorizar sequências que avancem mais.

É por isso que bugs autenticados, transições ocultas ou bugs de parser que ocorrem “somente após o handshake” muitas vezes passam despercebidos no fuzzing tradicional baseado em arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de driver com vários clientes

Uma alta edge coverage ainda pode deixar passar bugs no driver IPC, pois a coverage não descreve **propriedade de objetos, contagens de referências, mensagens pendentes, ordem de limpeza ou intercalações de threads**. A página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) aborda o modelo de objetos do driver; este exemplo se concentra no harness do fuzzer. Android Binder é um modelo útil: alcançar tanto os caminhos de alocação quanto os de liberação não basta se o fuzzer não conseguir fazer vários processos operarem sobre o mesmo objeto do kernel na ordem necessária.<sup>[[15]](#references)</sup>

#### Modele o protocolo, não buffers `ioctl` isolados

Represente um caso de teste como uma gramática ordenada de **identidade do cliente + operação + argumentos estruturados**. O fuzzer LKL do Binder usa protobuf e `libprotobuf-mutator`, com um cliente persistente de gerenciador de contexto e dois clientes comuns. Um harness semântico preserva então as relações que a mutação cega de bytes destruiria.<sup>[[15]](#references)</sup>

- Armazene em cache os valores retornados por operações anteriores. Por exemplo, `BC_FREE_BUFFER` precisa reutilizar um ponteiro de buffer de transação retornado por um `ioctl` anterior.
- Gere respostas padrão válidas para permitir que transações síncronas sejam concluídas e que operações posteriores continuem acessíveis.
- Rejeite transições impossíveis, como transações para o próprio cliente ou várias transações pendentes para o mesmo destino.
- Mantenha o estado singleton de inicialização fora da redefinição por entrada. Binder permite apenas um registro `BINDER_SET_CONTEXT_MGR` por inicialização; portanto, destruir e recriar esse cliente repetidamente invalidaria as entradas posteriores.

Um modelo útil para corridas de ciclo de vida é fazer um cliente transferir um objeto, iniciar a limpeza de uma thread ou processo e, simultaneamente, fazer o cliente receptor liberar o buffer da transação. No exemplo CVE-2020-0423, uma transferência de `BINDER_TYPE_WEAK_BINDER` seguida de `BINDER_THREAD_EXIT` em corrida com `BC_FREE_BUFFER` podia liberar um `binder_work` incorporado enquanto o caminho de limpeza da thread em encerramento ainda o utilizava.<sup>[[15]](#references)</sup>

#### Reintroduza intercalações controladas em um kernel no espaço do usuário

A [Linux Kernel Library (LKL)](https://github.com/lkl/linux) vincula o código real do kernel a um harness no espaço do usuário e expõe sua interface de chamadas de sistema por meio de `lkl_syscall`. Isso facilita coordenar estado protobuf, coverage e KASAN em um único processo. No entanto, normalmente o LKL executa uma chamada de sistema sem que outra thread do kernel a interrompa. Para campanhas de corrida, insira pontos `schedule()` ao redor de limites selecionados de lock/unlock e ciclo de vida; em seguida, deixe o harness escolher aleatoriamente o próximo cliente em cada yield. Mantenha esses pontos direcionados, pois cada um multiplica o espaço de busca de escalonamento. O escalonador aleatório descrito pelos pesquisadores **não** faz parte do fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compile e reproduza seeds de regressão serializadas

O harness upstream fixa uma versão compatível de `libprotobuf-mutator`, habilita a instrumentação de fuzzing do LKL e KASAN com `LKL_FUZZING=1`, e habilita `CONFIG_MMU` para Binder com `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Após conferir uma revisão deliberadamente vulnerável ou aplicar os patches de rollback documentados upstream, uma seed serializada pode reproduzir toda a transição de estado multi-client sem reconstruí-la em uma prova de conceito ad hoc em C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trate o use-after-free resultante do KASAN como confirmação de que o seed alcançou o caminho vulnerável de lifetime. Isso **não** demonstra as primitivas posteriores necessárias para execução de código no kernel ou escalonamento de privilégios.<sup>[[16]](#references)</sup>

## Truque de diversidade em uma única máquina (estilo Jackalope)

Uma forma prática de combinar **novidade generativa** com **reutilização de cobertura** é **reiniciar workers de curta duração** em um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos usando o corpus combinado, sincroniza novamente e então encerra. Isso produz **estruturas novas a cada geração**, ao mesmo tempo que aproveita a cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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

**Notas:**

- `-in empty` força um **corpus novo** em cada geração.
- `-server_update_interval T` aproxima uma **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo de fuzzing de gramática, a **sincronização inicial com o servidor é ignorada por padrão** (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do alvo**; geralmente funciona melhor alterá-lo depois que o worker encontra a maior parte da cobertura “fácil”.

## Fuzzing com snapshots para alvos difíceis de instrumentar

Quando o código que você quer testar só pode ser alcançado **após um custo elevado de preparação** (iniciar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é o **fuzzing com snapshots**: capturar o estado do processo ou da VM prontos, injetar cada caso de teste no caminho de entrada do alvo, executar até ocorrer um crash/timeout e restaurar o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **alvos apenas binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o alvo até que o estado de interesse esteja pronto.
2. Faça um snapshot de **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada mutada diretamente no buffer relevante do processo/guest.
4. Execute até ocorrer um crash/timeout/reset.
5. Restaure o snapshot; para alvos de VM, restaure apenas as **páginas sujas**, quando houver suporte, e repita.

Posicione o snapshot o mais próximo possível da primeira etapa custosa de análise/dispatch, por exemplo, após um `recv`/`read` ou no ponto de desserialização do pacote, e registre o buffer de entrada usado pelo alvo. Isso segue o princípio de posicionamento adaptativo: mover o snapshot para mais adiante no processamento da entrada, evitando repetir trabalho.<sup>[[11]](#references)</sup>

### Snapshots incrementais para estados de protocolo

Um snapshot fixo evita o custo de preparação, mas, por si só, não explora transições que exigem várias mensagens válidas. Um harness do LibAFL-Qemu pode monitorar gravações em um campo de estado do protocolo e salvar um novo snapshot quando o estado mudar. No [harness TCP do libslirp](https://github.com/quarkslab/slirp_snapshots_stateful), ele monitora `tcpcb.t_state`, calcula hashes do estado e dos flags de resposta para eliminar snapshots duplicados e armazena páginas sujas em relação a um snapshot pai. Antes de mutar a próxima mensagem estruturada, ele restaura o snapshot selecionado por meio da cadeia de snapshots pais. O testcase mantém um `SnapshotId` e os bytes de entrada gerados (`gen_bytes`); o gerenciador de snapshots acompanha a relação entre snapshots pais necessária para a reprodução.<sup>[[27]](#references)[[28]](#references)</sup>

O `SnapshotModule` em modo user-mode do LibAFL-Qemu salva mapeamentos e memória do alvo, mas não os registradores da CPU; preserve-os separadamente quando necessário. O gerenciador descrito oferece suporte a uma única árvore de snapshots raiz e não pode compartilhar IDs de snapshots entre workers. Seu modo multi-snapshot também não pode reutilizar diretamente o estado shadow do QASAN. Para triagem offline, reconstrua a cadeia de entrada em um processo instrumentado separado. Ao usar `AsanHostModule` e `DrCovModule`, `fuzzer.evaluate_input` executa os callbacks necessários de `pre_exec`/`post_exec`; apenas `qemu.run` não os executa.<sup>[[27]](#references)[[28]](#references)</sup>

### Detectar leituras além do limite lógico de um buffer circular

Uma leitura além da *quantidade de dados válidos* de um buffer pode permanecer dentro da alocação no host e escapar do ASAN comum. O [exemplo de dados urgentes do libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) também causa underflow em uma contagem de bytes sem sinal. Com o código-fonte disponível, a instrumentação para overflow de inteiros com sinal/sem sinal pode detectar esse efeito colateral; diferencie o wrap intencional do número de sequência TCP antes de suprimir relatórios. Um oracle proposto mais robusto consiste em envenenar a alocação circular personalizada, remover o envenenamento apenas dos intervalos válidos conforme o alocador interno avança e envenenar novamente os intervalos liberados. O LibAFL-Qemu oferece uma API de envenenamento do ASAN para alvos nos quais a instrumentação do código-fonte é impraticável.<sup>[[27]](#references)</sup>

## Exploração de condições de corrida no kernel Linux com MAccConc

O [MAccConc](https://github.com/googleprojectzero/MAccConc) transforma condições de corrida sensíveis ao timing no kernel Linux em sequências repetíveis de acessos à memória. Ele pode enumerar automaticamente execuções **A-B-A** de dois contextos ou permitir que um analista imponha restrições de ordem em uma interface de terminal/GUI. Trata-se de uma ferramenta experimental de pesquisa, não de um fuzzer de concorrência completo: atualmente, requer LLVM 23+ e o kernel modificado do projeto, as ferramentas de linha de comando oferecem suporte a duas threads de teste e a camada proposta de fuzzing em espaço de usuário ainda não foi implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Coletar pontos de comunicação entre contextos

Compile o kernel instrumentado com callbacks outline do KASAN e o suporte modificado de registro de memória do KCOV. O README do projeto também recomenda desativar a otimização de chamadas entre irmãos para manter as pilhas de chamadas utilizáveis.<sup>[[17]](#references)[[18]](#references)</sup>

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

O modo outline do KASAN (`asan-instrumentation-with-call-threshold=0`) converte os acessos instrumentados em chamadas auxiliares. Os patches do kernel MAccConc desativam `asan-opt-same-temp` para que acessos consecutivos não sejam mesclados; desative também a otimização `asan-opt-globals` quando for necessário detectar corridas em variáveis globais. O KCOV envia os registros resultantes ao espaço de usuário. Compare os acessos de diferentes contextos de execução e mantenha os pares cujos intervalos de bytes se sobrepõem e em que pelo menos um lado realiza uma escrita; trate `kfree()` como uma escrita para que transições de ciclo de vida também sejam candidatas.<sup>[[17]](#references)</sup>

Para trabalhos que escapam da tarefa que os iniciou, como processamento de pacotes ou callbacks de RCU, o subsistema precisa propagar um identificador de cobertura remota do KCOV. O KCOV remoto upstream é opt-in e não fica disponível automaticamente para trabalhos arbitrários em segundo plano; portanto, a falta dessa propagação pode tornar invisível uma interação real.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar o mesmo acesso dinâmico em cada execução

Não reproduza a execução usando um endereço concreto do heap, que pode mudar a cada alocação, nem apenas um endereço de instrução, que é ambíguo dentro de helpers como `memcpy()` e `spin_lock()`. O MAccConc usa um **rastreamento de pilha aumentado com contagens**: cada frame identifica uma função chamada e a contagem de invocações dentro da função chamadora, e o elemento final identifica a instrução de acesso à memória. Os registros de entrada/saída de função do SanitizerCoverage permitem que o espaço de usuário reconstrua esse identificador dinâmico, que permanece estável mesmo quando os endereços mudam ou há ruído de fluxo de controle não relacionado.<sup>[[17]](#references)</sup>

### Converter pares candidatos em escalonamentos forçados

O ioctl `KCOV_SET_DI` dos patches associa um identificador de acesso aumentado com contagens a uma ação de flag compartilhada.<sup>[[17]](#references)</sup>

| Ação | Semântica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Define a flag *N* imediatamente antes do acesso selecionado. |
| `DI_STACK_WAIT` | Antes do acesso selecionado, aguarda em loop até que a flag *N* seja definida ou o limite configurado expire. |
| `DI_STACK_WAKE_POST` | Define a flag *N* imediatamente depois do acesso selecionado. |

Para uma restrição parcial **A acontece antes de B**, associe `DI_STACK_WAKE_POST` a A e `DI_STACK_WAIT` a B usando a mesma flag. Para um escalonamento de dois contextos totalmente especificado, inicie B bloqueado; em seguida, faça A acordar B e aguardar no primeiro ponto de transferência. B realiza a operação inversa na transferência seguinte. Isso funciona como uma troca determinística de contexto e é o que o explorador automático A-B-A usa.<sup>[[17]](#references)</sup>

Uma campanha mínima consiste em compilar o caso de teste com quatro hooks (`test_setup`, duas funções de thread e `test_end`) como uma biblioteca compartilhada, coletar um rastreamento sem restrições e, então, enumerar candidatos A-B-A ou adicionar restrições manuais em torno de acessos suspeitos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprete os timeouts separadamente dos reordenamentos bem-sucedidos: a ordem solicitada pode ser impossível porque um lock ou uma dependência de inicialização/publicação impede que o segundo contexto alcance o ponto de injeção. Tenha em mente também os pontos cegos do KASAN: acessos diretos à stack geralmente não são instrumentados, a menos que possam sair dos limites; variáveis globais são omitidas com a otimização padrão; e os compiladores atuais não conseguem emitir hooks de ASAN e TSAN simultaneamente. Por fim, o protótipo perde seu buffer do KCOV quando uma guest entra em panic; portanto, mantenha um console/oráculo de crash independente.<sup>[[17]](#references)</sup>

Para fuzzing guiado por concorrência no futuro, registre resumos de acessos à memória por entrada ou por syscall, forme pares de operações que criariam pontos de comunicação entre contextos e, então, explore apenas essas combinações. Snapshots de VM estabilizam o estado global e os endereços; sem snapshots, metadados de sites de alocação podem abstrair objetos entre execuções. Esta é uma extensão proposta, não um recurso das ferramentas userspace atuais do MAccConc.<sup>[[17]](#references)</sup>

## Introspecção do Harness: Encontre Fuzzers Superficiais Mais Cedo

Quando uma campanha estagna, o problema geralmente não está no mutator, mas no **harness**. Use a **introspecção de alcançabilidade/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do seu alvo de fuzzing, mas raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um de três problemas.<sup>[[12]](#references)</sup>

- O harness entra no alvo tarde ou cedo demais.
- O corpus de seeds não contém toda uma família de recursos.
- O alvo realmente precisa de um **segundo harness**, em vez de um único harness enorme que “faz tudo”.

Se você usa fluxos de trabalho no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a alcançabilidade estática com a cobertura em tempo de execução e gerar relatórios a partir de uma execução temporizada ou de um corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Use o relatório para decidir se deve adicionar um novo harness para um caminho do parser ainda não testado, ampliar o corpus para um recurso específico ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de alvos de fuzzing orientada primeiro por grafo e triagem de mutações

Se você já tem **achados de análise estática**, **sobreviventes de mutation testing** e **relatórios de cobertura**, não os analise como listas independentes. Primeiro, construa um **grafo de chamadas**, anote os nós com **complexidade ciclomática**, **alcançabilidade a partir de pontos de entrada/dados não confiáveis** e quaisquer achados externos, depois faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade são alcançáveis a partir de entradas não confiáveis?
- Quais sobreviventes de mutação estão em caminhos dos parsers/handlers até código crítico para a segurança?
- Quais funções são pontos de estrangulamento arquiteturais com **raio de impacto** excepcionalmente grande?

Isso geralmente revela alvos de fuzzing melhores do que apenas escolher os de "menor cobertura". Um parser/decoder com **alta complexidade** e **alcançabilidade externa** confirmada é um candidato mais forte para um harness do que um helper interno isolado com cobertura baixa, mas sem um caminho controlado pelo atacante.

### Fluxo de trabalho prático de triagem

1. Construa um **grafo de código** a partir da base de código e extraia métricas de complexidade/ramificações por função.
2. Enumere os **pontos de entrada** que aceitam dados controlados pelo atacante: handlers de requisição, decoders, importers, parsers de protocolo, leitores de CLI/arquivos.
3. Execute consultas de caminho desses pontos de entrada até as funções candidatas para separar a superfície de ataque alcançável do código morto ou acessível apenas internamente.
4. Priorize os nós que combinam:
   - alta **complexidade ciclomática**
   - **alcançabilidade a partir de entradas não confiáveis** confirmada
   - alto **raio de impacto** ou muitos dependentes posteriores
   - evidências corroborantes, como achados **SARIF**, notas de auditoria ou sobreviventes de mutação
5. Escreva primeiro harnesses focados para os nós com melhor pontuação, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/mensagens.

### Sobreviventes de mutação: equivalentes vs. acionáveis

O mutation testing costuma produzir uma lista ruidosa de sobreviventes. Antes de tratar cada sobrevivente como uma falha de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um ponto de entrada controlado pelo atacante?
- Todos os caminhos de chamada são restringidos por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica apenas de formatação ou em um caminho de alta relevância para aritmética/parsing?

Sobreviventes que permanecem inalcançáveis ou estruturalmente restringidos costumam ser **mutantes equivalentes**. Sobreviventes que continuam **alcançáveis** e afetam **condições de limite**, **caminhos de overflow/carry** ou **aritmética/parsing críticos para a segurança** devem ser promovidos a:

- novos harnesses de fuzzing
- testes diretos de propriedades/invariantes
- vetores direcionados para casos-limite

### Correlacione achados externos ao grafo

Se o pipeline de SAST exportar **SARIF**, projete os achados nos nós do grafo usando **arquivo + intervalo de linhas** e use o grafo para ampliar a avaliação do impacto.<sup>[[6]](#references)</sup>

- calcule o **raio de impacto** da função sinalizada
- verifique se o achado está em algum caminho a partir de um ponto de entrada
- agrupe achados próximos que convergem para o mesmo ponto de estrangulamento

Isso é útil ao decidir se vale a pena dedicar tempo de fuzzing a uma função específica: um nó **alcançável**, **complexo** e que já tenha **achados de SAST** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho acessível pelo atacante.

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

## Fuzzing diferencial de codificações de chaves criptográficas

Comece com chaves serializadas válidas ou vetores de teste padrão. Mute campos codificados sem comprometer o comprimento e a estrutura necessários para alcançar os caminhos de importação e operação e, em seguida, envie os mesmos bytes a implementações independentes. Compare a aceitação e os erros. Assinaturas e textos cifrados aleatorizados precisam de oráculos de correção, não de comparação byte a byte: verifique as assinaturas ou compare os segredos compartilhados em uma operação de encapsulamento/descapsulamento. Os vetores de teste estabelecem a conformidade para casos conhecidos; a mutação diferencial investiga codificações malformadas além desses casos.<sup>[[23]](#references)[[26]](#references)</sup>

Para estes formatos de chave, use oráculos específicos para cada formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Chaves de assinatura expandidas ML-DSA:** altere coeficientes empacotados de `s1` ou `s2` para valores fora de `[-η, η]`, mantendo a chave analisável. Verifique se a importação ou a assinatura rejeita a chave e se alguma assinatura resultante é validada. Diferenças de aceitação, por si só, não violam os padrões, pois o FIPS 204 não exige verificações adicionais de chaves privadas. Consulte o [mecanismo de vazamento condicional](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pares de chaves ML-KEM:** diferencie as verificações obrigatórias da chave de encapsulamento e da entrada de descapsulamento da verificação opcional de consistência do par (PCT) na importação do par. Faça o encapsulamento com a chave pública, o descapsulamento com a chave privada e compare os segredos compartilhados; uma incompatibilidade pode interromper a comunicação criptografada mesmo quando as chaves passam nas verificações de entrada individuais. Verifique se a API valida as entradas durante a operação ou por meio de uma chamada separada; libcrux disponibiliza `validate_public_key(pk)` e `validate_private_key(sk, ct)`, que não substituem uma PCT.
- **Chaves brutas XMSS/XMSSMT:** teste operações de serialização e desserialização de chaves de **assinatura e verificação** entre conjuntos de parâmetros, não apenas operações com chaves em memória. XMSS e XMSSMT têm namespaces OID distintos de quatro bytes; portanto, um analisador que tenta XMSS primeiro pode classificar incorretamente uma chave XMSSMT com OID coincidente e rejeitar a importação. O analisador RustCrypto reportado ilustra uma falha de interoperabilidade/disponibilidade, não uma falsificação de assinatura.

## Fuzzing em Go com gosentry: mecanismo mais robusto, entradas tipadas e verificações diferenciais

Se um alvo em Go já tiver um harness nativo `testing.F`, uma forma prática de aprimorá-lo é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), uma toolchain de Go derivada que mantém `go test -fuzz`, mas substitui o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Isso é útil quando o fuzzer nativo do Go fica preso em **comparações difíceis**, **entradas tipadas** ou **formatos com muitos parsers**. A metodologia continua a mesma:

- Continue usando `f.Add(...)` para seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com agendamento/mutação do LibAFL e melhores detectores auxiliares.

### Transforme falhas silenciosas em achados de fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos muitas vezes **não** causam crash por padrão. Com o gosentry, você pode transformar várias classes de estados “ruins, mas silenciosos” em achados.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram a mensagem e continuam).
- `--catch-races=true` para executar novamente as novas entradas descobertas na fila com o detector de race do Go.
- `--catch-leaks=true` para executar novamente as novas entradas na fila com o `goleak` e parar ao detectar vazamentos de goroutines.
- O tratamento de travamentos do LibAFL para manter **loops infinitos / entradas muito lentas** como achados de fuzzing, em vez de deixá-los desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos cujo impacto na segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **travamento que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing com reconhecimento de structs para APIs Go tipadas

O fuzzing nativo do Go espera principalmente escalares como `[]byte`, `string` e números. Se o código sob teste consome objetos tipados, o gosentry pode fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, ponteiros), enquanto ainda muta os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Use isso ao criar um formato de transmissão falso apenas para fuzzing, pois isso ocultaria bugs de lógica por trás de código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolos

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **fuzzing gramatical Nautilus** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre a metodologia:

- Use o modo gramatical quando mutações em nível de byte falham principalmente nas verificações sintáticas iniciais.
- Mantenha a gramática focada no **subconjunto da linguagem/protocolo relevante para a segurança**, em vez de modelar a especificação completa.
- Use valores-limite grandes em terminais/não terminais para testar os limites de inteiros, comprimentos e máquinas de estados.
- O modo gramatical mantém as entradas válidas segundo a gramática, mas o alvo ainda recebe **bytes/strings**, então a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Fuzzing diferencial: compare implementações, não apenas falhas

Um padrão eficaz para ecossistemas Go é o **fuzzing diferencial baseado em gramática**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou mecanismos de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>

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

Trate o seguinte como achados:

- uma implementação entra em panic enquanto a outra rejeita a entrada corretamente
- divergências entre entradas aceitas e rejeitadas
- árvores de análise ou objetos decodificados diferentes
- divergências nas transições de estado, nonces, saldos ou raízes de estado

Esta é uma forma prática de encontrar **divergências de consenso**, **ambiguidades de parser** e **desvios entre especificação e implementação** que o fuzzing focado apenas em crashes costuma não detectar.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilize o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da fila salvo para gerar um relatório de cobertura do Go, sem precisar exportar um corpus separado manualmente.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Execute o comando no **mesmo pacote** e com o mesmo alvo `-fuzz` para que o gosentry resolva o estado de campanha em cache correto.

## References

- [1] [Fuzzing gramatical mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Faltava metade do toolkit ao fuzzing do Go. Fizemos um fork da toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede stateful usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: rumo ao fuzzing do kernel Linux sem descrições de chamadas de sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptáveis e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentação LLVM do AFL++: cobertura de caminhos e chamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing preditivo sensível ao contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de segurança ofensiva do Android - Fuzzing do Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer do Binder do LKL Android - documentação de compilação e seeds de regressão](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: explorando condições de corrida no kernel Linux com intercalações controladas de acessos à memória](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaxe de nomes de arquivo estendidos do CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Comunicado da Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing da sintaxe de nomes de arquivo estendidos do CFITSIO: 16 vulnerabilidades de segurança de memória e triagem assistida pelo Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing diferencial para criptografia](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: padrão de mecanismo de encapsulamento de chaves baseado em reticulados modulares](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug de parsing de OID do XMSSMT - issue #1442 do RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Estado das implementações de criptografia pós-quântica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Usando snapshots para chegar ao CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [slirp_snapshots_stateful da Quarkslab](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzers vs. IA: comparação entre Fuzzilli e BigSleep em engines JavaScript](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
