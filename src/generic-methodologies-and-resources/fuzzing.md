# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Cobertura vs. Semântica

No **mutational grammar fuzzing**, as entradas são mutadas sem deixar de ser **válidas segundo a gramática**. No modo guiado por cobertura, apenas amostras que acionam **nova cobertura** são salvas como seeds do corpus. Para **alvos de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de fluxo de dados**, nas quais a saída de uma construção se torna a entrada de outra.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o fluxo de dados encadeado**; assim, a amostra “mais próxima do bug” é descartada porque não adiciona cobertura. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna cara, e o feedback de cobertura não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **combinar fases mutacionais e generativas** ou favorecer padrões de **encadeamento de funções** (não apenas cobertura).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por cobertura é **gulosa**: uma amostra que gera nova cobertura é salva imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas**, com pouca diversidade estrutural. A minimização agressiva pode remover contexto útil; por isso, um compromisso prático é a **minimização ciente da gramática**, que **para ao atingir um limite mínimo de tokens** (reduzindo o ruído e mantendo estrutura ao redor suficiente para facilitar mutações).<sup>[[1]](#references)</sup>

Uma regra prática para corpora de mutational fuzzing é: **prefira um conjunto pequeno de seeds estruturalmente diferentes que maximize a cobertura** a um grande amontoado de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do alvo).
- Refine-as com **minimização de corpus baseada em cobertura**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos relevantes, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após grandes mudanças no harness ou na instrumentação, pois o corpus “ideal” muda quando a alcançabilidade muda.

## Mutação Ciente de Comparações para Valores Mágicos

Um motivo comum para os fuzzers estagnarem não é a sintaxe, mas as **comparações rígidas**: bytes mágicos, verificações de comprimento, strings de enum, checksums ou valores de despacho do parser protegidos por `memcmp`, tabelas de switch ou comparações em cascata. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses alvos, use **rastreamento de comparações** (por exemplo, workflows no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer observe os operandos de comparações malsucedidas e direcione as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>

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

- Isso é especialmente útil quando o alvo protege a lógica mais profunda com **assinaturas de arquivo**, **verbos de protocolo**, **tags de tipo** ou **bits de recursos dependentes da versão**.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de depuração. Um dicionário pequeno com tokens de gramática, nomes de blocos, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo realizar muitas verificações sequenciais, resolva primeiro as comparações “mágicas” iniciais e depois minimize novamente o corpus resultante, para que as etapas seguintes comecem com prefixos já válidos.

## Fuzzing de APIs de arquivos que ocultam uma linguagem de nomes de arquivo

Um parâmetro chamado `filename`, `path` ou `URL` pode ser um ponto de entrada de um interpretador, e não uma busca literal por arquivo. Por exemplo, o Extended Filename Syntax (EFS) do CFITSIO avalia seletores entre colchetes, expressões de linha/pixel, colunas calculadas, histogramas e transformações antes de retornar o objeto aberto; algumas formas também criam cópias temporárias. Ao mapear a superfície de ataque, classifique cada API de abertura/importação como **caminho literal** ou **caminho interpretado** e, em seguida, faça fuzzing do ponto de entrada de produção que as aplicações realmente chamam.<sup>[[20]](#references)[[22]](#references)</sup>

Para ver as primitivas resultantes de SSRF, cópia de arquivos e manipuladores de protocolo — e APIs de caminho literal mais seguras — consulte [Mini-linguagens de nomes de arquivo como primitivas de SSRF/arquivo](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantenha o objeto de apoio separado do programa sob fuzzing

Quando a gramática fica em um sufixo do nome do arquivo, modificar apenas os bytes do arquivo referenciado não alcança o parser. Em vez disso, um pequeno harness pode ler um caso de teste como string e passá-lo à API de abertura interpretada; a campanha do CFITSIO alcançou a maioria dos parsers e avaliadores de EFS chamando `fits_open_file()` em modo somente leitura. Mantenha arquivos de apoio válidos disponíveis separadamente para que as mutações possam se concentrar na linguagem de seletores/expressões, sem corromper continuamente o caminho base.<sup>[[22]](#references)</sup>

Use seeds que alcancem cada um uma família gramatical diferente e, em seguida, crie um dicionário compacto com base tanto na especificação quanto no código-fonte do lexer/parser. Se a cobertura estagnar enquanto as entradas falham repetidamente no mesmo caminho de erro de sintaxe, preserve os prefixos válidos e adicione delimitadores, operadores, palavras-chave, nomes de funções e nomes de campos representativos, em vez de apenas aumentar o tempo de mutação aleatória.<sup>[[22]](#references)</sup>

Execute o harness com o dicionário gramatical, por exemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Conter efeitos colaterais do harness "read-only"

Uma flag de biblioteca read-only não garante um testcase sem efeitos colaterais: a linguagem de nomes de arquivo pode reescrever a entrada, criar arquivos de saída ou materializar objetos temporários. A campanha com CFITSIO inicialmente destruiu arquivos seed e deixou arquivos inesperados pelo sistema de arquivos, então foi necessário implementar limpeza e isolamento.<sup>[[22]](#references)</sup>

- Dê a cada worker um diretório de trabalho descartável e um diretório temporário privado.
- Exponha cópias dos arquivos de suporte canônicos; nunca permita que o alvo altere a única cópia do corpus.
- Desative o acesso à rede, a menos que os backends remotos sejam o alvo pretendido, e restrinja os caminhos graváveis com um container, um namespace de montagem ou um sandbox equivalente.
- Redefina o diretório após cada execução ou lote de workers e trate alterações inesperadas no sistema de arquivos como descobertas adicionais.

### Ciclo de crash para patch e fuzzing

Agrupe os crashes antes de corrigi-los, para que milhares de artefatos não se transformem em milhares de tarefas de patch. Na avaliação do CFITSIO, o AFLTriage reduziu o conjunto inicial de crashes a algumas causas raiz; o advisory resultante mostra falhas distintas, incluindo verificações incorretas do tamanho do destino, ponteiros obsoletos após `realloc()`, falhas aritméticas e caminhos inseguros de limpeza do parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimize uma entrada representativa de cada grupo e reproduza-a com AddressSanitizer.
2. Registre o acesso exato que falhou, a localização no código-fonte, o histórico de alocações/liberações e o estado do parser que tornou falsa a invariante.
3. Aplique um patch candidato de escopo restrito e recompile com a mesma instrumentação de cobertura e sanitizador.
4. Reproduza o caso original **e todas as entradas do grupo**; habilite também a detecção de leaks, pois uma correção de segurança de memória pode quebrar o gerenciamento de propriedade em um caminho de erro.
5. Execute testes funcionais com arquivos reais e, em seguida, retome a partir da queue acumulada (ou reimporte essa queue se o mecanismo exigir um diretório de saída novo após a alteração do binário).
6. Repita: remover o primeiro crash superficial geralmente permite que as seeds existentes avancem para um estado mais profundo do parser.

Um LLM pode acelerar a etapa 2 e elaborar um rascunho para a etapa 3 quando recebe a entrada que causou o crash, o relatório do sanitizador, o harness e o código-fonte relevante, mas seu patch continua sendo não confiável. A reprodução com o sanitizador e os critérios de regressão — não a explicação do modelo — determinam se a correção é aceita.<sup>[[22]](#references)</sup>

## Feedback mais rico quando a cobertura de arestas reduz caminhos distintos a um só

A cobertura normal de arestas não consegue distinguir duas execuções que percorrem o mesmo helper por meio de chamadores diferentes ou que seguem combinações de branches diferentes dentro de uma função. Isso importa em decodificadores compartilhados, despachantes de protocolo e helpers de interpretador, nos quais a **rota** até uma aresta determina o estado ativo. Rastrear ingenuamente todo contexto de chamada também é perigoso: o mapa de cobertura e a queue podem crescer sem controle. Por isso, a pesquisa sobre fuzzing sensível ao contexto recomenda refinar apenas os contextos promissores, em vez de tratar todo o grafo de chamadas como sensível ao contexto.<sup>[[14]](#references)</sup>

Versões recentes do AFL++ oferecem **cobertura de caminhos por função Ball-Larus**, além da cobertura normal de arestas. Ela atribui um recurso a cada caminho acíclico por uma função; as arestas de retorno de loop são removidas, então esse feedback distingue combinações de branches, mas **não a quantidade de iterações do loop**. Comece com o nível relaxado `1` e, depois, aplique modos mais restritos apenas a trechos suspeitos do parser ou da máquina de estados, pois o número de caminhos pode crescer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para uma função auxiliar chamada em muitos pontos sensíveis à segurança, o modo LTO pode combinar cada caminho de função com seu ponto de chamada imediato:<sup>[[13]](#references)</sup>

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

**Orientações para a campanha:** aplique feedback mais rico com cautela e monitore o custo em coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Execute em paralelo uma instância comum de edge-coverage; o feedback mais rico só é útil se o custo extra de queue/map não reduzir as execuções por segundo.
- Use `AFL_LLVM_ALLOWLIST` para restringir a instrumentação de path/caller quando bibliotecas grandes, cheias de templates, ou código utilitário genérico dominarem o map.
- Funções com caminhos acíclicos excessivos podem ser ignoradas pelo AFL++; avisos durante a compilação são um indício de que o alvo precisa de allowlisting ou de um nível menos rigoroso.
- Caller + path coverage oferece suporte a apenas um nível de caller. Não combine isso com stacks de contexto mais profundos.
- Os IDs de path podem mudar entre versões principais do LLVM. Mantenha a toolchain fixa durante uma campanha e não sincronize corpora baseados em PATH como se seus feature IDs fossem estáveis entre builds.
- Esse feedback complementa o `CMPLOG`: o tracing de comparações resolve **qual valor passa por uma guard**, enquanto o feedback de path/caller preserva **qual rota e combinação de branches chegaram até ela**.

## Fuzzing com estado: sequências são seeds

Para **protocolos**, **workflows autenticados** e **parsers em várias etapas**, a unidade interessante geralmente não é um único blob, mas uma **sequência de mensagens**. Concatenar toda a transcrição em um arquivo e mutá-la às cegas costuma ser ineficiente, porque o fuzzer muta cada etapa igualmente, mesmo quando só a mensagem posterior alcança o estado vulnerável.<sup>[[4]](#references)</sup>

Um padrão mais eficaz é tratar a **própria sequência como seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos de objetos retornados) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha **mensagens válidas de prefixo** estáveis e concentre as mutações na mensagem que **impulsiona a transição**.
- Armazene em cache identificadores e valores gerados pelo servidor nas respostas anteriores quando a próxima etapa depender deles.
- Prefira mutação/splicing por mensagem a mutar toda a transcrição serializada como um blob opaco.
- Se o protocolo expuser códigos de resposta relevantes, use-os como um **oráculo de estado barato** para priorizar sequências que avancem mais.

É pela mesma razão que bugs autenticados, transições ocultas ou bugs de parser que ocorrem “somente após o handshake” muitas vezes passam despercebidos no fuzzing convencional no estilo de arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de driver com vários clientes

Uma alta cobertura de edges ainda pode deixar passar bugs no driver IPC, porque a cobertura não descreve **propriedade de objetos, contagens de referências, mensagens pendentes, ordem de limpeza ou intercalações entre threads**. A página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) aborda o modelo de objetos do driver; este exemplo se concentra no harness do fuzzer. Android Binder é um modelo útil: alcançar os caminhos de alocação e liberação não basta se o fuzzer não conseguir fazer vários processos operarem sobre o mesmo objeto do kernel na ordem necessária.<sup>[[15]](#references)</sup>

#### Modele o protocolo, não buffers `ioctl` isolados

Represente um caso de teste como uma gramática ordenada de **identidade do cliente + operação + argumentos estruturados**. O fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, com um cliente gerenciador de contexto persistente e dois clientes comuns. Um harness semântico preserva então as relações que a mutação cega de bytes destruiria.<sup>[[15]](#references)</sup>

- Armazene em cache os valores retornados por operações anteriores. Por exemplo, `BC_FREE_BUFFER` precisa reutilizar um ponteiro para buffer de transação retornado por um `ioctl` anterior.
- Gere respostas padrão válidas para que transações síncronas possam terminar e operações posteriores continuem alcançáveis.
- Rejeite transições impossíveis, como transações para si mesmo ou várias transações pendentes para o mesmo destino.
- Mantenha o estado de inicialização singleton fora do reset por entrada. Binder permite apenas um registro `BINDER_SET_CONTEXT_MGR` por boot; portanto, destruir e recriar repetidamente esse cliente invalidaria as entradas posteriores.

Um modelo útil para uma condição de corrida de ciclo de vida é fazer um cliente transferir um objeto, iniciar a limpeza de uma thread ou processo e, ao mesmo tempo, fazer o cliente receptor liberar o buffer da transação. No exemplo CVE-2020-0423, uma transferência `BINDER_TYPE_WEAK_BINDER` seguida de `BINDER_THREAD_EXIT` em disputa com `BC_FREE_BUFFER` podia liberar um `binder_work` embutido enquanto o caminho de limpeza da thread que estava saindo ainda o utilizava.<sup>[[15]](#references)</sup>

#### Reintroduza intercalações controladas em um kernel userspace

A [Linux Kernel Library (LKL)](https://github.com/lkl/linux) vincula o código real do kernel a um harness userspace e expõe sua interface de syscall por meio de `lkl_syscall`. Isso facilita coordenar o estado do protobuf, a cobertura e o KASAN em um único processo. No entanto, normalmente o LKL executa uma syscall sem que outra thread do kernel a interrompa. Para campanhas de race, insira pontos `schedule()` em torno de limites selecionados de lock/unlock e ciclo de vida; em seguida, deixe o harness escolher aleatoriamente o próximo cliente em cada yield. Mantenha esses pontos direcionados, pois cada um deles multiplica o espaço de busca do escalonamento. O escalonador aleatório descrito pelos pesquisadores **não** faz parte do fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compile e reproduza seeds de regressão serializadas

O harness upstream fixa uma versão compatível de `libprotobuf-mutator`, ativa a instrumentação de fuzzing do LKL e o KASAN com `LKL_FUZZING=1`, e ativa `CONFIG_MMU` para Binder com `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Depois de conferir uma revisão deliberadamente vulnerável ou aplicar os patches de rollback documentados upstream, uma semente serializada pode reproduzir toda a transição de estado multi-cliente sem reconstruí-la em uma prova de conceito C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trate o use-after-free do KASAN resultante como confirmação de que a seed alcançou o caminho vulnerável de ciclo de vida. Isso **não** demonstra as primitivas posteriores necessárias para executar código no kernel ou escalar privilégios.<sup>[[16]](#references)</sup>

## Truque de Diversidade em uma Única Máquina (Estilo Jackalope)

Uma maneira prática de combinar **novidade generativa** com **reutilização de cobertura** é **reiniciar workers de curta duração** contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos com o corpus combinado, sincroniza novamente e então encerra. Isso gera **estruturas novas a cada geração**, enquanto ainda aproveita a cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` força um **corpus novo** em cada geração.
- `-server_update_interval T` aproxima uma **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo de grammar fuzzing, a **sincronização inicial com o servidor é ignorada por padrão** (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do target**; em geral, funciona melhor mudar depois que o worker encontrar a maior parte da cobertura “fácil”.

## Snapshot Fuzzing Para Targets Difíceis de Preparar

Quando o código que você quer testar só fica acessível **após um grande custo de preparação** (iniciar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é **snapshot fuzzing**: capturar o estado pronto do processo ou da VM, injetar cada caso de teste no caminho de entrada do target, executar até ocorrer um crash/timeout e restaurar o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **targets somente binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o target até que o estado interessante esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, grave a entrada mutada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer um crash/timeout/reset.
5. Restaure o snapshot; para targets de VM, restaure apenas as **páginas sujas** quando houver suporte e, em seguida, repita.

Coloque o snapshot o mais próximo possível da primeira etapa custosa de análise/dispatch, por exemplo, após um `recv`/`read` ou um ponto de desserialização de pacotes, e registre o buffer de entrada usado pelo target. Isso segue o princípio de posicionamento adaptativo: mover o snapshot para mais adiante no processamento da entrada para evitar repetir trabalho.<sup>[[11]](#references)</sup>

## Exploração de Race Conditions no Kernel Linux Com MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforma race conditions sensíveis ao timing no kernel Linux em sequências repetíveis de acessos à memória. Ele pode enumerar automaticamente execuções **A-B-A** em dois contextos ou permitir que um analista imponha restrições de ordem por meio de uma interface de terminal/GUI. Trata-se de uma ferramenta experimental de pesquisa, não de um fuzzer de concorrência completo: atualmente, requer LLVM 23+ e o kernel corrigido do projeto; as ferramentas de linha de comando oferecem suporte a duas threads de teste; e a camada proposta de fuzzing em userspace ainda não foi implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Coletar pontos de comunicação entre contextos

Compile o kernel instrumentado com callbacks outline do KASAN e o suporte corrigido do KCOV para registro de memória. O README do projeto também recomenda desativar a otimização de chamadas entre irmãos para que as pilhas de chamadas continuem utilizáveis.<sup>[[17]](#references)[[18]](#references)</sup>

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

O modo outline do KASAN (`asan-instrumentation-with-call-threshold=0`) converte acessos instrumentados em chamadas auxiliares. Os patches do kernel MAccConc desativam `asan-opt-same-temp` para que acessos consecutivos não sejam mesclados; desative também a otimização `asan-opt-globals` quando for necessário detectar corridas em variáveis globais. O KCOV transporta os registros resultantes para o userspace. Compare acessos de diferentes contextos de execução e retenha os pares cujos intervalos de bytes se sobrepõem e em que pelo menos um lado realiza uma escrita; modele `kfree()` como uma escrita para que transições de ciclo de vida também sejam consideradas candidatas.<sup>[[17]](#references)</sup>

Para trabalhos que escapam da task que os iniciou, como processamento de pacotes ou callbacks de RCU, o subsistema precisa propagar um handle de cobertura remota do KCOV. O KCOV remoto upstream é opcional e não fica disponível automaticamente para trabalhos arbitrários em segundo plano, portanto, a falta de propagação pode tornar uma interação real invisível.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar o mesmo acesso dinâmico em cada execução

Não repita a execução usando um endereço concreto do heap, que pode mudar após cada alocação, nem apenas usando um endereço de instrução, que é ambíguo em helpers como `memcpy()` e `spin_lock()`. O MAccConc usa um **stack trace aumentado com contagens**: cada frame identifica um callee e a contagem de invocações dentro do caller, e o elemento final identifica a instrução de acesso à memória. Os registros de entrada/saída de funções do SanitizerCoverage permitem que o userspace reconstrua esse identificador dinâmico, que permanece estável apesar de mudanças de endereço e de ruídos de fluxo de controle não relacionados.<sup>[[17]](#references)</sup>

### Converter pares candidatos em escalonamentos forçados

O ioctl `KCOV_SET_DI` com patches associa um identificador de acesso aumentado com contagens a uma ação de flag compartilhada.<sup>[[17]](#references)</sup>

| Ação | Semântica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Define a flag *N* imediatamente antes do acesso selecionado. |
| `DI_STACK_WAIT` | Antes do acesso selecionado, aguarda em loop até que a flag *N* seja definida ou o limite configurado expire. |
| `DI_STACK_WAKE_POST` | Define a flag *N* imediatamente após o acesso selecionado. |

Para uma restrição parcial **A acontece antes de B**, associe `DI_STACK_WAKE_POST` a A e `DI_STACK_WAIT` a B usando a mesma flag. Para um escalonamento totalmente especificado entre dois contextos, inicie B bloqueado; em seguida, faça A desbloquear B e aguardar no primeiro ponto de transferência. B executa a operação inversa no próximo ponto de transferência. Isso funciona como uma troca determinística de contexto e é o que o explorador automático A-B-A usa.<sup>[[17]](#references)</sup>

Uma campanha mínima consiste em compilar o caso de teste com quatro hooks (`test_setup`, duas funções de thread e `test_end`) como uma biblioteca compartilhada, coletar um trace sem restrições e, em seguida, enumerar candidatos A-B-A ou adicionar restrições manuais em torno de acessos suspeitos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprete os timeouts separadamente das reordenações bem-sucedidas: a ordem solicitada pode ser impossível porque um lock ou uma dependência de inicialização/publicação impede que o segundo contexto alcance seu ponto de injeção. Além disso, lembre-se dos pontos cegos do KASAN: acessos diretos à stack geralmente não são instrumentados, a menos que possam ultrapassar os limites, variáveis globais são omitidas com a otimização padrão, e os compiladores atuais não conseguem emitir hooks de ASAN e TSAN simultaneamente. Por fim, o protótipo perde seu buffer do KCOV quando uma VM guest entra em panic; por isso, mantenha um console/oráculo de crash independente.<sup>[[17]](#references)</sup>

Para fuzzing guiado por concorrência no futuro, registre resumos de acessos à memória por entrada ou chamada de sistema, combine operações que formariam pontos de comunicação entre contextos e, em seguida, explore apenas essas combinações. Snapshots de VM estabilizam o estado global e os endereços; sem snapshots, metadados do ponto de alocação podem abstrair objetos entre execuções. Esta é uma extensão proposta, não um recurso das ferramentas userspace atuais do MAccConc.<sup>[[17]](#references)</sup>

## Introspecção do Harness: Identifique Fuzzers Superficiais Cedo

Quando uma campanha fica estagnada, muitas vezes o problema não está no mutator, mas no **harness**. Use a **introspecção de alcançabilidade/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do alvo de fuzzing, mas raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um destes três problemas.<sup>[[12]](#references)</sup>

- O harness entra no alvo tarde ou cedo demais.
- O seed corpus não contém uma família inteira de recursos.
- O alvo realmente precisa de um **segundo harness**, em vez de um único harness exageradamente grande que “faz tudo”.

Se você usa fluxos de trabalho no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a alcançabilidade estática com a cobertura em tempo de execução e gerar relatórios a partir de uma execução com duração definida ou de um corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser ainda não testado, expandir o corpus para um recurso específico ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de Alvos de Fuzzing com Base no Grafo e Triagem de Mutações

Se você já tem **resultados de análise estática**, **sobreviventes de mutation testing** e **relatórios de cobertura**, não os faça triagem como listas independentes. Primeiro, construa um **grafo de chamadas**, anote os nós com **complexidade ciclomática**, **alcance a partir de pontos de entrada/dados não confiáveis** e quaisquer resultados externos, depois faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade são alcançáveis a partir de dados não confiáveis?
- Quais sobreviventes de mutação estão em caminhos dos parsers/handlers até código crítico para a segurança?
- Quais funções são gargalos arquiteturais com um **blast radius** excepcionalmente grande?

Isso geralmente revela alvos de fuzzing melhores do que considerar apenas a “menor cobertura”. Um parser/decoder com **alta complexidade** e **alcance externo** confirmado é um candidato a harness mais forte do que um helper interno isolado com pouca cobertura, mas sem um caminho controlado por um atacante.

### Fluxo de trabalho prático de triagem

1. Construa um **grafo de código** a partir da base de código e extraia métricas de complexidade/ramificações por função.
2. Enumere os **pontos de entrada** que aceitam dados controlados por um atacante: handlers de requisição, decoders, importers, parsers de protocolo, leitores de CLI/arquivos.
3. Execute consultas de caminho desses pontos de entrada até as funções candidatas para separar a superfície de ataque alcançável do código morto/interno.
4. Priorize os nós que combinam:
   - alta **complexidade ciclomática**
   - **alcance confirmado a partir de dados não confiáveis**
   - alto **blast radius** ou muitos dependentes downstream
   - evidências corroborantes, como resultados **SARIF**, notas de auditoria ou sobreviventes de mutação
5. Escreva harnesses focados primeiro para os nós com as melhores pontuações, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/mensagens.

### Sobreviventes de mutação: equivalentes vs. acionáveis

O mutation testing costuma gerar uma lista ruidosa de sobreviventes. Antes de tratar cada sobrevivente como uma falha de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um ponto de entrada controlado por um atacante?
- Todos os caminhos de chamada são limitados por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica apenas de formatação ou em um caminho de aritmética/parser de alto impacto?

Sobreviventes que permanecem inalcançáveis ou estruturalmente restritos costumam ser **mutantes equivalentes**. Sobreviventes que continuam **alcançáveis** e afetam **condições de limite**, **caminhos de overflow/carry** ou **aritmética/parsing críticos para a segurança** devem ser promovidos a:

- novos fuzz harnesses
- testes diretos de propriedades/invariantes
- vetores direcionados para casos extremos

### Correlacionar resultados externos no grafo

Se o seu pipeline SAST exporta **SARIF**, projete os resultados nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para ampliar a análise de impacto.<sup>[[6]](#references)</sup>

- calcule o **blast radius** da função sinalizada
- verifique se o resultado está em algum caminho a partir de um ponto de entrada
- agrupe resultados próximos que convergem para o mesmo gargalo

Isso é útil para decidir se vale a pena dedicar tempo de fuzzing a uma função específica: um nó **alcançável**, **complexo** e que já apresenta **resultados SAST** costuma ser um alvo melhor do que um nó meramente complexo, sem caminho de ataque.

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

A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher alvos de fuzzing com o maior valor de segurança esperado e, em seguida, use os mutantes que sobreviverem para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing diferencial de codificações de chaves criptográficas

Comece com chaves serializadas válidas ou vetores de teste padrão. Mute os campos codificados sem comprometer o comprimento e a estrutura necessários para alcançar os caminhos de importação e operação; em seguida, envie os mesmos bytes para implementações independentes. Compare a aceitação e os erros. Assinaturas e textos cifrados aleatorizados precisam de oráculos de correção, não de comparação byte a byte: verifique as assinaturas ou compare os segredos compartilhados de uma operação de encapsulamento/decapsulamento. Vetores de teste estabelecem a conformidade para casos conhecidos; a mutação diferencial testa codificações malformadas além desses casos.<sup>[[23]](#references)[[26]](#references)</sup>

Para esses formatos de chave, use oráculos específicos para cada formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Chaves de assinatura expandidas ML-DSA:** altere os coeficientes `s1` ou `s2` compactados para que fiquem fora de `[-η, η]`, mantendo a chave analisável. Verifique se a importação ou a assinatura rejeita a chave e se alguma assinatura resultante é verificada. Diferenças de aceitação, por si só, não são violações dos padrões, pois FIPS 204 não exige verificações adicionais da chave privada. Consulte o [mecanismo de vazamento condicional](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pares de chaves ML-KEM:** diferencie as verificações obrigatórias da chave de encapsulamento e das entradas de decapsulamento da verificação opcional de consistência do par (PCT) em um par importado. Faça o encapsulamento com a chave pública, o decapsulamento com a chave privada e compare os segredos compartilhados; uma incompatibilidade pode interromper a comunicação criptografada mesmo quando as chaves passam individualmente pelas verificações de entrada. Verifique se a API valida as entradas durante a operação ou por meio de uma chamada separada; libcrux expõe `validate_public_key(pk)` e `validate_private_key(sk, ct)`, que não substituem uma PCT.
- **Chaves brutas XMSS/XMSSMT:** teste round trips de chaves serializadas de **assinatura e verificação** entre conjuntos de parâmetros, não apenas operações com chaves em memória. XMSS e XMSSMT têm namespaces OID de quatro bytes separados; portanto, um parser que testa apenas o OID e tenta XMSS primeiro pode classificar incorretamente uma chave XMSSMT com OID coincidente e rejeitar a importação. O parser RustCrypto relatado ilustra uma falha de interoperabilidade/disponibilidade, não uma falsificação de assinatura.

## Fuzzing em Go com gosentry: mecanismo mais robusto, entradas tipadas e verificações diferenciais

Se um alvo em Go já tiver um harness nativo `testing.F`, uma forma prática de atualizá-lo é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), uma toolchain de Go derivada que mantém `go test -fuzz`, mas troca o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Isso é útil quando o fuzzer nativo do Go trava em **comparações difíceis**, **entradas tipadas** ou **formatos com parsers complexos**. A metodologia continua a mesma:

- Continue usando `f.Add(...)` para as seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com agendamento/mutação do LibAFL e melhores detectores ao redor.

### Transforme falhas silenciosas em achados de fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos muitas vezes **não** causam um crash por padrão. Com o gosentry, você pode transformar várias classes de estados “ruins, mas silenciosos” em achados.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal`, que, de outra forma, apenas registrariam o erro e continuariam).
- `--catch-races=true` para reproduzir entradas recém-descobertas da fila com o detector de race do Go.
- `--catch-leaks=true` para reproduzir novas entradas da fila com o `goleak` e parar diante de leaks de goroutines.
- O tratamento de travamentos do LibAFL para manter **loops infinitos / entradas muito lentas** como achados de fuzzing, em vez de deixá-los desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos em que o impacto na segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **travamento que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing com reconhecimento de structs para APIs tipadas do Go

O fuzzing nativo do Go espera principalmente escalares como `[]byte`, `string` e números. Se o código em teste consome objetos tipados, o gosentry pode fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, pointers), enquanto continua mutando os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Use isso ao criar um formato wire falso apenas para fuzzing esconderia bugs de lógica por trás de código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolo

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **fuzzing de gramática Nautilus** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre a metodologia:

- Use o modo de gramática quando mutações no nível de bytes geralmente falham nas verificações sintáticas iniciais.
- Mantenha a gramática focada no **subconjunto da linguagem/protocolo relevante para a segurança**, em vez de modelar a especificação completa.
- Use valores grandes de limite em terminais/não terminais para testar os limites de inteiros, comprimentos e máquinas de estado.
- O modo de gramática mantém as entradas válidas segundo a gramática, mas o alvo ainda recebe **bytes/strings**, então a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Fuzzing diferencial: compare implementações, não apenas falhas

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

Considere os seguintes casos como descobertas:

- uma implementação entra em panic enquanto a outra rejeita corretamente
- incompatibilidades entre entradas aceitas/rejeitadas
- árvores de análise ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Esta é uma maneira prática de encontrar **incompatibilidades de consenso**, **ambiguidade de parser** e **divergências entre a especificação e a implementação** que muitas vezes passam despercebidas com fuzzing que apenas provoca falhas.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilizar o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Execute o comando do **mesmo pacote** e com o mesmo alvo `-fuzz` para que o gosentry resolva o estado correto da campanha em cache.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing com gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing do AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: sobre fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Faltava metade do conjunto de ferramentas de fuzzing do Go. Fizemos um fork do toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede stateful usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: rumo ao fuzzing do kernel Linux sem descrições de chamadas de sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptativos e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentação LLVM do AFL++: cobertura de caminhos e chamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing preditivo sensível ao contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de segurança ofensiva do Android - Fuzzing do Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer do Binder do LKL Android - documentação de compilação e seeds de regressão](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: explorando condições de corrida no kernel Linux com intercalações controladas de acessos à memória](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaxe de nomes de arquivo estendidos do CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Advisory da Doyensec: CFITSIO, quarto trimestre de 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing da sintaxe de nomes de arquivo estendidos do CFITSIO: 16 vulnerabilidades de segurança de memória e triagem assistida pelo Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing diferencial para criptografia](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: padrão de mecanismo de encapsulamento de chaves baseado em reticulados modulares](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug de parsing de OID do XMSSMT - issue #1442 do RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Estado das implementações de criptografia pós-quântica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
