# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Cobertura vs. Semântica

No **fuzzing de gramática mutacional**, as entradas são modificadas sem deixar de ser **válidas segundo a gramática**. No modo guiado por cobertura, somente as amostras que acionam **nova cobertura** são salvas como seeds do corpus. Para **alvos de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de fluxo de dados**, nas quais a saída de uma construção se torna a entrada de outra.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o fluxo de dados encadeado**; assim, a amostra “mais próxima do bug” é descartada porque não acrescenta cobertura. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna cara, e o feedback de cobertura não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **combinar fases mutacionais e generativas** ou favorecer padrões de **encadeamento de funções** durante a geração (não apenas a cobertura).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por cobertura é **gulosa**: uma amostra que gera nova cobertura é salva imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas** com pouca diversidade estrutural. Uma minimização agressiva pode remover contexto útil; por isso, uma solução prática é a **minimização com conhecimento da gramática**, que **para ao atingir um limite mínimo de tokens** (reduzindo o ruído e mantendo estrutura ao redor suficiente para facilitar mutações).<sup>[[1]](#references)</sup>

Uma regra prática para o corpus em fuzzing mutacional é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximize a cobertura** a um grande conjunto de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do alvo).
- Destile-as com **minimização do corpus baseada em cobertura**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos significativos, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após grandes mudanças no harness ou na instrumentação, pois o corpus “ideal” muda quando a alcançabilidade muda.

## Mutação Guiada por Comparações para Valores Mágicos

Um motivo comum para os fuzzers estagnarem não é a sintaxe, mas **comparações difíceis**: bytes mágicos, verificações de comprimento, strings de enum, checksums ou valores de dispatch do parser protegidos por `memcmp`, tabelas `switch` ou comparações em cascata. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte por byte.

Para esses alvos, use **rastreamento de comparações** (por exemplo, workflows no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar os operandos de comparações malsucedidas e direcionar as mutações a valores que as satisfaçam.<sup>[[3]](#references)</sup>

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

- Isso é especialmente útil quando o alvo bloqueia a lógica profunda por trás de **assinaturas de arquivo**, **verbos de protocolo**, **tags de tipo** ou **bits de recursos dependentes da versão**.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de depuração. Um dicionário pequeno com tokens gramaticais, nomes de chunks, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo realizar muitas verificações sequenciais, resolva primeiro as comparações de “magic” mais iniciais e depois minimize novamente o corpus resultante para que os estágios posteriores comecem com prefixos já válidos.

## Mais feedback quando a cobertura de arestas colapsa caminhos diferentes

A cobertura normal de arestas não consegue distinguir duas execuções que percorrem o mesmo helper por meio de chamadores diferentes ou assumem combinações diferentes de ramificações dentro de uma função. Isso é importante em decodificadores compartilhados, despachantes de protocolo e helpers de interpretadores, onde a **rota** até uma aresta determina o estado ativo. Rastrear ingenuamente cada contexto de chamada também é perigoso: o mapa de cobertura e a fila podem explodir. Por isso, pesquisas sobre fuzzing sensível a contexto recomendam refinar apenas os contextos promissores, em vez de tratar todo o grafo de chamadas como sensível a contexto.<sup>[[14]](#references)</sup>

Versões recentes do AFL++ oferecem **cobertura de caminhos por função Ball-Larus**, além da cobertura normal de arestas. Ela atribui um recurso a cada caminho acíclico por uma função; as arestas de retorno de loop são removidas, então esse feedback distingue combinações de ramificações, mas **não a contagem de iterações do loop**. Comece com o nível relaxado `1` e, em seguida, aplique modos mais rigorosos apenas ao código suspeito de parser/máquina de estados, pois o número de caminhos pode crescer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para uma função auxiliar chamada em muitos locais relevantes para a segurança, o modo LTO pode combinar cada caminho da função com seu local de chamada imediato:<sup>[[13]](#references)</sup>

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

**Orientação para a campanha:** aplique feedback mais rico com cautela e monitore o custo na coverage map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Execute em paralelo uma instância comum de edge coverage; o feedback mais rico só é útil se o custo extra de queue/map não reduzir demais as execuções por segundo.
- Use `AFL_LLVM_ALLOWLIST` para restringir a instrumentação de caminhos/chamadores quando bibliotecas grandes e cheias de templates ou código utilitário genérico dominarem o map.
- Funções com caminhos acíclicos em excesso podem ser ignoradas pelo AFL++; avisos durante a compilação são indícios de que o alvo precisa de allowlisting ou de um nível menos rigoroso.
- A cobertura de chamador + caminho oferece suporte a apenas um nível de chamador. Não a combine com stacks de contexto mais profundos.
- Os IDs de caminho podem mudar entre versões principais do LLVM. Mantenha a toolchain fixa durante uma campanha e não sincronize corpora baseados em PATH como se os IDs de recurso fossem estáveis entre builds.
- Esse feedback complementa o `CMPLOG`: o rastreamento de comparações resolve **qual valor passa por uma condição**, enquanto o feedback de caminho/chamador preserva **qual rota e combinação de ramificações chegaram até ela**.

## Fuzzing com estado: sequências são seeds

Para **protocolos**, **fluxos de trabalho autenticados** e **parsers em várias etapas**, a unidade interessante muitas vezes não é um único blob, mas uma **sequência de mensagens**. Concatenar toda a transcrição em um arquivo e mutá-la às cegas costuma ser ineficiente, pois o fuzzer altera cada etapa igualmente, mesmo quando apenas a mensagem posterior alcança o estado vulnerável.<sup>[[4]](#references)</sup>

Uma abordagem mais eficaz é tratar a **própria sequência como seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos de objeto retornados) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha **mensagens de prefixo válidas** estáveis e concentre as mutações na mensagem que **aciona a transição**.
- Armazene em cache identificadores e valores gerados pelo servidor nas respostas anteriores quando a etapa seguinte depender deles.
- Prefira mutações/splicing por mensagem a mutar toda a transcrição serializada como um blob opaco.
- Se o protocolo expuser códigos de resposta relevantes, use-os como um **oráculo de estado barato** para priorizar sequências que avancem mais.

É por isso que bugs autenticados, transições ocultas ou bugs de parser que ocorrem “somente após o handshake” muitas vezes passam despercebidos no fuzzing convencional baseado em arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de driver com vários clientes

Uma alta cobertura de arestas ainda pode não revelar bugs no driver IPC, pois a cobertura não descreve **propriedade de objetos, contagens de referências, mensagens pendentes, ordem de limpeza ou intercalações entre threads**. A página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) aborda o modelo de objetos do driver; este exemplo se concentra no harness do fuzzer. Android Binder é um modelo útil: alcançar os caminhos de alocação e liberação não basta se o fuzzer não conseguir fazer vários processos operarem sobre o mesmo objeto do kernel na ordem necessária.<sup>[[15]](#references)</sup>

#### Modele o protocolo, não buffers `ioctl` isolados

Represente um caso de teste como uma gramática ordenada de **identidade do cliente + operação + argumentos estruturados**. O fuzzer LKL do Binder usa protobuf e `libprotobuf-mutator`, com um cliente gerenciador de contexto persistente e dois clientes comuns. Um harness semântico preserva as relações que a mutação cega de bytes destruiria.<sup>[[15]](#references)</sup>

- Armazene em cache os valores retornados por operações anteriores. Por exemplo, `BC_FREE_BUFFER` precisa reutilizar um ponteiro de buffer de transação retornado por um `ioctl` anterior.
- Gere respostas padrão válidas para que transações síncronas possam terminar e operações posteriores continuem alcançáveis.
- Rejeite transições impossíveis, como transações para si mesmo ou várias transações pendentes para o mesmo destino.
- Mantenha o estado de inicialização singleton fora da redefinição por entrada. O Binder permite apenas um registro `BINDER_SET_CONTEXT_MGR` por inicialização; destruir e recriar esse cliente repetidamente invalidaria as entradas posteriores.

Um modelo útil para uma condição de corrida de ciclo de vida é fazer um cliente transferir um objeto, iniciar a limpeza de uma thread ou processo e, em paralelo, fazer o cliente receptor liberar o buffer de transação. No exemplo CVE-2020-0423, uma transferência `BINDER_TYPE_WEAK_BINDER` seguida de `BINDER_THREAD_EXIT` em disputa com `BC_FREE_BUFFER` podia liberar um `binder_work` embutido enquanto o caminho de limpeza da thread em encerramento ainda o utilizava.<sup>[[15]](#references)</sup>

#### Reintroduza intercalações controladas em um kernel em espaço de usuário

A [Linux Kernel Library (LKL)](https://github.com/lkl/linux) vincula o código real do kernel a um harness em espaço de usuário e expõe sua interface de chamadas de sistema por meio de `lkl_syscall`. Isso facilita coordenar protobuf, cobertura e KASAN em um único processo. No entanto, normalmente o LKL executa uma chamada de sistema sem que outra thread do kernel a interrompa. Para campanhas de condições de corrida, insira pontos `schedule()` em torno de limites selecionados de bloqueio/desbloqueio e ciclo de vida; em seguida, deixe o harness escolher aleatoriamente o próximo cliente a cada cedência. Mantenha esses pontos direcionados, pois cada um amplia o espaço de busca do escalonamento. O escalonador aleatório descrito pelos pesquisadores **não** faz parte do fuzzer upstream do Binder.<sup>[[15]](#references)</sup>

#### Compile e reproduza seeds de regressão serializadas

O harness upstream fixa uma versão compatível de `libprotobuf-mutator`, habilita a instrumentação de fuzzing do LKL e o KASAN com `LKL_FUZZING=1`, e habilita `CONFIG_MMU` para o Binder com `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Após obter uma revisão deliberadamente vulnerável ou aplicar os patches de rollback documentados upstream, uma seed serializada pode reproduzir toda a transição de estado de múltiplos clientes sem reconstruí-la em uma prova de conceito C improvisada:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trate o use-after-free resultante do KASAN como confirmação de que o seed alcançou o caminho vulnerável de ciclo de vida. Isso **não** demonstra as primitivas posteriores necessárias para execução de código no kernel ou escalonamento de privilégios.<sup>[[16]](#references)</sup>

## Truque de diversidade em uma única máquina (estilo Jackalope)

Uma maneira prática de combinar **novidade generativa** com **reaproveitamento de cobertura** é **reiniciar workers de curta duração** contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos usando o corpus combinado, sincroniza novamente e então encerra. Isso gera **estruturas novas a cada geração** e, ao mesmo tempo, aproveita a cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` força um **corpus novo** em cada geração.
- `-server_update_interval T` aproxima uma **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo de grammar fuzzing, a **sincronização inicial com o servidor é ignorada por padrão** (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do alvo**; geralmente funciona melhor mudar depois que o worker encontrar a maior parte da cobertura “fácil”.

## Snapshot Fuzzing Para Alvos Difíceis de Instrumentar

Quando o código que você quer testar só pode ser alcançado **após um grande custo de preparação** (inicializar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é o **snapshot fuzzing**: capturar o estado pronto do processo ou da VM, injetar cada caso de teste no caminho de entrada do alvo, executar até ocorrer um crash ou timeout e restaurar o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **alvos apenas binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o alvo até que o estado desejado esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, grave a entrada mutada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer um crash, timeout ou reset.
5. Restaure o snapshot; para alvos em VM, restaure apenas as **páginas sujas**, quando houver suporte, e repita.

Posicione o snapshot o mais próximo possível da primeira etapa de análise/dispatch dispendiosa, como após um `recv`/`read` ou um ponto de desserialização de pacote, e registre o buffer de entrada usado pelo alvo. Isso segue o princípio de posicionamento adaptativo: mover o snapshot para mais perto do processamento da entrada para evitar repetir trabalho.<sup>[[11]](#references)</sup>

## Introspecção do Harness: Identifique Cedo Fuzzers Superficiais

Quando uma campanha estagna, o problema muitas vezes não está no mutator, mas no **harness**. Use a **introspecção de alcançabilidade/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do alvo do fuzz, mas raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um destes três problemas.<sup>[[12]](#references)</sup>

- O harness entra no alvo tarde ou cedo demais.
- O corpus de seeds não contém uma família inteira de funcionalidades.
- O alvo realmente precisa de um **segundo harness**, em vez de um único harness “faz tudo” superdimensionado.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a alcançabilidade estática com a cobertura em runtime e gerar relatórios a partir de uma execução temporizada ou de um corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Use o relatório para decidir se deve adicionar um novo harness para um caminho do parser ainda não testado, expandir o corpus para um recurso específico ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de alvos de fuzzing com foco no grafo e triagem de mutações

Se você já tem **resultados de análise estática**, **sobreviventes de testes de mutação** e **relatórios de cobertura**, não os avalie como listas independentes. Primeiro, crie um **grafo de chamadas**, anote os nós com **complexidade ciclomática**, **alcançabilidade a partir de pontos de entrada/dados não confiáveis** e quaisquer resultados externos, depois faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade podem ser alcançadas a partir de dados não confiáveis?
- Quais sobreviventes de mutação estão em caminhos dos parsers/handlers até código crítico para a segurança?
- Quais funções são gargalos arquiteturais com **raio de impacto** excepcionalmente alto?

Isso geralmente revela alvos de fuzzing melhores do que considerar apenas a "menor cobertura". Um parser/decodificador com **alta complexidade** e **alcançabilidade externa** confirmada é um candidato a harness mais forte do que um helper interno isolado com baixa cobertura, mas sem um caminho controlável por um atacante.

### Fluxo prático de triagem

1. Crie um **grafo de código** a partir da base de código e extraia métricas de complexidade/ramificações por função.
2. Enumere os **pontos de entrada** que aceitam dados controlados por um atacante: handlers de requisição, decodificadores, importadores, parsers de protocolo, leitores de CLI/arquivos.
3. Execute consultas de caminho a partir desses pontos de entrada até as funções candidatas para separar a superfície de ataque alcançável do código morto/interno.
4. Priorize os nós que combinam:
   - alta **complexidade ciclomática**
   - **alcançabilidade confirmada a partir de dados não confiáveis**
   - alto **raio de impacto** ou muitos dependentes downstream
   - evidências corroborativas, como resultados de **SARIF**, notas de auditoria ou sobreviventes de mutação
5. Escreva primeiro harnesses focados para os nós com melhor pontuação, especialmente **parsers/codecs**, como decodificadores de hex/Base64/IP/mensagens.

### Sobreviventes de mutação: equivalentes ou acionáveis

Os testes de mutação costumam gerar uma lista ruidosa de sobreviventes. Antes de tratar cada sobrevivente como uma lacuna de segurança, use o grafo para perguntar:

- A função mutada pode ser alcançada a partir de um ponto de entrada controlado por um atacante?
- Todos os caminhos de chamada são restringidos por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, em lógica que só afeta a formatação ou em um caminho de alto impacto envolvendo aritmética/parsers?

Sobreviventes que continuam inalcançáveis ou estruturalmente restritos costumam ser **mutantes equivalentes**. Sobreviventes que continuam **alcançáveis** e afetam **condições de limite**, **caminhos de overflow/carry** ou **aritmética/parsing críticos para a segurança** devem ser promovidos a:

- novos harnesses de fuzzing
- testes diretos de propriedades/invariantes
- vetores direcionados para casos-limite

### Correlacione resultados externos no grafo

Se seu pipeline de SAST exporta **SARIF**, projete os resultados nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para ampliar a análise de impacto.<sup>[[6]](#references)</sup>

- calcule o **raio de impacto** da função sinalizada
- verifique se o resultado está em algum caminho a partir de um ponto de entrada
- agrupe resultados próximos que convergem para o mesmo gargalo

Isso é útil para decidir se vale a pena dedicar tempo de fuzzing a uma função específica: um nó **alcançável**, **complexo** e que já apresenta **resultados de SAST** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho acessível a um atacante.

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

A metodologia importante está na interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher alvos de fuzzing com o maior valor de segurança esperado e, em seguida, use os sobreviventes às mutações para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing em Go com gosentry: mecanismo mais robusto, entradas tipadas e verificações diferenciais

Se um alvo em Go já tiver um harness nativo de `testing.F`, uma opção prática de atualização é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), um fork do toolchain do Go que mantém `go test -fuzz`, mas troca o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Isso é útil quando o fuzzer nativo do Go trava em **comparações difíceis**, **entradas tipadas** ou **formatos com parsing intensivo**. A metodologia continua a mesma:

- Continue usando `f.Add(...)` para as seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com o agendamento e a mutação do LibAFL e detectores adicionais mais eficazes.

### Transforme falhas silenciosas em achados de fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos muitas vezes **não** causam crash por padrão. Com o gosentry, você pode transformar várias classes de estados “ruins, mas silenciosos” em achados.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer caminhos selecionados de log/erro se comportarem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram o erro e continuam).
- `--catch-races=true` para reproduzir entradas recém-descobertas da fila com o detector de race do Go.
- `--catch-leaks=true` para reproduzir novas entradas da fila com `goleak` e parar diante de vazamentos de goroutines.
- O tratamento de travamentos do LibAFL mantém **loops infinitos / entradas muito lentas** como achados de fuzzing, em vez de deixá-los desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos cujo impacto na segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **travamento que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing ciente de structs para APIs tipadas do Go

O fuzzing nativo do Go espera principalmente escalares, como `[]byte`, `string` e números. Se o código sob teste consome objetos tipados, o gosentry pode fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, pointers), continuando a mutar os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Use isso ao criar um formato wire fictício apenas para fuzzing, pois isso esconderia bugs de lógica por trás de código de parsing usado somente pelo harness. Em campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolo

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **fuzzing gramatical Nautilus** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre a metodologia:

- Use o modo grammar quando mutações no nível de byte falharem principalmente em verificações sintáticas iniciais.
- Mantenha a grammar focada no **subconjunto da linguagem/protocolo relevante para a segurança**, em vez de modelar toda a especificação.
- Use valores-limite grandes em terminais/não terminais para testar limites de inteiros, comprimentos e máquinas de estado.
- O modo grammar mantém as entradas válidas segundo a grammar, mas o alvo ainda recebe **bytes/strings**, então a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: compare implementações, não apenas crashes

Um padrão eficaz para ecossistemas Go é o **differential fuzzing baseado em grammar**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou mecanismos de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considere os seguintes casos como achados:

- uma implementação entra em panic enquanto a outra rejeita a entrada corretamente
- divergências entre entradas aceitas/rejeitadas
- árvores de análise ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Esta é uma maneira prática de encontrar **divergências de consenso**, **ambiguidades de parser** e **desvios entre especificação e implementação** que o fuzzing focado apenas em crashes costuma não detectar.

### Reutilizar o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Execute o comando a partir do **mesmo pacote** e com o **mesmo alvo `-fuzz`** para que o gosentry resolva o estado em cache correto da campanha.



## References

- [1] [Fuzzing com gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing com AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Faltava metade do kit de ferramentas de fuzzing do Go. Fizemos um fork do toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede com estado usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: rumo ao fuzzing do kernel Linux sem descrições de chamadas de sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptáveis e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentação LLVM do AFL++: cobertura de caminhos e chamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing preditivo sensível ao contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de segurança ofensiva do Android - fuzzing do Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL do Binder do Android - documentação de compilação e seeds de regressão](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
