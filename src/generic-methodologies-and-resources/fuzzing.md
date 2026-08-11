# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Cobertura vs. Semântica

No **fuzzing de gramática mutacional**, as entradas são modificadas enquanto permanecem **válidas segundo a gramática**. No modo guiado por cobertura, apenas as amostras que acionam **nova cobertura** são salvas como seeds do corpus. Para **targets de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de fluxo de dados**, nas quais a saída de um constructo se torna a entrada de outro.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o fluxo de dados encadeado**; por isso, a amostra “mais próxima do bug” é descartada porque não adiciona cobertura. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna cara e o feedback de cobertura não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **hibridizar fases mutacionais e generativas** ou favorecer a geração de padrões de **encadeamento de funções** (não apenas a cobertura).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por cobertura é **gananciosa**: uma amostra com nova cobertura é salva imediatamente, geralmente mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas**, com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil; portanto, um compromisso prático é a **minimização ciente da gramática**, que **para após atingir um limite mínimo de tokens** (reduzindo o ruído enquanto mantém estrutura circundante suficiente para continuar favorável à mutação).<sup>[[1]](#references)</sup>

Uma regra prática para o corpus em fuzzing mutacional é: **preferir um pequeno conjunto de seeds estruturalmente diferentes que maximize a cobertura** a uma grande quantidade de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do target).
- Refine-as usando **minimização de corpus baseada em cobertura**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos significativos, em vez de gastarem a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após grandes alterações no harness ou na instrumentação, pois o “melhor” corpus muda quando a alcançabilidade muda.

## Mutação Ciente de Comparações Para Valores Mágicos

Um motivo comum para os fuzzers atingirem um platô não é a sintaxe, mas as **comparações rígidas**: magic bytes, verificações de tamanho, strings de enum, checksums ou valores de dispatch do parser protegidos por `memcmp`, tabelas de switch ou comparações encadeadas. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses targets, use **rastreamento de comparações** (por exemplo, workflows no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar os operandos de comparações malsucedidas e direcionar as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>
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

- Isso é especialmente útil quando o alvo oculta a lógica profunda por trás de **file signatures**, **protocol verbs**, **type tags** ou **version-dependent feature bits**.
- Combine isso com **dictionaries** extraídos de amostras reais, especificações de protocolos ou debug logs. Um pequeno dictionary com tokens de gramática, nomes de chunks, verbs e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo realizar muitas verificações sequenciais, resolva primeiro as comparações “magic” mais iniciais e depois minimize novamente o corpus resultante, para que os estágios posteriores comecem com prefixos já válidos.

## Fuzzing Stateful: Sequências São Seeds

Para **protocols**, **authenticated workflows** e **multi-stage parsers**, a unidade interessante geralmente não é um único blob, mas uma **message sequence**. Concatenar todo o transcript em um único arquivo e sofrer mutações cegamente costuma ser ineficiente, pois o fuzzer modifica cada etapa igualmente, mesmo quando apenas a mensagem posterior alcança o estado frágil.<sup>[[4]](#references)</sup>

Um padrão mais eficaz é tratar a **sequence em si como a seed** e usar o **estado observável** (response codes, protocol states, parser phases, returned object types) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha as **valid prefix messages** estáveis e concentre as mutações na mensagem que conduz à **transition**.
- Armazene em cache os identificadores e valores gerados pelo servidor a partir das respostas anteriores quando a próxima etapa depender deles.
- Prefira mutação/splicing por mensagem em vez de modificar todo o transcript serializado como um blob opaco.
- Se o protocolo expuser response codes significativos, use-os como um **state oracle** barato para priorizar sequências que avancem mais profundamente.

Essa é a mesma razão pela qual bugs autenticados, transições ocultas ou bugs de parser que ocorrem “only-after-handshake” frequentemente não são encontrados pelo fuzzing vanilla no estilo de arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

## Truque de Diversidade em Uma Única Máquina (Estilo Jackalope)

Uma forma prática de combinar **generative novelty** com **coverage reuse** é **reiniciar workers de curta duração** contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos sobre o corpus combinado, sincroniza novamente e então termina. Isso produz **estruturas novas a cada geração**, enquanto continua aproveitando a coverage acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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

**Notas:**

- `-in empty` força um **corpus novo** a cada geração.
- `-server_update_interval T` aproxima uma **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo de grammar fuzzing, a **sincronização inicial com o servidor é ignorada por padrão** (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do target**; normalmente, funciona melhor alternar depois que o worker tiver encontrado a maior parte da cobertura “fácil”.

## Snapshot Fuzzing Para Targets Difíceis de Instrumentar

Quando o código que você quer testar só se torna alcançável **após um grande custo de configuração** (inicializar uma VM, concluir um login, receber um pacote, fazer o parsing de um container, inicializar um serviço), uma alternativa útil é o **snapshot fuzzing**: capture o estado do processo ou da VM prontos, injete cada caso de teste no caminho de entrada do target, execute até ocorrer um crash/timeout e restaure o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **targets somente binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o target até que o estado interessante esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada modificada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer crash/timeout/reset.
5. Restaure o snapshot; para targets em VM, restaure apenas as **páginas modificadas** quando houver suporte e repita.

Posicione o snapshot o mais próximo possível da primeira etapa cara de parsing/dispatch, como depois de um `recv`/`read` ou de um ponto de desserialização de pacote, e registre o buffer de entrada usado pelo target. Isso segue o princípio de posicionamento adaptativo de mover o snapshot para mais adiante no processamento da entrada, evitando repetir trabalho.<sup>[[11]](#references)</sup>

## Introspecção do Harness: Encontre Fuzzers Superficiais Cedo

Quando uma campanha fica estagnada, o problema geralmente não está no mutator, mas no **harness**. Use a **introspecção de alcançabilidade/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do fuzz target, mas que raramente ou nunca são cobertas dinamicamente. Essas funções normalmente indicam um destes três problemas.<sup>[[12]](#references)</sup>

- O harness entra no target tarde ou cedo demais.
- O seed corpus não contém uma família inteira de funcionalidades.
- O target realmente precisa de um **segundo harness**, em vez de um harness “faz tudo” grande demais.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a alcançabilidade estática com a cobertura em runtime e gerar relatórios a partir de uma execução temporizada ou de um corpus público.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus de um recurso específico ou dividir um harness monolítico em entry points menores.

## Seleção de alvos de fuzzing orientada por grafos e triagem de mutações

Se você já possui **findings de static analysis**, **sobreviventes de mutation testing** e **relatórios de cobertura**, não faça a triagem como listas independentes. Construa primeiro um **call graph**, anote os nós com **complexidade ciclomática**, **alcançabilidade a partir de entry points/input não confiável** e quaisquer findings externos, e então faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade são alcançáveis a partir de input não confiável?
- Quais sobreviventes de mutação estão em caminhos entre parsers/handlers e código crítico para a segurança?
- Quais funções são choke points arquiteturais com **blast radius** excepcionalmente alto?

Isso geralmente revela alvos de fuzzing melhores do que considerar apenas a "menor cobertura". Um parser/decoder com **alta complexidade** e **alcançabilidade externa** confirmada é um candidato a harness mais forte do que um helper interno isolado, com cobertura fraca, mas sem um caminho controlado pelo atacante.

### Fluxo prático de triagem

1. Construa um **code graph** a partir do codebase e extraia métricas de complexidade/branches por função.
2. Enumere os **entry points** que aceitam input controlado pelo atacante: request handlers, decoders, importers, protocol parsers, leitores de CLI/arquivos.
3. Execute **path queries** desses entry points até as funções candidatas para separar a attack surface alcançável do código morto/estritamente interno.
4. Priorize os nós que combinam:
- alta **complexidade ciclomática**
- **alcançabilidade confirmada a partir de input não confiável**
- **blast radius** alto ou muitos dependentes downstream
- evidências corroborantes, como findings de **SARIF**, notas de auditoria ou sobreviventes de mutação
5. Escreva harnesses focados para os nós com melhor pontuação primeiro, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensagens.

### Sobreviventes de mutação: equivalentes vs. acionáveis

O mutation testing geralmente produz uma lista ruidosa de sobreviventes. Antes de tratar cada sobrevivente como uma falha de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um entry point controlado pelo atacante?
- Todos os call paths são restringidos por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica relacionada apenas à formatação ou em um caminho de aritmética/parser de alto impacto?

Sobreviventes que continuam inalcançáveis ou estruturalmente restringidos geralmente são **mutantes equivalentes**. Sobreviventes que permanecem **alcançáveis** e afetam **condições de contorno**, **caminhos de overflow/carry** ou **aritmética/parsing crítico para a segurança** devem ser promovidos para:

- novos fuzz harnesses
- testes diretos de propriedades/invariantes
- vetores direcionados para edge cases

### Correlacione findings externos no grafo

Se seu pipeline de SAST exporta **SARIF**, projete os findings nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para expandir o impacto.<sup>[[6]](#references)</sup>

- calcule o **blast radius** da função sinalizada
- verifique se o finding está em algum caminho a partir de um entry point
- agrupe findings próximos que convergem para o mesmo choke point

Isso é útil ao decidir se vale a pena investir tempo de fuzzing em uma função específica: um nó que é **alcançável**, **complexo** e que já possui **hits de SAST** geralmente é um alvo melhor do que um nó apenas complexo, sem caminho controlado pelo atacante.

Exemplo de workflow com Trailmark.<sup>[[6]](#references)</sup>
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
A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher os fuzz targets com o maior valor de segurança esperado e, em seguida, use os mutation survivors para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing em Go com gosentry: Engine Mais Forte, Entradas Tipadas e Verificações Diferenciais

Se um target Go já possui um harness nativo `testing.F`, um caminho prático de upgrade é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), um toolchain Go derivado que mantém `go test -fuzz`, mas troca o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Isso é útil quando o fuzzer nativo do Go trava em **comparações difíceis**, **entradas tipadas** ou **formatos que exigem muito do parser**. A metodologia permanece a mesma:

- Continue usando `f.Add(...)` para seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal orientada por cobertura, mas com agendamento/mutação do LibAFL e melhores detectores complementares.

### Transformar falhas silenciosas em fuzz findings

Um problema recorrente em assessments de Go é que comportamentos perigosos frequentemente **não** causam crash por padrão. Com o gosentry, você pode promover várias classes de estados “ruins, mas silenciosos” a findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registrariam o log e continuariam).
- `--catch-races=true` para reproduzir entradas de fila recém-descobertas com o detector de race do Go.
- `--catch-leaks=true` para reproduzir novas entradas de fila com o `goleak` e interromper ao detectar leaks de goroutines.
- O tratamento de hangs do LibAFL para manter **loops infinitos / entradas muito lentas** como fuzz findings, em vez de deixá-los desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos cujo impacto de segurança seja uma **falha de parser sem panic**, um **bug de concorrência** ou um **hang causado apenas por DoS**, em vez de corrupção de memória.

### Fuzzing ciente de structs para APIs Go tipadas

O fuzzing nativo do Go espera principalmente escalares como `[]byte`, `string` e números. Se o código sob teste consumir objetos tipados, o gosentry poderá fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, pointers), continuando a mutar bytes internamente.<sup>[[7]](#references)[[8]](#references)</sup>
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
Use isto ao criar um wire format falso apenas para fuzzing, pois isso ocultaria bugs de lógica atrás de um código de parsing exclusivo do harness. Para campanhas differential ou grammar-based, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolos

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **Nautilus grammar fuzzing** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness normalmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodologia:

- Use o grammar mode quando as mutações no nível de bytes morrerem principalmente nas verificações de sintaxe iniciais.
- Mantenha a grammar focada no **subconjunto relevante para a segurança** da linguagem/protocolo, em vez de modelar toda a especificação.
- Use valores-limite grandes em terminais/não terminais para estressar os limites de inteiros, comprimentos e máquinas de estado.
- O grammar mode mantém as entradas válidas conforme a grammar, mas o alvo ainda recebe **bytes/strings**, portanto a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: comparar implementações, não apenas crashes

Um padrão forte para ecossistemas Go é o **grammar-based differential fuzzing**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou mecanismos de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>
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
Considere os seguintes como resultados:

- uma implementação entra em panic enquanto a outra rejeita de forma limpa
- incompatibilidades entre entradas aceitas/rejeitadas
- árvores de parsing ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Esta é uma forma prática de encontrar **incompatibilidades de consenso**, **ambiguidades de parser** e **divergências entre a especificação e a implementação** que o fuzzing puro de crashes frequentemente não detecta.

### Reutilizar o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus de fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Execute o comando a partir do **mesmo pacote** e com o **mesmo alvo `-fuzz`** para que o gosentry resolva o estado correto da campanha armazenado em cache.

## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing do AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: sobre fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Ao fuzzing do Go faltava metade do toolkit. Fizemos um fork do toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede stateful usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: rumo ao fuzzing do kernel Linux sem descrições de chamadas do sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptativos e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
