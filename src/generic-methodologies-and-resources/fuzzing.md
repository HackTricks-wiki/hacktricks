# Metodologia de Fuzzing

## Fuzzing de Gramática Mutacional: Coverage vs. Semantics

No **fuzzing de gramática mutacional**, as entradas são modificadas enquanto permanecem **válidas segundo a gramática**. No modo guiado por coverage, apenas as amostras que acionam **nova coverage** são salvas como seeds do corpus. Para **language targets** (parsers, interpreters, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de dataflow**, nas quais a saída de um constructo se torna a entrada de outro.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitives semelhantes), mas **não preserva o dataflow encadeado**; assim, a amostra “mais próxima do bug” é descartada porque não adiciona coverage. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna cara, e o feedback de coverage não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para gramáticas com muitas dependências, considere **combinar as fases mutacional e generativa** ou direcionar a geração para padrões de **function chaining** (não apenas para coverage).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por coverage é **greedy**: uma amostra com nova coverage é salva imediatamente, geralmente mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas**, com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil; por isso, um compromisso prático é a **minimização consciente da gramática**, que **para após atingir um limite mínimo de tokens** (reduzindo o ruído e mantendo estrutura circundante suficiente para continuar favorável à mutação).<sup>[[1]](#references)</sup>

Uma regra prática para o corpus em fuzzing mutacional é: **preferir um conjunto pequeno de seeds estruturalmente diferentes que maximize a coverage** em vez de uma grande coleção de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do target).
- Refine-as usando **minimização de corpus baseada em coverage**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos relevantes, em vez de passar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após alterações importantes no harness ou na instrumentação, pois o corpus “melhor” muda quando a reachability muda.

## Mutação Orientada a Comparações Para Magic Values

Um motivo comum para os fuzzers atingirem um plateau não é a sintaxe, mas as **comparações rígidas**: magic bytes, verificações de tamanho, strings de enum, checksums ou valores de dispatch do parser protegidos por `memcmp`, tabelas de switch ou comparações encadeadas. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses targets, use **rastreamento de comparações** (por exemplo, workflows no estilo `CMPLOG` / Redqueen do AFL++) para que o fuzzer possa observar os operandos de comparações malsucedidas e direcionar as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>
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

- Isso é especialmente útil quando o alvo coloca a lógica profunda atrás de **assinaturas de arquivo**, **verbos de protocolo**, **type tags** ou **feature bits** dependentes da versão.
- Combine-o com **dictionaries** extraídos de amostras reais, especificações de protocolo ou debug logs. Um dictionary pequeno com tokens de gramática, nomes de chunks, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo realizar muitas verificações sequenciais, resolva primeiro as comparações “mágicas” mais iniciais e, em seguida, minimize novamente o corpus resultante para que os estágios posteriores comecem com prefixos já válidos.

## Stateful Fuzzing: Sequências São Seeds

Para **protocolos**, **workflows autenticados** e **parsers em múltiplos estágios**, a unidade interessante geralmente não é um único blob, mas uma **sequência de mensagens**. Concatenar toda a transcrição em um único arquivo e mutá-la cegamente costuma ser ineficiente, porque o fuzzer muta cada etapa igualmente, mesmo quando apenas a mensagem posterior alcança o estado frágil.<sup>[[4]](#references)</sup>

Um padrão mais eficaz é tratar a **própria sequência como a seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos dos objetos retornados) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha as **mensagens de prefixo válidas** estáveis e concentre as mutações na mensagem que **conduz a transição**.
- Armazene em cache os identificadores e valores gerados pelo servidor nas respostas anteriores quando a etapa seguinte depender deles.
- Prefira mutação/splicing por mensagem em vez de mutar toda a transcrição serializada como um blob opaco.
- Se o protocolo expuser códigos de resposta relevantes, use-os como um **oráculo de estado barato** para priorizar sequências que avancem mais profundamente.

Essa é a mesma razão pela qual bugs autenticados, transições ocultas ou bugs de parser que ocorrem “somente após o handshake” frequentemente não são encontrados pelo fuzzing vanilla no estilo de arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas estrutura.<sup>[[4]](#references)</sup>

## Truque de Diversidade em uma Única Máquina (Estilo Jackalope)

Uma forma prática de combinar **novidade generativa** com **reutilização de coverage** é **reiniciar workers de curta duração** contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos usando o corpus combinado, sincroniza novamente e então encerra. Isso produz **estruturas novas a cada geração**, enquanto ainda aproveita a coverage acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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
- O valor ideal de `T` **depende do target**; a troca depois que o worker encontrar a maior parte da cobertura “fácil” tende a funcionar melhor.

## Snapshot Fuzzing Para Targets Difíceis de Instrumentar

Quando o código que você deseja testar só se torna acessível **após um grande custo de configuração** (inicializar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é o **snapshot fuzzing**: capture o estado do processo ou da VM pronto, injete cada caso de teste no caminho de entrada do target, execute até ocorrer um crash/timeout e restaure o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **targets somente binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o target até que o estado interessante esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada mutada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer um crash/timeout/reset.
5. Restaure o snapshot; para targets de VM, restaure apenas as **páginas modificadas** quando houver suporte e repita.

Posicione o snapshot o mais próximo possível da primeira etapa dispendiosa de parsing/dispatch, como após um `recv`/`read` ou um ponto de desserialização de pacotes, e registre o buffer de entrada usado pelo target. Isso segue o princípio de posicionamento adaptativo de mover o snapshot para mais perto do processamento da entrada, evitando repetir trabalho.<sup>[[11]](#references)</sup>

## Introspecção do Harness: Encontre Fuzzers Superficiais Cedo

Quando uma campanha estagna, o problema geralmente não está no mutator, mas no **harness**. Use a **introspecção de reachability/coverage** para encontrar funções que são estaticamente alcançáveis a partir do seu fuzz target, mas que raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um dos três problemas.<sup>[[12]](#references)</sup>

- O harness entra no target tarde ou cedo demais.
- O seed corpus não contém toda uma família de recursos.
- O target realmente precisa de um **segundo harness**, em vez de um único harness gigantesco que “faz tudo”.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a reachability estática com a coverage em runtime e gerar relatórios a partir de uma execução temporizada ou de um corpus público.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus de uma funcionalidade específica ou dividir um harness monolítico em entry points menores.

## Seleção de Alvos de Fuzzing com Graph-First e Triagem de Mutações

Se você já possui **static-analysis findings**, **mutation-testing survivors** e **coverage reports**, não faça a triagem como listas independentes. Primeiro, crie um **call graph**, anote os nós com **cyclomatic complexity**, **entrypoint/untrusted-input reachability** e quaisquer findings externos, e então faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade são alcançáveis a partir de untrusted input?
- Quais mutation survivors estão em caminhos de parsers/handlers até código security-critical?
- Quais funções são choke points arquiteturais com **blast radius** excepcionalmente alto?

Isso normalmente revela alvos de fuzzing melhores do que considerar apenas a "lowest coverage". Um parser/decoder com **high complexity** e **external reachability** confirmada é um candidato mais forte a harness do que um helper interno isolado com cobertura fraca, mas sem um caminho controlado pelo atacante.

### Fluxo prático de triagem

1. Crie um **code graph** a partir da codebase e extraia métricas de complexidade/branch por função.
2. Enumere os **entrypoints** que aceitam input controlado pelo atacante: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Execute **path queries** a partir desses entrypoints até as funções candidatas para separar a attack surface alcançável do código morto/contido apenas internamente.
4. Priorize os nós que combinam:
- alta **cyclomatic complexity**
- **reachability from untrusted input** confirmada
- alto **blast radius** ou muitos dependentes downstream
- evidências adicionais, como findings de **SARIF**, notas de auditoria ou mutation survivors
5. Escreva harnesses focados primeiro para os nós com melhor pontuação, especialmente **parsers/codecs** como decoders de hex/Base64/IP/message.

### Mutation survivors: equivalentes vs. acionáveis

O mutation testing geralmente produz uma lista ruidosa de survivors. Antes de tratar cada survivor como uma falha de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um entrypoint controlado pelo atacante?
- Todos os call paths são restringidos por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica relacionada apenas à formatação ou em um caminho de aritmética/parser de alto impacto?

Survivors que continuam inacessíveis ou estruturalmente restringidos geralmente são **equivalent mutants**. Survivors que permanecem **reachable** e afetam **boundary conditions**, **overflow/carry paths** ou **security-critical arithmetic/parsing** devem ser promovidos a:

- novos fuzz harnesses
- testes diretos de propriedades/invariantes
- vetores direcionados de edge cases

### Correlacione findings externos no grafo

Se o pipeline de SAST exportar **SARIF**, projete os findings nos nós do grafo usando **file + line range** e use o grafo para expandir o impacto.<sup>[[6]](#references)</sup>

- calcule o **blast radius** da função sinalizada
- verifique se o finding está em algum caminho a partir de um entrypoint
- agrupe findings próximos que convergem para o mesmo choke point

Isso é útil ao decidir se vale a pena investir tempo de fuzzing em uma função específica: um nó que seja **reachable**, **complex** e já possua **SAST hits** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho controlado pelo atacante.

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
A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher os fuzz targets com o maior valor de segurança esperado e, em seguida, use os sobreviventes das mutações para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing em Go com gosentry: Engine Mais Forte, Inputs Tipados e Verificações Diferenciais

Se um target em Go já tiver um harness nativo `testing.F`, um caminho prático de upgrade é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), um toolchain Go bifurcado que mantém `go test -fuzz`, mas substitui o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Isso é útil quando o fuzzer nativo do Go trava em **comparações difíceis**, **entradas tipadas** ou **formatos pesados em parsers**. A metodologia permanece a mesma:

- Continue usando `f.Add(...)` para seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com scheduling/mutation do LibAFL e melhores detectores complementares.

### Transformar falhas silenciosas em descobertas do fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos frequentemente **não** causam crash por padrão. Com o gosentry, você pode promover várias classes de estados “ruins, mas silenciosos” a descobertas.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram o erro e continuam).
- `--catch-races=true` para reproduzir novas entradas da fila com o detector de race do Go.
- `--catch-leaks=true` para reproduzir novas entradas da fila com o `goleak` e interromper ao detectar leaks de goroutines.
- Tratamento de hangs do LibAFL para manter **loops infinitos / entradas muito lentas** como descobertas do fuzzing, em vez de deixá-las desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos cujo impacto de segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **hang que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing consciente de structs para APIs tipadas do Go

O fuzzing nativo do Go espera principalmente escalares, como `[]byte`, `string` e números. Se o código sob teste consumir objetos tipados, o gosentry poderá fazer fuzzing diretamente de **valores compostos** (structs, slices, arrays, pointers), continuando a mutar os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>
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
Use isso ao criar um wire format falso apenas para fuzzing, pois isso ocultaria bugs lógicos atrás de um código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolo

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **Nautilus grammar fuzzing** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve receber um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodologia:

- Use o modo grammar quando mutações em nível de byte geralmente morrem nas verificações iniciais de sintaxe.
- Mantenha a grammar focada no **subconjunto relevante para a segurança** da linguagem/protocolo, em vez de modelar a especificação completa.
- Use valores de limite grandes em terminais/não terminais para estressar limites de inteiros, comprimentos e máquinas de estado.
- O modo grammar mantém as entradas válidas de acordo com a grammar, mas o alvo ainda recebe **bytes/strings**, portanto a análise e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: compare implementações, não apenas crashes

Um padrão forte para os ecossistemas Go é o **grammar-based differential fuzzing**: gere entradas estruturadas válidas e forneça-as a dois parsers, clientes ou mecanismos de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>
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
Trate os seguintes casos como descobertas:

- uma implementação entra em panic enquanto a outra rejeita de forma limpa
- incompatibilidade entre entradas aceitas/rejeitadas
- árvores de análise ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Essa é uma forma prática de encontrar **consensus mismatches**, **parser ambiguity** e **spec-vs-implementation drift** que o crash fuzzing puro frequentemente não detecta.

### Reutilize o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus de fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Execute o comando a partir do **mesmo package** e com o **mesmo alvo `-fuzz`** para que o gosentry resolva o estado correto da campaign armazenado em cache.

## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing com AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: sobre fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [O fuzzing de Go não tinha metade do toolkit. Fizemos um fork do toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede stateful usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: em direção ao fuzzing do kernel Linux sem descrições de system calls](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptativos e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
