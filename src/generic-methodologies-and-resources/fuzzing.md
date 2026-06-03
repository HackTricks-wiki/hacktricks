# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Coverage vs. Semantics

Em **mutational grammar fuzzing**, os inputs são mutados enquanto permanecem **grammar-valid**. Em modo coverage-guided, apenas amostras que disparam **new coverage** são salvas como corpus seeds. Para **language targets** (parsers, interpreters, engines), isso pode deixar passar bugs que exigem **semantic/dataflow chains** em que a saída de uma construção se torna a entrada de outra.

**Failure mode:** o fuzzer encontra seeds que individualmente exercitam `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o chained dataflow**, então a amostra “mais próxima do bug” é descartada porque não adiciona coverage. Com **3+ dependent steps**, a recombinação aleatória fica cara e o feedback de coverage não guia a busca.

**Implication:** para grammars com muitas dependências, considere **hybridizing mutational and generative phases** ou enviesar a geração para padrões de **function chaining** (não apenas coverage).

## Armadilhas de Diversidade no Corpus

A mutação guided by coverage é **greedy**: uma amostra com new-coverage é salva imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora viram **near-duplicates** com baixa diversidade estrutural. Minimização agressiva pode remover contexto útil, então um compromisso prático é **grammar-aware minimization** que **para após um minimum token threshold** (reduz ruído enquanto mantém estrutura suficiente ao redor para continuar amigável à mutação).

Uma regra prática de corpus para fuzzing mutacional é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximizem coverage** em vez de um grande monte de near-duplicates. Na prática, isso normalmente significa:

- Comece com **real-world samples** (public corpora, crawling, captured traffic, conjuntos de arquivos do ecossistema alvo).
- Extraia-os com **coverage-based corpus minimization** em vez de manter cada amostra válida.
- Mantenha seeds **pequenas o suficiente** para que as mutações atinjam campos significativos, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após grandes mudanças no harness/instrumentation, porque o corpus “melhor” muda quando a reachability muda.

## Comparison-Aware Mutation For Magic Values

Um motivo comum para fuzzers entrarem em platô não é sintaxe, mas **hard comparisons**: magic bytes, length checks, enum strings, checksums ou valores de dispatch do parser protegidos por `memcmp`, switch tables ou comparações em cascata. Mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses targets, use **comparison tracing** (por exemplo, AFL++ `CMPLOG` / workflows estilo Redqueen) para que o fuzzer possa observar operandos de comparações falhas e enviesar mutações em direção a valores que as satisfaçam.
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

- Isso é especialmente útil quando o alvo bloqueia lógica profunda atrás de **file signatures**, **protocol verbs**, **type tags** ou **version-dependent feature bits**.
- Combine isso com **dictionaries** extraídos de amostras reais, specs de protocolo ou logs de debug. Um pequeno dictionary com grammar tokens, nomes de chunks, verbs e delimitadores costuma ser muito mais valioso do que um massive generic wordlist.
- Se o alvo faz muitas verificações sequenciais, resolva primeiro as comparações “magic” mais iniciais e depois minimize novamente o corpus resultante para que as etapas posteriores comecem a partir de prefixes já válidos.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** e **multi-stage parsers**, a unidade interessante muitas vezes não é um blob único, mas uma **message sequence**. Concatenar toda a transcript em um único arquivo e mutá-la cegamente geralmente é ineficiente, porque o fuzzer muta cada etapa igualmente, mesmo quando só a mensagem mais tarde alcança o estado frágil.

Um padrão mais eficaz é tratar a **sequence em si como o seed** e usar **observable state** (response codes, protocol states, parser phases, returned object types) como feedback adicional:

- Mantenha as **valid prefix messages** estáveis e foque as mutações na mensagem que **drives the transition**.
- Faça cache de identificadores e valores gerados pelo servidor a partir de respostas anteriores quando a próxima etapa depender deles.
- Prefira mutação/splicing por mensagem em vez de mutar toda a transcript serializada como um blob opaco.
- Se o protocol expõe response codes significativos, use-os como um **cheap state oracle** para priorizar sequences que avançam mais fundo.

Esse é o mesmo motivo pelo qual bugs autenticados, transições ocultas ou bugs de parser “only-after-handshake” muitas vezes passam despercebidos pelo file-style fuzzing vanilla: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas estrutura.

## Single-Machine Diversity Trick (Jackalope-Style)

Uma forma prática de híbridar **generative novelty** com **coverage reuse** é **reiniciar workers de curta duração** contra um server persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, roda mais `T` segundos no corpus combinado, sincroniza de novo e então sai. Isso produz **fresh structures each generation** enquanto ainda aproveita coverage acumulada.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers sequenciais (loop de exemplo):**

<details>
<summary>Loop de reinício do worker Jackalope</summary>
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

- `-in empty` força um **fresh corpus** a cada geração.
- `-server_update_interval T` aproxima **sync atrasado** (novelty primeiro, reuse depois).
- Em modo grammar fuzzing, a **sync inicial do server é ignorada por padrão** (não há necessidade de `-skip_initial_server_sync`).
- O `T` ideal é **dependente do target**; trocar depois que o worker encontrou a maior parte da cobertura “easy” tende a funcionar melhor.

## Snapshot Fuzzing Para Targets Difíceis de Harness

Quando o código que você quer testar só se torna acessível **depois de um grande custo de setup** (booting de uma VM, concluir um login, receber um packet, parsear um container, inicializar um serviço), uma alternativa útil é **snapshot fuzzing**:

1. Execute o target até que o estado interessante esteja pronto.
2. Faça snapshot de **memory + registers** nesse ponto.
3. Para cada test case, escreva a entrada mutada diretamente no buffer relevante do guest/process.
4. Execute até crash/timeout/reset.
5. Restaure apenas as **dirty pages** e repita.

Isso evita pagar o custo total de setup a cada iteração e é especialmente útil para **network services**, **firmware**, **post-auth attack surfaces**, e **binary-only targets** que são difíceis de refatorar para um harness clássico in-process.

Um truque prático é interromper imediatamente após um ponto de `recv`/`read`/packet-deserialization, anotar o endereço do buffer de entrada, fazer snapshot ali e então mutar esse buffer diretamente em cada iteração. Isso permite fuzzing da lógica de parsing profunda sem reconstruir todo o handshake toda vez.

## Harness Introspection: Encontre Shallow Fuzzers Cedo

Quando uma campanha trava, o problema muitas vezes não é o mutator, mas o **harness**. Use **reachability/coverage introspection** para encontrar funções que são estaticamente alcançáveis a partir do seu fuzz target, mas raramente ou nunca cobertas dinamicamente. Essas funções normalmente indicam um de três problemas:

- O harness entra no target tarde demais ou cedo demais.
- O seed corpus está sem uma família inteira de features.
- O target realmente precisa de um **second harness** em vez de um único harness “faça tudo” grande demais.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector é útil para esse triagem:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus para uma feature específica ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de Fuzz Target e Triagem de Mutation Baseada em Grafo

Se você já tem **achados de análise estática**, **survivors de mutation-testing** e **relatórios de cobertura**, não faça a triagem como listas independentes. Primeiro, construa um **call graph**, anote os nós com **complexidade ciclomática**, **alcance a partir do entrypoint/input não confiável** e quaisquer achados externos, e então faça perguntas de grafo:

- Quais funções de alta complexidade são alcançáveis a partir de input não confiável?
- Quais survivors de mutation estão em caminhos de parsers/handlers para código crítico de segurança?
- Quais funções são pontos de estrangulamento arquitetural com **blast radius** incomumente alto?

Isso geralmente revela melhores fuzz targets do que apenas “menor coverage”. Um parser/decoder com **alta complexidade** e alcance externo confirmado é um candidato mais forte a harness do que um helper interno isolado com coverage fraco, mas sem caminho controlado por atacante.

### Fluxo prático de triagem

1. Construa um **code graph** a partir da codebase e extraia métricas de complexidade/branch por função.
2. Enumere os **entrypoints** que aceitam input controlado por atacante: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Execute **path queries** desses entrypoints até funções candidatas para separar a superfície de ataque alcançável de código morto/apenas interno.
4. Priorize nós que combinem:
- alta **complexidade ciclomática**
- **alcance confirmado a partir de input não confiável**
- alto **blast radius** ou muitos dependentes downstream
- evidências corroborativas como achados **SARIF**, notas de auditoria ou survivors de mutation
5. Escreva harnesses focados primeiro para os nós com melhor pontuação, especialmente **parsers/codecs** como decoders de hex/Base64/IP/message.

### Survivors de mutation: equivalentes vs acionáveis

Mutation testing frequentemente gera uma lista ruidosa de survivors. Antes de tratar todo survivor como uma lacuna de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um entrypoint controlado por atacante?
- Todos os caminhos de chamada são restringidos por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica apenas de formatação, ou em um caminho de alto impacto de aritmética/parser?

Survivors que permanecem inalcançáveis ou estruturalmente restringidos são frequentemente **equivalent mutants**. Survivors que permanecem **alcançáveis** e atingem **boundary conditions**, **overflow/carry paths** ou aritmética/parsing crítico para segurança devem ser promovidos para:

- novos fuzz harnesses
- testes diretos de propriedades/invariantes
- vetores direcionados de edge cases

### Correlacione achados externos no grafo

Se seu pipeline de SAST exporta **SARIF**, projete os achados nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para expandir o impacto:

- compute o **blast radius** da função sinalizada
- verifique se o achado está em algum caminho a partir de um entrypoint
- agrupe achados próximos que convergem para o mesmo ponto de estrangulamento

Isso é útil ao decidir se vale gastar tempo de fuzzing em uma função específica: um nó que é **alcançável**, **complexo** e já tem **SAST hits** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho de atacante.

Exemplo de fluxo de trabalho com Trailmark:
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
A metodologia importante é a interseção: **complexity x exposure x impact**. Use o gráfico para escolher fuzz targets com o maior valor de segurança esperado, depois use mutation survivors para decidir quais boundaries e invariants seu harness deve stressar.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Se um target em Go já tem um harness nativo `testing.F`, um caminho prático de upgrade é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), uma toolchain Go forked que mantém `go test -fuzz` mas troca o backend para **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Isso é útil quando o fuzzer nativo do Go trava em **comparações difíceis**, **inputs tipados** ou **formatos com muito parser**. A metodologia continua a mesma:

- Continue usando `f.Add(...)` para seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com scheduling/mutation do LibAFL e melhores detectores ao redor.

### Transforme falhas silenciosas em findings de fuzzing

Um problema recorrente em assessments de Go é que comportamentos perigosos muitas vezes **não** crasham por padrão. Com gosentry, você pode promover várias classes de estados “ruins, mas silenciosos” em findings:

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/error se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram e continuam).
- `--catch-races=true` para repetir entradas recém-descobertas da queue com o detector de race do Go.
- `--catch-leaks=true` para repetir novas entradas da queue com `goleak` e parar em leaks de goroutine.
- Tratamento de hang do LibAFL para manter **loops infinitos / inputs muito lentos** como findings de fuzzing em vez de deixá-los desaparecer como timeouts.
- Checks integrados de overflow aritmético por padrão, além de checks opcionais de truncation via instrumentação no estilo go-panikint.

Isso é especialmente valioso para alvos em que o impacto de segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **hang de DoS-only**, em vez de corrupção de memória.

### Fuzzing ciente de struct para APIs Go tipadas

O fuzzing nativo do Go espera principalmente escalares como `[]byte`, `string` e números. Se o código sob teste consome objetos tipados, o gosentry pode fuzzar **valores compostos** diretamente (structs, slices, arrays, pointers) enquanto ainda muta bytes por baixo.
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
Use isso ao construir um wire format falso apenas para fuzzing, pois isso esconderia bugs de lógica atrás de código de parsing apenas do harness. Para campanhas differential ou baseadas em grammar, mantenha a input do harness como um único `[]byte` ou `string` e faça o parsing dentro da callback em vez disso.

### Grammar-based fuzzing para parsers e protocol inputs

Para parsers, formatos e input languages, gosentry pode executar **Nautilus grammar fuzzing** em cima de LibAFL. A grammar é um JSON array de production rules, e o harness normalmente deve receber um único argumento `[]byte` ou `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodologia:

- Use o modo grammar quando mutações em nível de byte morrerem principalmente em verificações iniciais de syntax.
- Mantenha a grammar focada no **subconjunto relevante para security** da language/protocol em vez de modelar a especificação completa.
- Use grandes boundary values em terminais/não terminais para estressar integer, length e edges de state-machine.
- O modo grammar mantém os inputs grammar-valid, mas o target ainda recebe **bytes/strings**, então parsing e semantic checks continuam dentro do código harnessed.

### Differential fuzzing: compare implementations, not just crashes

Um padrão forte para ecossistemas Go é **grammar-based differential fuzzing**: gerar inputs estruturados válidos e enviá-los a dois parsers, clients ou state-transition engines.
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
Trate o seguinte como findings:

- uma implementação entra em panic enquanto a outra rejeita de forma limpa
- incompatibilidades entre input aceito/rejeitado
- diferentes parse trees ou objetos decodificados
- transições de estado, nonces, balances ou state roots divergentes

Esta é uma forma prática de encontrar **consensus mismatches**, **parser ambiguity** e **spec-vs-implementation drift** que o pure crash fuzzing muitas vezes perde.

### Reutilize o corpus da campaign para coverage reporting

Após uma campaign, reexecute o saved queue corpus para gerar um Go coverage report sem exportar manualmente um corpus separado:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Execute o comando a partir do **mesmo package** e com o mesmo alvo `-fuzz` para que o gosentry resolva o estado de campanha em cache correto.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
