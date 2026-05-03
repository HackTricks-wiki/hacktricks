# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Em **mutational grammar fuzzing**, as entradas são mutadas enquanto permanecem **grammar-valid**. Em modo guiado por cobertura, apenas samples que acionam **new coverage** são salvos como seeds do corpus. Para **language targets** (parsers, interpreters, engines), isso pode deixar passar bugs que exigem **semantic/dataflow chains**, onde a saída de um construct se torna a entrada de outro.

**Failure mode:** o fuzzer encontra seeds que individualmente exercitam `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o chained dataflow**, então o sample “mais próximo do bug” é descartado porque não adiciona coverage. Com **3+ dependent steps**, a recombinação aleatória se torna cara e o feedback de coverage não guia a busca.

**Implication:** para grammars com muita dependência, considere **hybridizing mutational and generative phases** ou enviesar a geração para padrões de **function chaining** (não apenas coverage).

## Corpus Diversity Pitfalls

A mutação guiada por coverage é **greedy**: um sample com new-coverage é salvo imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **near-duplicates** com baixa diversidade estrutural. Minimização agressiva pode remover contexto útil, então um compromisso prático é **grammar-aware minimization** que **para após um minimum token threshold** (reduzir ruído mantendo estrutura suficiente ao redor para continuar amigável à mutação).

Uma regra prática de corpus para mutational fuzzing é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximizem coverage** em vez de uma grande pilha de near-duplicates. Na prática, isso geralmente significa:

- Começar com **real-world samples** (public corpora, crawling, tráfego capturado, conjuntos de arquivos do ecossistema alvo).
- Refiná-los com **coverage-based corpus minimization** em vez de manter todo sample válido.
- Manter seeds **small enough** para que as mutações atinjam campos significativos, em vez de gastar a maioria dos ciclos em bytes irrelevantes.
- Reexecutar a minimização do corpus após grandes mudanças no harness/instrumentation, porque o “melhor” corpus muda quando a reachability muda.

## Comparison-Aware Mutation For Magic Values

Uma razão comum para fuzzers entrarem em platô não é sintaxe, mas **hard comparisons**: magic bytes, length checks, enum strings, checksums ou valores de dispatch do parser protegidos por `memcmp`, switch tables ou cascaded comparisons. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses alvos, use **comparison tracing** (por exemplo, workflows estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar operandos de comparações falhas e enviesar mutações em direção aos valores que as satisfazem.
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

- Isso é especialmente útil quando o alvo coloca lógica profunda atrás de **file signatures**, **protocol verbs**, **type tags** ou **version-dependent feature bits**.
- Combine isso com **dictionaries** extraídos de amostras reais, specs de protocolo ou logs de debug. Um dictionary pequeno com grammar tokens, chunk names, verbs e delimiters costuma ser muito mais valioso do que uma massive generic wordlist.
- Se o alvo realiza muitas checagens sequenciais, resolva primeiro as comparações “magic” iniciais e depois minimize novamente o corpus resultante, para que as etapas posteriores comecem a partir de prefixes já válidos.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** e **multi-stage parsers**, a unidade interessante muitas vezes não é um blob único, mas uma **message sequence**. Concatenar toda a transcript em um único arquivo e mutá-la cegamente costuma ser ineficiente porque o fuzzer muta todas as etapas igualmente, mesmo quando apenas a mensagem posterior alcança o estado frágil.

Um padrão mais eficaz é tratar a **sequence em si como o seed** e usar **observable state** (response codes, protocol states, parser phases, returned object types) como feedback adicional:

- Mantenha **valid prefix messages** estáveis e concentre as mutações na mensagem que **conduz a transição**.
- Faça cache de identifiers e values gerados pelo server a partir de respostas anteriores quando a próxima etapa depender deles.
- Prefira mutation/splicing por mensagem em vez de mutar toda a transcript serializada como um blob opaco.
- Se o protocol expõe response codes significativos, use-os como um **cheap state oracle** para priorizar sequences que avancem mais fundo.

Esse é o mesmo motivo pelo qual bugs autenticados, transições ocultas ou bugs de parser do tipo “only-after-handshake” frequentemente passam despercebidos pelo file-style fuzzing padrão: o fuzzer precisa preservar **ordem, state e dependencies**, não apenas estrutura.

## Single-Machine Diversity Trick (Jackalope-Style)

Uma forma prática de combinar **generative novelty** com **coverage reuse** é **reiniciar workers de curta duração** contra um server persistente. Cada worker começa a partir de um corpus vazio, sincroniza após `T` seconds, executa por mais `T` seconds no corpus combinado, sincroniza novamente e então encerra. Isso produz **fresh structures a cada geração** enquanto ainda aproveita a coverage acumulada.

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

- `-in empty` força um **corpus novo** a cada geração.
- `-server_update_interval T` aproxima **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo de fuzzing com grammar, a **sincronização inicial do servidor é ignorada por padrão** (não há necessidade de `-skip_initial_server_sync`).
- O `T` ideal é **dependente do target**; trocar depois que o worker encontrou a maior parte da cobertura “fácil” tende a funcionar melhor.

## Snapshot Fuzzing Para Targets Difíceis de Harnessar

Quando o código que você quer testar só se torna alcançável **após um grande custo de preparação** (iniciar uma VM, completar um login, receber um pacote, fazer o parsing de um container, inicializar um serviço), uma alternativa útil é **snapshot fuzzing**:

1. Execute o target até que o estado interessante esteja pronto.
2. Tire um snapshot de **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada mutada diretamente no buffer relevante do guest/process.
4. Execute até crash/timeout/reset.
5. Restaure apenas as **dirty pages** e repita.

Isso evita pagar o custo total de preparação a cada iteração e é especialmente útil para **network services**, **firmware**, **post-auth attack surfaces** e **binary-only targets** que são difíceis de refatorar para um harness clássico in-process.

Um truque prático é interromper imediatamente após um ponto de `recv`/`read`/deserialização de pacote, anotar o endereço do buffer de entrada, tirar um snapshot ali e então mutar esse buffer diretamente em cada iteração. Isso permite fuzzing da lógica de parsing profunda sem reconstruir todo o handshake a cada vez.

## Harness Introspection: Encontre Fuzzers Rasos Cedo

Quando uma campanha trava, o problema muitas vezes não é o mutator, mas o **harness**. Use **reachability/coverage introspection** para encontrar funções que são estaticamente alcançáveis a partir do seu fuzz target, mas raramente ou nunca cobertas dinamicamente. Essas funções geralmente indicam um destes três problemas:

- O harness entra no target tarde demais ou cedo demais.
- O seed corpus está sem uma família inteira de features.
- O target realmente precisa de um **segundo harness** em vez de um único harness gigantesco de “fazer tudo”.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector é útil para essa triagem:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus para um recurso específico, ou dividir um harness monolítico em pontos de entrada menores.

## Seleção de alvo de fuzzing e triagem de mutação com foco em grafos

Se você já tem **achados de static-analysis**, **mutation-testing survivors** e **relatórios de cobertura**, não faça a triagem deles como listas independentes. Primeiro, construa um **call graph**, anote os nós com **complexidade ciclomática**, **alcance por entrypoint/untrusted-input**, e quaisquer achados externos, e então faça perguntas ao grafo:

- Quais funções de alta complexidade são alcançáveis a partir de input não confiável?
- Quais mutation survivors ficam em caminhos que vão de parsers/handlers até código security-critical?
- Quais funções são pontos de estrangulamento arquiteturais com um **blast radius** incomumente alto?

Isso normalmente revela melhores alvos de fuzzing do que apenas o “menor coverage”. Um parser/decoder com **alta complexidade** e **alcance externo** confirmado é um candidato de harness mais forte do que um helper interno isolado com coverage fraca, mas sem caminho controlado por attacker.

### Fluxo prático de triagem

1. Construa um **code graph** a partir do codebase e extraia métricas de complexidade/branch por função.
2. Enumere **entrypoints** que aceitam input controlado por attacker: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Execute consultas de **path** a partir desses entrypoints até funções candidatas para separar attack surface alcançável de código morto/somente interno.
4. Priorize nós que combinam:
- alta **complexidade ciclomática**
- **reachability** confirmada a partir de untrusted input
- alto **blast radius** ou muitos dependents downstream
- evidências corroborantes como achados de **SARIF**, notas de auditoria ou mutation survivors
5. Escreva harnesses focados primeiro para os nós com melhor pontuação, especialmente **parsers/codecs** como decoders de hex/Base64/IP/message.

### Mutation survivors: equivalentes vs acionáveis

Mutation testing frequentemente gera uma lista ruidosa de survivors. Antes de tratar todo survivor como uma lacuna de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um entrypoint controlado por attacker?
- Todos os call paths são limitados por invariantes mais fortes do que a verificação mutada?
- O nó está em código morto, lógica apenas de formatação, ou em um caminho aritmético/parser de alto impacto?

Survivors que permanecem inalcançáveis ou estruturalmente limitados são frequentemente **equivalent mutants**. Survivors que continuam **alcançáveis** e tocam **boundary conditions**, caminhos de **overflow/carry**, ou aritmética/parsing security-critical devem ser promovidos para:

- novos fuzz harnesses
- testes diretos de propriedade/invariante
- vetores direcionados de edge-case

### Correlacione achados externos no grafo

Se seu pipeline de SAST exporta **SARIF**, projete os achados nos nós do grafo por **file + line range** e use o grafo para expandir o impacto:

- compute o **blast radius** da função sinalizada
- verifique se o achado está em algum caminho a partir de um entrypoint
- agrupe achados próximos que convergem para o mesmo ponto de estrangulamento

Isso é útil ao decidir se vale gastar tempo de fuzzing em uma função específica: um nó que é **alcançável**, **complexo** e já tem **SAST hits** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho de attacker.

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
A metodologia importante é a interseção: **complexity x exposure x impact**. Use o gráfico para escolher fuzz targets com o maior valor de segurança esperado, depois use mutation survivors para decidir quais boundaries e invariants seu harness deve stress.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
