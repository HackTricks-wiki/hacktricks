# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing Gramatical Mutacional: Cobertura vs. Semântica

No **fuzzing gramatical mutacional**, os inputs são mutados enquanto permanecem **válidos pela gramática**. No modo guiado por cobertura, apenas samples que disparam **nova cobertura** são salvos como seeds do corpus. Para **targets de linguagem** (parsers, interpreters, engines), isso pode perder bugs que exigem **cadeias semânticas/de fluxo de dados** onde a saída de uma construção se torna a entrada de outra.

**Modo de falha:** o fuzzer encontra seeds que exercem individualmente `document()` e `generate-id()` (ou primitives semelhantes), mas **não preserva o fluxo de dados encadeado**, então o sample “mais perto do bug” é descartado porque não adiciona cobertura. Com **3+ passos dependentes**, a recombinação aleatória se torna cara e o feedback de cobertura não guia a busca.

**Implicação:** para grammars com muitas dependências, considere **hibridizar fases mutacionais e generativas** ou enviesar a geração em direção a padrões de **encadeamento de funções** (não apenas cobertura).

## Armadilhas de Diversidade do Corpus

A mutação guiada por cobertura é **gananciosa**: um sample com nova cobertura é salvo imediatamente, muitas vezes mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicados** com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil, então um compromisso prático é **minimização ciente da gramática** que **para após um limite mínimo de tokens** (reduza ruído enquanto mantém estrutura ao redor suficiente para continuar amigável à mutação).

Uma regra prática de corpus para fuzzing mutacional é: **prefira um pequeno conjunto de seeds estruturalmente diferentes que maximizem cobertura** em vez de um grande monte de quase duplicados. Na prática, isso geralmente significa:

- Comece com **samples do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do target).
- Destile-os com **minimização de corpus baseada em cobertura** em vez de manter todo sample válido.
- Mantenha seeds **pequenos o suficiente** para que as mutações caiam em campos significativos, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após mudanças grandes no harness/instrumentation, porque o corpus “melhor” muda quando a alcançabilidade muda.

## Mutação Ciente de Comparações Para Magic Values

Uma razão comum para fuzzers estagnarem não é sintaxe, mas **comparações difíceis**: magic bytes, checks de comprimento, strings de enum, checksums, ou valores de dispatch do parser protegidos por `memcmp`, tabelas de switch ou comparações em cascata. Mutação aleatória pura desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses targets, use **comparison tracing** (por exemplo, fluxos de trabalho no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar operandos de comparações falhadas e enviesar mutações em direção a valores que as satisfaçam.
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

- Isso é especialmente útil quando o target coloca lógica profunda atrás de **file signatures**, **protocol verbs**, **type tags** ou **version-dependent feature bits**.
- Combine isso com **dictionaries** extraídos de samples reais, especificações de protocolo ou debug logs. Um pequeno dictionary com grammar tokens, chunk names, verbs e delimiters costuma ser muito mais valioso do que uma enorme wordlist genérica.
- Se o target executa muitas verificações sequenciais, resolva primeiro as comparações “magic” mais iniciais e depois minimize novamente o corpus resultante, para que as etapas posteriores comecem a partir de prefixes já válidos.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** e **multi-stage parsers**, a unidade interessante muitas vezes não é um único blob, mas uma **message sequence**. Concatenar todo o transcript em um único arquivo e mutá-lo cegamente costuma ser ineficiente porque o fuzzer muta cada passo igualmente, mesmo quando só a mensagem posterior alcança o estado frágil.

Um padrão mais eficaz é tratar a **sequence em si como a seed** e usar **observable state** (response codes, protocol states, parser phases, returned object types) como feedback adicional:

- Mantenha as **valid prefix messages** estáveis e concentre as mutações na mensagem que **impulsiona a transição**.
- Faça cache de identificadores e valores gerados pelo servidor a partir de respostas anteriores quando a próxima etapa depender deles.
- Prefira mutação/splicing por mensagem em vez de mutar todo o transcript serializado como um blob opaco.
- Se o protocol expõe response codes significativos, use-os como um **cheap state oracle** para priorizar sequences que avançam mais profundamente.

Essa é a mesma razão pela qual bugs autenticados, transições ocultas ou bugs de parser “only-after-handshake” muitas vezes são perdidos pelo file-style fuzzing vanilla: o fuzzer precisa preservar **ordem, state e dependencies**, não apenas a estrutura.

## Single-Machine Diversity Trick (Jackalope-Style)

Uma forma prática de hibridizar **generative novelty** com **coverage reuse** é **reiniciar workers de curta duração** contra um persistent server. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos no corpus combinado, sincroniza novamente e então encerra. Isso produz **fresh structures a cada geração** enquanto ainda aproveita a cobertura acumulada.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (example loop):**

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
- `-server_update_interval T` aproxima **sincronização atrasada** (novidade primeiro, reuso depois).
- No modo de grammar fuzzing, a **sincronização inicial com o server é ignorada por padrão** (não é საჭირო usar `-skip_initial_server_sync`).
- O `T` ideal é **dependente do target**; mudar depois que o worker encontrou a maior parte da cobertura “fácil” tende a funcionar melhor.

## Snapshot Fuzzing Para Targets Difíceis de Harness

Quando o código que você quer testar só se torna alcançável **depois de um grande custo de setup** (iniciar uma VM, concluir um login, receber um packet, fazer parsing de um container, inicializar um service), uma alternativa útil é **snapshot fuzzing**:

1. Execute o target até o estado interessante estar pronto.
2. Faça snapshot de **memory + registers** nesse ponto.
3. Para cada test case, escreva o input mutado diretamente no buffer relevante do guest/process.
4. Execute até crash/timeout/reset.
5. Restaure apenas as **dirty pages** e repita.

Isso evita pagar o custo total de setup a cada iteração e é especialmente útil para **network services**, **firmware**, **post-auth attack surfaces** e **binary-only targets** que são dolorosos de refatorar para um harness clássico in-process.

Um truque prático é quebrar imediatamente após um ponto de `recv`/`read`/deserialização de packet, anotar o endereço do buffer de input, fazer snapshot ali e então mutar esse buffer diretamente em cada iteração. Isso permite que você faça fuzzing da lógica profunda de parsing sem reconstruir todo o handshake a cada vez.

## Harness Introspection: Encontre Shallow Fuzzers Cedo

Quando uma campanha estagna, o problema muitas vezes não é o mutator, mas o **harness**. Use **reachability/coverage introspection** para encontrar funções que são estaticamente alcançáveis a partir do seu fuzz target, mas raramente ou nunca cobertas dinamicamente. Essas funções geralmente indicam um de três problemas:

- O harness entra no target tarde demais ou cedo demais.
- O seed corpus está sem uma família inteira de features.
- O target realmente precisa de um **segundo harness** em vez de um harness gigante de “faça tudo”.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector é útil para esse triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus para um recurso específico ou dividir um harness monolítico em pontos de entrada menores.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
