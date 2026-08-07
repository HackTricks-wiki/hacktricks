# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Em **mutational grammar fuzzing**, as entradas são modificadas enquanto permanecem **válidas segundo a gramática**. No modo guiado por coverage, apenas as amostras que acionam **nova coverage** são salvas como seeds do corpus. Para **language targets** (parsers, interpreters, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/de dataflow**, nas quais a saída de um constructo se torna a entrada de outro.

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitives semelhantes), mas **não preserva o dataflow encadeado**, então a amostra “mais próxima do bug” é descartada porque não adiciona coverage. Com **3+ etapas dependentes**, a recombinação aleatória se torna cara e o feedback de coverage não orienta a busca.

**Implicação:** para grammars com muitas dependências, considere **hibridizar fases mutacionais e generativas** ou direcionar a geração para padrões de **function chaining** (não apenas coverage).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por coverage é **greedy**: uma amostra com nova coverage é salva imediatamente, geralmente mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **near-duplicates** com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil, portanto um compromisso prático é a **minimização grammar-aware**, que **para após um limite mínimo de tokens** (reduzindo o ruído enquanto mantém estrutura circundante suficiente para continuar favorável à mutação).<sup>[[1]](#references)</sup>

Uma regra prática para o corpus em mutational fuzzing é: **preferir um pequeno conjunto de seeds estruturalmente diferentes que maximize a coverage** a uma grande coleção de near-duplicates. Na prática, isso geralmente significa:<sup>[[1]](#references)</sup>

- Começar com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do target).
- Destilá-las com **minimização de corpus baseada em coverage**, em vez de manter todas as amostras válidas.
- Manter as seeds **pequenas o suficiente** para que as mutações atinjam campos significativos, em vez de gastar a maioria dos ciclos em bytes irrelevantes.
- Executar novamente a minimização do corpus após grandes alterações no harness/instrumentation, pois o corpus “melhor” muda quando a reachability muda.

## Mutação Consciente de Comparações Para Magic Values

Um motivo comum para os fuzzers estagnarem não é a sintaxe, mas as **comparações rígidas**: magic bytes, verificações de tamanho, strings de enum, checksums ou valores de dispatch do parser protegidos por `memcmp`, switch tables ou comparações encadeadas. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses targets, use **comparison tracing** (por exemplo, workflows no estilo AFL++ `CMPLOG` / Redqueen) para que o fuzzer possa observar os operandos das comparações que falharam e direcionar as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>
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

- Isso é especialmente útil quando o alvo bloqueia lógica profunda por trás de **assinaturas de arquivo**, **verbos de protocolo**, **type tags** ou **feature bits** dependentes da versão.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de debug. Um dicionário pequeno com tokens de gramática, nomes de chunks, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo realizar muitas verificações sequenciais, resolva primeiro as comparações “magic” mais iniciais e depois minimize o corpus resultante novamente, para que os estágios posteriores comecem a partir de prefixos já válidos.

## Stateful Fuzzing: Sequências são Seeds

Para **protocolos**, **workflows autenticados** e **parsers em múltiplos estágios**, a unidade interessante geralmente não é um blob isolado, mas uma **sequência de mensagens**. Concatenar todo o transcript em um único arquivo e mutá-lo cegamente costuma ser ineficiente, pois o fuzzer modifica cada etapa igualmente, mesmo quando apenas a mensagem posterior alcança o estado frágil.

Um padrão mais eficaz é tratar a **própria sequência como a seed** e usar o **estado observável** (códigos de resposta, estados do protocolo, fases do parser, tipos de objetos retornados) como feedback adicional:<sup>[[4]](#references)</sup>

- Mantenha estáveis as **mensagens de prefixo válidas** e concentre as mutações na mensagem que **conduz a transição**.
- Armazene em cache os identificadores e valores gerados pelo servidor nas respostas anteriores quando a próxima etapa depender deles.
- Prefira mutação/splicing por mensagem em vez de mutar todo o transcript serializado como um blob opaco.
- Se o protocolo expuser códigos de resposta relevantes, use-os como um **state oracle barato** para priorizar sequências que avancem mais profundamente.

Essa é a mesma razão pela qual bugs autenticados, transições ocultas ou bugs de parser “somente após o handshake” costumam não ser encontrados por fuzzing vanilla no estilo de arquivo: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.

## Single-Machine Diversity Trick (Jackalope-Style)

Uma forma prática de combinar **novidade generativa** com **reutilização de coverage** é **reiniciar workers de curta duração** contra um servidor persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos usando o corpus combinado, sincroniza novamente e então encerra. Isso produz **estruturas novas a cada geração** e, ao mesmo tempo, aproveita a coverage acumulada.<sup>[[2]](#references)</sup>

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

- `-in empty` força um **fresh corpus** a cada geração.
- `-server_update_interval T` aproxima uma **delayed sync** (novidade primeiro, reutilização depois).
- No modo de grammar fuzzing, a **initial server sync** é ignorada por padrão (não é necessário usar `-skip_initial_server_sync`).
- O valor ideal de `T` **depende do alvo**; mudar depois que o worker encontrar a maior parte da coverage “fácil” tende a funcionar melhor.

## Snapshot Fuzzing Para Alvos Difíceis de Instrumentar

Quando o código que você quer testar só se torna alcançável **após um grande custo de configuração** (inicializar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é o **snapshot fuzzing**:

1. Execute o alvo até que o estado interessante esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada modificada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer um crash/timeout/reset.
5. Restaure apenas as **páginas modificadas** e repita.

Isso evita pagar o custo total de configuração a cada iteração e é especialmente útil para **network services**, **firmware**, **post-auth attack surfaces** e alvos **binários** que são difíceis de refatorar em um harness clássico in-process.

Um truque prático é interromper imediatamente após um ponto de `recv`/`read`/desserialização de pacote, anotar o endereço do buffer de entrada, fazer um snapshot nesse ponto e, então, modificar esse buffer diretamente em cada iteração. Isso permite fazer fuzzing da lógica de parsing profunda sem reconstruir todo o handshake a cada vez.

## Harness Introspection: Encontre Fuzzers Superficiais Cedo

Quando uma campanha fica estagnada, o problema geralmente não está no mutator, mas no **harness**. Use **reachability/coverage introspection** para encontrar funções que são estaticamente alcançáveis a partir do seu alvo de fuzzing, mas que raramente ou nunca são cobertas dinamicamente. Essas funções normalmente indicam um dos três problemas:

- O harness entra no alvo tarde ou cedo demais.
- O seed corpus não contém uma família inteira de funcionalidades.
- O alvo realmente precisa de um **segundo harness**, em vez de um único harness “faz tudo” grande demais.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector é útil para essa triagem:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus de um recurso específico ou dividir um harness monolítico em entry points menores.

## Seleção de alvos de Fuzz orientada primeiro por grafos e triagem de mutações

Se você já possui **findings de static analysis**, **sobreviventes de mutation testing** e **relatórios de coverage**, não faça a triagem como listas independentes. Primeiro, construa um **call graph**, anote os nós com **complexidade ciclomática**, **alcançabilidade a partir de entrypoints/entradas não confiáveis** e quaisquer findings externos; em seguida, faça perguntas sobre o grafo:<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade são alcançáveis a partir de entradas não confiáveis?
- Quais sobreviventes de mutação estão em caminhos entre parsers/handlers e código crítico de segurança?
- Quais funções são choke points arquiteturais com **blast radius** excepcionalmente alto?

Isso geralmente revela alvos de fuzzing melhores do que considerar apenas a "menor coverage". Um parser/decoder com **alta complexidade** e **alcançabilidade externa** confirmada é um candidato mais forte a harness do que um helper interno isolado com coverage fraca, mas sem um caminho controlado pelo atacante.

### Fluxo prático de triagem

1. Construa um **code graph** a partir da codebase e extraia métricas de complexidade/branches por função.
2. Enumere os **entrypoints** que aceitam entradas controladas pelo atacante: request handlers, decoders, importers, protocol parsers, leitores de CLI/arquivos.
3. Execute **path queries** desses entrypoints até as funções candidatas para separar a attack surface alcançável do código morto ou exclusivamente interno.
4. Priorize os nós que combinam:
- alta **complexidade ciclomática**
- **alcançabilidade confirmada a partir de entradas não confiáveis**
- alto **blast radius** ou muitos dependentes downstream
- evidências corroborantes, como findings de **SARIF**, notas de auditoria ou sobreviventes de mutação
5. Escreva harnesses focados para os nós com melhor pontuação primeiro, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/message.

### Sobreviventes de mutação: equivalentes vs. acionáveis

O mutation testing frequentemente produz uma lista ruidosa de sobreviventes. Antes de tratar cada sobrevivente como uma falha de segurança, use o grafo para perguntar:

- A função mutada é alcançável a partir de um entrypoint controlado pelo atacante?
- Todos os caminhos de chamada são restringidos por invariants mais fortes do que a verificação mutada?
- O nó está em código morto, lógica relacionada apenas à formatação ou em um caminho de arithmetic/parser de alto impacto?

Sobreviventes que permanecem inalcançáveis ou estruturalmente restringidos são frequentemente **mutantes equivalentes**. Sobreviventes que continuam **alcançáveis** e afetam **boundary conditions**, **caminhos de overflow/carry** ou **arithmetic/parsing crítico para a segurança** devem ser promovidos a:

- novos fuzz harnesses
- testes diretos de propriedades/invariants
- vetores direcionados para edge cases

### Correlacione findings externos ao grafo

Se o pipeline de SAST exporta **SARIF**, projete os findings nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para expandir o impacto:

- calcule o **blast radius** da função sinalizada
- verifique se o finding está em algum caminho a partir de um entrypoint
- agrupe findings próximos que convergem para o mesmo choke point

Isso é útil ao decidir se vale a pena investir tempo de fuzzing em uma função específica: um nó que seja **alcançável**, **complexo** e que já possua **achados de SAST** geralmente é um alvo melhor do que um nó meramente complexo sem caminho de ataque.

Exemplo de fluxo de trabalho com Trailmark:<sup>[[6]](#references)</sup>
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
A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher os alvos de fuzzing com o maior valor esperado de segurança e, em seguida, use os sobreviventes das mutações para decidir quais limites e invariantes seu harness deve testar intensivamente.

## Fuzzing em Go com gosentry: mecanismo mais forte, entradas tipadas e verificações diferenciais

Se um alvo Go já possui um harness nativo `testing.F`, um caminho prático de upgrade é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), uma toolchain Go bifurcada que mantém `go test -fuzz`, mas troca o backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Isso é útil quando o fuzzer nativo do Go trava em **hard comparisons**, **typed inputs** ou **parser-heavy formats**. A metodologia permanece a mesma:

- Continue usando `f.Add(...)` para seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez da toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com scheduling/mutation do LibAFL e melhores detectores auxiliares.

### Transforme falhas silenciosas em descobertas de fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos frequentemente **não** causam crash por padrão. Com o gosentry, você pode transformar várias classes de estados “ruins, mas silenciosos” em descobertas:

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram o erro e continuam).
- `--catch-races=true` para reproduzir novas entradas descobertas da queue com o race detector do Go.
- `--catch-leaks=true` para reproduzir novas entradas da queue com `goleak` e interromper a execução ao detectar vazamentos de goroutines.
- O tratamento de hangs do LibAFL para manter **loops infinitos / inputs muito lentos** como descobertas de fuzzing, em vez de permitir que desapareçam como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para targets cujo impacto de segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **hang que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing consciente de structs para APIs Go tipadas

O fuzzing nativo do Go espera principalmente scalars, como `[]byte`, `string` e números. Se o código em teste consumir objetos tipados, o gosentry poderá aplicar fuzzing diretamente em **valores compostos** (structs, slices, arrays, pointers), continuando a mutar os bytes subjacentes.
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
Use isso ao criar um wire format falso apenas para fuzzing, pois isso ocultaria bugs de lógica por trás de um código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolos

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **Nautilus grammar fuzzing** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve aceitar um único argumento `[]byte` ou `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodologia:

- Use grammar mode quando as mutações em nível de byte morrerem principalmente nas verificações iniciais de sintaxe.
- Mantenha a gramática focada no **subconjunto relevante para a segurança** da linguagem/protocolo, em vez de modelar toda a especificação.
- Use valores de limite grandes em terminais/não terminais para testar limites de inteiros, comprimentos e máquinas de estado.
- O grammar mode mantém as entradas válidas de acordo com a gramática, mas o alvo ainda recebe **bytes/strings**, portanto a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: compare implementações, não apenas crashes

Um padrão forte para ecossistemas Go é o **grammar-based differential fuzzing**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou engines de transição de estado.
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

- uma implementação entra em panic enquanto a outra rejeita corretamente
- incompatibilidades entre entradas aceitas/rejeitadas
- árvores de análise ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Essa é uma maneira prática de encontrar **incompatibilidades de consenso**, **ambiguidade de parser** e **divergências entre especificação e implementação** que o fuzzing focado apenas em crashes geralmente não detecta.

### Reutilize o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da fila salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Execute o comando a partir do **mesmo pacote** e com o mesmo destino `-fuzz` para que o gosentry resolva o estado correto da campanha armazenado em cache.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
