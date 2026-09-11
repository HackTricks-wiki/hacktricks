# Metodologia de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Coverage vs. Semântica

No **fuzzing de gramática mutacional**, as entradas são modificadas enquanto permanecem **válidas de acordo com a gramática**. No modo guiado por coverage, apenas as amostras que acionam **nova coverage** são salvas como seeds do corpus. Para **targets de linguagem** (parsers, interpretadores, engines), isso pode deixar passar bugs que exigem **cadeias semânticas/dataflow**, nas quais a saída de um constructo se torna a entrada de outro.<sup>[[1]](#references)</sup>

**Modo de falha:** o fuzzer encontra seeds que exercitam individualmente `document()` e `generate-id()` (ou primitivas semelhantes), mas **não preserva o dataflow encadeado**, então a amostra “mais próxima do bug” é descartada porque não adiciona coverage. Com **3 ou mais etapas dependentes**, a recombinação aleatória se torna cara, e o feedback de coverage não orienta a busca.<sup>[[1]](#references)</sup>

**Implicação:** para grammars com muitas dependências, considere **hibridizar fases mutacionais e generativas** ou direcionar a geração para padrões de **function chaining** (não apenas para coverage).<sup>[[1]](#references)</sup>

## Armadilhas da Diversidade do Corpus

A mutação guiada por coverage é **greedy**: uma amostra com nova coverage é salva imediatamente, geralmente mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **quase duplicatas**, com baixa diversidade estrutural. A minimização agressiva pode remover contexto útil, portanto um compromisso prático é a **minimização ciente da grammar**, que **para após atingir um limite mínimo de tokens** (reduzindo o ruído e mantendo estrutura circundante suficiente para continuar favorável à mutação).<sup>[[1]](#references)</sup>

Uma regra prática de corpus para fuzzing mutacional é: **preferir um pequeno conjunto de seeds estruturalmente diferentes que maximize a coverage** a uma grande quantidade de quase duplicatas. Na prática, isso geralmente significa o seguinte.<sup>[[1]](#references)[[3]](#references)</sup>

- Comece com **amostras do mundo real** (corpora públicos, crawling, tráfego capturado, conjuntos de arquivos do ecossistema do target).
- Destile-as usando **minimização de corpus baseada em coverage**, em vez de manter todas as amostras válidas.
- Mantenha as seeds **pequenas o suficiente** para que as mutações atinjam campos significativos, em vez de gastar a maior parte dos ciclos em bytes irrelevantes.
- Execute novamente a minimização do corpus após mudanças importantes no harness/instrumentation, pois o corpus “melhor” muda quando a reachability muda.

## Mutação Ciente de Comparações Para Valores Mágicos

Um motivo comum para os fuzzers atingirem um plateau não é a sintaxe, mas **comparações rígidas**: magic bytes, verificações de comprimento, strings de enum, checksums ou valores de dispatch do parser protegidos por `memcmp`, tabelas switch ou comparações encadeadas. A mutação puramente aleatória desperdiça ciclos tentando adivinhar esses valores byte a byte.

Para esses targets, use **comparison tracing** (por exemplo, workflows no estilo `CMPLOG` / Redqueen do AFL++) para que o fuzzer possa observar os operandos das comparações que falharam e direcionar as mutações para valores que as satisfaçam.<sup>[[3]](#references)</sup>
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

- Isso é especialmente útil quando o alvo oculta lógica profunda atrás de **assinaturas de arquivo**, **verbos de protocolo**, **tags de tipo** ou **feature bits dependentes da versão**.
- Combine isso com **dicionários** extraídos de amostras reais, especificações de protocolo ou logs de debug. Um dicionário pequeno com tokens de gramática, nomes de chunks, verbos e delimitadores costuma ser mais valioso do que uma wordlist genérica enorme.
- Se o alvo executar muitas verificações sequenciais, resolva primeiro as comparações “mágicas” mais iniciais e depois minimize o corpus resultante novamente, para que os estágios posteriores comecem com prefixos já válidos.

## Feedback Mais Rico Quando a Cobertura de Edges Colapsa Caminhos Diferentes

A cobertura normal de edges não consegue distinguir duas execuções que percorrem o mesmo helper por meio de callers diferentes ou que seguem combinações de branches diferentes dentro de uma função. Isso é importante em decoders compartilhados, dispatchers de protocolo e helpers de interpretadores, nos quais a **rota** até um edge determina o estado ativo. Rastrear ingenuamente todo contexto de chamada também é perigoso: o mapa de cobertura e a queue podem explodir. Por isso, pesquisas sobre fuzzing sensível ao contexto recomendam refinar apenas os contextos promissores, em vez de tratar todo o call graph como sensível ao contexto.<sup>[[14]](#references)</sup>

Builds recentes do AFL++ fornecem **Ball-Larus per-function path coverage**, além da cobertura normal de edges. Esse recurso atribui uma feature a cada caminho acíclico através de uma função; as loop back-edges são removidas, portanto esse feedback distingue combinações de branches, mas **não as contagens de iterações dos loops**. Comece com o nível relaxado `1` e, depois, restrinja os modos mais rigorosos ao código suspeito de parsers/state machines, pois o número de caminhos pode crescer exponencialmente.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Para um helper chamado a partir de muitos pontos relevantes para a segurança, o modo LTO pode combinar cada caminho de função com seu ponto de chamada imediato:<sup>[[13]](#references)</sup>
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
**Orientação da campanha:** aplique feedback mais rico com cautela e monitore o custo no coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Execute uma instância comum de edge-coverage em paralelo; o feedback mais rico só é útil se o custo adicional de queue/map não destruir o número de execuções por segundo.
- Use `AFL_LLVM_ALLOWLIST` para restringir a instrumentação de path/caller quando bibliotecas grandes e repletas de templates ou código utilitário genérico dominarem o map.
- Funções com caminhos acíclicos excessivos podem ser ignoradas pelo AFL++; warnings durante a compilação indicam que o target precisa de allowlisting ou de um nível menos estrito.
- Caller + path coverage oferece suporte a apenas uma profundidade de caller. Não combine isso com context stacks mais profundos.
- Os IDs de path podem mudar entre versões principais do LLVM. Mantenha o toolchain fixo durante uma campanha e não sincronize corpora baseados em PATH como se seus feature IDs fossem estáveis entre builds.
- Esse feedback complementa o `CMPLOG`: o rastreamento de comparações resolve **qual valor passa por um guard**, enquanto o feedback de path/caller preserva **qual rota e combinação de branches o alcançaram**.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** e **multi-stage parsers**, a unidade interessante geralmente não é um único blob, mas uma **message sequence**. Concatenar toda a transcrição em um único arquivo e mutá-la cegamente costuma ser ineficiente, pois o fuzzer muta cada etapa igualmente, mesmo quando apenas a mensagem posterior alcança o estado frágil.<sup>[[4]](#references)</sup>

Um padrão mais eficaz é tratar a **sequence em si como o seed** e usar o **estado observável** (response codes, protocol states, parser phases, returned object types) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantenha **valid prefix messages** estáveis e concentre as mutações na mensagem que **conduz a transição**.
- Armazene em cache os identificadores e valores gerados pelo server nas respostas anteriores quando a próxima etapa depender deles.
- Prefira mutação/splicing por mensagem em vez de mutar toda a transcript serializada como um blob opaco.
- Se o protocol expuser response codes significativos, use-os como uma **state oracle barata** para priorizar sequences que avancem mais profundamente.

Essa é a mesma razão pela qual authenticated bugs, hidden transitions ou parser bugs que ocorrem “only-after-handshake” frequentemente não são encontrados pelo fuzzing vanilla no estilo de arquivos: o fuzzer precisa preservar **ordem, estado e dependências**, não apenas a estrutura.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Uma forma prática de combinar **novidade generativa** com **reutilização de coverage** é **reiniciar workers de curta duração** contra um server persistente. Cada worker começa com um corpus vazio, sincroniza após `T` segundos, executa por mais `T` segundos usando o corpus combinado, sincroniza novamente e então encerra. Isso produz **estruturas novas a cada geração**, enquanto ainda aproveita a coverage acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` aproxima-se de uma **delayed sync** (novidade primeiro, reutilização depois).
- No modo de grammar fuzzing, a **initial server sync** é ignorada por padrão (não é necessário usar `-skip_initial_server_sync`).
- O `T` ideal depende do **target**; alternar depois que o worker encontrar a maior parte da cobertura “fácil” tende a funcionar melhor.

## Snapshot Fuzzing Para Targets Difíceis de Instrumentar

Quando o código que você quer testar só se torna acessível **após um grande custo de configuração** (inicializar uma VM, concluir um login, receber um pacote, analisar um container, inicializar um serviço), uma alternativa útil é o **snapshot fuzzing**: capture o estado do processo ou da VM pronto, injete cada caso de teste no caminho de entrada do target, execute até ocorrer um crash/timeout e restaure o snapshot. Isso evita repetir a inicialização ou os prefixos do protocolo e é útil para **serviços de rede**, **firmware**, **superfícies de ataque pós-autenticação** e **targets somente binários**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Execute o target até que o estado relevante esteja pronto.
2. Faça um snapshot da **memória + registradores** nesse ponto.
3. Para cada caso de teste, escreva a entrada modificada diretamente no buffer relevante do guest/processo.
4. Execute até ocorrer crash/timeout/reset.
5. Restaure o snapshot; para targets de VM, restaure somente as **páginas sujas** quando houver suporte e repita.

Posicione o snapshot o mais próximo possível da primeira etapa dispendiosa de análise/dispatch, como após um ponto de `recv`/`read` ou de desserialização de pacotes, e registre o buffer de entrada usado pelo target. Isso segue o princípio de posicionamento adaptativo de mover o snapshot para mais perto do processamento da entrada, evitando repetir trabalho.<sup>[[11]](#references)</sup>

## Introspecção do Harness: Encontre Fuzzers Superficiais Cedo

Quando uma campanha trava, o problema geralmente não está no mutator, mas no **harness**. Use a **introspecção de reachability/cobertura** para encontrar funções que são estaticamente alcançáveis a partir do seu fuzz target, mas que raramente ou nunca são cobertas dinamicamente. Essas funções geralmente indicam um destes três problemas.<sup>[[12]](#references)</sup>

- O harness entra no target tarde ou cedo demais.
- O seed corpus não contém uma família inteira de funcionalidades.
- O target realmente precisa de um **segundo harness**, em vez de um harness “faz tudo” grande demais.

Se você usa workflows no estilo OSS-Fuzz / ClusterFuzz, o Fuzz Introspector pode comparar a reachability estática com a cobertura em runtime e gerar relatórios a partir de uma execução temporizada ou de um corpus público.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use o relatório para decidir se deve adicionar um novo harness para um caminho de parser não testado, expandir o corpus para um recurso específico ou dividir um harness monolítico em entry points menores.

## Seleção de Fuzz Targets com Prioridade no Grafo e Triagem de Mutações

Se você já possui **findings de static analysis**, **mutation-testing survivors** e **relatórios de coverage**, não os faça triagem como listas independentes. Construa primeiro um **call graph**, anote os nós com **complexidade ciclomática**, **reachability a partir de entrypoints/untrusted input** e quaisquer findings externos, e então faça perguntas sobre o grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quais funções de alta complexidade são alcançáveis a partir de untrusted input?
- Quais mutation survivors estão em caminhos de parsers/handlers até código security-critical?
- Quais funções são choke points arquiteturais com **blast radius** excepcionalmente alto?

Isso geralmente revela fuzz targets melhores do que considerar apenas a "menor coverage". Um parser/decoder com **alta complexidade** e **external reachability confirmada** é um candidato a harness mais forte do que um helper interno isolado com coverage fraca, mas sem um caminho controlado pelo atacante.

### Fluxo prático de triagem

1. Construa um **code graph** a partir do codebase e extraia métricas de complexidade/branches por função.
2. Enumere os **entrypoints** que aceitam input controlado pelo atacante: request handlers, decoders, importers, protocol parsers, leitores de CLI/arquivos.
3. Execute **path queries** desses entrypoints até as funções candidatas para separar a attack surface alcançável do código morto/visível apenas internamente.
4. Priorize os nós que combinam:
- alta **complexidade ciclomática**
- **reachability confirmada a partir de untrusted input**
- **blast radius** alto ou muitos dependents downstream
- evidências corroborantes, como findings de **SARIF**, notas de auditoria ou mutation survivors
5. Escreva harnesses focados primeiro para os nós com melhor pontuação, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensagens.

### Mutation survivors: equivalentes vs. acionáveis

Mutation testing frequentemente produz uma lista ruidosa de survivors. Antes de tratar cada survivor como uma security gap, use o grafo para perguntar:

- A função mutada é alcançável a partir de um entrypoint controlado pelo atacante?
- Todos os call paths são limitados por invariants mais fortes do que o check mutado?
- O nó está em código morto, lógica que trata apenas de formatação ou em um caminho de arithmetic/parser de alto impacto?

Survivors que permanecem inalcançáveis ou estruturalmente limitados frequentemente são **equivalent mutants**. Survivors que continuam **alcançáveis** e afetam **boundary conditions**, **caminhos de overflow/carry** ou **arithmetic/parsing security-critical** devem ser promovidos a:

- novos fuzz harnesses
- property/invariant tests diretos
- edge-case vectors direcionados

### Correlacione findings externos no grafo

Se seu pipeline de SAST exporta **SARIF**, projete os findings nos nós do grafo por **arquivo + intervalo de linhas** e use o grafo para expandir o impacto.<sup>[[6]](#references)</sup>

- calcule o **blast radius** da função sinalizada
- verifique se o finding está em algum caminho a partir de um entrypoint
- agrupe findings próximos que convergem para o mesmo choke point

Isso é útil para decidir se vale a pena investir tempo de fuzzing em uma função específica: um nó que é **alcançável**, **complexo** e já possui **SAST hits** costuma ser um alvo melhor do que um nó apenas complexo, sem caminho controlado pelo atacante.

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
A metodologia importante é a interseção: **complexidade x exposição x impacto**. Use o gráfico para escolher os alvos de fuzzing com o maior valor de segurança esperado e, em seguida, use os sobreviventes das mutações para decidir quais limites e invariantes seu harness deve testar.<sup>[[5]](#references)</sup>

## Fuzzing em Go com gosentry: Engine mais forte, entradas tipadas e verificações diferenciais

Se um alvo em Go já tem um harness nativo `testing.F`, um caminho prático de upgrade é executar o mesmo harness com [gosentry](https://github.com/trailofbits/gosentry), uma toolchain Go bifurcada que mantém `go test -fuzz`, mas troca o backend para **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Isso é útil quando o fuzzer nativo do Go trava em **comparações difíceis**, **entradas tipadas** ou **formatos pesados em parsers**. A metodologia permanece a mesma:

- Continue usando `f.Add(...)` para seeds e `f.Fuzz(...)` para o callback.
- Reutilize o mesmo harness, mas execute-o com o binário `go` do gosentry em vez do toolchain padrão.
- Trate a campanha resultante como uma execução normal guiada por cobertura, mas com agendamento/mutação do LibAFL e melhores detectores auxiliares.

### Transforme falhas silenciosas em descobertas de fuzzing

Um problema recorrente em avaliações de Go é que comportamentos perigosos frequentemente **não** causam crash por padrão. Com o gosentry, você pode promover várias classes de estados “ruins, mas silenciosos” a descobertas.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para fazer com que caminhos selecionados de logging/erro se comportem como crashes (útil para caminhos de código no estilo `log.Fatal` que, de outra forma, apenas registram o erro e continuam).
- `--catch-races=true` para reproduzir novas entradas da fila com o detector de race do Go.
- `--catch-leaks=true` para reproduzir novas entradas da fila com o `goleak` e interromper em caso de leaks de goroutines.
- Tratamento de hangs do LibAFL para manter **loops infinitos / entradas muito lentas** como descobertas de fuzzing, em vez de deixá-las desaparecer como timeouts.
- Verificações integradas de overflow aritmético por padrão, além de verificações opcionais de truncamento por meio de instrumentação no estilo go-panikint.

Isso é especialmente valioso para targets nos quais o impacto de segurança é uma **falha de parser sem panic**, um **bug de concorrência** ou um **hang que causa apenas DoS**, em vez de corrupção de memória.

### Fuzzing ciente de structs para APIs tipadas em Go

O fuzzing nativo do Go espera principalmente escalares como `[]byte`, `string` e números. Se o código sob teste consumir objetos tipados, o gosentry poderá aplicar fuzzing diretamente em **valores compostos** (structs, slices, arrays, pointers), enquanto continua mutando os bytes subjacentes.<sup>[[7]](#references)[[8]](#references)</sup>
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
Use isso ao criar um wire format falso apenas para fuzzing, pois isso ocultaria bugs lógicos por trás de um código de parsing exclusivo do harness. Para campanhas diferenciais ou baseadas em gramática, mantenha a entrada do harness como um único `[]byte` ou `string` e faça o parsing dentro do callback.

### Fuzzing baseado em gramática para parsers e entradas de protocolo

Para parsers, formatos e linguagens de entrada, o gosentry pode executar **fuzzing de gramática Nautilus** sobre o LibAFL. A gramática é um array JSON de regras de produção, e o harness geralmente deve aceitar um único argumento `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodologia:

- Use o grammar mode quando as mutações em nível de byte geralmente morrem nas verificações sintáticas iniciais.
- Mantenha a grammar focada no **subconjunto relevante para a segurança** da linguagem/protocolo, em vez de modelar toda a especificação.
- Use valores de limite grandes em terminais/não terminais para estressar os limites de inteiros, comprimentos e máquinas de estado.
- O grammar mode mantém as entradas válidas segundo a gramática, mas o alvo ainda recebe **bytes/strings**, portanto a análise sintática e as verificações semânticas continuam dentro do código instrumentado.

### Differential fuzzing: compare implementações, não apenas crashes

Um padrão forte para ecossistemas Go é o **grammar-based differential fuzzing**: gerar entradas estruturadas válidas e fornecê-las a dois parsers, clientes ou engines de transição de estado.<sup>[[7]](#references)[[8]](#references)</sup>
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

- uma implementação entra em panic enquanto a outra rejeita de forma limpa
- divergências entre inputs aceitos/rejeitados
- árvores de parsing ou objetos decodificados diferentes
- transições de estado, nonces, saldos ou raízes de estado divergentes

Esta é uma forma prática de encontrar **divergências de consenso**, **ambiguidades de parser** e **desvios entre a especificação e a implementação** que o crash fuzzing puro frequentemente não detecta.

### Reutilize o corpus da campanha para gerar relatórios de cobertura

Após uma campanha, reproduza o corpus da queue salvo para gerar um relatório de cobertura do Go sem exportar manualmente um corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Execute o comando a partir do **mesmo pacote** e com o mesmo destino `-fuzz` para que o gosentry resolva o estado correto da campanha em cache.



## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing do AFL++ em profundidade](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco anos depois: sobre fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforma código em grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [O fuzzing do Go não tinha metade do toolkit. Fizemos um fork do toolchain para corrigir isso.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: um fuzzer greybox rápido para protocolos de rede stateful usando snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sem gramática, sem problema: rumo ao fuzzing do kernel Linux sem descrições de chamadas de sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente com snapshots adaptativos e mutáveis](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentação LLVM do AFL++: cobertura de caminhos e de callers](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing preditivo sensível ao contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
