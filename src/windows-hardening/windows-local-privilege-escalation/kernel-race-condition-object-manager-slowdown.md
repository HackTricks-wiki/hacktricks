# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Por que ampliar a janela de race é importante

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Visão geral interna da resolução do Object Manager

* **Estrutura OMNS** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório a diretório. Cada componente faz o kernel localizar/abrir um *Object Directory* e comparar strings Unicode. Links simbólicos (e.g., letras de unidade) podem ser atravessados no percurso.
* **Limite do UNICODE_STRING** – Caminhos OM são transportados dentro de um `UNICODE_STRING` cujo `Length` é um valor de 16 bits. O limite absoluto é 65 535 bytes (32 767 UTF-16 codepoints). Com prefixos como `\BaseNamedObjects\`, um atacante ainda controla ≈32 000 caracteres.
* **Pré-requisitos do atacante** – Qualquer usuário pode criar objetos sob diretórios graváveis como `\BaseNamedObjects`. Quando o código vulnerável usa um nome ali dentro, ou segue um link simbólico que aponta para lá, o atacante controla o desempenho da lookup sem privilégios especiais.

## Primitiva de desaceleração #1 – Componente único máximo

O custo de resolver um componente é aproximadamente linear ao seu comprimento porque o kernel deve realizar uma comparação Unicode contra cada entrada no diretório pai. Criar um event com um nome de 32 kB aumenta imediatamente a latência de `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (plataforma de testes Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas práticas*

- Você pode atingir o limite de comprimento usando qualquer objeto de kernel nomeado (events, sections, semaphores…).
- Symbolic links ou reparse points podem apontar um nome curto “victim” para este componente gigante, de modo que o slowdown seja aplicado de forma transparente.
- Como tudo reside em namespaces graváveis pelo usuário, o payload funciona a partir de um nível de integridade de usuário padrão.

## Slowdown primitive #2 – Deep recursive directories

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto aciona a lógica de resolução de diretório (ACL checks, hash lookups, reference counting), de modo que a latência por nível é maior do que numa única comparação de string. Com ~16 000 níveis (limitado pelo mesmo tamanho de `UNICODE_STRING`), os tempos empíricos ultrapassam a barreira de 35 µs alcançada por componentes longos de um único segmento.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Tips:

* Alterne o caractere por nível (`A/B/C/...`) se o diretório pai começar a rejeitar duplicatas.
* Mantenha um array de handles para poder excluir a cadeia de forma limpa após a exploração e evitar poluir o namespace.

## Primitiva de desaceleração #3 – Shadow directories, hash collisions & symlink reparses (minutos em vez de microssegundos)

Object directories suportam **shadow directories** (fallback lookups) e tabelas hash bucketed para entradas. Abuse ambos mais o limite de 64 componentes de symbolic-link reparse para multiplicar a desaceleração sem exceder o comprimento de `UNICODE_STRING`:

1. Crie dois diretórios em `\BaseNamedObjects`, por exemplo `A` (shadow) e `A\A` (target). Crie o segundo usando o primeiro como shadow directory (`NtCreateDirectoryObjectEx`), de modo que lookups ausentes em `A` caiam para `A\A`.
2. Preencha cada diretório com milhares de **colliding names** que caem no mesmo hash bucket (por exemplo, variando dígitos finais enquanto mantém o mesmo valor de `RtlHashUnicodeString`). As buscas agora degradam para varreduras lineares O(n) dentro de um único diretório.
3. Construa uma cadeia de ~63 **object manager symbolic links** que reparse repetidamente para o longo sufixo `A\A\…`, consumindo o orçamento de reparse. Cada reparse reinicia o parsing do topo, multiplicando o custo das colisões.
4. O lookup do componente final (`...\\0`) agora leva **minutos** no Windows 11 quando 16 000 colisões estão presentes por diretório, fornecendo uma vitória de race praticamente garantida para one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por que isso importa*: Uma lentidão de vários minutos transforma one-shot race-based LPEs em exploits determinísticos.

## Medindo sua race window

Insira um harness rápido dentro do seu exploit para medir o quão grande a race window se torna no hardware da vítima. O trecho abaixo abre o objeto alvo `iterations` vezes e retorna o custo médio por abertura usando `QueryPerformanceCounter`.
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Os resultados alimentam diretamente sua estratégia de orquestração da race (por exemplo, número de worker threads necessários, sleep intervals, quão cedo você precisa flipar o shared state).

## Fluxo de exploração

1. **Locate the vulnerable open** – Trace o caminho no kernel (via symbols, ETW, hypervisor tracing, or reversing) até encontrar uma chamada `NtOpen*`/`ObOpenObjectByName` que percorre um nome controlado pelo atacante ou um link simbólico em um diretório gravável por usuário.
2. **Replace that name with a slow path**
- Crie o componente longo ou cadeia de diretórios sob `\BaseNamedObjects` (ou outra raiz OM gravável).
- Crie um link simbólico de modo que o nome que o kernel espera agora resolva para o caminho lento. Você pode direcionar a busca de diretório do driver vulnerável para sua estrutura sem tocar o alvo original.
3. **Trigger the race**
- Thread A (vítima) executa o código vulnerável e fica bloqueada dentro da lookup lenta.
- Thread B (atacante) flipa o guarded state (por exemplo, troca um file handle, reescreve um link simbólico, alterna a object security) enquanto Thread A está ocupada.
- Quando Thread A retoma e executa a ação privilegiada, ela observa um estado stale e executa a operação controlada pelo atacante.
4. **Clean up** – Exclua a cadeia de diretórios e os links simbólicos para evitar deixar artefatos suspeitos ou quebrar usuários legítimos de IPC.

## Considerações operacionais

- **Combine primitives** – Você pode usar um nome longo por nível em uma cadeia de diretórios para latência ainda maior até esgotar o tamanho de `UNICODE_STRING`.
- **One-shot bugs** – A janela expandida (de dezenas de microssegundos a minutos) torna bugs de “single trigger” realistas quando combinados com CPU affinity pinning ou preemption assistida por hypervisor.
- **Side effects** – A desaceleração afeta apenas o caminho malicioso, então o desempenho geral do sistema permanece inalterado; defensores raramente notarão, a menos que monitorem o crescimento do namespace.
- **Cleanup** – Mantenha handles para cada diretório/objeto que você criar para que possa chamar `NtMakeTemporaryObject`/`NtClose` depois. Cadeias de diretórios sem limites podem persistir entre reinicializações caso contrário.

## Notas defensivas

- Código do kernel que depende de named objects deve revalidar o estado sensível à segurança *após* o open, ou obter uma referência antes da verificação (fechando a lacuna TOCTOU).
- Aplique limites superiores na profundidade/comprimento de paths do OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes de volta para a janela de microssegundos.
- Instrumente o crescimento do namespace do object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas com milhares de componentes sob `\BaseNamedObjects`.

## Referências

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
