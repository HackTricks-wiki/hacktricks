# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Por que alongar a race window importa

Muitos Windows kernel LPEs seguem o padrão clássico `check_state(); NtOpenX("name"); privileged_action();`. Em hardware moderno, uma chamada fria `NtOpenEvent`/`NtOpenSection` resolve um nome curto em ~2 µs, deixando quase nenhum tempo para inverter o estado verificado antes que a ação segura ocorra. Forçando deliberadamente a resolução do Object Manager Namespace (OMNS) no passo 2 para levar dezenas de microssegundos, o atacante ganha tempo suficiente para vencer consistentemente races instáveis sem precisar de milhares de tentativas.

## Internais da lookup do Object Manager em poucas palavras

* **OMNS structure** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório a diretório. Cada componente faz o kernel localizar/abrir um *Object Directory* e comparar strings Unicode. Symbolic links (por exemplo, letras de drive) podem ser percorridos ao longo do caminho.
* **UNICODE_STRING limit** – Caminhos do OM são transportados dentro de um `UNICODE_STRING` cujo `Length` é um valor de 16 bits. O limite absoluto é 65 535 bytes (32 767 codepoints UTF-16). Com prefixos como `\BaseNamedObjects\`, um atacante ainda controla ≈32 000 caracteres.
* **Attacker prerequisites** – Qualquer usuário pode criar objetos sob diretórios graváveis como `\BaseNamedObjects`. Quando o código vulnerável usa um nome ali dentro, ou segue um symbolic link que aponte para lá, o atacante controla o desempenho da lookup sem privilégios especiais.

## Slowdown primitive #1 – Single maximal component

O custo de resolver um componente é aproximadamente linear em relação ao seu comprimento porque o kernel precisa realizar uma comparação Unicode contra cada entrada no diretório pai. Criar um evento com um nome de 32 kB aumenta imediatamente a latência do `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas práticas*

- Você pode atingir o limite de comprimento usando qualquer named kernel object (events, sections, semaphores…).
- Symbolic links or reparse points podem apontar um nome curto “victim” para este componente gigante, de modo que o slowdown seja aplicado de forma transparente.
- Como tudo vive em user-writable namespaces, o payload funciona em um standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto aciona a lógica de resolução de diretório (ACL checks, hash lookups, reference counting), portanto a latência por nível é maior do que uma única comparação de string. Com ~16 000 níveis (limitado pelo mesmo tamanho de `UNICODE_STRING`), medições empíricas ultrapassam a barreira de 35 µs alcançada por componentes únicos longos.
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
Dicas:

* Alterne o caractere por nível (`A/B/C/...`) se o diretório pai começar a rejeitar duplicatas.
* Mantenha um handle array para que você possa deletar a cadeia de forma limpa após a exploitation, evitando poluir o namespace.

## Medindo sua race window

Insira um harness rápido no seu exploit para medir quão grande a janela fica no hardware da vítima. O snippet abaixo abre o target object `iterations` vezes e retorna o custo médio por abertura usando `QueryPerformanceCounter`.
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
Os resultados alimentam diretamente sua estratégia de orquestração da corrida (por exemplo, número de worker threads necessárias, intervalos de sleep, quão cedo você precisa alterar o estado compartilhado).

## Fluxo de exploração

1. **Localize a abertura vulnerável** – Rastreie o caminho do kernel (via símbolos, ETW, hypervisor tracing, ou reversing) até encontrar uma chamada `NtOpen*`/`ObOpenObjectByName` que percorra um nome controlado pelo atacante ou um symbolic link em um diretório gravável pelo usuário.
2. **Replace that name with a slow path**
- Crie o componente longo ou cadeia de diretórios sob `\BaseNamedObjects` (ou outra writable OM root).
- Crie um symbolic link para que o nome que o kernel espera agora resolva para o caminho lento. Você pode apontar a directory lookup do driver vulnerável para sua estrutura sem tocar no alvo original.
3. **Trigger the race**
- Thread A (vítima) executa o código vulnerável e bloqueia dentro da slow lookup.
- Thread B (atacante) altera o estado protegido (por ex., troca um file handle, reescreve um symbolic link, alterna object security) enquanto Thread A está ocupada.
- Quando Thread A retoma e executa a ação privilegiada, ela observa um estado obsoleto e executa a operação controlada pelo atacante.
4. **Limpeza** – Delete a cadeia de diretórios e os symbolic links para evitar deixar artefatos suspeitos ou quebrar usuários legítimos de IPC.

## Considerações operacionais

- **Combine primitives** – Você pode usar um nome longo *por nível* em uma cadeia de diretórios para latência ainda maior até esgotar o tamanho de `UNICODE_STRING`.
- **One-shot bugs** – A janela expandida (dezenas de microssegundos) torna bugs de “single trigger” realistas quando emparelhados com CPU affinity pinning ou preempção assistida por hypervisor.
- **Efeitos colaterais** – A lentidão afeta apenas o caminho malicioso, então o desempenho geral do sistema permanece inalterado; defensores raramente notarão a menos que monitorem o crescimento do namespace.
- **Limpeza** – Mantenha handles para cada diretório/objeto que você criar para que possa chamar `NtMakeTemporaryObject`/`NtClose` depois. Cadeias de diretórios sem limite podem persistir entre reinicializações caso contrário.

## Notas defensivas

- Código do kernel que depende de objetos nomeados deve revalidar o estado sensível à segurança *após* a abertura, ou tomar uma referência antes da verificação (fechando a brecha TOCTOU).
- Aplique limites máximos na profundidade/comprimento do caminho OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes de volta para a janela de microssegundos.
- Instrumente o crescimento do namespace do object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas com milhares de componentes sob `\BaseNamedObjects`.

## Referências

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
