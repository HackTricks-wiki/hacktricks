# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Por que alongar a janela de race é importante

Muitos Windows kernel LPEs seguem o padrão clássico `check_state(); NtOpenX("name"); privileged_action();`. Em hardware moderno um cold `NtOpenEvent`/`NtOpenSection` resolve um nome curto em ~2 µs, deixando quase nenhum tempo para inverter o estado verificado antes que a ação segura ocorra. Ao forçar deliberadamente o lookup do Object Manager Namespace (OMNS) no passo 2 a levar dezenas de µs, o atacante ganha tempo suficiente para vencer consistentemente races que seriam instáveis, sem precisar de milhares de tentativas.

## Como funciona o lookup do Object Manager, em poucas palavras

* **OMNS structure** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório por diretório. Cada componente faz com que o kernel encontre/abra um *Object Directory* e compare Unicode strings. Symbolic links (e.g., drive letters) podem ser atravessados no caminho.
* **UNICODE_STRING limit** – Caminhos OM são transportados dentro de um `UNICODE_STRING` cujo `Length` é um valor de 16 bits. O limite absoluto é 65 535 bytes (32 767 UTF-16 codepoints). Com prefixos como `\BaseNamedObjects\`, um atacante ainda controla ≈32 000 caracteres.
* **Attacker prerequisites** – Qualquer usuário pode criar objetos em diretórios graváveis como `\BaseNamedObjects`. Quando o código vulnerável usa um nome dentro, ou segue um symbolic link que aponta para lá, o atacante controla o desempenho do lookup sem privilégios especiais.

## Primitiva de desaceleração #1 – Componente único máximo

O custo de resolver um componente é aproximadamente linear em relação ao seu comprimento porque o kernel deve realizar uma comparação Unicode contra cada entrada no diretório pai. Criar um evento com um nome de 32 kB aumenta imediatamente a latência do `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Symbolic links ou reparse points podem apontar um curto “victim” name para esse componente gigante para que o slowdown seja aplicado de forma transparente.
- Porque tudo vive em user-writable namespaces, o payload funciona a partir de um nível de integridade de usuário padrão.

## Slowdown primitive #2 – Deep recursive directories

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto aciona a lógica de resolução de diretório (ACL checks, hash lookups, reference counting), então a latência por nível é maior do que uma simples string compare. Com ~16 000 níveis (limitados pelo mesmo `UNICODE_STRING` size), medições empíricas ultrapassam a barreira de 35 µs alcançada por long single components.
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
* Mantenha um array de handles para poder deletar a cadeia de forma limpa após a exploração e evitar poluir o namespace.

## Primitiva de slowdown #3 – Shadow directories, hash collisions & symlink reparses (minutos em vez de microssegundos)

Object directories suportam **shadow directories** (fallback lookups) e tabelas de hash bucketed para entradas. Abuse ambos mais o limite de reparse de 64 componentes de symbolic-link para multiplicar o slowdown sem exceder o comprimento de `UNICODE_STRING`:

1. Crie dois diretórios sob `\BaseNamedObjects`, e.g. `A` (shadow) e `A\A` (target). Crie o segundo usando o primeiro como shadow directory (`NtCreateDirectoryObjectEx`), de modo que lookups ausentes em `A` caiam para `A\A`.
2. Preencha cada diretório com milhares de **colliding names** que caiam no mesmo bucket de hash (e.g., variando dígitos finais enquanto mantém o mesmo valor `RtlHashUnicodeString`). As lookups agora degradam para varreduras lineares O(n) dentro de um único diretório.
3. Construa uma cadeia de ~63 **object manager symbolic links** que reparsem repetidamente para o longo sufixo `A\A\…`, consumindo o orçamento de reparse. Cada reparse reinicia o parsing desde o topo, multiplicando o custo das colisões.
4. A lookup do componente final (`...\\0`) agora leva **minutos** no Windows 11 quando 16 000 colisões estão presentes por diretório, fornecendo uma vitória de race praticamente garantida para LPEs de kernel one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por que isso importa*: Uma desaceleração de vários minutos transforma one-shot race-based LPEs em exploits determinísticos.

## Medindo sua janela de corrida

Incorpore um pequeno harness dentro do seu exploit para medir o quão grande a janela se torna no hardware da vítima. O trecho abaixo abre o objeto alvo `iterations` vezes e retorna o custo médio por abertura usando `QueryPerformanceCounter`.
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
Os resultados alimentam diretamente sua race orchestration strategy (por exemplo, número de worker threads necessários, intervalos de sleep, quão cedo você precisa flipar o estado compartilhado).

## Fluxo de exploração

1. **Localize o open vulnerável** – Trace o caminho do kernel (via símbolos, ETW, hypervisor tracing, ou reversing) até encontrar uma chamada `NtOpen*`/`ObOpenObjectByName` que percorre um nome controlado pelo atacante ou um symbolic link em um diretório gravável pelo usuário.
2. **Substitua esse nome por um caminho lento**
- Crie o componente longo ou a cadeia de diretórios sob `\BaseNamedObjects` (ou outra OM root gravável).
- Crie um symbolic link para que o nome que o kernel espera agora aponte para o caminho lento. Você pode direcionar a busca de diretório do driver vulnerável para sua estrutura sem tocar no destino original.
3. **Trigger the race**
- Thread A (vítima) executa o código vulnerável e bloqueia dentro da lookup lenta.
- Thread B (atacante) flipa o estado guardado (por exemplo, troca um file handle, reescreve um symbolic link, alterna a segurança do objeto) enquanto a Thread A está ocupada.
- Quando a Thread A retoma e executa a ação privilegiada, ela observa um estado stale e realiza a operação controlada pelo atacante.
4. **Limpeza** – Delete a cadeia de diretórios e os symbolic links para evitar deixar artefatos suspeitos ou quebrar usuários legítimos de IPC.

## Considerações operacionais

- **Combine primitives** – Você pode usar um nome longo *por nível* em uma cadeia de diretórios para aumentar ainda mais a latência até esgotar o tamanho de `UNICODE_STRING`.
- **One-shot bugs** – A janela expandida (de dezenas de microssegundos a minutos) torna bugs de “gatilho único” realistas quando pareados com CPU affinity pinning ou preempção assistida por hypervisor.
- **Efeitos colaterais** – A desaceleração afeta apenas o caminho malicioso, então o desempenho geral do sistema permanece inalterado; os defensores raramente notarão a menos que monitorem o crescimento do namespace.
- **Cleanup** – Mantenha handles de cada diretório/objeto que você criar para poder chamar `NtMakeTemporaryObject`/`NtClose` depois. Cadeias de diretórios sem limites podem persistir após reboot caso contrário.

## Notas defensivas

- Código de kernel que depende de objetos nomeados deve revalidar estados sensíveis à segurança *após* o open, ou tomar uma referência antes da verificação (fechando a brecha TOCTOU).
- Aplique limites superiores na profundidade/comprimento do caminho do OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes de volta para a janela de microssegundos.
- Instrumente o crescimento do namespace do object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas com milhares de componentes sob `\BaseNamedObjects`.

## Referências

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
