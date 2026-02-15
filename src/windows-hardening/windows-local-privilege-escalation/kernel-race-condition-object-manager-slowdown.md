# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Por que alongar a janela de race importa

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. Em hardware moderno um `NtOpenEvent`/`NtOpenSection` a frio resolve um nome curto em ~2 µs, deixando quase nenhum tempo para inverter o estado verificado antes que a ação segura ocorra. Ao forçar deliberadamente a resolução no Object Manager Namespace (OMNS) na etapa 2 para que leve dezenas de microssegundos, o atacante ganha tempo suficiente para vencer consistentemente races instáveis sem precisar de milhares de tentativas.

## Internals da resolução do Object Manager em poucas palavras

* **Estrutura OMNS** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório por diretório. Cada componente faz com que o kernel localize/abra um *Object Directory* e compare cadeias Unicode. Links simbólicos (por ex., letras de unidade) podem ser seguidos no caminho.
* **UNICODE_STRING limit** – Caminhos do OM são transportados dentro de um `UNICODE_STRING` cujo `Length` é um valor de 16 bits. O limite absoluto é 65 535 bytes (32 767 codepoints UTF-16). Com prefixos como `\BaseNamedObjects\`, um atacante ainda controla ≈32 000 caracteres.
* **Pré-requisitos do atacante** – Qualquer usuário pode criar objetos sob diretórios graváveis como `\BaseNamedObjects`. Quando o código vulnerável usa um nome dentro desses diretórios, ou segue um link simbólico que aponta para lá, o atacante controla o desempenho da resolução sem privilégios especiais.

## Primitiva de desaceleração #1 – componente único máximo

O custo de resolver um componente é aproximadamente linear com seu comprimento porque o kernel precisa executar uma comparação Unicode contra cada entrada no diretório pai. Criar um event com um nome de 32 kB aumenta imediatamente a latência do `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas práticas*

- Você pode atingir o limite de comprimento usando qualquer objeto nomeado do kernel (events, sections, semaphores…).
- Symbolic links or reparse points podem apontar um nome curto de “vítima” para esse componente gigante, de modo que o slowdown seja aplicado de forma transparente.
- Como tudo vive em namespaces graváveis pelo usuário, o payload funciona a partir de um integrity level de usuário padrão.

## Slowdown primitive #2 – Deep recursive directories

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto dispara a lógica de resolução de diretório (ACL checks, hash lookups, contagem de referências), então a latência por nível é maior que a de uma única comparação de string. Com ~16 000 níveis (limitado pelo mesmo tamanho de `UNICODE_STRING`), os tempos empíricos ultrapassam a barreira de 35 µs alcançada por componentes únicos longos.
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

* Alterne o caractere por nível (`A/B/C/...`) se o parent directory começar a rejeitar duplicatas.
* Mantenha um handle array para que você possa remover a cadeia de forma limpa após exploitation, evitando poluir o namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutos em vez de microsegundos)

Object directories suportam **shadow directories** (fallback lookups) e bucketed hash tables para entradas. Abuse de ambos mais o limite de 64 componentes de reparse de symbolic-link para multiplicar o slowdown sem exceder o comprimento de `UNICODE_STRING`:

1. Crie dois diretórios sob `\BaseNamedObjects`, por exemplo `A` (shadow) e `A\A` (target). Crie o segundo usando o primeiro como o shadow directory (`NtCreateDirectoryObjectEx`), de modo que lookups faltantes em `A` caiam em `A\A`.
2. Preencha cada diretório com milhares de **colliding names** que caem no mesmo hash bucket (por exemplo, variando dígitos finais enquanto mantém o mesmo valor de `RtlHashUnicodeString`). As lookups agora degradam para varreduras lineares O(n) dentro de um único diretório.
3. Construa uma cadeia de ~63 **object manager symbolic links** que repetidamente reparseiam no longo sufixo `A\A\…`, consumindo o reparse budget. Cada reparse reinicia o parsing desde o início, multiplicando o custo das colisões.
4. A lookup do componente final (`...\\0`) agora leva **minutos** no Windows 11 quando 16 000 colisões estão presentes por diretório, fornecendo uma vitória de race praticamente garantida para one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por que isso importa*: Um desaceleramento de minutos transforma LPEs baseados em race de tentativa única em exploits determinísticos.

### Notas de reteste de 2025 e ferramentas prontas

- James Forshaw republicou a técnica com timings atualizados no Windows 11 24H2 (ARM64). As aberturas de referência permanecem ~2 µs; um componente de 32 kB eleva isso para ~35 µs, e shadow-dir + collision + 63-reparse chains ainda chegam a ~3 minutos, confirmando que as primitives sobrevivem às builds atuais. O código-fonte e o perf harness estão no post atualizado do Project Zero.
- Você pode automatizar a configuração usando o bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para gerar o par shadow/target e `NativeSymlink.exe` em loop para emitir a cadeia de 63 saltos. Isso evita wrappers `NtCreate*` escritos à mão e mantém os ACLs consistentes.

## Medindo sua janela de race

Incorpore um harness rápido dentro do seu exploit para medir o quanto a janela cresce no hardware da vítima. O snippet abaixo abre o objeto target `iterations` vezes e retorna o custo médio por abertura usando `QueryPerformanceCounter`.
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
Os resultados alimentam diretamente sua estratégia de orquestração da race (por exemplo, número de worker threads necessárias, intervalos de sleep, quão cedo você precisa flipar o estado compartilhado).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Crie o componente longo ou a cadeia de diretórios sob `\BaseNamedObjects` (ou outra raiz OM gravável).
- Crie um symbolic link de modo que o nome que o kernel espera agora resolva para o caminho lento. Você pode apontar a lookup de diretório do driver vulnerável para sua estrutura sem tocar no alvo original.
3. **Trigger the race**
- Thread A (vítima) executa o código vulnerável e bloqueia dentro da lookup lenta.
- Thread B (atacante) flipa o estado guardado (por exemplo, troca um file handle, reescreve um symbolic link, alterna a security do objeto) enquanto a Thread A está ocupada.
- Quando a Thread A retoma e executa a ação privilegiada, ela observa um estado stale e executa a operação controlada pelo atacante.
4. **Clean up** – Delete a cadeia de diretórios e os symbolic links para evitar deixar artefatos suspeitos ou quebrar usuários legítimos de IPC.

## Operational considerations

- **Combine primitives** – Você pode usar um nome longo *por nível* em uma cadeia de diretórios para latência ainda maior até esgotar o tamanho de `UNICODE_STRING`.
- **One-shot bugs** – A janela expandida (de dezenas de microssegundos a minutos) torna bugs “single trigger” realistas quando combinados com pinagem de afinidade de CPU ou preempção assistida por hypervisor.
- **Side effects** – A slowdown afeta apenas o caminho malicioso, então o desempenho geral do sistema permanece inalterado; defensores raramente notarão a menos que monitorem o crescimento do namespace.
- **Cleanup** – Mantenha handles para cada diretório/objeto que você criar para poder chamar `NtMakeTemporaryObject`/`NtClose` depois. Cadeias de diretórios sem limites podem persistir entre reboots caso contrário.
- **File-system races** – Se o caminho vulnerável eventualmente resolver via NTFS, você pode empilhar um Oplock (por exemplo, `SetOpLock.exe` do mesmo toolkit) no arquivo de suporte enquanto a slowdown do OM roda, congelando o consumidor por milissegundos adicionais sem alterar o grafo do OM.

## Defensive notes

- Kernel code que depende de named objects deve revalidar o estado sensível à segurança *após* o open, ou tomar uma referência antes da verificação (fechando a brecha TOCTOU).
- Aplique limites superiores na profundidade/tamanho do path do OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes de volta para a janela de microssegundos.
- Instrumen­te o crescimento do namespace do object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas de milhares de componentes sob `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
