# Exploração de Race Condition no Kernel via Slow Paths do Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por que aumentar a janela da race é importante

Muitas LPEs no kernel do Windows seguem o padrão clássico `check_state(); NtOpenX("name"); privileged_action();`. Em hardware moderno, um `NtOpenEvent`/`NtOpenSection` cold resolve um nome curto em ~2 µs, deixando pouquíssimo tempo para alterar o estado verificado antes que a ação privilegiada ocorra. Ao forçar deliberadamente a busca no Object Manager Namespace (OMNS) na etapa 2 a levar dezenas de microssegundos, o atacante obtém tempo suficiente para vencer consistentemente races que, de outra forma, seriam instáveis, sem precisar de milhares de tentativas.<sup>[[1]](#references)</sup>

## Internals da busca do Object Manager em resumo

* **Estrutura do OMNS** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório por diretório. Cada componente faz com que o kernel encontre/abra um *Object Directory* e compare strings Unicode. Symbolic links (por exemplo, letras de unidade) podem ser percorridos durante o processo.
* **Limite de `UNICODE_STRING`** – Os caminhos do OM são transportados dentro de uma `UNICODE_STRING` cujo `Length` é um valor de 16 bits. O limite absoluto é 65 535 bytes (32 767 codepoints UTF-16). Com prefixos como `\BaseNamedObjects\`, o atacante ainda controla aproximadamente 32 000 caracteres.
* **Pré-requisitos do atacante** – Qualquer usuário pode criar objetos em diretórios graváveis, como `\BaseNamedObjects`. Quando o código vulnerável usa um nome interno ou segue um symbolic link que aponta para esse local, o atacante controla o desempenho da busca sem privilégios especiais.<sup>[[1]](#references)</sup>

## Primitive de slowdown #1 – Componente único máximo

O custo de resolver um componente é aproximadamente linear em relação ao seu tamanho, pois o kernel precisa realizar uma comparação Unicode com cada entrada no diretório pai. Criar um evento com um nome de 32 kB aumenta imediatamente a latência de `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (ambiente de teste Snapdragon X Elite).
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
- Symbolic links ou reparse points podem apontar um nome curto de “victim” para esse componente gigante, fazendo com que o slowdown seja aplicado de forma transparente.
- Como tudo reside em namespaces graváveis pelo usuário, o payload funciona a partir de um nível de integridade de usuário padrão.<sup>[[1]](#references)</sup>

## Primitiva de slowdown #2 – Diretórios recursivos profundos

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto aciona a lógica de resolução de diretórios (verificações de ACL, pesquisas de hash, contagem de referências), portanto a latência por nível é maior do que a de uma única comparação de strings. Com cerca de 16 000 níveis (limitados pelo mesmo tamanho de `UNICODE_STRING`), as medições empíricas ultrapassam a barreira de 35 µs alcançada por componentes únicos longos.
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
* Mantenha um array de handles para poder excluir a cadeia de forma limpa após a exploração e evitar poluir o namespace.<sup>[[1]](#references)</sup>

## Primitiva de slowdown #3 – Diretórios shadow, colisões de hash e reparses de symlink (minutos em vez de microssegundos)

Os diretórios de objetos oferecem **diretórios shadow** (lookups de fallback) e tabelas hash divididas em buckets para as entradas. Abuse de ambos, junto com o limite de reparse de 64 componentes de symbolic-link, para multiplicar o slowdown sem exceder o tamanho de `UNICODE_STRING`:

1. Crie dois diretórios em `\BaseNamedObjects`, por exemplo, `A` (shadow) e `A\A` (target). Crie o segundo usando o primeiro como diretório shadow (`NtCreateDirectoryObjectEx`), para que os lookups ausentes em `A` passem para `A\A`.
2. Preencha cada diretório com milhares de **nomes com colisão** que caiam no mesmo bucket de hash (por exemplo, variando os dígitos finais enquanto mantém o mesmo valor de `RtlHashUnicodeString`). Os lookups agora se degradam para varreduras lineares O(n) dentro de um único diretório.
3. Construa uma cadeia de aproximadamente 63 **symbolic links do object manager** que façam reparse repetidamente para o sufixo longo `A\A\…`, consumindo o orçamento de reparse. Cada reparse reinicia o parsing a partir do início, multiplicando o custo das colisões.
4. O lookup do componente final (`...\\0`) agora leva **minutos** no Windows 11 quando há 16.000 colisões por diretório, proporcionando uma vitória de race praticamente garantida para kernel LPEs one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por que isso importa*: uma lentidão de alguns minutos transforma LPEs baseados em race de tentativa única em exploits determinísticos.<sup>[[1]](#references)</sup>

### Notas do reteste de 2025 e tooling pronto

- James Forshaw republicou a técnica com timings atualizados no Windows 11 24H2 (ARM64). As aberturas base permanecem em ~2 µs; um componente de 32 kB aumenta esse valor para ~35 µs, e as cadeias shadow-dir + collision + 63-reparse ainda chegam a ~3 minutos, confirmando que os primitives sobrevivem às builds atuais. O código-fonte e o perf harness estão na publicação atualizada do Project Zero.<sup>[[1]](#references)</sup>
- Você pode automatizar a configuração usando o pacote público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para criar o par shadow/target e `NativeSymlink.exe` em um loop para emitir a cadeia de 63 hops. Isso evita wrappers `NtCreate*` escritos manualmente e mantém as ACLs consistentes.<sup>[[2]](#references)</sup>

## Medindo sua race window

Inclua um harness rápido no seu exploit para medir o tamanho da window no hardware da vítima. O snippet abaixo abre o objeto-alvo `iterations` vezes e retorna o custo médio por abertura usando `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Os resultados alimentam diretamente sua estratégia de orquestração da race (por exemplo, o número de threads de worker necessárias, os intervalos de sleep e quão cedo você precisa alternar o estado compartilhado).

## Fluxo de exploração

1. **Localize o open vulnerável** – Rastreie o caminho do kernel (por meio de symbols, ETW, tracing do hypervisor ou reversing) até encontrar uma chamada `NtOpen*`/`ObOpenObjectByName` que percorra um nome controlado pelo atacante ou um symbolic link em um diretório gravável pelo usuário.
2. **Substitua esse nome por um slow path**
- Crie o componente longo ou a cadeia de diretórios sob `\BaseNamedObjects` (ou outra raiz gravável do OM).
- Crie um symbolic link para que o nome esperado pelo kernel agora seja resolvido pelo slow path. Você pode direcionar a busca de diretório do driver vulnerável para sua estrutura sem tocar no alvo original.
3. **Dispare a race**
- A thread A (vítima) executa o código vulnerável e bloqueia dentro da busca lenta.
- A thread B (atacante) alterna o estado protegido (por exemplo, troca um file handle, reescreve um symbolic link ou alterna a segurança do objeto) enquanto a thread A está ocupada.
- Quando a thread A retoma e executa a ação privilegiada, ela observa um estado obsoleto e realiza a operação controlada pelo atacante.
4. **Faça a limpeza** – Exclua a cadeia de diretórios e os symbolic links para evitar deixar artefatos suspeitos ou interromper usuários legítimos de IPC.<sup>[[1]](#references)</sup>

## Considerações operacionais

- **Combine primitives** – Você pode usar um nome longo *por nível* em uma cadeia de diretórios para obter uma latência ainda maior, até esgotar o tamanho de `UNICODE_STRING`.
- **Bugs de disparo único** – A janela expandida (de dezenas de microssegundos a minutos) torna realistas os bugs de “single trigger” quando combinados com fixação de afinidade da CPU ou preempção assistida por hypervisor.
- **Efeitos colaterais** – A lentidão afeta apenas o caminho malicioso, portanto o desempenho geral do sistema permanece inalterado; os defenders raramente perceberão, a menos que monitorem o crescimento do namespace.
- **Limpeza** – Mantenha handles para cada diretório/objeto criado para que você possa chamar `NtMakeTemporaryObject`/`NtClose` posteriormente. Caso contrário, cadeias de diretórios sem limite poderão persistir após reinicializações.
- **Races de file system** – Se o caminho vulnerável finalmente for resolvido por meio do NTFS, você poderá adicionar um Oplock (por exemplo, `SetOpLock.exe` do mesmo toolkit) ao arquivo subjacente enquanto o slowdown do OM estiver em execução, congelando o consumidor por milissegundos adicionais sem alterar o grafo do OM.<sup>[[2]](#references)</sup>

## Notas defensivas

- O código do kernel que depende de objetos nomeados deve revalidar o estado sensível à segurança *após* o open ou obter uma reference antes da verificação (fechando a lacuna de TOCTOU).
- Aplique limites superiores à profundidade/tamanho do caminho do OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes de volta à janela de microssegundos.
- Instrumente o crescimento do namespace do object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas com milhares de componentes sob `\BaseNamedObjects`.

## Referências

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
