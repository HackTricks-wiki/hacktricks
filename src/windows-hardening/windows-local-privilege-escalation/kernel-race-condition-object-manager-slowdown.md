# Exploração de Race Condition do Kernel por meio de Slow Paths do Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por que ampliar a race window é importante

Muitos LPEs do kernel do Windows seguem o padrão clássico `check_state(); NtOpenX("name"); privileged_action();`. Em hardware moderno, um `NtOpenEvent`/`NtOpenSection` cold resolve um nome curto em ~2 µs, deixando quase nenhum tempo para alterar o estado verificado antes que a ação privilegiada ocorra. Ao forçar deliberadamente a consulta do Object Manager Namespace (OMNS) na etapa 2 a levar dezenas de microssegundos, o attacker obtém tempo suficiente para vencer consistentemente races que, de outra forma, seriam instáveis, sem precisar de milhares de tentativas.<sup>[[1]](#references)</sup>

## Internals da consulta do Object Manager em resumo

* **Estrutura do OMNS** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório por diretório. Cada componente faz com que o kernel encontre/abra um *Object Directory* e compare strings Unicode. Symbolic links (por exemplo, letras de unidades) podem ser percorridos durante o processo.
* **Limite de UNICODE_STRING** – Os caminhos do OM são transportados dentro de uma `UNICODE_STRING`, cujo `Length` é um valor de 16 bits. O limite absoluto é de 65 535 bytes (32 767 codepoints UTF-16). Com prefixos como `\BaseNamedObjects\`, um attacker ainda controla aproximadamente 32 000 caracteres.
* **Pré-requisitos do attacker** – Qualquer usuário pode criar objects dentro de diretórios graváveis, como `\BaseNamedObjects`. Quando o código vulnerável usa um nome dentro desse diretório ou segue um symbolic link que aponta para lá, o attacker controla a performance da consulta sem privilégios especiais.<sup>[[1]](#references)</sup>

## Primitiva de slowdown #1 – Componente único máximo

O custo de resolver um componente é aproximadamente linear em relação ao seu comprimento, pois o kernel precisa realizar uma comparação Unicode com cada entrada no diretório pai. Criar um event com um nome de 32 kB aumenta imediatamente a latência de `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas práticas*

- Você pode atingir o limite de tamanho usando qualquer kernel object nomeado (events, sections, semaphores…).
- Symbolic links ou reparse points podem apontar um nome curto de “victim” para esse componente gigante, fazendo com que o slowdown seja aplicado de forma transparente.
- Como tudo reside em namespaces graváveis pelo usuário, o payload funciona a partir de um nível de integridade de usuário padrão.<sup>[[1]](#references)</sup>

## Primitiva de slowdown #2 – Diretórios recursivos profundos

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto aciona a lógica de resolução de diretórios (verificações de ACL, consultas de hash, contagem de referências), portanto a latência por nível é maior que a de uma única comparação de string. Com cerca de 16 000 níveis (limitados pelo mesmo tamanho de `UNICODE_STRING`), as medições empíricas ultrapassam a barreira de 35 µs alcançada por componentes únicos longos.
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

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutos em vez de microssegundos)

Os diretórios de objetos oferecem suporte a **shadow directories** (consultas de fallback) e tabelas hash organizadas em buckets para as entradas. Abuse de ambos, além do limite de reparse de 64 componentes de symbolic link, para multiplicar o slowdown sem exceder o comprimento de `UNICODE_STRING`:

1. Crie dois diretórios sob `\BaseNamedObjects`, por exemplo, `A` (shadow) e `A\A` (target). Crie o segundo usando o primeiro como shadow directory (`NtCreateDirectoryObjectEx`), de modo que consultas ausentes em `A` recorram a `A\A`.
2. Preencha cada diretório com milhares de **colliding names** que caiam no mesmo hash bucket (por exemplo, variando os dígitos finais enquanto mantém o mesmo valor de `RtlHashUnicodeString`). As consultas agora são degradadas para varreduras lineares O(n) dentro de um único diretório.
3. Crie uma cadeia de aproximadamente 63 **object manager symbolic links** que façam reparse repetidamente para o sufixo longo `A\A\…`, consumindo o orçamento de reparse. Cada reparse reinicia a análise a partir do topo, multiplicando o custo das colisões.
4. A consulta do componente final (`...\\0`) agora leva **minutos** no Windows 11 quando há 16 000 colisões por diretório, proporcionando uma vitória de race praticamente garantida para LPEs de kernel de execução única.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por que isso importa*: Uma lentidão de vários minutos transforma LPEs baseadas em race de uma única tentativa em exploits determinísticos.<sup>[[1]](#references)</sup>

### Notas do reteste de 2025 e tooling pronto

- James Forshaw republicou a técnica com timings atualizados no Windows 11 24H2 (ARM64). As aberturas baseline continuam em ~2 µs; um componente de 32 kB aumenta esse valor para ~35 µs, e shadow-dir + collision + cadeias de 63 reparse ainda chegam a ~3 minutos, confirmando que as primitivas sobrevivem às builds atuais. O código-fonte e o perf harness estão no post atualizado do Project Zero.<sup>[[1]](#references)</sup>
- Você pode fazer o setup via script usando o bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para criar o par shadow/target e `NativeSymlink.exe` em um loop para gerar a cadeia de 63 hops. Isso evita escrever wrappers `NtCreate*` manualmente e mantém as ACLs consistentes.<sup>[[2]](#references)</sup>

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
Os resultados alimentam diretamente sua estratégia de orquestração da race (por exemplo, o número de worker threads necessários, os intervalos de sleep e quão cedo você precisa alterar o estado compartilhado).

## Fluxo de exploração

1. **Localize a abertura vulnerável** – Rastreie o caminho do kernel (por meio de symbols, ETW, hypervisor tracing ou reversing) até encontrar uma chamada `NtOpen*`/`ObOpenObjectByName` que percorra um nome controlado pelo atacante ou um symbolic link em um diretório gravável pelo usuário.
2. **Substitua esse nome por um caminho lento**
- Crie o componente longo ou a cadeia de diretórios em `\BaseNamedObjects` (ou em outra raiz gravável do OM).
- Crie um symbolic link para que o nome esperado pelo kernel agora seja resolvido para o caminho lento. Você pode direcionar a busca de diretório do driver vulnerável para sua estrutura sem tocar no alvo original.
3. **Dispare a race**
- A Thread A (vítima) executa o código vulnerável e bloqueia dentro da busca lenta.
- A Thread B (atacante) altera o estado protegido (por exemplo, troca um file handle, reescreve um symbolic link ou alterna a segurança do objeto) enquanto a Thread A está ocupada.
- Quando a Thread A retoma e executa a ação privilegiada, ela observa um estado obsoleto e realiza a operação controlada pelo atacante.
4. **Faça a limpeza** – Exclua a cadeia de diretórios e os symbolic links para evitar deixar artefatos suspeitos ou interromper usuários legítimos de IPC.<sup>[[1]](#references)</sup>

## Cadeia aplicada: placeholders mutáveis do Cloud Files + troca de caminhos do Object Manager

O [ShieldBreak](https://github.com/MSNightmare/ShieldBreak), publicado como um bypass para o RoguePlanet (CVE-2026-50656), demonstra um padrão de exploração mais amplo: fazer um scanner privilegiado classificar uma representação de um arquivo lógico e, em seguida, alterar tanto seus bytes quanto a resolução do namespace antes que a remediação o utilize. O PoC combina um TOCTOU de hydration do Cloud Files, um fallback de shadow-directory do Object Manager, a captura de nomes gerados pelo CLFS e um link de administrative share local para transformar a limpeza do Defender em uma escrita de DLL protegida.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitua o conteúdo por meio da hydration do Cloud Files

Registre um diretório gravável pelo atacante como uma Cloud Files sync root, conecte um callback `CF_CALLBACK_TYPE_FETCH_DATA` e crie um placeholder cujo tamanho anunciado corresponda a um gatilho de detecção determinístico, como o EICAR ZIP. O primeiro fetch retorna o gatilho e altera o estado do callback; os fetches posteriores retornam o payload. Depois que o scanner classificar a primeira representação, obtenha a transfer key e reinicie a hydration com metadados do tamanho do payload; em seguida, force a hydration até EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
O limite de segurança falha se a análise, a decisão e a remediação se referirem apenas a um pathname ou a uma identidade de placeholder: nenhuma delas garante que uma hidratação posterior retorne os bytes que foram inspecionados.<sup>[[4]](#references)</sup>

### 2. Alterne um caminho invariável por meio de um fallback de shadow-directory

Crie um diretório do Object Manager de destino e um segundo diretório com `NtCreateDirectoryObjectEx`, passando o handle do destino como diretório de shadow/fallback. Coloque uma entrada `WD_SCAN` com o mesmo nome em ambas as camadas de resolução: a entrada visível aponta para o diretório de trabalho normal, enquanto a entrada de fallback aponta para `\CLFS\??\<working-directory>`. Forneça ao Defender somente o caminho invariável abaixo; excluir o link visível enquanto a operação estiver ativa faz com que a mesma string passe para a entrada apoiada pelo CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Isso é diferente de usar shadow directories apenas para retardar a busca: o atacante altera o **significado** de um caminho previamente aceito sem modificar sua string.<sup>[[4]](#references)</sup>

### 3. Capture o nome gerado e instale um link específico para o filename

Monitore o working directory com `ReadDirectoryChangesW`. Na primeira ocorrência de `FILE_ACTION_ADDED`, remova o link visível `WD_SCAN` para ativar a busca de fallback. Capture o segundo filename gerado, abra esse arquivo relacionado ao CLFS e bloqueie o intervalo `0..MAXLONGLONG` com `LockFileEx`. Enquanto a operação privilegiada estiver travada, substitua `WD_SCAN` no diretório visível por um diretório real do Object Manager e crie um symbolic link filho nomeado com base no filename observado (o PoC remove seus quatro caracteres finais). Aponte-o para o destino protegido por meio de SMB local:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
O processo sem privilégios não pode gravar esse destino por conta própria, mas o contexto SYSTEM do Defender pode percorrer o administrative share de loopback. Combinar a observação de nomes gerados com um link do Object Manager específico para o nome do arquivo evita a necessidade de prever antecipadamente o artefato de remediação.<sup>[[4]](#references)</sup>

### 4. Estabilizar a race de limpeza e acionar um loader privilegiado

Antes da varredura, o PoC armazena um PE válido (`ntdll.dll`) no alternate data stream NTFS `:stream` do placeholder. Depois que o redirecionamento cria o arquivo base protegido, ele abre `phoneinfo.dll:stream` com acesso de execução e mantém um mapeamento `PAGE_EXECUTE_READ | SEC_IMAGE` ativo enquanto a limpeza é retomada; os objetos de arquivo/seção ativos restringem a exclusão ou substituição durante a race final. A hydration reiniciada agora retorna a DLL de payload em vez do EICAR, portanto o arquivo base protegido contém código controlado pelo atacante.<sup>[[4]](#references)</sup>

Uma gravação protegida é então convertida em execução como SYSTEM ao colocar um `Report.wer` criado pelo atacante em `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` e invocar `\Microsoft\Windows\Windows Error Reporting\QueueReporting` por meio da Task Scheduler COM API. Nessa cadeia, o processamento privilegiado do WER carrega o `C:\Windows\System32\phoneinfo.dll` plantado; uma conexão named-pipe é usada como sinal de execução do payload.<sup>[[4]](#references)</sup>

### Pontos de detecção

Correlações úteis são mais específicas do que qualquer nome temporário isolado e abrangem todas as transições de namespace na cadeia:<sup>[[4]](#references)</sup>

- Um provedor Cloud Files recém-registrado, seguido pela detecção do EICAR e de `CF_OPERATION_TYPE_RESTART_HYDRATION` no mesmo placeholder.
- Caminhos do Object Manager contendo `WD_TARGET_*`, `WD_SHADOW_*` ou `WD_SCAN`, especialmente um caminho de varredura abaixo de `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Criação de arquivo CLFS, seguida por um bloqueio exclusivo do arquivo inteiro e acesso de loopback a `\\127.0.0.1\C$\Windows\System32\*.dll` a partir de um processo de segurança privilegiado.
- Criação de uma DLL em System32 junto com um NTFS ADS, seguida pelo mapeamento `SEC_IMAGE` do stream.
- Uma entrada de fila WER criada pelo atacante, seguida por uma execução manual incomum de `\Microsoft\Windows\Windows Error Reporting\QueueReporting` e pelo carregamento da imagem da DLL plantada.

## Considerações operacionais

- **Combinar primitives** – Você pode usar um nome longo *por nível* em uma cadeia de diretórios para obter uma latência ainda maior, até esgotar o tamanho de `UNICODE_STRING`.
- **Bugs de execução única** – A janela ampliada (de dezenas de microssegundos a minutos) torna realistas os bugs de “single trigger” quando combinados com fixação de afinidade de CPU ou preempção assistida por hypervisor.
- **Efeitos colaterais** – A lentidão afeta apenas o caminho malicioso, portanto o desempenho geral do sistema permanece inalterado; os defensores raramente perceberão isso, a menos que monitorem o crescimento do namespace.
- **Limpeza** – Mantenha handles para todos os diretórios/objetos criados para poder chamar `NtMakeTemporaryObject`/`NtClose` posteriormente. Caso contrário, cadeias de diretórios sem limite podem persistir após reinicializações.
- **Races de sistema de arquivos** – Se o caminho vulnerável eventualmente for resolvido pelo NTFS, você pode colocar um Oplock (por exemplo, `SetOpLock.exe` do mesmo toolkit) no arquivo de suporte enquanto o slowdown do OM estiver em execução, congelando o consumidor por milissegundos adicionais sem alterar o grafo do OM.<sup>[[2]](#references)</sup>

## Observações defensivas

- O código do kernel que depende de objetos nomeados deve revalidar o estado sensível à segurança *após* a abertura ou obter uma referência antes da verificação (eliminando a brecha de TOCTOU).
- Imponha limites superiores à profundidade/comprimento dos caminhos do OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes a voltar à janela de microssegundos.
- Instrumente o crescimento do namespace do Object Manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas com milhares de componentes em `\BaseNamedObjects`.

## References

- [1] [Project Zero – Técnicas de exploração do Windows: vencendo race conditions com consultas de caminho](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/ferramentas-de-teste-de-symboliclink](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
