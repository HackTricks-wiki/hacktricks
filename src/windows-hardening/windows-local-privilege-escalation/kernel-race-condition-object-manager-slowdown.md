# Exploração de Race Condition no Kernel via Slow Paths do Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por que ampliar a janela da race é importante

Muitos LPEs no kernel do Windows seguem o padrão clássico `check_state(); NtOpenX("name"); privileged_action();`. Em hardware moderno, um `NtOpenEvent`/`NtOpenSection` cold resolve um nome curto em ~2 µs, deixando quase nenhum tempo para alterar o estado verificado antes que a ação privilegiada ocorra. Ao forçar deliberadamente a consulta no Object Manager Namespace (OMNS), na etapa 2, a levar dezenas de microssegundos, o atacante obtém tempo suficiente para vencer de forma consistente races que, de outra forma, seriam instáveis, sem precisar de milhares de tentativas.<sup>[[1]](#references)</sup>

## Internals da consulta do Object Manager em poucas palavras

* **Estrutura do OMNS** – Nomes como `\BaseNamedObjects\Foo` são resolvidos diretório por diretório. Cada componente faz com que o kernel encontre/abra um *Object Directory* e compare strings Unicode. Symbolic links (por exemplo, letras de unidade) podem ser percorridos durante o processo.
* **Limite de UNICODE_STRING** – Os caminhos do OM são transportados dentro de uma `UNICODE_STRING`, cujo `Length` é um valor de 16 bits. O limite absoluto é de 65 535 bytes (32 767 codepoints UTF-16). Com prefixos como `\BaseNamedObjects\`, um atacante ainda controla aproximadamente 32 000 caracteres.
* **Pré-requisitos do atacante** – Qualquer usuário pode criar objetos dentro de diretórios graváveis, como `\BaseNamedObjects`. Quando o código vulnerável usa um nome interno ou segue um symbolic link que aponta para lá, o atacante controla o desempenho da consulta sem privilégios especiais.<sup>[[1]](#references)</sup>

## Primitiva de Slowdown #1 – Componente único máximo

O custo de resolver um componente é aproximadamente linear em relação ao seu comprimento, pois o kernel precisa realizar uma comparação Unicode com cada entrada no diretório pai. Criar um evento com um nome de 32 kB aumenta imediatamente a latência de `NtOpenEvent` de ~2 µs para ~35 µs no Windows 11 24H2 (ambiente de teste Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas práticas*

- Você pode atingir o limite de comprimento usando qualquer kernel object nomeado (events, sections, semaphores…).
- Symbolic links ou reparse points podem apontar um nome curto de “victim” para esse componente gigante, fazendo com que o slowdown seja aplicado de forma transparente.
- Como tudo reside em namespaces graváveis pelo usuário, o payload funciona a partir de um nível de integridade de usuário padrão.<sup>[[1]](#references)</sup>

## Primitiva de slowdown nº 2 – Diretórios recursivos profundos

Uma variante mais agressiva aloca uma cadeia de milhares de diretórios (`\BaseNamedObjects\A\A\...\X`). Cada salto aciona a lógica de resolução de diretórios (verificações de ACL, consultas de hash, contagem de referências), portanto a latência por nível é maior do que a de uma única comparação de strings. Com aproximadamente 16 000 níveis (limitados pelo mesmo tamanho de `UNICODE_STRING`), as medições empíricas ultrapassam a barreira de 35 µs obtida com componentes únicos longos.
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
* Mantenha um array de handles para poder excluir a chain de forma limpa após a exploração e evitar poluir o namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutos em vez de microssegundos)

Os diretórios de objetos oferecem **shadow directories** (lookups de fallback) e tabelas hash divididas em buckets para as entradas. Abuse de ambos, além do limite de reparse de 64 componentes de symbolic-link, para multiplicar o slowdown sem exceder o tamanho de `UNICODE_STRING`:

1. Crie dois diretórios em `\BaseNamedObjects`, por exemplo, `A` (shadow) e `A\A` (target). Crie o segundo usando o primeiro como shadow directory (`NtCreateDirectoryObjectEx`), para que os lookups ausentes em `A` sejam encaminhados para `A\A`.
2. Preencha cada diretório com milhares de **colliding names** que caiam no mesmo hash bucket (por exemplo, variando os dígitos finais enquanto mantém o mesmo valor de `RtlHashUnicodeString`). Os lookups agora degradam para scans lineares O(n) dentro de um único diretório.
3. Construa uma chain de aproximadamente 63 **object manager symbolic links** que façam reparse repetidamente para o sufixo longo `A\A\…`, consumindo o reparse budget. Cada reparse reinicia o parsing a partir do topo, multiplicando o custo das colisões.
4. O lookup do componente final (`...\\0`) agora leva **minutos** no Windows 11 quando há 16 000 colisões por diretório, proporcionando uma vitória de race praticamente garantida para kernel LPEs one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por que isso importa*: Uma desaceleração de vários minutos transforma LPEs baseados em race condition de tentativa única em exploits determinísticos.<sup>[[1]](#references)</sup>

### Notas do reteste de 2025 e tooling pronto

- James Forshaw republicou a técnica com timings atualizados no Windows 11 24H2 (ARM64). As aberturas de baseline continuam em ~2 µs; um componente de 32 kB eleva esse valor para ~35 µs, e as cadeias shadow-dir + collision + 63-reparse ainda chegam a ~3 minutos, confirmando que os primitives sobrevivem nas builds atuais. O código-fonte e o perf harness estão na publicação atualizada do Project Zero.<sup>[[1]](#references)</sup>
- Você pode automatizar a configuração usando o bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para criar o par shadow/target e `NativeSymlink.exe` em um loop para emitir a cadeia de 63 hops. Isso evita wrappers `NtCreate*` escritos manualmente e mantém as ACLs consistentes.<sup>[[2]](#references)</sup>

## Medindo sua race window

Inclua um harness rápido no seu exploit para medir o tamanho que a window atinge no hardware da vítima. O snippet abaixo abre o objeto-alvo `iterations` vezes e retorna o custo médio por abertura usando `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Os resultados alimentam diretamente sua estratégia de orquestração da race (por exemplo, o número de worker threads necessários, os intervalos de sleep e quão cedo você precisa alternar o estado compartilhado).

## Fluxo de exploração

1. **Localize a abertura vulnerável** – Rastreie o caminho do kernel (por meio de símbolos, ETW, hypervisor tracing ou reversing) até encontrar uma chamada `NtOpen*`/`ObOpenObjectByName` que percorra um nome controlado pelo atacante ou um symbolic link em um diretório gravável pelo usuário.
2. **Substitua esse nome por um caminho lento**
- Crie o componente longo ou a cadeia de diretórios em `\BaseNamedObjects` (ou em outra raiz gravável do OM).
- Crie um symbolic link para que o nome esperado pelo kernel agora seja resolvido para o caminho lento. Você pode direcionar a busca de diretório do driver vulnerável para sua estrutura sem tocar no alvo original.
3. **Dispare a race**
- A Thread A (vítima) executa o código vulnerável e bloqueia dentro da busca lenta.
- A Thread B (atacante) alterna o estado protegido (por exemplo, troca um file handle, reescreve um symbolic link ou alterna a segurança do objeto) enquanto a Thread A está ocupada.
- Quando a Thread A retoma a execução e realiza a ação privilegiada, ela observa um estado obsoleto e executa a operação controlada pelo atacante.
4. **Faça a limpeza** – Exclua a cadeia de diretórios e os symbolic links para evitar deixar artefatos suspeitos ou interromper usuários legítimos de IPC.<sup>[[1]](#references)</sup>

## Cadeia aplicada: Cloud Files placeholders mutáveis + alternância de caminhos do Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), publicado como um bypass para RoguePlanet (CVE-2026-50656), demonstra um padrão de exploração mais amplo: fazer um scanner privilegiado classificar uma representação de um arquivo lógico e, em seguida, alterar tanto seus bytes quanto a resolução de namespace antes que a remediation a utilize. O PoC combina uma TOCTOU de hydration do Cloud Files, um fallback de shadow-directory do Object Manager, a captura de nomes gerados pelo CLFS e um link de compartilhamento administrativo local para transformar a limpeza do Defender em uma escrita de DLL protegida.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitua o conteúdo por meio da hydration do Cloud Files

Registre um diretório gravável pelo atacante como uma sync root do Cloud Files, conecte um callback `CF_CALLBACK_TYPE_FETCH_DATA` e crie um placeholder cujo tamanho anunciado corresponda a um gatilho de detecção determinístico, como o EICAR ZIP. O primeiro fetch retorna o gatilho e alterna o estado do callback; os fetches posteriores retornam o payload. Depois que o scanner classificar a primeira representação, obtenha a transfer key e reinicie a hydration com metadados do tamanho do payload; em seguida, force a hydration até EOF.<sup>[[4]](#references)</sup>
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
A fronteira de segurança falha se a verificação, a decisão e a remediação se referirem apenas a um pathname ou a uma identidade de placeholder: nenhuma delas garante que uma hidratação posterior retorne os bytes que foram inspecionados.<sup>[[4]](#references)</sup>

### 2. Alterne um caminho invariável por meio de um fallback de shadow-directory

Crie um diretório do Object Manager de destino e um segundo diretório com `NtCreateDirectoryObjectEx`, passando o handle do destino como diretório de shadow/fallback. Coloque uma entrada `WD_SCAN` com o mesmo nome em ambas as camadas de resolução: a entrada visível aponta para o diretório de trabalho normal, enquanto a entrada de fallback aponta para `\CLFS\??\<working-directory>`. Forneça ao Defender apenas o caminho invariável abaixo; excluir o link visível enquanto a operação está ativa faz com que a mesma string passe para a entrada apoiada pelo CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Isso é diferente de usar diretórios shadow apenas para desacelerar a pesquisa: o atacante altera o **significado** de um caminho previamente aceito sem modificar sua string.<sup>[[4]](#references)</sup>

### 3. Capture o nome gerado e instale um link específico para o filename

Monitore o diretório de trabalho com `ReadDirectoryChangesW`. Na primeira ocorrência de `FILE_ACTION_ADDED`, remova o link visível `WD_SCAN` para ativar a pesquisa de fallback. Capture o segundo filename gerado, abra esse arquivo relacionado ao CLFS e bloqueie o intervalo `0..MAXLONGLONG` com `LockFileEx`. Enquanto a operação privilegiada estiver paralisada, substitua `WD_SCAN` no diretório visível por um diretório real do Object Manager e crie um symbolic link filho nomeado a partir do filename observado (o PoC remove seus quatro caracteres finais). Aponte-o para o destino protegido por meio de SMB local:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
O processo sem privilégios não pode gravar nesse destino por conta própria, mas o contexto SYSTEM do Defender pode atravessar o administrative share de loopback. Combinar a observação de nomes gerados com um link do Object Manager específico para o nome do arquivo evita a necessidade de prever antecipadamente o artefato de remediação.<sup>[[4]](#references)</sup>

### 4. Estabilizar a race de limpeza e acionar um loader privilegiado

Antes da varredura, o PoC armazena um PE válido (`ntdll.dll`) no alternate data stream NTFS `:stream` do placeholder. Depois que o redirecionamento cria o arquivo base protegido, ele abre `phoneinfo.dll:stream` com acesso de execução e mantém um mapeamento `PAGE_EXECUTE_READ | SEC_IMAGE` ativo enquanto a limpeza é retomada; os objetos de arquivo/seção ativos restringem a exclusão ou substituição durante a race final. A hydration reiniciada agora retorna a payload DLL em vez de EICAR, portanto o arquivo base protegido contém código controlado pelo atacante.<sup>[[4]](#references)</sup>

Uma escrita protegida é então convertida em execução SYSTEM ao posicionar um `Report.wer` criado sob `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` e invocar `\Microsoft\Windows\Windows Error Reporting\QueueReporting` por meio da Task Scheduler COM API. Nessa chain, o processamento privilegiado do WER carrega o `C:\Windows\System32\phoneinfo.dll` implantado; uma conexão de named pipe é usada como sinal de execução da payload.<sup>[[4]](#references)</sup>

### Pivôs de detecção

Correlações úteis são mais específicas do que qualquer nome temporário isolado e abrangem todas as transições de namespace na chain:<sup>[[4]](#references)</sup>

- Um provedor Cloud Files registrado recentemente, seguido pela detecção de EICAR e por `CF_OPERATION_TYPE_RESTART_HYDRATION` no mesmo placeholder.
- Caminhos do Object Manager contendo `WD_TARGET_*`, `WD_SHADOW_*` ou `WD_SCAN`, especialmente um caminho de varredura abaixo de `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Criação de arquivo CLFS seguida por um bloqueio exclusivo do arquivo inteiro e acesso de loopback a `\\127.0.0.1\C$\Windows\System32\*.dll` a partir de um processo de segurança privilegiado.
- Criação de uma DLL em System32 junto com um NTFS ADS, seguida pelo mapeamento `SEC_IMAGE` do stream.
- Uma entrada de fila WER criada pelo atacante, seguida por uma execução manual incomum de `\Microsoft\Windows\Windows Error Reporting\QueueReporting` e pelo carregamento da imagem da DLL implantada.

## Chain aplicada: troca de mount point controlada por oplock contra remediação privilegiada

Um padrão reutilizável de LPE aparece quando um scanner privilegiado verifica um arquivo controlado pelo atacante e depois o remedia reabrindo o **pathname**, em vez de continuar usando handles validados. FalconFlank é um exemplo público direcionado ao workflow de remoção de macros do Office do CrowdStrike Falcon; o repositório afirma ter sido testado no Windows 11 25H2 e no Windows Server 2025 com a política relevante habilitada, mas não publica CVE, intervalo de builds afetados, advisory do fornecedor ou status de patch, portanto trate a afirmação específica do produto como não verificada e dependente do build.<sup>[[5]](#references)[[6]](#references)</sup>

### Estrutura da race

1. Crie uma árvore gravável cujo nome relativo final seja útil no destino pretendido. O exemplo usa `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, mas inicialmente grava um documento com macro OLE — e não uma DLL PE — em `bcrypt.dll`. A detecção baseada em conteúdo aciona a remediação, enquanto o basename controlado pelo atacante é preservado para o side-load posterior.<sup>[[5]](#references)</sup>
2. Abra os diretórios com compartilhamento amplo e `FILE_OPEN_REPARSE_POINT`, depois solicite um oplock RH assíncrono no trigger usando `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` e `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Aguarde o evento overlapped e use sua conclusão como indicação para a troca de caminho. Uma notificação de quebra de oplock RH é apenas consultiva, e não uma prova de que toda operação conflitante está bloqueada; portanto, a explorabilidade ainda depende da sequência exata de abertura/remediação da vítima.<sup>[[5]](#references)[[7]](#references)</sup>
3. Após a quebra, remova o diretório folha com `FileDispositionInformationEx` (information class 64), usando flags de exclusão mais semântica POSIX, feche seu handle e aplique um `IO_REPARSE_TAG_MOUNT_POINT` ao parent agora vazio com `FSCTL_SET_REPARSE_POINT_EX`. O mount point redireciona o sufixo inalterado para uma árvore protegida, como `\\SystemRoot\\System32\\WindowsPowerShell`; definir um reparse point falha se o diretório não estiver vazio, o que explica a etapa de exclusão anterior.<sup>[[5]](#references)[[8]](#references)</sup>
4. Retome o workflow privilegiado. Se ele resolver a string novamente sem provar que a cadeia de diretórios e o objeto final são os mesmos inspecionados anteriormente, o mesmo pathname lógico agora alcança o diretório protegido selecionado pelo atacante. No exemplo, o sucesso é testado reabrindo `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` para leitura/escrita a partir do processo original; isso diferencia a primitive de escrita confused-deputy da etapa posterior de code execution.<sup>[[5]](#references)</sup>
5. Substitua o arquivo resultante pela DLL real e ative um loader privilegiado. O PoC usa `CreateTransaction` + `CreateFileTransacted`, trunca o arquivo, mapeia a substituição do tamanho da DLL, copia o PE e faz commit; o TxF vincula o file handle e as operações subsequentes baseadas em handle à transaction, mas é um mecanismo de substituição pós-race, e não a origem da falha no limite de privilégio.<sup>[[5]](#references)[[9]](#references)</sup>
6. Por fim, execute uma scheduled task privilegiada existente cujo executável procure o filename adjacente implantado. FalconFlank invoca `\\Microsoft\\Windows\\Application Experience\\MareBackup`, aguarda a conexão da DLL com `\\??\\pipe\\FALCONFLANK` e então exclui o arquivo implantado. Não presuma um token resultante específico apenas pelo nome da task — verifique o processo iniciado, o module path, o integrity level e o token no build testado.<sup>[[5]](#references)</sup>

A questão central da auditoria, portanto, não é “o serviço valida o input path original?”, mas “toda mutação privilegiada permanece vinculada aos mesmos objetos de arquivo e diretório abertos que foram validados?”. Manter handles durante a verificação e o uso, abrir objetos filhos relativos a um handle de diretório confiável, rejeitar reparse tags inesperadas e revalidar a identidade do arquivo antes da mutação encerram essa classe de bug de substituição de pathname.<sup>[[1]](#references)[[8]](#references)</sup>

### Detecção e triagem do PoC

A detecção de alto sinal correlaciona a transição de namespace com o consumidor privilegiado: um cabeçalho OLE sob um basename de DLL em uma árvore temporária nomeada com GUID, uma quebra de oplock, a remoção em estilo POSIX do diretório folha, a criação de um mount point direcionado a um diretório protegido do Windows e a criação ou modificação do mesmo basename abaixo desse destino. Para o exemplo público, adicione `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, a execução manual de `MareBackup` e o named pipe `FALCONFLANK` como pivôs mais restritos; nenhum deles é suficiente isoladamente.<sup>[[5]](#references)</sup>

Ao reproduzir o PoC, considere três defeitos de confiabilidade no código-fonte publicado: ele chama `FlushFileBuffers` com o ponteiro do byte-array incorporado em vez do file handle, testa um `HRESULT` obsoleto após `GetFolder`, `GetTask` e `Run`, e usa loops de retry/wait sem limite para a exclusão do diretório, a criação do reparse, o evento de oplock e a conexão do pipe.<sup>[[5]](#references)</sup>

## Considerações operacionais

- **Combinar primitives** – Você pode usar um nome longo *por nível* em uma cadeia de diretórios para obter uma latência ainda maior, até esgotar o tamanho de `UNICODE_STRING`.
- **Bugs de disparo único** – A janela ampliada (de dezenas de microssegundos a minutos) torna realistas os bugs de “trigger único” quando combinados com fixação de afinidade de CPU ou preempção assistida por hypervisor.
- **Efeitos colaterais** – A lentidão afeta apenas o caminho malicioso, portanto o desempenho geral do sistema permanece inalterado; os defenders raramente perceberão, a menos que monitorem o crescimento do namespace.
- **Limpeza** – Mantenha handles para todos os diretórios/objetos criados para que possa chamar `NtMakeTemporaryObject`/`NtClose` depois. Caso contrário, cadeias de diretórios sem limite podem persistir após reinicializações.
- **Races de sistema de arquivos** – Se o caminho vulnerável acabar sendo resolvido por NTFS, você pode adicionar um Oplock (por exemplo, `SetOpLock.exe` do mesmo toolkit) ao arquivo de suporte enquanto o slowdown do OM estiver em execução, congelando o consumidor por milissegundos adicionais sem alterar o grafo do OM.<sup>[[2]](#references)</sup>

## Notas defensivas

- O código do kernel que depende de objetos nomeados deve revalidar o estado sensível à segurança *após* a abertura ou obter uma referência antes da verificação (fechando a lacuna de TOCTOU).
- Aplique limites superiores à profundidade/tamanho do caminho do OM antes de desreferenciar nomes controlados pelo usuário. Rejeitar nomes excessivamente longos força os atacantes a voltar à janela de microssegundos.
- Instrumente o crescimento do namespace do Object Manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadeias suspeitas com milhares de componentes sob `\BaseNamedObjects`.

## References

- [1] [Project Zero – Técnicas de Exploitation do Windows: vencendo Races com Consultas de Caminho](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Como usar o NTFS transacional](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
