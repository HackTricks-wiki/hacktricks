# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos de memória

### Arquivos de swap

Os arquivos de swap, como `/private/var/vm/swapfile0`, funcionam como **caches quando a memória física está cheia**. Quando não há mais espaço na memória física, os dados são transferidos para um arquivo de swap e depois trazidos de volta para a memória física conforme necessário. Pode haver vários arquivos de swap, com nomes como swapfile0, swapfile1 e assim por diante.

### Imagem de hibernação

O arquivo localizado em `/private/var/vm/sleepimage` é essencial durante o **modo de hibernação**. **Os dados da memória são armazenados nesse arquivo quando o OS X hiberna**. Ao reativar o computador, o sistema recupera os dados da memória desse arquivo, permitindo que o usuário continue de onde parou.

Vale mencionar que, em sistemas MacOS modernos, esse arquivo normalmente é criptografado por motivos de segurança, dificultando a recuperação.

- Para verificar se a criptografia está habilitada para o sleepimage, o comando `sysctl vm.swapusage` pode ser executado. Ele mostrará se o arquivo está criptografado.

### Logs de pressão de memória

Outro arquivo importante relacionado à memória nos sistemas MacOS é o **log de pressão de memória**. Esses logs estão localizados em `/var/log` e contêm informações detalhadas sobre o uso da memória do sistema e os eventos de pressão. Eles podem ser particularmente úteis para diagnosticar problemas relacionados à memória ou entender como o sistema gerencia a memória ao longo do tempo.

## Dumping de memória com osxpmem

Para fazer o dumping da memória em uma máquina MacOS, você pode usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Atualmente, este é principalmente um **workflow legado**. O `osxpmem` depende do carregamento de uma extensão do kernel, o projeto [Rekall](https://github.com/google/rekall) foi arquivado, a versão mais recente é de **2017**, e o binário publicado é direcionado a **Macs Intel**. Nas versões atuais do macOS, especialmente no **Apple Silicon**, a aquisição de RAM completa baseada em kext normalmente é bloqueada pelas restrições modernas às extensões do kernel, pelo SIP e pelos requisitos de assinatura da plataforma. Na prática, em sistemas modernos, com mais frequência você acabará fazendo um **dump com escopo de processo** em vez de obter uma imagem completa da RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se você encontrar este erro: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Você pode corrigi-lo fazendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Outros erros** podem ser corrigidos **permitindo o carregamento do kext** em "Security & Privacy --> General"; basta **permiti-lo**.

Você também pode usar este **oneliner** para baixar o aplicativo, carregar o kext e fazer o dump da memória:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping de processos ativos com LLDB

Nas **versões recentes do macOS**, a abordagem mais prática geralmente é fazer o dump da memória de um **processo específico**, em vez de tentar criar uma imagem de toda a memória física.

O LLDB pode salvar um arquivo core Mach-O a partir de um target ativo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Por padrão, isso geralmente cria um **skinny core**. Para forçar o LLDB a incluir toda a memória mapeada do processo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandos úteis de follow-up antes do dump:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Isso geralmente é suficiente quando o objetivo é recuperar:

- Blobs de configuração descriptografados
- Tokens, cookies ou credenciais na memória
- Secrets em texto simples protegidos apenas em repouso
- Páginas Mach-O descriptografadas após unpacking / JIT / runtime patching

Se o alvo estiver protegido pelo **hardened runtime**, ou se `taskgated` negar o attach, normalmente você precisará de uma destas condições:

- O alvo possui **`get-task-allow`**
- Seu debugger está assinado com o **debugger entitlement** apropriado
- Você é **root** e o alvo é um processo de terceiros que não usa hardened runtime

Para obter mais informações sobre como obter uma task port e o que pode ser feito com ela:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Verificações rápidas antes do attach

Antes de investir tempo no LLDB/Frida, verifique rapidamente se o alvo é realisticamente **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operacionalmente, isso geralmente significa:

- Um app de terceiros distribuído com **`get-task-allow`** geralmente pode ser diretamente analisado com LLDB, e o dump resultante pode expor dados protegidos pelo TCC aos quais o app já teve acesso.<sup>[1]</sup>
- Um alvo **hardened** sem `get-task-allow` normalmente rejeitará attaches, mesmo como `root`, a menos que você controle os entitlements do debugger / o caminho de policy relevante.
- Processos de terceiros não hardened ainda são o local mais fácil para usar `lldb`, `vmmap`, Frida ou readers personalizados de `task_for_pid`/`vm_read`.

### Procure nested helpers dumpable

Pesquisas recentes sobre apps macOS notarized continuam encontrando **`get-task-allow`** em nested helpers, em vez do binário GUI principal. Quando um app de nível superior parece hardened, enumere seus **serviços XPC**, **login items**, **helper tools** e CLIs incluídos antes de desistir:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Um executável aninhado com `get-task-allow` costuma ser o local mais fácil para fazer attach com `lldb`, gerar um core ou extrair memória com um cliente `task_for_pid` personalizado, mesmo quando o app principal possui hardening mais rigoroso.

## Dumps seletivos com Frida ou readers em userland

Quando um core completo gera muito ruído, fazer dump apenas dos **intervalos legíveis interessantes** costuma ser mais rápido. O Frida é especialmente útil porque funciona bem para **extração direcionada** depois que você consegue fazer attach ao processo.

Abordagem básica:

1. Enumerar os intervalos legíveis/graváveis
2. Filtrar por módulo, heap, stack ou memória anônima
3. Fazer dump apenas das regiões que contêm strings candidatas, keys, protobufs, blobs plist/XML ou código/dados descriptografados

Exemplo mínimo de Frida para fazer dump de todos os intervalos anônimos legíveis:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Isso é útil quando você quer evitar arquivos core gigantes e coletar apenas:

- Chunks de heap do App contendo secrets
- Regiões anônimas criadas por packers ou loaders customizados
- Páginas de código JIT / unpacked após alterar as proteções

Quando o target continua **alocando / liberando** memória enquanto você faz o dump, prefira a primitiva **`readVolatile()`** do Frida em vez de **`readByteArray()`** para ranges instáveis. Ela é mais lenta, mas evita encerrar o target caso uma página se torne ilegível durante a leitura. Para aquisições maiores, também pode ser mais organizado transmitir os chunks de volta com `send(..., data)` e compactá-los no controller, em vez de criar milhares de arquivos pequenos dentro do target.

Ferramentas userland mais antigas, como [`readmem`](https://github.com/gdbinit/readmem), também existem, mas são principalmente úteis como **referências de código-fonte** para dumping direto no estilo `task_for_pid`/`vm_read` e não são bem mantidas para workflows modernos em Apple Silicon.

## Snapshots de Heap / VM com `.memgraph`

Se você se importa principalmente com **objetos do heap**, **proveniência das alocações** ou um snapshot que possa ser movido para outra máquina, um `.memgraph` costuma ser mais prático do que um core Mach-O gigante. As ferramentas `leaks` podem gerar um a partir de um processo em execução:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Então faça a triagem offline com as ferramentas padrão da Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` é o principal motivo para manter uma captura `-fullContent`, pois os labels que descrevem o conteúdo da memória são omitidos de um `.memgraph` minimal.

Isso é especialmente útil quando:

- Você quer um **snapshot menor e compartilhável** em vez de um full core
- `MallocStackLogging` estava habilitado e você quer **allocation backtraces**
- Você já conhece um **heap address interessante** e quer fazer pivot com `malloc_history`
- Você precisa de uma análise rápida de **VM/heap** antes de decidir se vale a pena lidar com o ruído de um dump completo

### Triagem diferencial de memgraph

Se você controla como o target é iniciado, habilite o **historical allocation logging** antes do launch para que snapshots posteriores preservem backtraces úteis de alloc/free:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Em seguida, capture snapshots em torno da ação interessante e compare-os offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Esta é uma maneira prática de isolar **objetos pós-autenticação**, **buffers `CFData` grandes** ou **regiões de VM anônimas** que só aparecem após uma etapa de descriptografia, desempacotamento ou recuperação de secrets.

## Targets com muito Swift: `swift-inspect`

Para aplicações que mantêm dados de alto valor dentro de **objetos do runtime do Swift**, `swift-inspect` pode ser um bom complemento ao LLDB ou Frida. Em vez de fazer o dump de tudo primeiro, você pode consultar estruturas específicas do runtime do Swift em um processo ativo:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Isso é útil para identificar:

- Grandes arrays Swift armazenando dados interessantes
- Alocações de metadata que revelam tipos carregados em runtime
- Estado de concorrência do Swift (`Task`, relações entre actors e threads) antes de realizar um dump mais direcionado

Para uma triagem em nível de objeto em runtime, depois que você já conseguir inspecionar o processo, consulte [a página dedicada a objetos na memória](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Notas de triagem rápida

- `sysctl vm.swapusage` ainda é uma forma rápida de verificar o **uso de swap** e se o swap está **criptografado**.
- `sleepimage` continua sendo relevante principalmente em cenários de **hibernate/safe sleep**, mas os sistemas modernos geralmente o protegem; portanto, ele deve ser tratado como uma **fonte de artefatos a verificar**, não como um caminho de aquisição confiável.
- Nas versões recentes do macOS, o **dump em nível de processo** geralmente é mais realista do que a **imagem completa da memória física**, a menos que você controle a política de boot, o estado do SIP e o carregamento de kexts.

## Referências

- [1] [Permitir ou não get-task-allow: análise de segurança do macOS](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [página man de leaks(1)](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
