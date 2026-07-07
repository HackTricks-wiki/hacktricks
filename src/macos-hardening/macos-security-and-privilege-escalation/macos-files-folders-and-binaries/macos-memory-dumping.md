# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Arquivos de swap, como `/private/var/vm/swapfile0`, servem como **caches quando a memória física está cheia**. Quando não há mais espaço na memória física, seus dados são transferidos para um arquivo de swap e então trazidos de volta para a memória física conforme necessário. Vários arquivos de swap podem estar presentes, com nomes como swapfile0, swapfile1 e assim por diante.

### Hibernate Image

O arquivo localizado em `/private/var/vm/sleepimage` é crucial durante o **modo de hibernação**. **Os dados da memória são armazenados neste arquivo quando o OS X hiberna**. Ao despertar o computador, o sistema recupera os dados de memória desse arquivo, permitindo ao usuário continuar de onde parou.

Vale notar que, em sistemas MacOS modernos, esse arquivo geralmente é criptografado por motivos de segurança, tornando a recuperação difícil.

- Para verificar se a criptografia está habilitada para o sleepimage, o comando `sysctl vm.swapusage` pode ser executado. Isso mostrará se o arquivo está criptografado.

### Memory Pressure Logs

Outro arquivo importante relacionado à memória em sistemas MacOS é o **memory pressure log**. Esses logs estão localizados em `/var/log` e contêm informações detalhadas sobre o uso de memória do sistema e eventos de pressão. Eles podem ser particularmente úteis para diagnosticar problemas relacionados à memória ou entender como o sistema gerencia a memória ao longo do tempo.

## Dumping memory with osxpmem

Para fazer dump da memória em uma máquina MacOS você pode usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: isso é principalmente um **fluxo legado** hoje em dia. `osxpmem` depende do carregamento de uma kernel extension, o projeto [Rekall](https://github.com/google/rekall) está arquivado, a versão mais recente é de **2017**, e o binário publicado é voltado para **Intel Macs**. Em versões atuais do macOS, especialmente em **Apple Silicon**, a aquisição completa da RAM via kext geralmente é bloqueada por restrições modernas de kernel extension, SIP e requisitos de assinatura da plataforma. Na prática, em sistemas modernos, você com mais frequência acabará fazendo um **process-scoped dump** em vez de uma imagem de RAM completa.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se você encontrar este erro: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Você pode corrigir isso fazendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Outros erros** podem ser corrigidos **permitindo o carregamento do kext** em "Security & Privacy --> General", basta **allow** isso.

Você também pode usar este **oneliner** para baixar a aplicação, carregar o kext e fazer dump da memória:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping de processo ao vivo com LLDB

Para **versões recentes do macOS**, a abordagem mais prática geralmente é despejar a memória de um **processo específico** em vez de tentar capturar toda a memória física.

O LLDB pode salvar um arquivo core Mach-O de um alvo em execução:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Por padrão, isso normalmente cria um **skinny core**. Para forçar o LLDB a incluir toda a memória mapeada do processo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandos úteis de acompanhamento antes de fazer o dump:
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
- Tokens, cookies ou credentials em memória
- Secrets em plaintext que estão protegidos apenas em repouso
- Páginas Mach-O descriptografadas após unpacking / JIT / runtime patching

Se o alvo estiver protegido pelo **hardened runtime**, ou se `taskgated` negar o attach, normalmente você precisa de uma destas condições:

- O alvo possui **`get-task-allow`**
- Seu debugger está assinado com a **debugger entitlement** apropriada
- Você é **root** e o alvo é um processo de terceiros não hardened

Para mais contexto sobre obter um task port e o que pode ser feito com ele:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Antes de gastar tempo com LLDB/Frida, verifique rapidamente se o alvo é realisticamente **dumpable**:
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

- Um app de terceiros distribuído com **`get-task-allow`** muitas vezes pode ser dumpado diretamente com LLDB, e o dump resultante pode expor dados protegidos por TCC que o app já acessou.
- Um alvo **hardened** sem `get-task-allow` normalmente rejeitará attaches, mesmo como `root`, a menos que você controle os entitlements relevantes do debugger / caminho de policy.
- Processos de terceiros unhardened ainda são o lugar mais fácil para usar `lldb`, `vmmap`, Frida, ou readers customizados de `task_for_pid`/`vm_read`.

## Selective dumps with Frida or userland readers

Quando um core completo é muito ruidoso, dumpar apenas **faixas legíveis interessantes** costuma ser mais rápido. Frida é especialmente útil porque funciona bem para **extração direcionada** depois que você consegue attach ao processo.

Abordagem de exemplo:

1. Enumerar faixas legíveis/graváveis
2. Filtrar por módulo, heap, stack, ou memória anônima
3. Dumpar apenas as regiões que contenham strings candidatas, keys, protobufs, blobs plist/XML, ou code/data descriptografados

Exemplo mínimo de Frida para dumpar todas as faixas anônimas legíveis:
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
Isso é útil quando você quer evitar giant core files e coletar apenas:

- App heap chunks contendo secrets
- Regiões anonymous criadas por custom packers ou loaders
- Páginas de código JIT / unpacked after changing protections

Ferramentas userland mais antigas, como [`readmem`](https://github.com/gdbinit/readmem), também existem, mas são principalmente úteis como **source references** para direct `task_for_pid`/`vm_read` style dumping e não são bem mantidas para fluxos de trabalho modernos de Apple Silicon.

## Heap / VM snapshots with `.memgraph`

Se você se importa principalmente com **heap objects**, **allocation provenance**, ou um snapshot que possa ser movido para outra máquina, um `.memgraph` geralmente é mais prático do que um giant Mach-O core. A ferramenta `leaks` pode gerar um a partir de um processo em execução:
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
`stringdups` é o principal motivo para manter uma captura `-fullContent`, porque os rótulos que descrevem o conteúdo da memória são omitidos de um `.memgraph` mínimo.

Isso é especialmente útil quando:

- Você quer um **snapshot menor e compartilhável** em vez de um core completo
- `MallocStackLogging` estava habilitado e você quer **backtraces de alocação**
- Você já conhece um **endereço de heap interessante** e quer pivotar com `malloc_history`
- Você precisa de um rápido **resumo de VM/heap** antes de decidir se um dump completo vale o ruído

## Swift-heavy targets: `swift-inspect`

Para aplicações que mantêm dados de alto valor dentro de **objetos de runtime do Swift**, `swift-inspect` pode ser um bom complemento ao LLDB ou Frida. Em vez de despejar tudo primeiro, você pode consultar estruturas específicas do runtime do Swift de um processo ao vivo:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Isto é útil para identificar:

- Grandes arrays Swift que armazenam dados interessantes
- Alocações de metadata que revelam tipos carregados em tempo de execução
- Estado de concorrência do Swift (`Task`, actor, relações de thread) antes de fazer um dump mais direcionado

Para uma triagem de runtime mais específica por objeto, quando você já consegue inspecionar o processo, veja [a página dedicada a objetos em memória](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` ainda é uma forma rápida de verificar o **uso de swap** e se a swap está **encrypted**.
- `sleepimage` continua relevante principalmente para cenários de **hibernate/safe sleep**, mas sistemas modernos normalmente o protegem, então deve ser tratado como uma **fonte de artefato para verificar**, e não como um caminho confiável de aquisição.
- Em versões recentes do macOS, o **process-level dumping** geralmente é mais realista do que a **full physical memory imaging**, a menos que você controle a política de boot, o estado do SIP e o carregamento de kext.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
