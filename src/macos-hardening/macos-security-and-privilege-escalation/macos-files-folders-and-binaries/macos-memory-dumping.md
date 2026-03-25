# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Arquivos de swap, como `/private/var/vm/swapfile0`, servem como **cache quando a memória física está cheia**. Quando não há mais espaço na memória física, seus dados são transferidos para um arquivo de swap e depois trazidos de volta para a memória física conforme necessário. Vários arquivos de swap podem estar presentes, com nomes como swapfile0, swapfile1, e assim por diante.

### Hibernate Image

O arquivo localizado em `/private/var/vm/sleepimage` é crucial durante o **modo de hibernação**. **Dados da memória são armazenados neste arquivo quando o OS X hiberna**. Ao acordar o computador, o sistema recupera os dados de memória desse arquivo, permitindo que o usuário continue de onde parou.

Vale notar que em sistemas MacOS modernos, este arquivo costuma ser criptografado por motivos de segurança, tornando a recuperação difícil.

- Para verificar se a criptografia está habilitada para o sleepimage, o comando `sysctl vm.swapusage` pode ser executado. Isso mostrará se o arquivo está criptografado.

### Memory Pressure Logs

Outro arquivo importante relacionado à memória em sistemas MacOS é o **log de pressão de memória**. Esses logs estão localizados em `/var/log` e contêm informações detalhadas sobre o uso de memória do sistema e eventos de pressão de memória. Eles podem ser particularmente úteis para diagnosticar problemas relacionados à memória ou entender como o sistema gerencia a memória ao longo do tempo.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: This is mostly a **legacy workflow** now. `osxpmem` depends on loading a kernel extension, the [Rekall](https://github.com/google/rekall) project is archived, the latest release is from **2017**, and the published binary targets **Intel Macs**. On current macOS releases, especially on **Apple Silicon**, kext-based full-RAM acquisition is usually blocked by modern kernel-extension restrictions, SIP, and platform-signing requirements. In practice, on modern systems you will more often end up doing a **process-scoped dump** instead of a whole-RAM image.
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
**Outros erros** podem ser corrigidos permitindo o carregamento do kext em "Security & Privacy --> General", basta **allow**.

Você também pode usar este **oneliner** para baixar a aplicação, carregar o kext e dump the memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Despejo de processo ao vivo com LLDB

Para **versões recentes do macOS**, a abordagem mais prática costuma ser despejar a memória de um **processo específico** em vez de tentar obter uma imagem de toda a memória física.

LLDB pode salvar um Mach-O core file a partir de um alvo em execução:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Por padrão isso geralmente cria um **skinny core**. Para forçar o LLDB a incluir toda a memória mapeada do processo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandos úteis a executar antes do dumping:
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
- Tokens em memória, cookies ou credenciais
- Segredos em texto simples que são protegidos apenas quando em repouso
- Páginas Mach-O descriptografadas após unpacking / JIT / runtime patching

Se o alvo for protegido pelo **hardened runtime**, ou se `taskgated` negar o attach, normalmente você precisa de uma destas condições:

- O alvo possui **`get-task-allow`**
- Seu debugger está assinado com o **debugger entitlement** apropriado
- Você é **root** e o alvo é um processo de terceiros não-hardened

Para mais contexto sobre como obter um task port e o que pode ser feito com ele:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selective dumps with Frida or userland readers

Quando um core completo é muito ruidoso, extrair apenas os **intervalos legíveis interessantes** costuma ser mais rápido. Frida é especialmente útil porque funciona bem para **extração direcionada** assim que você consegue anexar ao processo.

Exemplo de abordagem:

1. Enumerar intervalos legíveis/escritíveis
2. Filtrar por módulo, heap, stack ou memória anônima
3. Extrair apenas as regiões que contêm strings candidatas, chaves, protobufs, blobs plist/XML, ou código/dados descriptografados

Exemplo mínimo de Frida para extrair todos os intervalos anônimos legíveis:
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
Isto é útil quando você quer evitar arquivos core gigantes e coletar apenas:

- Partes do heap do App contendo segredos
- Regiões anônimas criadas por custom packers ou loaders
- JIT / páginas de código desempacotadas após alterar as proteções

Ferramentas userland mais antigas, como [`readmem`](https://github.com/gdbinit/readmem), também existem, mas são úteis principalmente como **referências de origem** para despejo estilo `task_for_pid`/`vm_read` e não são bem mantidas para fluxos de trabalho modernos do Apple Silicon.

## Notas rápidas de triagem

- `sysctl vm.swapusage` continua sendo uma forma rápida de verificar o **uso de swap** e se o swap está **criptografado**.
- `sleepimage` permanece relevante principalmente para cenários de **hibernação/suspensão segura**, mas sistemas modernos normalmente o protegem, portanto deve ser tratado como uma **fonte de artefatos a verificar**, não como um caminho confiável de aquisição.
- Em lançamentos recentes do macOS, **process-level dumping** geralmente é mais realista do que **full physical memory imaging**, a menos que você controle o boot policy, o SIP state e o kext loading.

## Referências

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
