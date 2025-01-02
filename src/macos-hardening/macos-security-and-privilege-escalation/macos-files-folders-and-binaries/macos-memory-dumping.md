# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Os arquivos de swap, como `/private/var/vm/swapfile0`, servem como **caches quando a memória física está cheia**. Quando não há mais espaço na memória física, seus dados são transferidos para um arquivo de swap e, em seguida, trazidos de volta para a memória física conforme necessário. Vários arquivos de swap podem estar presentes, com nomes como swapfile0, swapfile1 e assim por diante.

### Hibernate Image

O arquivo localizado em `/private/var/vm/sleepimage` é crucial durante o **modo de hibernação**. **Os dados da memória são armazenados neste arquivo quando o OS X hiberna**. Ao acordar o computador, o sistema recupera os dados da memória deste arquivo, permitindo que o usuário continue de onde parou.

Vale ressaltar que em sistemas MacOS modernos, este arquivo é tipicamente criptografado por razões de segurança, dificultando a recuperação.

- Para verificar se a criptografia está habilitada para o sleepimage, o comando `sysctl vm.swapusage` pode ser executado. Isso mostrará se o arquivo está criptografado.

### Memory Pressure Logs

Outro arquivo importante relacionado à memória nos sistemas MacOS é o **log de pressão de memória**. Esses logs estão localizados em `/var/log` e contêm informações detalhadas sobre o uso da memória do sistema e eventos de pressão. Eles podem ser particularmente úteis para diagnosticar problemas relacionados à memória ou entender como o sistema gerencia a memória ao longo do tempo.

## Dumping memory with osxpmem

Para despejar a memória em uma máquina MacOS, você pode usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: As instruções a seguir funcionarão apenas para Macs com arquitetura Intel. Esta ferramenta agora está arquivada e o último lançamento foi em 2017. O binário baixado usando as instruções abaixo é direcionado a chips Intel, pois o Apple Silicon não existia em 2017. Pode ser possível compilar o binário para a arquitetura arm64, mas você terá que tentar por conta própria.
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
**Outros erros** podem ser corrigidos **permitindo o carregamento do kext** em "Segurança e Privacidade --> Geral", apenas **permita**.

Você também pode usar este **oneliner** para baixar o aplicativo, carregar o kext e despejar a memória:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
