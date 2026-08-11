# Integridade do firmware

{{#include ../../banners/hacktricks-training.md}}

Quando uma avaliação autorizada identifica uma verificação fraca ou ausente da assinatura do firmware, uma imagem de firmware modificada pode demonstrar o impacto na integridade. O workflow de laboratório a seguir adiciona um bind shell, mantendo as etapas originais de extração, emulação e repacotamento.<sup>[[2]](#references)[[3]](#references)</sup>

1. O firmware pode ser extraído usando o firmware-mod-kit (FMK).
2. A arquitetura e o endianness do firmware-alvo devem ser identificados.
3. Um cross compiler pode ser compilado usando o Buildroot ou outros métodos adequados ao ambiente.
4. O backdoor pode ser compilado usando o cross compiler.
5. O backdoor pode ser copiado para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. O backdoor pode ser emulado usando chroot e QEMU.
8. O backdoor pode ser acessado via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser repacotado usando o FMK.
11. O firmware com backdoor pode ser testado emulando-o com o firmware analysis toolkit (FAT) e conectando-se ao IP e à porta do backdoor-alvo usando netcat.

Se um root shell já tiver sido obtido por meio de análise dinâmica, manipulação do bootloader ou testes de segurança de hardware, binários de teste pré-compilados, como implants ou reverse shells, podem ser executados. O `msfvenom` do Metasploit pode gerar um payload específico para a arquitetura para este workflow de validação:<sup>[[4]](#references)</sup>

1. A arquitetura e o endianness do firmware-alvo devem ser identificados.
2. O Msfvenom pode ser usado para especificar o payload-alvo, o IP do host do atacante, o número da porta de escuta, o filetype, a arquitetura, a plataforma e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido, garantindo que tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com requisições recebidas iniciando o msfconsole e configurando as definições de acordo com o payload.
5. O reverse shell do meterpreter pode ser executado no dispositivo comprometido.

## Bridges de transporte não autenticadas para protocolos privilegiados de atualização

Um erro comum de design em dispositivos embarcados é expor o **mesmo protocolo de comandos interno por meio de vários transports**, mas exigir autenticação em apenas um deles. Por exemplo, o USB pode exigir challenge-response, enquanto o BLE simplesmente encaminha **GATT writes** não autenticadas para o mesmo handler privilegiado de atualização de firmware.<sup>[[1]](#references)</sup>

Workflow ofensivo típico:

1. Enumerar o banco de dados GATT do BLE e identificar as characteristics graváveis usadas pelo app mobile oficial.
2. Capturar o tráfego do app e procurar **magic bytes / opcodes** que correspondam ao protocolo cabeado.
3. Reproduzir comandos privilegiados via BLE **sem pairing** e verificar se as operações sensíveis continuam funcionando.
4. Se opcodes de upgrade de firmware, escrita de configuração, debug ou factory-test estiverem acessíveis, tratar o BLE como uma **admin port acessível por rádio**.

Verificações rápidas:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Coisas a verificar durante o reversing:

- O BLE exige **pairing/bonding** ou apenas uma conexão simples?
- Todos os transports são encaminhados para a mesma tabela de dispatch interna?
- Os opcodes privilegiados são filtrados de forma diferente em USB / BLE / UART / Wi-Fi?
- O aplicativo móvel pode acionar remotamente handlers de atualização de firmware, recovery ou diagnóstico?

## Containers de firmware protegidos apenas por checksum ainda são firmware controlado pelo atacante

Um container de firmware protegido apenas por um **checksum não autenticado** (CRC32, SHA-256, MD5 etc.) fornece detecção de corrupção, **não autenticidade**. Se o atacante conseguir alcançar a rotina de atualização, poderá modificar a imagem, recalcular o checksum e fazer flash de código arbitrário.<sup>[[1]](#references)</sup>

Sinais de alerta durante o RE:

- O código de atualização valida apenas um blob de checksum no final, como `CHK2`, `CRC` ou `SHA256`.
- Não há verificação de assinatura nem uma root of trust de secure boot.
- Não é usado MAC / HMAC vinculado ao dispositivo nem authenticated encryption.
- O recovery mode aceita o mesmo formato de imagem não autenticado.

Fluxo prático de validação:

1. Extraia o container de firmware e identifique o bootloader, o firmware principal e os metadados de integridade.
2. Modifique uma string ou banner inofensivo na imagem.
3. Recalcule o checksum exatamente como esperado pelo updater.
4. Faça reflash da imagem pelo caminho normal de atualização.
5. Confirme a alteração durante o boot para provar a substituição arbitrária do firmware.

Se isso funcionar por um transport acessível remotamente, como BLE/Wi-Fi, o bug é efetivamente uma **substituição não autenticada de firmware OTA**.

## Transformando um periférico USB confiável em BadUSB por meio de reflashing do firmware

Quando o dispositivo-alvo já é confiável pelo host via USB, um firmware malicioso talvez não precise implementar uma nova USB stack completa. Um pivot muito mais simples costuma ser **reutilizar o suporte HID existente**.<sup>[[1]](#references)</sup>

Padrão útil:

1. Verifique se o dispositivo já é enumerado como uma interface **HID Consumer Control** / de mídia / HID de vendor.
2. Localize o **HID report descriptor** existente no firmware.
3. Adicione ou substitua entradas do descriptor para que o dispositivo também anuncie capacidade de **keyboard**.
4. Reutilize as rotinas de firmware existentes que já enviam HID reports, em vez de escrever uma nova implementação de transport.
5. Injete reports de pressionamento + liberação de teclas para digitar comandos no host.

Isso transforma o comprometimento do firmware em **comprometimento do host**, pois o PC confiará no periférico reflasheado como um teclado legítimo.

### Checklist mínimo de avaliação

- `dmesg`, o Device Manager ou os USB descriptors mostram uma interface HID existente?
- Há espaço livre próximo ao report descriptor ou uma tabela de descriptors relocável?
- As rotinas existentes de envio de controle de mídia podem ser reutilizadas para keyboard reports?
- O host aceita automaticamente a nova interface de teclado após o reflash?

## Execução confiável de payloads dentro de firmware RTOS

Em vez de inserir trampolines frágeis em caminhos de código aleatórios, procure **tarefas de RTOS existentes** que não sejam usadas ou tenham baixo impacto durante a operação normal.<sup>[[1]](#references)</sup>

Por que isso é útil:

- O scheduler inicia seu payload naturalmente durante o boot.
- Você evita corromper o fluxo de controle crítico.
- Payloads atrasados têm menos probabilidade de acionar resets do watchdog do que quando executados dentro de um handler de USB/rede sensível à latência.

Bons alvos são tarefas de diagnóstico, factory-test, telemetria ou serviços de coprocessador que pareçam inativas durante o uso normal.

## Iteração rápida de exploits: reutilizando handlers de protocolo benignos

Quando o patching do firmware é possível, uma forma compacta de acelerar o RE é sobrescrever um handler de comando inofensivo (por exemplo, um **opcode de echo/debug**) com primitivas personalizadas de **memory read / write / execute**. Isso evita fazer reflash completo a cada experimento e é especialmente útil quando o dispositivo oferece suporte ao handler modificado por meio de um transport cabeado rápido.<sup>[[1]](#references)</sup>

Use isso para:

- Verificar mapas de memória scatter-loaded
- Inspecionar o estado do heap/task em tempo real
- Testar payloads pequenos antes de gravá-los na flash
- Recuperar ponteiros de função, strings e tabelas de descriptors com segurança

## References

- [1] [Pwnd Blaster: Hackeando seu PC usando seu alto-falante sem nunca tocá-lo](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Toolkit de análise de firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Como usar `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
