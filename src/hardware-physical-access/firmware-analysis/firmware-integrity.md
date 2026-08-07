# Integridade do Firmware

{{#include ../../banners/hacktricks-training.md}}

O **firmware personalizado e/ou os binários compilados podem ser enviados para explorar falhas de integridade ou de verificação de assinaturas**. As etapas a seguir podem ser usadas para a compilação de um bind shell backdoor:

1. O firmware pode ser extraído usando o firmware-mod-kit (FMK).
2. A arquitetura e o endianness do firmware-alvo devem ser identificados.
3. Um cross compiler pode ser compilado usando o Buildroot ou outros métodos adequados ao ambiente.
4. O backdoor pode ser compilado usando o cross compiler.
5. O backdoor pode ser copiado para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. O backdoor pode ser emulado usando chroot e QEMU.
8. O backdoor pode ser acessado via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser reempacotado usando o FMK.
11. O firmware com backdoor pode ser testado emulando-o com o firmware analysis toolkit (FAT) e conectando-se ao IP e à porta do backdoor-alvo usando netcat.

Se um root shell já tiver sido obtido por meio de análise dinâmica, manipulação do bootloader ou testes de segurança de hardware, binários maliciosos pré-compilados, como implants ou reverse shells, poderão ser executados. Ferramentas automatizadas de payload/implant, como o framework Metasploit e o 'msfvenom', podem ser utilizadas seguindo estas etapas:

1. A arquitetura e o endianness do firmware-alvo devem ser identificados.
2. O Msfvenom pode ser usado para especificar o payload-alvo, o IP do host do atacante, o número da porta de escuta, o tipo de arquivo, a arquitetura, a plataforma e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido, garantindo que ele tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com solicitações recebidas iniciando o msfconsole e configurando as definições de acordo com o payload.
5. O reverse shell do meterpreter pode ser executado no dispositivo comprometido.

## Pontes de transporte não autenticadas para protocolos de atualização privilegiados

Um erro comum de design em sistemas embarcados é expor o **mesmo protocolo de comandos interno por meio de vários transportes**, mas aplicar autenticação em apenas um deles. Por exemplo, o USB pode exigir challenge-response, enquanto o BLE simplesmente encaminha **GATT writes** não autenticados para o mesmo handler privilegiado de atualização de firmware.<sup>[[1]](#references)</sup>

Fluxo de trabalho ofensivo típico:

1. Enumerar o banco de dados GATT do BLE e identificar as characteristics graváveis usadas pelo aplicativo móvel oficial.
2. Capturar o tráfego do aplicativo e procurar **magic bytes / opcodes** que correspondam ao protocolo com fio.
3. Reproduzir comandos privilegiados via BLE **sem pareamento** e verificar se as operações sensíveis ainda funcionam.
4. Se os opcodes de atualização de firmware, gravação de configuração, debug ou teste de fábrica estiverem acessíveis, tratar o BLE como uma **porta administrativa acessível por rádio**.

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
- Todos os transports são roteados para a mesma tabela interna de dispatch?
- Os opcodes privilegiados são filtrados de forma diferente em USB / BLE / UART / Wi-Fi?
- O mobile app pode acionar remotamente handlers de firmware update, recovery ou diagnóstico?

## Containers de firmware protegidos apenas por checksum ainda são firmware controlado pelo atacante

Um container de firmware protegido apenas por um **checksum sem chave** (CRC32, SHA-256, MD5 etc.) fornece detecção de corrupção, **não autenticidade**. Se o atacante conseguir alcançar a rotina de update, poderá modificar a imagem, recalcular o checksum e fazer flash de código arbitrário.<sup>[[1]](#references)</sup>

Red flags durante o RE:

- O código de update valida apenas um blob de checksum no final, como `CHK2`, `CRC` ou `SHA256`.
- Não há verificação de assinatura nem uma root of trust de secure boot.
- Não é usado MAC / HMAC vinculado ao dispositivo nem authenticated encryption.
- O recovery mode aceita o mesmo formato de imagem não autenticado.

Fluxo prático de validação:

1. Extraia o container de firmware e identifique o bootloader, o firmware principal e os metadados de integridade.
2. Modifique uma string ou banner inofensivo na imagem.
3. Recalcule o checksum exatamente como esperado pelo updater.
4. Faça reflash da imagem pelo caminho normal de update.
5. Confirme a alteração durante o boot para provar a substituição arbitrária do firmware.

Se isso funcionar por um transport acessível remotamente, como BLE/Wi-Fi, o bug é efetivamente uma **substituição não autenticada de firmware OTA**.

## Transformando um periférico USB confiável em BadUSB via reflash de firmware

Quando o dispositivo-alvo já é confiável pelo host via USB, o firmware malicioso talvez não precise implementar uma nova USB stack completa. Um pivot muito mais fácil costuma ser **reutilizar o suporte HID existente**.<sup>[[1]](#references)</sup>

Padrão útil:

1. Verifique se o dispositivo já é enumerado como uma interface **HID Consumer Control** / media / vendor HID.
2. Localize o **HID report descriptor** existente no firmware.
3. Adicione ou substitua entradas do descriptor para que o dispositivo também anuncie capacidade de **keyboard**.
4. Reutilize as rotinas de firmware existentes que já enviam HID reports, em vez de escrever uma nova implementação de transport.
5. Injete reports de key press + key release para digitar comandos no host.

Isso transforma o comprometimento do firmware em **comprometimento do host**, porque o PC confiará no periférico reflashed como um keyboard legítimo.

### Checklist mínimo de avaliação

- `dmesg`, o Device Manager ou os USB descriptors mostram uma interface HID existente?
- Há espaço livre próximo ao report descriptor ou uma tabela de descriptors relocável?
- As rotinas existentes de envio de media-control podem ser reutilizadas para keyboard reports?
- O host aceita automaticamente a nova interface de keyboard após o reflash?

## Execução confiável de payload dentro de firmware RTOS

Em vez de inserir trampolines frágeis em caminhos de código aleatórios, procure **tasks existentes do RTOS** que não sejam usadas ou tenham baixo impacto na operação normal.<sup>[[1]](#references)</sup>

Por que isso é útil:

- O scheduler inicia seu payload naturalmente durante o boot.
- Você evita corromper o fluxo de controle crítico.
- Payloads atrasados têm menos probabilidade de acionar watchdog resets do que quando executados dentro de um handler de USB/network sensível à latência.

Bons alvos são tasks de diagnóstico, factory-test, telemetria ou serviços de coprocessor que pareçam inativas no uso normal.

## Iteração rápida de exploit: reutilize handlers de protocolo benignos

Quando o patching de firmware for possível, uma forma compacta de acelerar o RE é sobrescrever um command handler inofensivo (por exemplo, um **echo/debug opcode**) com primitives personalizadas de **memory read / write / execute**. Isso evita um reflash completo a cada experimento e é especialmente útil quando o dispositivo oferece suporte ao handler modificado por meio de um transport wired rápido.<sup>[[1]](#references)</sup>

Use isso para:

- Verificar scatter-loaded memory maps
- Inspecionar o estado do heap/task ao vivo
- Testar payloads pequenos antes de gravá-los na flash
- Recuperar function pointers, strings e descriptor tables com segurança

## Referências

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
