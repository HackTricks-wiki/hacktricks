# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

O **firmware custom e/ou binários compilados podem ser enviados para explorar falhas de integridade ou verificação de assinatura**. Os passos a seguir podem ser usados para a compilação de um bind shell backdoor:

1. O firmware pode ser extraído usando firmware-mod-kit (FMK).
2. A arquitetura e a endianness do firmware alvo devem ser identificadas.
3. Um cross compiler pode ser construído usando Buildroot ou outros métodos adequados para o ambiente.
4. O backdoor pode ser compilado usando o cross compiler.
5. O backdoor pode ser copiado para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. O backdoor pode ser emulado usando chroot e QEMU.
8. O backdoor pode ser acessado via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser reempacotado usando FMK.
11. O firmware com backdoor pode ser testado emulando-o com firmware analysis toolkit (FAT) e conectando-se ao IP e porta do backdoor alvo usando netcat.

Se um root shell já tiver sido obtido por meio de dynamic analysis, manipulação do bootloader ou hardware security testing, binários maliciosos pré-compilados, como implants ou reverse shells, podem ser executados. Ferramentas automatizadas de payload/implant como o Metasploit framework e 'msfvenom' podem ser usadas seguindo os passos abaixo:

1. A arquitetura e a endianness do firmware alvo devem ser identificadas.
2. O msfvenom pode ser usado para especificar o payload alvo, o IP do host atacante, o número da porta de escuta, o filetype, a arquitetura, a platform e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido e deve-se নিশ্চিতir que ele tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com as solicitações recebidas iniciando o msfconsole e configurando as opções de acordo com o payload.
5. O meterpreter reverse shell pode ser executado no dispositivo comprometido.

## Unauthenticated transport bridges to privileged update protocols

Um erro comum de design em embedded é expor o **mesmo protocolo de comando interno por vários transports** mas impor autenticação apenas em um deles. Por exemplo, USB pode exigir challenge-response enquanto BLE simplesmente encaminha **GATT writes** sem autenticação para o mesmo handler privilegiado de firmware-update.

Fluxo ofensivo típico:

1. Enumere o banco de dados GATT do BLE e identifique characteristics graváveis usadas pelo aplicativo móvel oficial.
2. Intercepte o tráfego do app e procure por **magic bytes / opcodes** que correspondam ao protocolo com fio.
3. Reproduza comandos privilegiados via BLE **sem pairing** e verifique se operações sensíveis ainda funcionam.
4. Se firmware upgrade, config write, debug ou factory-test opcodes estiverem acessíveis, trate o BLE como uma **porta de administração alcançável por rádio**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Coisas a verificar durante o reverse engineering:

- BLE exige **pairing/bonding** ou apenas uma conexão simples?
- Todos os transports são roteados para a mesma tabela interna de dispatcher?
- Opcodes privilegiados são filtrados de forma diferente em USB / BLE / UART / Wi-Fi?
- O mobile app pode acionar firmware update, recovery, ou handlers de diagnóstico remotamente?

## Containers de firmware com checksum בלבד ainda são firmware controlado pelo attacker

Um container de firmware protegido apenas por um **checksum sem chave** (CRC32, SHA-256, MD5, etc.) fornece detecção de corrupção, **não autenticidade**. Se o attacker conseguir alcançar a rotina de update, ele pode alterar a image, recomputar o checksum e flashar código arbitrário.

Red flags durante RE:

- O código de update valida apenas um blob de checksum no final, como `CHK2`, `CRC` ou `SHA256`.
- Não há verificação de assinatura nem root of trust de secure boot.
- Não é usado MAC / HMAC / authenticated encryption atrelado ao device.
- O modo recovery aceita o mesmo formato de image não autenticada.

Fluxo prático de validação:

1. Extraia o container de firmware e identifique bootloader, main firmware e metadata de integridade.
2. Modifique uma string ou banner inofensivo na image.
3. Recompute o checksum exatamente como o updater espera.
4. Reflash a image pelo caminho normal de update.
5. Confirme a alteração no boot para provar substituição arbitrária do firmware.

Se isso funcionar sobre um transport acessível remotamente, como BLE/Wi-Fi, o bug é efetivamente **unauthenticated OTA firmware replacement**.

## Transformando um peripheral USB confiável em BadUSB via reflashing de firmware

Quando o device-alvo já é confiado pelo host via USB, o firmware malicioso pode não precisar implementar uma nova USB stack completa. Um pivot muito mais fácil é muitas vezes **reutilizar o suporte HID existente**.

Padrão útil:

1. Verifique se o device já enumera como uma interface **HID Consumer Control** / media / vendor HID.
2. Localize o **HID report descriptor** existente no firmware.
3. Acrescente ou substitua entradas do descriptor para que o device também anuncie capacidade de **keyboard**.
4. Reutilize rotinas de firmware já existentes que enviam HID reports, em vez de escrever uma nova implementação de transport.
5. Injete reports de key press + key release para digitar comandos no host.

Isso transforma comprometimento de firmware em **host compromise** porque o PC vai confiar no peripheral reflasheado como um keyboard legítimo.

### Checklist mínimo de avaliação

- `dmesg`, Device Manager, ou descriptors USB mostram uma interface HID existente?
- Há espaço sobrando perto do report descriptor ou uma tabela de descriptors relocável?
- Rotinas existentes de envio de media-control podem ser reutilizadas para reports de keyboard?
- O host aceita automaticamente a nova interface de keyboard após o reflashing?

## Execução confiável de payload dentro de firmware RTOS

Em vez de inserir trampolines frágeis em caminhos aleatórios de código, procure por **tarefas RTOS existentes** que estejam sem uso ou com baixo impacto na operação normal.

Por que isso é útil:

- O scheduler inicia seu payload naturalmente durante o boot.
- Você evita corromper o fluxo de controle crítico.
- Payloads atrasados têm menos chance de disparar watchdog resets do que quando executados dentro de um handler de USB/network sensível à latência.

Bons alvos são tarefas de diagnóstico, factory-test, telemetry, ou serviço de coprocessador que pareçam inativas no uso normal.

## Iteração rápida de exploit: reaproveite handlers benignos de protocolo

Depois que o patching de firmware for possível, uma forma compacta de acelerar RE é sobrescrever um handler de comando inofensivo (por exemplo um opcode de **echo/debug**) com primitivas personalizadas de **memory read / write / execute**. Isso evita reflashing completo para cada experimento e é especialmente útil quando o device suporta o handler modificado sobre um transport cabeado rápido.

Use isso para:

- Verificar scatter-loaded memory maps
- Inspecionar heap/task state ao vivo
- Testar payloads pequenos antes de gravá-los em flash
- Recuperar function pointers, strings e descriptor tables com segurança

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
