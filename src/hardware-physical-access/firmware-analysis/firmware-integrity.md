# Integridade do firmware

{{#include ../../banners/hacktricks-training.md}}

Quando uma avaliação autorizada identifica uma verificação fraca ou inexistente de assinaturas de firmware, uma imagem de firmware modificada pode demonstrar o impacto sobre a integridade. O fluxo de trabalho de laboratório a seguir adiciona um bind shell, mantendo as etapas originais de extração, emulação e remontagem.<sup>[[2]](#references)[[3]](#references)</sup>

1. O firmware pode ser extraído usando o firmware-mod-kit (FMK).
2. A arquitetura e a endianness do firmware de destino devem ser identificadas.
3. Um compilador cruzado pode ser criado usando Buildroot ou outros métodos adequados ao ambiente.
4. O backdoor pode ser compilado usando o compilador cruzado.
5. O backdoor pode ser copiado para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. O backdoor pode ser emulado usando chroot e QEMU.
8. O backdoor pode ser acessado via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser remontado usando o FMK.
11. O firmware com backdoor pode ser testado emulando-o com o firmware analysis toolkit (FAT) e conectando-se ao IP e à porta do backdoor de destino usando netcat.

Se um root shell já tiver sido obtido por meio de análise dinâmica, manipulação do bootloader ou testes de segurança de hardware, binários de teste pré-compilados, como implants ou reverse shells, podem ser executados. O `msfvenom` do Metasploit pode gerar um payload específico para a arquitetura neste fluxo de validação:<sup>[[4]](#references)</sup>

1. A arquitetura e a endianness do firmware de destino devem ser identificadas.
2. O Msfvenom pode ser usado para especificar o payload de destino, o IP do host do atacante, o número da porta de escuta, o tipo de arquivo, a arquitetura, a plataforma e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido, garantindo que tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com solicitações recebidas iniciando o msfconsole e configurando as opções de acordo com o payload.
5. O reverse shell do meterpreter pode ser executado no dispositivo comprometido.

## Pontes de transporte não autenticadas para protocolos de atualização privilegiados

Um erro comum de projeto em dispositivos embarcados é expor **o mesmo protocolo de comando interno por vários meios de transporte**, mas exigir autenticação em apenas um deles. Por exemplo, o USB pode exigir challenge-response, enquanto o BLE simplesmente encaminha **escritas GATT** não autenticadas ao mesmo manipulador privilegiado de atualização de firmware.<sup>[[1]](#references)</sup>

Fluxo de trabalho ofensivo típico:

1. Enumerar o banco de dados GATT do BLE e identificar as características graváveis usadas pelo aplicativo móvel oficial.
2. Capturar o tráfego do aplicativo e procurar **magic bytes / opcodes** que correspondam ao protocolo com fio.
3. Reproduzir comandos privilegiados via BLE **sem pareamento** e verificar se operações sensíveis ainda funcionam.
4. Se os opcodes de atualização de firmware, gravação de configuração, depuração ou teste de fábrica estiverem acessíveis, tratar o BLE como uma **porta de administração acessível por rádio**.

Verificações rápidas:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Coisas a verificar durante a engenharia reversa:

- BLE exige **pareamento/vinculação** ou apenas uma conexão simples?
- Todos os transportes são encaminhados para a mesma tabela de dispatcher interno?
- Os opcodes privilegiados são filtrados de forma diferente em USB / BLE / UART / Wi-Fi?
- O aplicativo móvel pode acionar remotamente handlers de atualização de firmware, recuperação ou diagnóstico?

## Contêineres de firmware protegidos apenas por checksum ainda contêm firmware controlado pelo atacante

Um contêiner de firmware protegido apenas por um **checksum sem chave** (CRC32, SHA-256, MD5 etc.) detecta corrupção, **mas não garante autenticidade**. Se o atacante conseguir acessar a rotina de atualização, poderá corrigir a imagem, recalcular o checksum e gravar código arbitrário.<sup>[[1]](#references)</sup>

Sinais de alerta durante a RE:

- O código de atualização valida apenas um bloco de checksum no final, como `CHK2`, `CRC` ou `SHA256`.
- Não há verificação de assinatura nem raiz de confiança de secure boot.
- Não é usado MAC / HMAC vinculado ao dispositivo nem criptografia autenticada.
- O modo de recuperação aceita o mesmo formato de imagem não autenticado.

Fluxo prático de validação:

1. Extraia o contêiner de firmware e identifique o bootloader, o firmware principal e os metadados de integridade.
2. Modifique uma string ou um banner inofensivo na imagem.
3. Recalcule o checksum exatamente como o updater espera.
4. Regrave a imagem pelo fluxo normal de atualização.
5. Confirme a alteração durante a inicialização para provar que é possível substituir o firmware por qualquer outro.

Se isso funcionar por um transporte acessível remotamente, como BLE/Wi-Fi, a vulnerabilidade equivale, na prática, à **substituição não autenticada de firmware OTA**.

## Estado de atualização fragmentado e metadados de integridade graváveis

Um updater pode verificar um cabeçalho de firmware assinado durante a instalação, mas ainda inicializar imagens usando apenas um hash de integridade armazenado. No Cypherock X1, o Bootloader invocava tarefas separadas do Firewall para verificar o cabeçalho e colocar a versão/tamanho na RAM, armazenar a assinatura do firmware na RAM, verificar a imagem gravada e, por fim, calcular o hash da imagem e armazená-lo nos dados persistentes do Primary Bootloader. A assinatura não era persistida. Essas tarefas podiam ser chamadas independentemente, sem impor uma única transação de atualização autenticada.<sup>[[5]](#references)</sup>

Com execução de código no MCU e acesso de gravação à Flash, o ataque relatado regravava a imagem do aplicativo, alterava os valores de versão/tamanho na RAM do Bootloader compartilhada com o Firewall e, em seguida, chamava a tarefa final de metadados para armazenar o hash da imagem maliciosa e restaurar o estado normal de inicialização. A verificação normal de integridade na inicialização aceitava esse hash sem verificar novamente a assinatura. Ao analisar um updater semelhante, rastreie **qual componente pode invocar cada tarefa**, onde os valores verificados ficam armazenados e se a decisão tomada na inicialização autentica a *mesma imagem* cujo hash está armazenado. Esse cenário é mais específico do que um formato de imagem protegido apenas por checksum: havia verificação de assinatura, mas a transição de estado não estava vinculada a ela.<sup>[[5]](#references)</sup>

## Assinaturas do elemento seguro sobre medições de firmware não confiáveis

Um elemento seguro não atesta o código em execução apenas por assinar um hash fornecido por esse código. Na mesma carteira, o elemento seguro assinava o número de série do dispositivo e, em seguida, o XOR de um nonce da nuvem com um hash de firmware fornecido pelo MCU. Um firmware comprometido poderia apresentar o hash esperado para ser assinado enquanto executava bytes diferentes. O cliente complementar também enviava a versão do firmware para a nuvem, portanto a comparação do hash esperado pelo verificador ainda dependia de uma medição originada no MCU, em vez de uma leitura independente da Flash.<sup>[[5]](#references)</sup>

O resultado no dispositivo estava em uma fronteira de confiança separada: a nuvem verificava o dispositivo, mas o dispositivo não autenticava a resposta da nuvem. Um cliente modificado poderia informar sucesso local a um dispositivo adulterado. Teste separadamente a origem da medição e a autenticação da resposta; uma assinatura válida do elemento seguro e uma tela de sucesso, por si só, não provam que o aplicativo instalado é autêntico.<sup>[[5]](#references)</sup>

Para ver a divulgação de código protegido que possibilitou a análise desse updater, consulte [Firewall copy-task firmware acquisition](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Transformar um periférico USB confiável em BadUSB por meio da regravação do firmware

Quando o dispositivo-alvo já é confiável para o host via USB, talvez o firmware malicioso não precise implementar uma pilha USB totalmente nova. Muitas vezes, é muito mais fácil **reutilizar o suporte HID existente**.<sup>[[1]](#references)</sup>

Padrão útil:

1. Verifique se o dispositivo já é enumerado como uma interface **HID Consumer Control** / de mídia / HID de fornecedor.
2. Localize no firmware o **descritor de relatório HID** existente.
3. Acrescente ou substitua entradas do descritor para que o dispositivo também anuncie capacidade de **teclado**.
4. Reutilize rotinas de firmware existentes que já enviam relatórios HID, em vez de implementar um novo transporte.
5. Injete relatórios de pressionamento + liberação de teclas para digitar comandos no host.

Isso transforma o comprometimento do firmware em **comprometimento do host**, pois o PC confiará no periférico regravado como um teclado legítimo.

### Lista de verificação mínima para avaliação

- `dmesg`, o Device Manager ou os descritores USB mostram uma interface HID existente?
- Há espaço livre próximo ao descritor de relatório ou uma tabela de descritores relocável?
- As rotinas existentes de envio de controles de mídia podem ser reutilizadas para relatórios de teclado?
- O host aceita automaticamente a nova interface de teclado após a regravação?

## Execução confiável de payload em firmware RTOS

Em vez de inserir trampolins frágeis em caminhos de código aleatórios, procure **tarefas RTOS existentes** que não sejam usadas ou tenham baixo impacto durante a operação normal.<sup>[[1]](#references)</sup>

Por que isso é útil:

- O scheduler inicia seu payload naturalmente durante a inicialização.
- Você evita corromper o fluxo de controle crítico.
- Payloads atrasados têm menos probabilidade de acionar resets do watchdog do que quando executados dentro de um handler de USB/rede sensível à latência.

Bons alvos são tarefas de diagnóstico, teste de fábrica, telemetria ou serviço de coprocessador que pareçam inativas no uso normal.

## Iteração rápida de exploits: reutilizar handlers de protocolo inofensivos

Quando é possível corrigir o firmware, uma maneira compacta de acelerar a RE é sobrescrever um handler de comando inofensivo (por exemplo, um **opcode de echo/debug**) com primitivas personalizadas de **leitura / gravação / execução de memória**. Isso evita regravar o firmware a cada experimento e é especialmente útil quando o dispositivo oferece suporte ao handler modificado por meio de um transporte com fio rápido.<sup>[[1]](#references)</sup>

Use isso para:

- Verificar mapas de memória carregados em várias regiões
- Inspecionar em tempo real o estado do heap/tarefas
- Testar pequenos payloads antes de gravá-los na flash
- Recuperar ponteiros de função, strings e tabelas de descritores com segurança

## References

- [1] [Pwnd Blaster: Hackeando seu PC usando seu alto-falante sem nunca tocá-lo](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Kit de ferramentas de análise de firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Como usar `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Como e por que hackeamos a carteira de hardware Cypherock: a história completa](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
