# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

SPI (Serial Peripheral Interface) é um barramento serial síncrono comumente usado para comunicação de curta distância entre circuitos integrados. Um controlador fornece o clock e seleciona um periférico, como uma EEPROM, um sensor ou um dispositivo de controle, usando um sinal de seleção do chip (chip-select).<sup>[[1]](#references)</sup>

Vários periféricos podem compartilhar as linhas de clock e dados, normalmente com um chip-select separado para cada periférico. O controlador coordena as transferências; normalmente, os periféricos não se comunicam diretamente entre si pelo barramento SPI. A polaridade e a temporização do chip-select variam conforme o dispositivo; a seleção active-low é comum, mas não universal. SPI não define descoberta, endereçamento, comandos nem um comprimento máximo único para transferências; portanto, consulte sempre a folha de dados do dispositivo-alvo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta dados do controlador para o periférico, e MISO/CIPO transporta dados do periférico para o controlador. Os dados podem ser deslocados simultaneamente nos dois sentidos. A relação entre um comando, um endereço, ciclos dummy e os dados retornados é definida pelo periférico — não pelo SPI — e depende da polaridade e da fase do clock (modos 0–3). Não presuma que a saída começa exatamente um ciclo de clock depois que a entrada termina.<sup>[[1]](#references)</sup>

## Extraindo firmware de EEPROMs

A extração de firmware pode ser útil para analisá-lo e encontrar vulnerabilidades. A imagem correta pode não estar disponível online ou pode variar conforme o modelo, a revisão de hardware ou a versão; portanto, extraí-la diretamente do dispositivo físico fornece um alvo de avaliação exato.

Um console serial pode ajudar, mas o sistema de arquivos pode ser somente leitura, e o alvo pode não ter ferramentas de análise, incluindo utilitários necessários para enviar/receber tráfego de teste ou extrair binários com facilidade. Uma imagem offline preserva o layout completo da flash e permite extrair o sistema de arquivos e fazer engenharia reversa sem modificar o alvo em execução.

Durante uma avaliação física autorizada, um dump verificado também pode dar suporte a testes controlados de modificação e regravação. Isso inclui alterar arquivos ou injetar um payload/backdoor de teste para demonstrar persistência no nível do firmware. Preserve várias leituras coincidentes e a imagem original antes de qualquer gravação: uma tensão, seleção de chip, layout ou imagem incorretos podem inutilizar o dispositivo.

### Programador e leitor de EEPROM CH341A

Esta ferramenta USB de baixo custo pode fazer dump e regravar dispositivos compatíveis de EEPROM serial e flash SPI. É comumente usada com chips de flash SPI NOR que armazenam firmware BIOS/UEFI de PCs e é prática durante acessos físicos com tempo limitado.

![drawing](../../images/board_image_ch341a.jpg)

Conecte a memória flash ao CH341A e, em seguida, conecte o programador ao computador. Se o próprio programador não for detectado, verifique o cabo USB, as permissões do sistema operacional e o driver CH341A apropriado antes de investigar o chip-alvo. Confirme a tensão do chip, o pino 1, a fiação do adaptador e a saída do programador consultando as folhas de dados ou usando um multímetro — **não** confie em uma regra como colocar VCC no lado oposto ao conector USB. A orientação incorreta ou a aplicação de 5 V a um componente de 3,3/1,8 V pode destruí-lo. As leituras em circuito também podem falhar porque o restante da placa carrega ou alimenta o barramento.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Use softwares como `flashrom` ou G-Flash para ler o chip. G-Flash é uma interface gráfica mínima e pode detectar automaticamente dispositivos compatíveis, o que pode ser útil durante uma aquisição rápida, mas confirme você mesmo o modelo detectado e a tensão. Especifique o programador exato e, quando necessário, o modelo exato do chip; faça pelo menos duas leituras e compare seus hashes antes de considerar um dump confiável.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Depois de extrair o firmware, a análise pode ser feita nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk etc. podem ser usadas para extrair muitas informações sobre o firmware e também sobre todo o sistema de arquivos.

Para uma triagem inicial, o Binwalk pode procurar assinaturas conhecidas e extrair conteúdo incorporado compatível:

```
binwalk -e <filename>
```

O arquivo de saída pode usar `.bin`, `.rom` ou outra extensão; a extensão não determina o formato.

> [!CAUTION]
> Observe que a extração de firmware é um processo delicado e exige muita paciência. Qualquer manuseio incorreto pode corromper o firmware ou até apagá-lo completamente, tornando o dispositivo inutilizável. Recomenda-se estudar o dispositivo específico antes de tentar extrair o firmware.

### Bus Pirate + flashrom

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algumas folhas de dados identificam os pinos do dispositivo-alvo como `DI` e `DO`: em uma conexão convencional de flash com uma única linha de dados, **MOSI/COPI** do controlador se conecta a DI, e **MISO/CIPO** do controlador se conecta a DO. Verifique a folha de dados do dispositivo-alvo, pois componentes com I/O dual/quad reutilizam os pinos em outros modos.

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Observe que, mesmo que a PINAGEM do Bus Pirate indique pinos para MOSI e MISO se conectarem ao SPI, alguns SPIs podem...](<../../images/image (360).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para extrair o conteúdo da memória flash executando algo como:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

A documentação recente do Bus Pirate também mostra os parâmetros opcionais `serialspeed` e `spispeed`. Comece com uma velocidade conservadora se fios longos ou a carga do circuito causarem leituras instáveis.<sup>[[3]](#references)</sup>

### Leituras em circuito quando o controlador compartilha o barramento flash

Um clip SOIC pode alimentar o restante da PCB pela alimentação da flash. Se o MCU estiver ligado e acessar o mesmo chip, suas transferências SPI podem colidir com as transferências do programador externo. Portanto, o resultado `No EEPROM/flash device found` não prova que a flash esteja ausente ou não seja compatível. Primeiro, verifique o pinout, a tensão e o contato; em seguida, determine se o controlador integrado também está ativo.<sup>[[4]](#references)</sup>

Se houver um ponto de teste de reset, confirme sua polaridade e tensão com um multímetro antes de acioná-lo. Manter o MCU em reset pode deixar a flash acessível enquanto interrompe o host SPI concorrente. As alternativas são dessoldar o chip ou registrar passivamente as leituras do MCU; a segunda opção não permite acessar regiões ainda não lidas nem gravar no chip, e a fiação adicional das sondas pode perturbar um barramento rápido. Intervir no oscilador ou no modo de boot depende do alvo e não substitui a verificação do esquema e dos sinais.<sup>[[4]](#references)</sup>

Com o MCU mantido inativo, um Raspberry Pi com a interface `spidev` habilitada pode ler usando o programador `linux_spi` do flashrom. Altere `-p` para usar um adaptador diferente. Repita a leitura e compare os hashes antes de confiar nela; a autodetecção de SFDP e uma leitura bem-sucedida **não** comprovam que as operações de apagamento, gravação ou proteção contra gravação funcionem em uma peça que, de outra forma, não é compatível.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstruindo leituras de SPI flash com um analisador lógico

Quando a leitura ativa não for possível, capture chip select, clock, dados do controlador para a flash e dados da flash para o controlador durante o boot ou uma ação específica na UI. No PulseView, identifique primeiro o intervalo ativo de chip select e o clock; em seguida, configure os canais de dados do decodificador SPI de acordo com o pinout da flash e verifique se há um comando/endereço plausível seguido dos bytes retornados. Exporte os bytes de **saída MISO/flash** com o Binary Decoder Output View e preserve os endereços de leitura decodificados para que cada resposta possa ser colocada no offset correspondente da flash. Capturar apenas leituras acionadas por menus fornece somente as regiões solicitadas, não uma imagem completa da flash; não concatene respostas como se fossem contíguas sem verificar os endereços.<sup>[[4]](#references)</sup>

Para um dump que pareça conter gráficos em vez de código executável, continue com a [triagem de assets de display brutos](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy e capturas SPI/QSPI mistas

Em probes sem rótulos, diferencie MOSI de MISO pela linha que carrega o opcode antes dos dados de resposta e, em seguida, verifique o comando no datasheet da flash. Pulsos menores que um ciclo de clock podem ser ruído da probe, em vez de bits amostrados, e fios extras nas presilhas podem tornar as capturas de alta velocidade pouco confiáveis.<sup>[[5]](#references)</sup>

A exportação CSV de SPI do Saleae usa `enable` e `disable` para delimitar um intervalo de chip select, com bytes MOSI/MISO nas linhas `result`. Agrupe os bytes por intervalo antes de decodificar; concatenar todos os dados MISO elimina os endereços das transações.<sup>[[5]](#references)</sup> Um `Packet` do Scapy pode modelar o cabeçalho MOSI com um opcode `ByteEnumField` e campos condicionais de endereço e dummy. Para leituras NOR de 24 bits, `0x03` tem um opcode e três bytes de endereço, enquanto `0x0B` adiciona um byte dummy. `len(req.self_build())` fornece o comprimento do cabeçalho modelado: em uma leitura single-lane, `miso[header_length:]` é a resposta da flash, enquanto os dados MOSI após o cabeçalho são dados don't-care do lado do controlador.<sup>[[5]](#references)</sup> Coloque as respostas nos endereços decodificados em uma imagem preenchida com `0xFF` e acompanhe separadamente os offsets cobertos. Um byte não observado não é evidência de que a flash continha `0xFF` nessa posição.<sup>[[5]](#references)[[6]](#references)</sup>

Uma leitura `0x6B` (1-1-4) no estilo W25Q usa uma lane para o opcode e o endereço, mas IO0–IO3 para os dados de resposta. A atividade nos pinos anteriormente `/WP` e `/HOLD` é uma evidência mais forte de uma mudança para o modo quad do que apenas um clock mais rápido; um analisador single-lane pode decodificar incorretamente a resposta quad.<sup>[[5]](#references)</sup> Exporte essa fase com um analisador QSPI configurado para as larguras de lane e os ciclos dummy do comando; em seguida, combine as leituras single-lane e quad-lane pelo endereço da flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` detecta automaticamente os dois formatos de exportação, descarta as leituras decodificadas com a largura de lane incorreta e informa a cobertura de leitura.<sup>[[6]](#references)</sup> No repositório, após instalar as dependências, combine as capturas com:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

O resultado continua sendo uma observação esparsa, não um dump completo do chip.<sup>[[5]](#references)[[6]](#references)</sup> Para inspecionar as gravações separadamente, correlacione `0x06` write-enable, as consultas de status `0x05`, os opcodes de apagamento e os comandos de gravação de página `0x02`. Os dados de gravação de página vêm após o endereço em MOSI e não são incluídos na reconstrução somente de leitura.<sup>[[5]](#references)</sup> Analise a imagem resultante com [análise de firmware](../firmware-analysis/) mantendo as informações de cobertura de leitura.

## References

- [1] [Analog Devices — Introdução à interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual do flashrom — programador SPI CH341A e opções de leitura/gravação](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentação do Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Recapitulando o hacking de hardware, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Estendendo o Scapy para engenharia reversa de hardware](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — captura e reconstrução de traces SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Analisador QSPI para Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
