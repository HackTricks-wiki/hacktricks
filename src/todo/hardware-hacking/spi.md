# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

SPI (Serial Peripheral Interface) é um barramento serial síncrono normalmente usado para comunicação de curta distância entre circuitos integrados. Um controlador fornece o clock e seleciona um periférico, como uma EEPROM, um sensor ou um dispositivo de controle, usando um sinal de chip-select.<sup>[[1]](#references)</sup>

Vários periféricos podem compartilhar as linhas de clock e de dados, normalmente com um chip-select separado para cada periférico. O controlador coordena as transferências; normalmente, os periféricos não se comunicam diretamente entre si pelo barramento SPI. A polaridade e o timing do chip-select são específicos de cada dispositivo; a seleção active-low é comum, mas não universal. O SPI não define discovery, endereçamento, comandos nem um único tamanho máximo de transferência; portanto, consulte sempre o datasheet do alvo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta dados do controlador para o periférico, e MISO/CIPO transporta dados do periférico para o controlador. Ambas as direções podem fazer shift simultaneamente. A relação entre um comando, um endereço, ciclos dummy e os dados retornados é definida pelo periférico — não pelo SPI — e depende da polaridade e da fase do clock (modos 0–3). Não presuma que a saída começa exatamente um clock após o término da entrada.<sup>[[1]](#references)</sup>

## Extraindo Firmware de EEPROMs

A extração de firmware pode ser útil para analisá-lo e encontrar vulnerabilidades. A imagem correta pode não estar disponível online ou pode ser diferente conforme o modelo, a revisão do hardware ou a versão; portanto, extraí-la diretamente do dispositivo físico fornece um alvo exato para avaliação.

Um console serial pode ajudar, mas seu sistema de arquivos pode ser somente leitura, e o alvo pode não ter ferramentas de análise, incluindo utilitários necessários para enviar/receber tráfego de teste ou extrair binários convenientemente. Uma imagem offline preserva o layout completo da flash e permite a extração do sistema de arquivos e a engenharia reversa sem modificar o alvo em execução.

Durante uma avaliação física autorizada, um dump verificado também pode permitir testes controlados de modificação e reflashing. Isso inclui alterar arquivos ou injetar um test payload/backdoor para demonstrar persistência no nível do firmware. Preserve várias leituras correspondentes e a imagem original antes de qualquer escrita: uma tensão, seleção do chip, layout ou imagem incorretos podem inutilizar o dispositivo.

### CH341A EEPROM Programmer and Reader

Esta ferramenta USB barata pode fazer dump e reflash de dispositivos EEPROM serial e SPI flash compatíveis. Ela é frequentemente usada com chips SPI NOR flash que armazenam firmware de PC BIOS/UEFI e é conveniente durante acessos físicos com tempo limitado.

![drawing](../../images/board_image_ch341a.jpg)

Conecte a memória flash ao CH341A e, em seguida, conecte o programmer ao computador. Se o programmer não for detectado, verifique o cabo USB, as permissões do sistema operacional e o driver apropriado do CH341A antes de solucionar problemas no chip-alvo. Confirme a tensão do chip, o pino 1, a fiação do adaptador e a saída do programmer usando os datasheets ou um multímetro — **não** confie em uma regra como colocar o VCC no lado oposto ao conector USB. A orientação incorreta ou a aplicação de 5 V em um componente de 3,3/1,8 V pode destruí-lo. Leituras in-circuit também podem falhar porque o restante da placa carrega ou alimenta o barramento.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Use softwares como `flashrom` ou G-Flash para ler o chip. O G-Flash é uma GUI minimalista e pode detectar automaticamente dispositivos compatíveis, o que pode ser conveniente durante uma aquisição rápida, mas confirme você mesmo o modelo e a tensão detectados. Especifique o programmer exato e, quando necessário, o modelo exato do chip; faça pelo menos duas leituras e compare seus hashes antes de considerar um dump confiável.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Depois de extrair o firmware, a análise pode ser feita nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk etc. podem ser usadas para extrair muitas informações sobre o firmware e também sobre todo o sistema de arquivos.

Para a triagem inicial, o Binwalk pode verificar assinaturas conhecidas e extrair conteúdo incorporado compatível:
```
binwalk -e <filename>
```
O arquivo de saída pode usar `.bin`, `.rom` ou outra extensão; a extensão não estabelece o formato.

> [!CAUTION]
> Observe que a extração de firmware é um processo delicado e exige muita paciência. Qualquer manuseio incorreto pode potencialmente corromper o firmware ou até mesmo apagá-lo completamente, tornando o dispositivo inutilizável. Recomenda-se estudar o dispositivo específico antes de tentar extrair o firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Alguns datasheets identificam os pinos-alvo como `DI` e `DO`: para uma conexão flash convencional com uma única linha de dados, o controlador **MOSI/COPI se conecta a DI** e o controlador **MISO/CIPO se conecta a DO**. Verifique o datasheet do alvo, pois componentes com E/S dual/quad reutilizam os pinos em outros modos.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Observe que, mesmo que o PINOUT do Pirate Bus indique pinos para MOSI e MISO se conectarem ao SPI, alguns SPIs podem...](<../../images/image (360).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para extrair o conteúdo da memória flash executando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
A documentação recente do Bus Pirate também mostra os parâmetros opcionais `serialspeed` e `spispeed`. Comece de forma conservadora se fios longos ou cargas no circuito tornarem as leituras instáveis.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introdução à interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [manual do flashrom — programador SPI CH341A e opções de leitura/gravação](https://flashrom.org/classic_cli_manpage.html)
- [3] [documentação do Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
