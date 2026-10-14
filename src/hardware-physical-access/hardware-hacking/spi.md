# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

SPI (Serial Peripheral Interface) é um barramento serial síncrono comumente usado para comunicação de curta distância entre circuitos integrados. Um controlador fornece o clock e seleciona um periférico, como uma EEPROM, sensor ou dispositivo de controle, usando um sinal de seleção de chip.<sup>[[1]](#references)</sup>

Vários periféricos podem compartilhar as linhas de clock e dados, normalmente com uma seleção de chip separada para cada periférico. O controlador coordena as transferências; normalmente, os periféricos não se comunicam diretamente entre si pelo barramento SPI. A polaridade e o timing da seleção de chip variam conforme o dispositivo; a seleção ativa em nível baixo é comum, mas não universal. SPI não define descoberta, endereçamento, comandos nem um comprimento máximo único de transferência, portanto, consulte sempre a folha de dados do dispositivo-alvo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta dados do controlador para o periférico, e MISO/CIPO transporta dados do periférico para o controlador. Os dados podem ser deslocados simultaneamente nas duas direções. A relação entre um comando, um endereço, ciclos dummy e os dados retornados é definida pelo periférico — não pelo SPI — e depende da polaridade e da fase do clock (modos 0–3). Não presuma que a saída começa exatamente um ciclo de clock após o fim da entrada.<sup>[[1]](#references)</sup>

## Extraindo firmware de EEPROMs

A extração de firmware pode ser útil para analisá-lo e encontrar vulnerabilidades. A imagem correta pode não estar disponível online ou pode ser diferente conforme o modelo, a revisão de hardware ou a versão. Por isso, extraí-la diretamente do dispositivo físico fornece um alvo de avaliação exato.

Um console serial pode ajudar, mas seu sistema de arquivos pode ser somente leitura e o alvo pode não ter ferramentas de análise, incluindo utilitários necessários para enviar/receber tráfego de teste ou extrair binários com facilidade. Uma imagem offline preserva o layout completo da flash e permite a extração do sistema de arquivos e a engenharia reversa sem modificar o alvo em execução.

Durante uma avaliação física autorizada, um dump verificado também pode servir de base para testes controlados de modificação e regravação. Isso inclui alterar arquivos ou injetar um payload/backdoor de teste para demonstrar persistência em nível de firmware. Preserve várias leituras correspondentes e a imagem original antes de qualquer gravação: tensão, seleção de chip, layout ou imagem incorretos podem inutilizar o dispositivo.

### Programador e leitor de EEPROM CH341A

Esta ferramenta USB de baixo custo pode extrair e regravar dispositivos compatíveis de EEPROM serial e flash SPI. É comumente usada com chips de flash SPI NOR que armazenam o firmware do BIOS/UEFI de PCs e é conveniente durante acessos físicos com tempo limitado.

![drawing](../../images/board_image_ch341a.jpg)

Conecte a memória flash ao CH341A e, em seguida, conecte o programador ao computador. Se o próprio programador não for detectado, verifique o cabo USB, as permissões do sistema operacional e o driver CH341A apropriado antes de solucionar problemas com o chip-alvo. Confirme a tensão do chip, o pino 1, a fiação do adaptador e a saída do programador com as folhas de dados ou um multímetro — **não** confie em uma regra como colocar o VCC no lado oposto ao conector USB. A orientação incorreta ou a aplicação de 5 V a um componente de 3,3/1,8 V pode destruí-lo. Leituras em circuito também podem falhar porque o restante da placa carrega ou alimenta o barramento.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Use softwares como `flashrom` ou G-Flash para ler o chip. G-Flash é uma interface gráfica mínima e pode detectar automaticamente dispositivos compatíveis, o que pode ser conveniente durante uma aquisição rápida, mas confirme você mesmo o modelo detectado e a tensão. Especifique o programador exato e, quando necessário, o modelo exato do chip; faça pelo menos duas leituras e compare seus hashes antes de considerar um dump confiável.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Depois de extrair o firmware, a análise pode ser feita nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk etc. podem ser usadas para extrair muitas informações sobre o firmware e também sobre todo o sistema de arquivos.

Para a triagem inicial, o Binwalk pode procurar assinaturas conhecidas e extrair conteúdo incorporado compatível:

```
binwalk -e <filename>
```

O arquivo de saída pode usar `.bin`, `.rom` ou outra extensão; a extensão não determina o formato.

> [!CAUTION]
> Observe que a extração de firmware é um processo delicado e exige muita paciência. Qualquer manuseio incorreto pode corromper o firmware ou até mesmo apagá-lo completamente, tornando o dispositivo inutilizável. Recomenda-se estudar o dispositivo específico antes de tentar extrair o firmware.

### Bus Pirate + flashrom

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algumas folhas de dados identificam os pinos de destino como `DI` e `DO`: em uma conexão convencional de flash com uma única linha de dados, **MOSI/COPI** do controlador se conecta a DI, e **MISO/CIPO** do controlador se conecta a DO. Verifique a folha de dados do dispositivo de destino, pois componentes com E/S dual/quad reutilizam os pinos em outros modos.

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Observe que, embora o PINOUT do Bus Pirate indique pinos para conectar MOSI e MISO ao SPI, alguns SPIs podem...](<../../images/image (360).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para despejar o conteúdo da memória flash executando algo como:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Documentações recentes do Bus Pirate também mostram os parâmetros opcionais `serialspeed` e `spispeed`. Comece com valores conservadores se fios longos ou a carga do circuito tornarem as leituras instáveis.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introdução à interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual do flashrom — programador CH341A SPI e opções de leitura/gravação](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentação do Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
