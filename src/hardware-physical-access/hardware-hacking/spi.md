# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

SPI (Serial Peripheral Interface) é um barramento serial síncrono comumente usado para comunicação de curta distância entre circuitos integrados. Um controlador fornece o clock e seleciona um periférico, como uma EEPROM, um sensor ou um dispositivo de controle, usando um sinal de seleção do chip.<sup>[[1]](#references)</sup>

Vários periféricos podem compartilhar as linhas de clock e dados, normalmente com uma linha de seleção do chip separada para cada periférico. O controlador coordena as transferências; normalmente, os periféricos não se comunicam diretamente entre si pelo barramento SPI. A polaridade e o timing da seleção do chip variam conforme o dispositivo; a seleção ativa em nível baixo é comum, mas não universal. SPI não define descoberta, endereçamento, comandos nem um comprimento máximo único de transferência, portanto, consulte sempre a folha de dados do dispositivo-alvo.<sup>[[1]](#references)</sup>

MOSI/COPI transporta dados do controlador para o periférico, e MISO/CIPO transporta dados do periférico para o controlador. Os dados podem ser deslocados simultaneamente nas duas direções. A relação entre um comando, um endereço, ciclos dummy e os dados retornados é definida pelo periférico — não pelo SPI — e depende da polaridade e da fase do clock (modos 0–3). Não presuma que a saída começa exatamente um ciclo de clock após o fim da entrada.<sup>[[1]](#references)</sup>

## Extraindo firmware de EEPROMs

Extrair firmware pode ser útil para analisá-lo e encontrar vulnerabilidades. A imagem correta pode não estar disponível online ou pode variar conforme o modelo, a revisão de hardware ou a versão; portanto, extraí-la diretamente do dispositivo físico fornece um alvo de avaliação exato.

Um console serial pode ajudar, mas o sistema de arquivos pode ser somente leitura e o dispositivo-alvo pode não ter ferramentas de análise, incluindo utilitários necessários para enviar/receber tráfego de teste ou extrair binários com facilidade. Uma imagem offline preserva o layout completo da flash e permite a extração do sistema de arquivos e a engenharia reversa sem modificar o dispositivo em execução.

Durante uma avaliação física autorizada, um dump verificado também pode servir de base para testes controlados de modificação e regravação. Isso inclui alterar arquivos ou injetar um payload de teste/backdoor para demonstrar persistência no nível do firmware. Preserve várias leituras correspondentes e a imagem original antes de qualquer gravação: tensão, seleção do chip, layout ou imagem incorretos podem inutilizar o dispositivo.

### Programador e leitor de EEPROM CH341A

Esta ferramenta USB de baixo custo pode extrair e regravar dispositivos compatíveis de EEPROM serial e flash SPI. É comumente usada com chips de flash NOR SPI que armazenam o firmware de BIOS/UEFI de PCs e é conveniente durante acessos físicos com tempo limitado.

![desenho](../../images/board_image_ch341a.jpg)

Conecte a memória flash ao CH341A e, em seguida, conecte o programador ao computador. Se o próprio programador não for detectado, verifique o cabo USB, as permissões do sistema operacional e o driver CH341A adequado antes de solucionar problemas com o chip-alvo. Confirme a tensão do chip, o pino 1, a fiação do adaptador e a saída do programador consultando as folhas de dados ou usando um multímetro — **não** confie em regras como posicionar o VCC no lado oposto ao conector USB. A orientação incorreta ou a aplicação de 5 V a um componente de 3,3/1,8 V pode destruí-lo. Leituras em circuito também podem falhar porque o restante da placa carrega o barramento ou fornece energia a ele.<sup>[[2]](#references)</sup>

![desenho](../../images/connect_wires_ch341a.jpg) ![desenho](../../images/eeprom_plugged_ch341a.jpg)

Use software como `flashrom` ou G-Flash para ler o chip. G-Flash é uma interface gráfica mínima e pode detectar automaticamente dispositivos compatíveis, o que pode ser conveniente durante uma aquisição rápida, mas confirme você mesmo o modelo detectado e a tensão. Especifique o programador exato e, quando necessário, o modelo exato do chip; faça pelo menos duas leituras e compare seus hashes antes de considerar um dump confiável.<sup>[[2]](#references)</sup>

![desenho](../../images/connected_status_ch341a.jpg)

Depois de extrair o firmware, a análise pode ser feita nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk etc. podem ser usadas para extrair muitas informações sobre o firmware e também sobre todo o sistema de arquivos.

Para a triagem inicial, o Binwalk pode procurar assinaturas conhecidas e extrair conteúdo incorporado compatível:

```
binwalk -e <filename>
```

O arquivo de saída pode usar `.bin`, `.rom` ou outra extensão; a extensão não determina o formato.

> [!CAUTION]
> Observe que a extração de firmware é um processo delicado e exige muita paciência. Qualquer manuseio incorreto pode corromper o firmware ou até apagá-lo completamente e tornar o dispositivo inutilizável. Recomenda-se estudar o dispositivo específico antes de tentar extrair o firmware.

### Bus Pirate + flashrom

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Algumas folhas de dados identificam os pinos do alvo como `DI` e `DO`: em uma conexão convencional de flash com uma única linha de dados, **MOSI/COPI** do controlador se conecta a DI e **MISO/CIPO** do controlador se conecta a DO. Consulte a folha de dados do alvo, pois componentes com I/O dual/quad reutilizam pinos em outros modos.

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Observe que, mesmo que o PINOUT do Bus Pirate indique pinos para conectar MOSI e MISO ao SPI, alguns SPIs podem...](<../../images/image (360).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para despejar o conteúdo da memória flash executando algo como:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

A documentação recente do Bus Pirate também mostra os parâmetros opcionais `serialspeed` e `spispeed`. Comece com valores conservadores se fios longos ou a carga do circuito tornarem as leituras instáveis.<sup>[[3]](#references)</sup>

### Leituras no circuito quando o controlador compartilha o barramento da flash

Um clip SOIC pode alimentar o restante da PCB com a tensão da flash. Se o MCU estiver ligado e acessar o mesmo chip, suas transferências SPI podem colidir com as transferências do programador externo. Portanto, o resultado `No EEPROM/flash device found` não prova que a flash esteja ausente ou não seja compatível. Verifique primeiro o pinout, a tensão e o contato; depois, determine se o controlador integrado também está ativo.<sup>[[4]](#references)</sup>

Se houver um ponto de teste de reset, confirme sua polaridade e tensão com um multímetro antes de acioná-lo. Manter o MCU em reset pode deixar a flash acessível e, ao mesmo tempo, interromper o controlador SPI concorrente. As alternativas são dessoldar o chip ou registrar passivamente as leituras do MCU; a segunda opção não permite acessar regiões que ainda não foram lidas nem gravar no chip, e a fiação adicional da sonda pode interferir em um barramento rápido. Uma intervenção no oscilador ou no modo de boot depende do alvo e não substitui a verificação do esquema e dos sinais.<sup>[[4]](#references)</sup>

Com o MCU inativo, um Raspberry Pi com a interface `spidev` habilitada pode ler usando o programador `linux_spi` do flashrom. Altere `-p` para usar outro adaptador. Repita a leitura e compare os hashes antes de confiar no resultado; a detecção automática de SFDP e uma leitura bem-sucedida **não** comprovam que as operações de apagamento, gravação ou proteção contra gravação funcionem em um componente que não tenha suporte.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstruindo leituras de flash SPI com um analisador lógico

Quando não for possível fazer a leitura ativa, capture os sinais de seleção do chip, clock, dados do controlador para a flash e dados da flash para o controlador durante a inicialização ou uma ação específica na interface. No PulseView, identifique primeiro o intervalo ativo do sinal de seleção do chip e o clock; em seguida, configure os canais de dados do decodificador SPI de acordo com o pinout da flash e verifique se há um comando/endereço plausível seguido pelos bytes retornados. Exporte os bytes **MISO/saída da flash** com o Binary Decoder Output View e preserve os endereços de leitura decodificados para que cada resposta possa ser posicionada no offset correspondente da flash. Capturar apenas leituras acionadas por menus fornece somente as regiões solicitadas, não uma imagem completa da flash; não concatene as respostas como se fossem contíguas sem verificar os endereços.<sup>[[4]](#references)</sup>

Se um dump parecer conter gráficos em vez de código executável, continue com a [triagem de recursos gráficos brutos](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Introdução à interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manual do flashrom — programador SPI CH341A e opções de leitura/gravação](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentação do Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Revisão de hardware hacking, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
