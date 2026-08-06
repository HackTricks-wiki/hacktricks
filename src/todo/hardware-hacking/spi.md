# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informações Básicas

SPI (Serial Peripheral Interface) é um Protocolo de Comunicação Serial Síncrona usado em sistemas embarcados para comunicação de curta distância entre ICs (Integrated Circuits). O Protocolo de Comunicação SPI utiliza a arquitetura master-slave, orquestrada pelos sinais de Clock e Chip Select. Uma arquitetura master-slave consiste em um master (geralmente um microprocessador) que gerencia periféricos externos, como EEPROMs, sensores, dispositivos de controle etc., considerados slaves.

Vários slaves podem ser conectados a um master, mas os slaves não podem se comunicar entre si. Os slaves são administrados por dois pinos: clock e chip select. Como SPI é um protocolo de comunicação síncrona, os pinos de entrada e saída seguem os sinais de clock. O chip select é usado pelo master para selecionar um slave e interagir com ele. Quando o chip select está em nível alto, o dispositivo slave não está selecionado; quando está em nível baixo, o chip foi selecionado e o master passa a interagir com o slave.

O MOSI (Master Out, Slave In) e o MISO (Master In, Slave Out) são responsáveis pelo envio e recebimento de dados. Os dados são enviados ao dispositivo slave pelo pino MOSI enquanto o chip select permanece em nível baixo. Os dados de entrada contêm instruções, endereços de memória ou dados, conforme o datasheet do fabricante do dispositivo slave. Após uma entrada válida, o pino MISO é responsável por transmitir dados ao master. Os dados de saída são enviados exatamente no próximo ciclo de clock após o término da entrada. Os pinos MISO transmitem dados até que eles sejam totalmente transmitidos ou até que o master defina o pino chip select como nível alto (nesse caso, o slave interromperá a transmissão e o master não continuará escutando após esse ciclo de clock).

## Extraindo Firmware de EEPROMs

A extração de firmware pode ser útil para analisá-lo e encontrar vulnerabilidades. Muitas vezes, o firmware não está disponível na internet ou é irrelevante devido a variações em fatores como número do modelo, versão etc. Portanto, extrair o firmware diretamente do dispositivo físico pode ser útil para realizar uma busca por ameaças de forma específica.

Obter um Serial Console pode ser útil, mas muitas vezes os arquivos são somente leitura. Isso limita a análise por vários motivos. Por exemplo, as ferramentas necessárias para enviar e receber pacotes não estariam presentes no firmware. Portanto, extrair os binários para fazer engenharia reversa não seria viável. Assim, ter todo o firmware extraído no sistema e extrair os binários para análise pode ser muito útil.

Além disso, durante atividades de red teaming e ao obter acesso físico a dispositivos, extrair o firmware pode ajudar a modificar os arquivos ou injetar arquivos maliciosos e depois regravá-los na memória, o que pode ser útil para implantar um backdoor no dispositivo. Portanto, há inúmeras possibilidades que podem ser viabilizadas pela extração de firmware.

### CH341A EEPROM Programmer and Reader

Este dispositivo é uma ferramenta barata para extrair firmware de EEPROMs e também regravá-las com arquivos de firmware. Ele é uma opção popular para trabalhar com chips de BIOS de computadores (que são apenas EEPROMs). O dispositivo se conecta via USB e requer poucas ferramentas para começar. Além disso, geralmente conclui a tarefa rapidamente, podendo ser útil também durante o acesso físico a dispositivos.

![desenho](../../images/board_image_ch341a.jpg)

Conecte a memória EEPROM ao CH341a Programmer e conecte o dispositivo ao computador. Caso o dispositivo não seja detectado, tente instalar os drivers no computador. Além disso, verifique se a EEPROM está conectada na orientação correta (geralmente, coloque o pino VCC na orientação oposta ao conector USB); caso contrário, o software não conseguirá detectar o chip. Consulte o diagrama, se necessário:

![desenho](../../images/connect_wires_ch341a.jpg) ![desenho](../../images/eeprom_plugged_ch341a.jpg)

Por fim, use softwares como flashrom, G-Flash (GUI) etc. para extrair o firmware. G-Flash é uma ferramenta GUI mínima, rápida e que detecta a EEPROM automaticamente. Isso pode ser útil quando o firmware precisa ser extraído rapidamente, sem muito trabalho com a documentação.

![desenho](../../images/connected_status_ch341a.jpg)

Após extrair o firmware, a análise pode ser realizada nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk etc. podem ser usadas para extrair muitas informações sobre o firmware e também sobre todo o sistema de arquivos.

Para extrair o conteúdo do firmware, pode-se usar o binwalk. O binwalk analisa assinaturas hexadecimais, identifica os arquivos no arquivo binário e é capaz de extraí-los.
```
binwalk -e <filename>
```
Pode ser `.bin` ou `.rom`, conforme as ferramentas e configurações utilizadas.

> [!CAUTION]
> Observe que a extração do firmware é um processo delicado e requer muita paciência. Qualquer manuseio inadequado pode potencialmente corromper o firmware ou até mesmo apagá-lo completamente, tornando o dispositivo inutilizável. Recomenda-se estudar o dispositivo específico antes de tentar extrair o firmware.

### Bus Pirate + flashrom

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Observe que, mesmo que o PINOUT do Bus Pirate indique pinos **MOSI** e **MISO** para conexão com SPI, alguns SPIs podem indicar os pinos como DI e DO. **MOSI -> DI, MISO -> DO**

![Programador e leitor de EEPROM CH341A - Bus Pirate + flashrom: Observe que, mesmo que o PINOUT do Bus Pirate indique pinos MOSI e MISO para conexão com SPI, alguns SPIs podem...](<../../images/image (360).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para extrair o conteúdo da memória flash executando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
