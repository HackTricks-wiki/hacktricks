Ao modificar o início do dispositivo e os bootloaders, como o U-boot, tente o seguinte:

* Tente acessar o shell do interpretador do bootloader pressionando "0", espaço ou outros "códigos mágicos" identificados durante a inicialização.
* Modifique as configurações para executar um comando shell, como adicionar '`init=/bin/sh`' no final dos argumentos de inicialização
  * `#printenv`
  * `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
  * `#saveenv`
  * `#boot`
* Configure um servidor tftp para carregar imagens pela rede localmente a partir do seu workstation. Certifique-se de que o dispositivo tenha acesso à rede.
  * `#setenv ipaddr 192.168.2.2 #IP local do dispositivo`
  * `#setenv serverip 192.168.2.1 #IP do servidor tftp`
  * `#saveenv`
  * `#reset`
  * `#ping 192.168.2.1 #verifique se o acesso à rede está disponível`
  * `#tftp ${loadaddr} uImage-3.6.35 #loadaddr leva dois argumentos: o endereço para carregar o arquivo e o nome do arquivo da imagem no servidor TFTP`
* Use `ubootwrite.py` para gravar a imagem do uboot e enviar um firmware modificado para obter acesso root
* Verifique se há recursos de depuração habilitados, como:
  * registro detalhado
  * carregamento de kernels arbitrários
  * inicialização de fontes não confiáveis
* \*Tenha cuidado: conecte um pino ao solo, observe a sequência de inicialização do dispositivo, antes que o kernel seja descompactado, conecte o pino aterrado a um pino de dados (DO) em um chip flash SPI
* \*Tenha cuidado: conecte um pino ao solo, observe a sequência de inicialização do dispositivo, antes que o kernel seja descompactado, conecte o pino aterrado aos pinos 8 e 9 do chip flash NAND no momento em que o U-boot descompacta a imagem UBI
  * \*Revise a folha de dados do chip flash NAND antes de curto-circuitar os pinos
* Configure um servidor DHCP falso com parâmetros maliciosos como entrada para um dispositivo ingerir durante uma inicialização PXE
  * Use o servidor auxiliar DHCP do Metasploit (MSF) e modifique o parâmetro '`FILENAME`' com comandos de injeção de comando, como `‘a";/bin/sh;#’` para testar a validação de entrada para procedimentos de inicialização do dispositivo.

\*Teste de segurança de hardware
