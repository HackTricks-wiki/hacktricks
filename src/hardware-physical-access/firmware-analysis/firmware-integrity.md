{{#include ../../banners/hacktricks-training.md}}

## Integridade do Firmware

O **firmware personalizado e/ou binários compilados podem ser carregados para explorar falhas de verificação de integridade ou assinatura**. Os seguintes passos podem ser seguidos para a compilação de um backdoor bind shell:

1. O firmware pode ser extraído usando firmware-mod-kit (FMK).
2. A arquitetura do firmware alvo e a ordem de bytes devem ser identificadas.
3. Um compilador cruzado pode ser construído usando Buildroot ou outros métodos adequados para o ambiente.
4. O backdoor pode ser construído usando o compilador cruzado.
5. O backdoor pode ser copiado para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. O backdoor pode ser emulado usando chroot e QEMU.
8. O backdoor pode ser acessado via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser reempacotado usando FMK.
11. O firmware com backdoor pode ser testado emulando-o com a ferramenta de análise de firmware (FAT) e conectando-se ao IP e porta do backdoor alvo usando netcat.

Se um shell root já foi obtido através de análise dinâmica, manipulação do bootloader ou testes de segurança de hardware, binários maliciosos pré-compilados, como implantes ou shells reversos, podem ser executados. Ferramentas automatizadas de payload/implante, como o framework Metasploit e 'msfvenom', podem ser aproveitadas usando os seguintes passos:

1. A arquitetura do firmware alvo e a ordem de bytes devem ser identificadas.
2. Msfvenom pode ser usado para especificar o payload alvo, IP do host atacante, número da porta de escuta, tipo de arquivo, arquitetura, plataforma e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido e garantir que ele tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com solicitações recebidas iniciando o msfconsole e configurando as configurações de acordo com o payload.
5. O shell reverso meterpreter pode ser executado no dispositivo comprometido.

{{#include ../../banners/hacktricks-training.md}}
