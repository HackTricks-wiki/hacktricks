{{#include ../../banners/hacktricks-training.md}}

## Integridade do Firmware

O **firmware personalizado e/ou binários compilados podem ser carregados para explorar falhas de verificação de integridade ou assinatura**. Os seguintes passos podem ser seguidos para a compilação de um shell bind de backdoor:

1. O firmware pode ser extraído usando firmware-mod-kit (FMK).
2. A arquitetura do firmware alvo e a ordem de bytes devem ser identificadas.
3. Um compilador cruzado pode ser construído usando Buildroot ou outros métodos adequados para o ambiente.
4. A backdoor pode ser construída usando o compilador cruzado.
5. A backdoor pode ser copiada para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. A backdoor pode ser emulada usando chroot e QEMU.
8. A backdoor pode ser acessada via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser reempacotado usando FMK.
11. O firmware com backdoor pode ser testado emulando-o com a ferramenta de análise de firmware (FAT) e conectando-se ao IP e porta da backdoor alvo usando netcat.

Se um shell root já foi obtido através de análise dinâmica, manipulação do bootloader ou testes de segurança de hardware, binários maliciosos pré-compilados, como implantes ou shells reversos, podem ser executados. Ferramentas automatizadas de payload/implante, como o framework Metasploit e 'msfvenom', podem ser aproveitadas usando os seguintes passos:

1. A arquitetura do firmware alvo e a ordem de bytes devem ser identificadas.
2. Msfvenom pode ser usado para especificar o payload alvo, IP do host atacante, número da porta de escuta, tipo de arquivo, arquitetura, plataforma e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido e garantir que ele tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com solicitações recebidas iniciando o msfconsole e configurando as definições de acordo com o payload.
5. O shell reverso meterpreter pode ser executado no dispositivo comprometido.
6. As sessões meterpreter podem ser monitoradas à medida que se abrem.
7. Atividades pós-exploração podem ser realizadas.

Se possível, vulnerabilidades dentro de scripts de inicialização podem ser exploradas para obter acesso persistente a um dispositivo durante reinicializações. Essas vulnerabilidades surgem quando scripts de inicialização referenciam, [link simbolicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dependem de código localizado em locais montados não confiáveis, como cartões SD e volumes flash usados para armazenar dados fora dos sistemas de arquivos raiz.

## Referências

- Para mais informações, consulte [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
