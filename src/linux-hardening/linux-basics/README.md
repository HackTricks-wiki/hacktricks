# Noções básicas de Linux

{{#include ../../banners/hacktricks-training.md}}

Este é o ponto de partida para avaliar hosts Linux. As páginas abordam um fluxo amplo de escalada de privilégios, comandos práticos, variáveis de ambiente e restrições comuns que afetam o que pode ser executado em um host.

- [Escalada de privilégios no Linux](linux-privilege-escalation/README.md) apresenta a enumeração e possíveis caminhos de escalada local. Para uma lista de tarefas mais curta, use a [lista de verificação de escalada de privilégios](../main-system-information/linux-privilege-escalation-checklist.md).
- [Inicialização do shell, aliases e histórico](shell-startup-aliases-and-history.md) explica a resolução de comandos, a execução de arquivos de inicialização e as pistas encontradas no histórico.
- [Comandos Linux úteis](useful-linux-commands.md) reúne comandos para inspecionar arquivos, processos, serviços e o ambiente.
- [Variáveis de ambiente do Linux](linux-environment-variables.md) explica como os valores do ambiente afetam a execução e onde valores sensíveis podem aparecer.
- [Contornar restrições do Linux](bypass-linux-restrictions/README.md) aborda shells e ambientes de execução restritos, incluindo proteções do sistema de arquivos, `noexec` e sistemas distroless.

## Exploração nativa de binários

Quando uma avaliação aponta para um executável Linux vulnerável, consulte o material relevante em Binary Exploitation:

- [Formato ELF e comportamento do carregador](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) e [proteções de binários e formas de contorná-las](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) explicam a estrutura do executável e as mitigações.
- [Exploração da stack](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) e [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) abordam ataques ao fluxo de controle.
- [Exploração do heap da libc](../../binary-exploitation/libc-heap/README.md) e [format strings](../../binary-exploitation/format-strings/README.md) abordam outros caminhos comuns de corrupção de memória.

Estudos de caso específicos do kernel estão vinculados em [material sobre Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
