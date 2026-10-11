# Fundamentos de Linux

{{#include ../../banners/hacktricks-training.md}}

Este é o ponto de partida para avaliar hosts Linux. As páginas abordam um fluxo amplo de escalonamento de privilégios, comandos práticos, variáveis de ambiente e restrições comuns que afetam o que pode ser executado em um host.

- [Escalonamento de privilégios no Linux](linux-privilege-escalation/README.md) apresenta a enumeração e possíveis caminhos de escalonamento local. Para uma lista de tarefas mais curta, use a [lista de verificação de escalonamento de privilégios](../main-system-information/linux-privilege-escalation-checklist.md).
- [Inicialização do shell, aliases e histórico](shell-startup-aliases-and-history.md) explica a resolução de comandos, a execução de arquivos de inicialização e as pistas presentes no histórico.
- [Comandos úteis do Linux](useful-linux-commands.md) reúne comandos para inspecionar arquivos, processos, serviços e o ambiente.
- [Variáveis de ambiente do Linux](linux-environment-variables.md) explica como os valores do ambiente afetam a execução e onde valores sensíveis podem aparecer.
- [Contornar restrições do Linux](bypass-linux-restrictions/README.md) aborda shells e ambientes de execução restritos, incluindo proteções do sistema de arquivos, `noexec` e sistemas distroless.

## Exploração nativa de binários

Quando uma avaliação leva a um executável Linux vulnerável, consulte o material relevante em Exploração de binários:

- [Formato ELF e comportamento do loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) e [proteções de binários e formas de contorná-las](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) explicam o layout do executável e as mitigações.
- [Exploração da stack](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) e [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) abordam ataques de fluxo de controle.
- [Exploração do heap da libc](../../binary-exploitation/libc-heap/README.md) e [format strings](../../binary-exploitation/format-strings/README.md) abordam outros caminhos comuns de corrupção de memória.

Estudos de caso específicos do kernel estão vinculados em [material sobre Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
