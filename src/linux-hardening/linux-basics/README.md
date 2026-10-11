# Fundamentos do Linux

{{#include ../../banners/hacktricks-training.md}}

Este é o ponto de partida para a avaliação de hosts Linux. As páginas abordam um fluxo de trabalho amplo de privilege escalation, comandos práticos, variáveis de ambiente e restrições comuns que afetam o que pode ser executado em um host.

- [Linux privilege escalation](linux-privilege-escalation/README.md) apresenta a enumeração e possíveis caminhos de escalada local. Para uma lista de tarefas mais curta, use o [checklist de privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Inicialização do shell, aliases e histórico](shell-startup-aliases-and-history.md) explica a resolução de comandos, a execução de arquivos de inicialização e as pistas encontradas no histórico.
- [Comandos Linux úteis](useful-linux-commands.md) reúne comandos para inspecionar arquivos, processos, serviços e o ambiente.
- [Variáveis de ambiente do Linux](linux-environment-variables.md) explica como os valores do ambiente afetam a execução e onde valores confidenciais podem aparecer.
- [Contornar restrições do Linux](bypass-linux-restrictions/README.md) aborda shells e ambientes de execução restritos, incluindo proteções do sistema de arquivos, `noexec` e sistemas distroless.

## Native binary exploitation

Quando uma avaliação leva a um executável Linux vulnerável, consulte o material relevante em Binary Exploitation:

- [Formato ELF e comportamento do loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) e [proteções de binários e bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) explicam o layout do executável e as mitigações.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) e [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) abordam ataques de fluxo de controle.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) e [format strings](../../binary-exploitation/format-strings/README.md) abordam outros caminhos comuns de corrupção de memória.

Estudos de caso específicos do kernel estão vinculados em [material sobre Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
