# Informações principais do sistema

{{#include ../../banners/hacktricks-training.md}}

Inspecione o kernel do host, o sistema de arquivos, os helpers privilegiados e as rotas de escape disponíveis antes de escolher uma técnica de escalada local. A [lista de verificação de escalada de privilégios](linux-privilege-escalation-checklist.md) apresenta uma ordem de operações concisa.

- [Avaliação de vulnerabilidades do kernel e exposição em tempo de execução](kernel-vulnerability-assessment.md) verifica a aplicabilidade da build, a acessibilidade e as mitigações ativas.
- [Módulos do kernel e abuso do modprobe](kernel-modules-and-modprobe.md) aborda o carregamento de módulos e a exposição do caminho do helper.
- [Abuso de comandos sudo](sudo-command-abuse.md) examina maneiras pelas quais comandos delegados podem ultrapassar limites de privilégios.
- [Symlinks, hardlinks e descritores de arquivos](filesystem-links-and-file-descriptors.md) aborda o redirecionamento de caminhos e arquivos herdados ou abertos que foram excluídos.
- [Sistema de arquivos, inodes e recuperação](filesystem-inodes-and-recovery.md) explica o comportamento do sistema de arquivos útil durante a investigação.
- [Lista de verificação: escalada de privilégios no Linux](linux-privilege-escalation-checklist.md) lista verificações do host e links para materiais mais detalhados.
- [Escaping de jails](escaping-from-limited-bash.md) aborda shells limitados e ambientes restritos.
- [Materiais sobre Kernel/LPE/CVE](kernel-lpe-cves/README.md) reúne análises específicas sobre escalada local de privilégios e vulnerabilidades.
{{#include ../../banners/hacktricks-training.md}}
