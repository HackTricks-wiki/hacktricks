# Informações principais do sistema

{{#include ../../banners/hacktricks-training.md}}

Inspecione o kernel do host, o sistema de arquivos, os helpers privilegiados e as rotas de escape disponíveis antes de escolher uma técnica de escalonamento local. A [lista de verificação de escalonamento de privilégios](linux-privilege-escalation-checklist.md) apresenta uma ordem concisa de etapas.

- [Avaliação de vulnerabilidades do kernel e exposição em tempo de execução](kernel-vulnerability-assessment.md) verifica a aplicabilidade à build, a acessibilidade e as mitigações ativas.
- [Módulos do kernel e abuso do modprobe](kernel-modules-and-modprobe.md) aborda o carregamento de módulos e a exposição de caminhos de helpers.
- [Abuso de comandos do Sudo](sudo-command-abuse.md) examina como comandos delegados podem cruzar limites de privilégios.
- [Symlinks, hardlinks e descritores de arquivo](filesystem-links-and-file-descriptors.md) aborda o redirecionamento de caminhos e arquivos herdados ou abertos e excluídos.
- [Sistema de arquivos, inodes e recuperação](filesystem-inodes-and-recovery.md) explica comportamentos do sistema de arquivos úteis durante a investigação.
- [Lista de verificação: escalonamento de privilégios no Linux](linux-privilege-escalation-checklist.md) lista verificações do host e links para materiais mais detalhados.
- [Escapar de jails](escaping-from-limited-bash.md) aborda shells limitados e ambientes restritos.
- [Materiais sobre Kernel/LPE/CVE](kernel-lpe-cves/README.md) reúne análises específicas sobre escalonamento local de privilégios e vulnerabilidades.
{{#include ../../banners/hacktricks-training.md}}
