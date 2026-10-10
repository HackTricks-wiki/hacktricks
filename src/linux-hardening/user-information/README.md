# Informações do usuário

{{#include ../../banners/hacktricks-training.md}}

A identidade do usuário, a associação a grupos e as credenciais delegadas determinam quais recursos um processo pode acessar. Verifique a identidade efetiva e os grupos suplementares antes de investigar os caminhos de acesso abaixo.

- [Usuários, sessões e artefatos de credenciais](user-and-session-triage.md) aborda a enumeração de contas, logins ativos, artefatos de SSH e shell e armazenamentos de credenciais.
- [IDs de usuário real, efetivo e salvo](euid-ruid-suid.md) explica as mudanças de identidade relacionadas a programas SUID e à execução de processos.
- [Grupos interessantes para escalonamento de privilégios no Linux](interesting-groups-linux-pe/README.md) aborda o acesso concedido por grupos, incluindo LXD/LXC.
- [Exploração do agente de encaminhamento SSH](ssh-forward-agent-exploitation.md) examina os riscos das credenciais SSH encaminhadas.
- [Active Directory no Linux](linux-active-directory.md) aborda hosts associados a um ambiente AD.

{{#include ../../banners/hacktricks-training.md}}
