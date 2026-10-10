# Fortalecimento do Linux

{{#include ../banners/hacktricks-training.md}}

Use esta seção para investigar hosts Linux, entender os limites de privilégio e revisar os controles que restringem o acesso local. Comece pelos [fundamentos do Linux](linux-basics/README.md) e pela [lista de verificação de escalonamento de privilégios](main-system-information/linux-privilege-escalation-checklist.md) para uma avaliação geral; em seguida, consulte o tópico relevante abaixo.

- [Fundamentos do Linux](linux-basics/README.md): metodologia de escalonamento de privilégios, comandos úteis, variáveis de ambiente e contornos de restrições.
- [Informações principais do sistema](main-system-information/README.md): kernel, módulos, sudo, comportamento do sistema de arquivos, jails e a lista de verificação de escalonamento.
- [Informações do usuário](user-information/README.md): identidades e grupos do Linux, encaminhamento do agente SSH e integração com o Active Directory.
- [Arquivos e permissões interessantes](interesting-files-permissions/README.md): caminhos graváveis, capabilities, comportamento de SUID, NFS, expansão de curingas e SELinux.
- [Informações de rede](network-information/README.md): serviços locais, sockets e exemplos de exploração relacionados à rede.
- [Informações de software](software-information/README.md): módulos de autenticação e superfícies de ataque específicas de aplicativos.
- [Processos, crontab, systemd e D-Bus](processes-crontab-systemd-dbus/README.md): execução agendada e comunicação entre processos.
- [Contêineres e namespaces](containers-namespaces/README.md): runtimes, limites de isolamento e hardening de contêineres.
- [Post-exploitation](post-exploitation/README.md): descoberta de credenciais, persistência e técnicas adicionais no nível do host.
{{#include ../banners/hacktricks-training.md}}
