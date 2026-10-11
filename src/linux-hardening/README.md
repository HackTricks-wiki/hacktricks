# Fortalecimento do Linux

{{#include ../banners/hacktricks-training.md}}

Use esta seção para investigar hosts Linux, entender os limites de privilégio e revisar os controles que restringem o acesso local. Comece pelos [fundamentos do Linux](linux-basics/README.md) e pela [lista de verificação de privilege escalation](main-system-information/linux-privilege-escalation-checklist.md) para uma avaliação geral e, em seguida, consulte o tópico relevante abaixo.

- [Fundamentos do Linux](linux-basics/README.md): metodologia de privilege escalation, comandos úteis, variáveis de ambiente e bypasses de restrições.
- [Informações principais do sistema](main-system-information/README.md): kernel, módulos, sudo, comportamento do sistema de arquivos, jails e lista de verificação de privilege escalation.
- [Informações do usuário](user-information/README.md): identidades e grupos do Linux, encaminhamento do SSH agent e integração com Active Directory.
- [Arquivos interessantes e permissões](interesting-files-permissions/README.md): caminhos graváveis, capabilities, comportamento de SUID, NFS, expansão de curingas e SELinux.
- [Informações de rede](network-information/README.md): serviços locais, sockets e exemplos de exploração relacionados à rede.
- [Informações de software](software-information/README.md): módulos de autenticação e superfícies de ataque específicas de aplicações.
- [Processos, crontab, systemd e D-Bus](processes-crontab-systemd-dbus/README.md): execução agendada e comunicação entre processos.
- [Contêineres e namespaces](containers-namespaces/README.md): runtimes, limites de isolamento e hardening de contêineres.
- [Pós-exploração](post-exploitation/README.md): descoberta de credenciais, persistência e técnicas subsequentes no nível do host.
{{#include ../banners/hacktricks-training.md}}
