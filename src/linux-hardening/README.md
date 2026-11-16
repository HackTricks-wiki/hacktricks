# Fortalecimento do Linux

{{#include ../banners/hacktricks-training.md}}

Use esta seção para investigar hosts Linux, entender os limites de privilégios e revisar os controles que restringem o acesso local. Comece com o [básico do Linux](linux-basics/README.md) e a [lista de verificação de escalada de privilégios](main-system-information/linux-privilege-escalation-checklist.md) para uma avaliação geral e, em seguida, consulte o tópico relevante abaixo.

- [Básico do Linux](linux-basics/README.md): metodologia de escalada de privilégios, comandos úteis, variáveis de ambiente e formas de contornar restrições.
- [Informações principais do sistema](main-system-information/README.md): kernel, módulos, sudo, comportamento do sistema de arquivos, jails e a lista de verificação de escalada.
- [Informações do usuário](user-information/README.md): identidades e grupos do Linux, encaminhamento do agente SSH e integração com Active Directory.
- [Arquivos interessantes e permissões](interesting-files-permissions/README.md): caminhos graváveis, capabilities, comportamento de SUID, NFS, expansão de curingas e SELinux.
- [Informações de rede](network-information/README.md): serviços locais, sockets e exemplos de exploração relacionados à rede.
- [Informações de software](software-information/README.md): módulos de autenticação e superfícies de ataque específicas de aplicações.
- [Processos, crontab, systemd e D-Bus](processes-crontab-systemd-dbus/README.md): execução agendada e comunicação entre processos.
- [Contêineres e namespaces](containers-namespaces/README.md): runtimes, limites de isolamento e fortalecimento de contêineres.
- [Abuso de arquivos de controle de política do AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): avalie se um auxiliar privilegiado pode gravar em um arquivo de controle do AppArmor aberto por um usuário local.
- [Pós-exploração](post-exploitation/README.md): descoberta de credenciais, persistência e técnicas subsequentes no nível do host.

Em kernels afetados, abrir um arquivo de controle de política do AppArmor em securityfs como usuário sem privilégios pode funcionar, embora uma gravação direta seja negada. Se um auxiliar privilegiado herdar esse arquivo como stdout, a gravação poderá alterar a política carregada; esse é um caminho de ataque local distinto de simplesmente encontrar um perfil de contêiner fraco. Antes de testar, verifique as correções do kernel e do auxiliar fornecidas pelo fornecedor.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Comunicado técnico da Qualys sobre CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Base de conhecimento de vulnerabilidades do Ubuntu sobre CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
