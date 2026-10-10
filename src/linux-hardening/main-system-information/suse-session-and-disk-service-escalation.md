# Indicadores de escalonamento por sessão SUSE e serviço de disco

{{#include ../../banners/hacktricks-training.md}}

## Autorização de sessão SSH por meio do PAM

CVE-2025-6018 afetou configurações do PAM no SUSE 15 nas quais uma pilha de autenticação SSH carregava `pam_env` antes de a pilha de sessão carregar `pam_systemd`. Quando `pam_env` lia o arquivo `.pam_environment` de um usuário, esse usuário podia fornecer valores de `XDG_SEAT` e `XDG_VTNR` que faziam uma sessão SSH parecer fisicamente ativa para o Polkit. Uma ação `allow_active=yes` poderia então ficar disponível para um usuário remoto. Isso altera a autorização da sessão; por si só, não garante acesso root. O SUSE corrigiu o comportamento padrão de leitura do ambiente do usuário em `pam` e a posição do módulo gerada por `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Inspecione a cadeia efetiva de includes de `/etc/pam.d/sshd`, a ordem de `pam_env.so` e `pam_systemd.so`, e qualquer opção explícita `user_readenv=1`. Um pacote `pam` com correção altera o comportamento padrão, mas uma opção explícita ainda pode solicitar a leitura do ambiente do usuário. Um pacote `pam-config` mais recente não comprova que uma pilha PAM modificada localmente ou desatualizada tenha sido regenerada. Verifique juntos a versão do pacote do fornecedor e a configuração real.<sup>[[1]](#references)[[2]](#references)</sup>

## Caminho do serviço de disco para usuários ativos

CVE-2025-6019 era um caminho de escalonamento em `libblockdev`, usado por meio de `udisks2`: durante o redimensionamento de XFS, um sistema de arquivos fornecido por um atacante podia ser montado temporariamente sem a restrição `nosuid` esperada. Esse caminho exige um serviço D-Bus UDisks utilizável, suporte a redimensionamento de XFS, uma ação Polkit relevante disponível para o chamador e um pacote da biblioteca afetado. CVE-2025-6018 é uma forma de obter uma sessão de usuário ativo, mas um usuário que já esteja ativo pode acessar o caminho do serviço de disco independentemente.<sup>[[3]](#references)</sup>

Para uma análise passiva, verifique os metadados do serviço UDisks, a política `org.freedesktop.udisks2.modify-device`, `xfs_growfs` e o pacote `libbd_fs2` instalado. O SUSE indica a versão `2.26-150400.3.5.1` de `libbd_fs2` como corrigida para o openSUSE Leap 15.6; a versão exata com correção depende do produto. A presença da política e do pacote são apenas indícios, não provas de que um chamador possa montar ou redimensionar um dispositivo. Evite alterar montagens ou invocar métodos D-Bus durante a enumeração.<sup>[[3]](#references)</sup>

## References

- [1] [Comunicado do SUSE sobre CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Atualização de segurança do SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Comunicado do SUSE sobre CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
