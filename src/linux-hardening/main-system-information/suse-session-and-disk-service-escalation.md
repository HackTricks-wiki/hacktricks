# Indicadores de escalonamento por sessão e serviço de disco no SUSE

{{#include ../../banners/hacktricks-training.md}}

## Autorização de sessão SSH por meio do PAM

A CVE-2025-6018 afetou configurações do PAM do SUSE 15 nas quais uma pilha de autenticação SSH carregava `pam_env` antes de a pilha de sessão carregar `pam_systemd`. Quando `pam_env` lia o arquivo `.pam_environment` de um usuário, esse usuário podia fornecer valores `XDG_SEAT` e `XDG_VTNR` que faziam uma sessão SSH parecer fisicamente ativa para o Polkit. Uma ação `allow_active=yes` poderia então ficar disponível para um usuário remoto. Isso altera a autorização da sessão; por si só, não garante acesso root. O SUSE corrigiu o comportamento padrão do ambiente do usuário no `pam` e a posição do módulo gerada pelo `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Inspecione a cadeia efetiva de inclusão de `/etc/pam.d/sshd`, a ordem de `pam_env.so` e `pam_systemd.so` e qualquer opção explícita `user_readenv=1`. Um pacote `pam` corrigido altera o padrão, mas uma opção explícita ainda pode solicitar a leitura do ambiente do usuário. Um pacote `pam-config` mais recente não comprova que uma pilha PAM modificada localmente ou desatualizada foi regenerada. Verifique em conjunto a versão do pacote do fornecedor e a configuração real.<sup>[[1]](#references)[[2]](#references)</sup>

## Caminho de serviço de disco para usuário ativo

A CVE-2025-6019 era um caminho de escalonamento na `libblockdev`, usada por meio do `udisks2`: durante o redimensionamento de um XFS, um sistema de arquivos fornecido por um atacante podia ser montado temporariamente sem a restrição `nosuid` esperada. Esse caminho requer um serviço UDisks D-Bus utilizável, suporte a redimensionamento de XFS, uma ação Polkit relevante disponível para o usuário e um pacote de biblioteca afetado. A CVE-2025-6018 é uma forma de obter uma sessão de usuário ativo, mas um usuário que já esteja ativo pode alcançar o caminho do serviço de disco de forma independente.<sup>[[3]](#references)</sup>

Para uma análise passiva, verifique os metadados do serviço UDisks, a política `org.freedesktop.udisks2.modify-device`, `xfs_growfs` e o pacote `libbd_fs2` instalado. O SUSE lista a versão `2.26-150400.3.5.1` de `libbd_fs2` como corrigida para openSUSE Leap 15.6; a versão corrigida exata depende do produto. A presença da política e do pacote é apenas um indício, não prova que um usuário possa montar ou redimensionar um dispositivo. Evite alterar montagens ou invocar métodos D-Bus durante a enumeração.<sup>[[3]](#references)</sup>

## References

- [1] [Aviso do SUSE sobre a CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Atualização de segurança do SUSE para pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Aviso do SUSE sobre a CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
