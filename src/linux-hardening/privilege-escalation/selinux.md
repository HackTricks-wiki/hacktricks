{{#include ../../banners/hacktricks-training.md}}

# SELinux em Contêineres

[Introdução e exemplo da documentação da redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) é um **sistema de rotulagem**. Cada **processo** e cada objeto do sistema de arquivos tem um **rótulo**. As políticas do SELinux definem regras sobre o que um **rótulo de processo pode fazer com todos os outros rótulos** no sistema.

Os mecanismos de contêiner lançam **processos de contêiner com um único rótulo SELinux confinado**, geralmente `container_t`, e então definem o contêiner dentro do contêiner para ser rotulado como `container_file_t`. As regras de política do SELinux basicamente dizem que os **processos `container_t` só podem ler/gravar/executar arquivos rotulados como `container_file_t`**. Se um processo de contêiner escapar do contêiner e tentar gravar em conteúdo no host, o kernel do Linux nega o acesso e permite apenas que o processo de contêiner escreva em conteúdo rotulado como `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Usuários SELinux

Existem usuários SELinux além dos usuários regulares do Linux. Os usuários SELinux fazem parte de uma política SELinux. Cada usuário do Linux é mapeado para um usuário SELinux como parte da política. Isso permite que os usuários do Linux herdem as restrições e as regras e mecanismos de segurança impostos aos usuários SELinux.

{{#include ../../banners/hacktricks-training.md}}
