# Usuários, sessões e artefatos de credenciais

{{#include ../../banners/hacktricks-training.md}}

Comece pela identidade proprietária do shell atual e, em seguida, enumere outros usuários, grupos, sessões ativas e armazenamentos de credenciais. A página sobre [real, effective, and saved user ID](euid-ruid-suid.md) explica por que os privilégios efetivos de um processo podem ser diferentes dos da conta usada para iniciar sessão.

## Enumerar identidades e acesso baseado em grupos

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` inclui contas provenientes de diretórios que uma leitura simples de `/etc/passwd` pode não mostrar. Revise contas com UID 0, shells de login, diretórios pessoais, grupos suplementares e contas cuja configuração permita inesperadamente o login interativo. A página [interesting groups](interesting-groups-linux-pe/README.md) aborda acessos delegados, como `sudo`, `docker`, `disk` e `shadow`. Verifique as ACLs reais do sistema de arquivos e as políticas locais antes de considerar um grupo um privilégio.

Se o [NSS direciona consultas a `passwd`, `group` ou `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) para um banco de dados, revise o provedor ativo e o caminho de configuração antes de avaliar identidades armazenadas no banco de dados. Em implantações PostgreSQL NSS, `/etc/nss-pgsql.conf` e `/etc/nss-pgsql-root.conf` são apenas pistas de caminhos, pois as configurações de conexão podem conter credenciais. Uma role do banco de dados só importa se puder alterar registros que o provedor NSS ativo realmente retorna e se uma conta puder se autenticar usando esses registros. Um GID primário igual a 0 concede associação ao grupo root, não UID 0; um mapeamento para o grupo sudo exige uma [regra de grupo efetiva no sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) e qualquer autenticação necessária. Um mapeamento para UID 0 constitui um limite de identidade diferente. Não exiba strings de conexão nem altere registros de contas durante a enumeração passiva.

Compare também os UIDs numéricos entre nomes de contas locais. Dois nomes em [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) podem se referir à mesma identidade de arquivo Unix, enquanto seus registros de autenticação de login podem ser diferentes. Portanto, um alias adicionado recentemente com um UID não zero compartilhado pode dar acesso aos arquivos ou processos de outro usuário após uma autenticação bem-sucedida; isso não concede root, a menos que esse UID ou um caminho de privilégio separado o conceda. UIDs compartilhados podem ser intencionais. Verifique a origem da conta (`/etc/passwd` versus NSS), o histórico de criação, o shell e o diretório pessoal, a política de autenticação real e se as contas estão autorizadas a compartilhar a identidade. Uma verificação de duplicatas apenas local não descarta um alias proveniente de diretório.

## Encontrar sessões ativas e recentes

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Um socket de `screen` ou `tmux` pode expor um shell existente se as permissões permitirem que o usuário atual se conecte. Verifique o proprietário e as permissões do socket antes de tentar acessá-lo; uma sessão de outro usuário não pode ser conectada automaticamente. Um timestamp ativo do sudo ou um socket do agente SSH também pode ser relevante, mas a reutilização depende da identidade do usuário, das permissões e da política. Para abuso de agent forwarding, consulte [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Um [socket de controle multiplexado do OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) é diferente de `SSH_AUTH_SOCK`: `ControlMaster` e `ControlPath` permitem que clientes SSH posteriores compartilhem uma conexão autenticada existente, enquanto `ControlPersist` pode manter o master disponível após o término da primeira sessão. Inspecione o `.ssh/config` do usuário atual e os caminhos de socket em `.ssh` e seus subdiretórios imediatos, incluindo o proprietário e as permissões. O nome de um socket, por si só, não comprova que o master esteja ativo, que o usuário atual possa se conectar ou qual conta remota ele usa.

## Revisar artefatos do usuário

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

O histórico do shell, os arquivos de inicialização, as chaves SSH, a configuração de aplicativos, os keyrings GPG e os caches Kerberos podem revelar credenciais ou pontos de persistência graváveis. Um arquivo `authorized_keys` ou de inicialização do shell gravável de uma conta com mais privilégios merece ser analisado. A [página de post-exploitation](../post-exploitation/README.md) aborda a realocação do homedir do GPG e a busca por credenciais; [Linux Active Directory](linux-active-directory.md) aborda a reutilização de caches Kerberos e keytabs. A [página sobre PAM](../software-information/pam-pluggable-authentication-modules.md) explica os riscos das políticas de autenticação.
{{#include ../../banners/hacktricks-training.md}}
