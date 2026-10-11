# Usuários, sessões e artefatos de credenciais

{{#include ../../banners/hacktricks-training.md}}

Comece pela identidade proprietária do shell atual e, em seguida, enumere outros usuários, grupos, sessões ativas e armazenamentos de credenciais. A página [ID de usuário real, efetivo e salvo](euid-ruid-suid.md) explica por que os privilégios efetivos de um processo podem ser diferentes dos da conta usada para login.

## Enumerar identidades e acessos baseados em grupos

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` inclui contas apoiadas por diretórios que uma leitura simples de `/etc/passwd` pode não encontrar. Revise contas com UID 0, shells de login, diretórios home, grupos suplementares e contas cuja configuração permita inesperadamente o login interativo. A página [grupos interessantes](interesting-groups-linux-pe/README.md) aborda acessos delegados, como `sudo`, `docker`, `disk` e `shadow`. Verifique as ACLs reais do sistema de arquivos e as políticas locais antes de considerar um nome de grupo um privilégio.

Se o [NSS direcionar consultas a `passwd`, `group` ou `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) para um banco de dados, revise o provedor ativo e o caminho da configuração antes de avaliar identidades armazenadas no banco de dados. Em implantações de PostgreSQL NSS, `/etc/nss-pgsql.conf` e `/etc/nss-pgsql-root.conf` são apenas pistas sobre caminhos, pois as configurações de conexão podem conter credenciais. Uma role do banco de dados só importa se puder alterar registros que o provedor NSS ativo realmente retorna e se uma conta puder se autenticar usando esses registros. Um GID primário de 0 concede associação ao grupo root, não UID 0; um mapeamento para o grupo sudo exige uma [regra de grupo efetiva em sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) e qualquer autenticação necessária. Um mapeamento para UID 0 representa um limite de identidade diferente. Não exiba strings de conexão nem altere registros de contas durante a enumeração passiva.

Compare também os UIDs numéricos entre nomes de contas locais. Dois nomes em [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) podem se referir à mesma identidade de arquivo Unix, embora os registros de autenticação de login sejam diferentes. Portanto, um alias recém-adicionado com um UID não zero compartilhado pode dar acesso aos arquivos ou processos de outro usuário após uma autenticação bem-sucedida; isso não concede root, a menos que esse UID ou um caminho de privilégio separado o conceda. UIDs compartilhados podem ser intencionais. Verifique a origem da conta (`/etc/passwd` versus NSS), o histórico de criação, o shell e o diretório home, a política de autenticação efetiva e se as contas estão autorizadas a compartilhar a identidade. Uma verificação apenas local de duplicatas não descarta um alias apoiado por diretório.

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

Um socket de `screen` ou `tmux` pode expor um shell existente se as permissões permitirem que o usuário atual se conecte. Verifique o proprietário e as permissões do socket antes de tentar acessá-lo; a sessão de outro usuário não pode ser acessada automaticamente. Um timestamp sudo ativo ou um socket do SSH agent também pode ser relevante, mas sua reutilização depende da identidade do usuário, das permissões e da política. Para abuso de agent forwarding, consulte [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Um [socket de controle de multiplexação do OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) é separado de `SSH_AUTH_SOCK`: `ControlMaster` e `ControlPath` permitem que clientes SSH posteriores compartilhem uma conexão autenticada existente, enquanto `ControlPersist` pode manter o master disponível após o fim da primeira sessão. Inspecione o `.ssh/config` do usuário atual e os caminhos de socket superficiais em `.ssh`, incluindo o proprietário e as permissões. O nome de um socket, por si só, não comprova que o master está ativo, que o usuário atual pode se conectar ou qual conta remota ele usa.

## Revise artefatos do usuário

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

O histórico do shell, os arquivos de inicialização, as chaves SSH, a configuração de aplicativos, os keyrings GPG e os caches Kerberos podem revelar credenciais ou pontos de persistência graváveis. Um arquivo `authorized_keys` ou de inicialização do shell gravável para uma conta mais privilegiada merece ser analisado. A [página de post-exploitation](../post-exploitation/README.md) aborda a realocação do diretório pessoal do GPG e a busca por credenciais; [Linux Active Directory](linux-active-directory.md) aborda a reutilização de caches Kerberos e keytabs. A [página do PAM](../software-information/pam-pluggable-authentication-modules.md) explica os riscos das políticas de autenticação.
{{#include ../../banners/hacktricks-training.md}}
