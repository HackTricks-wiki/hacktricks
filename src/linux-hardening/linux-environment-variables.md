# Linux Omgewing Veranderlikes

{{#include ../banners/hacktricks-training.md}}

## Globale veranderlikes

Die globale veranderlikes **sal wees** geërf deur **kind proses**.

Jy kan 'n globale veranderlike vir jou huidige sessie skep deur:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees deur jou huidige sessies en sy kindprosesse.

Jy kan 'n veranderlike **verwyder** deur:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs **toegang verkry** word deur die **huidige shell/script**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lys huidige veranderlikes
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Algemene veranderlikes

Van: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – die vertoning wat deur **X** gebruik word. Hierdie veranderlike is gewoonlik op **:0.0** gestel, wat die eerste vertoning op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se verkiesde teksredigeerder.
- **HISTFILESIZE** – die maksimum aantal lyne wat in die geskiedenis lêer bevat is.
- **HISTSIZE** – Aantal lyne wat by die geskiedenis lêer gevoeg word wanneer die gebruiker sy sessie beëindig.
- **HOME** – jou tuisgids.
- **HOSTNAME** – die rekenaar se gasheernaam.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se posspool. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys van gidse om na handleidingsbladsye te soek.
- **OSTYPE** – die tipe bedryfstelsel.
- **PS1** – die standaardprompt in bash.
- **PATH** – stoor die pad van al die gidse wat binêre lêers bevat wat jy wil uitvoer net deur die naam van die lêer te spesifiseer en nie deur relatiewe of absolute pad nie.
- **PWD** – die huidige werkgids.
- **SHELL** – die pad na die huidige opdragskel (byvoorbeeld, **/bin/bash**).
- **TERM** – die huidige terminal tipe (byvoorbeeld, **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hacking

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat wanneer jy jou **sessie beëindig** die **geskiedenis lêer** (\~/.bash_history) **verwyder sal word**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat wanneer jy jou **sessie beëindig** enige opdrag by die **geskiedenis lêer** (\~/.bash_history) gevoeg sal word.
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier verklaar is, gebruik om via **http of https** met die internet te verbind.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Verander hoe jou prompt lyk.

[**Dit is 'n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Reguliere gebruiker:

![](<../images/image (740).png>)

Een, twee en drie agtergrond take:

![](<../images/image (145).png>)

Een agtergrond taak, een gestopte en laaste opdrag het nie korrek afgehandel nie:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
