# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Globalne promenljive **će biti** nasledjene od **dečijih procesa**.

Možete kreirati globalnu promenljivu za vašu trenutnu sesiju tako što ćete uraditi:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova promenljiva će biti dostupna vašim trenutnim sesijama i njihovim podprocesima.

Možete **ukloniti** promenljivu koristeći:
```bash
unset MYGLOBAL
```
## Lokalne promenljive

**Lokalne promenljive** mogu biti **pristupne** samo od strane **trenutne ljuske/skripte**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista trenutnih varijabli
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Uobičajene promenljive

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – prikaz koji koristi **X**. Ova promenljiva je obično postavljena na **:0.0**, što znači prvi prikaz na trenutnom računaru.
- **EDITOR** – omiljeni tekstualni editor korisnika.
- **HISTFILESIZE** – maksimalan broj linija sadržanih u datoteci istorije.
- **HISTSIZE** – Broj linija dodatih u datoteku istorije kada korisnik završi svoju sesiju.
- **HOME** – vaš kućni direktorijum.
- **HOSTNAME** – ime računara.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisničkog mail spoola. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma za pretragu priručnika.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva putanju svih direktorijuma koji sadrže binarne datoteke koje želite da izvršite samo navođenjem imena datoteke, a ne relativnom ili apsolutnom putanjom.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – putanja do trenutne komandne ljuske (na primer, **/bin/bash**).
- **TERM** – trenutna vrsta terminala (na primer, **xterm**).
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Zanimljive promenljive za hakovanje

### **HISTFILESIZE**

Promenite **vrednost ove promenljive na 0**, tako da kada **završite svoju sesiju** **datoteka istorije** (\~/.bash_history) **će biti obrisana**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promenite **vrednost ove promenljive na 0**, tako da kada **završite svoju sesiju** bilo koja komanda bude dodata u **datoteku istorije** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Procesi će koristiti **proxy** deklarisan ovde da se povežu na internet preko **http ili https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env varijablama**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Promenite izgled vašeg prompta.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Redovni korisnik:

![](<../images/image (740).png>)

Jedan, dva i tri pozadinska zadatka:

![](<../images/image (145).png>)

Jedan pozadinski zadatak, jedan zaustavljen i poslednja komanda nije završila ispravno:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
