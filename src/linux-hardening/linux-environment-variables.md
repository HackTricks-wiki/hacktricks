# Variabili d'ambiente Linux

{{#include ../banners/hacktricks-training.md}}

## Variabili globali

Le variabili globali **saranno** ereditate dai **processi figli**.

Puoi creare una variabile globale per la tua sessione attuale facendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Questa variabile sarà accessibile dalle tue sessioni attuali e dai suoi processi figli.

Puoi **rimuovere** una variabile facendo:
```bash
unset MYGLOBAL
```
## Variabili locali

Le **variabili locali** possono essere **accessibili** solo dalla **shell/script corrente**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Elenca le variabili correnti
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – il display utilizzato da **X**. Questa variabile è solitamente impostata su **:0.0**, il che significa il primo display sul computer attuale.
- **EDITOR** – l'editor di testo preferito dall'utente.
- **HISTFILESIZE** – il numero massimo di righe contenute nel file di cronologia.
- **HISTSIZE** – Numero di righe aggiunte al file di cronologia quando l'utente termina la sua sessione.
- **HOME** – la tua directory home.
- **HOSTNAME** – il nome host del computer.
- **LANG** – la tua lingua attuale.
- **MAIL** – la posizione della cassetta postale dell'utente. Di solito **/var/spool/mail/USER**.
- **MANPATH** – l'elenco delle directory da cercare per le pagine di manuale.
- **OSTYPE** – il tipo di sistema operativo.
- **PS1** – il prompt predefinito in bash.
- **PATH** – memorizza il percorso di tutte le directory che contengono file binari che desideri eseguire semplicemente specificando il nome del file e non il percorso relativo o assoluto.
- **PWD** – la directory di lavoro attuale.
- **SHELL** – il percorso della shell dei comandi attuale (ad esempio, **/bin/bash**).
- **TERM** – il tipo di terminale attuale (ad esempio, **xterm**).
- **TZ** – il tuo fuso orario.
- **USER** – il tuo nome utente attuale.

## Variabili interessanti per l'hacking

### **HISTFILESIZE**

Cambia il **valore di questa variabile a 0**, in modo che quando **termini la tua sessione** il **file di cronologia** (\~/.bash_history) **venga eliminato**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia il **valore di questa variabile a 0**, così quando **termini la tua sessione** qualsiasi comando verrà aggiunto al **file di cronologia** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

I processi utilizzeranno il **proxy** dichiarato qui per connettersi a internet tramite **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

I processi si fideranno dei certificati indicati in **queste variabili di ambiente**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Cambia l'aspetto del tuo prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Utente normale:

![](<../images/image (740).png>)

Un, due e tre lavori in background:

![](<../images/image (145).png>)

Un lavoro in background, uno fermato e l'ultimo comando non è terminato correttamente:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
