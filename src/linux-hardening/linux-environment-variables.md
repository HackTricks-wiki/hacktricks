# Zmienne środowiskowe Linuxa

{{#include ../banners/hacktricks-training.md}}

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla swojej bieżącej sesji, wykonując:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ta zmienna będzie dostępna w bieżących sesjach i ich procesach potomnych.

Możesz **usunąć** zmienną, wykonując:
```bash
unset MYGLOBAL
```
## Zmienne lokalne

**Zmienne lokalne** mogą być **uzyskiwane** tylko przez **bieżącą powłokę/skrypt**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Wyświetl bieżące zmienne
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – wyświetlacz używany przez **X**. Ta zmienna jest zazwyczaj ustawiona na **:0.0**, co oznacza pierwszy wyświetlacz na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba linii zawartych w pliku historii.
- **HISTSIZE** – Liczba linii dodawanych do pliku historii, gdy użytkownik kończy swoją sesję.
- **HOME** – twój katalog domowy.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – twój bieżący język.
- **MAIL** – lokalizacja spooling poczty użytkownika. Zazwyczaj **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów do przeszukiwania w poszukiwaniu stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżkę do wszystkich katalogów, które zawierają pliki binarne, które chcesz wykonać, po prostu podając nazwę pliku, a nie względną lub absolutną ścieżkę.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – bieżący typ terminala (na przykład **xterm**).
- **TZ** – twoja strefa czasowa.
- **USER** – twoja bieżąca nazwa użytkownika.

## Interesting variables for hacking

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash_history) **został usunięty**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** żadne polecenie nie było dodawane do **pliku historii** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Procesy będą używać **proxy** zadeklarowanego tutaj, aby połączyć się z internetem przez **http lub https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Zmień wygląd swojego prompta.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Zwykły użytkownik:

![](<../images/image (740).png>)

Jedna, dwie i trzy zadania w tle:

![](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnia komenda nie zakończyła się poprawnie:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
