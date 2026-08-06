# Kryminalistyka Docker

{{#include ../../banners/hacktricks-training.md}}

## Modyfikacja kontenera

Istnieją podejrzenia, że jakiś kontener Docker został zaatakowany:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Możesz łatwo **znaleźć modyfikacje wprowadzone w tym kontenerze względem obrazu**, używając:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
W poprzednim poleceniu **C** oznacza **Changed**, a **A** — **Added**.\
Jeśli znajdziesz interesujący zmodyfikowany plik, taki jak `/etc/shadow`, możesz pobrać go z kontenera, aby sprawdzić, czy nie doszło do złośliwej aktywności:
```bash
docker cp wordpress:/etc/shadow.
```
Możesz również **porównać go z oryginalnym** plikiem, uruchamiając nowy kontener i wyodrębniając z niego plik:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Jeśli stwierdzisz, że **dodano jakiś podejrzany plik**, możesz uzyskać dostęp do kontenera i go sprawdzić:
```bash
docker exec -it wordpress bash
```
## Modyfikacje obrazów

Gdy otrzymasz wyeksportowany obraz Docker (prawdopodobnie w formacie `.tar`), możesz użyć narzędzia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases), aby **wyodrębnić podsumowanie modyfikacji**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Następnie możesz **zdekompresować** obraz i **uzyskać dostęp do blobów**, aby wyszukać podejrzane pliki, które mogłeś znaleźć w historii zmian:
```bash
tar -xf image.tar
```
### Podstawowa analiza

Możesz uzyskać **podstawowe informacje** z obrazu, uruchamiając:
```bash
docker inspect <image>
```
Możesz również uzyskać podsumowanie **historii zmian** za pomocą:
```bash
docker history --no-trunc <image>
```
Możesz także wygenerować **dockerfile z obrazu** za pomocą:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Aby znaleźć dodane/zmodyfikowane pliki w obrazach Docker, możesz również użyć narzędzia [**dive**](https://github.com/wagoodman/dive) (pobierz je z sekcji [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Umożliwia to **nawigowanie po różnych blobach obrazów docker** i sprawdzanie, które pliki zostały zmodyfikowane/dodane. **Czerwony** oznacza dodane, a **żółty** zmodyfikowane. Użyj klawisza **tab**, aby przejść do innego widoku, oraz **spacji**, aby zwinąć/rozwinąć foldery.

Za pomocą die nie będziesz mieć dostępu do zawartości poszczególnych etapów obrazu. Aby to zrobić, musisz **rozpakować każdą warstwę i uzyskać do niej dostęp**.\
Możesz rozpakować wszystkie warstwy obrazu z katalogu, w którym obraz został rozpakowany, wykonując:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Dane uwierzytelniające z pamięci

Zauważ, że gdy uruchomisz kontener docker wewnątrz hosta, **możesz zobaczyć procesy działające w kontenerze z hosta**, uruchamiając po prostu `ps -ef`

Dlatego (jako root) możesz **zrzucić pamięć procesów** z hosta i wyszukać w niej **dane uwierzytelniające**, dokładnie [**tak jak w poniższym przykładzie**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).

{{#include ../../banners/hacktricks-training.md}}
