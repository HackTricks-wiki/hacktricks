# Analiza śledcza Docker

{{#include ../../banners/hacktricks-training.md}}


## Modyfikacja kontenera

Istnieją podejrzenia, że jakiś kontener Docker został naruszony:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Możesz łatwo **znaleźć modyfikacje wprowadzone w tym kontenerze względem obrazu** za pomocą:
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
W poprzednim poleceniu **C** oznacza **Zmodyfikowano**, a **A** — **Dodano**.\
Jeśli znajdziesz, że jakiś interesujący plik, taki jak `/etc/shadow`, został zmodyfikowany, możesz pobrać go z kontenera, aby sprawdzić, czy nie wykazuje złośliwej aktywności:
```bash
docker cp wordpress:/etc/shadow.
```
Możesz również **porównać go z oryginalnym**, uruchamiając nowy kontener i wyodrębniając z niego plik:
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
Następnie możesz **rozpakować** obraz i **uzyskać dostęp do blobów**, aby wyszukać podejrzane pliki, które mogłeś znaleźć w historii zmian:
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
Możesz również wygenerować **dockerfile na podstawie obrazu** za pomocą:
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
Pozwala to **poruszać się po różnych blobach obrazów docker** i sprawdzać, które pliki zostały zmodyfikowane/dodane. **Czerwony** oznacza dodane, a **żółty** zmodyfikowane. Użyj klawisza **tab**, aby przejść do drugiego widoku, oraz **spacji**, aby zwijać/rozwijać foldery.

Za pomocą die nie będzie można uzyskać dostępu do zawartości poszczególnych etapów obrazu. Aby to zrobić, musisz **zdekompresować każdą warstwę i uzyskać do niej dostęp**.\
Możesz zdekompresować wszystkie warstwy obrazu z katalogu, w którym obraz został zdekompresowany, wykonując:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Dane uwierzytelniające z pamięci

Zauważ, że gdy uruchomisz kontener dockerowy wewnątrz hosta, **z hosta możesz zobaczyć procesy uruchomione w kontenerze**, wykonując po prostu `ps -ef`

Dlatego (jako root) możesz **zrzucić pamięć procesów** z hosta i wyszukać **dane uwierzytelniające**, dokładnie [**tak jak w poniższym przykładzie**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
