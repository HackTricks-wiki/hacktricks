# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Modyfikacja kontenera

Istnieją podejrzenia, że niektóry kontener docker został skompromitowany:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Możesz łatwo **znaleźć modyfikacje wprowadzone do tego kontenera w odniesieniu do obrazu** za pomocą:
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
W poprzednim poleceniu **C** oznacza **Zmienione**, a **A** oznacza **Dodane**.\
Jeśli znajdziesz, że jakiś interesujący plik, taki jak `/etc/shadow`, został zmodyfikowany, możesz go pobrać z kontenera, aby sprawdzić aktywność złośliwą za pomocą:
```bash
docker cp wordpress:/etc/shadow.
```
Możesz również **porównać to z oryginałem**, uruchamiając nowy kontener i wyodrębniając z niego plik:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Jeśli odkryjesz, że **dodano jakiś podejrzany plik**, możesz uzyskać dostęp do kontenera i go sprawdzić:
```bash
docker exec -it wordpress bash
```
## Modyfikacje obrazów

Kiedy otrzymasz wyeksportowany obraz dockera (prawdopodobnie w formacie `.tar`), możesz użyć [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases), aby **wyodrębnić podsumowanie modyfikacji**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Następnie możesz **rozpakować** obraz i **uzyskać dostęp do blobów**, aby przeszukać podejrzane pliki, które mogłeś znaleźć w historii zmian:
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
Możesz również wygenerować **dockerfile z obrazu** za pomocą:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Aby znaleźć dodane/zmodyfikowane pliki w obrazach docker, możesz również użyć [**dive**](https://github.com/wagoodman/dive) (pobierz z [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) narzędzia:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
To pozwala na **nawigację przez różne bloby obrazów dockera** i sprawdzenie, które pliki zostały zmodyfikowane/dodane. **Czerwony** oznacza dodane, a **żółty** oznacza zmodyfikowane. Użyj **tab** aby przejść do innego widoku i **spacji** aby zwinąć/otworzyć foldery.

Z die nie będziesz w stanie uzyskać dostępu do zawartości różnych etapów obrazu. Aby to zrobić, musisz **dekompresować każdą warstwę i uzyskać do niej dostęp**.\
Możesz zdekompresować wszystkie warstwy z obrazu z katalogu, w którym obraz został zdekompresowany, wykonując:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Poświadczenia z pamięci

Zauważ, że gdy uruchamiasz kontener docker na hoście **możesz zobaczyć procesy działające w kontenerze z hosta** po prostu uruchamiając `ps -ef`

Dlatego (jako root) możesz **zrzucić pamięć procesów** z hosta i wyszukać **poświadczenia** po prostu [**jak w następującym przykładzie**](../../linux-hardening/privilege-escalation/#process-memory).

{{#include ../../banners/hacktricks-training.md}}
