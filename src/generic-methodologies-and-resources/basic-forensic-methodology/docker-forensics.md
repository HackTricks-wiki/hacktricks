# Analiza kryminalistyczna Docker

{{#include ../../banners/hacktricks-training.md}}

## Modyfikacja kontenera

Istnieją podejrzenia, że jakiś kontener Docker został przejęty:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Możesz łatwo **znaleźć zmiany wprowadzone w systemie plików tego kontenera od momentu jego utworzenia**:<sup>[[1]](#references)</sup>
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
W poprzednim poleceniu **C** oznacza **Zmieniono**, a **A** oznacza **Dodano**.<sup>[[1]](#references)</sup>\
Jeśli znajdziesz interesujący plik, taki jak `/etc/shadow`, który został zmodyfikowany, możesz pobrać go z kontenera, aby sprawdzić, czy nie występują w nim złośliwe działania:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Możesz także **porównać go z oryginalnym**, uruchamiając nowy kontener i wyodrębniając z niego plik:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Jeśli stwierdzisz, że **dodano jakiś podejrzany plik**, możesz uzyskać dostęp do kontenera i go sprawdzić:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Modyfikacje obrazów

When you are given an exported docker image (probably in `.tar` format) you can use [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) to **extract a summary of the modifications**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Następnie możesz **zdekompresować** obraz i **uzyskać dostęp do blobów**, aby wyszukać podejrzane pliki, które mogły zostać znalezione w historii zmian:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Podstawowa analiza

Możesz uzyskać **podstawowe informacje** z obrazu, uruchamiając:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Możesz również uzyskać podsumowanie **historii zmian** za pomocą:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Możesz również wygenerować **dockerfile z obrazu** za pomocą:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Aby znaleźć dodane/zmodyfikowane pliki w obrazach Docker, możesz również użyć narzędzia [**dive**](https://github.com/wagoodman/dive) (pobierz je z sekcji [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0):<sup>[[11]](#references)[[12]](#references)</sup>

Przed otwarciem tagu obrazu za pomocą dive załaduj zapisane archiwum do Docker:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Umożliwia to **nawigowanie po różnych blobach obrazów docker** i sprawdzanie, które pliki zostały zmodyfikowane/dodane/usunięte. Użyj **tab**, aby przejść do innego widoku, oraz **spacji**, aby zwijać/rozwijać foldery.<sup>[[11]](#references)</sup>

Za pomocą dive nie będziesz mieć dostępu do zawartości poszczególnych stages obrazu. Aby to zrobić, musisz **dekompresować każdą warstwę i uzyskać do niej dostęp**.\
Możesz zdekompresować wszystkie warstwy obrazu z katalogu, w którym obraz został zdekompresowany, wykonując:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Dane uwierzytelniające z pamięci

W systemie Linux nadrzędna przestrzeń nazw PID hosta może wyświetlać procesy w podrzędnej przestrzeni nazw PID kontenera, więc lista procesów hosta, taka jak `ps -ef`, może je pokazywać.<sup>[[14]](#references)</sup>

Gdy poświadczenia hosta, capabilities oraz zasady LSM/ptrace na to pozwalają, odpowiednio uprzywilejowany investigator hosta może **zrzucić pamięć procesu** i wyszukać w niej **dane uwierzytelniające** [**tak jak w poniższym przykładzie**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Różnice kontenera Docker](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Kopiowanie plików z kontenera Docker](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Uruchamianie kontenera Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Wykonywanie poleceń w kontenerze Docker](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Definicje analizatorów container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Zapisywanie obrazu Docker](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Inspekcja obrazu Docker](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Historia obrazu Docker](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Wydanie Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Wczytywanie obrazu Docker](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
