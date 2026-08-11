# Forenzika Docker-a

{{#include ../../banners/hacktricks-training.md}}

## Izmena kontejnera

Postoje sumnje da je neki Docker kontejner kompromitovan:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Možete lako **pronaći izmene napravljene na sistemu datoteka ovog container-a od njegovog kreiranja** pomoću:<sup>[[1]](#references)</sup>
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
U prethodnoj komandi **C** znači **Changed**, a **A** znači **Added**.<sup>[[1]](#references)</sup>\
Ako utvrdite da je neka zanimljiva datoteka, poput `/etc/shadow`, izmenjena, možete je preuzeti iz kontejnera da biste proverili da li postoje maliciozne aktivnosti:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Takođe ga možete **uporediti sa originalnim** pokretanjem novog container-a i izdvajanjem fajla iz njega:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ako utvrdite da je **dodat neki sumnjivi fajl**, možete pristupiti kontejneru i proveriti ga:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Izmene image-a

Kada dobijete izvezeni Docker image (verovatno u `.tar` formatu), možete koristiti [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) da biste **izvukli sažetak izmena**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Zatim možete **dekompresovati** sliku i **pristupiti blobovima** kako biste pretražili sumnjive datoteke koje ste možda pronašli u istoriji izmena:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Osnovna analiza

Možete dobiti **osnovne informacije** iz slike pokretanjem:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Možete dobiti i sažetu **istoriju izmena** pomoću:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Takođe možete generisati **dockerfile iz image-a** pomoću:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Da biste pronašli dodate/izmenjene datoteke u docker images, možete koristiti i alat [**dive**](https://github.com/wagoodman/dive) (preuzmite ga iz odeljka [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0):<sup>[[11]](#references)[[12]](#references)</sup>

Učitajte sačuvanu arhivu u Docker pre nego što otvorite njenu image oznaku pomoću alata dive:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Ovo vam omogućava da **se krećete kroz različite blobove docker images** i proverite koji su fajlovi izmenjeni/dodati/uklonjeni. Koristite **tab** da biste prešli na drugi prikaz, a **space** da biste skupili/otvorili foldere.<sup>[[11]](#references)</sup>

Pomoću alata dive nećete moći da pristupite sadržaju različitih stage-ova image-a. Da biste to uradili, moraćete da **dekompresujete svaki layer i pristupite mu**.\
Sve layer-e iz image-a možete dekompresovati iz direktorijuma u kojem je image dekompresovan, izvršavanjem:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Akreditivi iz memorije

Na Linux-u, PID namespace pretka hosta može da vidi procese u child PID namespace-u containera, tako da listing procesa na hostu, kao što je `ps -ef`, može da ih prikaže.<sup>[[14]](#references)</sup>

Kada host credentials, capabilities i LSM/ptrace policy to dozvoljavaju, odgovarajuće privilegovan host investigator može da **dump-uje memoriju procesa** i pretraži je u potrazi za **credentials**, baš [**kao u sledećem primeru**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Definicije analyzer-a za container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
