# Forenzika Docker-a

{{#include ../../banners/hacktricks-training.md}}


## Izmena kontejnera

Postoje sumnje da je neki docker kontejner kompromitovan:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Lako možete **pronaći izmene napravljene u ovom containeru u odnosu na image** pomoću:
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
U prethodnoj komandi **C** znači **Izmenjeno**, a **A** znači **Dodato**.\
Ako otkrijete da je neka zanimljiva datoteka, poput `/etc/shadow`, izmenjena, možete je preuzeti iz kontejnera kako biste proverili da li postoji zlonamerna aktivnost:
```bash
docker cp wordpress:/etc/shadow.
```
Možete ga takođe **uporediti sa originalnim** pokretanjem novog container-a i izdvajanjem datoteke iz njega:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ako utvrdite da je dodat **neki sumnjivi fajl**, možete pristupiti container-u i proveriti ga:
```bash
docker exec -it wordpress bash
```
## Izmene image-a

Kada dobijete izvezeni Docker image (verovatno u `.tar` formatu), možete koristiti [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) da **izvučete sažetak izmena**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Zatim možete **dekompresovati** image i **pristupiti blobovima** da biste potražili sumnjive fajlove koje ste možda pronašli u istoriji izmena:
```bash
tar -xf image.tar
```
### Osnovna analiza

**Osnovne informacije** možete dobiti pokretanjem:
```bash
docker inspect <image>
```
Možete takođe dobiti sažetak **istorije izmena** pomoću:
```bash
docker history --no-trunc <image>
```
Možete takođe generisati **dockerfile iz image-a** pomoću:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Da biste pronašli dodate/izmenjene fajlove u Docker images, možete koristiti i uslužni program [**dive**](https://github.com/wagoodman/dive) (preuzmite ga sa stranice [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Ovo vam omogućava da **se krećete kroz različite blobove docker images** i proverite koji su fajlovi izmenjeni/dodati. **Crveno** znači dodato, a **žuto** znači izmenjeno. Koristite **tab** da pređete na drugi prikaz, a **space** da sažmete/otvorite foldere.

Pomoću die nećete moći da pristupite sadržaju različitih stage-ova image-a. Da biste to uradili, moraćete da **dekompresujete svaki layer i pristupite mu**.\
Možete dekompresovati sve layer-e iz image-a iz direktorijuma u kojem je image dekompresovan, izvršavanjem:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials iz memorije

Imajte na umu da, kada pokrenete docker container unutar hosta, **možete da vidite procese koji se izvršavaju u containeru sa hosta** jednostavnim pokretanjem komande `ps -ef`

Zato (kao root) možete da **dumpujete memoriju procesa** sa hosta i pretražite je u potrazi za **credentials**, upravo [**kao u sledećem primeru**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
