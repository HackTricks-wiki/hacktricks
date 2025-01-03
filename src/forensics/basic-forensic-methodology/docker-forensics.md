# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Izmena kontejnera

Postoje sumnje da je neki docker kontejner kompromitovan:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Možete lako **pronaći izmene koje su izvršene na ovom kontejneru u vezi sa slikom** pomoću:
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
U prethodnoj komandi **C** znači **Promenjeno** a **A** znači **Dodato**.\
Ako otkrijete da je neki zanimljiv fajl kao što je `/etc/shadow` izmenjen, možete ga preuzeti iz kontejnera da proverite za malicioznu aktivnost sa:
```bash
docker cp wordpress:/etc/shadow.
```
Možete takođe **uporediti sa originalom** pokretanjem novog kontejnera i ekstrakcijom datoteke iz njega:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ako otkrijete da je **neki sumnjiv fajl dodat**, možete pristupiti kontejneru i proveriti ga:
```bash
docker exec -it wordpress bash
```
## Izmene slika

Kada dobijete eksportovanu docker sliku (verovatno u `.tar` formatu), možete koristiti [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) da **izvučete sažetak izmena**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Zatim možete **dekompresovati** sliku i **pristupiti blobovima** da biste pretražili sumnjive datoteke koje ste možda pronašli u istoriji promena:
```bash
tar -xf image.tar
```
### Osnovna Analiza

Možete dobiti **osnovne informacije** iz slike pokretanjem:
```bash
docker inspect <image>
```
Možete takođe dobiti sažetak **istorije promena** sa:
```bash
docker history --no-trunc <image>
```
Možete takođe generisati **dockerfile iz slike** sa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Da biste pronašli dodate/izmenjene datoteke u docker slikama, možete koristiti [**dive**](https://github.com/wagoodman/dive) (preuzmite ga sa [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) alata:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Ovo vam omogućava da **navigirate kroz različite blobove docker slika** i proverite koji su fajlovi modifikovani/dodati. **Crvena** označava dodato, a **žuta** označava modifikovano. Koristite **tab** za prelazak na drugi prikaz i **space** za skupljanje/otvaranje foldera.

Sa die nećete moći da pristupite sadržaju različitih faza slike. Da biste to uradili, moraćete da **dekompresujete svaki sloj i pristupite mu**.\
Možete dekompresovati sve slojeve iz slike iz direktorijuma gde je slika dekompresovana izvršavanjem:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Kredencijali iz memorije

Napomena da kada pokrenete docker kontejner unutar hosta **možete videti procese koji se izvršavaju na kontejneru iz hosta** jednostavno pokretanjem `ps -ef`

Stoga (kao root) možete **izvršiti dump memorije procesa** iz hosta i pretražiti za **kredencijalima** baš [**kao u sledećem primeru**](../../linux-hardening/privilege-escalation/#process-memory).


{{#include ../../banners/hacktricks-training.md}}
