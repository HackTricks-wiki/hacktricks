# Docker Security

{{#include ../../../banners/hacktricks-training.md}}

## **Osnovna sigurnost Docker Engine-a**

**Docker engine** koristi **Namespaces** i **Cgroups** iz Linux kernela za izolaciju kontejnera, pružajući osnovni sloj sigurnosti. Dodatna zaštita se obezbeđuje kroz **Capabilities dropping**, **Seccomp** i **SELinux/AppArmor**, poboljšavajući izolaciju kontejnera. **Auth plugin** može dodatno ograničiti korisničke akcije.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Siguran pristup Docker Engine-u

Docker engine može se pristupiti lokalno putem Unix soketa ili daljinski koristeći HTTP. Za daljinski pristup, neophodno je koristiti HTTPS i **TLS** kako bi se obezbedila poverljivost, integritet i autentifikacija.

Docker engine, po defaultu, sluša na Unix soketu na `unix:///var/run/docker.sock`. Na Ubuntu sistemima, opcije pokretanja Dockera su definisane u `/etc/default/docker`. Da biste omogućili daljinski pristup Docker API-ju i klijentu, izložite Docker demon preko HTTP soketa dodavanjem sledećih podešavanja:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Međutim, izlaganje Docker demona preko HTTP-a nije preporučljivo zbog bezbednosnih problema. Preporučuje se osiguranje veza korišćenjem HTTPS-a. Postoje dva glavna pristupa za osiguranje veze:

1. Klijent verifikuje identitet servera.
2. I klijent i server međusobno autentifikuju identitet jedan drugog.

Sertifikati se koriste za potvrdu identiteta servera. Za detaljne primere oba metoda, pogledajte [**ovaj vodič**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Bezbednost slika kontejnera

Slike kontejnera mogu biti smeštene u privatnim ili javnim repozitorijumima. Docker nudi nekoliko opcija za skladištenje slika kontejnera:

- [**Docker Hub**](https://hub.docker.com): Javni registar usluga od Docker-a.
- [**Docker Registry**](https://github.com/docker/distribution): Open-source projekat koji omogućava korisnicima da hostuju svoj registar.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Komercijalna ponuda Docker-ovog registra, sa autentifikacijom korisnika zasnovanom na rolama i integracijom sa LDAP servisima.

### Skener slika

Kontejneri mogu imati **bezbednosne ranjivosti** ili zbog osnovne slike ili zbog softvera instaliranog na osnovnoj slici. Docker radi na projektu pod nazivom **Nautilus** koji vrši bezbednosno skeniranje kontejnera i navodi ranjivosti. Nautilus funkcioniše tako što upoređuje svaku sloj slike kontejnera sa repozitorijumom ranjivosti kako bi identifikovao bezbednosne rupe.

Za više [**informacija pročitajte ovo**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Komanda **`docker scan`** omogućava vam da skenirate postojeće Docker slike koristeći ime ili ID slike. Na primer, pokrenite sledeću komandu da skenirate hello-world sliku:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker Image Signing

Docker image signing osigurava sigurnost i integritet slika korišćenih u kontejnerima. Evo sažetka:

- **Docker Content Trust** koristi Notary projekat, zasnovan na The Update Framework (TUF), za upravljanje potpisivanjem slika. Za više informacija, pogledajte [Notary](https://github.com/docker/notary) i [TUF](https://theupdateframework.github.io).
- Da aktivirate Docker content trust, postavite `export DOCKER_CONTENT_TRUST=1`. Ova funkcija je po defaultu isključena u Docker verziji 1.10 i novijim.
- Sa ovom funkcijom uključenom, samo potpisane slike mogu biti preuzete. Prvo slanje slike zahteva postavljanje lozinki za root i tagging ključeve, pri čemu Docker takođe podržava Yubikey za poboljšanu sigurnost. Više detalja možete pronaći [ovde](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Pokušaj preuzimanja nepodpisane slike sa uključenim content trust rezultira greškom "No trust data for latest".
- Za slanja slika nakon prvog, Docker traži lozinku za repozitorijum ključ da potpiše sliku.

Da biste napravili rezervnu kopiju svojih privatnih ključeva, koristite komandu:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Kada se prebacujete između Docker hostova, neophodno je premestiti root i repozitorijum ključeve kako bi se održale operacije.

## Bezbednosne karakteristike kontejnera

<details>

<summary>Sažetak bezbednosnih karakteristika kontejnera</summary>

**Glavne karakteristike izolacije procesa**

U kontejnerizovanim okruženjima, izolacija projekata i njihovih procesa je od suštinskog značaja za bezbednost i upravljanje resursima. Evo pojednostavljenog objašnjenja ključnih koncepata:

**Namespaces**

- **Svrha**: Osiguranje izolacije resursa kao što su procesi, mreža i fajl sistemi. Posebno u Docker-u, namespaces drže procese kontejnera odvojene od hosta i drugih kontejnera.
- **Korišćenje `unshare`**: Komanda `unshare` (ili osnovni syscall) se koristi za kreiranje novih namespaces, pružajući dodatni sloj izolacije. Međutim, dok Kubernetes to inherentno ne blokira, Docker to čini.
- **Ograničenje**: Kreiranje novih namespaces ne omogućava procesu da se vrati na podrazumevane namespaces hosta. Da bi se penetriralo u namespaces hosta, obično bi bilo potrebno pristupiti hostovom `/proc` direktorijumu, koristeći `nsenter` za ulazak.

**Kontrolne grupe (CGroups)**

- **Funkcija**: Primarno se koriste za dodeljivanje resursa među procesima.
- **Aspekt bezbednosti**: CGroups same po sebi ne nude bezbednost izolacije, osim za `release_agent` funkciju, koja, ako je pogrešno konfigurisana, može potencijalno biti iskorišćena za neovlašćen pristup.

**Smanjenje sposobnosti**

- **Značaj**: To je ključna bezbednosna karakteristika za izolaciju procesa.
- **Funkcionalnost**: Ograničava radnje koje root proces može izvesti smanjenjem određenih sposobnosti. Čak i ako proces radi sa root privilegijama, nedostatak potrebnih sposobnosti sprečava ga da izvršava privilegovane radnje, jer će syscalls propasti zbog nedovoljnih dozvola.

Ovo su **preostale sposobnosti** nakon što proces odbaci ostale:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Omogućeno je po defaultu u Dockeru. Pomaže da se **dodatno ograniče syscalls** koje proces može pozvati.\
**Default Docker Seccomp profil** može se naći na [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ima šablon koji možete aktivirati: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Ovo će omogućiti smanjenje sposobnosti, syscalls, pristupa datotekama i folderima...

</details>

### Namespaces

**Namespaces** su funkcija Linux kernela koja **particionira kernel resurse** tako da jedan skup **procesa** **vidi** jedan skup **resursa** dok **drugi** skup **procesa** vidi **drugačiji** skup resursa. Funkcija radi tako što ima isti namespace za skup resursa i procesa, ali ti namespaces se odnose na različite resurse. Resursi mogu postojati u više prostora.

Docker koristi sledeće Linux kernel Namespaces za postizanje izolacije kontejnera:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Za **više informacija o namespaces** proverite sledeću stranicu:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Funkcija Linux kernela **cgroups** pruža mogućnost da **ograniči resurse kao što su cpu, memorija, io, mrežni propusni opseg među** skupom procesa. Docker omogućava kreiranje kontejnera koristeći cgroup funkciju koja omogućava kontrolu resursa za specifični kontejner.\
Sledeći je kontejner kreiran sa memorijom korisničkog prostora ograničenom na 500m, memorijom kernela ograničenom na 50m, deljenjem cpu na 512, blkioweight na 400. Deljenje CPU je odnos koji kontroliše korišćenje CPU kontejnera. Ima podrazumevanu vrednost od 1024 i opseg između 0 i 1024. Ako tri kontejnera imaju isto deljenje CPU od 1024, svaki kontejner može uzeti do 33% CPU u slučaju sukoba resursa CPU. blkio-weight je odnos koji kontroliše IO kontejnera. Ima podrazumevanu vrednost od 500 i opseg između 10 i 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Da biste dobili cgroup kontejnera, možete uraditi:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Za više informacija proverite:

{{#ref}}
cgroups.md
{{#endref}}

### Kapaciteti

Kapaciteti omogućavaju **finer control for the capabilities that can be allowed** za root korisnika. Docker koristi funkciju kapaciteta Linux kernela da **limitira operacije koje se mogu izvesti unutar kontejnera** bez obzira na tip korisnika.

Kada se docker kontejner pokrene, **proces gubi osetljive kapacitete koje bi proces mogao koristiti da pobegne iz izolacije**. Ovo pokušava da osigura da proces neće moći da izvrši osetljive radnje i pobegne:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp u Dockeru

Ovo je bezbednosna funkcija koja omogućava Dockeru da **limitira syscalls** koje se mogu koristiti unutar kontejnera:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor u Dockeru

**AppArmor** je poboljšanje kernela koje ograničava **kontejnere** na **ograničen** skup **resursa** sa **profilima po programu**.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux u Dockeru

- **Sistem označavanja**: SELinux dodeljuje jedinstvenu oznaku svakom procesu i objektu datotečnog sistema.
- **Sprovođenje politika**: Sprovodi bezbednosne politike koje definišu koje radnje oznaka procesa može izvršiti na drugim oznakama unutar sistema.
- **Oznake procesa kontejnera**: Kada kontejnerski motori pokreću procese kontejnera, obično im se dodeljuje ograničena SELinux oznaka, obično `container_t`.
- **Označavanje datoteka unutar kontejnera**: Datoteke unutar kontejnera obično su označene kao `container_file_t`.
- **Pravila politike**: SELinux politika prvenstveno osigurava da procesi sa oznakom `container_t` mogu da interaguju (čitaju, pišu, izvršavaju) samo sa datotekama označenim kao `container_file_t`.

Ovaj mehanizam osigurava da čak i ako je proces unutar kontejnera kompromitovan, on je ograničen na interakciju samo sa objektima koji imaju odgovarajuće oznake, značajno ograničavajući potencijalnu štetu od takvih kompromitacija.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

U Dockeru, autorizacioni dodatak igra ključnu ulogu u bezbednosti odlučujući da li da dozvoli ili blokira zahteve ka Docker demon-u. Ova odluka se donosi ispitivanjem dva ključna konteksta:

- **Kontekst autentifikacije**: Ovo uključuje sveobuhvatne informacije o korisniku, kao što su ko su i kako su se autentifikovali.
- **Kontekst komande**: Ovo obuhvata sve relevantne podatke vezane za zahtev koji se podnosi.

Ovi konteksti pomažu da se osigura da se obrađuju samo legitimni zahtevi od autentifikovanih korisnika, poboljšavajući bezbednost Docker operacija.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS iz kontejnera

Ako ne ograničavate pravilno resurse koje kontejner može koristiti, kompromitovani kontejner bi mogao izazvati DoS na hostu na kojem se pokreće.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- Bandwidth DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Zanimljive Docker zastavice

### --privileged zastavica

Na sledećoj stranici možete saznati **šta podrazumeva `--privileged` zastavica**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Ako pokrećete kontejner u kojem napadač uspe da dobije pristup kao korisnik sa niskim privilegijama. Ako imate **loše konfigurisanu suid binarnu datoteku**, napadač može da je zloupotrebi i **poveća privilegije unutar** kontejnera. Što mu može omogućiti da pobegne iz njega.

Pokretanje kontejnera sa **`no-new-privileges`** opcijom omogućenom će **sprečiti ovu vrstu eskalacije privilegija**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Drugo
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Za više **`--security-opt`** opcija pogledajte: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Ostale Bezbednosne Razmatranja

### Upravljanje Tajnama: Najbolje Prakse

Ključno je izbegavati ugrađivanje tajni direktno u Docker slike ili korišćenje promenljivih okruženja, jer ove metode izlažu vaše osetljive informacije svima koji imaju pristup kontejneru putem komandi kao što su `docker inspect` ili `exec`.

**Docker volumeni** su sigurnija alternativa, preporučena za pristup osetljivim informacijama. Mogu se koristiti kao privremeni fajl sistem u memoriji, smanjujući rizike povezane sa `docker inspect` i logovanjem. Međutim, korisnici sa root privilegijama i oni sa `exec` pristupom kontejneru i dalje mogu pristupiti tajnama.

**Docker tajne** nude još sigurniju metodu za rukovanje osetljivim informacijama. Za instance koje zahtevaju tajne tokom faze izgradnje slike, **BuildKit** predstavlja efikasno rešenje sa podrškom za tajne u vreme izgradnje, poboljšavajući brzinu izgradnje i pružajući dodatne funkcije.

Da biste iskoristili BuildKit, može se aktivirati na tri načina:

1. Kroz promenljivu okruženja: `export DOCKER_BUILDKIT=1`
2. Prefiksovanjem komandi: `DOCKER_BUILDKIT=1 docker build .`
3. Omogućavanjem po defaultu u Docker konfiguraciji: `{ "features": { "buildkit": true } }`, nakon čega sledi restart Dockera.

BuildKit omogućava korišćenje tajni u vreme izgradnje sa opcijom `--secret`, osiguravajući da ove tajne nisu uključene u keš izgradnje slike ili konačnu sliku, koristeći komandu kao što je:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Za tajne potrebne u aktivnom kontejneru, **Docker Compose i Kubernetes** nude robusna rešenja. Docker Compose koristi ključ `secrets` u definiciji servisa za specificiranje tajnih fajlova, kao što je prikazano u primeru `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Ova konfiguracija omogućava korišćenje tajni prilikom pokretanja servisa sa Docker Compose.

U Kubernetes okruženjima, tajne su nativno podržane i mogu se dodatno upravljati alatima kao što je [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Kontrole pristupa zasnovane na ulogama (RBAC) u Kubernetes-u poboljšavaju bezbednost upravljanja tajnama, slično kao u Docker Enterprise.

### gVisor

**gVisor** je aplikacioni kernel, napisan u Go, koji implementira značajan deo Linux sistemske površine. Uključuje [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime pod nazivom `runsc` koji pruža **granicu izolacije između aplikacije i host kernela**. `runsc` runtime se integriše sa Docker-om i Kubernetes-om, što olakšava pokretanje sandboxed kontejnera.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** je zajednica otvorenog koda koja radi na izgradnji sigurnog kontejnerskog runtime-a sa laganim virtuelnim mašinama koje se ponašaju i performiraju kao kontejneri, ali pružaju **jaču izolaciju radnog opterećenja koristeći tehnologiju hardverske virtualizacije** kao drugu liniju odbrane.

{% embed url="https://katacontainers.io/" %}

### Saveti za rezime

- **Ne koristite `--privileged` flag ili montirajte** [**Docker socket unutar kontejnera**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Docker socket omogućava pokretanje kontejnera, tako da je to lak način da preuzmete potpunu kontrolu nad hostom, na primer, pokretanjem drugog kontejnera sa `--privileged` flag-om.
- **Ne pokrećite kao root unutar kontejnera. Koristite** [**drugog korisnika**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **i** [**namespaces korisnika**](https://docs.docker.com/engine/security/userns-remap/)**.** Root u kontejneru je isti kao na hostu osim ako nije premapiran sa namespaces korisnika. Samo je blago ograničen, prvenstveno, Linux namespaces, sposobnostima i cgroups.
- [**Uklonite sve sposobnosti**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) i omogućite samo one koje su potrebne** (`--cap-add=...`). Mnoge radne opterećenja ne trebaju nikakve sposobnosti i njihovo dodavanje povećava opseg potencijalnog napada.
- [**Koristite opciju bez novih privilegija**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) kako biste sprečili procese da dobiju više privilegija, na primer kroz suid binarne datoteke.
- [**Ograničite resurse dostupne kontejneru**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Ograničenja resursa mogu zaštititi mašinu od napada uskraćivanja usluga.
- **Prilagodite** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ili SELinux)** profile kako biste ograničili radnje i syscalls dostupne kontejneru na minimum potreban.
- **Koristite** [**službene docker slike**](https://docs.docker.com/docker-hub/official_images/) **i zahtevajte potpise** ili izgradite svoje na osnovu njih. Ne nasleđujte ili koristite [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) slike. Takođe, čuvajte root ključeve, lozinke na sigurnom mestu. Docker planira da upravlja ključevima sa UCP.
- **Redovno** **ponovo izgradite** svoje slike kako biste **primenili bezbednosne zakrpe na host i slike.**
- Pametno upravljajte svojim **tajnama** kako bi napadaču bilo teško da im pristupi.
- Ako **izlažete docker daemon koristite HTTPS** sa autentifikacijom klijenta i servera.
- U vašem Dockerfile-u, **favorizujte COPY umesto ADD**. ADD automatski izvlači zipovane datoteke i može kopirati datoteke sa URL-ova. COPY nema te mogućnosti. Kada god je to moguće, izbegavajte korišćenje ADD kako ne biste bili podložni napadima putem udaljenih URL-ova i zip datoteka.
- Imate **odvojene kontejnere za svaku mikro** uslugu.
- **Ne stavljajte ssh** unutar kontejnera, “docker exec” se može koristiti za ssh u kontejner.
- Imate **manje** slike **kontejnera**.

## Docker Breakout / Eskalacija privilegija

Ako ste **unutar docker kontejnera** ili imate pristup korisniku u **docker grupi**, možete pokušati da **pobegnete i eskalirate privilegije**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Zaobilaženje Docker Authentication Plugin-a

Ako imate pristup docker socket-u ili imate pristup korisniku u **docker grupi, ali su vaše akcije ograničene docker auth plugin-om**, proverite da li možete **da ga zaobiđete:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Ojačavanje Dockera

- Alat [**docker-bench-security**](https://github.com/docker/docker-bench-security) je skripta koja proverava desetine uobičajenih najboljih praksi oko implementacije Docker kontejnera u produkciji. Testovi su svi automatizovani i zasnovani su na [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Morate pokrenuti alat sa hosta koji pokreće docker ili iz kontejnera sa dovoljno privilegija. Saznajte **kako ga pokrenuti u README-u:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Reference

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

{{#include ../../../banners/hacktricks-training.md}}
