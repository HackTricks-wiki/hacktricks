# Docker Sekuriteit

{{#include ../../../banners/hacktricks-training.md}}

## **Basiese Docker Engine Sekuriteit**

Die **Docker engine** gebruik die Linux-kern se **Namespaces** en **Cgroups** om houers te isoleer, wat 'n basiese laag van sekuriteit bied. Addisionele beskerming word verskaf deur **Capabilities dropping**, **Seccomp**, en **SELinux/AppArmor**, wat houer-isolasie verbeter. 'n **auth plugin** kan gebruikersaksies verder beperk.

![Docker Sekuriteit](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Veilige Toegang tot Docker Engine

Die Docker engine kan plaaslik via 'n Unix-sok of afstandelik met HTTP toeganklik gemaak word. Vir afstandelike toegang is dit noodsaaklik om HTTPS en **TLS** te gebruik om vertroulikheid, integriteit en outentisering te verseker.

Die Docker engine luister standaard op die Unix-sok by `unix:///var/run/docker.sock`. Op Ubuntu-stelsels word Docker se opstartopsies gedefinieer in `/etc/default/docker`. Om afstandelike toegang tot die Docker API en kliënt te aktiveer, stel die Docker daemon bloot deur die volgende instellings by te voeg:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
egter, om die Docker daemon oor HTTP bloot te stel, word nie aanbeveel nie weens sekuriteitskwessies. Dit is raadsaam om verbindings te beveilig met behulp van HTTPS. Daar is twee hoofbenaderings om die verbinding te beveilig:

1. Die kliënt verifieer die bediener se identiteit.
2. Beide die kliënt en bediener verifieer mekaar se identiteit.

Sertifikate word gebruik om 'n bediener se identiteit te bevestig. Vir gedetailleerde voorbeelde van beide metodes, verwys na [**hierdie gids**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sekuriteit van Houer Beelde

Houer beelde kan in privaat of openbare repositories gestoor word. Docker bied verskeie stooropsies vir houer beelde:

- [**Docker Hub**](https://hub.docker.com): 'n Openbare registrasiediens van Docker.
- [**Docker Registry**](https://github.com/docker/distribution): 'n Oopbronprojek wat gebruikers toelaat om hul eie registrasie te huisves.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Docker se kommersiële registrasie-aanbod, wat rolgebaseerde gebruikersverifikasie en integrasie met LDAP-gidsdienste insluit.

### Beeld Skandering

Houer kan **sekuriteitskwesies** hê, hetsy as gevolg van die basisbeeld of as gevolg van die sagteware wat bo-op die basisbeeld geïnstalleer is. Docker werk aan 'n projek genaamd **Nautilus** wat 'n sekuriteitsskandering van Houers doen en die kwesbaarhede lys. Nautilus werk deur elke Houer beeldlaag met die kwesbaarheidrepository te vergelyk om sekuriteitsgate te identifiseer.

Vir meer [**inligting lees dit**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Die **`docker scan`** opdrag laat jou toe om bestaande Docker beelde te skandeer met behulp van die beeldnaam of ID. Byvoorbeeld, voer die volgende opdrag uit om die hello-world beeld te skandeer:
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
### Docker Beeld Handtekening

Docker beeld handtekening verseker die sekuriteit en integriteit van beelde wat in houers gebruik word. Hier is 'n saamgeperste verduideliking:

- **Docker Inhoud Vertroue** maak gebruik van die Notary projek, gebaseer op The Update Framework (TUF), om beeld handtekening te bestuur. Vir meer inligting, sien [Notary](https://github.com/docker/notary) en [TUF](https://theupdateframework.github.io).
- Om Docker inhoud vertroue te aktiveer, stel `export DOCKER_CONTENT_TRUST=1` in. Hierdie funksie is standaard afgeskakel in Docker weergawe 1.10 en later.
- Met hierdie funksie geaktiveer, kan slegs ondertekende beelde afgelaai word. Die aanvanklike beeld druk vereis die instelling van wagwoorde vir die wortel en etikettering sleutels, met Docker wat ook Yubikey ondersteun vir verbeterde sekuriteit. Meer besonderhede kan [hier](https://blog.docker.com/2015/11/docker-content-trust-yubikey/) gevind word.
- Pogings om 'n ongetekende beeld te trek met inhoud vertroue geaktiveer, lei tot 'n "Geen vertrou data vir laaste" fout.
- Vir beeld druk na die eerste, vra Docker vir die deposito sleutel se wagwoord om die beeld te teken.

Om jou private sleutels te rugsteun, gebruik die opdrag:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Wanneer jy Docker-gashere verander, is dit nodig om die wortel- en repository-sleutels te skuif om bedrywighede te handhaaf.

## Houers Sekuriteitskenmerke

<details>

<summary>Samevatting van Houer Sekuriteitskenmerke</summary>

**Hoof Proses Isolasie Kenmerke**

In gecontaineriseerde omgewings is dit van kardinale belang om projekte en hul prosesse te isoleer vir sekuriteit en hulpbronbestuur. Hier is 'n vereenvoudigde verduideliking van sleutelkonsepte:

**Namespaces**

- **Doel**: Verseker isolasie van hulpbronne soos prosesse, netwerk, en lêerstelsels. Veral in Docker, hou namespaces 'n houer se prosesse apart van die gasheer en ander houers.
- **Gebruik van `unshare`**: Die `unshare` opdrag (of die onderliggende syscall) word gebruik om nuwe namespaces te skep, wat 'n bykomende laag van isolasie bied. Tog, terwyl Kubernetes dit nie inherent blokkeer nie, doen Docker dit.
- **Beperking**: Die skep van nuwe namespaces laat nie 'n proses toe om na die gasheer se standaard namespaces terug te keer nie. Om in die gasheer namespaces te dring, sou 'n mens tipies toegang tot die gasheer se `/proc` gids benodig, met `nsenter` vir toegang.

**Beheer Groepe (CGroups)**

- **Funksie**: Primêr gebruik vir die toewysing van hulpbronne onder prosesse.
- **Sekuriteitsaspek**: CGroups self bied nie isolasie sekuriteit nie, behalwe vir die `release_agent` kenmerk, wat, indien verkeerd geconfigureer, potensieel misbruik kan word vir ongeoorloofde toegang.

**Vermogen Val**

- **Belangrikheid**: Dit is 'n noodsaaklike sekuriteitskenmerk vir proses isolasie.
- **Funksionaliteit**: Dit beperk die aksies wat 'n wortel proses kan uitvoer deur sekere vermogens te laat val. Selfs al loop 'n proses met wortelregte, verhoed die gebrek aan die nodige vermogens dat dit bevoorregte aksies kan uitvoer, aangesien die syscalls sal misluk weens onvoldoende toestemmings.

Dit is die **oorblywende vermogens** nadat die proses die ander laat val het:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Dit is standaard in Docker geaktiveer. Dit help om **die syscalls** wat die proses kan aanroep, **nog verder te beperk**.\
Die **standaard Docker Seccomp-profiel** kan gevind word in [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker het 'n sjabloon wat jy kan aktiveer: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Dit sal toelaat om vermoëns, syscalls, toegang tot lêers en vouers te verminder...

</details>

### Namespaces

**Namespaces** is 'n kenmerk van die Linux-kern wat **kernhulpbronne** partitioneer sodat een stel **prosesse** **een stel hulpbronne** sien terwyl **'n ander** stel **prosesse** 'n **verskillende** stel hulpbronne sien. Die kenmerk werk deur die samelewing van die selfde namespace vir 'n stel hulpbronne en prosesse, maar daardie namespaces verwys na onderskeie hulpbronne. Hulpbronne kan in verskeie ruimtes bestaan.

Docker maak gebruik van die volgende Linux-kern Namespaces om Containere isolasie te bereik:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Vir **meer inligting oor die namespaces** kyk na die volgende bladsy:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Die Linux-kern kenmerk **cgroups** bied die vermoë om **hulpbronne soos cpu, geheue, io, netwerkbandwydte onder** 'n stel prosesse te **beperk**. Docker laat toe om Containere te skep met behulp van die cgroup kenmerk wat hulpbronbeheer vir die spesifieke Container toelaat.\
Hieronder is 'n Container geskep met gebruikersruimte geheue beperk tot 500m, kern geheue beperk tot 50m, cpu-aandeel tot 512, blkioweight tot 400. CPU-aandeel is 'n verhouding wat die Container se CPU-gebruik beheer. Dit het 'n standaardwaarde van 1024 en 'n reeks tussen 0 en 1024. As drie Containere dieselfde CPU-aandeel van 1024 het, kan elke Container tot 33% van die CPU neem in die geval van CPU-hulpbronkompetisie. blkio-weight is 'n verhouding wat die Container se IO beheer. Dit het 'n standaardwaarde van 500 en 'n reeks tussen 10 en 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Om die cgroup van 'n houer te kry, kan jy doen:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Vir meer inligting, kyk:

{{#ref}}
cgroups.md
{{#endref}}

### Vermoëns

Vermoëns stel **finer beheer van die vermoëns wat vir die wortelgebruiker toegelaat kan word** moontlik. Docker gebruik die Linux-kern vermoënskenmerk om **die operasies wat binne 'n houer gedoen kan word, te beperk** ongeag die tipe gebruiker.

Wanneer 'n docker-houer gedraai word, **laat die proses sensitiewe vermoëns wat die proses kon gebruik om uit die isolasie te ontsnap, val**. Dit probeer verseker dat die proses nie sensitiewe aksies kan uitvoer en ontsnap nie:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp in Docker

Dit is 'n sekuriteitskenmerk wat Docker toelaat om **die syscalls** wat binne die houer gebruik kan word, te beperk:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor in Docker

**AppArmor** is 'n kernverbetering om **houers** tot 'n **beperkte** stel **hulpbronne** met **per-program profiele** te beperk.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux in Docker

- **Etiketstelsel**: SELinux ken 'n unieke etiket aan elke proses en lêersysteemobjek toe.
- **Beleidstoepassing**: Dit handhaaf sekuriteitsbeleide wat definieer watter aksies 'n proses etiket op ander etikette binne die stelsel kan uitvoer.
- **Houer Proses Etikette**: Wanneer houer enjinse houerprosesse inisieer, word hulle gewoonlik 'n beperkte SELinux-etiket, algemeen `container_t`, toegeken.
- **Lêer Etikettering binne Houers**: Lêers binne die houer word gewoonlik as `container_file_t` geëtiketteer.
- **Beleidreëls**: Die SELinux-beleid verseker hoofsaaklik dat prosesse met die `container_t` etiket slegs met lêers geëtiketteer as `container_file_t` kan interaksie hê (lees, skryf, voer uit).

Hierdie meganisme verseker dat selfs as 'n proses binne 'n houer gecompromitteer word, dit beperk is tot interaksie slegs met voorwerpe wat die ooreenstemmende etikette het, wat die potensiële skade van sulke kompromies aansienlik beperk.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

In Docker speel 'n magtiging-plug-in 'n belangrike rol in sekuriteit deur te besluit of versoeke aan die Docker-daemon toegelaat of geblokkeer moet word. Hierdie besluit word geneem deur twee sleutelkontexte te ondersoek:

- **Verifikasiekonteks**: Dit sluit omvattende inligting oor die gebruiker in, soos wie hulle is en hoe hulle hulself geverifieer het.
- **Opdragkonteks**: Dit bestaan uit alle relevante data rakende die versoek wat gemaak word.

Hierdie kontekste help verseker dat slegs wettige versoeke van geverifieerde gebruikers verwerk word, wat die sekuriteit van Docker-operasies verbeter.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS vanaf 'n houer

As jy nie behoorlik die hulpbronne wat 'n houer kan gebruik, beperk nie, kan 'n gecompromitteerde houer die gasheer waar dit draai, DoS.

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
## Interessante Docker Vlaggies

### --privileged vlag

Op die volgende bladsy kan jy leer **wat die `--privileged` vlag impliseer**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

As jy 'n houer bestuur waar 'n aanvaller daarin slaag om toegang te verkry as 'n lae voorreg gebruiker. As jy 'n **verkeerd-gekonfigureerde suid binêre** het, kan die aanvaller dit misbruik en **voorregte binne** die houer verhoog. Dit kan hom toelaat om daaruit te ontsnap.

Om die houer met die **`no-new-privileges`** opsie geaktiveer te laat loop, sal **hierdie soort voorregverhoging voorkom**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Ander
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
Vir meer **`--security-opt`** opsies, kyk: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Ander Sekuriteitsoorwegings

### Bestuur van Geheime: Beste Praktyke

Dit is van kardinale belang om te vermy om geheime in Docker-beelde in te sluit of om omgewingsveranderlikes te gebruik, aangesien hierdie metodes jou sensitiewe inligting blootstel aan enigiemand met toegang tot die houer deur opdragte soos `docker inspect` of `exec`.

**Docker volumes** is 'n veiliger alternatief, wat aanbeveel word vir die toegang tot sensitiewe inligting. Hulle kan as 'n tydelike lêerstelsel in geheue gebruik word, wat die risiko's wat verband hou met `docker inspect` en logging verminder. egter, wortelgebruikers en diegene met `exec` toegang tot die houer mag steeds toegang tot die geheime hê.

**Docker geheime** bied 'n selfs veiliger metode vir die hantering van sensitiewe inligting. Vir voorbeelde wat geheime tydens die beeldbou-fase benodig, bied **BuildKit** 'n doeltreffende oplossing met ondersteuning vir bou-tyd geheime, wat die bou-snelheid verbeter en addisionele funksies bied.

Om BuildKit te benut, kan dit op drie maniere geaktiveer word:

1. Deur 'n omgewingsveranderlike: `export DOCKER_BUILDKIT=1`
2. Deur opdragte te prefix: `DOCKER_BUILDKIT=1 docker build .`
3. Deur dit standaard in die Docker-konfigurasie in te skakel: `{ "features": { "buildkit": true } }`, gevolg deur 'n Docker-herstart.

BuildKit stel die gebruik van bou-tyd geheime met die `--secret` opsie moontlik, wat verseker dat hierdie geheime nie in die beeldbou-kas of die finale beeld ingesluit word nie, met 'n opdrag soos:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Vir geheime wat nodig is in 'n lopende houer, **Docker Compose en Kubernetes** bied robuuste oplossings. Docker Compose gebruik 'n `secrets` sleutel in die diensdefinisie om geheime lêers te spesifiseer, soos getoon in 'n `docker-compose.yml` voorbeeld:
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
Hierdie konfigurasie stel die gebruik van geheime in staat wanneer dienste met Docker Compose begin word.

In Kubernetes-omgewings word geheime van nature ondersteun en kan verder bestuur word met gereedskap soos [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Kubernetes se Rolgebaseerde Toegangsbeheer (RBAC) verbeter die sekuriteit van geheime bestuur, soortgelyk aan Docker Enterprise.

### gVisor

**gVisor** is 'n toepassingskern, geskryf in Go, wat 'n substansiële gedeelte van die Linux-stelselsurface implementeer. Dit sluit 'n [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime genaamd `runsc` in wat 'n **isolasiegrens tussen die toepassing en die gasheer-kern** bied. Die `runsc` runtime integreer met Docker en Kubernetes, wat dit eenvoudig maak om sandboxed houers te laat loop.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** is 'n oopbron-gemeenskap wat werk om 'n veilige houer-runtime te bou met liggewig virtuele masjiene wat soos houers voel en presteer, maar **sterker werklading-isolasie bied met behulp van hardeware virtualisering** tegnologie as 'n tweede laag van verdediging.

{% embed url="https://katacontainers.io/" %}

### Samevatting Wenke

- **Moet nie die `--privileged` vlag gebruik of 'n** [**Docker-soket binne die houer monteer**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Die docker soket stel in staat om houers te laat ontstaan, so dit is 'n maklike manier om volle beheer oor die gasheer te neem, byvoorbeeld deur 'n ander houer met die `--privileged` vlag te laat loop.
- Moet **nie as root binne die houer loop nie. Gebruik 'n** [**ander gebruiker**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **en** [**gebruikersnamespaces**](https://docs.docker.com/engine/security/userns-remap/)**.** Die root in die houer is dieselfde as op die gasheer tensy dit met gebruikersnamespaces herverdeel word. Dit is slegs liggies beperk deur, hoofsaaklik, Linux-namespaces, vermoëns, en cgroups.
- [**Laat alle vermoëns val**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) en stel slegs diegene wat benodig word in** (`--cap-add=...`). Baie werklading het nie enige vermoëns nodig nie en om dit by te voeg verhoog die omvang van 'n potensiële aanval.
- [**Gebruik die “no-new-privileges” sekuriteitsopsie**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) om te voorkom dat prosesse meer voorregte verkry, byvoorbeeld deur suid-binaries.
- [**Beperk hulpbronne beskikbaar aan die houer**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Hulpbronlimiete kan die masjien beskerm teen ontkenning van diens-aanvalle.
- **Pas** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(of SELinux)** profiele aan om die aksies en syscalls wat beskikbaar is vir die houer tot die minimum vereiste te beperk.
- **Gebruik** [**amptelike docker-beelde**](https://docs.docker.com/docker-hub/official_images/) **en vereis handtekeninge** of bou jou eie gebaseer daarop. Moet nie [terugdeure](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) beelde erf of gebruik nie. Stoor ook root sleutels, wagwoorde op 'n veilige plek. Docker het planne om sleutels met UCP te bestuur.
- **Bou gereeld** jou beelde om **sekuriteitsopdaterings op die gasheer en beelde toe te pas.**
- Bestuur jou **geheime verstandig** sodat dit moeilik is vir die aanvaller om toegang daartoe te verkry.
- As jy **die docker daemon blootstel, gebruik HTTPS** met kliënt- en bediener-authentisering.
- In jou Dockerfile, **gee voorkeur aan COPY eerder as ADD**. ADD onttrek outomaties gecomprimeerde lêers en kan lêers van URL's kopieer. COPY het nie hierdie vermoëns nie. Vermy waar moontlik die gebruik van ADD sodat jy nie kwesbaar is vir aanvalle deur middel van afgeleë URL's en Zip-lêers nie.
- Het **afsonderlike houers vir elke mikro-diens**
- **Moet nie ssh** binne die houer plaas nie, “docker exec” kan gebruik word om na die Houer te ssh.
- Het **kleiner** houer **beelde**

## Docker Breakout / Privilege Escalation

As jy **binne 'n docker-houer** is of jy het toegang tot 'n gebruiker in die **docker-groep**, kan jy probeer om te **ontsnap en voorregte te verhoog**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Docker Authentication Plugin Bypass

As jy toegang het tot die docker soket of toegang het tot 'n gebruiker in die **docker-groep maar jou aksies word beperk deur 'n docker-auth-plugin**, kyk of jy dit kan **omseil:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Hardening Docker

- Die gereedskap [**docker-bench-security**](https://github.com/docker/docker-bench-security) is 'n skrip wat vir dosyne algemene beste praktyke rondom die ontplooiing van Docker-houers in produksie nagaan. Die toetse is almal geoutomatiseer, en is gebaseer op die [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Jy moet die gereedskap vanaf die gasheer wat docker bestuur of vanaf 'n houer met genoeg voorregte uitvoer. Vind uit **hoe om dit in die README te loop:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Verwysings

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
