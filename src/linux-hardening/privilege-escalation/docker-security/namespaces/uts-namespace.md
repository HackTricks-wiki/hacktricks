# UTS prostor imena

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

UTS (UNIX Time-Sharing System) namespace je funkcionalnost Linux kernela koja obezbeđuje i**solation of two system identifiers**: **hostname** i **NIS** (Network Information Service) domain name. Ova izolacija omogućava svakom UTS namespace-u da ima **own independent hostname and NIS domain name**, što je naročito korisno u scenarijima containerization-a gde svaki kontejner treba da se pojavi kao poseban sistem sa sopstvenim hostname-om.

### Kako to radi:

1. Kada se kreira novi UTS namespace, on počinje sa **copy of the hostname and NIS domain name from its parent namespace**. To znači da novo namespace prilikom kreiranja s**hares the same identifiers as its parent**. Međutim, sve kasnije izmene hostname-a ili NIS domain name-a unutar tog namespace-a neće uticati na druge namespace-ove.
2. Procesi unutar UTS namespace-a **can change the hostname and NIS domain name** koristeći `sethostname()` i `setdomainname()` sistemske pozive, respektivno. Te izmene su lokalne za taj namespace i ne utiču na druge namespace-ove niti na host sistem.
3. Procesi mogu da se premeste između namespace-ova koristeći `setns()` sistemski poziv ili da kreiraju nove namespace-ove koristeći `unshare()` ili `clone()` sistemske pozive sa `CLONE_NEWUTS` flagom. Kada se proces premesti u novi namespace ili ga kreira, počinje da koristi hostname i NIS domain name povezane sa tim namespace-om.

## Vežba:

### Kreiranje različitih namespace-ova

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Kada se `unshare` izvrši bez opcije `-f`, javlja se greška zbog načina na koji Linux rukuje novim PID (Process ID) namespace-ovima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace-ove koristeći sistemski poziv `unshare`. Međutim, proces koji inicira kreiranje novog PID namespace-a (nazivan "unshare" proces) ne ulazi u novi namespace; u njega ulaze samo njegovi podprocesi.
- Pokretanje `%unshare -p /bin/bash%` pokreće `/bin/bash` u istom procesu kao `unshare`. Kao posledica, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima specijalnu ulogu usvajanja napuštenih (orphan) procesa. Linux kernel će potom onemogućiti dodelu PID-ova u tom namespace-u.

2. **Posledica**:

- Izlazak PID 1 u novom namespace-u dovodi do čišćenja flag-a `PIDNS_HASH_ADDING`. To rezultira time da funkcija `alloc_pid` ne uspe da dodeli novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Cannot allocate memory".

3. **Rešenje**:
- Problem se može rešiti korišćenjem opcije `-f` sa `unshare`. Ova opcija tera `unshare` da izvrši fork novog procesa nakon kreiranja novog PID namespace-a.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da sam `unshare` postane PID 1 u novom namespace-u. `/bin/bash` i njegovi podprocesi se tada bezbedno nalaze unutar tog namespace-a, sprečavajući prevremen izlazak PID 1 i omogućavajući normalnu dodelu PID-ova.

Time što se `unshare` pokreće sa `-f` flagom, novi PID namespace se pravilno održava, što omogućava `/bin/bash` i njegovim podprocesima da rade bez suočavanja sa greškom "Cannot allocate memory".

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Proverite u kojem se namespace-u nalazi vaš proces
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Pronađite sve UTS namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Zloupotreba deljenja host UTS namespace-a

Ako se kontejner pokrene sa `--uts=host`, pridružiće se host UTS namespace-u umesto da dobije sopstveni izolovani. Sa privilegijama kao što su `--cap-add SYS_ADMIN`, kod u kontejneru može promeniti hostname/NIS ime hosta putem `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Promena imena hosta može da izmeni logove/upozorenja, zbuni otkrivanje klastera ili pokvari TLS/SSH konfiguracije koje fiksiraju ime hosta.

### Otkrivanje kontejnera koji dele UTS sa hostom
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
