# Vremenski Namespac

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne Informacije

Vremenski namespace u Linuxu omogućava offsete po namespace-u za sistemske monotone i boot-time satove. Često se koristi u Linux kontejnerima za promenu datuma/vremena unutar kontejnera i podešavanje satova nakon vraćanja iz tačke preuzimanja ili snimka.

## Laboratorija:

### Kreirajte različite Namespac-e

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Montiranjem nove instance `/proc` datotečnog sistema ako koristite parametar `--mount-proc`, osiguravate da nova mount namespace ima **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Greška: bash: fork: Ne može da dodeli memoriju</summary>

Kada se `unshare` izvrši bez opcije `-f`, dolazi do greške zbog načina na koji Linux upravlja novim PID (Process ID) namespace-ima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace-e koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID namespace-a (poznat kao "unshare" proces) ne ulazi u novi namespace; samo njegovi podprocesi to čine.
- Pokretanjem `%unshare -p /bin/bash%` pokreće se `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja siročadi procesa. Linux kernel će tada onemogućiti dodelu PID-a u tom namespace-u.

2. **Posledica**:

- Izlazak PID 1 u novom namespace-u dovodi do čišćenja `PIDNS_HASH_ADDING` oznake. To rezultira neuspehom funkcije `alloc_pid` da dodeli novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Ne može da dodeli memoriju".

3. **Rešenje**:
- Problem se može rešiti korišćenjem `-f` opcije sa `unshare`. Ova opcija čini da `unshare` fork-uje novi proces nakon kreiranja novog PID namespace-a.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da `unshare` komanda sama postane PID 1 u novom namespace-u. `/bin/bash` i njegovi podprocesi su tada sigurno sadržani unutar ovog novog namespace-a, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalnu dodelu PID-a.

Osiguravanjem da `unshare` radi sa `-f` oznakom, novi PID namespace se ispravno održava, omogućavajući `/bin/bash` i njegove podprocese da funkcionišu bez susretanja greške u dodeli memorije.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Proverite u kojem je namespace vaš proces
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Pronađi sve Time namespace-ove
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u vremenski prostor
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulacija vremenskim pomeranjima

Počevši od Linux-a 5.6, dva sata mogu biti virtualizovana po vremenskom imenu:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Njihovi delti po imenu su izloženi (i mogu se modifikovati) kroz datoteku `/proc/<PID>/timens_offsets`:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Datoteka sadrži dve linije – po jednu za svaki sat – sa pomerajem u **nanosekundama**. Procesi koji imaju **CAP_SYS_TIME** _u vremenskom imenskom prostoru_ mogu promeniti vrednost:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Ako vam je potrebno da se zidni sat (`CLOCK_REALTIME`) takođe menja, i dalje se morate osloniti na klasične mehanizme (`date`, `hwclock`, `chronyd`, …); **nije** imenski prostoran.


### `unshare(1)` pomoćne zastavice (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
Duge opcije automatski upisuju odabrane delte u `timens_offsets` odmah nakon što je prostor imena kreiran, čime se štedi ručni `echo`.

---

## OCI i podrška za runtime

* **OCI Runtime Specification v1.1** (Nov 2023) je dodao posvećen tip `time` prostora imena i polje `linux.timeOffsets` kako bi kontejnerski motori mogli da traže virtualizaciju vremena na prenosiv način.
* **runc >= 1.2.0** implementira taj deo specifikacije. Minimalni fragment `config.json` izgleda ovako:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Zatim pokrenite kontejner sa `runc run <id>`.

>  NAPOMENA: runc **1.2.6** (Feb 2025) je ispravio grešku "exec into container with private timens" koja je mogla dovesti do zastoja i potencijalnog DoS-a. Uverite se da ste na ≥ 1.2.6 u produkciji.

---

## Bezbednosna razmatranja

1. **Zahtevana sposobnost** – Procesu je potrebna **CAP_SYS_TIME** unutar svog korisničkog/vremenskog prostora imena da bi promenio ofsete. Odbacivanje te sposobnosti u kontejneru (podrazumevano u Docker-u i Kubernetes-u) sprečava manipulaciju.
2. **Bez promena na zidu sata** – Pošto je `CLOCK_REALTIME` deljen sa hostom, napadači ne mogu da lažiraju trajanje sertifikata, isteke JWT-a itd. samo putem timens-a.
3. **Izbegavanje logova / detekcije** – Softver koji se oslanja na `CLOCK_MONOTONIC` (npr. limitatori brzine zasnovani na vremenu rada) može biti zbunjen ako korisnik prostora imena prilagodi ofset. Preferirajte `CLOCK_REALTIME` za vremenske oznake relevantne za bezbednost.
4. **Površina napada na kernel** – Čak i sa uklonjenim `CAP_SYS_TIME`, kernel kod ostaje dostupan; održavajte host ažuriranim. Linux 5.6 → 5.12 je primio više ispravki grešaka vezanih za timens (NULL-deref, problemi sa potpisivanjem).

### Lista za učvršćivanje

* Odbacite `CAP_SYS_TIME` u podrazumevanom profilu vašeg kontejnerskog runtime-a.
* Održavajte runtime-ove ažuriranim (runc ≥ 1.2.6, crun ≥ 1.12).
* Zaključajte util-linux ≥ 2.38 ako se oslanjate na `--monotonic/--boottime` pomoćne alate.
* Revizija softvera unutar kontejnera koji čita **uptime** ili **CLOCK_MONOTONIC** za logiku kritičnu za bezbednost.

## Reference

* man7.org – Stranica sa priručnikom za vremenske prostore imena: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: novi vremenski i RDT prostori imena" (15. novembar 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
