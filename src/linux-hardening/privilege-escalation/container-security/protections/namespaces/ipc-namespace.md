# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

IPC namespace izoluje **System V IPC objects** i **POSIX message queues**. To uključuje shared memory segments, semaphores i message queues koji bi inače bili vidljivi nepovezanim procesima na hostu. U praktičnom smislu, ovo sprečava kontejner da slučajno prikači IPC objekte koji pripadaju drugim radnim opterećenjima ili hostu.

U poređenju sa mount, PID, or user namespaces, IPC namespace se često ređe pominje, ali to ne treba mešati sa nevažnosti. Shared memory i povezani IPC mehanizmi mogu sadržati veoma koristan state. Ako je host IPC namespace izložen, workload može dobiti uvid u objekte za koordinaciju među procesima ili podatke koji nikada nisu trebali preći granicu kontejnera.

## Funkcionisanje

Kada runtime kreira novi IPC namespace, proces dobija sopstveni izolovani skup IPC identifikatora. To znači da komande kao što su `ipcs` prikazuju samo objekte dostupne u tom namespace-u. Ako se kontejner umesto toga pridruži host IPC namespace-u, ti objekti postaju deo zajedničkog globalnog pregleda.

Ovo je posebno važno u okruženjima gde aplikacije ili servisi intenzivno koriste shared memory. Čak i kada kontejner ne može direktno pobeći samo putem IPC, namespace može leak informacije ili omogućiti međuprocesnu interferenciju koja značajno pomaže kasnijem napadu.

## Laboratorija

Možete kreirati privatni IPC namespace pomoću:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I uporedite ponašanje u runtime-u sa:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker i Podman podrazumevano izoluju IPC. Kubernetes obično daje Pod-u sopstveni IPC namespace, koji dele kontejneri u istom Pod-u ali ne i sa hostom po defaultu. Deljenje host IPC je moguće, ali to treba smatrati značajnim smanjenjem izolacije, a ne beznačajnom runtime opcijom.

## Misconfigurations

Očigledna greška je `--ipc=host` ili `hostIPC: true`. To se može uraditi radi kompatibilnosti sa legacy softverom ili iz praktičnih razloga, ali značajno menja model poverenja. Još jedan čest problem je jednostavno prevideti IPC jer deluje manje dramatično od host PID ili host networking. U stvarnosti, ako workload obrađuje browsere, baze podataka, naučne zadatke ili drugi softver koji intenzivno koristi deljenu memoriju, IPC površina može biti veoma relevantna.

## Abuse

Kada se host IPC deli, napadač može da pregleda ili ometa objekte deljene memorije, stekne nove uvide u ponašanje hosta ili susednih workload-a, ili kombinuje informacije tamo dobijene sa vidljivošću procesa i ptrace-style mogućnostima. Deljenje IPC često je pomoćna slabost, a ne kompletan breakout path, ali pomoćne slabosti su važne jer skraćuju i stabilizuju stvarne lančane napade.

The first useful step is to enumerate what IPC objects are visible at all:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ako je host IPC namespace deljen, veliki segmenti deljene memorije ili interesantni vlasnici objekata mogu odmah otkriti ponašanje aplikacije:
```bash
ipcs -m -p
ipcs -q -p
```
U nekim okruženjima, sadržaj `/dev/shm` sam po sebi leak-uje imena fajlova, artefakte ili tokene koje vredi proveriti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing retko samo po sebi odmah daje host root, ali može otkriti podatke i kanale za koordinaciju koji znatno olakšavaju kasnije napade na procese.

### Potpun primer: `/dev/shm` oporavak tajne

Najrealniji kompletan slučaj zloupotrebe je krađa podataka, a ne direktno bekstvo. Ako je host IPC ili širok raspored deljene memorije izložen, osetljivi artefakti ponekad mogu biti direktno povraćeni:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Uticaj:

- izvlačenje tajni ili materijala sesije ostavljenih u deljenoj memoriji
- pregled aplikacija koje su trenutno aktivne na hostu
- bolje ciljanje za kasnije napade zasnovane na PID-namespace ili ptrace

Deljenje IPC-a se stoga bolje razume kao **pojačivač napada** nego kao samostalni host-escape primitive.

## Provere

Ove komande su namenjene da odgovore da li workload ima privatan IPC prikaz, da li su vidljivi značajni objekti deljene memorije ili poruka, i da li sam `/dev/shm` otkriva korisne artefakte.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Šta je ovde zanimljivo:

- Ako `ipcs -a` otkrije objekte u vlasništvu neočekivanih korisnika ili servisa, namespace možda nije onoliko izolovan koliko se očekivalo.
- Veliki ili neobični segmenti deljene memorije često vredi dalje istražiti.
- Široko mountovan `/dev/shm` nije automatski bug, ali u nekim okruženjima leaks imena fajlova, artefakte i privremene tajne.

IPC retko dobija toliko pažnje kao veći tipovi namespace-a, ali u okruženjima koja ga intenzivno koriste, deljenje sa hostom je u velikoj meri sigurnosna odluka.
