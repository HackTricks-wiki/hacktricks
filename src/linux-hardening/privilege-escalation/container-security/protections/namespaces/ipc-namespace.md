# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

IPC namespace izoluje **System V IPC objects** i **POSIX message queues**. To uključuje segmente deljene memorije, semafore i message queues koji bi inače bili vidljivi procesima koji nisu povezani na hostu. U praktičnom smislu, ovo sprečava kontejner da slučajno pristupi IPC objektima koji pripadaju drugim workload‑ima ili hostu.

U poređenju sa mount, PID, ili user namespaces, IPC namespace se često ređe pominje, ali to ne znači da je nevažan. Deljena memorija i srodni IPC mehanizmi mogu sadržati vrlo korisno stanje. Ako je host IPC namespace izložen, workload može dobiti uvid u objekte za koordinaciju među procesima ili podatke koji nikada nisu bili namenjeni da pređu granicu kontejnera.

## Funkcionisanje

Kada runtime kreira novu IPC namespace, proces dobija sopstveni izolovani skup IPC identifikatora. To znači da komande kao `ipcs` prikazuju samo objekte dostupne u toj namespace. Ako se kontejner umesto toga pridruži host IPC namespace‑u, ti objekti postaju deo zajedničkog globalnog pregleda.

Ovo je posebno važno u okruženjima gde aplikacije ili servisi intenzivno koriste shared memory. Čak i kada kontejner ne može direktno da pobegne kroz IPC sam, namespace može leak informacije ili omogućiti međuprocesnu interferenciju koja značajno pomaže kasnijem napadu.

## Laboratorija

Možete kreirati privatnu IPC namespace sa:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I uporedite ponašanje tokom izvršavanja sa:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Korišćenje u runtime-u

Docker i Podman po podrazumevano izoluju IPC. Kubernetes obično dodeljuje Pod-u sopstveni IPC namespace, koji je deljen među kontejnerima u istom Pod-u, ali po podrazumevano nije deljen sa host-om. Deljenje host IPC-a je moguće, ali treba ga tretirati kao značajno smanjenje izolacije, a ne kao beznačajnu runtime opciju.

## Pogrešne konfiguracije

Očigledna greška je `--ipc=host` ili `hostIPC: true`. To se može raditi radi kompatibilnosti sa legacy softverom ili iz praktičnih razloga, ali to značajno menja model poverenja. Drugi čest problem je jednostavno zanemarivanje IPC jer deluje manje dramatično od host PID-a ili host networking-a. U stvarnosti, ako radno opterećenje rukuje browser-ima, bazama podataka, naučnim zadacima ili drugim softverom koji intenzivno koristi deljenu memoriju, IPC površina može biti veoma relevantna.

## Zloupotreba

Kada je host IPC deljen, napadač može da ispita ili ometa objekate deljene memorije, stekne nova saznanja o ponašanju host-a ili susednog radnog opterećenja, ili kombinuje informacije tamo dobijene sa vidljivošću procesa i mogućnostima nalik ptrace-u. Deljenje IPC-a je često pomoćna slabost, a ne kompletan put izlaza, ali pomoćne slabosti su važne jer skraćuju i stabilizuju stvarne lance napada.

Prvi koristan korak je da se enumerišu koji IPC objekti su uopšte vidljivi:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ako se host IPC namespace deli, veliki segmenti deljene memorije ili zanimljivi vlasnici objekata mogu odmah otkriti ponašanje aplikacije:
```bash
ipcs -m -p
ipcs -q -p
```
U nekim okruženjima, sami sadržaji `/dev/shm` leak filenames, artifacts, or tokens koje vredi proveriti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Deljenje IPC retko samo po sebi odmah daje host root, ali može izložiti podatke i kanale za koordinaciju koji znatno olakšavaju kasnije napade na procese.

### Potpun primer: `/dev/shm` oporavak tajni

Najrealističniji slučaj potpune zloupotrebe je krađa podataka, a ne direktno bekstvo. Ako je host IPC ili širok raspored deljene memorije izložen, osetljivi artefakti se ponekad mogu direktno oporaviti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact:

- ekstrakcija tajni ili materijala sesije ostavljenog u deljenoj memoriji
- uvid u aplikacije koje su trenutno aktivne na hostu
- bolje ciljanje za kasnije PID-namespace ili ptrace-based napade

IPC sharing is therefore better understood as an **pojačivač napada** than as a standalone host-escape primitive.

## Provere

Ove komande su namenjene da odgovore da li workload ima privatni IPC prikaz, da li su vidljivi značajni objekti deljene memorije ili poruka, i da li `/dev/shm` sam po sebi izlaže korisne artefakte.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Šta je zanimljivo ovde:

- Ako `ipcs -a` otkrije objekte u vlasništvu neočekivanih korisnika ili servisa, namespace možda nije izolovan koliko se očekivalo.
- Veliki ili neuobičajeni segmenti deljene memorije često vredi dalje istražiti.
- Široko montiran `/dev/shm` nije automatski bug, ali u nekim okruženjima it leaks nazive fajlova, artefakte i privremene tajne.

IPC retko dobija toliko pažnje kao veći tipovi namespace-a, ali u okruženjima koja ga intenzivno koriste, deljenje sa hostom je u velikoj meri bezbednosna odluka.
{{#include ../../../../../banners/hacktricks-training.md}}
