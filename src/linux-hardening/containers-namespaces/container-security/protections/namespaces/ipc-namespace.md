# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

IPC namespace izoluje **System V IPC objekte** i **POSIX message queues**. To obuhvata shared memory segmente, semafore i message queues koji bi inače bili vidljivi nepovezanim procesima na hostu. U praksi, ovo sprečava da se container proizvoljno poveže sa IPC objektima koji pripadaju drugim workload-ima ili hostu.

U poređenju sa mount, PID ili user namespace-ovima, o IPC namespace-u se često manje govori, ali to ne treba mešati sa nevažnošću. Shared memory i povezani IPC mehanizmi mogu sadržati veoma korisno stanje. Ako je host IPC namespace izložen, workload može dobiti uvid u objekte za koordinaciju između procesa ili podatke koji nikada nisu bili namenjeni za prelazak granice container-a.

## Rad

Kada runtime kreira novi IPC namespace, proces dobija sopstveni izolovani skup IPC identifikatora. To znači da komande kao što je `ipcs` prikazuju samo objekte dostupne u tom namespace-u. Ako se container umesto toga pridruži host IPC namespace-u, ti objekti postaju deo deljenog globalnog prikaza.

Ovo je naročito važno u okruženjima u kojima aplikacije ili servisi intenzivno koriste shared memory. Čak i kada container ne može direktno da izvrši breakout samo pomoću IPC-a, namespace može leak-ovati informacije ili omogućiti interference između procesa, što značajno pomaže u kasnijem napadu.

## Lab

Private IPC namespace možete kreirati pomoću:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I uporedi ponašanje tokom izvršavanja sa:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Upotreba tokom izvršavanja

Docker i Podman podrazumevano izoluju IPC. Kubernetes obično dodeljuje Pod-u sopstveni IPC namespace, koji dele container-i u istom Pod-u, ali ga podrazumevano ne dele sa host-om. Deljenje host IPC-a je moguće, ali ga treba tretirati kao značajno smanjenje izolacije, a ne kao nevažnu runtime opciju.

## Pogrešne konfiguracije

Očigledna greška je `--ipc=host` ili `hostIPC: true`. To se može uraditi zbog kompatibilnosti sa legacy softverom ili radi praktičnosti, ali značajno menja model poverenja. Još jedan čest problem je jednostavno zanemarivanje IPC-a jer deluje manje dramatično od host PID-a ili host networkinga. U stvarnosti, ako workload obrađuje browser-e, baze podataka, naučne workload-e ili drugi softver koji intenzivno koristi shared memory, IPC surface može biti veoma relevantan.

## Abuse

Kada se host IPC deli, attacker može da pregleda ili ometa shared memory objekte, stekne nove uvide u ponašanje host-a ili susednih workload-a ili da kombinuje tamo prikupljene informacije sa vidljivošću procesa i ptrace-style capabilities. Deljenje IPC-a je često supporting weakness, a ne kompletan breakout path, ali supporting weaknesses su važne jer skraćuju i stabilizuju realne attack chain-ove.

Prvi koristan korak je enumeracija IPC objekata koji su uopšte vidljivi:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ako je IPC namespace hosta deljen, veliki segmenti deljene memorije ili zanimljivi vlasnici objekata mogu odmah otkriti ponašanje aplikacije:
```bash
ipcs -m -p
ipcs -q -p
```
U nekim okruženjima, sam sadržaj direktorijuma `/dev/shm` može leakovati nazive fajlova, artefakte ili tokene koje vredi proveriti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Deljenje IPC-a retko samo po sebi odmah omogućava host root, ali može otkriti kanale za podatke i koordinaciju koji znatno olakšavaju kasnije napade na procese.

### Potpun primer: Oporavak tajne iz `/dev/shm`

Najrealniji potpuni scenario zloupotrebe jeste krađa podataka, a ne direktno bekstvo. Ako su host IPC ili širok raspored deljene memorije izloženi, osetljivi artefakti se ponekad mogu direktno povratiti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Uticaj:

- izvlačenje secrets ili session materijala ostavljenog u shared memory
- uvid u aplikacije koje su trenutno aktivne na hostu
- bolje usmeravanje kasnijih napada zasnovanih na PID namespace ili ptrace

IPC sharing se zato bolje razume kao **pojačivač napada** nego kao samostalni host-escape primitive.

## Provere

Ove komande služe da utvrde da li workload ima privatni IPC prikaz, da li su vidljivi značajni objekti shared memory ili poruka i da li sam `/dev/shm` otkriva korisne artefakte.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Šta je ovde interesantno:

- Ako `ipcs -a` otkrije objekte čiji su vlasnici neočekivani korisnici ili servisi, namespace možda nije izolovan onoliko koliko se očekuje.
- Veliki ili neuobičajeni shared memory segmenti često su vredni dodatne provere.
- Širok `/dev/shm` mount nije automatski bug, ali u nekim okruženjima leak-uje nazive fajlova, artefakte i privremene secrets.

IPC retko dobija toliko pažnje kao veći tipovi namespace-a, ali u okruženjima koja ga intenzivno koriste, njegovo deljenje sa hostom predstavlja veoma važnu security odluku.

{{#include ../../../../../banners/hacktricks-training.md}}
