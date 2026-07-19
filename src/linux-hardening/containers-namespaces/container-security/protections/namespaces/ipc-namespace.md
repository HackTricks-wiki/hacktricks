# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

IPC namespace izoluje **System V IPC objekte** i **POSIX message queues**. To obuhvata segmente deljene memorije, semafore i redove poruka koji bi inače bili vidljivi nepovezanim procesima na hostu. Praktično, ovo sprečava container da se nepromišljeno poveže sa IPC objektima koji pripadaju drugim radnim opterećenjima ili hostu.

U poređenju sa mount, PID ili user namespace-ovima, o IPC namespace-u se često manje govori, ali to ne treba mešati sa nevažnošću. Deljena memorija i povezani IPC mehanizmi mogu sadržati veoma korisno stanje. Ako je host IPC namespace izložen, workload može dobiti uvid u objekte za međuprocesnu koordinaciju ili podatke koji nikada nisu bili namenjeni za prelazak granice containera.

## Rad

Kada runtime kreira novi IPC namespace, proces dobija sopstveni izolovani skup IPC identifikatora. To znači da komande kao što je `ipcs` prikazuju samo objekte dostupne u tom namespace-u. Ako se container umesto toga pridruži host IPC namespace-u, ti objekti postaju deo zajedničkog globalnog prikaza.

Ovo je naročito važno u okruženjima u kojima aplikacije ili servisi intenzivno koriste deljenu memoriju. Čak i kada container ne može direktno da izvrši breakout samo putem IPC-a, namespace može da leak-uje informacije ili omogući međuprocesno ometanje koje značajno pomaže u kasnijem napadu.

## Lab

Privatni IPC namespace možete kreirati pomoću:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I uporedite ponašanje tokom izvršavanja sa:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Upotreba tokom izvršavanja

Docker i Podman podrazumevano izoluju IPC. Kubernetes obično dodeljuje Pod-u sopstveni IPC namespace, koji dele container-i u istom Pod-u, ali ga podrazumevano ne dele sa host-om. Deljenje IPC-a sa host-om je moguće, ali ga treba posmatrati kao značajno smanjenje izolacije, a ne kao nevažnu runtime opciju.

## Pogrešne konfiguracije

Očigledna greška je `--ipc=host` ili `hostIPC: true`. To se može uraditi zbog kompatibilnosti sa legacy softverom ili radi praktičnosti, ali značajno menja model poverenja. Drugi čest problem je jednostavno zanemarivanje IPC-a, jer deluje manje dramatično od host PID-a ili host networkinga. U stvarnosti, ako workload obrađuje browser-e, baze podataka, scientific workload-e ili drugi softver koji intenzivno koristi shared memory, IPC surface može biti veoma relevantan.

## Zloupotreba

Kada se host IPC deli, attacker može da pregleda ili ometa shared memory objekte, stekne nove uvide u ponašanje host-a ili susednog workload-a, ili da kombinuje tamo prikupljene informacije sa process visibility i ptrace-style capabilities. Deljenje IPC-a je često prateća slabost, a ne kompletan breakout path, ali su prateće slabosti važne jer skraćuju i stabilizuju stvarne attack chain-ove.

Prvi koristan korak je enumeracija svih IPC objekata koji su uopšte vidljivi:
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
U nekim okruženjima, sam sadržaj direktorijuma `/dev/shm` može da leak-uje nazive fajlova, artefakte ili tokene koje vredi proveriti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Deljenje IPC-a retko samo po sebi odmah omogućava host root, ali može da otkrije podatke i kanale za koordinaciju koji znatno olakšavaju kasnije process attacks.

### Potpun primer: oporavak tajni iz `/dev/shm`

Najrealističniji slučaj potpune zloupotrebe jeste krađa podataka, a ne direktni escape. Ako su host IPC ili širok raspored deljene memorije izloženi, osetljivi artefakti se ponekad mogu direktno oporaviti:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Uticaj:

- ekstrakcija secrets ili sesijskog materijala ostavljenog u deljenoj memoriji
- uvid u aplikacije koje su trenutno aktivne na hostu
- bolje usmeravanje kasnijih napada zasnovanih na PID-namespace ili ptrace

Deljenje IPC-a se zato bolje shvata kao **pojačivač napada**, a ne kao samostalni primitive za bekstvo sa hosta.

## Provere

Ove komande treba da utvrde da li workload ima privatni IPC prikaz, da li su vidljivi značajni objekti deljene memorije ili poruka i da li sam `/dev/shm` izlaže korisne artefakte.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Šta je ovde interesantno:

- Ako `ipcs -a` otkrije objekte čiji su vlasnici neočekivani korisnici ili servisi, namespace možda nije izolovan u meri u kojoj se očekuje.
- Veliki ili neuobičajeni segmenti deljene memorije često zahtevaju dalju proveru.
- Širok `/dev/shm` mount nije automatski bug, ali u nekim okruženjima leak-uje nazive fajlova, artefakte i privremene secrets.

IPC retko dobija toliko pažnje kao veći tipovi namespace-a, ali u okruženjima koja ga intenzivno koriste, njegovo deljenje sa hostom predstavlja veoma važnu security odluku.
{{#include ../../../../../banners/hacktricks-training.md}}
