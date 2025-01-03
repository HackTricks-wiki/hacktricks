# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### User Identification Variables

- **`ruid`**: **kitambulisho halisi cha mtumiaji** kinamaanisha mtumiaji aliyeanzisha mchakato.
- **`euid`**: Inajulikana kama **kitambulisho cha mtumiaji kinachofanya kazi**, kinawakilisha utambulisho wa mtumiaji unaotumiwa na mfumo kubaini ruhusa za mchakato. Kwa ujumla, `euid` inafanana na `ruid`, isipokuwa katika matukio kama utekelezaji wa binary ya SetUID, ambapo `euid` inachukua utambulisho wa mmiliki wa faili, hivyo kutoa ruhusa maalum za uendeshaji.
- **`suid`**: Huu **kitambulisho kilichohifadhiwa cha mtumiaji** ni muhimu wakati mchakato wa kiwango cha juu (kawaida ukifanya kazi kama root) unahitaji kuachana kwa muda na ruhusa zake ili kutekeleza kazi fulani, kisha baadaye kurejesha hadhi yake ya juu ya awali.

#### Important Note

Mchakato usiokuwa chini ya root unaweza kubadilisha `euid` yake ili ifanane na `ruid`, `euid`, au `suid` ya sasa tu.

### Understanding set\*uid Functions

- **`setuid`**: Kinyume na dhana za awali, `setuid` hasa inabadilisha `euid` badala ya `ruid`. Kwa mchakato wenye ruhusa, inalinganisha `ruid`, `euid`, na `suid` na mtumiaji aliyeainishwa, mara nyingi root, kwa ufanisi inaimarisha vitambulisho hivi kutokana na `suid` inayoshinda. Maelezo ya kina yanaweza kupatikana kwenye [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** na **`setresuid`**: Hizi kazi zinaruhusu marekebisho ya kina ya `ruid`, `euid`, na `suid`. Hata hivyo, uwezo wao unategemea kiwango cha ruhusa za mchakato. Kwa michakato isiyo ya root, marekebisho yanakabiliwa na thamani za sasa za `ruid`, `euid`, na `suid`. Kinyume chake, michakato ya root au zile zenye uwezo wa `CAP_SETUID` zinaweza kupewa thamani zisizo za kawaida kwa vitambulisho hivi. Maelezo zaidi yanaweza kupatikana kwenye [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) na [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Hizi kazi zimeundwa si kama mekanismu ya usalama bali kusaidia mtiririko wa uendeshaji unaokusudiwa, kama vile wakati programu inachukua utambulisho wa mtumiaji mwingine kwa kubadilisha kitambulisho chake cha mtumiaji kinachofanya kazi.

Kwa kuzingatia, ingawa `setuid` inaweza kuwa chaguo la kawaida kwa kuinua ruhusa hadi root (kwa kuwa inalinganisha vitambulisho vyote na root), kutofautisha kati ya hizi kazi ni muhimu kwa kuelewa na kudhibiti tabia za kitambulisho cha mtumiaji katika hali tofauti.

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve` inaanzisha programu, inayoamuliwa na hoja ya kwanza. Inachukua hoja mbili za array, `argv` kwa ajili ya hoja na `envp` kwa mazingira.
- **Behavior**: Inahifadhi nafasi ya kumbukumbu ya mwitikiaji lakini inasasisha stack, heap, na sehemu za data. Msimbo wa programu unabadilishwa na programu mpya.
- **User ID Preservation**:
- `ruid`, `euid`, na vitambulisho vya makundi ya ziada vinabaki bila kubadilika.
- `euid` inaweza kuwa na mabadiliko madogo ikiwa programu mpya ina SetUID bit iliyowekwa.
- `suid` inasasishwa kutoka `euid` baada ya utekelezaji.
- **Documentation**: Maelezo ya kina yanaweza kupatikana kwenye [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**

- **Functionality**: Kinyume na `execve`, `system` inaunda mchakato wa mtoto kwa kutumia `fork` na inatekeleza amri ndani ya mchakato huo wa mtoto kwa kutumia `execl`.
- **Command Execution**: Inatekeleza amri kupitia `sh` kwa `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Kwa kuwa `execl` ni aina ya `execve`, inafanya kazi kwa njia sawa lakini katika muktadha wa mchakato mpya wa mtoto.
- **Documentation**: Maelezo zaidi yanaweza kupatikana kwenye [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- Ina chaguo la `-p` linaloathiri jinsi `euid` na `ruid` zinavyoshughulikiwa.
- Bila `-p`, `bash` inabadilisha `euid` kuwa `ruid` ikiwa awali zinatofautiana.
- Kwa `-p`, `euid` ya awali inahifadhiwa.
- Maelezo zaidi yanaweza kupatikana kwenye [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Haina mekanismu inayofanana na `-p` katika `bash`.
- Tabia kuhusu vitambulisho vya mtumiaji haijatajwa wazi, isipokuwa chini ya chaguo la `-i`, ikisisitiza uhifadhi wa usawa wa `euid` na `ruid`.
- Maelezo ya ziada yanapatikana kwenye [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Mekanismu hizi, tofauti katika uendeshaji wao, zinatoa anuwai ya chaguzi za kutekeleza na kubadilisha kati ya programu, huku zikiwa na tofauti maalum katika jinsi vitambulisho vya mtumiaji vinavyoshughulikiwa na kuhifadhiwa.

### Testing User ID Behaviors in Executions

Mifano imechukuliwa kutoka https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, angalia kwa maelezo zaidi

#### Case 1: Using `setuid` with `system`

**Objective**: Kuelewa athari ya `setuid` kwa pamoja na `system` na `bash` kama `sh`.

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Uundaji na Ruhusa:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analysis:**

- `ruid` na `euid` huanza kama 99 (nobody) na 1000 (frank) mtawalia.
- `setuid` inawalinganisha wote kuwa 1000.
- `system` inatekeleza `/bin/bash -c id` kutokana na symlink kutoka sh hadi bash.
- `bash`, bila `-p`, inarekebisha `euid` ili ifanane na `ruid`, na kusababisha wote kuwa 99 (nobody).

#### Case 2: Using setreuid with system

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Uundaji na Ruhusa:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `setreuid` inaweka ruid na euid zote mbili kuwa 1000.
- `system` inaita bash, ambayo inashikilia vitambulisho vya mtumiaji kutokana na usawa wao, ikifanya kazi kama frank.

#### Kesi ya 3: Kutumia setuid na execve

Lengo: Kuchunguza mwingiliano kati ya setuid na execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `ruid` inabaki 99, lakini euid imewekwa kwa 1000, kulingana na athari ya setuid.

**Mfano wa Kode ya C 2 (Kuita Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- Ingawa `euid` imewekwa kuwa 1000 na `setuid`, `bash` inarejesha euid kuwa `ruid` (99) kutokana na ukosefu wa `-p`.

**Mfano wa Kode ya C 3 (Kutumia bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Marejeleo

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
