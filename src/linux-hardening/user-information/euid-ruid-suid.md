# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Vigezo vya Utambulisho wa User

- **`ruid`**: **real user ID** humtambulisha user aliyeanzisha process.
- **`euid`**: Inayojulikana kama **effective user ID**, huwakilisha utambulisho wa user unaotumiwa na system kubaini privileges za process. Kwa kawaida, `euid` huwa sawa na `ruid`, isipokuwa katika hali kama execution ya SetUID binary, ambapo `euid` huchukua utambulisho wa owner wa file, hivyo kutoa permissions maalum za uendeshaji.
- **`suid`**: Hii **saved user ID** ni muhimu wakati process yenye privileges za juu (kwa kawaida inayoendesha kama root) inahitaji kuachia privileges zake kwa muda ili kutekeleza tasks fulani, kisha baadaye kurejesha hali yake ya awali yenye privileges za juu.

#### Kumbuka Muhimu

Process isiyoendesha chini ya root inaweza kubadilisha `euid` yake pekee ili ilingane na `ruid`, `euid`, au `suid` ya sasa.

### Kuelewa set\*uid Functions

- **`setuid`**: Kinyume na dhana za awali, `setuid` hubadilisha hasa `euid` badala ya `ruid`. Hasa, kwa processes zenye privileges, huweka `ruid`, `euid`, na `suid` ziwe sawa na user aliyeainishwa, mara nyingi root, hivyo kuzifanya IDs hizi ziwe thabiti kwa sababu ya `suid` inayozifunika. Maelezo zaidi yanapatikana kwenye [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** na **`setresuid`**: Functions hizi huruhusu marekebisho mahususi ya `ruid`, `euid`, na `suid`. Hata hivyo, uwezo wake unategemea kiwango cha privileges cha process. Kwa processes zisizo za root, mabadiliko yanawekewa mipaka ya values za sasa za `ruid`, `euid`, na `suid`. Kinyume chake, processes za root au zile zenye capability ya `CAP_SETUID` zinaweza kuweka values zozote kwenye IDs hizi. Maelezo zaidi yanaweza kupatikana kwenye [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) na [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Utendaji huu haukuundwa kama security mechanism, bali kuwezesha operational flow iliyokusudiwa, kama vile program inapochukua utambulisho wa user mwingine kwa kubadilisha effective user ID yake.

Muhimu, ingawa `setuid` inaweza kuwa chaguo la kawaida la kuongeza privileges hadi root (kwa kuwa huweka IDs zote ziwe root), kutofautisha kati ya functions hizi ni muhimu kwa kuelewa na kudhibiti tabia za user ID katika scenarios mbalimbali.

### Mbinu za Program Execution katika Linux

#### **`execve` System Call**

- **Functionality**: `execve` huanzisha program, iliyoamuliwa na argument ya kwanza. Huchukua array arguments mbili, `argv` kwa arguments na `envp` kwa environment.
- **Behavior**: Huhifadhi memory space ya caller lakini hu-refresh stack, heap, na data segments. Code ya program hubadilishwa na program mpya.
- **User ID Preservation**:
- `ruid`, `euid`, na supplementary group IDs hubaki bila kubadilishwa.
- `euid` inaweza kubadilika kwa namna mahususi ikiwa program mpya ina SetUID bit iliyowekwa.
- `suid` husasishwa kutoka kwa `euid` baada ya execution.
- **Documentation**: Maelezo ya kina yanapatikana kwenye [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: Tofauti na `execve`, `system` huunda child process kwa kutumia `fork` na kutekeleza command ndani ya child process hiyo kwa kutumia `execl`.
- **Command Execution**: Hutekeleza command kupitia `sh` kwa `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Kwa kuwa `execl` ni aina ya `execve`, hufanya kazi kwa njia inayofanana lakini katika context ya child process mpya.
- **Documentation**: Maelezo zaidi yanaweza kupatikana kwenye [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior ya `bash` na `sh` pamoja na SUID**

- **`bash`**:
- Ina option ya `-p` inayoathiri jinsi `euid` na `ruid` zinavyoshughulikiwa.
- Bila `-p`, `bash` huweka `euid` iwe sawa na `ruid` ikiwa awali zilikuwa tofauti.
- Ikiwa na `-p`, `euid` ya awali huhifadhiwa.
- Maelezo zaidi yanaweza kupatikana kwenye [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Haina mechanism inayofanana na `-p` ya `bash`.
- Behavior inayohusu user IDs haijaelezwa wazi, isipokuwa chini ya option ya `-i`, inayosisitiza kuhifadhi usawa wa `euid` na `ruid`.
- Maelezo ya ziada yanapatikana kwenye [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Mechanisms hizi, ambazo hutofautiana katika utendaji wake, hutoa options mbalimbali za kutekeleza na kuhamia kati ya programs, zikiwa na nuances mahususi kuhusu jinsi user IDs zinavyodhibitiwa na kuhifadhiwa.

### Testing User ID Behaviors katika Executions

Examples zimechukuliwa kutoka https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, iangalie kwa maelezo zaidi<sup>[[1]](#references)</sup>

#### Case 1: Kutumia `setuid` pamoja na `system`

**Objective**: Kuelewa effect ya `setuid` inapounganishwa na `system` na `bash` kama `sh`.

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
**Kompilesheni na Ruhusa:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `ruid` na `euid` huanza zikiwa 99 (nobody) na 1000 (frank), mtawalia.
- `setuid` huzilinganisha zote kuwa 1000.
- `system` hutekeleza `/bin/bash -c id` kutokana na symlink kutoka sh kwenda bash.
- `bash`, bila `-p`, hubadilisha `euid` ilingane na `ruid`, hivyo zote zinakuwa 99 (nobody).

#### Kesi ya 2: Kutumia setreuid na system

**Msimbo wa C**:
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
**Ukompilishaji na Ruhusa:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Uchambuzi:**

- `setreuid` huweka ruid na euid zote kuwa 1000.
- `system` huendesha bash, ambayo hudumisha vitambulisho vya mtumiaji kwa sababu ni sawa, hivyo kufanya kazi kwa ufanisi kama frank.

#### Kisa cha 3: Kutumia setuid na execve

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

- `ruid` inabaki kuwa 99, lakini euid imewekwa kuwa 1000, kulingana na athari ya setuid.

**Mfano wa Msimbo wa C 2 (Kuita Bash):**
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

- Ingawa `euid` imewekwa kuwa 1000 na `setuid`, `bash` huweka upya euid kuwa `ruid` (99) kwa sababu ya kutokuwepo kwa `-p`.

**Mfano wa C Code 3 (Kwa kutumia bash -p):**
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
## Marejeo

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - ukurasa wa man wa setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - ukurasa wa man wa setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - ukurasa wa man wa setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - ukurasa wa man wa execve](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
