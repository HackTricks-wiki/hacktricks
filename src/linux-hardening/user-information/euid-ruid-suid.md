# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Ідентифікаційні змінні користувача

- **`ruid`**: **реальний ідентифікатор користувача** позначає користувача, який ініціював процес.
- **`euid`**: Відомий як **ефективний ідентифікатор користувача**, він представляє ідентичність користувача, яку система використовує для визначення привілеїв процесу. Зазвичай `euid` збігається з `ruid`, за винятком випадків на кшталт виконання SetUID binary, коли `euid` набуває ідентичності власника файлу, надаючи відповідні операційні дозволи.
- **`suid`**: Цей **збережений ідентифікатор користувача** є важливим, коли процес із високими привілеями (зазвичай запущений від root) має тимчасово відмовитися від своїх привілеїв для виконання певних завдань, а потім відновити початковий підвищений статус.

#### Важлива примітка

Процес, який не працює від root, може змінити свій `euid` лише так, щоб він відповідав поточному `ruid`, `euid` або `suid`.

### Розуміння функцій set\*uid

- **`setuid`**: Всупереч початковим припущенням, `setuid` переважно змінює `euid`, а не `ruid`. Зокрема, для привілейованих процесів вона встановлює `ruid`, `euid` і `suid` у вказаного користувача, часто root, фактично фіксуючи ці ID через перевизначення `suid`. Докладні відомості наведено на [сторінці man setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** і **`setresuid`**: Ці функції дають змогу детально змінювати `ruid`, `euid` і `suid`. Однак їхні можливості залежать від рівня привілеїв процесу. Для процесів, що не працюють від root, зміни обмежені поточними значеннями `ruid`, `euid` і `suid`. Натомість процеси root або процеси з capability `CAP_SETUID` можуть призначати цим ID довільні значення. Додаткову інформацію можна знайти на [сторінці man setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) і [сторінці man setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ці функціональні можливості призначені не як механізм безпеки, а для забезпечення передбаченого операційного процесу, наприклад коли програма приймає ідентичність іншого користувача, змінюючи свій ефективний ідентифікатор користувача.

Варто зазначити, що хоча `setuid` може бути поширеним засобом підвищення привілеїв до root (оскільки він встановлює всі ID у root), розрізнення між цими функціями має вирішальне значення для розуміння та керування поведінкою user ID у різних сценаріях.

### Механізми виконання програм у Linux

#### **Системний виклик `execve`**

- **Функціональність**: `execve` запускає програму, визначену першим аргументом. Він приймає два масиви аргументів: `argv` для аргументів і `envp` для середовища.
- **Поведінка**: Він зберігає memory space викликувача, але оновлює stack, heap і data segments. Код програми замінюється кодом нової програми.
- **Збереження User ID**:
- `ruid`, `euid` і supplementary group IDs залишаються без змін.
- `euid` може зазнати незначних змін, якщо для нової програми встановлено біт SetUID.
- `suid` після виконання оновлюється зі значення `euid`.
- **Документація**: Докладну інформацію можна знайти на [сторінці man [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html)].

#### **Функція `system`**

- **Функціональність**: На відміну від `execve`, `system` створює child process за допомогою `fork` і виконує команду в цьому child process за допомогою `execl`.
- **Виконання команди**: Виконує команду через `sh` за допомогою `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Поведінка**: Оскільки `execl` є формою `execve`, вона працює подібним чином, але в контексті нового child process.
- **Документація**: Додаткові відомості можна отримати на [сторінці man [`system`](https://man7.org/linux/man-pages/man3/system.3.html)].

#### **Поведінка `bash` і `sh` із SUID**

- **`bash`**:
- Має опцію `-p`, яка впливає на обробку `euid` і `ruid`.
- Без `-p` `bash` встановлює `euid` у значення `ruid`, якщо спочатку вони відрізнялися.
- Із `-p` початковий `euid` зберігається.
- Додаткові відомості наведено на [сторінці man [`bash`](https://linux.die.net/man/1/bash)].
- **`sh`**:
- Не має механізму, подібного до `-p` у `bash`.
- Поведінка щодо user ID явно не описана, за винятком опції `-i`, яка підкреслює збереження рівності `euid` і `ruid`.
- Додаткову інформацію наведено на [сторінці man [`sh`](https://man7.org/linux/man-pages/man1/sh.1p.html)].

Ці механізми, що відрізняються принципом роботи, забезпечують широкий набір варіантів для виконання та переходу між програмами, із певними нюансами керування та збереження user ID.

### Тестування поведінки User ID під час виконання

Приклади взято з https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, перегляньте це джерело для додаткової інформації

#### Випадок 1: Використання `setuid` із `system`

**Мета**: Зрозуміти вплив `setuid` у поєднанні з `system` і `bash` як `sh`.

**Код C**:
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
**Компіляція та права доступу:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- `ruid` і `euid` спочатку мають значення 99 (nobody) і 1000 (frank) відповідно.
- `setuid` встановлює обидва значення рівними 1000.
- `system` виконує `/bin/bash -c id` через symlink від sh до bash.
- `bash` без `-p` змінює `euid`, щоб він відповідав `ruid`, у результаті чого обидва мають значення 99 (nobody).

#### Випадок 2: Використання setreuid із system

**Код C:**
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
**Компіляція та права доступу:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Виконання та результат:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- `setreuid` встановлює і ruid, і euid у значення 1000.
- `system` викликає bash, який зберігає ідентифікатори користувача через їхню рівність, фактично виконуючи роботу як frank.

#### Випадок 3: Використання setuid із execve

Мета: дослідження взаємодії між setuid і execve.
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
**Виконання та результат:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- `ruid` залишається 99, але `euid` встановлюється в 1000 відповідно до ефекту setuid.

**Приклад коду C 2 (виклик Bash):**
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
**Виконання та результат:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Аналіз:**

- Хоча `euid` встановлено в `1000` за допомогою `setuid`, `bash` скидає `euid` до `ruid` (`99`) через відсутність `-p`.

**Приклад коду C 3 (Використання bash -p):**
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
**Виконання та результат:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Посилання

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
