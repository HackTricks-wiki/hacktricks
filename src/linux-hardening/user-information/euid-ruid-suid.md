# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Змінні ідентифікації користувача

- **`ruid`**: **реальний ID користувача** визначає користувача, який ініціював процес.
- **`euid`**: Відомий як **ефективний ID користувача**, він представляє ідентичність користувача, яку система використовує для визначення привілеїв процесу. Зазвичай `euid` відповідає `ruid`, за винятком таких випадків, як виконання SetUID binary, коли `euid` набуває ідентичність власника файлу, надаючи відповідні operational permissions.
- **`suid`**: Цей **збережений ID користувача** є важливим, коли процес із високими привілеями (зазвичай запущений від root) має тимчасово відмовитися від своїх привілеїв для виконання певних завдань, а потім відновити свій початковий підвищений статус.

#### Важлива примітка

Процес, який не працює від root, може змінити свій `euid` лише так, щоб він відповідав поточному `ruid`, `euid` або `suid`.

### Розуміння функцій set\*uid

- **`setuid`**: Всупереч початковим припущенням, `setuid` переважно змінює `euid`, а не `ruid`. Зокрема, для привілейованих процесів вона встановлює `ruid`, `euid` і `suid` у вказаного користувача, часто root, фактично закріплюючи ці ID завдяки перевизначенню `suid`. Докладні відомості наведено на [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** і **`setresuid`**: Ці функції дають змогу детально налаштовувати `ruid`, `euid` і `suid`. Однак їхні можливості залежать від рівня привілеїв процесу. Для процесів без root модифікації обмежені поточними значеннями `ruid`, `euid` і `suid`. Натомість процеси root або процеси з capability `CAP_SETUID` можуть призначати цим ID довільні значення. Більше інформації наведено на [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) і [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ці функціональні можливості призначені не як механізм безпеки, а для забезпечення передбаченого operational flow, наприклад коли програма приймає ідентичність іншого користувача, змінюючи свій ефективний ID користувача.

Варто зазначити, що хоча `setuid` може бути поширеним варіантом для підвищення привілеїв до root (оскільки вона встановлює всі ID у root), розрізнення між цими функціями є важливим для розуміння та керування поведінкою user ID у різних сценаріях.

### Механізми виконання програм у Linux

#### **Системний виклик `execve`**

- **Функціональність**: `execve` запускає програму, визначену першим аргументом. Вона приймає два масиви аргументів: `argv` для аргументів і `envp` для середовища.
- **Поведінка**: Вона зберігає memory space caller, але оновлює stack, heap і data segments. Код програми замінюється новою програмою.
- **Збереження User ID**:
- `ruid`, `euid` і supplementary group IDs залишаються без змін.
- `euid` може зазнати певних змін, якщо для нової програми встановлено біт SetUID.
- `suid` оновлюється зі значення `euid` після виконання.
- **Документація**: Докладну інформацію наведено на [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Функція `system`**

- **Функціональність**: На відміну від `execve`, `system` створює child process за допомогою `fork` і виконує команду в цьому child process за допомогою `execl`.
- **Виконання команди**: Виконує команду через `sh` за допомогою `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Поведінка**: Оскільки `execl` є формою `execve`, вона працює аналогічно, але в контексті нового child process.
- **Документація**: Додаткові відомості наведено на [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Поведінка `bash` і `sh` із SUID**

- **`bash`**:
- Має опцію `-p`, яка впливає на обробку `euid` і `ruid`.
- Без `-p` `bash` встановлює `euid` у значення `ruid`, якщо спочатку вони відрізнялися.
- Із `-p` початковий `euid` зберігається.
- Докладнішу інформацію наведено на [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Не має механізму, подібного до `-p` у `bash`.
- Поведінка щодо user ID явно не описана, за винятком опції `-i`, яка підкреслює збереження рівності `euid` і `ruid`.
- Додаткову інформацію наведено на [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ці механізми, відмінні за принципом роботи, забезпечують широкий набір варіантів для виконання програм і переходу між ними, з окремими нюансами керування та збереження user ID.

### Тестування поведінки User ID під час виконання

Приклади взято з https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, перегляньте його для отримання додаткової інформації<sup>[[1]](#references)</sup>

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
- `setuid` вирівнює обидва значення до 1000.
- `system` виконує `/bin/bash -c id` через symlink від sh до bash.
- `bash` без `-p` змінює `euid` відповідно до `ruid`, у результаті обидва мають значення 99 (nobody).

#### Випадок 2: Використання setreuid із system

**Код C**:
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
- `system` викликає bash, який зберігає ідентифікатори користувачів завдяки їхній рівності, фактично працюючи як frank.

#### Випадок 3: Використання setuid з execve

Мета: дослідити взаємодію між setuid і execve.
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

**Приклад коду C 2 (Виклик Bash):**
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

- Хоча `euid` встановлено в 1000 за допомогою `setuid`, `bash` скидає euid до `ruid` (99) через відсутність `-p`.

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

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - сторінка довідки setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - сторінка довідки setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - сторінка довідки setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - сторінка довідки execve](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
