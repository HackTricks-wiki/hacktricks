# Контрольний список підвищення привілеїв у Linux

{{#include ../../banners/hacktricks-training.md}}

# Контрольний список — підвищення привілеїв у Linux



### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path): чи є там **доступна для запису папка**?
- [ ] Перевірити [**змінні середовища**](../linux-basics/linux-privilege-escalation/index.html#env-info): чи містять вони конфіденційні дані?
- [ ] Шукати [**експлойти ядра**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] Перш ніж запускати PoC для ядра, перевірити його **фактичні передумови**, а не лише `uname -r`: архітектуру, потрібні параметри/модулі `CONFIG_*`, можливість створення просторів імен і активні механізми захисту. Наприклад, перевірити доступність просторів імен користувача/мережі за допомогою `unshare -Urn true`; сучасним експлойтам netfilter можуть бути потрібні `CONFIG_USER_NS`, непривілейовані простори імен користувача та `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Перевірити**, чи є [**версія sudo вразливою**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Не вдалася перевірка підпису Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Переглянути [**помилкові налаштування модулів ядра та їх завантаження**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, примусове перевіряння підпису та `modules_disabled`.
- [ ] Перевірити [**шляхи зловживання kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), якщо шлях до допоміжної програми можна змінити або викликати.
- [ ] Перевірити [**шляхи /lib/modules, доступні для запису**](kernel-modules-and-modprobe.md#writable-libmodules-review), зокрема файли `.ko*` і метадані `modules.*`, доступні для запису.
- [ ] Додатково зібрати дані про систему ([дату, системну статистику, інформацію про CPU, принтери](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перерахувати інші механізми захисту](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Перелічити змонтовані** диски
- [ ] **Є незмонтований диск?**
- [ ] **Є облікові дані у fstab?**

### [**Встановлене ПЗ**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Перевірити, чи встановлено**[ **корисне ПЗ**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Перевірити, чи встановлено** [**вразливе ПЗ**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] У Debian/Ubuntu перевірити, чи встановлено/увімкнено **сканування інтерпретаторів needrestart**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. У вразливих збірках межу привілеїв обходили, повторно використовуючи контрольовані зловмисником `PYTHONPATH`/`RUBYLIB`, змагаючись за доступ до `/proc/<pid>/exe` або скануючи контрольовані зловмисником шляхи Perl, коли APT чи `unattended-upgrades` запускали needrestart від root.<sup>[[4]](#references)</sup>

### [Процеси](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Чи запущено якесь **невідоме ПЗ**?
- [ ] Чи працює якесь ПЗ із **вищими привілеями, ніж потрібно**?
- [ ] Шукати **експлойти для запущених процесів** (особливо для запущеної версії).
- [ ] Чи можете ви **змінити бінарний файл** будь-якого запущеного процесу?
- [ ] **Відстежувати процеси** й перевіряти, чи часто запускається якийсь цікавий процес.
- [ ] Чи можете ви **прочитати** пам’ять якогось цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані завдання/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)якимось cron-завданням і чи можете ви **записувати** в нього?
- [ ] Чи є [**підстановочний символ** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)у cron-завданні?
- [ ] Чи **виконується** якийсь [**скрипт, який можна змінити** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink), або він міститься в **папці, яку можна змінити**?
- [ ] Чи виявили ви, що якийсь **скрипт може виконуватися або виконується** [**дуже **часто**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Служби](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Чи є **файл .service, доступний для запису**?
- [ ] Чи є **бінарний файл, доступний для запису**, який **запускає служба**?
- [ ] Чи є допоміжний файл, файл конфігурації або файл середовища, на який посилається root unit (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`) і який можна змінити? Перегляньте об’єднаний unit за допомогою `systemctl cat <unit>` і перевірте [зловживання файлами служб/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Чи запускає привілейований процес за запитом допоміжну програму з каталогу з нижчими привілеями, доступного для запису? Перевірте і допоміжну програму, і її батьківський каталог на наявність [запуску від root скриптів/бінарних файлів, доступних для зміни користувачем](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); короткочасні допоміжні програми можуть з’являтися лише під час виконання процесу.
- [ ] Чи є **папка в PATH systemd, доступна для запису**?
- [ ] Чи є **drop-in конфігурація systemd, доступна для запису**, у `/etc/systemd/system/<unit>.d/*.conf`, яка може перевизначити `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Таймери](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Чи є **таймер, доступний для запису**?

### [Сокети](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Чи є **файл .socket, доступний для запису**?
- [ ] Чи можете ви **взаємодіяти з будь-яким сокетом**?
- [ ] **HTTP-сокети** з цікавою інформацією?
- [ ] Чи можете ви отримати доступ до [**API середовища виконання контейнерів або агента вузла**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), наприклад `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` або кінцевої точки kubelet? Перевірте безпосередньо API raw HTTP/gRPC, навіть якщо звичного CLI немає.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **взаємодіяти з будь-яким D-Bus**?

### [Мережа](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб з’ясувати, де ви перебуваєте
- [ ] Чи є **відкриті порти, до яких ви не мали доступу до отримання shell на машині**?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Загальне **перерахування користувачів/груп**
- [ ] Чи маєте ви **дуже великий UID**? Чи є **машина** **вразливою**?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](../user-information/interesting-groups-linux-pe/index.html), до якої належите?
- [ ] Дані **буфера обміну**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви раніше виявили, щоб увійти **під кожним** можливим **користувачем**. Спробуйте також увійти без пароля.

### [PATH, доступний для запису](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права на запис у якусь папку з PATH**, ви можете підвищити привілеї

### [Команди SUDO та SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконати **будь-яку команду через sudo**? Чи можете ви за її допомогою ЧИТАТИ, ЗАПИСУВАТИ або ВИКОНУВАТИ щось від імені root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірте **ін’єкцію аргументів sudoedit** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR` для редагування довільних файлів у вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Чи є **експлуатований SUID-бінарний файл**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені команди [**sudo** **шляхом**? Чи можна **обійти** ці обмеження](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Команда Sudo/SUID-бінарний файл без указаного шляху**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-бінарний файл із указаним шляхом**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Обійти обмеження
- [ ] [**Вразливість LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Відсутня .so-бібліотека в SUID-бінарному файлі**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) у папці, доступній для запису?
- [ ] [**SUID RPATH/RUNPATH або шлях до бібліотеки, доступний для запису**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Доступні токени SUDO**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можете ви створити токен SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**прочитати або змінити файли sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**змінити /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Команда [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Можливості](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Чи має якийсь бінарний файл **неочікувану можливість**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Чи має якийсь файл **неочікуваний ACL**?

### [Відкриті shell-сеанси](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] [**Передбачуваний PRNG OpenSSL у Debian — CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві параметри конфігурації SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Файли профілю** — прочитати конфіденційні дані? Записати для підвищення привілеїв?
- [ ] **Файли passwd/shadow** — прочитати конфіденційні дані? Записати для підвищення привілеїв?
- [ ] **Перевірити типові цікаві папки** на наявність конфіденційних даних
- [ ] **Файли в дивних місцях/файли з цікавим власником** — можливо, ви маєте доступ до виконуваних файлів або можете їх змінити
- [ ] **Змінені** за останні хвилини
- [ ] **Файли баз даних Sqlite**
- [ ] **Приховані файли**
- [ ] **Скрипти/бінарні файли в PATH**
- [ ] **Вебфайли** (паролі?)
- [ ] **Резервні копії**?
- [ ] **Відомі файли, що містять паролі**: використайте **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Файли, доступні для запису**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Змінити бібліотеку python**, щоб виконувати довільні команди?
- [ ] Чи можете ви **змінити файли журналів**? Експлойт **Logtotten**
- [ ] Чи можете ви **змінити /etc/sysconfig/network-scripts/**? Експлойт для Centos/Redhat
- [ ] Чи можете ви [**записувати в файли ini, int.d, systemd або rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші хитрощі**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**вийти з обмеженої оболонки**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Рекомендація з безпеки sudo: довільне редагування файлів через sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Документація Oracle Linux: конфігурація drop-in для systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: вимоги до експлойту CVE-2024-1086 та дослідження](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Рекомендація з безпеки Qualys: LPE у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
