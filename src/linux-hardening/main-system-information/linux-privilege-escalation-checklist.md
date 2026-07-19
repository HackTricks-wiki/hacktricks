# Чекліст - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку локальних векторів Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), чи є **доступна для запису директорія**?
- [ ] Перевірити [**змінні середовища**](../linux-basics/linux-privilege-escalation/index.html#env-info), чи містять вони конфіденційні дані?
- [ ] Шукати [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] **Перевірити**, чи є [**версія sudo вразливою**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Перевірка підпису Dmesg не вдалася**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Перевірити [**помилки конфігурації kernel module і завантаження модулів**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, примусову перевірку підписів і `modules_disabled`.
- [ ] Перевірити [**шляхи зловживання kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), якщо шлях до helper можна змінити або викликати.
- [ ] Перевірити [**доступні для запису шляхи /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), зокрема доступні для запису файли `.ko*` і метадані `modules.*`.
- [ ] Додатковий system enum ([дата, статистика системи, інформація про CPU, принтери](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перерахувати додаткові механізми захисту](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Перелічити підмонтовані** диски
- [ ] **Чи є непідмонтований диск?**
- [ ] **Чи є облікові дані у fstab?**

### [**Встановлене ПЗ**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Перевірити наявність**[ **корисного ПЗ**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **серед встановленого**
- [ ] **Перевірити наявність** [**вразливого ПЗ**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **серед встановленого**

### [Процеси](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Чи **запущене невідоме ПЗ**?
- [ ] Чи запущене якесь ПЗ із **більшими привілеями, ніж потрібно**?
- [ ] Шукати **експлойти запущених процесів** (особливо для запущеної версії).
- [ ] Чи можна **змінити бінарний файл** якогось запущеного процесу?
- [ ] **Моніторити процеси** та перевірити, чи часто запускається якийсь цікавий процес.
- [ ] Чи можна **прочитати** пам’ять якогось цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані/Cron-завдання?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)якимось cron, і чи можете ви **записувати** в нього?
- [ ] Чи є [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)у cron-завданні?
- [ ] Чи **виконується** якийсь [**скрипт, доступний для зміни** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink), або він розташований у **доступній для зміни директорії**?
- [ ] Чи виявили ви, що якийсь **скрипт** може або вже [**виконується** дуже **часто**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Сервіси](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Чи є файл **.service, доступний для запису**?
- [ ] Чи є **бінарний файл, доступний для запису**, який запускається **сервісом**?
- [ ] Чи є **доступна для запису директорія в PATH systemd**?
- [ ] Чи є **доступний для запису drop-in systemd unit** у `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?

### [Таймери](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Чи є **доступний для запису timer**?

### [Сокети](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Чи є файл **.socket, доступний для запису**?
- [ ] Чи можете ви **взаємодіяти з будь-яким сокетом**?
- [ ] **HTTP-сокети** з цікавою інформацією?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **взаємодіяти з будь-яким D-Bus**?

### [Мережа](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб визначити, де ви перебуваєте
- [ ] **Відкриті порти, до яких ви не мали доступу до** отримання shell усередині машини?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Загальне **перерахування користувачів/груп**
- [ ] Чи маєте ви **дуже великий UID**? Чи є **машина** **вразливою**?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](../user-information/interesting-groups-linux-pe/index.html), до якої належите?
- [ ] Дані **Clipboard**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви раніше виявили, щоб увійти **під кожним** можливим **користувачем**. Також спробуйте увійти без пароля.

### [Доступний для запису PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права на запис у якусь директорію в PATH**, ви можете підвищити привілеї

### [Команди SUDO і SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконати **будь-яку команду через sudo**? Чи можете використати її, щоб READ, WRITE або EXECUTE щось від імені root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірте **ін’єкцію аргументів sudoedit** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR`, щоб редагувати довільні файли у вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Чи є **експлуатований SUID-бінарний файл**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені [**команди sudo** **шляхом**]? Чи можна **обійти ці обмеження**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-бінарний файл без вказаного шляху**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-бінарний файл із вказаним шляхом**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Обійти
- [ ] [**Вразливість LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Відсутня .so-бібліотека у SUID-бінарному файлі**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) у доступній для запису директорії?
- [ ] [**SUID RPATH/RUNPATH або доступний для запису шлях до бібліотеки**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Доступні SUDO-токени**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можете ви створити SUDO-токен**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**прочитати або змінити файли sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**змінити /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Команда [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Чи має якийсь бінарний файл **неочікувану capability**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Чи має якийсь файл **неочікувану ACL**?

### [Відкриті shell-сесії](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Передбачуваний PRNG OpenSSL - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві значення конфігурації SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Файли профілю** - Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Файли passwd/shadow** - Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Перевірити загальновідомі цікаві директорії** на наявність конфіденційних даних
- [ ] **Файли в дивних місцях/файли, що належать**, до яких ви можете отримати доступ або змінити виконувані файли
- [ ] **Змінені** протягом останніх хвилин
- [ ] **Файли баз даних Sqlite**
- [ ] **Приховані файли**
- [ ] **Скрипти/бінарні файли в PATH**
- [ ] **Web-файли** (паролі?)
- [ ] **Резервні копії**?
- [ ] **Відомі файли, що містять паролі**: Використати **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Файли, доступні для запису**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Змінити python-бібліотеку**, щоб виконувати довільні команди?
- [ ] Чи можете ви **змінювати log-файли**? Експлойт **Logtotten**
- [ ] Чи можете ви **змінити /etc/sysconfig/network-scripts/**? Експлойт Centos/Redhat
- [ ] Чи можете ви [**записувати в ini, int.d, systemd або rc.d-файли**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші трюки**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**вийти з restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [Рекомендації Sudo: редагування довільних файлів через sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Документація Oracle Linux: конфігурація drop-in systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
