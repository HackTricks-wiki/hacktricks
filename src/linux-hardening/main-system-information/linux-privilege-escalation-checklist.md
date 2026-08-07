# Чекліст підвищення привілеїв у Linux

{{#include ../../banners/hacktricks-training.md}}

# Чекліст — підвищення привілеїв у Linux



### **Найкращий інструмент для пошуку локальних векторів підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), чи є **доступна для запису папка**?
- [ ] Перевірити [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), чи є конфіденційні дані?
- [ ] Шукати [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] **Перевірити**, чи є [**версія sudo** вразливою](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Перевірка підпису Dmesg завершилася невдало**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Перевірити [**помилкові конфігурації kernel module і завантаження модулів**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, примусову перевірку підписів і `modules_disabled`.
- [ ] Перевірити [**шляхи зловживання kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), якщо шлях helper можна змінити або запустити.
- [ ] Перевірити [**шляхи /lib/modules, доступні для запису**](kernel-modules-and-modprobe.md#writable-libmodules-review), зокрема файли `.ko*` і метадані `modules.*`, доступні для запису.
- [ ] Додатковий system enum ([дата, статистика системи, інформація про CPU, принтери](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перерахувати додаткові засоби захисту](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Перелічити змонтовані** диски
- [ ] **Є незмонтований диск?**
- [ ] **Є creds у fstab?**

### [**Встановлене ПЗ**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Перевірити, чи встановлено**[ **корисне ПЗ**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Перевірити, чи встановлено** [**вразливе ПЗ**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)

### [Процеси](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Запущено невідоме **ПЗ**?
- [ ] Чи запущено якесь ПЗ із **вищими привілеями, ніж необхідно**?
- [ ] Шукати **експлойти для запущених процесів** (особливо для запущеної версії).
- [ ] Чи можна **змінити бінарний файл** будь-якого запущеного процесу?
- [ ] **Моніторити процеси** та перевірити, чи часто запускається якийсь цікавий процес.
- [ ] Чи можна **прочитати** пам’ять якогось цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані завдання/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)якимось cron і чи можете ви **записувати** в нього?
- [ ] Є [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)у cron job?
- [ ] Чи **виконується** якийсь [**скрипт, доступний для зміни** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)або він міститься в **папці, доступній для зміни**?
- [ ] Чи виявили ви, що якийсь **скрипт** може або вже [**виконується** дуже **часто**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Сервіси](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Є файл **.service, доступний для запису**?
- [ ] Є **бінарний файл, доступний для запису**, який запускається **сервісом**?
- [ ] Є **папка в PATH systemd, доступна для запису**?
- [ ] Є **drop-in systemd unit, доступний для запису**, у `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Таймери](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Є **таймер, доступний для запису**?

### [Сокети](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Є файл **.socket, доступний для запису**?
- [ ] Чи можете ви **взаємодіяти з будь-яким сокетом**?
- [ ] **HTTP-сокети** з цікавою інформацією?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **взаємодіяти з будь-яким D-Bus**?

### [Мережа](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб визначити, де ви перебуваєте
- [ ] **Відкриті порти, до яких ви не могли отримати доступ до** отримання shell всередині машини?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Загальне **перерахування** користувачів/груп
- [ ] У вас **дуже великий UID**? Чи є **машина** **вразливою**?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](../user-information/interesting-groups-linux-pe/index.html), до якої належите?
- [ ] Дані **Clipboard**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви раніше виявили, для входу **під кожним** можливим **користувачем**. Також спробуйте увійти без пароля.

### [PATH, доступний для запису](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права на запис до якоїсь папки в PATH**, ви можете підвищити привілеї

### [Команди SUDO і SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконати **будь-яку команду через sudo**? Чи можете використати її для ЧИТАННЯ, ЗАПИСУ або ВИКОНАННЯ чогось від імені root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірити **ін’єкцію аргументів sudoedit** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR`, щоб редагувати довільні файли у вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Є **експлуатований SUID-бінарний файл**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені [команди **sudo** **шляхом**]? Чи можете ви **обійти ці обмеження**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Бінарний файл Sudo/SUID без вказаного шляху**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-бінарний файл із указаним шляхом**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Обійти
- [ ] [**Вразливість LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Відсутня .so-бібліотека у SUID-бінарному файлі**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) у папці, доступній для запису?
- [ ] [**SUID RPATH/RUNPATH або шлях до бібліотеки, доступний для запису**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Доступні SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можете ви створити SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**прочитати або змінити файли sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**змінити /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Команда [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Має якийсь бінарний файл **неочікувану capability**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Має якийсь файл **неочікувану ACL**?

### [Відкриті shell-сесії](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Передбачуваний PRNG OpenSSL — CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві значення конфігурації SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Файли профілів** — Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Файли passwd/shadow** — Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Перевірити поширені цікаві папки** на наявність конфіденційних даних
- [ ] **Файли в нетиповому розташуванні/власником яких є інший користувач,** до яких ви можете отримати доступ або змінити які можна виконувані файли
- [ ] **Змінені** протягом останніх хвилин
- [ ] **Файли баз даних Sqlite**
- [ ] **Приховані файли**
- [ ] **Скрипти/бінарні файли в PATH**
- [ ] **Web-файли** (паролі?)
- [ ] **Резервні копії**?
- [ ] **Відомі файли, що містять паролі**: Використовуйте **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Файли, доступні для запису**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Змінити бібліотеку Python**, щоб виконувати довільні команди?
- [ ] Чи можете ви **змінювати log-файли**? Експлойт **Logtotten**
- [ ] Чи можете ви **змінити /etc/sysconfig/network-scripts/**? Експлойт Centos/Redhat
- [ ] Чи можете ви [**записувати в ini, int.d, systemd або rc.d-файли**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші прийоми**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**вийти з обмеженої shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?

## Посилання

- [1] [Рекомендації Sudo: довільне редагування файлів через sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Документація Oracle Linux: конфігурація systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
