# Чеклист - Підвищення привілеїв в Linux

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів підвищення локальних привілеїв в Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](privilege-escalation/#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](privilege-escalation/#path), чи є **записувана папка**?
- [ ] Перевірити [**змінні середовища**](privilege-escalation/#env-info), чи є чутливі дані?
- [ ] Шукати [**експлойти ядра**](privilege-escalation/#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] **Перевірити**, чи [**версія sudo** вразлива](privilege-escalation/#sudo-version)
- [ ] [**Перевірка підпису Dmesg** не вдалася](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Більше системної енумерації ([дата, статистика системи, інформація про процесор, принтери](privilege-escalation/#more-system-enumeration))
- [ ] [**Перерахувати більше захистів**](privilege-escalation/#enumerate-possible-defenses)

### [Диски](privilege-escalation/#drives)

- [ ] **Перелічити змонтовані** диски
- [ ] **Якийсь незмонтований диск?**
- [ ] **Якісь облікові дані в fstab?**

### [**Встановлене програмне забезпечення**](privilege-escalation/#installed-software)

- [ ] **Перевірити наявність** [**корисного програмного забезпечення**](privilege-escalation/#useful-software) **встановленого**
- [ ] **Перевірити наявність** [**вразливого програмного забезпечення**](privilege-escalation/#vulnerable-software-installed) **встановленого**

### [Процеси](privilege-escalation/#processes)

- [ ] Чи є **невідоме програмне забезпечення, що працює**?
- [ ] Чи працює якесь програмне забезпечення з **більшими привілеями, ніж повинно**?
- [ ] Шукати **експлойти працюючих процесів** (особливо версія, що працює).
- [ ] Чи можете ви **модифікувати бінарний файл** будь-якого працюючого процесу?
- [ ] **Моніторити процеси** і перевірити, чи працює якийсь цікавий процес часто.
- [ ] Чи можете ви **читати** деяку цікаву **пам'ять процесу** (де можуть зберігатися паролі)?

### [Заплановані/cron завдання?](privilege-escalation/#scheduled-jobs)

- [ ] Чи змінюється [**PATH**](privilege-escalation/#cron-path) якимось cron і ви можете **записувати** в нього?
- [ ] Якийсь [**шаблон**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) в cron завданні?
- [ ] Якийсь [**модифікований скрипт**](privilege-escalation/#cron-script-overwriting-and-symlink) виконується або знаходиться в **модифікованій папці**?
- [ ] Чи виявили ви, що якийсь **скрипт** може бути або виконується [**дуже часто**](privilege-escalation/#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Служби](privilege-escalation/#services)

- [ ] Якийсь **записуваний .service** файл?
- [ ] Якийсь **записуваний бінарний файл**, що виконується службою?
- [ ] Якась **записувана папка в системному PATH**?

### [Таймери](privilege-escalation/#timers)

- [ ] Якийсь **записуваний таймер**?

### [Сокети](privilege-escalation/#sockets)

- [ ] Якийсь **записуваний .socket** файл?
- [ ] Чи можете ви **спілкуватися з будь-яким сокетом**?
- [ ] **HTTP сокети** з цікавою інформацією?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Чи можете ви **спілкуватися з будь-яким D-Bus**?

### [Мережа](privilege-escalation/#network)

- [ ] Перерахувати мережу, щоб знати, де ви знаходитесь
- [ ] **Відкриті порти, до яких ви не могли отримати доступ раніше**, потрапивши в оболонку всередині машини?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](privilege-escalation/#users)

- [ ] Загальна **перерахування користувачів/груп**
- [ ] Чи маєте ви **дуже великий UID**? Чи **вразлива** **машина**?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](privilege-escalation/interesting-groups-linux-pe/), до якої належите?
- [ ] **Дані буфера обміну**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви раніше виявили, щоб увійти **з кожним** можливим **користувачем**. Спробуйте також увійти без пароля.

### [Записуваний PATH](privilege-escalation/#writable-path-abuses)

- [ ] Якщо у вас є **права на запис в деяку папку в PATH**, ви можете підвищити привілеї

### [Команди SUDO та SUID](privilege-escalation/#sudo-and-suid)

- [ ] Чи можете ви виконати **будь-яку команду з sudo**? Чи можете ви використовувати його для ЧИТАННЯ, ЗАПИСУ або ВИКОНАННЯ чогось як root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи є якийсь **експлуатований SUID бінарний файл**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи [**обмежені** команди **sudo** **шляхом**? Чи можете ви **обійти** обмеження](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID бінарний файл без вказаного шляху**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID бінарний файл з вказаним шляхом**](privilege-escalation/#suid-binary-with-command-path)? Обійти
- [ ] [**LD_PRELOAD вразливість**](privilege-escalation/#ld_preload)
- [ ] [**Відсутність .so бібліотеки в SUID бінарному файлі**](privilege-escalation/#suid-binary-so-injection) з записуваної папки?
- [ ] [**Токени SUDO доступні**](privilege-escalation/#reusing-sudo-tokens)? [**Чи можете ви створити SUDO токен**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**читати або модифікувати файли sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**модифікувати /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) команда

### [Можливості](privilege-escalation/#capabilities)

- [ ] Чи має якийсь бінарний файл **неочікувану можливість**?

### [ACL](privilege-escalation/#acls)

- [ ] Чи має якийсь файл **неочікуваний ACL**?

### [Відкриті сеанси оболонки](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Передбачуваний PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві конфігураційні значення SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Цікаві файли](privilege-escalation/#interesting-files)

- [ ] **Файли профілю** - Читати чутливі дані? Записувати для підвищення привілеїв?
- [ ] **Файли passwd/shadow** - Читати чутливі дані? Записувати для підвищення привілеїв?
- [ ] **Перевірити загально цікаві папки** на наявність чутливих даних
- [ ] **Дивні місця/власні файли**, до яких ви можете отримати доступ або змінити виконувані файли
- [ ] **Змінено** за останні хвилини
- [ ] **Файли Sqlite DB**
- [ ] **Сховані файли**
- [ ] **Скрипти/бінарники в PATH**
- [ ] **Веб файли** (паролі?)
- [ ] **Резервні копії**?
- [ ] **Відомі файли, що містять паролі**: Використовуйте **Linpeas** та **LaZagne**
- [ ] **Загальний пошук**

### [**Записувані файли**](privilege-escalation/#writable-files)

- [ ] **Модифікувати бібліотеку python** для виконання довільних команд?
- [ ] Чи можете ви **модифікувати журнали**? **Logtotten** експлойт
- [ ] Чи можете ви **модифікувати /etc/sysconfig/network-scripts/**? Centos/Redhat експлойт
- [ ] Чи можете ви [**записувати в ini, int.d, systemd або rc.d файли**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Інші трюки**](privilege-escalation/#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**втекти з обмеженої оболонки**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
