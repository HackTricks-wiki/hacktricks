# Чеклист - Підвищення привілеїв в Linux

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв в Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](privilege-escalation/index.html#path), чи є **записувана папка**?
- [ ] Перевірити [**змінні середовища**](privilege-escalation/index.html#env-info), чи є чутливі дані?
- [ ] Шукати [**експлойти ядра**](privilege-escalation/index.html#kernel-exploits) **використовуючи скрипти** (DirtyCow?)
- [ ] **Перевірити**, чи [**версія sudo** вразлива](privilege-escalation/index.html#sudo-version)
- [ ] [**Перевірка підпису Dmesg** не вдалася](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Більше системної енумерації ([дата, статистика системи, інформація про процесор, принтери](privilege-escalation/index.html#more-system-enumeration))
- [ ] [**Перерахувати більше захистів**](privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](privilege-escalation/index.html#drives)

- [ ] **Перелічити змонтовані** диски
- [ ] **Якийсь незмонтований диск?**
- [ ] **Якісь облікові дані в fstab?**

### [**Встановлене програмне забезпечення**](privilege-escalation/index.html#installed-software)

- [ ] **Перевірити наявність** [**корисного програмного забезпечення**](privilege-escalation/index.html#useful-software) **встановленого**
- [ ] **Перевірити наявність** [**вразливого програмного забезпечення**](privilege-escalation/index.html#vulnerable-software-installed) **встановленого**

### [Процеси](privilege-escalation/index.html#processes)

- [ ] Чи є **невідоме програмне забезпечення, що працює**?
- [ ] Чи працює якесь програмне забезпечення з **більшими привілеями, ніж повинно**?
- [ ] Шукати **експлойти працюючих процесів** (особливо версії, що працює).
- [ ] Чи можете ви **модифікувати бінарний файл** будь-якого працюючого процесу?
- [ ] **Моніторити процеси** і перевірити, чи працює якийсь цікавий процес часто.
- [ ] Чи можете ви **читати** деяку цікаву **пам'ять процесу** (де можуть зберігатися паролі)?

### [Заплановані/cron завдання?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH**](privilege-escalation/index.html#cron-path) якимось cron, і ви можете **записувати** в нього?
- [ ] Якийсь [**шаблон**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) в cron завданні?
- [ ] Якийсь [**модифікований скрипт**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) виконується або знаходиться в **модифікованій папці**?
- [ ] Чи виявили ви, що якийсь **скрипт** може бути або виконується [**дуже часто**](privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Служби](privilege-escalation/index.html#services)

- [ ] Якийсь **записуваний .service** файл?
- [ ] Якийсь **записуваний бінарний файл**, що виконується службою?
- [ ] Якась **записувана папка в системному PATH**?

### [Таймери](privilege-escalation/index.html#timers)

- [ ] Якийсь **записуваний таймер**?

### [Сокети](privilege-escalation/index.html#sockets)

- [ ] Якийсь **записуваний .socket** файл?
- [ ] Чи можете ви **спілкуватися з будь-яким сокетом**?
- [ ] **HTTP сокети** з цікавою інформацією?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **спілкуватися з будь-яким D-Bus**?

### [Мережа](privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб знати, де ви знаходитесь
- [ ] **Відкриті порти, до яких ви не могли отримати доступ раніше** отримавши оболонку всередині машини?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](privilege-escalation/index.html#users)

- [ ] Загальна **перерахування користувачів/груп**
- [ ] Чи маєте ви **дуже великий UID**? Чи **вразлива** **машина**?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](privilege-escalation/interesting-groups-linux-pe/), до якої належите?
- [ ] **Дані буфера обміну**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви раніше виявили, щоб увійти **з кожним** можливим **користувачем**. Спробуйте також увійти без пароля.

### [Записуваний PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права запису на якусь папку в PATH**, ви можете підвищити привілеї

### [Команди SUDO та SUID](privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконати **будь-яку команду з sudo**? Чи можете ви використовувати його для ЧИТАННЯ, ЗАПИСУ або ВИКОНАННЯ чогось як root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи є якийсь **експлуатований SUID бінарний файл**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи [**обмежені** команди **sudo** **шляхом**? Чи можете ви **обійти** обмеження](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID бінарний файл без вказаного шляху**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID бінарний файл з вказаним шляхом**](privilege-escalation/index.html#suid-binary-with-command-path)? Обійти
- [ ] [**LD_PRELOAD вразливість**](privilege-escalation/index.html#ld_preload)
- [ ] [**Відсутність .so бібліотеки в SUID бінарному файлі**](privilege-escalation/index.html#suid-binary-so-injection) з записуваної папки?
- [ ] [**Доступні токени SUDO**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можете ви створити токен SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**читати або модифікувати файли sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**модифікувати /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) команда

### [Можливості](privilege-escalation/index.html#capabilities)

- [ ] Чи має якийсь бінарний файл **неочікувану можливість**?

### [ACL](privilege-escalation/index.html#acls)

- [ ] Чи має якийсь файл **неочікуваний ACL**?

### [Відкриті сесії оболонки](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Передбачуваний PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві конфігураційні значення SSH**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](privilege-escalation/index.html#interesting-files)

- [ ] **Файли профілю** - Чи можна прочитати чутливі дані? Записати для підвищення привілеїв?
- [ ] **Файли passwd/shadow** - Чи можна прочитати чутливі дані? Записати для підвищення привілеїв?
- [ ] **Перевірити загально цікаві папки** на наявність чутливих даних
- [ ] **Дивні місця/власні файли**, до яких ви можете отримати доступ або змінити виконувані файли
- [ ] **Змінені** за останні хвилини
- [ ] **Файли Sqlite DB**
- [ ] **Сховані файли**
- [ ] **Скрипти/Бінарники в PATH**
- [ ] **Веб файли** (паролі?)
- [ ] **Резервні копії**?
- [ ] **Відомі файли, що містять паролі**: Використовуйте **Linpeas** та **LaZagne**
- [ ] **Загальний пошук**

### [**Записувані файли**](privilege-escalation/index.html#writable-files)

- [ ] **Модифікувати бібліотеку python** для виконання довільних команд?
- [ ] Чи можете ви **модифікувати журнали**? **Logtotten** експлойт
- [ ] Чи можете ви **модифікувати /etc/sysconfig/network-scripts/**? Centos/Redhat експлойт
- [ ] Чи можете ви [**записувати в ini, int.d, systemd або rc.d файли**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші трюки**](privilege-escalation/index.html#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**втекти з обмеженої оболонки**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
