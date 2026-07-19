# Чекліст підвищення привілеїв у Linux

{{#include ../../banners/hacktricks-training.md}}

# Чекліст - підвищення привілеїв у Linux



### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), чи є **доступна для запису папка**?
- [ ] Перевірити [**змінні env**](../linux-basics/linux-privilege-escalation/index.html#env-info), чи містять вони конфіденційні дані?
- [ ] Шукати [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] **Перевірити**, чи є [**версія sudo вразливою**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Перевірка підпису Dmesg не вдалася**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Перевірити [**помилкові налаштування kernel module і завантаження модулів**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, enforcement підписів і `modules_disabled`.
- [ ] Перевірити [**шляхи зловживання kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), якщо шлях до helper можна змінити або активувати.
- [ ] Перевірити [**шляхи /lib/modules, доступні для запису**](kernel-modules-and-modprobe.md#writable-libmodules-review), зокрема файли `.ko*` і метадані `modules.*`, доступні для запису.
- [ ] Додаткова enum системи ([дата, статистика системи, інформація про CPU, принтери](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перерахувати додаткові засоби захисту](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Перерахувати змонтовані** диски
- [ ] **Чи є незмонтований диск?**
- [ ] **Чи є creds у fstab?**

### [**Встановлене ПЗ**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Перевірити наявність**[ **корисного ПЗ**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **серед встановленого**
- [ ] **Перевірити наявність** [**вразливого ПЗ**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **серед встановленого**

### [Процеси](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Чи **запущене невідоме ПЗ**?
- [ ] Чи запущене якесь ПЗ з **більшими привілеями, ніж повинно**?
- [ ] Шукати **exploits запущених процесів** (особливо версії, що запущена).
- [ ] Чи можна **змінити binary** будь-якого запущеного процесу?
- [ ] **Моніторити процеси** й перевірити, чи якийсь цікавий процес запускається часто.
- [ ] Чи можна **прочитати** пам’ять якогось цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)якимось cron і чи можете ви **записувати** в нього?
- [ ] Чи є [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)у cron job?
- [ ] Чи **виконується** якийсь [**скрипт, доступний для зміни** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)або він розташований у **папці, доступній для зміни**?
- [ ] Чи виявили ви, що якийсь **скрипт** може або вже [**виконується** дуже **часто**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Сервіси](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Чи є файл **.service, доступний для запису**?
- [ ] Чи є **binary, доступний для запису**, який виконується **сервісом**?
- [ ] Чи є **папка, доступна для запису, у PATH systemd**?
- [ ] Чи є **systemd unit drop-in, доступний для запису**, у `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?

### [Таймери](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Чи є **таймер, доступний для запису**?

### [Сокети](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Чи є файл **.socket, доступний для запису**?
- [ ] Чи можете ви **взаємодіяти з будь-яким сокетом**?
- [ ] **HTTP-сокети** з цікавою інформацією?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **взаємодіяти з будь-яким D-Bus**?

### [Мережа](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб зрозуміти, де ви перебуваєте
- [ ] **Відкриті порти, до яких ви не могли отримати доступ до** отримання shell усередині машини?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Загальна **enum користувачів/груп**
- [ ] Чи маєте ви **дуже великий UID**? Чи є **машина** **вразливою**?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](../user-information/interesting-groups-linux-pe/index.html), до якої належите?
- [ ] Дані **Clipboard**?
- [ ] Політика паролів?
- [ ] Спробувати **використати** кожен **відомий пароль**, який ви раніше виявили, щоб увійти **під кожним** можливим **користувачем**. Також спробувати увійти без пароля.

### [PATH, доступний для запису](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права запису до папки в PATH**, ви можете отримати можливість підвищити привілеї

### [Команди SUDO і SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконати **будь-яку команду через sudo**? Чи можете використати її, щоб READ, WRITE або EXECUTE щось від імені root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірити **ін’єкцію аргументів sudoedit** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR`, щоб редагувати довільні файли у вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Чи є **SUID binary, який можна експлуатувати**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені [команди **sudo** **шляхом**]? Чи можна [**обійти обмеження**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary без зазначеного шляху**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary із зазначеним шляхом**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Обійти
- [ ] [**Вразливість LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Відсутність .so library у SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) у папці, доступній для запису?
- [ ] [**SUID RPATH/RUNPATH або шлях до library, доступний для запису**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Доступні SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можете ви створити SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**прочитати або змінити файли sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**змінити /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Команда [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Чи має будь-який binary **неочікувану capability**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Чи має будь-який файл **неочікувану ACL**?

### [Відкриті shell-сесії](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві значення конфігурації SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Прочитати конфіденційні дані? Записати для privesc?
- [ ] **passwd/shadow files** - Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Перевірити поширені цікаві папки** на наявність конфіденційних даних
- [ ] **Файли в нетипових місцях/файли, власником яких є інший користувач,** до яких ви можете отримати доступ або змінити executable files
- [ ] **Змінені** протягом останніх хвилин
- [ ] **Файли SQLite DB**
- [ ] **Приховані файли**
- [ ] **Скрипти/Binaries у PATH**
- [ ] **Web-файли** (паролі?)
- [ ] **Backups**?
- [ ] **Відомі файли, що містять паролі**: використати **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Файли, доступні для запису**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Змінити python library**, щоб виконати довільні команди?
- [ ] Чи можете ви **змінювати log files**? exploit **Logtotten**
- [ ] Чи можете ви **змінити /etc/sysconfig/network-scripts/**? exploit для Centos/Redhat
- [ ] Чи можете ви [**записувати в ini, int.d, systemd або rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**вийти з restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [Рекомендації Sudo: редагування довільних файлів через sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Документація Oracle Linux: конфігурація systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
