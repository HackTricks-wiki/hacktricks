# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#3f17" id="3f17"></a>

**Перегляньте оригінальну публікацію, щоб отримати [всю інформацію про цю техніку](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

**Коротко**: якщо ви можете записувати значення властивості **msDS-KeyCredentialLink** користувача або комп'ютера, ви можете отримати **NT hash цього об'єкта**.<sup>[[1]](#references)</sup>

У публікації описано метод налаштування **облікових даних автентифікації на основі відкритого та приватного ключів** для отримання унікального **Service Ticket**, який містить NTLM hash цільового об'єкта. Цей процес передбачає зашифрований NTLM_SUPPLEMENTAL_CREDENTIAL у межах Privilege Attribute Certificate (PAC), який можна розшифрувати.<sup>[[1]](#references)</sup>

### Вимоги

Для застосування цієї техніки мають виконуватися певні умови:<sup>[[1]](#references)</sup>

- Потрібен щонайменше один Windows Server 2016 Domain Controller.
- На Domain Controller має бути встановлено цифровий сертифікат server authentication.
- Active Directory має працювати на Windows Server 2016 Functional Level.
- Потрібен обліковий запис із делегованими правами на зміну атрибута msDS-KeyCredentialLink цільового об'єкта.

## Зловживання

Зловживання Key Trust для об'єктів-комп'ютерів охоплює більше кроків, ніж отримання Ticket Granting Ticket (TGT) і NTLM hash. Доступні такі варіанти:<sup>[[1]](#references)</sup>

1. Створення **RC4 silver ticket** для роботи від імені привілейованих користувачів на цільовому хості.
2. Використання TGT разом із **S4U2Self** для імперсонації **привілейованих користувачів**, що потребує зміни Service Ticket для додавання service class до імені service.

Важливою перевагою зловживання Key Trust є те, що воно обмежується приватним ключем, згенерованим зловмисником, не передбачає делегування потенційно вразливим обліковим записам і не вимагає створення облікового запису комп'ютера, який може бути складно видалити.<sup>[[1]](#references)</sup>

## Інструменти

### [**Whisker**](https://github.com/eladshamir/Whisker)

Він базується на DSInternals і надає C#-інтерфейс для цієї атаки. Whisker та його Python-аналог, **pyWhisker**, дають змогу змінювати атрибут `msDS-KeyCredentialLink` для отримання контролю над обліковими записами Active Directory. Ці інструменти підтримують різні операції, зокрема додавання, перелік, видалення та очищення key credentials цільового об'єкта.

Функції **Whisker**:

- **Add**: генерує пару ключів і додає key credential.
- **List**: відображає всі записи key credential.
- **Remove**: видаляє вказаний key credential.
- **Clear**: стирає всі key credentials, що потенційно може порушити легітимне використання WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Розширює функціональність Whisker для **UNIX-based systems**, використовуючи Impacket і PyDSInternals для комплексних можливостей exploitation, зокрема перегляду списку, додавання та видалення KeyCredentials, а також їх імпорту й експорту у форматі JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray призначений для **експлуатації дозволів GenericWrite/GenericAll, які широкі групи користувачів можуть мати щодо об'єктів домену**, щоб масово застосовувати Shadow Credentials. Він передбачає вхід до домену, перевірку функціонального рівня домену, перерахування об'єктів домену та спроби додати KeyCredentials для отримання TGT і розкриття NT hash. Параметри очищення та тактики рекурсивної експлуатації розширюють його корисність.

## Посилання

- [1] [Shadow Credentials: зловживання зіставленням облікових записів через Key Trust для захоплення облікового запису](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - інструмент для захоплення облікових записів AD шляхом маніпуляції msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - інструмент для масового застосування Shadow Credentials у домені](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - версія інструмента Shadow Credentials на Python](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
