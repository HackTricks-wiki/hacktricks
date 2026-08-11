# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#3f17" id="3f17"></a>

**Перегляньте оригінальний допис, щоб отримати [всю інформацію про цю техніку](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Коротко кажучи, контроль над **`msDS-KeyCredentialLink`** користувача або комп'ютера дає зловмиснику змогу додати ключову credential, автентифікуватися як цей об'єкт за допомогою PKINIT і — коли KDC та обліковий запис підтримують необхідні потоки — використати отриманий ticket із `S4U2Self`/user-to-user для відновлення NT hash об'єкта.<sup>[[1]](#references)</sup>

У дописі описано метод налаштування **credentials автентифікації на основі відкритого та приватного ключів** для отримання унікального **Service Ticket**, що містить NTLM hash цільового об'єкта. Цей процес передбачає зашифрований NTLM_SUPPLEMENTAL_CREDENTIAL у складі Privilege Attribute Certificate (PAC), який можна розшифрувати.<sup>[[1]](#references)</sup>

### Вимоги

Для застосування цієї техніки мають виконуватися певні умови:<sup>[[1]](#references)</sup>

- Потрібен щонайменше один Windows Server 2016 Domain Controller.
- На Domain Controller має бути встановлений цифровий сертифікат server authentication.
- Схема каталогу має містити `msDS-KeyCredentialLink`; Windows Server 2016 або новіший DC і сертифікат, сумісний із PKINIT, на KDC є практичними вимогами до платформи, описаними в дослідженні. Перевіряйте схему домену та комбінацію версій DC, а не припускайте, що лише позначка функціонального рівня домену визначає можливість exploitation.
- Потрібен обліковий запис із делегованими правами на зміну атрибута msDS-KeyCredentialLink цільового об'єкта.

## Зловживання

Зловживання Key Trust для об'єктів-комп'ютерів охоплює кроки, що виходять за межі отримання Ticket Granting Ticket (TGT) і NTLM hash. Серед варіантів:<sup>[[1]](#references)</sup>

1. Створення **RC4 silver ticket** для дій від імені привілейованих користувачів на потрібному host.
2. Використання TGT із **S4U2Self** для impersonation **привілейованих користувачів**, що потребує змінити Service Ticket, додавши service class до service name.

Важливою перевагою зловживання Key Trust є те, що воно обмежується приватним ключем, згенерованим зловмисником, не вимагає делегування до потенційно вразливих облікових записів і не потребує створення computer account, який може бути складно видалити.<sup>[[1]](#references)</sup>

## Інструменти

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker використовує DSInternals для маніпуляції `msDS-KeyCredentialLink` із C#. Whisker та його Python-аналог **pyWhisker** підтримують додавання, перелік, видалення й очищення key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Функції **Whisker**:

- **Add**: Генерує пару ключів і додає key credential.
- **List**: Відображає всі записи key credentials.
- **Remove**: Видаляє вказану key credential.
- **Clear**: Видаляє всі key credentials, що потенційно може порушити легітимне використання WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker переносить робочий процес у **UNIX-подібні системи** за допомогою Impacket і PyDSInternals, включно з операціями list/add/remove та імпортом/експортом JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray перераховує доменні об'єкти, щодо яких оператор має права, такі як `GenericWrite`/`GenericAll`, намагається широко додавати ключові облікові дані та містить режими очищення/рекурсії. Масове розповсюдження є руйнівним і помітним; використовуйте явні цілі та зберігайте кожен доданий DeviceID для точного видалення.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: зловживання зіставленням облікових записів через довіру до ключів для захоплення облікового запису](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - інструмент для захоплення облікових записів AD шляхом маніпулювання msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - інструмент для розповсюдження Shadow Credentials у домені](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - версія інструмента Shadow Credentials для Python](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
