# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#3f17" id="3f17"></a>

**Перегляньте оригінальну публікацію, щоб дізнатися [всю інформацію про цю техніку](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Коротко: контроль над **`msDS-KeyCredentialLink`** користувача або комп’ютера може дозволити атакувальнику додати облікові дані ключа, автентифікуватися як цей об’єкт за допомогою PKINIT і — якщо KDC та обліковий запис підтримують необхідні потоки — використати отриманий квиток із `S4U2Self`/user-to-user, щоб отримати NT-хеш об’єкта.<sup>[[1]](#references)</sup>

У публікації описано метод налаштування **облікових даних автентифікації на основі відкритого та закритого ключів** для отримання унікального **Service Ticket**, що містить NTLM-хеш цілі. Цей процес використовує зашифрований NTLM_SUPPLEMENTAL_CREDENTIAL у Privilege Attribute Certificate (PAC), який можна розшифрувати.<sup>[[1]](#references)</sup>

### Вимоги

Для застосування цієї техніки мають бути виконані певні умови:<sup>[[1]](#references)</sup>

- Потрібен принаймні один контролер домену Windows Server 2016.
- На контролері домену має бути встановлений цифровий сертифікат автентифікації сервера.
- Схема каталогу має містити `msDS-KeyCredentialLink`; практичними вимогами до платформи, описаними в дослідженні, є контролер домену Windows Server 2016 або новішої версії та сертифікат із підтримкою PKINIT на KDC. Перевірте схему домену та версії його контролерів, а не припускайте, що можливість експлуатації визначається лише рівнем функціональності домену.
- Потрібен обліковий запис із делегованими правами на зміну атрибута msDS-KeyCredentialLink цільового об’єкта.

## Зловживання

Зловживання Key Trust для комп’ютерних об’єктів охоплює кроки, що виходять за межі отримання Ticket Granting Ticket (TGT) і NTLM-хешу. Серед можливих дій:<sup>[[1]](#references)</sup>

1. Створити **RC4 silver ticket**, щоб діяти як привілейовані користувачі на потрібному хості.
2. Використати TGT із **S4U2Self** для імперсонації **привілейованих користувачів**; для цього потрібно змінити Service Ticket, додавши клас служби до імені служби.

Важлива перевага зловживання Key Trust полягає в тому, що воно обмежується згенерованим атакувальником закритим ключем, не вимагає делегування потенційно вразливим обліковим записам і створення облікового запису комп’ютера, який може бути складно видалити.<sup>[[1]](#references)</sup>

## Інструменти

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker використовує DSInternals для роботи з `msDS-KeyCredentialLink` із C#. Whisker і його аналог для Python **pyWhisker** підтримують додавання, перегляд, видалення та очищення облікових даних ключів.<sup>[[2]](#references)[[4]](#references)</sup>

Функції **Whisker**:

- **Add**: генерує пару ключів і додає облікові дані ключа.
- **List**: відображає всі записи облікових даних ключів.
- **Remove**: видаляє вказані облікові дані ключа.
- **Clear**: видаляє всі облікові дані ключів, що може порушити роботу легітимного WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker переносить workflow на **UNIX-подібні системи** за допомогою Impacket і PyDSInternals, зокрема підтримує операції зі списками, додаванням і видаленням, а також імпортом/експортом JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray перераховує об’єкти домену, над якими оператор має права, як-от `GenericWrite`/`GenericAll`, намагається масово додати облікові дані ключів і підтримує режими очищення/рекурсії. Масове розпилення є деструктивним і помітним; використовуйте конкретні цілі та зберігайте кожен доданий DeviceID, щоб точно його видалити.<sup>[[3]](#references)</sup>

ADWS може передавати запис облікових даних ключа, якщо прямий LDAP фільтрується. Див. [робочий процес SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: зловживання зіставленням облікових записів на основі довіри до ключа для захоплення облікового запису](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker — інструмент для захоплення облікових записів AD через маніпуляції з msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray — інструмент для розпилення Shadow Credentials у домені](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker — версія інструмента Shadow Credentials для Python](https://github.com/ShutdownRepo/pywhisker)
- [5] [Вікі SOAPy — Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
