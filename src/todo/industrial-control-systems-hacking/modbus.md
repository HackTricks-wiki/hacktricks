# Протокол Modbus

{{#include ../../banners/hacktricks-training.md}}

## Вступ до Modbus

Modbus — це відкритий протокол прикладного рівня, широко реалізований у PLC, сенсорах, виконавчих механізмах та інших промислових пристроях. Його модель запит/відповідь надає доступ до котушок і регістрів через function codes. Тому під час security testing основну увагу приділяють несанкціонованому читанню/запису, спостереженню за трафіком, replay та небезпечній поведінці пристроїв, а не лише виявленню TCP-порту 502.<sup>[[1]](#references)</sup>

Багато розгортань і надалі використовують застаріле serial-обладнання, оскільки оновлення потребує простою, повторної сертифікації або заміни польових пристроїв. Традиційний Modbus не забезпечує ні конфіденційності, ні автентифікації вузлів; Modbus Security — це окремий профіль на основі TLS, що використовує сертифікати X.509 і TCP-порт 802. Оскільки специфікація є відкритою та може незалежно реалізовуватися різними виробниками, поведінка продуктів і підтримка optional functions відрізняються, тому їх слід fingerprint, а не припускати заздалегідь.<sup>[[1]](#references)[[2]](#references)</sup>

## Архітектура client-server

У сучасній термінології **client** ініціює транзакцію, а **server** повертає відповідь. У старішій документації використовуються терміни **master/slave**. Не плутайте цей прикладний зв’язок із SPI або I2C: це інші bus protocols.<sup>[[1]](#references)</sup>

## Serial- та Ethernet-транспорти

Ті самі дані прикладного рівня Modbus можуть передаватися через serial-варіанти (RTU або ASCII framing) і через Modbus TCP. Modbus TCP додає MBAP header і зазвичай використовує TCP-порт 502; serial RTU використовує компактне binary framing і CRC, тоді як serial ASCII представляє байти у вигляді hexadecimal characters і використовує LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Представлення даних

Модель даних складається з однобітових coils/discrete inputs і 16-бітових input/holding registers. Значення, що займають кілька регістрів, порядок байтів, масштабування та семантичне значення залежать від пристрою й мають бути підтверджені за register map виробника.<sup>[[1]](#references)</sup>

## Function codes

Function codes визначають такі операції, як читання coils (`0x01`), читання holding registers (`0x03`), запис одного coil/register (`0x05`/`0x06`) і запис кількох coils/registers (`0x0F`/`0x10`). Перехоплений write request може бути придатним для replay, якщо в розгортанні відсутні компенсувальна автентифікація або перевірки стану процесу. За наявності дозволеного фізичного доступу до довгих serial-ліній assessor також може безпосередньо перехоплювати або інжектити frames у wiring після визначення electrical interface, termination і безпечного способу підключення. Будь-яка з цих дій може вплинути на physical process, тому використовуйте lab або explicit operational authorization.<sup>[[1]](#references)[[3]](#references)</sup>

## Адресація

Serial-пристрої використовують unit address. Modbus TCP використовує IP-адресацію разом із Unit Identifier у MBAP header, що особливо важливо, коли TCP-to-serial gateway маршрутизує запити до downstream units. Посилання на регістри в документації продукту можуть бути one-based (`40001`), тоді як protocol addresses є zero-based, що часто спричиняє off-by-one errors.<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing містить перевірки transmission errors (CRC для RTU і LRC для ASCII), а TCP забезпечує звичайну transport checksum. Вони виявляють випадкове пошкодження даних, але не є cryptographic integrity або origin authentication.<sup>[[3]](#references)</sup>

Під час authorized assessment перевіряйте exposure, дозволені function codes, діапазони writable addresses, обробку exceptions, rate limits, а також те, чи обмежує network segmentation або Modbus-aware firewall клієнтів. До відповідних загроз належать passive disclosure, unauthorized command injection, replay, data forgery і denial of service. Узгоджуйте всі active tests із process owners, оскільки, на перший погляд, невеликі зміни регістрів можуть змінити physical process.

## References

- [1] [Modbus Organization — Специфікація протоколу прикладного рівня Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Протокол Modbus Security і посібники з реалізації](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Специфікація та посібник із реалізації Modbus через Serial Line V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
