# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Базові Payloads

- **Простий список:** Просто список, що містить один запис у кожному рядку
- **Файл під час виконання:** Список, який зчитується під час виконання (не завантажується в пам'ять). Для підтримки великих списків.
- **Модифікація регістру:** Застосування змін до списку рядків (без змін, у нижній регістр, у ВЕРХНІЙ регістр, у форматі Proper name — з великої літери, решта — у нижньому регістрі, у форматі Proper Name — з великої літери, решта без змін).
- **Числа:** Генерування чисел від X до Y з кроком Z або у випадковому порядку.
- **Brute Forcer:** Набір символів, мінімальна та максимальна довжина.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload для виконання команд і отримання результату через DNS-запити до burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
