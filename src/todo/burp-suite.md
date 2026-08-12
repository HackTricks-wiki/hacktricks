# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Типи payload для Intruder

Burp Intruder містить такі вбудовані генератори та перетворення payload:<sup>[[1]](#references)</sup>

- **Simple list:** Використовує налаштований список рядків як payload.
- **Runtime file:** Зчитує один payload на рядок під час виконання. Це корисно для великих списків, оскільки Burp не завантажує весь файл у пам'ять.
- **Case modification:** Генерує початкове значення, форми в нижньому та верхньому регістрах, `Propername` (перша літера у верхньому регістрі, решта — у нижньому) або `ProperName` (перша літера у верхньому регістрі, решта символів без змін). Burp відкидає дублікати результатів.
- **Numbers:** Генерує послідовні або випадкові числа в межах налаштованого діапазону.
- **Brute forcer:** Генерує всі перестановки для вибраного набору символів і мінімальної/максимальної довжини.

## Розширення та супутні інструменти

- **Collabfiltrator** генерує payload, які виконують команди та ексфільтрують їхній результат через DNS-запити до Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** експортує результати Burp для використання в інших процесах підготовки звітів.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** перетворює HTTP-запити на скрипти кількома мовами.<sup>[[4]](#references)</sup>

## References

- [1] [Документація PortSwigger - типи payload Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
