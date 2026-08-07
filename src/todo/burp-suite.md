# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Osnovni Payloads

- **Simple List:** Samo lista koja sadrži jednu stavku u svakom redu
- **Runtime File:** Lista koja se čita tokom izvršavanja (ne učitava se u memoriju). Za podršku velikim listama.
- **Case Modification:** Primena izmena na listu stringova (bez izmena, mala slova, VELIKA SLOVA, Proper name - prvo slovo veliko, a ostatak mala slova-, Proper Name -prvo slovo veliko, a ostatak ostaje isti-.
- **Numbers:** Generisanje brojeva od X do Y koristeći korak Z ili nasumično.
- **Brute Forcer:** Skup karaktera, min. i maks. dužina.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload za izvršavanje komandi i preuzimanje izlaza putem DNS zahteva ka burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
