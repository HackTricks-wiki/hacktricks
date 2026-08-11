# FZ - Infracrveno

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Za više informacija o tome kako funkcioniše Infracrveno, pogledajte:


{{#ref}}
../infrared.md
{{#endref}}

## IR prijemnik signala u Flipper Zero uređaju <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero koristi demodulišući IR prijemnik za hvatanje signala sa uobičajenih IR daljinskih upravljača. Neki telefoni, uključujući određene Xiaomi modele, imaju IR predajnik, ali većina ne može da prima i dekoduje signale daljinskog upravljača.<sup>[[1]](#references)</sup>

Flipper infracrveni **prijemnik je veoma osetljiv**. Možete čak **uhvatiti signal** dok se nalazite **negde između** daljinskog upravljača i televizora. Nije neophodno usmeriti daljinski upravljač direktno ka IR portu Flipper uređaja. Ovo je korisno kada neko menja kanale dok stoji blizu televizora, a vi i Flipper ste udaljeni od njega.

Dekodiranje protokola obavlja se u softveru. Prepoznati protokoli mogu se sačuvati kao dekodovane komande; nepodržani protokoli mogu se uhvatiti i reprodukovati kao raw podaci o vremenskom rasporedu, u okviru ograničenja hardvera u pogledu noseće frekvencije i vremenskog rasporeda.<sup>[[1]](#references)</sup>

## Radnje

### Univerzalni daljinski upravljači

Režim univerzalnog daljinskog upravljača Flipper Zero uređaja prolazi kroz poznate komande iz svoje infracrvene baze podataka za podržane televizore, audio-opremu, projektore i klima-uređaje. Nije garantovano da će upravljati svakim uređajem i treba ga koristiti samo na opremi koja je u vašem vlasništvu ili za čije testiranje imate ovlašćenje.<sup>[[1]](#references)</sup>

Dovoljno je pritisnuti dugme za napajanje u režimu Universal Remote i Flipper će **uzastopno slati komande "Power Off"** za sve televizore koje poznaje: Sony, Samsung, Panasonic... i tako dalje. Kada televizor primi njegov signal, reagovaće i isključiće se.

Takav brute-force zahteva vreme. Što je rečnik veći, duže će trajati njegovo izvršavanje. Nije moguće saznati koji je signal televizor tačno prepoznao, jer televizor ne pruža povratne informacije.

### Učenje novog daljinskog upravljača

Flipper Zero može da **uhvati infracrveni signal**. Ako prepozna protokol i komandu, čuva dekodovanu reprezentaciju; u suprotnom, može sačuvati raw podatke o vremenskom rasporedu za kasniju reprodukciju.<sup>[[1]](#references)</sup>

## References

- [1] [Preuzimanje kontrole nad televizorima pomoću infracrvenog porta Flipper Zero uređaja](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
