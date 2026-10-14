# FZ - Infracrveno

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Za više informacija o tome kako funkcioniše infracrvena komunikacija, pogledajte:


{{#ref}}
../infrared.md
{{#endref}}

## IR prijemnik signala u Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero koristi demodulišući IR prijemnik za hvatanje signala uobičajenih IR daljinskih upravljača. Neki telefoni, uključujući određene modele Xiaomi, imaju IR predajnik, ali većina ne može da prima i dekodira signale daljinskih upravljača.<sup>[[1]](#references)</sup>

Infracrveni **prijemnik Flipper uređaja je prilično osetljiv**. Možete čak i da **uhvatite signal** dok se nalazite **negde između** daljinskog upravljača i televizora. Nije neophodno da daljinski upravljač bude usmeren direktno ka IR portu uređaja Flipper. To je korisno kada neko menja kanale stojeći blizu televizora, a vi i Flipper ste na izvesnoj udaljenosti.

Dekodiranje protokola obavlja se softverski. Prepoznati protokoli mogu da se sačuvaju kao dekodirane komande; nepodržani protokoli mogu da se snime i ponovo emituju kao sirovi vremenski podaci, u okviru ograničenja hardvera u pogledu noseće frekvencije i vremena.<sup>[[1]](#references)</sup>

## Radnje

### Univerzalni daljinski upravljači

Režim univerzalnog daljinskog upravljača uređaja Flipper Zero prolazi kroz poznate komande iz svoje infracrvene baze podataka za podržane televizore, audio-opremu, projektore i klima-uređaje. Nije garantovano da će upravljati svakim uređajem i treba ga koristiti samo sa opremom koju posedujete ili za čije testiranje imate ovlašćenje.<sup>[[1]](#references)</sup>

Dovoljno je da pritisnete dugme za napajanje u režimu Universal Remote i Flipper će **redom slati komande „Isključi“** za sve televizore koje poznaje: Sony, Samsung, Panasonic... i tako dalje. Kada televizor primi signal, reagovaće i isključiti se.

Ovakav brute-force postupak zahteva vreme. Što je rečnik veći, duže će trajati. Nije moguće saznati koji je tačno signal televizor prepoznao jer televizor ne šalje povratnu informaciju.

### Učenje novog daljinskog upravljača

Flipper Zero može da **uhvati infracrveni signal**. Ako prepozna protokol i komandu, čuva njihovu dekodiranu reprezentaciju; u suprotnom, može da sačuva sirove vremenske podatke za kasnije ponovno emitovanje.<sup>[[1]](#references)</sup>

## References

- [1] [Preuzimanje kontrole nad televizorima pomoću infracrvenog porta uređaja Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
