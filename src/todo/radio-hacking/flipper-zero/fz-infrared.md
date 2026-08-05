# FZ - Infracrveni

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Za više informacija o tome kako infracrveni signal funkcioniše, pogledajte:


{{#ref}}
../infrared.md
{{#endref}}

## IR prijemnik signala u Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper koristi digitalni IR prijemnik signala TSOP, koji **omogućava presretanje signala sa IR daljinskih upravljača**. Postoje neki **pametni telefoni**, kao što je Xiaomi, koji takođe imaju IR port, ali imajte na umu da **većina njih može samo da šalje** signale i **nije u mogućnosti da ih prima**.<sup>[[1]](#references)</sup>

Flipperov infracrveni **prijemnik je veoma osetljiv**. Signal možete čak **uhvatiti** dok se nalazite **negde između** daljinskog upravljača i televizora. Nije neophodno usmeriti daljinski upravljač direktno ka Flipperovom IR portu. Ovo je korisno kada neko menja kanale dok stoji blizu televizora, a vi i Flipper ste udaljeni od njega.

Pošto se **dekodiranje infracrvenog** signala odvija na **softverskoj** strani, Flipper Zero potencijalno podržava **prijem i slanje bilo kojih kodova IR daljinskih upravljača**. U slučaju **nepoznatih** protokola koji nisu mogli da budu prepoznati, on **snima i reprodukuje** sirovi signal tačno onako kako je primljen.<sup>[[1]](#references)</sup>

## Radnje

### Univerzalni daljinski upravljači

Flipper Zero se može koristiti kao **univerzalni daljinski upravljač za kontrolu bilo kog televizora, klima-uređaja ili media centra**. U ovom režimu, Flipper **bruteforces** sve **poznate kodove** svih podržanih proizvođača **prema rečniku sa SD kartice**. Nije potrebno da izaberete određeni daljinski upravljač da biste isključili televizor u restoranu.<sup>[[1]](#references)</sup>

Dovoljno je pritisnuti dugme za napajanje u režimu Universal Remote i Flipper će **uzastopno slati komande "Power Off"** svih televizora koje poznaje: Sony, Samsung, Panasonic... i tako dalje. Kada televizor primi njegov signal, reagovaće i isključiti se.

Ovakav brute-force zahteva vreme. Što je rečnik veći, duže će trajati završetak procesa. Nije moguće saznati koji je signal televizor tačno prepoznao, pošto televizor ne daje povratne informacije.

### Učenje novog daljinskog upravljača

Moguće je **uhvatiti infracrveni signal** pomoću Flipper Zero uređaja. Ako **pronađe signal u bazi podataka**, Flipper će automatski **znati o kom uređaju je reč** i omogućiće vam interakciju sa njim.\
Ako ga ne pronađe, Flipper može **sačuvati** **signal** i omogućiti vam da ga **ponovo reprodukujete**.<sup>[[1]](#references)</sup>

## Reference

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
