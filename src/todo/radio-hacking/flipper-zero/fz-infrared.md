# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Za više informacija o tome kako funkcioniše infracrveno, proverite:

{{#ref}}
../infrared.md
{{#endref}}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper koristi digitalni IR prijemnik TSOP, koji **omogućava presretanje signala sa IR daljinskih upravljača**. Postoje neki **smartfoni** poput Xiaomija, koji takođe imaju IR port, ali imajte na umu da **većina njih može samo da prenosi** signale i **nije u stanju da ih primi**.

Flipperov infracrveni **prijemnik je prilično osetljiv**. Možete čak i **uhvatiti signal** dok se nalazite **negde između** daljinskog upravljača i TV-a. Usmeravanje daljinskog upravljača direktno na Flipperov IR port nije neophodno. Ovo je korisno kada neko menja kanale dok stoji blizu TV-a, a i vi i Flipper ste na određenoj udaljenosti.

Kako se **dekodiranje infracrvenog** signala dešava na **softverskoj** strani, Flipper Zero potencijalno podržava **prijem i prenos bilo kojih IR kodova daljinskog upravljača**. U slučaju **nepoznatih** protokola koji nisu mogli biti prepoznati - on **snima i reprodukuje** sirovi signal tačno onako kako je primljen.

## Actions

### Universal Remotes

Flipper Zero može se koristiti kao **univerzalni daljinski upravljač za kontrolu bilo kog TV-a, klima uređaja ili medijskog centra**. U ovom režimu, Flipper **bruteforcuje** sve **poznate kodove** svih podržanih proizvođača **prema rečniku sa SD kartice**. Nije potrebno odabrati određeni daljinski upravljač da biste isključili TV u restoranu.

Dovoljno je pritisnuti dugme za napajanje u režimu Univerzalnog daljinskog upravljača, i Flipper će **uzastopno slati "Power Off"** komande svih TV-a koje poznaje: Sony, Samsung, Panasonic... i tako dalje. Kada TV primi svoj signal, reagovaće i isključiti se.

Takav bruteforce zahteva vreme. Što je veći rečnik, duže će trajati da se završi. Nemoguće je saznati koji signal je tačno TV prepoznao jer nema povratne informacije od TV-a.

### Learn New Remote

Moguće je **uhvatiti infracrveni signal** sa Flipper Zero. Ako **pronađe signal u bazi podataka**, Flipper će automatski **znati koji je to uređaj** i omogućiti vam da komunicirate s njim.\
Ako ne, Flipper može **sačuvati** **signal** i omogućiti vam da ga **ponovo reprodukujete**.

## References

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
