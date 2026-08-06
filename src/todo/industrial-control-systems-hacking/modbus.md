# Modbus protokol

{{#include ../../banners/hacktricks-training.md}}

## Uvod u Modbus protokol

Modbus protokol je široko korišćen protokol u industrijskoj automatizaciji i kontrolnim sistemima. Modbus omogućava komunikaciju između različitih uređaja, kao što su programabilni logički kontroleri (PLCs), senzori, aktuatori i drugi industrijski uređaji. Razumevanje Modbus protokola je od suštinskog značaja, pošto je to najkorišćeniji komunikacioni protokol u ICS-u i ima veliku potencijalnu attack surface za sniffing, pa čak i injection komandi u PLCs.

Ovde su koncepti navedeni po tačkama, uz pružanje konteksta o protokolu i njegovom načinu rada. Najveći izazov u bezbednosti ICS sistema predstavljaju troškovi implementacije i nadogradnje. Ovi protokoli i standardi dizajnirani su početkom 80-ih i 90-ih godina, a i dalje se široko koriste. Pošto industrija ima veliki broj uređaja i veza, nadogradnja uređaja je veoma teška, što hakerima daje prednost u radu sa zastarelim protokolima. Attacks na Modbus su praktično neizbežni, jer će se koristiti bez nadogradnje ukoliko je njegov rad od kritičnog značaja za industriju.

## Client-Server arhitektura

Modbus protokol se obično koristi u Client-Server arhitekturi, gde master uređaj (client) pokreće komunikaciju sa jednim ili više slave uređaja (servera). Ovo se takođe naziva Master-Slave arhitektura, koja se široko koristi u elektronici i IoT-u sa SPI, I2C itd.

## Serijske i Etherent verzije

Modbus protokol je dizajniran i za serijsku komunikaciju i za Ethernet komunikaciju. Serijska komunikacija se široko koristi u legacy sistemima, dok moderni uređaji podržavaju Ethernet, koji nudi veće brzine prenosa podataka i pogodniji je za moderne industrijske mreže.

## Predstavljanje podataka

Podaci se u Modbus protokolu prenose kao ASCII ili Binary, iako se Binary format koristi zbog svoje kompaktibilnosti sa starijim uređajima.

## Function Codes

ModBus protokol radi sa prenosom specifičnih function codes koji se koriste za upravljanje PLCs i različitim kontrolnim uređajima. Ovaj deo je važno razumeti, jer se replay attacks mogu izvesti ponovnim slanjem function codes. Legacy uređaji ne podržavaju nikakvu enkripciju prenosa podataka i obično imaju dugačke kablove koji ih povezuju, što omogućava tampering nad ovim kablovima, kao i hvatanje i injection podataka.

## Adresiranje u Modbusu

Svaki uređaj u mreži ima jedinstvenu adresu, koja je neophodna za komunikaciju između uređaja. Protokoli kao što su Modbus RTU, Modbus TCP itd. koriste se za implementaciju adresiranja i služe kao transportni sloj za prenos podataka. Podaci koji se prenose nalaze se u formatu Modbus protokola, koji sadrži poruku.

Pored toga, Modbus implementira i provere grešaka kako bi se obezbedio integritet prenetih podataka. Ali najvažnije je to što je Modbus Open Standard i svako može da ga implementira u svojim uređajima. Zbog toga je ovaj protokol postao globalni standard i široko je rasprostranjen u industrijskoj automatizaciji.

Zbog široke upotrebe i nedostatka nadogradnji, napad na Modbus pruža značajnu prednost zahvaljujući njegovoj attack surface. ICS u velikoj meri zavisi od komunikacije između uređaja, a svi napadi izvedeni nad njima mogu biti opasni po rad industrijskih sistema. Attacks kao što su replay, data injection, data sniffing i leak, Denial of Service, data forgery itd. mogu se izvesti ako napadač identifikuje medijum prenosa.

{{#include ../../banners/hacktricks-training.md}}
