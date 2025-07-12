# Protokol Modbus

{{#include ../../banners/hacktricks-training.md}}

## Uvod u Modbus Protokol

Protokol Modbus je široko korišćen protokol u industrijskoj automatizaciji i kontrolnim sistemima. Modbus omogućava komunikaciju između različitih uređaja kao što su programabilni logički kontroleri (PLC), senzori, aktuatori i drugi industrijski uređaji. Razumevanje Modbus protokola je od suštinskog značaja, jer je ovo jedini najviše korišćen komunikacioni protokol u ICS-u i ima mnogo potencijalnih površina za napade, kao što su prisluškivanje i čak injektovanje komandi u PLC-e.

Ovde su koncepti navedeni tačkasto, pružajući kontekst protokola i njegovog načina rada. Najveći izazov u bezbednosti ICS sistema je trošak implementacije i nadogradnje. Ovi protokoli i standardi su dizajnirani početkom 80-ih i 90-ih godina, a i dalje su široko korišćeni. Pošto industrija ima mnogo uređaja i konekcija, nadogradnja uređaja je veoma teška, što daje prednost hakerima u radu sa zastarelim protokolima. Napadi na Modbus su praktično neizbežni, jer će se koristiti bez nadogradnje, a njegova operacija je kritična za industriju.

## Klijent-Server Arhitektura

Modbus protokol se obično koristi u Klijent-Server arhitekturi gde master uređaj (klijent) inicira komunikaciju sa jednim ili više slave uređaja (servera). Ovo se takođe naziva Master-Slave arhitektura, koja se široko koristi u elektronici i IoT-u sa SPI, I2C, itd.

## Serijske i Ethernet Verzije

Modbus protokol je dizajniran za serijsku komunikaciju kao i Ethernet komunikaciju. Serijska komunikacija se široko koristi u nasleđenim sistemima, dok moderni uređaji podržavaju Ethernet koji nudi visoke brzine prenosa podataka i više je pogodan za moderne industrijske mreže.

## Predstavljanje Podataka

Podaci se prenose u Modbus protokolu kao ASCII ili Binarni, iako se binarni format koristi zbog svoje kompatibilnosti sa starijim uređajima.

## Funkcijski Kodovi

ModBus protokol radi sa prenosom specifičnih funkcijskih kodova koji se koriste za upravljanje PLC-ima i raznim kontrolnim uređajima. Ovaj deo je važan za razumevanje, jer se napadi ponovnog slanja mogu izvršiti ponovnim slanjem funkcijskih kodova. Nasleđeni uređaji ne podržavaju nikakvu enkripciju tokom prenosa podataka i obično imaju duge žice koje ih povezuju, što rezultira manipulacijom ovih žica i hvatanjem/injektovanim podacima.

## Adresiranje Modbus-a

Svaki uređaj u mreži ima jedinstvenu adresu koja je suštinska za komunikaciju između uređaja. Protokoli kao što su Modbus RTU, Modbus TCP, itd. se koriste za implementaciju adresiranja i služe kao transportni sloj za prenos podataka. Podaci koji se prenose su u formatu Modbus protokola koji sadrži poruku.

Pored toga, Modbus takođe implementira provere grešaka kako bi osigurao integritet prenetih podataka. Ali najvažnije, Modbus je otvoreni standard i svako može da ga implementira u svoje uređaje. Ovo je omogućilo da ovaj protokol postane globalni standard i da se široko koristi u industriji automatizacije.

Zbog svoje široke upotrebe i nedostatka nadogradnji, napad na Modbus pruža značajnu prednost sa svojom površinom napada. ICS je veoma zavistan od komunikacije između uređaja i svaki napad na njih može biti opasan za rad industrijskih sistema. Napadi poput ponovnog slanja, injektovanja podataka, prisluškivanja podataka i curenja, uskraćivanja usluga, falsifikovanja podataka, itd. mogu se izvršiti ako je sredstvo prenosa identifikovano od strane napadača.

{{#include ../../banners/hacktricks-training.md}}
