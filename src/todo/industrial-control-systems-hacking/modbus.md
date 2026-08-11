# Protokol Modbus

{{#include ../../banners/hacktricks-training.md}}

## Uvod u Modbus

Modbus je otvoreni protokol aplikacionog sloja koji se široko implementira u PLC-ovima, senzorima, aktuatorima i drugim industrijskim uređajima. Njegov model zahtev/odgovor izlaže coils i registre putem function codes. Zbog toga se bezbednosno testiranje fokusira na neovlašćena čitanja/upisivanja, posmatranje saobraćaja, replay i nebezbedno ponašanje uređaja — a ne samo na pronalaženje TCP porta 502.<sup>[[1]](#references)</sup>

Mnoge implementacije zadržavaju staru serijsku opremu zato što nadogradnje zahtevaju prekid rada, ponovnu sertifikaciju ili zamenu terenskih uređaja. Tradicionalni Modbus ne pruža ni poverljivost ni autentikaciju ravnopravnih učesnika; Modbus Security je zaseban profil zasnovan na TLS-u, koji koristi X.509 sertifikate i TCP port 802. Pošto je specifikacija javna i može se nezavisno implementirati, ponašanje proizvođača i podrška za opcione funkcije variraju i treba ih fingerprintovati, a ne pretpostavljati.<sup>[[1]](#references)[[2]](#references)</sup>

## Arhitektura klijent-server

U aktuelnoj terminologiji, **klijent** pokreće transakciju, a **server** vraća odgovor. Starija dokumentacija koristi termine **master/slave**. Ovaj odnos na nivou aplikacije ne treba mešati sa SPI ili I2C protokolima: to su različiti bus protokoli.<sup>[[1]](#references)</sup>

## Serijski i Ethernet transporti

Isti Modbus aplikacioni podaci mogu se prenositi serijskim varijantama (RTU ili ASCII framing) i putem Modbus TCP-a. Modbus TCP dodaje MBAP header i obično koristi TCP port 502; serijski RTU koristi kompaktni binarni framing i CRC, dok serijski ASCII predstavlja bajtove kao heksadecimalne karaktere i koristi LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Predstavljanje podataka

Model podataka sastoji se od jednobitnih coils/discrete inputs i 16-bitnih input/holding registara. Vrednosti koje zauzimaju više registara, redosled bajtova, skaliranje i semantičko značenje specifični su za uređaj i moraju se potvrditi u mapi registara proizvođača.<sup>[[1]](#references)</sup>

## Function codes

Function codes biraju operacije kao što su čitanje coils (`0x01`), čitanje holding registara (`0x03`), upisivanje jednog coil/registera (`0x05`/`0x06`) i upisivanje više coils/registara (`0x0F`/`0x10`). Uhvaćeni zahtev za upisivanje može moći da se replay-uje kada implementacija nema kompenzujuću autentikaciju ili provere stanja procesa. Uz autorizovani fizički pristup dugim serijskim vodovima, assessor takođe može da uhvati ili ubaci frame-ove direktno na ožičenje nakon utvrđivanja električnog interfejsa, terminacije i bezbednog načina povezivanja. Svaka od ovih radnji može uticati na fizički proces, zato koristite lab ili izričito operativno odobrenje.<sup>[[1]](#references)[[3]](#references)</sup>

## Adresiranje

Serijski uređaji koriste unit adresu. Modbus TCP koristi IP adresiranje zajedno sa Unit Identifier-om u MBAP header-u, što je naročito relevantno kada TCP-to-serial gateway usmerava zahteve ka nizvodnim jedinicama. Reference registara prikazane u dokumentaciji proizvoda mogu biti zasnovane na indeksiranju od jedan (`40001`), dok su protokolarne adrese zasnovane na indeksiranju od nule, što je čest izvor off-by-one grešaka.<sup>[[1]](#references)[[3]](#references)</sup>

Serijski framing uključuje provere grešaka u prenosu (CRC za RTU i LRC za ASCII), a TCP obezbeđuje svoj uobičajeni transportni checksum. Oni otkrivaju slučajnu korupciju; ne predstavljaju kriptografski integritet niti autentikaciju porekla.<sup>[[3]](#references)</sup>

Tokom autorizovane procene testirajte izloženost, dozvoljene function codes, opsege upisivih adresa, obradu izuzetaka, rate limits i da li network segmentation ili Modbus-aware firewall ograničava klijente. Relevantne pretnje uključuju pasivno otkrivanje podataka, neovlašćenu command injection, replay, falsifikovanje podataka i denial of service. Koordinirajte sva aktivna testiranja sa vlasnicima procesa, jer naizgled male promene registara mogu izmeniti fizički proces.

## References

- [1] [Modbus Organization — Specifikacija Modbus aplikacionog protokola V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security protokol i vodiči za implementaciju](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Specifikacija i vodič za implementaciju Modbus-a preko serijske linije V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
