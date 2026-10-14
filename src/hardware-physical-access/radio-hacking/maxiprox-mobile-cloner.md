# Izrada prenosivog HID MaxiProx 125 kHz mobilnog klonera

{{#include ../../banners/hacktricks-training.md}}

## Cilj
Prepraviti HID MaxiProx 5375 čitač velikog dometa od 125 kHz, napajan iz električne mreže, u kloner kartica na baterije za terensku upotrebu, koji neprimetno prikuplja proximity kartice tokom procena fizičke bezbednosti.

Ovde opisana prepravka zasniva se na istraživačkoj seriji TrustedSec „Hajde da kloniramo kloner – 3. deo: Sastavljanje celine“ i obuhvata mehaničke, električne i RF aspekte kako bi se završni uređaj mogao spakovati u ranac i odmah koristiti na terenu.<sup>[[1]](#references)</sup>

> [!warning]
> Rad sa opremom napajanom iz električne mreže i litijum-jonskim power bank uređajima može biti opasan. Proverite svaki spoj **pre** nego što uključite kolo i ostavite antene, koaksijalni kabl i uzemljivačke ploče tačno onako kako su postavljeni u fabričkom dizajnu da biste izbegli detjuniranje čitača.

## Spisak materijala (BOM)

* HID MaxiProx 5375 čitač (ili bilo koji HID Prox® čitač velikog dometa od 12 V)
* ESP RFID Tool v2.2 (Wiegand sniffer/logger zasnovan na ESP32)
* USB-PD (Power-Delivery) trigger modul koji može da pregovara 12 V pri ≥3 A
* USB-C power bank od 100 W (sa izlaznim 12 V PD profilom)
* Silikonski izolovana žica 26 AWG – crvena/bela
* Panelni SPST prekidač (za beeper kill-switch)
* NKK AT4072 zaštitni poklopac prekidača / poklopac protiv slučajnog aktiviranja
* Lemilica, pletenica za odlemljivanje i pumpica za odlemljivanje
* Ručni alati za ABS: testerica, skalpel, ravna i poluokrugla turpija
* Burgije 1/16″ (1,5 mm) i 1/8″ (3 mm)
* Dvostrana traka 3 M VHB i vezice

## 1. Podsistem za napajanje

1. Odlemiti i ukloniti fabričku buck-converter ćerku ploču koja obezbeđuje 5 V za logičku PCB.
2. Postaviti USB-PD trigger pored ESP RFID Tool uređaja i provući USB-C priključak triggera do spoljne strane kućišta.
3. PD trigger pregovara 12 V sa power bank uređajem i direktno ih dovodi do MaxiProx-a (čitač po specifikaciji očekuje 10–14 V). Sekundarna 5 V grana uzima se sa ESP ploče za napajanje dodatne opreme.
4. Baterija od 100 W postavlja se poravnato uz unutrašnji odstojnik, tako da **nema** kablova za napajanje položenih preko feritne antene, čime se čuvaju RF performanse.

## 2. Beeper kill-switch – nečujan rad

1. Pronaći dve kontaktne pločice zvučnika na MaxiProx logičkoj ploči.
2. Očistiti *obe* pločice pletenicom za odlemljivanje, pa ponovo zalemiti samo **negativnu** pločicu.
3. Zalemiti žice 26 AWG (bela = negativna, crvena = pozitivna) na kontaktne pločice beepera i provući ih kroz novonapravljeni prorez do panelnog SPST prekidača.
4. Kada je prekidač otvoren, kolo beepera je prekinuto i čitač radi potpuno nečujno – idealno za neprimetno prikupljanje kartica.
5. Postaviti opružni sigurnosni poklopac NKK AT4072 preko preklopnog prekidača. Pažljivo proširiti otvor testericom/turpijom dok ne nalegne preko tela prekidača. Poklopac sprečava slučajno aktiviranje u rancu.

## 3. Kućište i mehanički radovi

• Ravnim kleštima za sečenje, a zatim nožem i turpijom *ukloniti* unutrašnje ABS „izbočenje“ kako bi velika USB-C baterija ravno nalegla na odstojnik.
• Urezati dva paralelna kanala u zid kućišta za USB-C kabl; tako se baterija učvršćuje i sprečava pomeranje/vibriranje.
• Napraviti pravougaoni otvor za dugme za **napajanje** baterije:
  1. Zalepiti papirni šablon preko mesta.
  2. Izbušiti pilot-rupe burgijom 1/16″ u sva četiri ugla.
  3. Proširiti ih burgijom 1/8″.
  4. Spojiti rupe testericom; završno obraditi ivice turpijom.  
  ✱  *Izbegnuta je* rotaciona Dremel alatka – burgija velike brzine topi debeli ABS i ostavlja ružnu ivicu.

## 4. Završno sklapanje

1. Ponovo postaviti MaxiProx logičku ploču i zalemiti SMA pigtail na uzemljivačku pločicu na PCB-u čitača.
2. Pričvrstiti ESP RFID Tool i USB-PD trigger trakom 3 M VHB.
3. Učvrstiti sve žice vezicama i držati provodnike za napajanje **daleko** od antenske petlje.
4. Zategnuti zavrtnje kućišta tako da se baterija blago pritisne; unutrašnje trenje sprečava pomeranje pakovanja kada se uređaj trzne posle svakog očitavanja kartice.

## 5. Testovi dometa i oklopljenja

* Sa testnom karticom **Pupa** od 125 kHz, prenosivi kloner je ostvario dosledna očitavanja na **≈ 8 cm** na otvorenom – isto kao pri napajanju iz električne mreže.<sup>[[1]](#references)</sup>
* Postavljanje čitača u metalnu kasetu sa tankim zidovima (kao simulacija stola u holu banke) smanjilo je domet na ≤ 2 cm, što potvrđuje da kućišta sa značajnom količinom metala efikasno štite od RF signala.<sup>[[1]](#references)</sup>

## Tok upotrebe

1. Napuniti USB-C bateriju, povezati je i uključiti glavni prekidač.
2. (Opcionalno) Otvoriti zaštitni poklopac beepera i uključiti zvučnu povratnu informaciju tokom testiranja na radnom stolu; zaključati ga pre neprimetne terenske upotrebe.
3. Proći pored osobe koja nosi ciljnu karticu – MaxiProx će aktivirati karticu, a ESP RFID Tool će snimiti Wiegand tok.
4. Izvući prikupljene pristupne podatke putem Wi-Fi-ja ili USB-UART-a i po potrebi ih ponovo emitovati/klonirati.

## Rešavanje problema

| Simptom | Verovatan uzrok | Rešenje |
|---------|--------------|------|
| Čitač se ponovo pokreće kada se prinese kartica | PD trigger je pregovarao 9 V umesto 12 V | Proveriti džampere na triggeru / probati USB-C kabl veće snage |
| Nema dometa očitavanja | Baterija ili žice se nalaze *iznad* antene | Premestiti kablove i ostaviti 2 cm razmaka oko feritne petlje |
| Beeper i dalje pišti | Prekidač je povezan na pozitivni umesto na negativni vod | Premestiti kill-switch tako da prekida **negativnu** liniju zvučnika |

## References

- [1] [Hajde da kloniramo kloner – 3. deo (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}