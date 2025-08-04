# Izrada prenosivog HID MaxiProx 125 kHz mobilnog klonera

{{#include ../../banners/hacktricks-training.md}}

## Cilj
Pretvoriti HID MaxiProx 5375 čitač dugog dometa sa napajanjem iz mreže u kloner bedževa koji se može koristiti na terenu, napajan baterijama, i koji tiho prikuplja proximity kartice tokom procena fizičke sigurnosti.

Konverzija koja se ovde pokriva zasniva se na istraživačkom serijalu TrustedSec-a “Let’s Clone a Cloner – Part 3: Putting It All Together” i kombinuje mehaničke, električne i RF aspekte tako da se konačni uređaj može staviti u ranac i odmah koristiti na terenu.

> [!warning]
> Manipulacija opremom koja se napaja iz mreže i litijum-jonskim baterijama može biti opasna. Proverite svaku vezu **pre** nego što energizujete krug i držite antene, koaksijalne kablove i uzemljenja tačno onako kako su bile u fabričkom dizajnu kako biste izbegli detuning čitača.

## Spisak materijala (BOM)

* HID MaxiProx 5375 čitač (ili bilo koji 12 V HID Prox® čitač dugog dometa)
* ESP RFID Tool v2.2 (ESP32-bazirani Wiegand sniffer/logger)
* USB-PD (Power-Delivery) okidač modul sposoban da pregovara 12 V @ ≥3 A
* 100 W USB-C power-bank (izlazi 12 V PD profil)
* 26 AWG silikonski izolovani povezni kabl – crvena/bela
* Panel-mount SPST prekidač (za beeper kill-switch)
* NKK AT4072 zaštita za prekidač / kapica otporna na nesreće
* Lemilica, lemni konac i pumpa za odlemljivanje
* ABS alate: ručna pila, nož, ravne i poluokrugle datoteke
* Svrdla 1/16″ (1.5 mm) i 1/8″ (3 mm)
* 3 M VHB dvostrana traka i Zip-ties

## 1. Power Sub-System

1. Odlemljivanje i uklanjanje fabričkog buck-converter dodatnog borda koji se koristi za generisanje 5 V za logički PCB.
2. Montirati USB-PD okidač pored ESP RFID Tool i usmeriti USB-C priključak okidača ka spoljašnjoj strani kućišta.
3. PD okidač pregovara 12 V iz power-banka i direktno ga dovodi do MaxiProx-a (čitač očekuje 10–14 V). Sekundarna 5 V pruga se uzima sa ESP borda za napajanje bilo kojih dodataka.
4. 100 W baterijski paket je postavljen ravno uz unutrašnji standoff tako da **nema** naponskih kablova prebačenih preko ferritne antene, čime se očuvava RF performansa.

## 2. Beeper Kill-Switch – Tiha operacija

1. Pronađite dva zvučna jastučića na logičkoj ploči MaxiProx-a.
2. Očistite *oba* jastučića, a zatim ponovo zalemite samo **negativni** jastučić.
3. Zalemite 26 AWG žice (bela = negativna, crvena = pozitivna) na jastučiće za beeper i usmerite ih kroz novo isečeni otvor do panel-mount SPST prekidača.
4. Kada je prekidač otvoren, krug za beeper je prekinut i čitač radi u potpunoj tišini – idealno za prikriveno prikupljanje bedževa.
5. Postavite NKK AT4072 opružnu zaštitu preko prekidača. Pažljivo proširite otvor pomoću ručne pile / datoteke dok se ne zaključa preko tela prekidača. Zaštita sprečava slučajno aktiviranje unutar ranca.

## 3. Kućište i mehanički rad

• Koristite ravne sekače, a zatim nož i datoteku da *uklonite* unutrašnji ABS “bump-out” tako da velika USB-C baterija leži ravno na standoff-u.
• Isecite dva paralelna kanala u zidu kućišta za USB-C kabl; ovo zaključava bateriju na mestu i eliminiše kretanje/vibracije.
• Napravite pravougaoni otvor za **napajanje** dugme baterije:
1. Zalepite papirni šablon preko lokacije.
2. Izbušite 1/16″ pilot rupe u sva četiri ugla.
3. Proširite sa svrdlom od 1/8″.
4. Povežite rupe pomoću ručne pile; završite ivice datotekom.
✱  Rotirajući Dremel je *izbegnut* – visoko brzi bit topi debeli ABS i ostavlja ružnu ivicu.

## 4. Konačna montaža

1. Ponovo instalirajte logičku ploču MaxiProx-a i ponovo zalemite SMA pigtail na uzemljeni jastučić PCB-a čitača.
2. Montirajte ESP RFID Tool i USB-PD okidač koristeći 3 M VHB.
3. Uredite sve žice sa zip-ties, držeći naponske vodove **daleko** od antene.
4. Stegnite šrafove kućišta dok se baterija lagano ne kompresuje; unutrašnja trenja sprečava pomeranje paketa kada se uređaj povuče nakon svakog očitavanja kartice.

## 5. Testovi dometa i štitnika

* Koristeći 125 kHz **Pupa** test karticu, prenosivi kloner je postigao dosledna očitavanja na **≈ 8 cm** u slobodnom vazduhu – identično radu sa napajanjem iz mreže.
* Postavljanjem čitača unutar metalne kutije za novac sa tankim zidovima (da simulira bankarsku recepciju) domet je smanjen na ≤ 2 cm, potvrđujući da značajne metalne kućišta deluju kao efikasni RF štitovi.

## Radni tok korišćenja

1. Napunite USB-C bateriju, povežite je i prebacite glavni prekidač za napajanje.
2. (Opcionalno) Otvorite zaštitu za beeper i omogućite zvučnu povratnu informaciju prilikom testiranja; zaključajte je pre prikrivenog korišćenja na terenu.
3. Prođite pored ciljanog nosioca bedža – MaxiProx će energizovati karticu, a ESP RFID Tool će zabeležiti Wiegand stream.
4. Prenesite zabeležene akreditive putem Wi-Fi ili USB-UART i ponovo reprodukujte/klonirajte po potrebi.

## Rešavanje problema

| Simptom | Verovatni uzrok | Rešenje |
|---------|-----------------|---------|
| Čitač se restartuje kada se kartica prikaže | PD okidač pregovarao 9 V umesto 12 V | Proverite jumpere okidača / pokušajte sa kablom višeg napajanja USB-C |
| Nema dometa očitavanja | Baterija ili žice leže *na vrhu* antene | Ponovo usmerite kablove i održavajte razmak od 2 cm oko ferritne petlje |
| Beeper i dalje zvoni | Prekidač povezan na pozitivni vod umesto na negativni | Premestite kill-switch da prekine **negativni** zvučni trag |

## Reference

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
