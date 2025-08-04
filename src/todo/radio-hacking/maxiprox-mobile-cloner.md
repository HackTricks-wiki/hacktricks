# Kujenga MaxiProx 125 kHz Mobile Cloner ya HID Inayobebeka

{{#include ../../banners/hacktricks-training.md}}

## Lengo
Geuza HID MaxiProx 5375 yenye nguvu ya umeme kuwa cloner ya vitambulisho inayoweza kutumika uwanjani, inayotumia betri, ambayo inakusanya kadi za karibu kimya kimya wakati wa tathmini za usalama wa kimwili.

Mabadiliko yaliyofunikwa hapa yanategemea mfululizo wa utafiti wa TrustedSec "Tujenge Cloner – Sehemu ya 3: Kuunganisha Yote Pamoja" na yanachanganya mambo ya mitambo, umeme na RF ili kifaa cha mwisho kiweze kutupwa kwenye mkoba na kutumika mara moja kwenye tovuti.

> [!warning]
> Kuingilia kati vifaa vinavyotumia umeme na benki za nguvu za Lithium-ion kunaweza kuwa hatari. Thibitisha kila muunganisho **kabla** ya kuanzisha mzunguko na uweke antena, coax na ndege za ardhi kama zilivyokuwa katika muundo wa kiwanda ili kuepuka kuathiri utendaji wa msomaji.

## Orodha ya Vifaa (BOM)

* HID MaxiProx 5375 msomaji (au msomaji wowote wa HID Prox® wa umbali mrefu wa 12 V)
* ESP RFID Tool v2.2 (sniffer/logger ya ESP32 inayotumia Wiegand)
* Moduli ya trigger ya USB-PD (Power-Delivery) inayoweza kujadiliana 12 V @ ≥3 A
* Benki ya nguvu ya USB-C ya 100 W (inatoa 12 V PD profile)
* Waya ya kuunganisha ya silicone ya 26 AWG – nyekundu/nyekundu
* Switch ya SPST ya paneli (kwa beeper kill-switch)
* Kifuniko cha NKK AT4072 / kifuniko kisichoweza kuharibika
* Chuma cha kusafisha, wick ya solder & pampu ya kuondoa solder
* Zana za mkono zenye kiwango cha ABS: saw ya coping, kisu cha matumizi, faili za gorofa na nusu-duara
* Vifaa vya kuchimba 1/16″ (1.5 mm) na 1/8″ (3 mm)
* Kanda ya pande mbili ya 3 M VHB & Zip-ties

## 1. Mfumo wa Nguvu

1. Ondoa solder na kuondoa bodi ya buck-converter ya kiwanda iliyotumika kuzalisha 5 V kwa PCB ya mantiki.
2. Mount trigger ya USB-PD karibu na Zana ya ESP RFID na uelekeze receptacle ya USB-C ya trigger nje ya kifuniko.
3. Trigger ya PD inajadiliana 12 V kutoka benki ya nguvu na kupeleka moja kwa moja kwa MaxiProx (msomaji kwa asili unatarajia 10–14 V).  Reli ya pili ya 5 V inachukuliwa kutoka bodi ya ESP ili kupeleka nguvu kwa vifaa vyovyote.
4. Pakiti ya betri ya 100 W imewekwa kwa usawa dhidi ya standoff ya ndani ili kuwe na **hakuna** nyaya za nguvu zinazotundikwa juu ya antena ya ferrite, kuhifadhi utendaji wa RF.

## 2. Beeper Kill-Switch – Uendeshaji wa Kimya

1. Tafuta pad mbili za spika kwenye bodi ya mantiki ya MaxiProx.
2. Safisha *pad zote* kisha re-solder tu pad ya **negative**.
3. Solder waya za 26 AWG (nyeupe = hasi, nyekundu = chanya) kwenye pad za beeper na uelekeze kupitia slot mpya iliyokatwa hadi swichi ya SPST ya paneli.
4. Wakati swichi iko wazi mzunguko wa beeper unavunjika na msomaji unafanya kazi kwa kimya kabisa – bora kwa ukusanyaji wa vitambulisho kwa siri.
5. Weka kifuniko cha usalama cha NKK AT4072 chenye spring juu ya toggle.  Panua kwa uangalifu bore kwa kutumia saw ya coping / faili hadi ikavunjika juu ya mwili wa swichi.  Mlinzi huu unazuia kuanzishwa kwa bahati mbaya ndani ya mkoba.

## 3. Kifuniko & Kazi ya Mitambo

• Tumia cutters za flush kisha kisu & faili ili *kuondoa* "bump-out" ya ndani ya ABS ili betri kubwa ya USB-C ikae kwa usawa kwenye standoff.
• Kata njia mbili za sambamba kwenye ukuta wa kifuniko kwa ajili ya kebo ya USB-C; hii inashikilia betri mahali na kuondoa mwendo/vibrations.
• Unda aperture ya mraba kwa **nishati** ya betri:
1. Bandika stencil ya karatasi juu ya eneo.
2. Chimba mashimo ya kuongoza ya 1/16″ kwenye kona zote nne.
3. Panua kwa kutumia kidonda cha 1/8″.
4. Unganisha mashimo kwa kutumia saw ya coping; maliza mipaka kwa faili.
✱  Dremel ya rotary iliepukwa – kidonda cha kasi ya juu kinayeyusha ABS nzito na kuacha kingo mbaya.

## 4. Mkusanyiko wa Mwisho

1. Re-install bodi ya mantiki ya MaxiProx na re-solder pigtail ya SMA kwenye pad ya ardhi ya PCB ya msomaji.
2. Mount Zana ya ESP RFID na trigger ya USB-PD kwa kutumia 3 M VHB.
3. Pamba nyaya zote kwa zip-ties, ukihifadhi nyaya za nguvu **mbali** na mzunguko wa antena.
4. Bana screws za kifuniko hadi betri inakandamizwa kidogo; msuguano wa ndani unazuia pakiti kuhamasika wakati kifaa kinapokosa baada ya kila kusoma kadi.

## 5. Jaribio la Kiwango & Ulinzi

* Kwa kutumia kadi ya mtihani ya 125 kHz **Pupa** cloner inayobebeka ilipata kusoma kwa usawa kwa **≈ 8 cm** hewani – sawa na uendeshaji wa umeme.
* Kuweka msomaji ndani ya sanduku la fedha lenye ukuta mwembamba (kuiga meza ya lobby ya benki) kulipunguza kiwango hadi ≤ 2 cm, kuthibitisha kwamba vifuniko vya chuma vya kiasi kikubwa vinatumika kama kinga bora ya RF.

## Mchakato wa Matumizi

1. Chaji betri ya USB-C, iunganishe, na geuza swichi kuu ya nguvu.
2. (Hiari) Fungua mlinzi wa beeper na wezesha mrejesho wa sauti unapofanya majaribio ya benchi; ifunge kabla ya matumizi ya siri uwanjani.
3. Tembea karibu na mmiliki wa vitambulisho wa lengo – MaxiProx itawasha kadi na Zana ya ESP RFID inakamata mtiririko wa Wiegand.
4. Tupa akidi zilizokamatwa kupitia Wi-Fi au USB-UART na rudia/clona kama inavyohitajika.

## Kutatua Matatizo

| Dalili | Sababu Inayoweza Kuwa | Suluhisho |
|---------|--------------|------|
| Msomaji unarejea wakati kadi inawasilishwa | Trigger ya PD ilijadiliana 9 V sio 12 V | Thibitisha jumpers za trigger / jaribu kebo ya USB-C yenye nguvu zaidi |
| Hakuna kiwango cha kusoma | Betri au nyaya zikiwa *juu* ya antena | Re-route nyaya & weka 2 cm wazi karibu na mzunguko wa ferrite |
| Beeper bado inatoa sauti | Swichi imeunganishwa kwenye nyaya chanya badala ya hasi | Hamisha kill-switch ili kuvunja **mchoro** wa spika hasi |

## Marejeleo

- [Tujenge Cloner – Sehemu ya 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
