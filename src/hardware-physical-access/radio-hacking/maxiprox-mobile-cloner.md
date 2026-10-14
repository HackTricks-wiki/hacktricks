# Kutengeneza Kifaa Kinachobebeka cha HID MaxiProx 125 kHz cha Kunakili Kadi

{{#include ../../banners/hacktricks-training.md}}

## Lengo
Kubadilisha kisomaji cha HID MaxiProx 5375 cha masafa marefu cha 125 kHz, kinachotumia umeme wa mains, kuwa kifaa cha kunakili beji kinachotumia betri na kinachoweza kutumika nje ya maabara, ili kunasa kadi za ukaribu kimyakimya wakati wa tathmini za usalama wa kimwili.

Mabadiliko yaliyoelezwa hapa yanategemea mfululizo wa utafiti wa TrustedSec, “Let’s Clone a Cloner – Part 3: Putting It All Together”, na yanajumuisha mambo ya kiufundi, umeme na RF ili kifaa cha mwisho kiweze kuwekwa kwenye mkoba na kutumika mara moja eneo husika.<sup>[[1]](#references)</sup>

> [!warning]
> Kufanyia kazi vifaa vinavyotumia umeme wa mains na power-bank za Lithium-ion kunaweza kuwa hatari. Hakikisha kila muunganisho **kabla** ya kuwasha saketi, na uhifadhi antena, coax na ground planes jinsi zilivyokuwa kwenye muundo wa kiwandani ili kuepuka kuathiri utunaji wa kisomaji.

## Orodha ya Vifaa (BOM)

* Kisomaji cha HID MaxiProx 5375 (au kisomaji chochote cha HID Prox® cha masafa marefu cha 12 V)
* ESP RFID Tool v2.2 (sniffer/logger ya Wiegand inayotumia ESP32)
* Moduli ya USB-PD (Power-Delivery) trigger inayoweza kujadiliana kupata 12 V @ ≥3 A
* Power-bank ya USB-C ya 100 W (hutoa profaili ya 12 V PD)
* Waya wa kuunganisha wa 26 AWG uliofunikwa kwa silicone – nyekundu/nyeupe
* Swichi ya SPST ya paneli (ya kuzima buzzer)
* Kifuniko cha usalama cha swichi cha NKK AT4072 / kisichowashwa kwa bahati mbaya
* Chuma cha kutengenezea, waya wa kuondoa solder na pampu ya kuondoa solder
* Zana za mkono zinazofaa kwa ABS: msumeno wa coping, kisu cha matumizi, faili bapa na ya nusu duara
* Vichimba vya 1/16″ (1.5 mm) na 1/8″ (3 mm)
* Tape ya pande mbili ya 3 M VHB na zip-ties

## 1. Mfumo wa Umeme

1. Ondoa solder na uondoe ubao mdogo wa buck-converter wa kiwandani uliotumika kuzalisha 5 V kwa PCB ya logic.
2. Weka USB-PD trigger karibu na ESP RFID Tool na elekeza soketi ya USB-C ya trigger hadi nje ya kasha.
3. PD trigger hupata 12 V kutoka kwa power-bank na kuipeleka moja kwa moja kwenye MaxiProx (kisomaji kinahitaji 10–14 V). Reli ya pili ya 5 V hutolewa kutoka kwenye ubao wa ESP ili kuwasha vifaa vingine.
4. Weka pakiti ya betri ya 100 W ikigusa kizuizi cha ndani ili kusiwe na nyaya za umeme zinazopita juu ya antena ya ferrite, hivyo kuhifadhi utendaji wa RF.

## 2. Swichi ya Kuzima Buzzer – Uendeshaji Kimyakimya

1. Tafuta pedi mbili za spika kwenye ubao wa logic wa MaxiProx.
2. Ondoa solder kwenye pedi *zote mbili*, kisha rudisha solder kwenye pedi ya **hasi** pekee.
3. Solder waya za 26 AWG (nyeupe = hasi, nyekundu = chanya) kwenye pedi za buzzer na uzipitishe kwenye nafasi mpya iliyokatwa hadi kwenye swichi ya SPST ya paneli.
4. Swichi ikiwa wazi, saketi ya buzzer hukatika na kisomaji hufanya kazi kimyakimya kabisa – inafaa kwa kunasa beji kwa siri.
5. Weka kifuniko cha usalama cha NKK AT4072 chenye spring juu ya swichi. Panua tundu kwa uangalifu kwa kutumia msumeno wa coping/faili hadi kifuniko kikae juu ya mwili wa swichi. Kifuniko huzuia swichi kuwashwa kwa bahati mbaya ndani ya mkoba.

## 3. Kasha na Kazi za Kimitambo

• Tumia koleo la kukatia kisha kisu na faili *kuondoa* sehemu ya ndani ya ABS iliyoinuka ili betri kubwa ya USB-C ikae sawasawa kwenye kizuizi.
• Tengeneza mifereji miwili sambamba kwenye ukuta wa kasha kwa ajili ya kebo ya USB-C; hii hufunga betri mahali pake na kuzuia kusogea/kutetemeka.
• Tengeneza tundu la mstatili kwa ajili ya kitufe cha **umeme** cha betri:
  1. Bandika stencil ya karatasi juu ya eneo hilo.
  2. Toboa mashimo ya kuongozea ya 1/16″ kwenye pembe zote nne.
  3. Panua kwa biti ya 1/8″.
  4. Unganisha mashimo kwa msumeno wa coping; kisha lainisha kingo kwa faili.  
  ✱  Dremel ya mzunguko *haikutumika* – biti inayozunguka kwa kasi huyeyusha ABS nene na kuacha ukingo mbaya.

## 4. Kukusanya Kifaa cha Mwisho

1. Rudisha ubao wa logic wa MaxiProx na solder tena pigtail ya SMA kwenye pedi ya ground ya PCB ya kisomaji.
2. Weka ESP RFID Tool na USB-PD trigger kwa kutumia 3 M VHB.
3. Panga nyaya zote kwa zip-ties, huku ukiziweka nyaya za umeme **mbali** na kitanzi cha antena.
4. Kaza skrubu za kasha hadi betri ibanwe kidogo; msuguano wa ndani huzuia pakiti kusogea kifaa kinaporejea nyuma baada ya kila usomaji wa kadi.

## 5. Majaribio ya Masafa na Ukingaji

* Kwa kutumia kadi ya majaribio ya 125 kHz **Pupa**, kifaa kinachobebeka cha kunakili kilisoma kadi kwa uthabiti kutoka umbali wa **≈ 8 cm** hewani – sawa na utendaji kinapotumia umeme wa mains.<sup>[[1]](#references)</sup>
* Kuweka kisomaji ndani ya kisanduku cha pesa cha chuma chenye kuta nyembamba (kuiga kaunta ya benki) kulipunguza masafa hadi ≤ 2 cm, na kuthibitisha kuwa makasha makubwa ya chuma hufanya kazi kama vizuiaji bora vya RF.<sup>[[1]](#references)</sup>

## Mtiririko wa Matumizi

1. Chaji betri ya USB-C, iunganishe, kisha washa swichi kuu ya umeme.
2. (Si lazima) Fungua kifuniko cha buzzer na uwashe sauti unapojaribu kwenye benchi; kifunge kabla ya matumizi ya siri eneo husika.
3. Pita karibu na mwenye beji lengwa – MaxiProx itawasha kadi na ESP RFID Tool itanasa mtiririko wa Wiegand.
4. Hamisha vitambulisho vilivyonaswa kupitia Wi-Fi au USB-UART kisha uvichezeshe tena/uvinakili inavyohitajika.

## Utatuzi wa Matatizo

| Dalili | Sababu Inayowezekana | Suluhisho |
|---------|--------------|------|
| Kisomaji hujiwasha upya kadi inapowasilishwa | PD trigger ilijadiliana kupata 9 V badala ya 12 V | Hakiki jumpers za trigger / jaribu kebo ya USB-C yenye nguvu zaidi |
| Masafa ya usomaji hayapo | Betri au nyaya zimekaa *juu ya* antena | Elekeza nyaya upya na uache nafasi ya sentimita 2 kuzunguka kitanzi cha ferrite |
| Buzzer bado inalia kwa vipindi | Swichi imeunganishwa kwenye waya chanya badala ya hasi | Hamisha kill-switch ili ikate njia **hasi** ya spika |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}