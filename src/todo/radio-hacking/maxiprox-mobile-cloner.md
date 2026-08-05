# Kujenga Portable HID MaxiProx 125 kHz Mobile Cloner

{{#include ../../banners/hacktricks-training.md}}

## Lengo
Kubadilisha HID MaxiProx 5375 long-range 125 kHz reader inayotumia mains kuwa badge cloner inayobebeka, inayotumia battery na inaweza kutumika现场 kukusanya proximity cards bila kutoa sauti wakati wa physical-security assessments.

Mabadiliko yaliyoelezwa hapa yanategemea mfululizo wa utafiti wa TrustedSec wa “Let’s Clone a Cloner – Part 3: Putting It All Together” na yanachanganya masuala ya mechanical, electrical na RF ili kifaa cha mwisho kiweze kuwekwa kwenye backpack na kutumiwa mara moja现场.<sup>[[1]](#references)</sup>

> [!warning]
> Kushughulikia vifaa vinavyotumia mains na Lithium-ion power-banks kunaweza kuwa hatari. Thibitisha kila connection **kabla** ya kuenergise circuit na uache antennas, coax na ground planes zikiwa jinsi zilivyokuwa katika factory design ili kuepuka ku-detune reader.

## Orodha ya Vifaa (BOM)

* HID MaxiProx 5375 reader (au 12 V HID Prox® long-range reader yoyote)
* ESP RFID Tool v2.2 (Wiegand sniffer/logger inayotumia ESP32)
* USB-PD (Power-Delivery) trigger module inayoweza ku-negotiate 12 V @ ≥3 A
* 100 W USB-C power-bank (hutoa 12 V PD profile)
* 26 AWG silicone-insulated hook-up wire – nyekundu/nyeupe
* Panel-mount SPST toggle switch (kwa beeper kill-switch)
* NKK AT4072 switch-guard / accident-proof cap
* Soldering iron, solder wick & desolder pump
* ABS-rated hand tools: coping-saw, utility-knife, flat & half-round files
* Drill bits 1/16″ (1.5 mm) na 1/8″ (3 mm)
* 3 M VHB double-sided tape & Zip-ties

## 1. Power Sub-System

1. Desolder na uondoe factory buck-converter daughter-board iliyotumika kuzalisha 5 V kwa logic PCB.
2. Mount USB-PD trigger karibu na ESP RFID Tool na peleka USB-C receptacle ya trigger hadi nje ya enclosure.
3. PD trigger hu-negotiate 12 V kutoka kwa power-bank na kuilisha moja kwa moja MaxiProx (reader inatarajia 10–14 V kwa asili). Secondary 5 V rail inachukuliwa kutoka ESP board ili ku-power accessories zozote.
4. 100 W battery pack iwekwe ikiwa imelala sawasawa dhidi ya internal standoff ili kusiwe na **power cables** zinazopita juu ya ferrite antenna, hivyo kuhifadhi RF performance.

## 2. Beeper Kill-Switch – Silent Operation

1. Tafuta speaker pads mbili kwenye MaxiProx logic board.
2. Safisha *pads* **zote mbili** kwa wick, kisha solder tena **negative** pad pekee.
3. Solder 26 AWG wires (nyeupe = negative, nyekundu = positive) kwenye beeper pads na zipitishe kupitia slot mpya hadi kwenye panel-mount SPST switch.
4. Switch ikiwa open, beeper circuit hukatika na reader hufanya kazi bila sauti kabisa – inafaa kwa covert badge harvesting.
5. Weka NKK AT4072 spring-loaded safety cap juu ya toggle. Panua bore kwa uangalifu kwa coping-saw / file hadi cap ijifunge juu ya switch body. Guard huzuia activation ya bahati mbaya ndani ya backpack.

## 3. Enclosure & Mechanical Work

• Tumia flush cutters kisha knife & file kuondoa *internal ABS “bump-out”* ili USB-C battery kubwa ikae sawasawa kwenye standoff.
• Tengeneza channels mbili zinazofanana kwenye ukuta wa enclosure kwa USB-C cable; hii hufunga battery mahali pake na kuondoa movement/vibration.
• Tengeneza rectangular aperture kwa **power** button ya battery:
1. Bandika paper stencil juu ya eneo hilo.
2. Toboa 1/16″ pilot holes kwenye pembe zote nne.
3. Panua kwa 1/8″ bit.
4. Unganisha holes kwa coping saw; malizia edges kwa file.
✱  Rotary Dremel *iliepukwa* – high-speed bit huyeyusha ABS nene na kuacha edge isiyopendeza.

## 4. Final Assembly

1. Re-install MaxiProx logic board na solder tena SMA pigtail kwenye reader’s PCB ground pad.
2. Mount ESP RFID Tool na USB-PD trigger kwa kutumia 3 M VHB.
3. Panga wiring yote kwa zip-ties, ukiweka power leads **mbali** na antenna loop.
4. Kaza enclosure screws hadi battery ikandamizwe kidogo; internal friction huzuia pack kusogea wakati kifaa kinaporudi nyuma baada ya kila card read.

## 5. Range & Shielding Tests

* Kwa kutumia 125 kHz **Pupa** test card, portable cloner ilifanya reads thabiti hadi **≈ 8 cm** katika free-air – sawa kabisa na operation inayotumia mains.<sup>[[1]](#references)</sup>
* Kuweka reader ndani ya thin-walled metal cash box (kuiga bank lobby desk) kulipunguza range hadi ≤ 2 cm, kuthibitisha kuwa metal enclosures nzito hufanya kazi kama RF shields bora.<sup>[[1]](#references)</sup>

## Usage Workflow

1. Charge USB-C battery, iunganishe, kisha washa main power switch.
2. (Optional) Fungua beeper guard na uwashe audible feedback wakati wa bench-testing; ifunge kabla ya covert field use.
3. Pita karibu na target badge holder – MaxiProx itaenergise card na ESP RFID Tool itakamata Wiegand stream.
4. Dump captured credentials kupitia Wi-Fi au USB-UART na uzireplay/clone inavyohitajika.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|------|
| Reader inareboot card inapowasilishwa | PD trigger ime-negotiate 9 V badala ya 12 V | Thibitisha trigger jumpers / jaribu higher-power USB-C cable |
| Hakuna read range | Battery au wiring imekaa *juu ya* antenna | Re-route cables na uweke clearance ya 2 cm kuzunguka ferrite loop |
| Beeper bado inalia | Switch imeunganishwa kwenye positive lead badala ya negative | Hamisha kill-switch ili ikate **negative** speaker trace |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
