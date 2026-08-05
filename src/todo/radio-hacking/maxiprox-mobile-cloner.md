# एक Portable HID MaxiProx 125 kHz Mobile Cloner बनाना

{{#include ../../banners/hacktricks-training.md}}

## लक्ष्य
मुख्य विद्युत-संचालित HID MaxiProx 5375 long-range 125 kHz reader को field में उपयोग योग्य, battery-powered badge cloner में बदलना, जो physical-security assessments के दौरान proximity cards को चुपचाप harvest कर सके।

यहाँ वर्णित conversion TrustedSec की “Let’s Clone a Cloner – Part 3: Putting It All Together” research series पर आधारित है और mechanical, electrical तथा RF considerations को मिलाता है, ताकि final device को backpack में रखकर site पर तुरंत उपयोग किया जा सके।<sup>[[1]](#references)</sup>

> [!warning]
> मुख्य विद्युत-संचालित equipment और Lithium-ion power-banks के साथ काम करना खतरनाक हो सकता है। Circuit को energise करने से **पहले** हर connection को verify करें और reader की detuning से बचने के लिए antennas, coax तथा ground planes को factory design के अनुसार ही रखें।

## सामग्री की सूची (BOM)

* HID MaxiProx 5375 reader (या कोई भी 12 V HID Prox® long-range reader)
* ESP RFID Tool v2.2 (ESP32-based Wiegand sniffer/logger)
* USB-PD (Power-Delivery) trigger module, जो 12 V @ ≥3 A negotiate कर सके
* 100 W USB-C power-bank (12 V PD profile output)
* 26 AWG silicone-insulated hook-up wire – red/white
* Panel-mount SPST toggle switch (beeper kill-switch के लिए)
* NKK AT4072 switch-guard / accident-proof cap
* Soldering iron, solder wick और desolder pump
* ABS-rated hand tools: coping-saw, utility-knife, flat और half-round files
* Drill bits 1/16″ (1.5 mm) और 1/8″ (3 mm)
* 3 M VHB double-sided tape और Zip-ties

## 1. Power Sub-System

1. Logic PCB के लिए 5 V बनाने वाले factory buck-converter daughter-board को desolder करके निकालें।
2. ESP RFID Tool के पास USB-PD trigger mount करें और trigger के USB-C receptacle को enclosure के बाहर route करें।
3. PD trigger power-bank से 12 V negotiate करता है और इसे सीधे MaxiProx को देता है (reader मूल रूप से 10–14 V अपेक्षित करता है)। Accessories को power देने के लिए ESP board से secondary 5 V rail ली जाती है।
4. 100 W battery pack को internal standoff के साथ flush position में रखें, ताकि ferrite antenna के ऊपर कोई **power cables** न लटके और RF performance बनी रहे।

## 2. Beeper Kill-Switch – Silent Operation

1. MaxiProx logic board पर दो speaker pads खोजें।
2. *दोनों* pads को साफ wick करें, फिर केवल **negative** pad को दोबारा solder करें।
3. 26 AWG wires (white = negative, red = positive) को beeper pads पर solder करें और उन्हें newly cut slot के माध्यम से panel-mount SPST switch तक route करें।
4. Switch open होने पर beeper circuit टूट जाता है और reader पूरी तरह silent mode में काम करता है – covert badge harvesting के लिए आदर्श।
5. Toggle के ऊपर NKK AT4072 spring-loaded safety cap लगाएँ। Coping-saw / file से bore को सावधानीपूर्वक तब तक बड़ा करें, जब तक वह switch body पर snap न हो जाए। Guard backpack के अंदर accidental activation को रोकता है।

## 3. Enclosure और Mechanical Work

• पहले flush cutters और फिर knife & file का उपयोग करके internal ABS “bump-out” *हटाएँ*, ताकि बड़ा USB-C battery pack standoff पर flat बैठ सके।
• USB-C cable के लिए enclosure wall में दो parallel channels बनाएँ; इससे battery अपनी जगह lock रहती है और movement/vibration समाप्त हो जाता है।
• Battery के **power** button के लिए rectangular aperture बनाएँ:
1. Location के ऊपर paper stencil tape से लगाएँ।
2. चारों corners में 1/16″ pilot holes drill करें।
3. 1/8″ bit से holes को बड़ा करें।
4. Coping saw से holes को जोड़ें; file से edges को finish करें।
✱  Rotary Dremel से *बचा गया* – high-speed bit thick ABS को पिघला देता है और खराब edge छोड़ता है।

## 4. Final Assembly

1. MaxiProx logic board को फिर से install करें और SMA pigtail को reader के PCB ground pad पर दोबारा solder करें।
2. ESP RFID Tool और USB-PD trigger को 3 M VHB का उपयोग करके mount करें।
3. सभी wiring को zip-ties से व्यवस्थित करें और power leads को antenna loop से **दूर** रखें।
4. Enclosure screws को तब तक tighten करें, जब तक battery हल्के से compress न हो जाए; internal friction pack को हर card read के बाद device के recoil करने पर खिसकने से रोकता है।

## 5. Range और Shielding Tests

* 125 kHz **Pupa** test card का उपयोग करते हुए portable cloner ने free-air में **≈ 8 cm** पर consistent reads प्राप्त किए – mains-powered operation के समान।<sup>[[1]](#references)</sup>
* Reader को thin-walled metal cash box के अंदर रखने पर (bank lobby desk का simulation) range घटकर ≤ 2 cm हो गई, जिससे पुष्टि हुई कि substantial metal enclosures effective RF shields की तरह काम करते हैं।<sup>[[1]](#references)</sup>

## Usage Workflow

1. USB-C battery को charge करें, उसे connect करें और main power switch on करें।
2. (Optional) Bench-testing के दौरान audible feedback enable करने के लिए beeper guard खोलें; covert field use से पहले इसे lock कर दें।
3. Target badge holder के पास से गुजरें – MaxiProx card को energise करेगा और ESP RFID Tool Wiegand stream capture करेगा।
4. Captured credentials को Wi-Fi या USB-UART के माध्यम से dump करें और आवश्यकतानुसार replay/clone करें।

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|------|
| Card प्रस्तुत करने पर reader reboot होता है | PD trigger ने 9 V negotiate किया, 12 V नहीं | Trigger jumpers verify करें / अधिक power वाले USB-C cable का प्रयास करें |
| कोई read range नहीं | Battery या wiring antenna के *ऊपर* रखी है | Cables को re-route करें और ferrite loop के चारों ओर 2 cm clearance रखें |
| Beeper अब भी chirp करता है | Switch को negative के बजाय positive lead पर wire किया गया है | Kill-switch को **negative** speaker trace को break करने के लिए स्थानांतरित करें |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
