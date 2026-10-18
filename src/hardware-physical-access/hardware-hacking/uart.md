# UART

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

UART ni kiolesura cha serial kisichosawazishwa kinachohamisha mtiririko wa biti zilizopangwa kwa fremu bila kutumia saa ya pamoja. Usichanganye UART ya kiwango cha logic na RS-232: RS-232 hutumia viwango tofauti vya voltage, ambavyo mara nyingi huwa hasi, na huhitaji transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa kawaida, laini hushikiliwa juu (katika thamani ya logic 1) UART ikiwa katika hali ya kutokuwa na shughuli. Kisha, ili kuashiria kuanza kwa uhamishaji wa data, kisambazaji hutuma biti ya kuanza kwa kipokezi; wakati huo, ishara hushikiliwa chini (katika thamani ya logic 0). Baada ya hapo, kisambazaji hutuma biti tano hadi nane za data zenye ujumbe halisi, zikifuatiwa na biti ya hiari ya parity na biti moja au mbili za kusimama (zenye thamani ya logic 1), kulingana na usanidi. Biti ya parity, inayotumika kukagua makosa, haionekani mara nyingi katika matumizi ya kawaida. Biti (au biti) ya kusimama huashiria mwisho wa utumaji.

Usanidi unaotumika zaidi ni 8N1: biti nane za data, bila parity, na biti moja ya kusimama. UART hutuma biti ya data yenye umuhimu mdogo zaidi kwanza, kwa hivyo ASCII `C` (`0x43`) hutumwa kama: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Usanidi unaotumika zaidi huitwa 8N1: biti nane za data, bila parity, na biti moja ya kusimama. Kwa mfano, tukitaka kutuma herufi C, au 0x43 katika ASCII, kupitia UART ya 8N1](<../../images/image (764).png>)

Vifaa vya maunzi vya kuwasiliana kupitia UART:

- Adapta ya USB-to-serial
- Adapta zenye chipu za CP2102 au PL2303
- Kifaa cha matumizi mengi kama vile: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

### Kutambua Milango ya UART

Kichwa cha kawaida cha debug huwa na **TX**, **RX**, na **GND**; kinaweza pia kuwa na pini ya **Vcc/Vref**, reset, au pini za udhibiti wa mtiririko. Vcc si ishara ya UART na kwa kawaida inapaswa kutumika kama rejeleo la voltage tu—si kuunganishwa kama chanzo cha umeme—isipokuwa mchoro wa saketi ya bodi na mahitaji ya mkondo yajulikane.<sup>[[2]](#references)[[3]](#references)</sup>

Anza kifaa kikiwa **kimezimwa** na hakijaunganishwa:

- Tambua **GND** kwa kutumia continuity mode dhidi ya eneo linalojulikana kuwa ground, kinga ya kiunganishi, au ground ya usambazaji wa umeme. Usitumie continuity/resistance mode kwenye bodi iliyowashwa.
- Badilisha kwenda DC-voltage mode kabla ya kuwasha kifaa lengwa. Pima pini zinazoweza kuwa sahihi ukilinganisha na ground ili kutambua voltage ya logic. Reli ya voltage iliyo thabiti inaweza kuwa Vcc/Vref; usidhani ni salama kuiunganisha.
- Chunguza pini zinazoweza kuwa sahihi kwa kutumia logic analyzer au oscilloscope wakati wa kuwasha kifaa. **TX** kwa kawaida huwa juu bila shughuli na huonyesha milipuko ya data iliyopangwa kwa fremu. Multimeter inaweza kuonyesha mabadiliko ya wastani lakini haiwezi kuthibitisha upangaji wa fremu au baud rate.
- **RX** inaweza kubaki bila shughuli na haiwezi kutambuliwa kwa usalama kwa sababu tu iko karibu na TX. Fuatilia PCB, angalia datasheet ya SoC, au tumia analyzer yenye impedance ya juu kabla ya kuiendesha.

Kubadilishana TX na RX kwa kawaida husababisha kutokuwepo kwa mawasiliano; kuchanganya umeme, ground, au viwango vya ishara kunaweza kuharibu kabisa kifaa lengwa au adapta. Unganisha ground kwanza na uanze kwa **kupokea pekee** (TX ya kifaa lengwa kwenda RX ya adapta).

Watengenezaji wanaweza kuacha kichwa hicho, kuacha resistor za mfululizo bila kusakinishwa, kuzima console kwenye firmware, au kutoa TX pekee. Fuatilia test pad na maeneo ya resistor yaliyo karibu hadi kwenye SoC, na uongeze muunganisho wa muda wenye impedance ya juu tu baada ya kuthibitisha kiwango cha umeme. Kuwepo kwa dhamana hakumaanishi kwamba lazima kuwe na UART inayoweza kufikiwa.

### Kurejesha TX pad inayoonekana kuwa chini

TX pad iliyo na lebo lakini inayobaki chini katika picha ya awali ya oscilloscope haitoshi kuhitimisha kuwa hakuna UART. Baada ya kuthibitisha voltage ya logic ya kifaa lengwa na ground ya pamoja, jaribu pull-up dhaifu (mfano uliorekodiwa ulitumia **10 kΩ hadi 3.3 V**) na rudia kunasa huku ukibonyeza vitufe au kuwasha kifaa. Tumia tu reli ya logic iliyothibitishwa ya kifaa lengwa; usiunganishe pull-up kwenye ishara isiyojulikana au inayoendeshwa kikamilifu. Ikiwa mabadiliko yaliyopangwa kwa fremu yataonekana, pima muda mfupi zaidi wa biti ulio safi ili kukadiria baud rate kabla ya kuunganisha pad hiyo kwa ajili ya kupokea pekee kupitia adapta ya serial. Katika mfano, hatua hii ilirejesha logi za matukio ya vitufe za 115200-baud, lakini haikufichua dump ya firmware.<sup>[[8]](#references)</sup>

### Kutambua Baud Rate ya UART

Njia rahisi zaidi ya kutambua baud rate sahihi ni kuangalia matokeo ya **TX pin na kujaribu kusoma data**. Ikiwa data unayopokea haisomeki, badilisha kwenda baud rate inayowezekana inayofuata hadi data isomeke. Unaweza kutumia adapta ya USB-to-serial au kifaa cha matumizi mengi kama Bus Pirate, pamoja na script saidizi kama [baudrate.py](https://github.com/devttys0/baudrate/). Baud rate zinazotumika zaidi ni 9600, 38400, 19200, 57600, na 115200.

> [!CAUTION]
> Ni muhimu kukumbuka kwamba katika protocol hii unahitaji kuunganisha TX ya kifaa kimoja na RX ya kifaa kingine!

### Kuweka Kiotomatiki Unasaji wa UART Wakati wa Kuwasha kwa Kutumia SCPI

Ikiwa matokeo ya kuwasha ni mafupi au TX pad bado haijulikani, weka mchakato wa kuwasha mara kwa mara kiotomatiki badala ya kuendesha usambazaji wa umeme na oscilloscope kwa mkono. Unganisha usambazaji wa umeme unaoweza kuratibiwa na wenye kikomo cha mkondo kwenye ingizo la umeme lililothibitishwa la kifaa lengwa. Chunguza kila TX pad inayoweza kuwa sahihi kwa kutumia ingizo la oscilloscope lenye impedance ya juu na ground ya pamoja; usiendeshe pad hiyo.<sup>[[5]](#references)</sup>

VISA hufungua vipindi vya mawasiliano vya vifaa kupitia serial au Ethernet, huku SCPI ikidhibiti matokeo, trigger, na usomaji wa waveform.<sup>[[5]](#references)[[6]](#references)</sup> Sakinisha `pyvisa` na `pyvisa-py` (pamoja na `pyserial` kwa rasilimali za serial VISA); `ResourceManager('@py')` huchagua backend ya Python moja kwa moja.<sup>[[5]](#references)[[7]](#references)</sup> Badilisha mifuatano ya rasilimali na amri zitumike kulingana na zile zinazoungwa mkono na vifaa vinavyotumika.<sup>[[5]](#references)</sup>

Katika mfano wa Rigol MSO5000, weka trigger ya ukingo unaoshuka ya kunasa mara moja kabla ya kuwasha bodi: TX ya UART ambayo huwa juu bila shughuli hushuka kwanza wakati wa biti yake ya kuanza.<sup>[[5]](#references)</sup> Weka kiwango cha trigger kati ya viwango vilivyopimwa vya hali ya juu bila shughuli na hali ya chini, na uweke timebase kufunika kipindi cha kuwasha kinachokuvutia.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` inaweza kuzuia kingo kurudiwa katika unasaji endelevu, lakini haiwezi kuchukua nafasi ya kuthibitisha kwamba unasaji wa mara moja umekamilika.<sup>[[5]](#references)</sup> Ifuatayo hunasa kuwasha mara moja na kuhifadhi sampuli za unsigned-byte pamoja na metadata ya vipimo vyake; muda ukiisha, kifaa lengwa huzimwa badala ya kusubiri bila kikomo.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Kunasa waveform ya UART mara moja wakati wa kuwasha kwa kutumia PyVISA</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Kwa uchunguzi wa pad, rudia capture ya single-shot baada ya kusogeza probe, au acha kipindi cha supply kikiwa wazi na uwashe/kuzima output yake kwa kutumia muda wa kuwasha wakati wa boot na muda wa kuzima. Weka scope tayari upya kabla ya kila kuwasha umeme ili kila faili lilingane na boot moja na pad moja.<sup>[[5]](#references)</sup>

Preamble ya Rigol ni `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Thamani ya **tatu** ni idadi ya points, si sample rate kama ilivyoelezwa kwenye makala.<sup>[[5]](#references)[[6]](#references)</sup> Katika mfano wake, points `25,000,000` na `xincrement = 2e-8` sekunde zinaashiria `1 / xincrement = 50,000,000` samples/sekunde, si 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Hifadhi preamble pamoja na faili ya binary na uhakikishe kuwa urefu wa data iliyosomwa unalingana na `<points>`; mwongozo unaeleza usomaji wa segmented/batched kwa rekodi kubwa.<sup>[[6]](#references)</sup>

Ili decode signal iliyonaswa, leta `capture.bin` kwenye PulseView kama **Raw Analog Data Without Header**, chagua thamani za unsigned 8-bit (`U8`), kisha weka sample rate iliyokokotolewa kutoka `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Tumia **Logic via Threshold** kwenye channel ya analog, ukichagua threshold iliyo kati ya thamani za chini na za juu za sample.<sup>[[5]](#references)</sup> Pima upana wa start-bit iliyo safi ili kukadiria baud rate (takriban 17.36 µs kwa baud 57,600), kisha tumia UART decoder ya PulseView na uhakikishe kuwa frames kadhaa zina-decode kwa uthabiti.<sup>[[5]](#references)</sup> Edge inayoshuka pekee haithibitishi kuwa pad ni UART.

## Adapta ya CP210X UART hadi TTY

CP210x USB-to-UART bridges zinapatikana kwenye boards nyingi za prototyping na adapta za bei nafuu. Modules za kawaida hutoa pins za supply pamoja na GND, RXD na TXD, lakini headers na viwango vya I/O hutofautiana. Thibitisha voltage halisi kupitia muundo wa board au data sheet. Kwa kawaida, unganisha GND pekee, RX ya adapta kwenye TX ya kifaa lengwa, na—baada ya kuthibitisha receive-only—TX ya adapta kwenye RX ya kifaa lengwa. Usiunganishe pin ya supply ya 5 V/3.3 V ya adapta isipokuwa unakusudia kuwasha kifaa lengwa kinachojulikana kuvumilia voltage hiyo.<sup>[[3]](#references)</sup>

Ikiwa adapta haitambuliwi, hakikisha kuwa drivers za CP210X zimesakinishwa kwenye mfumo wa host. Adapta ikishatambuliwa na kuunganishwa, unaweza kutumia zana kama picocom, minicom au screen.

Kuorodhesha vifaa vilivyounganishwa kwenye mifumo ya Linux/MacOS:

```
ls /dev/
```

Kwa mwingiliano wa msingi na kiolesura cha UART, tumia amri ifuatayo:

```
picocom /dev/<adapter> --baud <baudrate>
```

Kwa minicom, tumia amri ifuatayo ili kuisanidi:

```
minicom -s
```

Sanidi mipangilio kama vile baudrate na jina la kifaa kwenye chaguo la `Serial port setup`.

Baada ya kusanidi, endesha `minicom` ili kufungua UART console.

## UART Kupitia Arduino UNO R3 (Bodi Zenye Chipu ya Atmel 328p Inayoweza Kuondolewa)

Ikiwa adapta za UART Serial hadi USB hazipatikani, Arduino UNO R3 inaweza kutumika kwa hila rahisi. Kwa kuwa Arduino UNO R3 hupatikana karibu kila mahali, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina adapta ya USB hadi Serial iliyojengwa kwenye ubao wenyewe. Ili kupata muunganisho wa UART, ondoa tu chipu ya Atmel 328p kutoka kwenye ubao. Hila hii hufanya kazi kwenye vibadala vya Arduino UNO R3 ambavyo Atmel 328p haijauzwa moja kwa moja kwenye ubao (toleo la SMD ndilo linalotumika ndani yake). Unganisha pini ya RX ya Arduino (Digital Pin 0) kwenye pini ya TX ya UART Interface na pini ya TX ya Arduino (Digital Pin 1) kwenye pini ya RX ya UART interface.

Tumia **Serial Monitor** ya Arduino IDE au terminal maalum yenye kasi ya baud inayolengwa. Mawimbi ya serial ya kawaida ya Uno R3 hutumia mantiki ya 5 V, kwa hivyo tumia level shifter au divider kabla ya kuyaunganisha kwenye kifaa lengwa cha 3.3 V au chenye voltage ya chini zaidi.

## Bus Pirate

Nakala ifuatayo hutumia kiolesura cha zamani cha firmware ya Bus Pirate kufuatilia matokeo ya UART. Firmware mpya zaidi ya Bus Pirate hutumia amri kama `m uart`, `{`/`}`, `monitor`, au `bridge`; rejelea nyaraka za toleo lililosakinishwa.<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## Kudump Firmware kwa kutumia UART Console

UART console hutoa ufikiaji wa wakati wa utekelezaji kwa boot logs na, wakati mwingine, bootloader au shell ya mfumo wa uendeshaji. Hata console ya kusoma pekee hufichua ramani za memory, flash drivers, boot arguments, mipangilio ya partitions na matoleo ya firmware. Firmware inaweza kuwa kwenye SPI NOR/NAND, eMMC au kifaa kingine; kwa kawaida haitekelezwi moja kwa moja kutoka EEPROM, na faili zilizoandikwa kwenye filesystem endelevu iliyomountiwa si lazima zipotee baada ya kuwasha upya.

Kuna njia kadhaa za kupata firmware, na sehemu ya SPI inaeleza usomaji wa moja kwa moja kutoka kwenye flash ya nje. Upatikanaji unaosaidiwa na console unaweza kuwa na athari ndogo zaidi ikiwa bootloader tayari ina amri salama ya kusoma, lakini kukatiza boot au kutumia amri za flash kunaweza kuathiri upatikanaji; kwa hiyo, rekodi hali ya awali na uepuke shughuli za write/erase.

Kudump firmware kwa msaada wa console mara nyingi huanza kwa kukatiza bootloader. Vifaa vingi vya Linux vilivyopachikwa hutumia **Das U-Boot**, lakini vingine hutumia bootloaders za wamiliki au huzima console shirikishi.

Ili kupima kama bootloader shirikishi inapatikana, unganisha njia ya kupokea ya UART na terminal wakati kifaa lengwa hakijawashwa, anza kurekodi, kisha ukiwashe. Fuata kidokezo cha autoboot kinachoonyeshwa; kutegemea build, kukatiza kunaweza kuhitaji kitufe, mfuatano mfupi wa vitufe au huenda kumezimwa kabisa.

Ukifanikiwa kukatiza, tumia `help`, `printenv` na amri za ugunduzi zisizoandika ili kuelewa mpangilio wa memory na hifadhi wa mtengenezaji huyo kabla ya kufikia anwani.

Katika U-Boot, `md` huonyesha **memory inayoweza kufikiwa kwa anwani**, wala si “EEPROM” moja kwa moja. Kwanza tumia amri maalum za board kama `mtd list`, `sf probe`, `mmc info`, `part list`, variables za mazingira na boot logs ili kutambua anwani sahihi iliyomapishwa au kupakia eneo la flash kwenye RAM. Kisha onyesha masafa yanayojulikana byte moja kwa wakati:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Rekodi matokeo ya serial kabla ya kuanza. Matokeo ya `md.b` yana anwani na safu ya ASCII, kwa hiyo ni uwakilishi wa maandishi badala ya taswira ghafi ya ROM.

Ondoa safu za anwani na ASCII, unganisha sehemu za baiti za heksadesimali pekee, kisha uzisimbue kuwa binary (kwa mfano kwa `xxd -r -p`). Thibitisha idadi ya baiti inayotarajiwa na urekodi hash kabla ya kuchanganua:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk kisha hutambua signature zinazojulikana kwenye binary iliyoundwa upya. Kusoma flash moja kwa moja kupitia kiolesura kinachofaa cha SPI/eMMC/NAND kwa kawaida ni haraka zaidi na kuna uwezekano mdogo wa makosa wakati console haiwezi kuhamisha data kwa uhakika.

U-Boot inaweza kuzima uwezekano wa kukatiza uanzishaji, kuhitaji mfuatano wa vitufe maalum wa vendor, au kufunga amri za memory/flash. Fuata kidokezo cha autoboot na boot log badala ya kutuma herufi bila kufikiri. Ikiwa console haiwezi kukatizwa, hifadhi boot log na utumie njia isiyoingilia ya kupata firmware.

## References

- [1] [Mwongozo wa Marejeleo wa Familia ya Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Nyaraka za Bus Pirate - hali ya UART na viwango vya umeme](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - hifadhidata ya CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Nyaraka za U-Boot - amri ya kuonyesha memory ya `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI na vifaa vya majaribio ya hardware kwa wahandisi wa reverse engineering, Sehemu ya 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Mwongozo wa Programu wa Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Kusanidi backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Kukumbushia misingi ya Hardware Hacking, Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
