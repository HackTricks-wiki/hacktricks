# UART

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

UART ni kiolesura cha mfululizo kisicho sawazishwa ambacho huhamisha mtiririko wa biti zilizopangwa katika fremu bila kutumia clock ya pamoja. Usichanganye UART ya kiwango cha logic na RS-232: RS-232 hutumia viwango tofauti vya voltage, mara nyingi hasi, na huhitaji transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa kawaida, laini hushikiliwa juu (katika thamani ya kimantiki 1) UART ikiwa katika hali ya kutotuma data. Kisha, ili kuashiria mwanzo wa uhamishaji wa data, kisambazaji hutuma biti ya mwanzo kwa kipokezi; wakati huo, ishara hushikiliwa chini (katika thamani ya kimantiki 0). Halafu, kisambazaji hutuma biti tano hadi nane za data zenye ujumbe halisi, zikifuatiwa na biti ya hiari ya parity na biti moja au mbili za kusitisha (zenye thamani ya kimantiki 1), kulingana na usanidi. Biti ya parity, inayotumika kukagua hitilafu, haionekani mara nyingi katika matumizi halisi. Biti (au biti) ya kusitisha huashiria mwisho wa uwasilishaji.

Usanidi unaotumika sana ni 8N1: biti nane za data, bila parity, na biti moja ya kusitisha. UART hutuma biti ya data yenye thamani ndogo zaidi kwanza, kwa hivyo ASCII `C` (`0x43`) hutumwa kama: mwanzo `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; kusitisha `1`.<sup>[[1]](#references)</sup>

![UART: Usanidi unaotumika sana huitwa 8N1: biti nane za data, bila parity, na biti moja ya kusitisha. Kwa mfano, tukitaka kutuma herufi C, au 0x43 katika ASCII, kwa UART ya 8N1](<../../images/image (764).png>)

Zana za maunzi za kuwasiliana na UART:

- Adapta ya USB-to-serial
- Adapta zenye chipu za CP2102 au PL2303
- Zana ya matumizi mengi kama vile: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

### Kutambua Milango ya UART

Kichwa cha kawaida cha utatuzi hutoa **TX**, **RX**, na **GND**; kinaweza pia kutoa pini ya **Vcc/Vref**, reset, au pini za udhibiti wa mtiririko. Vcc si ishara ya UART na kwa kawaida inapaswa kutumika tu kama rejeleo la voltage—si kuunganishwa kama chanzo cha umeme—isipokuwa mchoro wa saketi na mahitaji ya mkondo wa umeme ya ubao yanajulikana.<sup>[[2]](#references)[[3]](#references)</sup>

Anza kifaa kikiwa **kimezimwa** na kimekatwa:

- Tambua **GND** kwa kutumia hali ya continuity na kuilinganisha na sehemu ya ground inayojulikana, kinga ya kiunganishi, au ground ya chanzo cha umeme. Usitumie hali ya continuity/resistance kwenye ubao wenye umeme.
- Badili hadi hali ya DC-voltage kabla ya kuwasha kifaa lengwa. Pima pini zinazoweza kuwa sahihi ukizilinganisha na ground ili kutambua voltage ya logic. Laini ya voltage iliyo thabiti inaweza kuwa Vcc/Vref; usidhani ni salama kuiunganisha.
- Chunguza pini zinazoweza kuwa sahihi kwa kutumia logic analyzer au oscilloscope wakati wa kuwasha kifaa. **TX** kwa kawaida huwa juu ikiwa tuli na huonyesha milipuko ya data iliyopangwa katika fremu. Multimeter inaweza kuonyesha mabadiliko ya wastani, lakini haiwezi kuthibitisha mpangilio wa fremu au baud rate.
- **RX** inaweza kubaki tuli na haiwezi kutambuliwa kwa usalama kwa sababu tu iko karibu na TX. Fuata njia kwenye PCB, rejelea datasheet ya SoC, au tumia analyzer yenye impedance ya juu kabla ya kuitumia kuendesha ishara.

Kubadilishana TX na RX kwa kawaida hakutoi mawasiliano; kuchanganya umeme, ground, au viwango vya ishara kunaweza kuharibu kabisa kifaa lengwa au adapta. Unganisha ground kwanza na uanze kwa **kupokea tu** (TX ya kifaa lengwa kwenda RX ya adapta).

Watengenezaji wanaweza kuacha kichwa cha pini, kutoweka resistor za mfululizo, kuzima console kwenye firmware, au kutoa TX pekee. Fuatilia test pad na sehemu za resistor zilizo karibu hadi kwenye SoC, na ongeza muunganisho wa muda wenye impedance ya juu tu baada ya kuthibitisha kiwango cha umeme. Kuwepo kwa warranty hakumaanishi kuwa lazima kuwe na UART inayoweza kufikiwa.

### Kutambua Baud Rate ya UART

Njia rahisi zaidi ya kutambua baud rate sahihi ni kuangalia matokeo ya pini ya **TX na kujaribu kusoma data**. Ikiwa data unayopokea haisomeki, badili hadi baud rate inayofuata inayowezekana hadi data isomeke. Unaweza kutumia adapta ya USB-to-serial au kifaa cha matumizi mengi kama Bus Pirate kufanya hivi, pamoja na script saidizi kama [baudrate.py](https://github.com/devttys0/baudrate/). Baud rate zinazotumika sana ni 9600, 38400, 19200, 57600, na 115200.

> [!CAUTION]
> Ni muhimu kukumbuka kwamba katika itifaki hii unahitaji kuunganisha TX ya kifaa kimoja na RX ya kingine!

### Kurekodi UART Kiotomatiki Wakati wa Kuwasha kwa SCPI

Ikiwa matokeo ya kuwasha ni mafupi au pad ya TX bado haijulikani, otomatisha kuwasha upya mara kwa mara badala ya kuendesha chanzo cha umeme na oscilloscope kwa mkono. Unganisha chanzo cha umeme kinachoweza kupangwa na kikomo cha mkondo kwenye ingizo la umeme lililothibitishwa la kifaa lengwa. Chunguza kila pad ya TX inayowezekana kwa kutumia ingizo la oscilloscope lenye impedance ya juu na ground ya pamoja; usiendeshe pad hiyo.<sup>[[5]](#references)</sup>

VISA hufungua vipindi vya mawasiliano vya kifaa kupitia serial au Ethernet, huku SCPI ikidhibiti matokeo, trigger, na usomaji wa waveform.<sup>[[5]](#references)[[6]](#references)</sup> Sakinisha `pyvisa` na `pyvisa-py` (pamoja na `pyserial` kwa rasilimali za serial za VISA); `ResourceManager('@py')` huchagua backend ya Python moja kwa moja.<sup>[[5]](#references)[[7]](#references)</sup> Badilisha maandishi ya rasilimali na amri kwa zile zinazotumika na vifaa husika.<sup>[[5]](#references)</sup>

Katika mfano wa Rigol MSO5000, weka trigger ya falling-edge ya kunasa mara moja kabla ya kuwasha ubao: TX ya UART ambayo huwa juu ikiwa tuli hushuka kwanza kwa biti yake ya mwanzo.<sup>[[5]](#references)</sup> Weka kizingiti cha trigger kati ya viwango vilivyopimwa vya tuli na chini, na weka timebase ili ijumuisha kipindi cha kuwasha unachotaka kuchunguza.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` inaweza kuzuia edges zinazorudiwa katika kunasa kwa mfululizo, lakini si mbadala wa kuthibitisha kuwa kunasa mara moja kumekamilika.<sup>[[5]](#references)</sup> Mfano ufuatao hunasa kuwasha mara moja na kuhifadhi sampuli za unsigned-byte pamoja na metadata yake ya scaling; muda ukiisha, kifaa lengwa huzimwa badala ya kusubiri milele.<sup>[[5]](#references)[[6]](#references)</sup>

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

Kwa uchunguzi wa pad, rudia kunasa kwa single-shot baada ya kusogeza probe, au acha kikao cha supply kikiwa wazi na uwashe/kuzima output yake kwa kutumia muda wa kusubiri wakati wa boot na muda wa kuzimwa. Weka scope tayari kunasa kabla ya kila kuwasha kifaa ili kila faili ilingane na boot moja na pad moja.<sup>[[5]](#references)</sup>

Preamble ya Rigol ni `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Thamani ya **tatu** ni idadi ya points, si sample rate kama ilivyoelezwa kwenye makala.<sup>[[5]](#references)[[6]](#references)</sup> Katika mfano wake, points `25,000,000` na `xincrement = 2e-8` seconds humaanisha `1 / xincrement = 50,000,000` samples/second, si 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Hifadhi preamble pamoja na faili ya binary na uhakikishe kuwa urefu uliosomwa unalingana na `<points>`; mwongozo unaeleza usomaji uliogawanywa katika sehemu/vikundi kwa rekodi kubwa.<sup>[[6]](#references)</sup>

Ili decode signal iliyonaswa, leta `capture.bin` kwenye PulseView kama **Raw Analog Data Without Header**, chagua thamani za unsigned 8-bit (`U8`), na uweke sample rate iliyokokotolewa kutoka `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Tumia **Logic via Threshold** kwenye channel ya analog, ukichagua threshold iliyo kati ya thamani za chini na za juu za sample.<sup>[[5]](#references)</sup> Pima upana wa start-bit safi ili kukadiria baud rate (takriban 17.36 µs kwa baud 57,600), kisha tumia UART decoder ya PulseView na uhakikishe kuwa frames kadhaa zinadecode kwa uthabiti.<sup>[[5]](#references)</sup> Edge ya kushuka pekee haithibitishi kuwa pad ni UART.

## Adapta ya CP210X UART kwenda TTY

CP210x USB-to-UART bridges hupatikana kwenye boards nyingi za prototyping na adapta za bei nafuu. Modules za kawaida huwa na pins za supply pamoja na GND, RXD, na TXD, lakini headers na viwango vya I/O hutofautiana. Thibitisha voltage halisi kutoka kwenye muundo wa board au data sheet. Kwa kawaida, unganisha GND pekee, adapter RX kwa target TX, na—baada ya kuthibitisha kuwa inapokea tu—adapter TX kwa target RX. Usiunganishe pin ya supply ya 5 V/3.3 V ya adapter isipokuwa unakusudia kuwasha target inayojulikana kuvumilia voltage hiyo.<sup>[[3]](#references)</sup>

Ikiwa adapter haitambuliki, hakikisha kuwa drivers za CP210X zimesakinishwa kwenye mfumo wa host. Adapter ikishatambuliwa na kuunganishwa, zana kama picocom, minicom au screen zinaweza kutumika.

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

Sanidi mipangilio kama vile baudrate na jina la kifaa katika chaguo la `Serial port setup`.

Baada ya kusanidi, endesha `minicom` ili kufungua UART console.

## UART Kupitia Arduino UNO R3 (Bodi Zenye Chipu ya Atmel 328p Inayoweza Kuondolewa)

Ikiwa adapta za UART Serial to USB hazipatikani, Arduino UNO R3 inaweza kutumika kwa hila ya haraka. Kwa kuwa Arduino UNO R3 hupatikana karibu kila mahali, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina adapta ya USB to Serial iliyojengwa ndani ya bodi yenyewe. Ili kupata muunganisho wa UART, ondoa tu chipu ya microcontroller ya Atmel 328p kwenye bodi. Hila hii hufanya kazi kwenye matoleo ya Arduino UNO R3 ambayo Atmel 328p haijauzwa moja kwa moja kwenye bodi (toleo la SMD ndilo linalotumika ndani yake). Unganisha pini ya RX ya Arduino (Digital Pin 0) kwenye pini ya TX ya UART Interface, na pini ya TX ya Arduino (Digital Pin 1) kwenye pini ya RX ya UART interface.

Tumia **Serial Monitor** ya Arduino IDE au terminal maalumu iliyowekwa kwenye baud rate lengwa. Mawimbi ya kawaida ya serial ya Uno R3 hutumia mantiki ya 5 V, kwa hivyo tumia level shifter au divider kabla ya kuyaunganisha kwenye kifaa lengwa cha 3.3 V au chenye voltage ya chini zaidi.

## Bus Pirate

Maandishi yafuatayo ya mawasiliano yanatumia kiolesura cha legacy Bus Pirate firmware kufuatilia matokeo ya UART. Firmware mpya zaidi ya Bus Pirate hutumia amri kama `m uart`, `{`/`}`, `monitor`, au `bridge`; rejelea nyaraka za toleo lililosakinishwa.<sup>[[2]](#references)</sup>

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

## Kunakili Firmware kupitia UART Console

UART console hutoa ufikiaji wakati kifaa kinafanya kazi kwa boot logs na, wakati mwingine, bootloader au shell ya mfumo wa uendeshaji. Hata console ya kusoma pekee hufichua ramani za kumbukumbu, viendeshi vya flash, boot arguments, mpangilio wa partitions, na matoleo ya firmware. Firmware inaweza kuwa kwenye SPI NOR/NAND, eMMC, au kifaa kingine; kwa kawaida haiendeshwi kutoka EEPROM, na faili zilizoandikwa kwenye filesystem endelevu iliyowekwa (mounted) si lazima zipotee baada ya kuwasha upya.

Kuna njia kadhaa za kupata nakala, na sehemu ya SPI inaeleza usomaji wa moja kwa moja kutoka flash ya nje. Upatikanaji unaosaidiwa na console unaweza kuwa na athari ndogo zaidi iwapo bootloader tayari ina amri salama ya kusoma, lakini kukatiza boot au kutumia amri za flash kunaweza kuathiri upatikanaji, kwa hiyo rekodi hali ya awali na epuka shughuli za kuandika/kufuta.

Kunakili firmware kwa msaada wa console mara nyingi huanza kwa kukatiza bootloader. Vifaa vingi vya Linux vilivyopachikwa hutumia **Das U-Boot**, lakini vingine hutumia bootloader za wamiliki au huzima console shirikishi.

Ili kujaribu kama bootloader shirikishi ipo, unganisha njia ya kupokea ya UART na terminal wakati kifaa lengwa hakijawashwa, anza kurekodi, kisha ukiwashe. Fuata ujumbe wa autoboot unaoonyeshwa; kulingana na build, huenda ukahitaji kubonyeza kitufe, mfululizo mfupi wa vitufe, au huenda isiwezekane kukatiza kabisa.

Ufanikiwapo kukatiza, tumia amri za ugunduzi za kusoma pekee kama `help`, `printenv` na nyinginezo ili kuelewa mpangilio wa kumbukumbu na hifadhi wa mtengenezaji huyo kabla ya kufikia anwani.

Katika U-Boot, `md` huonyesha **kumbukumbu inayoweza kufikiwa kwa anwani**, si “EEPROM” moja kwa moja. Kwanza tumia amri mahususi za bodi kama `mtd list`, `sf probe`, `mmc info`, `part list`, vigezo vya mazingira, na boot logs ili kubaini anwani sahihi iliyopangwa au kupakia eneo la flash kwenye RAM. Kisha onyesha masafa yanayojulikana baiti kwa baiti:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Rekodi matokeo ya serial kabla ya kuanza. Matokeo ya `md.b` yana anwani na safu wima ya ASCII, kwa hiyo ni uwakilishi wa maandishi badala ya picha ghafi ya ROM.

Ondoa safu wima za anwani na ASCII, unganisha sehemu za baiti za heksadesimali pekee, na uzisimbue kuwa binary (kwa mfano kwa kutumia `xxd -r -p`). Thibitisha idadi ya baiti inayotarajiwa na urekodi hash kabla ya uchanganuzi:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk kisha hutambua signatures zinazojulikana kwenye binary iliyoundwa upya. Kusoma flash moja kwa moja kupitia kiolesura kinachofaa cha SPI/eMMC/NAND kwa kawaida huwa haraka zaidi na husababisha makosa machache wakati console haiwezi kuhamisha data kwa uaminifu.

U-Boot inaweza kuzima uingiliaji, kuhitaji mfuatano maalum wa vitufe wa vendor, au kufunga amri za memory/flash. Fuata ujumbe wa autoboot na boot log badala ya kutuma herufi bila kufikiri. Ikiwa console haiwezi kuingiliwa, hifadhi boot log na utumie njia isiyoingilia ya kupata firmware.

## References

- [1] [Mwongozo wa Marejeleo wa Familia ya Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Nyaraka za Bus Pirate - Hali ya UART na mipaka ya umeme](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - Hojaji ya CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Nyaraka za U-Boot - amri ya kuonyesha memory ya `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI na instrumentation ya hardware kwa wahandisi wa reverse engineering, Sehemu ya 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Mwongozo wa Programu wa Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Kusanidi backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
