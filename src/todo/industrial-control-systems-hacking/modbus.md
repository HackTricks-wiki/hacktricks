# Itifaki ya Modbus

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi wa Itifaki ya Modbus

Itifaki ya Modbus ni itifaki inayotumika sana katika Industrial Automation and Control Systems. Modbus huwezesha mawasiliano kati ya vifaa mbalimbali kama vile programmable logic controllers (PLCs), sensors, actuators, na vifaa vingine vya viwandani. Kuelewa Itifaki ya Modbus ni muhimu kwa sababu ndiyo communication protocol inayotumika zaidi katika ICS na ina attack surface kubwa kwa sniffing na hata injecting commands kwenye PLCs.

Hapa, concepts zimeelezwa kwa pointi ili kutoa muktadha kuhusu itifaki na jinsi inavyofanya kazi. Changamoto kubwa zaidi katika usalama wa ICS system ni gharama ya implementation na upgradation. Protocols na standards hizi zilibuniwa mwanzoni mwa miaka ya 80 na 90 na bado zinatumika kwa kiwango kikubwa. Kwa kuwa industry ina vifaa na connections nyingi, kufanya upgrade ya vifaa ni vigumu sana, jambo linalowapa hackers fursa ya kushughulika na protocols zilizopitwa na wakati. Attacks dhidi ya Modbus ni karibu kuepukika kwa sababu itaendelea kutumika bila upgradation ikiwa operation yake ni muhimu kwa industry.

## Client-Server Architecture

Itifaki ya Modbus kwa kawaida hutumika katika Client Server Architecture, ambapo master device (client) huanzisha mawasiliano na slave devices mmoja au zaidi (servers). Hii pia huitwa Master-Slave architecture, ambayo hutumika sana katika electronics na IoT pamoja na SPI, I2C, n.k.

## Matoleo ya Serial na Etherent

Itifaki ya Modbus imeundwa kwa Serial Communication na Ethernet Communications. Serial Communication hutumika sana katika legacy systems, huku vifaa vya kisasa vikiunga mkono Ethernet, inayotoa data rates za juu na kufaa zaidi kwa modern industrial networks.

## Uwakilishi wa Data

Data hutumwa katika Modbus protocol ikiwa ASCII au Binary, ingawa binary format hutumika kwa sababu ya compactibility yake na vifaa vya zamani.

## Function Codes

ModBus Protocol hufanya kazi kwa transmission ya function codes maalum zinazotumika kuendesha PLCs na control devices mbalimbali. Sehemu hii ni muhimu kuelewa kwa sababu replay attacks zinaweza kufanywa kwa retransmitting function codes. Legacy devices haziungi mkono encryption yoyote kwa data transmission na kwa kawaida huwa na wires ndefu zinazoviunganisha, jambo linalowezesha tampering ya wires hizo na capturing/injecting data.

## Addressing ya Modbus

Kila kifaa kwenye network kina address yake ya kipekee, ambayo ni muhimu kwa mawasiliano kati ya vifaa. Protocols kama Modbus RTU, Modbus TCP, n.k. hutumika kutekeleza addressing na hufanya kazi kama transport layer ya data transmission. Data inayohamishwa huwa katika Modbus protocol format iliyo na message.

Zaidi ya hayo, Modbus pia hutekeleza error checks ili kuhakikisha integrity ya data iliyotumwa. Lakini zaidi ya yote, Modbus ni Open Standard na mtu yeyote anaweza kuitekeleza katika vifaa vyake. Hii ilisababisha itifaki hii kuwa global standard na kutumika kwa kiwango kikubwa katika industrial automation industry.

Kwa sababu ya matumizi yake makubwa na ukosefu wa upgradations, kuishambulia Modbus hutoa faida kubwa kutokana na attack surface yake. ICS inategemea sana mawasiliano kati ya vifaa, na attacks zozote dhidi yake zinaweza kuwa hatari kwa operation ya industrial systems. Attacks kama replay, data injection, data sniffing na leaking, Denial of Service, data forgery, n.k. zinaweza kufanywa ikiwa medium ya transmission itatambuliwa na attacker.

{{#include ../../banners/hacktricks-training.md}}
