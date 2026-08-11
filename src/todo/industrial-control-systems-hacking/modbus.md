# Itifaki ya Modbus

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi wa Modbus

Modbus ni itifaki ya open application-layer inayotumiwa kwa upana na PLCs, sensors, actuators, na vifaa vingine vya viwandani. Muundo wake wa request/response hufichua coils na registers kupitia function codes. Kwa hivyo, security testing hulenga kusoma/kuandika bila ruhusa, kuchunguza traffic, replay, na tabia zisizo salama za kifaa—si kutafuta tu TCP port 502.<sup>[[1]](#references)</sup>

Deployments nyingi bado hutumia vifaa vya zamani vya serial kwa sababu upgrades zinahitaji downtime, recertification, au kubadilisha field devices. Modbus ya jadi haitoi confidentiality wala peer authentication; Modbus Security ni profile tofauti inayotumia TLS, X.509 certificates, na TCP port 802. Kwa kuwa specification iko wazi na inaweza kutekelezwa kwa kujitegemea, tabia za vendors na support ya optional functions hutofautiana, hivyo zinapaswa kufingerprintiwa badala ya kudhaniwa.<sup>[[1]](#references)[[2]](#references)</sup>

## Muundo wa Client-Server

Katika terminology ya sasa, **client** huanzisha transaction na **server** hurudisha response. Documentation ya zamani hutumia **master/slave**. Usichanganye uhusiano huu wa application na SPI au I2C: hizo ni bus protocols tofauti.<sup>[[1]](#references)</sup>

## Transports za Serial na Ethernet

Data ileile ya application ya Modbus inaweza kubebwa na serial variants (RTU au ASCII framing) na Modbus TCP. Modbus TCP huongeza MBAP header na kwa kawaida hutumia TCP port 502; serial RTU hutumia compact binary framing na CRC, huku serial ASCII ikiwakilisha bytes kama hexadecimal characters na kutumia LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Uwakilishi wa Data

Data model inajumuisha single-bit coils/discrete inputs na 16-bit input/holding registers. Thamani za multi-register, byte order, scaling, na semantic meaning hutegemea kifaa na lazima zithibitishwe dhidi ya register map ya vendor.<sup>[[1]](#references)</sup>

## Function Codes

Function codes huchagua operations kama kusoma coils (`0x01`), kusoma holding registers (`0x03`), kuandika coil/register moja (`0x05`/`0x06`), na kuandika coils/registers nyingi (`0x0F`/`0x10`). Request ya write iliyonaswa inaweza kufanyiwa replay pale deployment haina authentication ya ziada au ukaguzi wa process state. Kwa physical access iliyoidhinishwa kwenye serial runs ndefu, assessor anaweza pia kunasa au kuingiza frames moja kwa moja kwenye wiring baada ya kutambua electrical interface, termination, na njia salama ya kuunganisha. Kitendo chochote kati ya hivi kinaweza kuathiri physical process, kwa hiyo tumia lab au operational authorization iliyo wazi.<sup>[[1]](#references)[[3]](#references)</sup>

## Addressing

Vifaa vya serial hutumia unit address. Modbus TCP hutumia IP addressing pamoja na Unit Identifier katika MBAP header, jambo ambalo ni muhimu hasa wakati TCP-to-serial gateway inapopitisha requests kwa downstream units. Register references zinazoonyeshwa na product documentation zinaweza kuwa one-based (`40001`), huku protocol addresses zikiwa zero-based; hii ni chanzo cha kawaida cha off-by-one errors.<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing inajumuisha ukaguzi wa transmission errors (CRC kwa RTU na LRC kwa ASCII), na TCP hutoa transport checksum yake ya kawaida. Hizi hugundua corruption ya bahati mbaya; si cryptographic integrity wala origin authentication.<sup>[[3]](#references)</sup>

Wakati wa authorized assessment, test exposure, function codes zinazoruhusiwa, writable address ranges, exception handling, rate limits, na ikiwa network segmentation au Modbus-aware firewall inawazuia clients. Threats zinazohusika zinajumuisha passive disclosure, unauthorized command injection, replay, data forgery, na denial of service. Ratibu tests zote active na process owners kwa sababu mabadiliko yanayoonekana kuwa madogo kwenye registers yanaweza kubadilisha physical process.

## References

- [1] [Modbus Organization — Specification ya Modbus Application Protocol V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security Protocol na miongozo ya implementation](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Specification na Mwongozo wa Implementation wa Modbus over Serial Line V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
