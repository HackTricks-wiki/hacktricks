# Die Modbus-protokol

{{#include ../../banners/hacktricks-training.md}}

## Inleiding tot Modbus

Modbus is 'n oop application-layer-protokol wat wyd deur PLC's, sensors, aktuators en ander industriële toestelle geïmplementeer word. Sy versoek/antwoord-model stel coils en registers deur middel van function codes bloot. Security testing fokus daarom op ongemagtigde lees- en skryfbewerkings, verkeerswaarneming, replay en onveilige toestelgedrag — nie bloot op die vind van TCP-poort 502 nie.<sup>[[1]](#references)</sup>

Baie implementerings behou legacy-serietoerusting omdat opgraderings stilstand, hersertifisering of die vervanging van veldtoestelle vereis. Tradisionele Modbus bied nóg vertroulikheid nóg peer-authentication; Modbus Security is 'n afsonderlike TLS-gebaseerde profiel wat X.509-sertifikate en TCP-poort 802 gebruik. Omdat die spesifikasie publiek en onafhanklik implementeerbaar is, verskil vendor-gedrag en ondersteuning vir opsionele function codes, en moet dit gefingerprint word eerder as om dit te aanvaar.<sup>[[1]](#references)[[2]](#references)</sup>

## Die client-server-argitektuur

In huidige terminologie begin 'n **client** 'n transaksie en stuur 'n **server** 'n antwoord terug. Ouer dokumentasie gebruik **master/slave**. Moenie hierdie application-verhouding met SPI of I2C verwar nie: dit is verskillende bus-protokolle.<sup>[[1]](#references)</sup>

## Serial- en Ethernet-transporte

Dieselfde Modbus-application-data kan deur serial-variante (RTU- of ASCII-framing) en deur Modbus TCP gedra word. Modbus TCP voeg 'n MBAP-header by en gebruik normaalweg TCP-poort 502; serial RTU gebruik kompakte binêre framing en 'n CRC, terwyl serial ASCII grepe as heksadesimale karakters voorstel en 'n LRC gebruik.<sup>[[1]](#references)[[3]](#references)</sup>

## Datarepresentasie

Die datamodel bestaan uit enkelbis-coils/diskrete inputs en 16-bis-input/holding registers. Waardes wat oor verskeie registers strek, byte order, scaling en semantiese betekenis is toestelspesifiek en moet teen die vendor se register map bevestig word.<sup>[[1]](#references)</sup>

## Function codes

Function codes kies bewerkings soos die lees van coils (`0x01`), die lees van holding registers (`0x03`), die skryf van 'n enkele coil/register (`0x05`/`0x06`) en die skryf van veelvuldige coils/registers (`0x0F`/`0x10`). 'n Vasgelegde skryfversoek kan replaybaar wees wanneer die implementering geen kompenserende authentication- of process-state-kontroles het nie. Met gemagtigde fisiese toegang tot lang serial-kabels kan 'n assessor ook frames direk op die bedrading vaslê of injecteer nadat die elektriese interface, terminering en veilige verbindingsmetode geïdentifiseer is. Enige van hierdie handelinge kan die fisiese proses beïnvloed; gebruik dus 'n laboratorium of uitdruklike operasionele magtiging.<sup>[[1]](#references)[[3]](#references)</sup>

## Adressering

Serial-toestelle gebruik 'n unit address. Modbus TCP gebruik IP-adressering plus 'n Unit Identifier in die MBAP-header, wat veral relevant is wanneer 'n TCP-to-serial gateway versoeke na downstream units roeteer. Registerverwysings wat deur produkdokumentasie getoon word, kan eengebaseerd (`40001`) wees, terwyl protocol addresses nulgebaseerd is — 'n algemene bron van off-by-one-foute.<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing sluit transmissiefoutkontroles in (CRC vir RTU en LRC vir ASCII), en TCP verskaf sy normale transport checksum. Dit bespeur toevallige korrupsie; dit is nie kriptografiese integriteit of origin authentication nie.<sup>[[3]](#references)</sup>

Tydens 'n gemagtigde assessering moet blootstelling, toegelate function codes, skryfbare address ranges, exception handling, rate limits en die vraag of network segmentation of 'n Modbus-aware firewall clients beperk, getoets word. Relevante threats sluit passiewe openbaarmaking, ongemagtigde command injection, replay, data forgery en denial of service in. Koördineer alle aktiewe toetse met proses-eienaars, omdat klaarblyklik klein registerveranderinge 'n fisiese proses kan verander.

## References

- [1] [Modbus Organization — Modbus Application Protocol-spesifikasie V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security Protocol en implementeringsgidse](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Modbus over Serial Line-spesifikasie en implementeringsgids V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
