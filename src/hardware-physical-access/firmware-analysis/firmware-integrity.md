# Firmware-integriteit

{{#include ../../banners/hacktricks-training.md}}

Wanneer ’n gemagtigde assessering swak of ontbrekende firmware-handtekeningverifikasie aantoon, kan ’n gewysigde firmwarebeeld die impak op integriteit demonstreer. Die volgende laboratoriumwerkvloei voeg ’n bind shell by, terwyl die oorspronklike onttrekkings-, emulasie- en herverpakkingstappe behoue bly.<sup>[[2]](#references)[[3]](#references)</sup>

1. Die firmware kan met firmware-mod-kit (FMK) onttrek word.
2. Die teikenfirmware se argitektuur en endianiteit moet geïdentifiseer word.
3. ’n Kruiskompileerder kan met Buildroot of ander geskikte metodes vir die omgewing gebou word.
4. Die backdoor kan met die kruiskompileerder gebou word.
5. Die backdoor kan na die onttrekte firmware se /usr/bin-gids gekopieer word.
6. Die toepaslike QEMU-binêre lêer kan na die onttrekte firmware se rootfs gekopieer word.
7. Die backdoor kan met chroot en QEMU geëmuleer word.
8. Die backdoor kan via netcat bereik word.
9. Die QEMU-binêre lêer moet uit die onttrekte firmware se rootfs verwyder word.
10. Die gewysigde firmware kan met FMK herverpak word.
11. Die firmware met die backdoor kan getoets word deur dit met firmware analysis toolkit (FAT) te emuleer en met netcat aan die teiken se backdoor-IP-adres en -poort te koppel.

As ’n root-shell reeds deur dinamiese analise, selflaaiprogrammanipulasie of hardeware-sekuriteitstoetse verkry is, kan voorafgecompileerde toetsbinêre lêers soos implants of reverse shells uitgevoer word. Metasploit se `msfvenom` kan ’n argitektuurspesifieke payload vir hierdie valideringswerkvloei genereer:<sup>[[4]](#references)</sup>

1. Die teikenfirmware se argitektuur en endianiteit moet geïdentifiseer word.
2. Msfvenom kan gebruik word om die teikenpayload, aanvaller-gasheer se IP-adres, luisterpoortnommer, lêertipe, argitektuur, platform en uitvoerlêer te spesifiseer.
3. Die payload kan na die gekompromitteerde toestel oorgedra word, en daar kan seker gemaak word dat dit uitvoertoestemmings het.
4. Metasploit kan voorberei word om inkomende versoeke te hanteer deur msfconsole te begin en die instellings volgens die payload op te stel.
5. Die meterpreter reverse shell kan op die gekompromitteerde toestel uitgevoer word.

## Ongeverifieerde vervoerbrûe na geprivilegieerde opdateringsprotokolle

’n Algemene ontwerpfout in ingebedde stelsels is om **dieselfde interne opdragprotokol oor verskeie vervoermetodes bloot te stel**, maar net een daarvan te verifieer. Byvoorbeeld, USB vereis dalk uitdaging-antwoord-verifikasie, terwyl BLE bloot ongeverifieerde **GATT-writes** na dieselfde geprivilegieerde firmware-opdateringshanteerder aanstuur.<sup>[[1]](#references)</sup>

Tipiese offensiewe werkvloei:

1. Lys die BLE GATT-databasis op en identifiseer skryfbare eienskappe wat deur die amptelike mobiele toepassing gebruik word.
2. Snuffel die toepassing se verkeer af en soek **magic bytes / opcodes** wat met die bedrade protokol ooreenstem.
3. Herhaal geprivilegieerde opdragte oor BLE **sonder om te paar** en verifieer of sensitiewe bewerkings steeds werk.
4. As firmware-opgradering-, konfigurasieskryf-, ontfoutings- of fabriekstoets-opcodes bereikbaar is, behandel BLE as ’n **radiobereikbare adminpoort**.

Vinnige kontroles:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Dinge om tydens reverse engineering te verifieer:

- Vereis BLE **pairing/bonding**, of net ’n gewone verbinding?
- Word alle transportlae na dieselfde interne dispatcher table herlei?
- Word bevoorregte opcodes verskillend gefiltreer op USB / BLE / UART / Wi-Fi?
- Kan die mobiele toepassing firmware-opdatering-, herstel- of diagnostiese handlers op afstand aktiveer?

## Firmwarehouers wat slegs ’n kontrolesom gebruik, bevat steeds firmware wat deur ’n aanvaller beheer word

’n Firmwarehouer wat slegs deur ’n **ongesleutelde kontrolesom** (CRC32, SHA-256, MD5, ens.) beskerm word, spoor korrupsie op, maar bevestig **nie egtheid nie**. As die aanvaller die opdateringsroetine kan bereik, kan hulle die image wysig, die kontrolesom herbereken en arbitrêre kode flits.<sup>[[1]](#references)</sup>

Waarskuwingstekens tydens RE:

- Opdateringskode valideer slegs ’n kontrolesomblok aan die einde, soos `CHK2`, `CRC` of `SHA256`.
- Geen handtekeningverifikasie of secure-boot trust anchor is teenwoordig nie.
- Geen toestelgebonde MAC / HMAC / geverifieerde enkripsie word gebruik nie.
- Herstelmodus aanvaar dieselfde ongeverifieerde image-formaat.

Praktiese validasievloei:

1. Pak die firmwarehouer uit en identifiseer die bootloader, hooffirmware en integriteitsmetadata.
2. Wysig ’n onskadelike string of banier in die image.
3. Herbereken die kontrolesom presies soos die opdateringsprogram dit verwag.
4. Flits die image weer deur die gewone opdateringspad.
5. Bevestig die verandering tydens selflaai om arbitrêre firmwarevervanging te bewys.

As dit oor ’n afstandbereikbare transportlaag soos BLE/Wi-Fi werk, is die kwesbaarheid in wese **OTA-firmwarevervanging sonder verifikasie**.

## Gefragmenteerde opdateringstoestand en skryfbare integriteitsmetadata

’n Opdateringsprogram kan ’n getekende firmwarekopskrif tydens installasie verifieer, maar steeds images selflaai deur slegs ’n gestoorde integriteitshash te gebruik. Op die Cypherock X1 het die Bootloader afsonderlike Firewall-take aangeroep om die kopskrif te verifieer en weergawe/grootte in RAM te plaas, die firmwarehandtekening in RAM te stoor, die geskryfde image te verifieer en uiteindelik die image se hash in aanhoudende Primary Bootloader Data te stoor. Die handtekening self is nie aanhoudend gestoor nie. Hierdie take kon afsonderlik aangeroep word, in plaas daarvan om een geverifieerde opdateringstransaksie af te dwing.<sup>[[5]](#references)</sup>

Met MCU-kode-uitvoering en Flash-skryftoegang het die gerapporteerde aanval die toepassing-image herskryf, die weergawe-/groottewaardes in Bootloader-RAM wat met die Firewall gedeel is, verander, en daarna die finale metadatakaak aangeroep om die kwaadwillige image se hash te stoor en die normale selflaaitoestand te herstel. Die normale selflaai-integriteitskontrole het daardie hash aanvaar sonder om ’n handtekening weer te verifieer. Wanneer jy ’n soortgelyke opdateringsprogram ondersoek, volg **watter komponent elke taak kan aanroep**, waar geverifieerde waardes gestoor word, en of die selflaaibesluit die *dieselfde image* staaf waarvan die hash gestoor is. Dit is ’n nouer geval as ’n image-formaat wat slegs ’n kontrolesom gebruik: handtekeningverifikasie was beskikbaar, maar die toestandsverandering was nie daaraan gekoppel nie.<sup>[[5]](#references)</sup>

## Secure-element-handtekeninge oor onbetroubare firmwaremetings

’n Secure element staaf nie lopende kode bloot deur ’n hash te onderteken wat deur daardie kode verskaf word nie. In dieselfde beursie het die secure element die toestelreeksnommer onderteken, en daarna die XOR van ’n cloud-nonce en ’n firmwarehash wat deur die MCU verskaf is. Gekompromitteerde firmware kon ’n verwagte hash aanbied om onderteken te word terwyl dit ander grepe uitvoer. Die metgeselkliënt het ook die firmwareweergawe aan die cloud gestuur, dus het die verifieerder se verwagte-hash-vergelyking steeds gesteun op ’n MCU-oorsprongmeting eerder as ’n onafhanklike lees van Flash.<sup>[[5]](#references)</sup>

Die toestelresultaat was ’n afsonderlike trust boundary: die cloud het die toestel nagegaan, maar die toestel het nie die cloud se uitspraak geverifieer nie. ’n Gewysigde kliënt kon plaaslike sukses aan ’n gekompromitteerde toestel rapporteer. Toets die oorsprong van die meting en die verifikasie van die antwoord afsonderlik; ’n geldige secure-element-handtekening en ’n suksesboodskap bewys nie op hul eie dat die geïnstalleerde toepassing eg is nie.<sup>[[5]](#references)</sup>

Vir die openbaarmaking van beskermde kode wat die ontleding van hierdie opdateringsprogram moontlik gemaak het, sien [Verkryging van Firewall copy-task-firmware](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Verander ’n vertroude USB-randtoestel in BadUSB deur firmware te herflits

Wanneer die gasheertoestel die teikentoestel reeds oor USB vertrou, hoef kwaadwillige firmware dalk nie ’n hele nuwe USB-stack te implementeer nie. ’n Veel makliker omskakeling is dikwels om **bestaande HID-ondersteuning te hergebruik**.<sup>[[1]](#references)</sup>

Nuttige patroon:

1. Kyk of die toestel reeds as ’n **HID Consumer Control** / media- / vendor-HID-koppelvlak enumerateer.
2. Vind die bestaande **HID-report descriptor** in die firmware.
3. Voeg descriptor-inskrywings by of vervang dit sodat die toestel ook **sleutelbord**-vermoë adverteer.
4. Hergebruik bestaande firmware-roetines wat reeds HID-verslae stuur, eerder as om ’n nuwe transportimplementering te skryf.
5. Spuit sleuteldruk- en sleutelvrystellingverslae in om opdragte op die gasheer te tik.

Dit verander ’n firmwarekompromittering in **gasheerverromittering**, omdat die rekenaar die herflitste randtoestel as ’n wettige sleutelbord sal vertrou.

### Minimale assesseringskontrolelys

- Toon `dmesg`, Device Manager of USB-descriptors ’n bestaande HID-koppelvlak?
- Is daar ekstra ruimte naby die report descriptor, of ’n verplaasbare descriptortabel?
- Kan bestaande media-beheer-stuurroetines vir sleutelbordverslae hergebruik word?
- Sal die gasheer die nuwe sleutelbordkoppelvlak outomaties aanvaar nadat die firmware herflits is?

## Betroubare payload-uitvoering binne RTOS-firmware

In plaas daarvan om brose trampolines in willekeurige kodepaaie in te voeg, soek **bestaande RTOS-take** wat tydens normale werking ongebruik of van min belang is.<sup>[[1]](#references)</sup>

Waarom dit nuttig is:

- Die skeduleerder begin jou payload natuurlik tydens selflaai.
- Jy vermy korrupsie van kritieke beheervloei.
- Uitgestelde payloads sal minder waarskynlik watchdog-terugstellings veroorsaak as wanneer hulle binne ’n USB-/netwerkhandler met streng latensievereistes loop.

Goeie teikens is diagnostiese, fabriekstoets-, telemetrie- of koprosessordienstake wat tydens normale gebruik onaktief lyk.

## Vinnige exploit-iterasie: hergebruik onskadelike protokolhandlers

Sodra firmware-patching moontlik is, is ’n kompakte manier om RE te versnel om ’n onskadelike opdraghandler (byvoorbeeld ’n **echo/debug-opcode**) met pasgemaakte **geheuelees- / skryf- / uitvoerprimitiewe** te oorskryf. Dit vermy dat die firmware vir elke eksperiment volledig herflits moet word en is veral nuttig wanneer die toestel die gewysigde handler oor ’n vinnige bedrade transportlaag ondersteun.<sup>[[1]](#references)</sup>

Gebruik dit om:

- Scatter-loaded geheuekaarte te verifieer
- Heap-/taaktoestand intyds te inspekteer
- Klein payloads te toets voordat jy dit in flash inbrand
- Funksiewysers, stringe en descriptortabelle veilig te herwin

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - How to use `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [How And Why We Hacked Cypherock Hardware Wallet: The Full Story](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
