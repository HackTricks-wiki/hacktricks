# Gevirtualiseerde Payload-uitvoering en Custom VM-ontduiking

{{#include ../banners/hacktricks-training.md}}

Payload-virtualisering kompileer offensiewe logika na ’n guest-instruksiestel en voer dit met ’n native interpreter uit. Anders as ’n packer, wat uiteindelik die oorspronklike native instruksies in die geheue moet blootlê, kan ’n gevirtualiseerde payload die beskermde logika vir sy hele leeftyd as bytecode behou. Dit verwyder daardie spesifieke uitpakvenster, maar verberg **nie** gedrag wat op die host sigbaar is, soos syscalls, netwerkaktiwiteit of die VM-na-native-oproepgrens nie.<sup>[[2]](#references)[[3]](#references)</sup>

## Uitvoeringsmodel

’n Kompakte gevirtualiseerde loader kan uitvoering in die volgende lae verdeel.<sup>[[3]](#references)</sup>

1. Kompileer freestanding C, BOF-bronkode of runtime-biblioteke deur LLVM na ’n custom bytecode-ISA.
2. Begin ’n klein native interpreter en initialiseer ’n bou-spesifieke opcode-kartering.
3. Voer die PE linker-loader self as bytecode uit: ontleed headers, karteer seksies, pas relocations toe, los imports op en vul die IAT.
4. Hou guest-na-guest-oproepe binne die interpreter. Stuur teikens buite die bytecode-streek, soos geïmporteerde DLL-funksies, deur ’n native host-call thunk.
5. Plaas ondersteunende fasiliteite soos HTTP-framing, TLS en dele van die C-runtime agter dieselfde interpretasiegrens.

Hierdie model vermy die toekenning van ’n afsonderlike native kodegebied vir elke plugin en keer dat die oorspronklike payload as ’n herkenbare x86-64-instruksiestroom verskyn. Dit is steeds ’n ontduikings-/verduisteringsgrens, nie ’n sekuriteitsgrens nie: die native interpreter en elke eksterne effek bly waarneembaar.<sup>[[2]](#references)[[3]](#references)</sup>

## Gedeeldegeheue-hostbrug

’n Geïsoleerde VM stel pointers as offsets in ’n guest-buffer voor, dus vereis elke host-API-kruising pointervertaling en spesiale hantering van uitvoerparameters. ’n Gedeeldegeheue-VM maak eerder guest-adresse geldige host-prosesadresse. Lees- en skryfbewerkings kan gevolglik `memcpy`-agtige bewerkings gebruik, en ’n pointer wat deur ’n native toekenning-ECALL teruggestuur word, kan direk deur bytecode gedereferensieer word. RISC-Y Business het getoon dat hierdie ontwerp die brug kan beperk tot die verkryging van die PEB en die uitvoer van arbitrêre host-oproepe.<sup>[[1]](#references)</sup>

Vir Windows x64 kan die virtuele registerlêer die ABI weerspieël: plaas die eerste vier heelgetal- of pointerargumente in `RCX`, `RDX`, `R8` en `R9`, met latere argumente en shadow space op die stack. Wanneer ’n virtuele `CALL` buite die bytecode-reeks oplos, rangskik ’n universele thunk daardie toestand vir ’n native oproep en kopieer die terugkeerwaarde terug na die VM. Dit maak IAT-oproepe, heap-toekenning en socket-bewerkings moontlik sonder pointer-aanpassings.<sup>[[2]](#references)[[3]](#references)</sup>

Die kompromie is die algehele verlies aan isolasie. Korrupsie van guest-geheue kan die host direk beïnvloed, native callee-funksies kan guest-pointers behou of wysig, en die interpreter moet bytecode as ten volle vertroud beskou. Native-na-VM-terugroepe benodig ook ’n omgekeerde brug; ’n VM wat slegs uitgaande oproepe ondersteun, kan nie direk aan callback-gebaseerde API’s soos `EnumWindows` voldoen nie.<sup>[[1]](#references)[[3]](#references)</sup>

## ISA-polimorfisme per bou

’n Custom ISA met vaste breedte vereenvoudig dekodering, dispatch, relocations en kartering van virtuele registers. Centurion gebruik ’n 18-greep-instruksieformaat, geïnspireer deur x86-64. Dit verruil kode-digtheid vir voorspelbare ontleding en laat ook ’n moontlike pad oop om bestaande x86-64-artefakte na bytecode om te skakel.<sup>[[3]](#references)</sup>

Deur die opcode-na-handler-kartering vir elke bou te ewekansig te verander, lewer identiese guest-logika verskillende greepvolgordes op. Deur die karteringstabel te enkripteer en dit eers tydens runtime te herstel, word ’n stabiele opcode-woordeboek op skyf verder verwyder. Dit bemoeilik vaste signatures en herbruikbare disassemblereëls, maar maak nie die native dispatcher, tabel-dekripsieroetine of host-call-grens vanself polimorfies nie.<sup>[[3]](#references)</sup>

## Bring die uitvoeringsomgewing na die VM

Die host-proses kan beperk word tot geheue-, syscall- en socket-primitiewe, terwyl freestanding-biblioteke hoërvlakdienste binne die VM verskaf. FreeRTOS coreHTTP kan byvoorbeeld HTTP-framing implementeer, en mbedTLS kan TLS implementeer sonder om WinHTTP of ’n bedryfstelsel-TLS-API aan te roep. Rou sockets deur `afd.sys` of ’n soortgelyke koppelvlak vorm dan die nou native netwerkgrens.<sup>[[3]](#references)</sup>

Hierdie **Bring Your Own Execution Environment (BYOEE)**-ontwerp kan ook PE-laai, runtime-ondersteuning en ’n in-geheue-lêerstelsel agter die interpreter plaas. Dit verminder herkenbare native implementasies eerder as om telemetrie uit te skakel: rou socket-bewerkings bly sigbaar, en omgewings wat eksplisiete proxies of TLS-onderskepping vereis, kan keer dat die netwerkontwerp werk.<sup>[[3]](#references)</sup>

## Selektiewe native versnelling

Die interpretasie van elke instruksie is besonder duur in publieke-sleutel-kriptografie. ’n Praktiese verdeling gebruik mbedTLS se `MBEDTLS_ALT`-hooks as ’n sagteware-medeverwerker-koppelvlak: behou TLS-toestand, sertifikaatontleding, onderhandeling, toekenning en die hoëvlak-bignum-kode in bytecode, maar stuur die warm rekenkundige kernels vanaf `bignum_core.c` deur native ECALLs. In die Centurion-prototipe het `bignum.c`, `bignum_mod.c` en `bignum_mod_raw.c` gevirtualiseer gebly terwyl die binneste lusse native uitgevoer is. Dit het ’n ECDHE-handdruk van minute tot sekondes verkort.<sup>[[3]](#references)</sup>

Maak versnellers opsioneel sodat payloads wat nie TLS benodig nie, die bykomende native toegangspunte kan weglaat. Hierdie patroon geld vir enige interpreter-werklas: profileer eers en stel dan die kleinste moontlike native primitief beskikbaar, eerder as om ’n hele substelsel buite die VM te skuif.<sup>[[3]](#references)</sup>

Centurion het die volledige ketting met ’n TLS 1.2 bind shell bekragtig: die bytecode-loader het die PE gekarteer, socket-oproepe het deur die universele thunk gegaan, mbedTLS het die protokol binne die VM hanteer, en native ECALLs het ECDHE-rekenkunde versnel. Die native interpreter van ongeveer 18 KB het dus ’n geënkripteerde bevelkanaal ondersteun sonder om die payload as native x86-64-kode te materialiseer.<sup>[[3]](#references)</sup>

## Omgekeerde ingenieurswese- en opsporingsankers

Die volgende is praktiese ontledingsankers wat uit die argitektuur afgelei is; virtualisering verander waar ontleders gedrag waarneem, maar skakel nie die gedrag self uit nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifiseer die fetch/decode/dispatch-lus, virtuele programteller, registerlêer en herhaalde instruksiestappe met vaste breedte.
- Dump die opcode-tabel ná runtime-dekripsie en karteer handler-adresse terug na semantiese bewerkings, eerder as om geënkripteerde bytecode op skyf te probeer herken.
- Stel ’n breekpunt op die universele thunk of ECALL-dispatcher om die native teiken, virtuele argumentregisters, stack-argumente en terugkeerwaarde aan te teken.
- Volg PEB-toegang, export-resolusie, PE-header-ontleding, relocation-skrywings en IAT-vulling, selfs wanneer die loader-implementering self bytecode is.
- Korrelleer socket-skepping en `afd.sys`-verkeer met die afwesigheid van verwagte WinHTTP- of native TLS-oproepe; die ontbrekende hoëvlak-imports is ’n leidraad, nie bewys van onskadelike gedrag nie.
- Behandel native rekenkundige versnellers as semantiese knelpunte: hul oproepers kan sleuteluitruiling en sertifikaatvalideringsaktiwiteit blootlê terwyl die omliggende TLS-toestandsmasjien gevirtualiseer bly.

Vir ontledingswerkvloeie wat by die dispatcher eerder as die oorspronklike beheervloeigrafiek begin, sien die [leiding vir malware-ontleding oor die virtualisering van packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operasionele beperkings

Virtualisering voeg interpretasie-oorhoofse koste by, verhoog die kompleksiteit van die toolchain en ABI, en los nie gedragsopsporing op nie. Gedeelde geheue is ontwerp-onveilig, rou-socket-netwerkverkeer kan agter verpligte proxies misluk, en Win32-API’s met baie callbacks vereis native-na-VM-trampolines. Die interpreter, syscall-brug en enige native versnellers bly ook ’n konvensionele native voetspoor wat verdedigers kan signatuurherken of instrumenteer.<sup>[[2]](#references)[[3]](#references)</sup>

## Verwante bladsye

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Bou van ’n RISC-V-virtuele masjien vir payload-verduistering](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming in die era van EDR — ontduiking deur malware-virtualisering](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Bring jou eie uitvoeringsomgewing](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
