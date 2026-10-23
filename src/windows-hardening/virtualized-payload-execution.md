# Gevirtualiseerde Payload-uitvoering en ontduiking met pasgemaakte VM's

{{#include ../banners/hacktricks-training.md}}

Payload-virtualisering stel aanvallende logika saam na 'n gastinstruksiestel en voer dit met 'n inheemse interpreter uit. Anders as 'n packer, wat uiteindelik die oorspronklike inheemse instruksies in die geheue moet blootstel, kan 'n gevirtualiseerde payload die beskermde logika regdeur sy leeftyd as bytecode behou. Dit verwyder daardie spesifieke uitpakvenster, maar verberg **nie** gedrag wat vir die host sigbaar is, soos syscalls, netwerkaktiwiteit of die VM-na-inheemse-oproepgrens nie.<sup>[[2]](#references)[[3]](#references)</sup>

## WebAssembly-herhuisvesting om statiese-analise-ontduiking te bewerkstellig

In plaas daarvan om 'n Go-nutsding met baie signatures te wysig, kan dit as 'n `wasip1`-guest saamgestel en in 'n aparte inheemse loader ingebed word. Die guest word gebou teen 'n gelapte GOROOT waarin nie-ondersteunde bewerkings soos `net.Dial`, `net.Listen`, `os/exec` en `os.Pipe` via `//go:wasmimport` delegeer; 'n Wazero-hostmodule implementeer dan sockets, prosesbewerkings, Win32-oproepe en macOS-raamwerkoproepe. Dit behou die oorspronklike projek se Go API-gebruik terwyl die meeste van sy logika na 'n geënkripteerde WASM-module verskuif word wat statiese PE-gereedskap moontlik nie verstaan nie.<sup>[[4]](#references)</sup>

### Oorbrugging van lineêre geheue na inheemse API's

'n Guest-wyser is 'n 32-bis-afset in WASM-lineêre geheue, nie 'n virtuele host-adres nie. Voor 'n inheemse oproep kan die brug 'n argument vertaal slegs wanneer dit as 'n plaaslike wyser gemerk is en binne die reeks `0x10000 <= value < wasmMemorySize` val; die resultaat is `wasmMemoryBase + value`. Die onderste grens voorkom dat klein handvatsels, vlae en `nil` herskryf word; per-API-maskers wat uit `win32metadata` gegenereer word, onderskei regte wysers van handvatsels, groottes en afstandsprosesadresse, met oorheersings vir onakkurate of dubbelsinnige metadata.<sup>[[4]](#references)</sup>

Inheemse API's kan ook host-wysers via guest-uitsetbuffers teruggee. 'n Spieëltabel kan sulke objekte guest-geheuevoorstellings toeken en 'n omgekeerde kartering na die oorspronklike host-adres behou. COM vereis dat beide die koppelvlak en sy vtable weerspieël word: datawysers kan gevolg en weerspieël word, terwyl uitvoerbare wysers in `MEM_IMAGE`-streke ondeursigtige tokens moet bly omdat WASM nie inheemse instruksies kan uitvoer nie. Hierdie model ondersteun nie host-na-guest-terugbel-API's soos `EnumWindows` of `SetWindowsHookEx` direk nie.<sup>[[4]](#references)</sup>

### WASM VM-polimorfisme per bou

Die runtime en payload kan saam met elke bou getransformeer word: skommel die opcode-na-handler-tabel, herskryf elke guest-opcode volgens die nuwe kartering, randomiseer seksie-identifiseerders, vervang die standaard `\0asm`-magic met 'n bou-spesifieke merker en verander die runtime-kas-magic. Dieselfde bronkode lewer dan byte vir byte verskillende modules op, en gewone WASM-gereedskap kan die payload nie ontleed voordat die ontleder die pasgemaakte kartering en raamwerk uit die host-loader herwin nie.<sup>[[4]](#references)</sup>

Vir reverse engineering, begin by die inheemse host eerder as om net na `\0asm` te soek: identifiseer die saamgestelde merker, module-dekripteringspad, opcode-versendingstabel en `env`-hostfunksieregistrasies, en rekonstrueer dan 'n standaardmodule of instrumenteer die invoergrens. Die brug bly 'n nuttige gedragsknooppunt omdat oproepe vir netwerkgebruik, prosesskepping, registertoegang, dinamiese laai en algemene Win32-versending daardeur gaan, selfs wanneer die ingebedde bytecode tussen boue verander.<sup>[[4]](#references)</sup>

### Kamoeflering van die buitenste Go-uitvoerbare lêer

Om net die guest te verander, laat steeds 'n herkenbare loader agter. Die gedemonstreerde transformasies voeg digte simboolprofiele wat uit wettige Go-projekte versamel is by `gopclntab` in, roteer 'n klein geloofwaardige stel DLL-invoere en wissel PE `VERSIONINFO`- plus Authenticode-identiteitstringe af. Hierdie transformasies teiken statiese en masjienleerkenmerke van die houer; hulle verwyder nie die runtime-gedrag wat deur die host-shims blootgelê word nie.<sup>[[4]](#references)</sup>

## Uitvoeringsmodel

'n Kompakte gevirtualiseerde loader kan uitvoering in die volgende lae verdeel.<sup>[[3]](#references)</sup>

1. Stel freestanding C, BOF-bronkode of runtime-biblioteke deur LLVM saam na 'n pasgemaakte bytecode-ISA.
2. Begin 'n klein inheemse interpreter en initialiseer 'n bou-spesifieke opcode-kartering.
3. Voer die PE-linker-loader self as bytecode uit: ontleed headers, karteer seksies, pas relocations toe, los invoere op en vul die IAT.
4. Hou guest-na-guest-oproepe binne die interpreter. Stuur teikens buite die bytecode-streek, soos ingevoerde DLL-funksies, deur 'n inheemse host-oproep-thunk.
5. Skuif ondersteunende funksies soos HTTP-raamwerkvorming, TLS en dele van die C-runtime agter dieselfde interpretasiegrens.

Hierdie model vermy die toekenning van 'n aparte inheemse kodestreek vir elke plugin en voorkom dat die oorspronklike payload as 'n herkenbare x86-64-instruksiestroom verskyn. Dit is steeds 'n ontduikings-/verduisteringsgrens eerder as 'n sekuriteitsgrens: die inheemse interpreter en elke eksterne effek bly waarneembaar.<sup>[[2]](#references)[[3]](#references)</sup>

## Gedeeldegeheue-hostbrug

'n Geïsoleerde VM stel wysers voor as afsette in 'n guest-buffer, dus vereis elke deurgang deur 'n host-API wyserverta ling en spesiale hantering van uitsetparameters. 'n Gedeeldegeheue-VM maak guest-adresse daarenteen geldige host-prosesadresse. Lees- en skryfbewerkings kan dus `memcpy`-agtige bewerkings gebruik, en 'n wyser wat deur 'n inheemse toekennings-ECALL teruggegee word, kan direk deur bytecode gedereferensieer word. RISC-Y Business het gedemonstreer dat hierdie ontwerp die brug kan beperk tot die verkryging van die PEB en die uitreiking van arbitrêre host-oproepe.<sup>[[1]](#references)</sup>

Vir Windows x64 kan die virtuele registerlêer die ABI weerspieël: plaas die eerste vier heelgetal- of wyserargumente in `RCX`, `RDX`, `R8` en `R9`, met latere argumente en shadow space op die stapel. Wanneer 'n virtuele `CALL` buite die bytecode-reeks oplos, pak 'n universele thunk daardie toestand in 'n inheemse oproep in en kopieer die terugkeerwaarde terug na die VM. Dit maak IAT-oproepe, heap-toekenning en socketbewerkings moontlik sonder wyserregstellings.<sup>[[2]](#references)[[3]](#references)</sup>

Die kompromis is die volledige verlies aan isolasie. Guest-geheuekorrupsie kan die host direk beïnvloed, inheemse callees kan guest-wysers behou of wysig, en die interpreter moet bytecode as ten volle vertroud hanteer. Inheems-na-VM-terugroepe benodig ook 'n omgekeerde brug; 'n VM wat slegs uitgaande oproepe ondersteun, kan nie direk aan terugroepgebaseerde API's soos `EnumWindows` voldoen nie.<sup>[[1]](#references)[[3]](#references)</sup>

## ISA-polimorfisme per bou

'n Pasgemaakte ISA met vaste breedte vereenvoudig dekodering, versending, relocations en virtuele-registerkartering. Centurion gebruik 'n 18-greep-instruksieformaat geïnspireer deur x86-64, wat kode-digtheid verruil vir voorspelbare ontleding en ook 'n moontlike pad laat om bestaande x86-64-artefakte na bytecode om te skakel.<sup>[[3]](#references)</sup>

Deur die opcode-na-handler-kartering vir elke bou te randomiseer, lewer identiese guest-logika verskillende byte-sekwensies op. Deur die karteringstabel te enkripteer en dit eers tydens runtime te herwin, word 'n stabiele opcode-woordeboek op skyf verder verwyder. Dit verydel vaste signatures en herbruikbare disassembleringsreëls, maar maak nie die inheemse dispatcher, tabeldekripteringsroetine of host-oproepgrens outomaties polimorf nie.<sup>[[3]](#references)</sup>

## Bring die uitvoeringsomgewing binne die VM

Die host-proses kan tot geheue-, syscall- en socketprimitiewe beperk word, terwyl freestanding-biblioteke hoërvlakdienste binne die VM verskaf. FreeRTOS coreHTTP kan byvoorbeeld HTTP-raamwerkvorming implementeer en mbedTLS kan TLS implementeer sonder om WinHTTP of 'n bedryfstelsel-TLS-API aan te roep. Rou sockets deur `afd.sys` of 'n soortgelyke koppelvlak word dan die nou inheemse netwerkgrens.<sup>[[3]](#references)</sup>

Hierdie **Bring Your Own Execution Environment (BYOEE)**-ontwerp kan ook PE-laai, runtimesondersteuning en 'n in-geheue-lêerstelsel agter die interpreter plaas. Dit verminder herkenbare inheemse implementasies eerder as om telemetrie uit te skakel: rou socketbewerkings bly sigbaar, en omgewings wat eksplisiete proxys of TLS-onderskepping vereis, kan verhoed dat die netwerkontwerp werk.<sup>[[3]](#references)</sup>

## Selektiewe inheemse versnelling

Die interpretasie van elke instruksie is besonder duur in publieke-sleutel-kriptografie. 'n Praktiese verdeling gebruik mbedTLS se `MBEDTLS_ALT`-hooks as 'n sagteware-koprosessor-koppelvlak: behou TLS-toestand, sertifikaatontleding, onderhandeling, toekenning en die hoëvlak-bignum-kode in bytecode, maar stuur die warm rekenkundige kernels van `bignum_core.c` deur inheemse ECALLs. In die Centurion-prototipe het `bignum.c`, `bignum_mod.c` en `bignum_mod_raw.c` gevirtualiseer gebly terwyl die binneste lusse inheems geloop het; dit het 'n ECDHE-handdruk van minute na sekondes verkort.<sup>[[3]](#references)</sup>

Maak versnellers opsioneel sodat payloads wat nie TLS benodig nie die bykomende inheemse toegangspunte kan weglaat. Hierdie patroon veralgemeen na enige interpreter-werklas: profileer eers en stel dan die kleinste moontlike inheemse primitief beskikbaar in plaas daarvan om 'n hele subsisteem buite die VM te skuif.<sup>[[3]](#references)</sup>

Centurion het die volledige ketting met 'n TLS 1.2-bind shell bekragtig: die bytecode-loader het die PE gekarteer, socket-oproepe het deur die universele thunk gegaan, mbedTLS het die protokol binne die VM hanteer en inheemse ECALLs het ECDHE-rekenkunde versnel. Die inheemse interpreter van ongeveer 18 KB het dus 'n geënkripteerde opdragkanaal ondersteun sonder om die payload as inheemse x86-64-kode te materialiseer.<sup>[[3]](#references)</sup>

## Ankerpunte vir reverse engineering en opsporing

Die volgende is praktiese ontledingsanker punte wat uit die argitektuur afgelei is; virtualisering verander waar ontleders gedrag waarneem, maar verwyder nie die gedrag self nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifiseer die fetch/decode/dispatch-lus, virtuele programteller, registerlêer en herhaalde instruksiestappe met vaste breedte.
- Dump die opcode-tabel ná runtime-dekriptering en koppel handler-adresse aan semantiese bewerkings eerder as om geënkripteerde bytecode op skyf te probeer pas.
- Stel 'n breekpunt op die universele thunk of ECALL-dispatcher om die inheemse teiken, virtuele argumentregisters, stapelargumente en terugkeerwaarde aan te teken.
- Volg PEB-toegang, uitvoeroplossing, PE-headerontleding, relocation-skryfbewerkings en IAT-vulling, selfs wanneer die loader-implementasie self bytecode is.
- Korreleer socket-skepping en `afd.sys`-verkeer met die afwesigheid van verwagte WinHTTP- of inheemse TLS-oproepe; die ontbrekende hoëvlakinvoere is 'n leidraad, nie bewys van onskadelike gedrag nie.
- Behandel inheemse rekenkundige versnellers as semantiese knooppunte: hul oproepers kan sleuteluitruiling en sertifikaatvalideringsaktiwiteit openbaar terwyl die omliggende TLS-toestandsmasjien gevirtualiseer bly.

Vir ontledingswerkvloeie wat by die dispatcher begin eerder as by die oorspronklike beheervloeigrafiek, sien die [leiding vir malware-ontleding van gevirtualiseerde packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operasionele beperkings

Virtualisering voeg interpretasieoorhoofse koste by, verhoog die kompleksiteit van toolchains en ABI's, en los nie gedragsopsporing op nie. Gedeelde geheue is uit ontwerp onveilig, rou-socket-netwerkverkeer kan agter verpligte proxys misluk, en Win32-API's wat baie terugroepe gebruik, vereis inheems-na-VM-trampoliens. Die interpreter, syscall-brug en enige inheemse versnellers bly ook 'n konvensionele inheemse voetspoor wat verdedigers kan signatureer of instrumenteer.<sup>[[2]](#references)[[3]](#references)</sup>

## Verwante bladsye

Vir ontleding van VMProtect 3.x-packing, sien [geëmuleerde uitpak en invoerherstel](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Bou van 'n RISC-V-virtuele masjien vir payload-verduistering](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming in die era van EDR — ontduiking deur malware-virtualisering](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Bring jou eie uitvoeringsomgewing](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Betree die WasmForge: Sliver na WebAssembly saamstel](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
