# Utekelezaji wa Payload uliovirtualishwa na Ukwepaji wa VM Maalum

{{#include ../banners/hacktricks-training.md}}

Virtualization ya payload hukompile mantiki ya kushambulia kuwa guest instruction set na kuiendesha kwa native interpreter. Tofauti na packer, ambayo hatimaye lazima ifichue native instructions asilia kwenye memory, payload iliyovirtualishwa inaweza kuhifadhi mantiki iliyolindwa kama bytecode kwa muda wote wa uendeshaji wake. Hii huondoa dirisha hilo mahususi la unpacking, lakini **haifichi** tabia zinazoonekana kwa host kama syscalls, shughuli za mtandao, au mpaka wa miito kutoka VM kwenda native.<sup>[[2]](#references)[[3]](#references)</sup>

## Kuendesha WebAssembly upya ili kukwepa static analysis

Badala ya kuhariri zana ya Go yenye signature nyingi, inaweza kukompilewa kama guest ya `wasip1` na kupachikwa ndani ya native loader tofauti. Guest hujengwa dhidi ya GOROOT iliyopatchiwa ambamo operesheni zisizotumika kama `net.Dial`, `net.Listen`, `os/exec` na `os.Pipe` huelekezwa kupitia `//go:wasmimport`; kisha host module ya Wazero hutekeleza sockets, operesheni za process, miito ya Win32 na miito ya macOS framework. Hii huhifadhi matumizi ya Go API ya mradi asilia huku ikihamisha sehemu kubwa ya mantiki yake kwenye module ya WASM iliyosimbwa kwa njia fiche ambayo zana za static PE huenda zisiweze kuielewa.<sup>[[4]](#references)</sup>

### Kuunganisha linear memory na native APIs

Guest pointer ni offset ya biti 32 ndani ya WASM linear memory, si host virtual address. Kabla ya native call, bridge inaweza kutafsiri argument tu pale inapowekwa alama kuwa local pointer na iko katika masafa ya `0x10000 <= value < wasmMemorySize`, na hivyo kutoa `wasmMemoryBase + value`. Kikomo cha chini huzuia handles ndogo, flags na `nil` zisibadilishwe; masks za kila API zinazozalishwa kutoka `win32metadata` hutofautisha pointers halisi na handles, sizes na anwani za remote-process, pamoja na overrides za metadata isiyo sahihi au yenye utata.<sup>[[4]](#references)</sup>

Native APIs pia zinaweza kurudisha host pointers kupitia guest output buffers. Jedwali la mirror linaweza kuipa objects hizo uwakilishi kwenye guest memory na kuhifadhi mapping ya kurudi kwenye anwani asilia ya host. COM inahitaji ku-mirror interface na vtable yake: data pointers zinaweza kufuatwa na ku-mirror-iwa, ilhali executable pointers katika maeneo ya `MEM_IMAGE` lazima zibaki opaque tokens kwa sababu WASM haiwezi kutekeleza native instructions. Muundo huu hautumii moja kwa moja callback APIs zinazotoka host kwenda guest kama `EnumWindows` au `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### WASM VM polymorphism ya kila build

Runtime na payload zinaweza kubadilishwa pamoja kwenye kila build: changanya mpangilio wa jedwali la opcode-to-handler, andika upya kila guest opcode itumie mapping mpya, badilisha vitambulisho vya section bila mpangilio, badilisha alama ya kawaida ya `\0asm` kwa alama maalum ya build na ubadilishe cache magic ya runtime. Hivyo, source ileile huzalisha modules zenye byte sequences tofauti, na zana za kawaida za WASM haziwezi kuchanganua payload hadi mchambuzi apate mapping na framing maalum kutoka kwa host loader.<sup>[[4]](#references)</sup>

Kwa reverse engineering, anza na native host badala ya kuchanganua kwa kutafuta `\0asm` pekee: tambua alama iliyokompilewa, njia ya kusimbua module, jedwali la opcode dispatch na usajili wa host functions za `env`, kisha tengeneza upya standard module au weka instrumentation kwenye mpaka wa import. Bridge bado ni sehemu muhimu ya kuangalia tabia kwa sababu miito ya networking, uundaji wa process, ufikiaji wa registry, dynamic loading na generic Win32 dispatch hupitia hapo hata bytecode iliyopachikwa inapobadilika kati ya builds.<sup>[[4]](#references)</sup>

### Kuficha sifa za Go executable ya nje

Kubadilisha guest pekee bado huacha loader inayotambulika. Mabadiliko yaliyoonyeshwa huchanganya symbol profiles nzito zilizokusanywa kutoka kwa miradi halali ya Go ndani ya `gopclntab`, huzungusha seti ndogo inayoonekana ya DLL imports, na hubadilisha PE `VERSIONINFO` pamoja na Authenticode identity strings. Mabadiliko haya hulenga vipengele vya static na machine learning vya container; hayaondoi tabia ya runtime inayoonyeshwa na host shims.<sup>[[4]](#references)</sup>

## Muundo wa utekelezaji

Virtualized loader fupi inaweza kugawa utekelezaji katika tabaka zifuatazo.<sup>[[3]](#references)</sup>

1. Kisha kompilisha freestanding C, BOF source, au runtime libraries kupitia LLVM kuwa custom bytecode ISA.
2. Anzisha native interpreter ndogo na uanzishe opcode mapping maalum ya build.
3. Endesha PE linker-loader yenyewe kama bytecode: chambua headers, map sections, tekeleza relocations, resolve imports na jaza IAT.
4. Weka guest-to-guest calls ndani ya interpreter. Elekeza targets zilizo nje ya eneo la bytecode, kama imported DLL functions, kupitia native host-call thunk.
5. Hamishia facilities saidizi kama HTTP framing, TLS na sehemu za C runtime nyuma ya mpaka huohuo wa interpretation.

Muundo huu huepusha kutenga native code region tofauti kwa kila plugin na huzuia payload asilia isionekane kama x86-64 instruction stream inayotambulika. Bado ni mpaka wa evasion/obfuscation, si mpaka wa usalama: native interpreter na kila athari ya nje bado vinaweza kuonekana.<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

VM iliyotengwa huwakilisha pointers kama offsets ndani ya guest buffer, kwa hivyo kila kuvuka kwa host API kunahitaji pointer translation na ushughulikiaji maalum wa output parameters. VM ya shared-memory badala yake hufanya guest addresses ziwe host-process addresses halali. Kwa hiyo, reads na writes zinaweza kutumia operesheni za mtindo wa `memcpy`, na pointer inayorejeshwa na native allocation ECALL inaweza kufuatiliwa moja kwa moja na bytecode. RISC-Y Business ilionyesha kuwa muundo huu unaweza kupunguza bridge hadi kupata PEB na kutoa arbitrary host calls.<sup>[[1]](#references)</sup>

Kwa Windows x64, virtual register file inaweza kuakisi ABI: weka arguments nne za kwanza za integer au pointer kwenye `RCX`, `RDX`, `R8` na `R9`, huku arguments zinazofuata na shadow space zikiwa kwenye stack. Virtual `CALL` inapotatua anwani iliyo nje ya bytecode range, universal thunk huandaa hali hiyo kwa native call na kunakili return value kurudi kwenye VM. Hii huwezesha IAT calls, heap allocation na socket operations bila pointer fixups.<sup>[[2]](#references)[[3]](#references)</sup>

Hasara yake ni kupotea kabisa kwa isolation. Uharibifu wa guest memory unaweza kuathiri host moja kwa moja, native callees zinaweza kuhifadhi au kurekebisha guest pointers, na interpreter lazima ichukulie bytecode kuwa inayoaminika kabisa. Native-to-VM callbacks pia zinahitaji reverse bridge; VM inayotumia outbound calls pekee haiwezi kutimiza moja kwa moja callback-based APIs kama `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## ISA polymorphism ya kila build

Custom ISA yenye upana usiobadilika hurahisisha decoding, dispatch, relocation na virtual-register mapping. Centurion hutumia instruction format ya baiti 18 inayofanana na x86-64, inayobadilisha code density kwa urahisi wa kutabirika wa parsing na pia kutoa njia inayowezekana ya kutafsiri x86-64 artifacts zilizopo kuwa bytecode.<sup>[[3]](#references)</sup>

Kubadilisha opcode-to-handler mapping kwa kila build bila mpangilio husababisha guest logic ileile kutoa byte sequences tofauti. Kusimba jedwali la mapping na kulirejesha wakati wa runtime pia huondoa kamusi thabiti ya opcode kwenye diski. Hii hukwamisha fixed signatures na disassembly rules zinazoweza kutumika tena, lakini haibadilishi kiotomatiki native dispatcher, utaratibu wa kusimbua jedwali au mpaka wa host-call kuwa polymorphic.<sup>[[3]](#references)</sup>

## Kuingiza mazingira ya utekelezaji ndani ya VM

Host process inaweza kupunguzwa hadi memory, syscall na socket primitives, huku freestanding libraries zikitoa huduma za kiwango cha juu ndani ya VM. Kwa mfano, FreeRTOS coreHTTP inaweza kutekeleza HTTP framing na mbedTLS kutekeleza TLS bila kuita WinHTTP au operating-system TLS API. Raw sockets kupitia `afd.sys` au interface inayofanana huwa mpaka finyu wa native networking.<sup>[[3]](#references)</sup>

Muundo huu wa **Bring Your Own Execution Environment (BYOEE)** unaweza pia kuweka PE loading, runtime support na in-memory filesystem nyuma ya interpreter. Hupunguza native implementations zinazotambulika badala ya kuondoa telemetry: raw socket operations bado zinaonekana, na mazingira yanayohitaji proxies zilizoainishwa wazi au TLS interception yanaweza kuzuia muundo wa networking kufanya kazi.<sup>[[3]](#references)</sup>

## Uharakishaji teule wa native

Kutafsiri kila instruction ni ghali hasa katika public-key cryptography. Mgawanyo unaofaa hutumia hooks za mbedTLS `MBEDTLS_ALT` kama interface ya software-coprocessor: hifadhi TLS state, certificate parsing, negotiation, allocation na high-level bignum code kwenye bytecode, lakini tuma hot arithmetic kernels za `bignum_core.c` kupitia native ECALLs. Katika Centurion prototype, `bignum.c`, `bignum_mod.c` na `bignum_mod_raw.c` zilibaki virtualized huku inner loops zikiendeshwa native, na hivyo kupunguza ECDHE handshake kutoka dakika hadi sekunde.<sup>[[3]](#references)</sup>

Fanya accelerators ziwe za hiari ili payload zisizohitaji TLS zisiongeze native entry points. Muundo huu unaweza kutumika kwa kazi yoyote ya interpreter: kwanza pima utendaji, kisha weka wazi native primitive ndogo iwezekanavyo badala ya kuhamisha subsystem nzima nje ya VM.<sup>[[3]](#references)</sup>

Centurion ilithibitisha mnyororo mzima kwa bind shell ya TLS 1.2: bytecode loader ilimap PE, socket calls zilipitia universal thunk, mbedTLS ilishughulikia protocol ndani ya VM, na native ECALLs ziliharakisha ECDHE arithmetic. Hivyo native interpreter ya takriban KB 18 iliweza kutumia encrypted command channel bila kuunda payload kama native x86-64 code.<sup>[[3]](#references)</sup>

## Viashiria vya reverse engineering na detection

Yafuatayo ni viashiria vya vitendo vya uchanganuzi vinavyotokana na usanifu huu; virtualization hubadilisha mahali wachambuzi wanapoona tabia, lakini haiondoi tabia yenyewe.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Tambua fetch/decode/dispatch loop, virtual program counter, register file na marudio ya hatua za instruction zenye upana usiobadilika.
- Dump opcode table baada ya kusimbuliwa wakati wa runtime na uhusishe anwani za handlers na semantic operations badala ya kulinganisha bytecode iliyosimbwa kwenye diski.
- Weka breakpoint kwenye universal thunk au ECALL dispatcher ili kurekodi native target, virtual argument registers, stack arguments na return value.
- Fuatilia ufikiaji wa PEB, export resolution, PE-header parsing, relocation writes na ujazaji wa IAT hata kama utekelezaji wa loader wenyewe ni bytecode.
- Linganisha uundaji wa socket na traffic ya `afd.sys` na kutokuwepo kwa miito inayotarajiwa ya WinHTTP au native TLS; kukosekana kwa high-level imports ni dokezo, si uthibitisho wa tabia salama.
- Chukulia native arithmetic accelerators kama semantic chokepoints: callers zake zinaweza kufichua shughuli za key exchange na certificate-validation huku TLS state machine inayozizunguka ikiwa virtualized.

Kwa workflows za uchanganuzi zinazoanzia kwenye dispatcher badala ya original control-flow graph, tazama [mwongozo wa malware analysis kuhusu virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Vikwazo vya kiutendaji

Virtualization huongeza gharama ya interpretation, hufanya toolchain na ABI kuwa changamano zaidi, na haisuluhishi behavioral detection. Shared memory si salama kwa muundo wake, raw-socket networking inaweza kushindwa nyuma ya proxies za lazima, na Win32 APIs zinazotegemea callbacks sana zinahitaji native-to-VM trampolines. Interpreter, syscall bridge na native accelerators zozote pia hubaki kuwa native footprint ya kawaida ambayo defenders wanaweza kuipa signature au kuiwekea instrumentation.<sup>[[2]](#references)[[3]](#references)</sup>

## Kurasa zinazohusiana

Kwa uchanganuzi wa VMProtect 3.x packing, tazama [emulated unpacking na import repair](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Kuunda RISC-V Virtual Machine kwa Payload Obfuscation](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming katika Enzi ya EDR — Kukwepa Detection kwa Malware Virtualisation](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Leta Mazingira Yako ya Utekelezaji](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Ingia WasmForge: Kukompile Sliver kuwa WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
