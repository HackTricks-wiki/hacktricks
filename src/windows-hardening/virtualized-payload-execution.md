# Utekelezaji wa Payload Uliovirtualishwa na Kukwepa kwa VM Maalum

{{#include ../banners/hacktricks-training.md}}

Virtualization ya payload hukompaili mantiki ya kukera kuwa seti ya maagizo ya guest na kuiendesha kwa interpreter ya native. Tofauti na packer, ambayo hatimaye lazima ifichue maagizo ya awali ya native kwenye memory, payload iliyovirtualishwa inaweza kuhifadhi mantiki iliyolindwa kama bytecode kwa muda wake wote wa kufanya kazi. Hii huondoa dirisha hilo mahususi la unpacking, lakini **haifichi** tabia inayoonekana kwa host, kama vile syscalls, shughuli za mtandao, au mpaka wa wito kati ya VM na native.<sup>[[2]](#references)[[3]](#references)</sup>

## Muundo wa utekelezaji

Loader fupi iliyovirtualishwa inaweza kugawa utekelezaji katika tabaka zifuatazo.<sup>[[3]](#references)</sup>

1. Kompaili C isiyojitegemea, source ya BOF, au runtime libraries kupitia LLVM kuwa ISA maalum ya bytecode.
2. Anzisha interpreter ndogo ya native na uanzishe ramani ya opcode mahususi kwa build.
3. Endesha PE linker-loader yenyewe kama bytecode: changanua headers, panga sections kwenye memory, tumia relocations, suluhisha imports, na jaza IAT.
4. Weka wito wa guest-kwa-guest ndani ya interpreter. Elekeza malengo yaliyo nje ya eneo la bytecode, kama vile functions za imported DLL, kupitia native host-call thunk.
5. Hamishia huduma saidizi kama HTTP framing, TLS, na sehemu za C runtime nyuma ya mpaka huohuo wa interpretation.

Muundo huu huepuka kutenga eneo tofauti la native code kwa kila plugin na kuzuia payload ya awali isionekane kama mkondo wa maagizo wa x86-64 unaotambulika. Bado ni mpaka wa evasion/obfuscation badala ya mpaka wa usalama: interpreter ya native na kila athari ya nje bado vinaweza kuonekana.<sup>[[2]](#references)[[3]](#references)</sup>

## Daraja la shared-memory la host

VM iliyotengwa huwakilisha pointers kama offsets ndani ya guest buffer, kwa hiyo kila kuvuka API ya host kunahitaji kutafsiri pointers na kushughulikia kwa namna maalum vigezo vya matokeo. VM ya shared-memory badala yake hufanya guest addresses kuwa host-process addresses halali. Kwa hiyo, usomaji na uandishi unaweza kutumia shughuli za mtindo wa `memcpy`, na pointer inayorejeshwa na native allocation ECALL inaweza kurejelewa moja kwa moja na bytecode. RISC-Y Business ilionyesha kuwa muundo huu unaweza kurahisisha daraja hadi kupata PEB na kutekeleza host calls holela.<sup>[[1]](#references)</sup>

Kwa Windows x64, virtual register file inaweza kuakisi ABI: weka hoja nne za kwanza za integer au pointer katika `RCX`, `RDX`, `R8`, na `R9`, huku hoja zinazofuata na shadow space zikiwa kwenye stack. `CALL` ya virtual inapolenga nje ya eneo la bytecode, thunk ya jumla huandaa hali hiyo kwa native call na kunakili thamani ya matokeo kurudi kwenye VM. Hii huruhusu IAT calls, ugawaji wa heap, na shughuli za socket bila kurekebisha pointers.<sup>[[2]](#references)[[3]](#references)</sup>

Hasara yake ni kupotea kabisa kwa isolation. Uharibifu wa guest memory unaweza kuathiri host moja kwa moja, native callees zinaweza kuhifadhi au kubadilisha guest pointers, na interpreter lazima ichukulie bytecode kuwa inaaminika kikamilifu. Callbacks kutoka native kwenda VM pia zinahitaji daraja la kurudi; VM inayotumia tu wito wa kwenda nje haiwezi kutimiza moja kwa moja APIs zinazotegemea callbacks kama `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polymorphism ya ISA kwa kila build

ISA maalum yenye ukubwa usiobadilika hurahisisha decoding, dispatch, relocation, na ramani ya virtual-register. Centurion hutumia muundo wa maagizo wa baiti 18 unaofanana na x86-64, ambao hubadilishana code density kwa uchanganuzi unaotabirika na pia huacha uwezekano wa kutafsiri artifacts zilizopo za x86-64 kuwa bytecode.<sup>[[3]](#references)</sup>

Kubadilisha ramani ya opcode-kwa-handler kwa kila build hufanya mantiki ileile ya guest itoe mfuatano tofauti wa baiti. Kusimba jedwali la ramani kwa njia fiche na kulirejesha wakati wa runtime pekee huondoa zaidi kamusi thabiti ya opcode iliyo kwenye diski. Hii hutatiza signatures zisizobadilika na kanuni za disassembly zinazoweza kutumiwa tena, lakini haibadilishi polymorphism ya native dispatcher, utaratibu wa kusimbua jedwali, au mpaka wa host-call kiotomatiki.<sup>[[3]](#references)</sup>

## Kuingiza mazingira ya utekelezaji ndani ya VM

Mchakato wa host unaweza kupunguzwa hadi primitives za memory, syscall, na socket, huku libraries zisizojitegemea zikitoa huduma za kiwango cha juu ndani ya VM. Kwa mfano, FreeRTOS coreHTTP inaweza kutekeleza HTTP framing na mbedTLS inaweza kutekeleza TLS bila kutumia WinHTTP au API ya TLS ya mfumo wa uendeshaji. Raw sockets kupitia `afd.sys` au interface inayofanana kisha huwa mpaka mwembamba wa native networking.<sup>[[3]](#references)</sup>

Muundo huu wa **Bring Your Own Execution Environment (BYOEE)** unaweza pia kuweka PE loading, runtime support, na in-memory filesystem nyuma ya interpreter. Hupunguza implementations za native zinazotambulika badala ya kuondoa telemetry: shughuli za raw socket bado zinaonekana, na mazingira yanayohitaji proxies maalum au TLS interception yanaweza kuzuia muundo wa networking kufanya kazi.<sup>[[3]](#references)</sup>

## Uharakishaji teule wa native

Kutafsiri kila agizo huwa na gharama kubwa hasa katika public-key cryptography. Mgawanyo unaofaa hutumia hooks za `MBEDTLS_ALT` za mbedTLS kama interface ya software-coprocessor: hifadhi hali ya TLS, uchanganuzi wa certificate, negotiation, ugawaji wa memory, na bignum code ya kiwango cha juu katika bytecode, lakini peleka kernels za hesabu zinazotumika sana kutoka `bignum_core.c` kupitia native ECALLs. Katika prototype ya Centurion, `bignum.c`, `bignum_mod.c`, na `bignum_mod_raw.c` zilibaki virtualized huku inner loops zikiendeshwa natively, na hivyo kupunguza handshake ya ECDHE kutoka dakika hadi sekunde.<sup>[[3]](#references)</sup>

Fanya accelerators kuwa za hiari ili payload zisizohitaji TLS zisiongeze native entry points. Muundo huu unaweza kutumika kwa workload yoyote ya interpreter: kwanza pima utendaji, kisha weka wazi primitive ndogo zaidi ya native badala ya kuhamisha subsystem nzima nje ya VM.<sup>[[3]](#references)</sup>

Centurion ilithibitisha mlolongo mzima kwa bind shell ya TLS 1.2: bytecode loader ilipanga PE kwenye memory, socket calls zilipitia universal thunk, mbedTLS ilishughulikia protocol ndani ya VM, na native ECALLs ziliharakisha hesabu za ECDHE. Kwa hiyo, native interpreter ya takriban KB 18 iliwezesha command channel iliyosimbwa bila kuunda payload kama native x86-64 code.<sup>[[3]](#references)</sup>

## Viashiria vya reversing na detection

Yafuatayo ni viashiria vya vitendo vya uchanganuzi vinavyotokana na usanifu huu; virtualization hubadilisha mahali ambapo wachanganuzi huona tabia, lakini haiondoi tabia yenyewe.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Tambua fetch/decode/dispatch loop, virtual program counter, register file, na hatua zinazorudiwa za maagizo yenye ukubwa usiobadilika.
- Dump jedwali la opcode baada ya kusimbuliwa wakati wa runtime na ulinganishe anwani za handlers na shughuli za kisemantiki badala ya kulinganisha bytecode iliyosimbwa kwenye diski.
- Weka breakpoint kwenye universal thunk au ECALL dispatcher ili kurekodi native target, virtual argument registers, hoja za stack, na thamani ya matokeo.
- Fuatilia ufikiaji wa PEB, export resolution, uchanganuzi wa PE headers, uandishi wa relocations, na ujazaji wa IAT hata kama implementation ya loader yenyewe ni bytecode.
- Linganisha uundaji wa socket na trafiki ya `afd.sys` na kutokuwepo kwa WinHTTP au native TLS calls zinazotarajiwa; imports za kiwango cha juu zinazokosekana ni kidokezo, si uthibitisho wa tabia salama.
- Chukulia native arithmetic accelerators kama maeneo muhimu ya uchunguzi: callers zake zinaweza kufichua shughuli za key exchange na uthibitishaji wa certificate huku TLS state machine inayozizunguka ikiwa virtualized.

Kwa workflows za uchanganuzi zinazoanzia kwenye dispatcher badala ya control-flow graph ya awali, tazama [mwongozo wa malware analysis kuhusu virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Vikwazo vya kiutendaji

Virtualization huongeza gharama ya interpretation, utata wa toolchain na ABI, na haisuluhishi behavioral detection. Shared memory si salama kwa muundo wake, networking ya raw-socket inaweza kushindwa nyuma ya proxies za lazima, na Win32 APIs zinazotumia callbacks kwa wingi zinahitaji trampolines za native-to-VM. Interpreter, syscall bridge, na native accelerators zozote pia hubaki kuwa footprint ya kawaida ya native ambayo defenders wanaweza kuwekea signatures au kuifuatilia kwa instrumentation.<sup>[[2]](#references)[[3]](#references)</sup>

## Kurasa zinazohusiana

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Kujenga Mashine Pepe ya RISC-V kwa Obfuscation ya Payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming katika Enzi ya EDR — Evasion kupitia Malware Virtualisation](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Leta Mazingira Yako ya Utekelezaji](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
