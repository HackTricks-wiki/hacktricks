# Kernel-debugging in Windows met KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt is ’n Windows x64-debugger vir beheerde reverse-engineering-laboratoriums. ’n Gasheerkant-WPF-UI of `KfConsole.exe` stuur opdragte na `KfRelay.exe` in ’n toetsondertekende Windows-VM. Die relay vertaal dit in `DeviceIoControl`-versoeke vir `KernelFlirt.sys`, wat geheue-, register-, breekpunt-, uitvoeringsbeheer- en kernelmodulebewerkings verskaf. Die driver wysig ook die kernel-debugging-pad met ’n `KdpStub`/`KdTrap`-inline hook, dus moet jy dit slegs in ’n weggooibare VM gebruik.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Die relay is ’n bevoorregte debugging-grens eerder as ’n gewone remote diens. Hou TCP `31337` op ’n geïsoleerde host-only-netwerk en stel nooit die toetsondertekende driver of relay aan ’n onbetroubare netwerk bloot nie.<sup>[[1]](#references)</sup>

Verwante Windows-exploitation-tegnieke:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Lab-opstelling en eerste stop

Bouwerk vereis Windows 10/11 x64, Visual Studio 2022 met C++, WDK 10.0.26100.0 of later, en .NET 9. Laai die driver en relay binne die VM, en koppel dan vanaf die host. Die UI kan ’n remote EXE of SYS oopmaak, en die **Kernel Modules**-aansig kan breakpoints in reeds gelaaide drivers plaas.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Gebruik `KfLoader.exe unload` wanneer die lab afgehandel is. Die konsole ondersteun ’n REPL sonder verbinding, direkte toegang tot plaaslike toestelle en relay-toegang; slegs relay-modus implementeer die deterministiese `open`-werkvloei wat hieronder beskryf word.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

’n Minimale konsole-werkvloei is:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Addresses is uitdrukkings. Los getalle is heksadesimaal, en uitdrukkings kan registers, rekenkundige bewerkings, dereferensies soos `[rsp]` en simbole soos `ntdll!NtCreateFile` gebruik. Simboolbreekpunte moet eers bygevoeg word nadat `open` of `attach` modules opgespoor en hul PDB's gelaai het.<sup>[[2]](#references)</sup>

## Deterministiese vasvang by die toegangspunt met `EB FE`

`open` aan die relay-kant skep die teiken as gesuspendeer, stoor sy eerste toegangspuntgrepe, skryf `EB FE`, hervat die toegangsdraad en kontroleer herhaaldelik totdat die instruksiewyser daardie adres bereik. `EB FE` is 'n kort sprong van twee grepe terug na homself, dus vang dit uitvoering vas sonder om op die aflewering van 'n gebruikermodus-debuguitsondering staat te maak. Die relay herstel dan die oorspronklike grepe en laat die teiken by sy toegangspunt gestop.<sup>[[2]](#references)</sup>

Hierdie patroon is ook nuttig wanneer 'n vroeë laaierpad waargeneem moet word voordat normale debugger-opstelling voltooi is.<sup>[[2]](#references)</sup>

1. Skep die proses as gesuspendeer en bepaal sy werklike toegangspunt nadat die image gekarteer is.
2. Stoor die oorspronklike toegangspuntgrepe en vervang hulle met die tweegrepe-selflus.
3. Hervat die toegangsdraad en kontroleer die instruksiewyser herhaaldelik totdat dit die gelapte adres bereik.
4. Suspendeer die teiken en herstel die presiese oorspronklike grepe voordat ontleding voortgaan.

Die tegniek is doelbewus indringend. As die debugger of relay afsluit voordat herstel plaasvind, kan die teiken aanhou vasdraai. KernelFlirt se plaaslike modus bied nie toegangspunt-lapping aan die relay-kant nie; begin die proses handmatig en gebruik eerder `attach <pid>`.<sup>[[2]](#references)</sup>

## Kies die breekpuntmeganisme

KernelFlirt bied verskeie breekpuntmeganismes met verskillende newe-effekte. Met die volgende opdragte kan 'n ontleder tussen meganismes wissel wanneer gepakte kode homself herskryf, uitvoerbare bladsye leesalleen is, of sagtewarebreekpuntgrepe se integriteit nagegaan word.<sup>[[1]](#references)[[2]](#references)</sup>

| Meganisme | Opdrag | Werking en gebruik |
| --- | --- | --- |
| Sagteware | `bp <expr>` | MDL-gesteunde `INT3`; kan RX `.text`-bladsye instrumenteer |
| Voorwaardelike sagteware | `bp <expr> if <condition>` | Evalueer by elke treffer en hervat stilweg wanneer vals |
| Hardeware-uitvoering | `ba e1 <expr>` | Gebruik een van DR0-DR3 sonder om kodegrepe te verander |
| Hardewaredata | `ba w4 <expr>` / `ba r8 <expr>` | Hou skryf- of lees-/skryfbewerkings van 1, 2, 4 of 8 grepe dop |
| Guard page | `bm <expr> [size]` | Gebruik `PAGE_GUARD` vir 'n geheuegebiedbreekpunt |
| Tydelik | `g <expr>`, `p` of `o` | Hulpbreekpunt vir loop-tot-adres, stap-oor en stap-uit |

Gebruik `bl` om sagteware-, hardeware-, geheue- en tydelike inskrywings te onderskei, en `bc <address|handle|all>` om hulle te verwyder. Hardewaregleuwe is skaars en werk via die toestand van debugregisters, terwyl guard pages 'n groter gebied dek, maar ook aktiveer vir onverwante toegang tot dieselfde bladsy.

## Native x64- teenoor WoW64-stapuitvoering

Native x64-enkelstap stel die verwerker se trapvlag via `IOCTL_KF_SINGLE_STEP`. Step Over dekodeer die huidige instruksie en plaas tydelike breekpunte by die moontlike volgende adresse. Step Out lees die terugkeeradres bo-aan die huidige stapel. By 'n funksieproloog kan daardie stapelaanname verkeerd wees; verkies dus 'n bekende interne breekpunt.<sup>[[2]](#references)</sup>

Die `KdTrap`-haak vang nie 32-bis-uitsonderings op dieselfde manier vas nie. Vir WoW64-teikens dekodeer die debugger die instruksie met Iced, skryf `EB FE` by die berekende volgende `EIP`, en kontroleer die draadinstruksiewysers herhaaldelik. Gevolglik is `g <address>` nie vir WoW64 beskikbaar nie, en blokkeer 'n gewone `g` die konsole totdat 'n breekpunt bereik word. Stel eers 'n bereikbare breekpunt en vermy 'n onbepaalde uitvoering, want `Ctrl+C` beëindig die konsole eerder as om die kontrole te kanselleer.<sup>[[2]](#references)</sup>

## Ontleding met hulp van geheue, registers en simbole

Die konsole kan 'n simboliese stop kombineer met geheue-inspeksie en 'n beheerde pleister. Soektogte aanvaar grepe-wildcards, ASCII of UTF-16 en is beperk tot 4 MB, met hoogstens 256 gerapporteerde treffers. Toekenning- en beskermingsopdragte roep die bestuurder se toeken-, vrymaak- en beskerm-IOCTL's aan.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB-laai lees elke afgeleë module se PE-ontfoutingsgids, onttrek sy RSDS-identifiseerder, vind die ooreenstemmende PDB deur DbgHelp/SymSrv, en verifieer dat dit as ’n PDB gelaai is. Plaas private PDB’s langs die teiken op die relay-masjien, of voeg hul gids by `_NT_SYMBOL_PATH` op die gasheer.<sup>[[2]](#references)</sup>

## Kernel-gesteunde anti-debug-toestandveranderinge

Kernel-toegang laat die debugger toe om aanwysers te verwyder wat ’n user-mode debugger nie betroubaar kan versteek nie. Pas een verandering op ’n slag toe, bevestig die teikenkontrole en herstel die ooreenstemmende hook voordat jy die sessie beëindig.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` maak `EPROCESS.DebugPort` skoon.
- `clr_thread_hide` verwyder `HideFromDebugger` van teikendrade.
- `ntqsi on` bedrieg `NtQuerySystemInformation`-klas `0x23` (`SystemKernelDebuggerInformation`).
- `spoof on` laat user-mode-leesaksies van `KUSER_SHARED_DATA.KdDebuggerEnabled` vals sien, terwyl die kerneltoestand wat vir die trap-meganisme nodig is, behoue bly.
- `stats` kontroleer hook-tellers en die aangetekende `KiDebugRoutine`-, `KdpStub`- en `KdTrap`-toestand.

Hierdie bewerkings verander proses- en kerneltoestand. ’n Omval, ’n verouderde inline hook, ’n verkeerde struktuur-offset of onvoltooide patch-herstel kan die VM destabiliseer. Daarom is snapshots en ’n geïsoleerde toetsondertekeningsomgewing verpligtend.<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt-bewaarplek en hoofdokumentasie](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt-konsoleverwysing](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
