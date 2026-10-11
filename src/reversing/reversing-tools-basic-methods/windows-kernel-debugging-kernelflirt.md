# Utatuzi wa Hitilafu za Windows Kernel kwa KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt ni debugger ya Windows x64 kwa maabara za reverse-engineering zinazodhibitiwa. UI ya WPF upande wa host au `KfConsole.exe` hutuma amri kwa `KfRelay.exe` kwenye Windows VM iliyosainiwa kwa test signing. Relay huzibadilisha kuwa maombi ya `DeviceIoControl` kwa `KernelFlirt.sys`, ambayo hutoa shughuli za kumbukumbu, register, breakpoint, udhibiti wa utekelezaji na kernel-module. Driver pia hurekebisha njia ya kernel debugging kwa kutumia inline hook ya `KdpStub`/`KdTrap`, kwa hiyo itumie tu kwenye VM inayoweza kutupwa.<sup>[[1]](#references)</sup>

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

Relay ni mpaka wa debugging wenye mamlaka ya juu, si huduma ya kawaida ya mbali. Weka TCP `31337` kwenye mtandao uliotengwa wa host-only, na usiwahi kufichua driver iliyosainiwa kwa test au relay kwenye mtandao usioaminika.<sup>[[1]](#references)</sup>

Mbinu zinazohusiana za Windows exploitation:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Usanidi wa maabara na hatua ya kwanza

Build zinahitaji Windows 10/11 x64, Visual Studio 2022 yenye C++, WDK 10.0.26100.0 au toleo la baadaye, na .NET 9. Pakia driver na relay ndani ya VM, kisha unganisha kutoka kwa host. UI inaweza kufungua EXE au SYS ya mbali, na mwonekano wa **Kernel Modules** unaweza kuweka breakpoints kwenye drivers ambazo tayari zimepakiwa.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Tumia `KfLoader.exe unload` ukimaliza maabara. Console inasaidia REPL isiyounganishwa, ufikiaji wa moja kwa moja wa kifaa cha ndani, na ufikiaji kupitia relay; ni relay mode pekee inayotumia mtiririko wa kazi wa `open` unaoweza kubainishwa ulioelezwa hapa chini.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Mtiririko wa kazi wa console wa kiwango cha chini ni:<sup>[[2]](#references)</sup>

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

Anwani ni expressions. Namba zisizo na alama ni za hexadecimal, na expressions zinaweza kutumia registers, arithmetic, dereferences kama `[rsp]`, na symbols kama `ntdll!NtCreateFile`. Symbol breakpoints zinapaswa kuongezwa tu baada ya `open` au `attach` kuorodhesha modules na kupakia PDB zao.<sup>[[2]](#references)</sup>

## Kunasa entry point kwa uhakika kwa kutumia `EB FE`

`open` ya upande wa relay huunda target ikiwa imesimamishwa, huhifadhi bytes zake za kwanza za entry point, huandika `EB FE`, huendeleza thread ya entry, na hufuatilia hadi instruction pointer yake ifike kwenye anwani hiyo. `EB FE` ni short jump ya byte mbili inayojirukia yenyewe, kwa hiyo hunasa execution bila kutegemea kuwasilishwa kwa user-mode debug exception. Kisha relay hurejesha bytes za awali na kuiacha target ikiwa imesimama kwenye entry point yake.<sup>[[2]](#references)</sup>

Muundo huu pia ni muhimu pale ambapo njia ya mapema ya loader inahitaji kuangaliwa kabla usanidi wa kawaida wa debugger haujakamilika.<sup>[[2]](#references)</sup>

1. Unda process ikiwa imesimamishwa, kisha utambue entry point yake halisi baada ya image mapping.
2. Hifadhi bytes za awali za entry point na uzibadilishe kwa self-loop ya byte mbili.
3. Endeleza thread ya entry na ufuatilie instruction pointer yake hadi ifike kwenye anwani iliyowekewa patch.
4. Simamisha target na urejeshe bytes zilezile za awali kabla uchanganuzi haujaendelea.

Mbinu hii huingilia execution kwa makusudi. Ikiwa debugger au relay itatoka kabla ya urejeshaji, target inaweza kuendelea kuzunguka bila kikomo. Local mode ya KernelFlirt haitoi entry patching ya upande wa relay; anzisha process mwenyewe na utumie `attach <pid>` badala yake.<sup>[[2]](#references)</sup>

## Chagua primitive ya breakpoint

KernelFlirt hutoa mbinu kadhaa za breakpoint zenye side effects tofauti. Amri zifuatazo humwezesha mchambuzi kubadilisha primitive pale ambapo packed code hujibadilisha, kurasa zinazoweza kutekelezwa ni za kusomwa tu, au bytes za software breakpoint hukaguliwa kwa uadilifu.<sup>[[1]](#references)[[2]](#references)</sup>

| Primitive | Amri | Utaratibu na matumizi |
| --- | --- | --- |
| Software | `bp <expr>` | `INT3` inayotumia MDL; inaweza kuweka instrumentation kwenye kurasa za RX `.text` |
| Conditional software | `bp <expr> if <condition>` | Hutathmini kila inapopigwa na huendelea kimyakimya ikiwa condition ni false |
| Hardware execute | `ba e1 <expr>` | Hutumia mojawapo ya DR0-DR3 bila kubadilisha bytes za code |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | Hufuatilia writes au reads/writes za byte 1, 2, 4, au 8 |
| Guard page | `bm <expr> [size]` | Hutumia `PAGE_GUARD` kwa breakpoint ya eneo la memory |
| Temporary | `g <expr>`, `p`, au `o` | Helper breakpoint ya run-to-address, step-over, na step-out |

Tumia `bl` kutofautisha entries za software, hardware, memory, na temporary, na `bc <address|handle|all>` kuziondoa. Hardware slots ni chache na hutumika kupitia hali ya debug-register, ilhali guard pages hufunika eneo kubwa zaidi lakini husababishwa na accesses zisizohusiana kwenye page hiyo hiyo.

## Native x64 dhidi ya WoW64 stepping

Native x64 single-step huweka processor trap flag kupitia `IOCTL_KF_SINGLE_STEP`. Step Over hufasiri instruction ya sasa na kuweka breakpoints za muda kwenye anwani zinazoweza kuwa zinazofuata. Step Out husoma anwani ya kurejea kutoka juu ya stack ya sasa. Kwenye function prologue, dhana hiyo kuhusu stack inaweza kuwa si sahihi, kwa hiyo pendelea breakpoint ya ndani inayojulikana.<sup>[[2]](#references)</sup>

Hook ya `KdTrap` hainasi 32-bit exceptions kwa njia hiyo hiyo. Kwa targets za WoW64, debugger hufasiri instruction kwa kutumia Iced, huandika `EB FE` kwenye `EIP` inayofuata iliyokokotolewa, na hufuatilia instruction pointers za threads. Kwa hiyo, `g <address>` haipatikani kwa WoW64, na `g` ya kawaida huzuia console hadi breakpoint ifikiwe. Weka breakpoint inayoweza kufikiwa kwanza na uepuke kuendesha bila kikomo, kwa sababu `Ctrl+C` husitisha console badala ya kughairi ufuatiliaji.<sup>[[2]](#references)</sup>

## Uchanganuzi unaosaidiwa na memory, register, na symbol

Console inaweza kuunganisha kusimama kwenye symbol na ukaguzi wa memory pamoja na patch inayodhibitiwa. Search calls hukubali byte wildcards, ASCII, au UTF-16 na zimewekewa kikomo cha 4 MB na matches 256 zinazoripotiwa. Amri za allocation na protection hutumia allocate, free, na protect IOCTLs za driver.<sup>[[2]](#references)</sup>

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

Upakiaji wa PDB husoma directory ya PE debug ya kila module ya remote, hutoa kitambulisho chake cha RSDS, hupata PDB inayolingana kupitia DbgHelp/SymSrv, na kuthibitisha kuwa ilipakiwa kama PDB. Weka PDB za private karibu na target kwenye mashine ya relay au ongeza directory yake kwenye `_NT_SYMBOL_PATH` kwenye host.<sup>[[2]](#references)</sup>

## Mabadiliko ya hali ya anti-debug yanayoungwa mkono na Kernel

Ufikiaji wa Kernel huruhusu debugger kuondoa viashiria ambavyo debugger ya user-mode haiwezi kuficha kwa uhakika. Tekeleza mabadiliko moja kwa wakati, thibitisha ukaguzi wa target, na urejeshe hook inayohusika kabla ya kumaliza session.<sup>[[2]](#references)</sup>

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

- `clr_debug_port` husafisha `EPROCESS.DebugPort`.
- `clr_thread_hide` huondoa `HideFromDebugger` kwenye thread lengwa.
- `ntqsi on` hufanya spoof ya class `0x23` (`SystemKernelDebuggerInformation`) ya `NtQuerySystemInformation`.
- `spoof on` husababisha usomaji wa user-mode wa `KUSER_SHARED_DATA.KdDebuggerEnabled` kuonyesha false huku hali ya kernel inayohitajika na trap mechanism ikihifadhiwa.
- `stats` hukagua vihesabu vya hook na hali zilizorekodiwa za `KiDebugRoutine`, `KdpStub`, na `KdTrap`.

Operesheni hizi hubadilisha hali ya process na kernel. Crash, inline hook iliyobaki, offset isiyo sahihi ya muundo, au urejeshaji wa patch ambao haujakamilika vinaweza kufanya VM isiwe thabiti. Ndiyo sababu snapshots na mazingira ya majaribio yaliyotengwa yenye test-signing ni lazima.<sup>[[1]](#references)</sup>

## References

- [1] [Repository ya KernelFlirt na nyaraka kuu](https://github.com/AkaTorich/KernelFlirt)
- [2] [Marejeleo ya console ya KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
