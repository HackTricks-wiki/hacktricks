# Debugovanje Windows kernela pomoću KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt je Windows x64 debugger za kontrolisane laboratorije za reverse engineering. WPF UI na hostu ili `KfConsole.exe` šalje komande programu `KfRelay.exe` na Windows VM-u potpisanoj testnim sertifikatom. Relay ih prevodi u `DeviceIoControl` zahteve za `KernelFlirt.sys`, koji omogućava rad sa memorijom, registrima, breakpointovima, kontrolom izvršavanja i kernel modulima. Driver takođe menja putanju za kernel debugging pomoću inline hook-a `KdpStub`/`KdTrap`, zato ga koristite samo u VM-u koji možete da odbacite.<sup>[[1]](#references)</sup>

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

Relay je privilegovana granica za otklanjanje grešaka, a ne običan udaljeni servis. TCP port `31337` držite na izolovanoj host-only mreži i nikada ne izlažite testno potpisani driver ili relay nepouzdanoj mreži.<sup>[[1]](#references)</sup>

Povezane Windows tehnike eksploatacije:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Podešavanje laboratorije i prvi koraci

Za izgradnju su potrebni Windows 10/11 x64, Visual Studio 2022 sa C++, WDK 10.0.26100.0 ili noviji i .NET 9. Učitajte driver i relay unutar VM-a, a zatim se povežite sa hosta. UI može da otvori udaljeni EXE ili SYS, a prikaz **Kernel Modules** može da postavi tačke prekida u već učitane drivere.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Koristite `KfLoader.exe unload` kada završite laboratorijsku vežbu. Konzola podržava nepovezani REPL, direktan pristup lokalnom uređaju i relay pristup; samo relay mode implementira deterministički `open` tok rada opisan u nastavku.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Minimalni tok rada u konzoli je:<sup>[[2]](#references)</sup>

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

Adrese su izrazi. Goli brojevi su heksadecimalni, a izrazi mogu da koriste registre, aritmetičke operacije, dereferenciranje kao što je `[rsp]` i simbole kao što je `ntdll!NtCreateFile`. Simboličke breakpoint-e treba dodati tek nakon što `open` ili `attach` enumeriše module i učita njihove PDB-ove.<sup>[[2]](#references)</sup>

## Determinističko zaustavljanje na ulaznoj tački pomoću `EB FE`

Relay-side `open` kreira suspendovan ciljni proces, čuva prve bajtove njegove ulazne tačke, upisuje `EB FE`, nastavlja nit ulazne tačke i proverava sve dok njen instruction pointer ne stigne do te adrese. `EB FE` je dvobajtni kratki skok nazad na sebe, pa zaustavlja izvršavanje bez oslanjanja na isporuku user-mode debug izuzetka. Relay zatim vraća originalne bajtove i ostavlja ciljni proces zaustavljen na njegovoj ulaznoj tački.<sup>[[2]](#references)</sup>

Ovaj obrazac je koristan i kada treba posmatrati ranu putanju loader-a pre nego što se završi uobičajeno podešavanje debugger-a.<sup>[[2]](#references)</sup>

1. Kreirajte suspendovan proces i utvrdite njegovu stvarnu ulaznu tačku nakon mapiranja image-a.
2. Sačuvajte originalne bajtove ulazne tačke i zamenite ih dvobajtnom petljom koja skače na sebe.
3. Nastavite nit ulazne tačke i proveravajte njen instruction pointer dok ne stigne do zakrpljene adrese.
4. Suspendujte ciljni proces i vratite tačno originalne bajtove pre nastavka analize.

Ova tehnika je namerno intruzivna. Ako se debugger ili relay zatvori pre vraćanja bajtova, ciljni proces može da nastavi da se vrti u petlji. KernelFlirt local mode ne podržava relay-side zakrpljivanje ulazne tačke; pokrenite proces ručno i umesto toga koristite `attach <pid>`.<sup>[[2]](#references)</sup>

## Izaberite breakpoint primitivu

KernelFlirt nudi nekoliko mehanizama za breakpoint-e sa različitim sporednim efektima. Sledeće komande omogućavaju analitičaru da promeni primitivu kada upakovani kod menja sam sebe, kada su izvršne stranice samo za čitanje ili kada se proverava integritet bajtova software breakpoint-a.<sup>[[1]](#references)[[2]](#references)</sup>

| Primitiva | Komanda | Mehanizam i upotreba |
| --- | --- | --- |
| Software | `bp <expr>` | `INT3` podržan pomoću MDL-a; može da instrumentuje RX `.text` stranice |
| Uslovni software | `bp <expr> if <condition>` | Proverava uslov pri svakom pogotku i tiho nastavlja izvršavanje ako je uslov netačan |
| Hardware execute | `ba e1 <expr>` | Koristi jedan od DR0-DR3 bez menjanja bajtova koda |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | Prati upisivanja ili čitanja/upisivanja 1, 2, 4 ili 8 bajtova |
| Guard page | `bm <expr> [size]` | Koristi `PAGE_GUARD` za breakpoint opsega memorije |
| Privremeni | `g <expr>`, `p` ili `o` | Pomoćni breakpoint za pokretanje do adrese, korak preko poziva i izlazak iz funkcije |

Koristite `bl` da biste razlikovali software, hardware, memory i privremene stavke, a `bc <address|handle|all>` da biste ih uklonili. Hardware slot-ova ima malo i oni se primenjuju preko stanja debug registra, dok guard page pokriva veći opseg, ali se aktivira i pri nepovezanim pristupima istoj stranici.

## Izvršavanje korak po korak u native x64 i WoW64

Native x64 single-step postavlja trap flag procesora preko `IOCTL_KF_SINGLE_STEP`. Step Over dekodira trenutnu instrukciju i postavlja privremene breakpoint-e na njene moguće sledeće adrese. Step Out čita povratnu adresu sa vrha trenutnog stack-a. Na prologu funkcije ta pretpostavka o stack-u može biti pogrešna, pa je bolje koristiti poznati interni breakpoint.<sup>[[2]](#references)</sup>

Hook `KdTrap` ne hvata 32-bitne izuzetke na isti način. Za WoW64 ciljne procese, debugger dekodira instrukciju pomoću Iced-a, upisuje `EB FE` na izračunatu sledeću `EIP` adresu i proverava instruction pointer-e niti. Zbog toga `g <address>` nije dostupan za WoW64, a običan `g` blokira konzolu dok se ne dostigne breakpoint. Najpre postavite dostižan breakpoint i izbegavajte neograničeno izvršavanje, jer `Ctrl+C` zatvara konzolu umesto da otkaže proveru.<sup>[[2]](#references)</sup>

## Analiza uz pomoć memorije, registara i simbola

Konzola može da kombinuje simboličko zaustavljanje sa pregledom memorije i kontrolisanom zakrpom. Pretraga prihvata bajtove sa džokerima, ASCII ili UTF-16 i ograničena je na 4 MB, uz najviše 256 prijavljenih poklapanja. Komande za alokaciju i zaštitu pozivaju driver-ove IOCTL-ove za alokaciju, oslobađanje i zaštitu.<sup>[[2]](#references)</sup>

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

PDB učitavanje čita PE direktorijum za otklanjanje grešaka svakog udaljenog modula, izdvaja njegov RSDS identifikator, pronalazi odgovarajući PDB putem DbgHelp/SymSrv i proverava da li je učitan kao PDB. Postavite privatne PDB datoteke pored cilja na relay mašini ili dodajte njihov direktorijum u `_NT_SYMBOL_PATH` na hostu.<sup>[[2]](#references)</sup>

## Promene stanja za zaštitu od otkrivanja debugger-a, potpomognute kernel-om

Pristup kernel-u omogućava debugger-u da ukloni indikatore koje debugger u user-mode-u ne može pouzdano da sakrije. Primenjujte jednu promenu odjednom, proverite ciljnu proveru i vratite odgovarajući hook pre završetka sesije.<sup>[[2]](#references)</sup>

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

- `clr_debug_port` briše `EPROCESS.DebugPort`.
- `clr_thread_hide` uklanja `HideFromDebugger` iz ciljnih niti.
- `ntqsi on` lažira klasu `0x23` (`SystemKernelDebuggerInformation`) funkcije `NtQuerySystemInformation`.
- `spoof on` omogućava da čitanja iz user-mode-a polja `KUSER_SHARED_DATA.KdDebuggerEnabled` prikazuju false, uz zadržavanje stanja kernela potrebnog za trap mehanizam.
- `stats` proverava brojače hook-ova i zabeleženo stanje `KiDebugRoutine`, `KdpStub` i `KdTrap`.

Ove operacije menjaju stanje procesa i kernela. Crash, zastareo inline hook, netačan pomeraj strukture ili nedovršeno vraćanje patch-a mogu destabilizovati VM, zato su snimci stanja i izolovano okruženje za testno potpisivanje obavezni.<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt repozitorijum i glavna dokumentacija](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt referenca za konzolu](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
