# Debugging del kernel Windows con KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt è un debugger Windows x64 per laboratori controllati di reverse engineering. Un'interfaccia WPF sul sistema host o `KfConsole.exe` invia comandi a `KfRelay.exe` in una VM Windows con firma di test. Il relay li traduce in richieste `DeviceIoControl` per `KernelFlirt.sys`, che fornisce operazioni di memoria, registri, breakpoint, controllo dell'esecuzione e moduli del kernel. Il driver modifica anche il percorso di debugging del kernel con un inline hook `KdpStub`/`KdTrap`, quindi usalo solo in una VM usa e getta.<sup>[[1]](#references)</sup>

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

Il relay è un confine di debugging privilegiato, non un normale servizio remoto. Mantieni TCP `31337` su una rete host-only isolata e non esporre mai il driver firmato per i test o il relay a una rete non attendibile.<sup>[[1]](#references)</sup>

Tecniche correlate di exploitation di Windows:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Configurazione del lab e primo stop

Per le build servono Windows 10/11 x64, Visual Studio 2022 con C++, WDK 10.0.26100.0 o successivo e .NET 9. Carica il driver e il relay all'interno della VM, quindi connettiti dall'host. L'interfaccia utente può aprire un EXE o SYS remoto e la vista **Kernel Modules** consente di impostare breakpoint nei driver già caricati.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Usa `KfLoader.exe unload` al termine del lab. La console supporta un REPL non connesso, l’accesso diretto ai dispositivi locali e l’accesso tramite relay; solo la modalità relay implementa il workflow deterministico `open` descritto di seguito.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Un flusso di lavoro minimo da console è:<sup>[[2]](#references)</sup>

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

Gli indirizzi sono espressioni. I numeri senza prefisso sono esadecimali; le espressioni possono usare registri, operazioni aritmetiche, dereferenziazioni come `[rsp]` e simboli come `ntdll!NtCreateFile`. I breakpoint sui simboli vanno aggiunti solo dopo che `open` o `attach` ha enumerato i moduli e caricato i relativi PDB.<sup>[[2]](#references)</sup>

## Intercettare deterministicamente il punto di ingresso con `EB FE`

`open` lato relay crea il processo in stato sospeso, salva i byte iniziali del punto di ingresso, scrive `EB FE`, riprende il thread di ingresso e interroga ripetutamente il suo instruction pointer finché non raggiunge quell'indirizzo. `EB FE` è un salto breve di due byte che torna a se stesso, quindi intercetta l'esecuzione senza dipendere dalla consegna di un'eccezione di debug in user mode. Il relay ripristina quindi i byte originali e lascia il target fermo al punto di ingresso.<sup>[[2]](#references)</sup>

Questo schema è utile anche quando occorre osservare un percorso iniziale del loader prima che sia completata la normale configurazione del debugger.<sup>[[2]](#references)</sup>

1. Crea il processo in stato sospeso e risolvi il suo effettivo punto di ingresso dopo il mapping dell'immagine.
2. Salva i byte originali del punto di ingresso e sostituiscili con il ciclo infinito di due byte.
3. Riprendi il thread di ingresso e interroga il suo instruction pointer finché non raggiunge l'indirizzo modificato.
4. Sospendi il target e ripristina esattamente i byte originali prima di proseguire con l'analisi.

La tecnica è deliberatamente invasiva. Se il debugger o il relay si chiude prima del ripristino, il target può restare bloccato in un ciclo infinito. La modalità locale di KernelFlirt non supporta la modifica del punto di ingresso lato relay; avvia il processo manualmente e usa invece `attach <pid>`.<sup>[[2]](#references)</sup>

## Scegliere il meccanismo di breakpoint

KernelFlirt espone diversi meccanismi di breakpoint, ciascuno con effetti collaterali diversi. I seguenti comandi permettono all'analista di cambiare meccanismo quando il codice packed si riscrive, le pagine eseguibili sono di sola lettura o i byte dei breakpoint software vengono verificati per rilevare manomissioni.<sup>[[1]](#references)[[2]](#references)</sup>

| Meccanismo | Comando | Funzionamento e uso |
| --- | --- | --- |
| Software | `bp <expr>` | `INT3` basato su MDL; può strumentare pagine `.text` RX |
| Software condizionale | `bp <expr> if <condition>` | Valuta la condizione a ogni hit e riprende silenziosamente l'esecuzione se è falsa |
| Hardware su esecuzione | `ba e1 <expr>` | Usa uno dei registri DR0-DR3 senza modificare i byte del codice |
| Hardware sui dati | `ba w4 <expr>` / `ba r8 <expr>` | Monitora scritture o letture/scritture di 1, 2, 4 o 8 byte |
| Pagina guardia | `bm <expr> [size]` | Usa `PAGE_GUARD` per impostare un breakpoint su un intervallo di memoria |
| Temporaneo | `g <expr>`, `p` o `o` | Breakpoint di supporto per eseguire fino a un indirizzo, fare step-over e fare step-out |

Usa `bl` per distinguere le voci software, hardware, di memoria e temporanee, e `bc <address|handle|all>` per rimuoverle. Gli slot hardware sono limitati e dipendono dallo stato dei registri di debug, mentre le pagine guardia coprono un intervallo più ampio, ma si attivano anche in caso di accessi non correlati alla stessa pagina.

## Step singolo su x64 nativo e WoW64

Lo step singolo su x64 nativo imposta il trap flag del processore tramite `IOCTL_KF_SINGLE_STEP`. Step Over decodifica l'istruzione corrente e imposta breakpoint temporanei ai suoi possibili indirizzi successivi. Step Out legge l'indirizzo di ritorno dalla cima dello stack corrente. In corrispondenza del prologo di una funzione, questa ipotesi sullo stack potrebbe essere errata, quindi è preferibile usare un breakpoint interno noto.<sup>[[2]](#references)</sup>

L'hook `KdTrap` non intercetta le eccezioni a 32 bit allo stesso modo. Per i target WoW64, il debugger decodifica l'istruzione con Iced, scrive `EB FE` all'`EIP` successivo calcolato e interroga gli instruction pointer dei thread. Di conseguenza, `g <address>` non è disponibile per WoW64 e un semplice `g` blocca la console fino al raggiungimento di un breakpoint. Imposta prima un breakpoint raggiungibile ed evita un'esecuzione senza limite, perché `Ctrl+C` termina la console invece di annullare l'interrogazione.<sup>[[2]](#references)</sup>

## Analisi con l'ausilio di memoria, registri e simboli

La console può combinare un arresto su simbolo con l'ispezione della memoria e una modifica controllata. Le ricerche accettano wildcard per i byte, ASCII o UTF-16 e sono limitate a 4 MB, con un massimo di 256 corrispondenze riportate. I comandi di allocazione e protezione corrispondono agli IOCTL del driver per allocare, liberare e proteggere la memoria.<sup>[[2]](#references)</sup>

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

Il caricamento dei PDB legge la directory di debug PE di ciascun modulo remoto, estrae il relativo identificatore RSDS, trova il PDB corrispondente tramite DbgHelp/SymSrv e verifica che sia stato caricato come PDB. Posiziona i PDB privati accanto al target sulla macchina relay oppure aggiungi la relativa directory a `_NT_SYMBOL_PATH` sull’host.<sup>[[2]](#references)</sup>

## Modifiche allo stato anti-debug supportate dal kernel

L’accesso al kernel consente al debugger di rimuovere indicatori che un debugger in user mode non può nascondere in modo affidabile. Applica una modifica alla volta, verifica il controllo del target e ripristina l’hook corrispondente prima di terminare la sessione.<sup>[[2]](#references)</sup>

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

- `clr_debug_port` azzera `EPROCESS.DebugPort`.
- `clr_thread_hide` rimuove `HideFromDebugger` dai thread target.
- `ntqsi on` falsifica la classe `0x23` (`SystemKernelDebuggerInformation`) di `NtQuerySystemInformation`.
- `spoof on` fa sì che le letture in user-mode di `KUSER_SHARED_DATA.KdDebuggerEnabled` restituiscano false, mantenendo lo stato del kernel richiesto dal meccanismo trap.
- `stats` controlla i contatori degli hook e lo stato registrato di `KiDebugRoutine`, `KdpStub` e `KdTrap`.

Queste operazioni modificano lo stato dei processi e del kernel. Un crash, un inline hook obsoleto, un offset di struttura errato o un ripristino delle patch incompleto possono destabilizzare la VM: per questo sono obbligatori gli snapshot e un ambiente isolato con test signing.<sup>[[1]](#references)</sup>

## References

- [1] [Repository di KernelFlirt e documentazione principale](https://github.com/AkaTorich/KernelFlirt)
- [2] [Riferimento della console di KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
