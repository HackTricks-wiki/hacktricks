# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati valori importanti nella memoria di un gioco in esecuzione e modificarli.\
Quando lo scarichi e lo esegui, ti viene **presentato** un **tutorial** su come utilizzare lo strumento. Se vuoi imparare a usare lo strumento, è altamente consigliato completarlo.

## Cosa stai cercando?

![](<../../images/image (762).png>)

Questo strumento è molto utile per trovare **dove alcuni valori** (di solito un numero) **sono memorizzati nella memoria** di un programma.\
**Di solito i numeri** sono memorizzati in forma di **4byte**, ma potresti anche trovarli in formati **double** o **float**, o potresti voler cercare qualcosa **di diverso da un numero**. Per questo motivo devi essere sicuro di **selezionare** ciò che vuoi **cercare**:

![](<../../images/image (324).png>)

Puoi anche indicare **diversi** tipi di **ricerche**:

![](<../../images/image (311).png>)

Puoi anche spuntare la casella per **fermare il gioco mentre scansiona la memoria**:

![](<../../images/image (1052).png>)

### Tasti di scelta rapida

In _**Modifica --> Impostazioni --> Tasti di scelta rapida**_ puoi impostare diversi **tasti di scelta rapida** per diversi scopi, come **fermare** il **gioco** (che è molto utile se a un certo punto vuoi scansionare la memoria). Sono disponibili altre opzioni:

![](<../../images/image (864).png>)

## Modificare il valore

Una volta che hai **trovato** dove si trova il **valore** che stai **cercando** (di più su questo nei passaggi successivi), puoi **modificarlo** facendo doppio clic su di esso, quindi facendo doppio clic sul suo valore:

![](<../../images/image (563).png>)

E infine **spuntando la casella** per applicare la modifica nella memoria:

![](<../../images/image (385).png>)

La **modifica** alla **memoria** sarà immediatamente **applicata** (nota che finché il gioco non utilizza di nuovo questo valore, il valore **non verrà aggiornato nel gioco**).

## Cercare il valore

Quindi, supponiamo che ci sia un valore importante (come la vita del tuo utente) che vuoi migliorare, e stai cercando questo valore nella memoria.

### Attraverso un cambiamento noto

Supponendo che tu stia cercando il valore 100, **esegui una scansione** cercando quel valore e trovi molte coincidenze:

![](<../../images/image (108).png>)

Poi, fai qualcosa affinché **il valore cambi**, e **ferma** il gioco e **esegui** una **scansione successiva**:

![](<../../images/image (684).png>)

Cheat Engine cercherà i **valori** che **sono passati da 100 al nuovo valore**. Congratulazioni, hai **trovato** l'**indirizzo** del valore che stavi cercando, ora puoi modificarlo.\
&#xNAN;_Se hai ancora diversi valori, fai qualcosa per modificare di nuovo quel valore e esegui un'altra "scansione successiva" per filtrare gli indirizzi._

### Valore sconosciuto, cambiamento noto

Nello scenario in cui **non conosci il valore** ma sai **come farlo cambiare** (e persino il valore del cambiamento), puoi cercare il tuo numero.

Quindi, inizia eseguendo una scansione di tipo "**Valore iniziale sconosciuto**":

![](<../../images/image (890).png>)

Poi, fai cambiare il valore, indica **come** il **valore** **è cambiato** (nel mio caso è diminuito di 1) ed esegui una **scansione successiva**:

![](<../../images/image (371).png>)

Ti verranno presentati **tutti i valori che sono stati modificati nel modo selezionato**:

![](<../../images/image (569).png>)

Una volta trovato il tuo valore, puoi modificarlo.

Nota che ci sono **molti possibili cambiamenti** e puoi fare questi **passaggi quante più volte vuoi** per filtrare i risultati:

![](<../../images/image (574).png>)

### Indirizzo di memoria casuale - Trovare il codice

Fino ad ora abbiamo imparato come trovare un indirizzo che memorizza un valore, ma è altamente probabile che in **diverse esecuzioni del gioco quell'indirizzo si trovi in posti diversi della memoria**. Quindi scopriamo come trovare sempre quell'indirizzo.

Utilizzando alcuni dei trucchi menzionati, trova l'indirizzo dove il tuo gioco attuale sta memorizzando il valore importante. Poi (ferma il gioco se lo desideri) fai **clic destro** sull'**indirizzo** trovato e seleziona "**Scopri cosa accede a questo indirizzo**" o "**Scopri cosa scrive a questo indirizzo**":

![](<../../images/image (1067).png>)

La **prima opzione** è utile per sapere quali **parti** del **codice** stanno **utilizzando** questo **indirizzo** (che è utile per altre cose come **sapere dove puoi modificare il codice** del gioco).\
La **seconda opzione** è più **specifica** e sarà più utile in questo caso poiché siamo interessati a sapere **da dove questo valore viene scritto**.

Una volta selezionata una di queste opzioni, il **debugger** sarà **collegato** al programma e apparirà una nuova **finestra vuota**. Ora, **gioca** al **gioco** e **modifica** quel **valore** (senza riavviare il gioco). La **finestra** dovrebbe essere **riempita** con gli **indirizzi** che stanno **modificando** il **valore**:

![](<../../images/image (91).png>)

Ora che hai trovato l'indirizzo che modifica il valore, puoi **modificare il codice a tuo piacimento** (Cheat Engine ti consente di modificarlo rapidamente in NOP):

![](<../../images/image (1057).png>)

Quindi, ora puoi modificarlo affinché il codice non influisca sul tuo numero, o influisca sempre in modo positivo.

### Indirizzo di memoria casuale - Trovare il puntatore

Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, utilizzando "**Scopri cosa scrive a questo indirizzo**", scopri quale indirizzo scrive questo valore e fai doppio clic su di esso per ottenere la vista di disassemblaggio:

![](<../../images/image (1039).png>)

Poi, esegui una nuova scansione **cercando il valore esadecimale tra "\[]"** (il valore di $edx in questo caso):

![](<../../images/image (994).png>)

(_Se ne appaiono diversi, di solito hai bisogno di quello con l'indirizzo più piccolo_)\
Ora, abbiamo **trovato il puntatore che modificherà il valore che ci interessa**.

Fai clic su "**Aggiungi indirizzo manualmente**":

![](<../../images/image (990).png>)

Ora, fai clic sulla casella di controllo "Puntatore" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario, l'indirizzo trovato nell'immagine precedente era "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Nota come il primo "Indirizzo" è automaticamente popolato dall'indirizzo del puntatore che introduci)

Fai clic su OK e verrà creato un nuovo puntatore:

![](<../../images/image (308).png>)

Ora, ogni volta che modifichi quel valore, stai **modificando il valore importante anche se l'indirizzo di memoria dove si trova il valore è diverso.**

### Iniezione di codice

L'iniezione di codice è una tecnica in cui inietti un pezzo di codice nel processo target e poi reindirizzi l'esecuzione del codice per passare attraverso il tuo codice scritto (come darti punti invece di sottrarli).

Quindi, immagina di aver trovato l'indirizzo che sottrae 1 dalla vita del tuo giocatore:

![](<../../images/image (203).png>)

Fai clic su Mostra disassemblatore per ottenere il **codice disassemblato**.\
Poi, fai clic su **CTRL+a** per invocare la finestra di Auto assemble e seleziona _**Modello --> Iniezione di codice**_

![](<../../images/image (902).png>)

Compila l'**indirizzo dell'istruzione che vuoi modificare** (questo di solito viene autofillato):

![](<../../images/image (744).png>)

Verrà generato un modello:

![](<../../images/image (944).png>)

Quindi, inserisci il tuo nuovo codice assembly nella sezione "**newmem**" e rimuovi il codice originale dalla sezione "**originalcode**" se non vuoi che venga eseguito\*\*.\*\* In questo esempio, il codice iniettato aggiungerà 2 punti invece di sottrarre 1:

![](<../../images/image (521).png>)

**Fai clic su esegui e così via e il tuo codice dovrebbe essere iniettato nel programma cambiando il comportamento della funzionalità!**

## **Riferimenti**

- **Tutorial di Cheat Engine, completalo per imparare a iniziare con Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}
