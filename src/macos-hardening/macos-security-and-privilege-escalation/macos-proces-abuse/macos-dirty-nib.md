# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli sulla tecnica, controlla il post originale di:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) e il seguente post di [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Ecco un riassunto:

### Cosa sono i file Nib

I file Nib (abbreviazione di NeXT Interface Builder), parte dell'ecosistema di sviluppo di Apple, sono destinati a definire **elementi UI** e le loro interazioni nelle applicazioni. Comprendono oggetti serializzati come finestre e pulsanti, e vengono caricati durante l'esecuzione. Nonostante il loro utilizzo continuo, Apple ora promuove gli Storyboard per una visualizzazione più completa del flusso UI.

Il file Nib principale è referenziato nel valore **`NSMainNibFile`** all'interno del file `Info.plist` dell'applicazione ed è caricato dalla funzione **`NSApplicationMain`** eseguita nella funzione `main` dell'applicazione.

### Processo di Iniezione Dirty Nib

#### Creazione e Configurazione di un File NIB

1. **Impostazione Iniziale**:
- Crea un nuovo file NIB utilizzando XCode.
- Aggiungi un Oggetto all'interfaccia, impostando la sua classe su `NSAppleScript`.
- Configura la proprietà `source` iniziale tramite Attributi di Runtime Definiti dall'Utente.
2. **Gadget di Esecuzione del Codice**:
- La configurazione facilita l'esecuzione di AppleScript su richiesta.
- Integra un pulsante per attivare l'oggetto `Apple Script`, attivando specificamente il selettore `executeAndReturnError:`.
3. **Test**:

- Un semplice Apple Script per scopi di test:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- Testa eseguendo nel debugger di XCode e cliccando il pulsante.

#### Targeting di un'Applicazione (Esempio: Pages)

1. **Preparazione**:
- Copia l'app target (ad es., Pages) in una directory separata (ad es., `/tmp/`).
- Avvia l'app per evitare problemi con Gatekeeper e memorizzarla nella cache.
2. **Sovrascrittura del File NIB**:
- Sostituisci un file NIB esistente (ad es., About Panel NIB) con il file DirtyNIB creato.
3. **Esecuzione**:
- Attiva l'esecuzione interagendo con l'app (ad es., selezionando l'elemento di menu `About`).

#### Prova di Concetto: Accesso ai Dati Utente

- Modifica l'AppleScript per accedere ed estrarre dati utente, come foto, senza il consenso dell'utente.

### Esempio di Codice: File .xib Maligno

- Accedi e rivedi un [**esempio di un file .xib maligno**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) che dimostra l'esecuzione di codice arbitrario.

### Altro Esempio

Nel post [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) puoi trovare un tutorial su come creare un dirty nib.

### Affrontare i Vincoli di Avvio

- I Vincoli di Avvio ostacolano l'esecuzione delle app da posizioni inaspettate (ad es., `/tmp`).
- È possibile identificare le app non protette dai Vincoli di Avvio e mirare a esse per l'iniezione del file NIB.

### Ulteriori Protezioni di macOS

A partire da macOS Sonoma, le modifiche all'interno dei pacchetti delle app sono limitate. Tuttavia, i metodi precedenti prevedevano:

1. Copiare l'app in un'altra posizione (ad es., `/tmp/`).
2. Rinominare le directory all'interno del pacchetto dell'app per bypassare le protezioni iniziali.
3. Dopo aver eseguito l'app per registrarsi con Gatekeeper, modificare il pacchetto dell'app (ad es., sostituendo MainMenu.nib con Dirty.nib).
4. Rinominare di nuovo le directory e rieseguire l'app per eseguire il file NIB iniettato.

**Nota**: Gli aggiornamenti recenti di macOS hanno mitigato questo exploit impedendo le modifiche ai file all'interno dei pacchetti delle app dopo la memorizzazione nella cache di Gatekeeper, rendendo l'exploit inefficace.

{{#include ../../../banners/hacktricks-training.md}}
