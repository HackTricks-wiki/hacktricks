# LPE tramite propagazione del Registro di sistema dell'accessibilità del Secure Desktop (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Le funzionalità di accessibilità di Windows mantengono la configurazione dell'utente in HKCU e la propagano nelle posizioni HKLM specifiche della sessione. Durante una transizione al **Secure Desktop** (schermata di blocco o richiesta UAC), i componenti **SYSTEM** ricopiano questi valori. Se la **chiave HKLM specifica della sessione è scrivibile dall'utente**, diventa un punto privilegiato per la scrittura che può essere reindirizzato tramite **collegamenti simbolici del Registro di sistema**, ottenendo una **scrittura arbitraria nel Registro di sistema come SYSTEM**.<sup>[[1]](#references)</sup>

La tecnica RegPwn sfrutta questa catena di propagazione con una piccola race window stabilizzata tramite un **opportunistic lock (oplock)** su un file utilizzato da `osk.exe`.<sup>[[1]](#references)</sup>

## Catena di propagazione del Registro di sistema (Accessibilità -> Secure Desktop)

Esempio di funzionalità: **Tastiera su schermo** (`osk`). Le posizioni rilevanti sono:

- **Elenco delle funzionalità a livello di sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configurazione per utente (scrivibile dall'utente)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configurazione HKLM specifica della sessione (creata da `winlogon.exe`, scrivibile dall'utente)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Hive dell'utente predefinito/Secure Desktop (contesto SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagazione durante una transizione al Secure Desktop (semplificata):

1. **`atbroker.exe` dell'utente** copia `HKCU\...\ATConfig\osk` in `HKLM\...\Session<session id>\ATConfig\osk`.
2. **`atbroker.exe` eseguito come SYSTEM** copia `HKLM\...\Session<session id>\ATConfig\osk` in `HKU\.DEFAULT\...\ATConfig\osk`.
3. **`osk.exe` eseguito come SYSTEM** copia `HKU\.DEFAULT\...\ATConfig\osk` nuovamente in `HKLM\...\Session<session id>\ATConfig\osk`.

Se il sottoalbero HKLM della sessione è scrivibile dall'utente, il passaggio 2/3 fornisce una scrittura come SYSTEM tramite una posizione che l'utente può sostituire.<sup>[[1]](#references)</sup>

## Primitiva: scrittura arbitraria nel Registro di sistema come SYSTEM tramite collegamenti del Registro

Sostituisci la chiave specifica della sessione scrivibile dall'utente con un **collegamento simbolico del Registro di sistema** che punti a una destinazione scelta dall'attaccante. Quando avviene la copia come SYSTEM, il collegamento viene seguito e i valori controllati dall'attaccante vengono scritti nella chiave di destinazione arbitraria.

Idea chiave:

- Destinazione della scrittura della vittima (scrivibile dall'utente):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- L'attaccante sostituisce quella chiave con un **collegamento del Registro di sistema** verso qualsiasi altra chiave.
- SYSTEM esegue la copia e scrive nella chiave scelta dall'attaccante con autorizzazioni SYSTEM.

Questo produce una primitiva di **scrittura arbitraria nel Registro di sistema come SYSTEM**.<sup>[[1]](#references)</sup>

## Vincere la race window con gli oplock

Esiste una breve finestra temporale tra l'avvio di **`osk.exe` come SYSTEM** e la scrittura della chiave specifica della sessione. Per renderla affidabile, l'exploit posiziona un **oplock** su:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Quando si attiva l’oplock, l’attaccante sostituisce la chiave HKLM per-sessione con un registry link, lascia che la scrittura da parte di SYSTEM venga eseguita, quindi rimuove il link.<sup>[[1]](#references)</sup>

## Flusso di Exploitation di esempio (alto livello)

1. Ottieni l’**ID della sessione** corrente dal token di accesso.
2. Avvia un’istanza nascosta di `osk.exe` e attendi brevemente (per assicurarti che l’oplock si attivi).
3. Scrivi valori controllati dall’attaccante in:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Imposta un **oplock** su `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Attiva il **Secure Desktop** (`LockWorkstation()`), causando l’avvio di `atbroker.exe` / `osk.exe` da parte di SYSTEM.
6. Quando si attiva l’oplock, sostituisci `HKLM\...\Session<session id>\ATConfig\osk` con un **registry link** verso un target arbitrario.
7. Attendi brevemente il completamento della copia da parte di SYSTEM, quindi rimuovi il link.<sup>[[1]](#references)</sup>

## Conversione della Primitive in Esecuzione come SYSTEM

Una catena semplice consiste nel sovrascrivere un valore di **configurazione del servizio** (ad esempio `ImagePath`) e quindi avviare il servizio. Il PoC RegPwn sovrascrive `ImagePath` di **`msiserver`** e lo attiva istanziando l’**oggetto COM MSI**, ottenendo l’**esecuzione di codice** come **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Correlati

Per altri comportamenti di Secure Desktop / UIAccess, consulta:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
