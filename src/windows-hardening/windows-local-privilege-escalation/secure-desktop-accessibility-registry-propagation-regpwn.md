# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Le funzionalità Accessibility di Windows memorizzano la configurazione utente sotto HKCU e la propagano in posizioni HKLM per sessione. Durante una transizione del **Secure Desktop** (schermata di blocco o prompt UAC), i componenti **SYSTEM** ricopiano questi valori. Se la **chiave HKLM per sessione è scrivibile dall'utente**, diventa un punto di strozzatura per scritture privilegiate che può essere reindirizzato con **registry symbolic links**, producendo una **scrittura arbitraria nel registro con privilegi SYSTEM**.

La tecnica RegPwn abusa di quella catena di propagazione con una piccola finestra di race stabilizzata tramite un **opportunistic lock (oplock)** su un file usato da `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Esempio di feature: **On-Screen Keyboard** (`osk`). Le posizioni rilevanti sono:

- **Elenco delle funzionalità a livello di sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configurazione per utente (scrivibile dall'utente)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configurazione HKLM per sessione (creata da `winlogon.exe`, scrivibile dall'utente)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure Desktop/hive utente predefinito (contesto SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagazione durante una transizione del Secure Desktop (semplificata):

1. **Utente `atbroker.exe`** copia `HKCU\...\ATConfig\osk` in `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** copia `HKLM\...\Session<session id>\ATConfig\osk` in `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** copia `HKU\.DEFAULT\...\ATConfig\osk` di nuovo in `HKLM\...\Session<session id>\ATConfig\osk`.

Se il sottoramo HKLM della sessione è scrivibile dall'utente, i passaggi 2/3 forniscono una scrittura con privilegi SYSTEM attraverso una posizione che l'utente può sostituire.

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Sostituire la chiave per sessione scrivibile dall'utente con una **registry symbolic link** che punta a una destinazione scelta dall'attaccante. Quando avviene la copia da parte di SYSTEM, segue il link e scrive valori controllati dall'attaccante nella chiave di destinazione arbitraria.

Idea chiave:

- Obiettivo della scrittura vittima (scrivibile dall'utente):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- L'attaccante sostituisce quella chiave con una **registry link** verso qualsiasi altra chiave.
- SYSTEM esegue la copia e scrive nella chiave scelta dall'attaccante con permessi SYSTEM.

Ciò fornisce una primitiva di **scrittura arbitraria nel registro con privilegi SYSTEM**.

## Vincere la finestra di race con gli oplock

Esiste una breve finestra temporale tra l'avvio di **SYSTEM `osk.exe`** e la scrittura della chiave per sessione. Per renderlo affidabile, l'exploit posa un **oplock** su:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Quando l'oplock scatta, l'attaccante sostituisce la chiave HKLM per sessione con un registry link, consente al SYSTEM di scrivere, quindi rimuove il link.

## Esempio di flusso di sfruttamento (livello alto)

1. Recuperare l'**ID sessione** corrente dal token di accesso.
2. Avviare un'istanza nascosta di `osk.exe` e mettere in sleep brevemente (assicurarsi che l'oplock si attivi).
3. Scrivere valori controllati dall'attaccante in:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Impostare un **oplock** su `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Attivare il **Secure Desktop** (`LockWorkstation()`), causando l'avvio come SYSTEM di `atbroker.exe` / `osk.exe`.
6. Al trigger dell'oplock, sostituire `HKLM\...\Session<session id>\ATConfig\osk` con un **registry link** verso un target arbitrario.
7. Attendere brevemente il completamento della copia da parte di SYSTEM, quindi rimuovere il link.

## Conversione del primitivo in esecuzione SYSTEM

Una catena semplice è sovrascrivere un valore di **configurazione del servizio** (ad es., `ImagePath`) e poi avviare il servizio. Il PoC RegPwn sovrascrive il `ImagePath` di **`msiserver`** e lo attiva istanziando il **MSI COM object**, ottenendo l'esecuzione di codice come **SYSTEM**.

## Correlati

Per altri comportamenti di Secure Desktop / UIAccess, vedere:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
