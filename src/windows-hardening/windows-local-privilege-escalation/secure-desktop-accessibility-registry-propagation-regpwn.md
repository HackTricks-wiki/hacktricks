# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Le funzionalita di Accessibility di Windows mantengono la configurazione dell'utente in HKCU e la propagano nelle posizioni HKLM per-sessione. Durante una transizione al **Secure Desktop** (schermata di blocco o prompt UAC), i componenti **SYSTEM** ricopiano questi valori. Se la **per-session HKLM key** e scrivibile dall'utente, diventa un punto di scrittura privilegiato che puo essere reindirizzato con **registry symbolic links**, ottenendo una **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

La tecnica RegPwn sfrutta questa catena di propagazione con una piccola race window stabilizzata tramite un **opportunistic lock (oplock)** su un file utilizzato da `osk.exe`.<sup>[[1]](#references)</sup>

## Catena di propagazione del Registry (Accessibility -> Secure Desktop)

Feature di esempio: **On-Screen Keyboard** (`osk`). Le posizioni rilevanti sono:

- **Elenco delle feature a livello di sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configurazione per-utente (scrivibile dall'utente)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configurazione HKLM per-sessione (creata da `winlogon.exe`, scrivibile dall'utente)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (contesto SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagazione durante una transizione al secure desktop (semplificata):

1. L'`atbroker.exe` dell'**utente** copia `HKCU\...\ATConfig\osk` in `HKLM\...\Session<session id>\ATConfig\osk`.
2. L'`atbroker.exe` **SYSTEM** copia `HKLM\...\Session<session id>\ATConfig\osk` in `HKU\.DEFAULT\...\ATConfig\osk`.
3. L'`osk.exe` **SYSTEM** copia `HKU\.DEFAULT\...\ATConfig\osk` nuovamente in `HKLM\...\Session<session id>\ATConfig\osk`.

Se il subtree HKLM della sessione e scrivibile dall'utente, i passaggi 2/3 forniscono una scrittura SYSTEM attraverso una posizione che l'utente puo sostituire.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write tramite Registry Links

Sostituisci la key per-sessione scrivibile dall'utente con un **registry symbolic link** che punta a una destinazione scelta dall'attaccante. Quando avviene la copia SYSTEM, il link viene seguito e i valori controllati dall'attaccante vengono scritti nella key di destinazione arbitraria.

Idea principale:

- Target della scrittura della vittima (scrivibile dall'utente):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- L'attaccante sostituisce quella key con un **registry link** verso qualsiasi altra key.
- SYSTEM esegue la copia e scrive nella key scelta dall'attaccante con permessi SYSTEM.

Questo fornisce una primitive di **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

## Vincere la Race Window con gli Oplock

Esiste una breve finestra temporale tra l'avvio di **SYSTEM `osk.exe`** e la scrittura della per-session key. Per renderla affidabile, l'exploit imposta un **oplock** su:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Quando si attiva l'oplock, l'attaccante sostituisce la chiave HKLM per-sessione con un registry link, lascia che la scrittura da parte di SYSTEM venga completata, quindi rimuove il link.<sup>[[1]](#references)</sup>

## Flusso di sfruttamento di esempio (alto livello)

1. Ottenere l'**ID di sessione** corrente dal token di accesso.
2. Avviare un'istanza nascosta di `osk.exe` e attendere brevemente (per assicurarsi che l'oplock si attivi).
3. Scrivere valori controllati dall'attaccante in:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Impostare un **oplock** su `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Attivare **Secure Desktop** (`LockWorkstation()`), causando l'avvio di `atbroker.exe` / `osk.exe` da parte di SYSTEM.
6. Quando si attiva l'oplock, sostituire `HKLM\...\Session<session id>\ATConfig\osk` con un **registry link** verso un target arbitrario.
7. Attendere brevemente il completamento della copia da parte di SYSTEM, quindi rimuovere il link.<sup>[[1]](#references)</sup>

## Conversione della primitive in esecuzione come SYSTEM

Una catena semplice consiste nel sovrascrivere un valore di **configurazione del servizio** (ad esempio `ImagePath`) e quindi avviare il servizio. Il RegPwn PoC sovrascrive `ImagePath` di **`msiserver`** e lo attiva tramite l'istanza dell'**oggetto COM MSI**, ottenendo l'esecuzione di codice come **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Correlati

Per altri comportamenti di Secure Desktop / UIAccess, vedere:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Riferimenti

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
