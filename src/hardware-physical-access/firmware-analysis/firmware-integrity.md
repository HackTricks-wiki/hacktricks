# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Le **custom firmware e/o i binary compilati possono essere caricati per sfruttare flaw di integrity o di verifica delle signature**. I seguenti passaggi possono essere seguiti per la compilazione di un backdoor bind shell:

1. Il firmware può essere estratto usando firmware-mod-kit (FMK).
2. L'architettura e l'endianness del firmware target dovrebbero essere identificate.
3. Un cross compiler può essere costruito usando Buildroot o altri metodi adatti per l'ambiente.
4. Il backdoor può essere compilato usando il cross compiler.
5. Il backdoor può essere copiato nella directory /usr/bin del firmware estratto.
6. Il binario QEMU appropriato può essere copiato nella rootfs del firmware estratto.
7. Il backdoor può essere emulato usando chroot e QEMU.
8. Il backdoor può essere accessibile tramite netcat.
9. Il binario QEMU dovrebbe essere rimosso dalla rootfs del firmware estratto.
10. Il firmware modificato può essere ripacchettizzato usando FMK.
11. Il firmware backdoored può essere testato emulandolo con firmware analysis toolkit (FAT) e collegandosi all'IP e alla porta del target backdoor usando netcat.

Se una root shell è già stata ottenuta tramite dynamic analysis, bootloader manipulation o hardware security testing, binari malevoli precompilati come implants o reverse shells possono essere eseguiti. Strumenti automatici per payload/implant come il framework Metasploit e 'msfvenom' possono essere sfruttati seguendo questi passaggi:

1. L'architettura e l'endianness del firmware target dovrebbero essere identificate.
2. Msfvenom può essere usato per specificare il payload target, l'IP dell'host attacker, il numero di porta in ascolto, il filetype, l'architettura, la piattaforma e il file di output.
3. Il payload può essere trasferito sul dispositivo compromesso e bisogna assicurarsi che abbia i permessi di esecuzione.
4. Metasploit può essere preparato per gestire le richieste in arrivo avviando msfconsole e configurando le impostazioni in base al payload.
5. Il meterpreter reverse shell può essere eseguito sul dispositivo compromesso.

## Unauthenticated transport bridges to privileged update protocols

Un errore comune di progettazione embedded è esporre lo **stesso internal command protocol su più transport** ma imporre authentication solo su uno di essi. Per esempio, USB può richiedere challenge-response mentre BLE inoltra semplicemente **GATT writes** non autenticati nello stesso privileged firmware-update handler.

Flusso offensivo tipico:

1. Enumerare il BLE GATT database e identificare le writable characteristics usate dall'app mobile ufficiale.
2. Sniffare il traffico dell'app e cercare **magic bytes / opcodes** che corrispondano al protocollo cablato.
3. Riprodurre i privileged commands su BLE **senza pairing** e verificare se le operazioni sensibili funzionano ancora.
4. Se firmware upgrade, config write, debug o factory-test opcodes sono raggiungibili, considerare BLE come una **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Cose da verificare durante il reversing:

- BLE richiede **pairing/bonding** o solo una semplice connessione?
- Tutti i transport sono instradati alla stessa tabella interna di dispatcher?
- Gli opcode privilegiati sono filtrati in modo diverso su USB / BLE / UART / Wi-Fi?
- La mobile app può attivare da remoto i handler di firmware update, recovery o diagnostic?

## I container firmware protetti solo da checksum sono ancora firmware controllato dall'attaccante

Un container firmware protetto solo da un **checksum non keyed** (CRC32, SHA-256, MD5, ecc.) fornisce detection della corruzione, **non autenticità**. Se l'attaccante può raggiungere la routine di update, può patchare l'immagine, ricalcolare il checksum e flashare codice arbitrario.

Red flag durante la RE:

- Il codice di update valida solo un blob di checksum finale come `CHK2`, `CRC` o `SHA256`.
- Non è presente verifica di signature o un root of trust di secure boot.
- Non viene usato nessun MAC / HMAC / authenticated encryption legato al device.
- La recovery mode accetta lo stesso formato di immagine non autenticato.

Flusso pratico di validazione:

1. Estrai il container firmware e identifica bootloader, main firmware e metadata di integrità.
2. Modifica una stringa innocua o un banner nell'immagine.
3. Ricalcola il checksum esattamente come si aspetta l'updater.
4. Riflashare l'immagine attraverso il normale percorso di update.
5. Conferma la modifica al boot per dimostrare la sostituzione arbitraria del firmware.

Se questo funziona su un transport raggiungibile da remoto come BLE/Wi-Fi, il bug è di fatto una **unauthenticated OTA firmware replacement**.

## Trasformare un peripheral USB trusted in BadUSB tramite reflashing del firmware

Quando il device target è già trusted dall'host via USB, il firmware malevolo potrebbe non dover implementare una nuova USB stack completa. Un pivot molto più semplice è spesso **riutilizzare il supporto HID esistente**.

Pattern utile:

1. Verifica se il device si enumera già come interfaccia **HID Consumer Control** / media / vendor HID.
2. Individua il **HID report descriptor** esistente nel firmware.
3. Aggiungi o sostituisci voci del descriptor in modo che il device annunci anche capacità **keyboard**.
4. Riutilizza le routine firmware esistenti che già inviano report HID invece di scrivere una nuova implementazione del transport.
5. Inietta report di key press + key release per digitare comandi sull'host.

Questo trasforma il compromise del firmware in **host compromise** perché il PC si fiderà del peripheral riflashato come di una keyboard legittima.

### Checklist minima di assessment

- `dmesg`, Device Manager o i descriptor USB mostrano un'interfaccia HID esistente?
- C'è spazio disponibile vicino al report descriptor o una tabella descriptor rilocabile?
- Le routine esistenti di invio media-control possono essere riutilizzate per report keyboard?
- L'host accetta automaticamente la nuova interfaccia keyboard dopo il reflashing?

## Esecuzione affidabile del payload dentro firmware RTOS

Invece di inserire trampolini fragili in percorsi di codice casuali, cerca **task RTOS esistenti** che siano inutilizzati o a basso impatto durante il normale funzionamento.

Perché è utile:

- Lo scheduler avvia il payload in modo naturale durante il boot.
- Eviti di corrompere il control flow critico.
- I payload ritardati hanno meno probabilità di attivare watchdog reset rispetto all'esecuzione dentro un handler USB/network sensibile alla latenza.

I target migliori sono task di diagnostic, factory-test, telemetry o coprocessor service che sembrano dormienti nell'uso normale.

## Iterazione rapida dell'exploit: riutilizzare handler di protocolli benigni

Una volta possibile il patching del firmware, un modo compatto per accelerare la RE è sovrascrivere un handler di comando innocuo (per esempio un opcode **echo/debug**) con primitive personalizzate di **memory read / write / execute**. Questo evita il reflashing completo a ogni esperimento ed è particolarmente utile quando il device supporta l'handler modificato su un transport cablato veloce.

Usalo per:

- Verificare memory map sparse-loaded
- Ispezionare live lo stato di heap/task
- Testare piccoli payload prima di scriverli in flash
- Recuperare in sicurezza function pointer, stringhe e descriptor table

## Riferimenti

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
