# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara" sfrutta il percorso XFlash di MediaTek per eseguire una Download Agent modificata stage 2 (DA2) nonostante i controlli di integrità di DA1. DA1 memorizza l'SHA-256 atteso di DA2 in RAM e lo confronta prima del branch. Su molti loader, l'host controlla completamente l'indirizzo/size di caricamento di DA2, permettendo una scrittura in memoria non verificata che può sovrascrivere quell'hash in memoria e reindirizzare l'esecuzione verso payload arbitrari (contesto pre-OS con invalidazione della cache gestita da DA).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** è firmato/caricato da BootROM/Preloader. Quando Download Agent Authorization (DAA) è abilitato, solo DA1 firmati dovrebbero essere eseguiti.
- **DA2** è inviato via USB. DA1 riceve **size**, **load address**, e **SHA-256** e calcola l'hash della DA2 ricevuta, confrontandolo con un **hash atteso incorporato in DA1** (copiato in RAM).
- **Debolezza:** Su loader non patchati, DA1 non sanitizza l'indirizzo/size di caricamento di DA2 e mantiene l'hash atteso scrivibile in memoria, permettendo all'host di manomettere il controllo.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Entra nel flusso di staging DA1→DA2 (DA1 alloca, prepara la DRAM ed espone il buffer dell'hash atteso in RAM).
2. **Hash-slot overwrite:** Invia un piccolo payload che scansiona la memoria di DA1 per trovare l'hash atteso di DA2 e lo sovrascrive con l'SHA-256 della DA2 modificata dall'attaccante. Questo sfrutta il caricamento controllato dall'utente per posizionare il payload dove risiede l'hash.
3. **Second `BOOT_TO` + digest:** Innesca un altro `BOOT_TO` con i metadati DA2 patchati e invia il digest raw di 32 byte corrispondente alla DA2 modificata. DA1 ricalcola SHA-256 sulla DA2 ricevuta, lo confronta con l'hash atteso ora patchato, e il salto verso il codice dell'attaccante riesce.

Poiché indirizzo/size di caricamento sono controllati dall'attaccante, la stessa primitiva può scrivere ovunque in memoria (non solo nel buffer dell'hash), abilitando impianti early-boot, helper per bypassare secure-boot, o rootkit maligni.

## Minimal PoC pattern (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- `payload` replica il blob dello strumento a pagamento che patcha il buffer expected-hash all'interno di DA1.
- `sha256(...).digest()` invia byte grezzi (non in hex) quindi DA1 confronta con il buffer patchato.
- DA2 può essere qualsiasi immagine costruita dall'attaccante; scegliere il load address/size permette il posizionamento arbitrario in memoria con l'invalidazione della cache gestita da DA.

## Note per triage e hardening

- I dispositivi in cui DA2 address/size non vengono verificati e DA1 mantiene l'expected-hash scrivibile sono vulnerabili. Se un Preloader/DA successivo impone limiti agli indirizzi o mantiene l'hash immutabile, Carbonara è mitigato.
- Abilitare DAA e assicurarsi che DA1/Preloader convalidino i parametri BOOT_TO (bounds + autenticità di DA2) chiude la primitive. Chiudere solo la patch dell'hash senza limitare il load lascia comunque il rischio di scrittura arbitraria.

## Riferences

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
