# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Sommario

"Carbonara" sfrutta il percorso di download XFlash di MediaTek per eseguire una Download Agent stage 2 (DA2) modificata nonostante i controlli di integrità di DA1. DA1 memorizza lo SHA-256 previsto di DA2 in RAM e lo confronta prima di effettuare il branch. Su molti loader, l'host controlla completamente l'indirizzo/size di caricamento di DA2, fornendo una scrittura in memoria non verificata che può sovrascrivere quell'hash in memoria e reindirizzare l'esecuzione a payload arbitrari (contesto pre-OS con invalidazione della cache gestita da DA).

## Confine di fiducia in XFlash (DA1 → DA2)

- **DA1** è firmato/caricato da BootROM/Preloader. Quando Download Agent Authorization (DAA) è abilitato, solo DA1 firmati dovrebbero essere eseguiti.
- **DA2** viene inviato via USB. DA1 riceve **size**, **load address**, e **SHA-256** e calcola l'hash del DA2 ricevuto, confrontandolo con uno **SHA-256 previsto incorporato in DA1** (copiato in RAM).
- **Debolezza:** Su loader non patched, DA1 non sanitizza l'indirizzo/size di caricamento di DA2 e mantiene l'hash previsto scrivibile in memoria, permettendo all'host di manomettere il controllo.

## Flusso Carbonara ("two BOOT_TO" trick)

1. **Primo `BOOT_TO`:** Entra nel flusso di staging DA1→DA2 (DA1 alloca, prepara la DRAM, ed espone il buffer dell'hash previsto in RAM).
2. **Sovrascrittura dello slot hash:** Invia un piccolo payload che scansiona la memoria di DA1 per l'hash previsto di DA2 memorizzato e lo sovrascrive con lo SHA-256 del DA2 modificato dall'attaccante. Questo sfrutta il caricamento controllato dall'utente per posizionare il payload dove risiede l'hash.
3. **Secondo `BOOT_TO` + digest:** Innesca un altro `BOOT_TO` con i metadata di DA2 patchati e invia il digest raw di 32 byte corrispondente al DA2 modificato. DA1 ricalcola lo SHA-256 sul DA2 ricevuto, lo confronta con l'hash ora patchato, e il salto ha successo nell'eseguire il codice dell'attaccante.

Poiché l'indirizzo/size di caricamento sono controllati dall'attaccante, la stessa primitiva può scrivere ovunque in memoria (non solo nel buffer dell'hash), abilitando implant early-boot, helper per il bypass di secure-boot, o rootkit maligni.

## Pattern PoC minimo (mtkclient-style)
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
- `payload` replica il blob dello strumento a pagamento che patcha l'expected-hash buffer dentro DA1.
- `sha256(...).digest()` invia byte raw (non hex) così DA1 confronta con il buffer patchato.
- DA2 può essere qualsiasi immagine creata dall'attaccante; scegliere il load address/size permette il posizionamento arbitrario in memoria con cache invalidation gestita da DA.

## Patch landscape (hardened loaders)

- **Mitigazione**: I DAs aggiornati hardcodano il DA2 load address a `0x40000000` e ignorano l'indirizzo fornito dall'host, quindi le scritture non possono raggiungere lo slot hash di DA1 (~0x200000 range). L'hash viene comunque calcolato ma non è più attacker-writable.
- **Detecting patched DAs**: mtkclient/penumbra scansionano DA1 per pattern che indicano l'address-hardening; se trovato, Carbonara viene saltato. I DA vecchi espongono slot hash scrivibili (comunemente intorno a offset come `0x22dea4` in V5 DA1) e restano exploitable.
- **V5 vs V6**: Alcuni loader V6 (XML) accettano ancora indirizzi forniti dall'utente; i binari V6 più recenti di solito impongono l'indirizzo fisso e sono immuni a Carbonara a meno che non vengano downgradati.

## Post-Carbonara (heapb8) note

MediaTek ha patchato Carbonara; una vulnerabilità più recente, **heapb8**, prende di mira il DA2 USB file download handler sui loader V6 patchati, fornendo code execution anche quando `boot_to` è hardened. Abusa di un heap overflow durante trasferimenti di file chunked per impadronirsi del controllo del flusso di esecuzione di DA2. L'exploit è pubblico in Penumbra/mtk-payloads e dimostra che le fix per Carbonara non chiudono tutta la superficie d'attacco dei DA.

## Notes for triage and hardening

- I dispositivi in cui DA2 address/size non sono verificati e DA1 mantiene l'expected hash scrivibile sono vulnerabili. Se un Preloader/DA successivo impone limiti sugli indirizzi o mantiene l'hash immutabile, Carbonara è mitigata.
- Abilitare DAA e assicurarsi che DA1/Preloader validino i parametri BOOT_TO (bounds + autenticità di DA2) chiude la primitiva. Chiudere solo la patch dell'hash senza limitare il load lascia comunque il rischio di arbitrary write.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
