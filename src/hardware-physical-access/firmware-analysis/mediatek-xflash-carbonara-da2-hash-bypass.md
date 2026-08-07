# MediaTek XFlash Carbonara Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Riepilogo

"Carbonara" sfrutta il percorso di download XFlash di MediaTek per eseguire uno stage 2 del Download Agent (DA2) modificato nonostante i controlli di integrità di DA1. DA1 memorizza in RAM lo SHA-256 previsto di DA2 e lo confronta prima del salto. In molti loader, l'host controlla completamente l'indirizzo e la dimensione di caricamento di DA2, ottenendo una scrittura in memoria non verificata che può sovrascrivere l'hash presente in memoria e reindirizzare l'esecuzione verso payload arbitrari (in un contesto pre-OS, con l'invalidazione della cache gestita da DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** è firmato/caricato da BootROM/Preloader. Quando Download Agent Authorization (DAA) è abilitato, dovrebbe essere eseguito solo DA1 firmato.
- **DA2** viene inviato tramite USB. DA1 riceve **dimensione**, **indirizzo di caricamento** e **SHA-256**, calcola l'hash del DA2 ricevuto e lo confronta con un **hash previsto incorporato in DA1** (copiato in RAM).
- **Weakness:** nei loader non patchati, DA1 non sanifica l'indirizzo/la dimensione di caricamento di DA2 e mantiene l'hash previsto scrivibile in memoria, consentendo all'host di manomettere il controllo.<sup>[[1]](#references)[[2]](#references)</sup>

## Flusso Carbonara (trick dei "due BOOT_TO")

1. **Primo `BOOT_TO`:** entra nel flusso di staging DA1→DA2 (DA1 alloca memoria, prepara la DRAM ed espone in RAM il buffer dell'hash previsto).
2. **Sovrascrittura dello slot dell'hash:** invia un payload di piccole dimensioni che analizza la memoria di DA1 alla ricerca dell'hash previsto di DA2 memorizzato e lo sovrascrive con lo SHA-256 del DA2 modificato dall'attaccante. Questo sfrutta il caricamento controllato dall'utente per posizionare il payload nel punto in cui risiede l'hash.
3. **Secondo `BOOT_TO` + digest:** attiva un altro `BOOT_TO` con i metadati di DA2 modificati e invia il digest raw di 32 byte corrispondente al DA2 modificato. DA1 ricalcola lo SHA-256 sul DA2 ricevuto, lo confronta con l'hash previsto ora modificato e il salto riesce, portando all'esecuzione del codice dell'attaccante.

Poiché l'indirizzo e la dimensione di caricamento sono controllati dall'attaccante, la stessa primitive può scrivere ovunque in memoria (non solo nel buffer dell'hash), consentendo implantati early-boot, helper per il bypass del secure boot o rootkit malevoli.<sup>[[1]](#references)[[2]](#references)</sup>

## Pattern PoC minimo (in stile mtkclient)
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
- `payload` replica il blob del paid-tool che applica una patch al buffer dell’hash atteso all’interno di DA1.
- `sha256(...).digest()` invia byte grezzi (non esadecimali), quindi DA1 confronta il valore con il buffer modificato.
- DA2 può essere un’immagine creata dall’attaccante; la scelta dell’indirizzo/della dimensione di caricamento consente il posizionamento arbitrario in memoria, con l’invalidazione della cache gestita da DA.<sup>[[3]](#references)</sup>

## Scenario delle patch (loader hardened)

- **Mitigation**: i DA aggiornati impostano in modo statico l’indirizzo di caricamento di DA2 su `0x40000000` e ignorano l’indirizzo fornito dall’host, impedendo alle scritture di raggiungere lo slot dell’hash di DA1 (nell’area `0x200000`). L’hash continua a essere calcolato, ma non è più scrivibile dall’attaccante.
- **Rilevamento dei DA sottoposti a patch**: mtkclient/penumbra scansionano DA1 alla ricerca di pattern che indicano l’hardening dell’indirizzo; se vengono trovati, Carbonara viene ignorato. I DA obsoleti espongono slot dell’hash scrivibili (comunemente intorno a offset come `0x22dea4` in DA1 V5) e rimangono vulnerabili.
- **V5 vs V6**: alcuni loader V6 (XML) accettano ancora indirizzi forniti dall’utente; i binari V6 più recenti impongono generalmente l’indirizzo statico e sono immuni a Carbonara, a meno che non vengano sottoposti a downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota post-Carbonara (heapb8)

MediaTek ha applicato una patch a Carbonara; una vulnerabilità più recente, **heapb8**, prende di mira il gestore del download dei file USB di DA2 sui loader V6 sottoposti a patch, consentendo l’esecuzione di codice anche quando `boot_to` è sottoposto a hardening. Sfrutta un heap overflow durante i trasferimenti di file suddivisi in chunk per assumere il controllo del flusso di esecuzione di DA2. L’exploit è pubblico in Penumbra/mtk-payloads e dimostra che le correzioni di Carbonara non chiudono l’intera attack surface di DA.<sup>[[4]](#references)</sup>

## Note per il triage e l’hardening

- I dispositivi in cui l’indirizzo/la dimensione di DA2 non vengono verificati e DA1 mantiene scrivibile l’hash atteso sono vulnerabili. Se un Preloader/DA successivo impone limiti sull’indirizzo o mantiene l’hash immutabile, Carbonara è mitigato.
- L’abilitazione di DAA e la verifica che DA1/Preloader convalidino i parametri di BOOT_TO (limiti + autenticità di DA2) chiudono la primitive. Chiudere solo la patch dell’hash senza limitare il caricamento lascia comunque un rischio di scrittura arbitraria.

## Riferimenti

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
