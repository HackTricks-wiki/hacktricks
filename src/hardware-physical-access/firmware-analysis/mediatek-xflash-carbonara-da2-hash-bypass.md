# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Sommario

"Carbonara" abusa del percorso di download XFlash di MediaTek per eseguire uno stage 2 (DA2) modificato del Download Agent nonostante i controlli di integrità di DA1. DA1 memorizza in RAM lo SHA-256 previsto di DA2 e lo confronta prima del branch. In molti loader, l'host controlla completamente l'indirizzo e la dimensione di caricamento di DA2, ottenendo così una scrittura in memoria non verificata che può sovrascrivere l'hash presente in memoria e reindirizzare l'esecuzione verso payload arbitrari (in un contesto pre-OS, con l'invalidazione della cache gestita da DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** è firmato/caricato da BootROM/Preloader. Quando Download Agent Authorization (DAA) è abilitato, dovrebbe essere eseguito solo DA1 firmato.
- **DA2** viene inviato tramite USB. DA1 riceve **dimensione**, **indirizzo di caricamento** e **SHA-256**, calcola l'hash del DA2 ricevuto e lo confronta con un **hash previsto incorporato in DA1** (copiato in RAM).
- **Vulnerabilità:** nei loader non patchati, DA1 non convalida l'indirizzo/la dimensione di caricamento di DA2 e mantiene l'hash previsto scrivibile in memoria, consentendo all'host di manomettere il controllo.<sup>[[1]](#references)[[2]](#references)</sup>

## Flusso Carbonara (il trucco dei "due BOOT_TO")

1. **Primo `BOOT_TO`:** entra nel flusso di staging DA1→DA2 (DA1 alloca la memoria, prepara la DRAM ed espone in RAM il buffer dell'hash previsto).
2. **Sovrascrittura dell'hash-slot:** invia un payload di piccole dimensioni che analizza la memoria di DA1 alla ricerca dell'hash previsto di DA2 memorizzato e lo sovrascrive con lo SHA-256 del DA2 modificato dall'attacker. Questo sfrutta il caricamento controllato dall'utente per posizionare il payload nel punto in cui risiede l'hash.
3. **Secondo `BOOT_TO` + digest:** attiva un altro `BOOT_TO` con i metadati di DA2 modificati e invia il digest raw di 32 byte corrispondente al DA2 modificato. DA1 ricalcola lo SHA-256 sul DA2 ricevuto, lo confronta con l'hash previsto ora modificato e il salto riesce, entrando nel codice dell'attacker.

Nei loader interessati, l'indirizzo e la dimensione non verificati possono fornire all'attacker una primitive di scrittura in memoria pre-OS selezionabile, oltre l'hash-slot. A seconda della memory map del SoC e delle fasi di verifica successive, ciò può supportare implant early-boot, helper per secure-boot-bypass o payload in stile rootkit. La sola esecuzione del codice DA non fornisce automaticamente persistenza né un secure-boot-bypass completo; sono comunque necessari un meccanismo di persistenza separato e una verification chain compatibile.<sup>[[1]](#references)[[2]](#references)</sup>

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
- Il `payload` di 16 byte riproduce il blob osservato nel workflow dello strumento a pagamento e utilizzato dall'implementazione pubblicata per applicare una patch al buffer dell'hash atteso. È specifico del loader, non una patch portabile dello slot dell'hash per ogni SoC o DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` invia byte grezzi (non esadecimali), affinché DA1 confronti il valore con il buffer modificato.
- Con un loader vulnerabile e compatibile, DA2 può essere un'immagine creata dall'attaccante e i metadati di caricamento scelti ne controllano il posizionamento in memoria. Convalida la combinazione DA/SoC prima della trasmissione, poiché indirizzi errati possono bloccare o danneggiare il target.<sup>[[3]](#references)</sup>

## Panorama delle patch (loader hardened)

- **Mitigazione osservata**: I DA hardened esaminati dai ricercatori forzano l'indirizzo di caricamento di DA2 a `0x40000000` e ignorano l'indirizzo fornito dall'host, impedendo le scritture nella regione dell'hash di DA1 osservata, vicino a `0x200000`. Considera entrambi gli indirizzi specifici dell'implementazione, non costanti architetturali.
- **Rilevamento dei DA sottoposti a patch**: mtkclient/penumbra analizzano DA1 alla ricerca di pattern che indicano l'hardening dell'indirizzo; se vengono trovati, Carbonara viene ignorato. I DA precedenti espongono slot dell'hash scrivibili (comunemente intorno a offset come `0x22dea4` in V5 DA1) e restano sfruttabili.
- **V5 vs V6**: Alcuni loader V6 (XML) accettano ancora indirizzi forniti dall'utente; i binari V6 più recenti generalmente applicano l'indirizzo fisso e sono immuni a Carbonara, a meno che non vengano sottoposti a downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota post-Carbonara (heapb8)

MediaTek ha applicato una patch a Carbonara; una vulnerabilità più recente, **heapb8**, prende di mira l'handler per il download dei file USB di DA2 nei loader V6 sottoposti a patch, ottenendo l'esecuzione di codice anche quando `boot_to` è hardened. Sfrutta un heap overflow durante i trasferimenti di file suddivisi in chunk per assumere il controllo del flusso di esecuzione di DA2. L'exploit è pubblico in Penumbra/mtk-payloads e dimostra che le correzioni di Carbonara non chiudono l'intera attack surface dei DA.<sup>[[4]](#references)</sup>

## Note per il triage e l'hardening

- I dispositivi in cui l'indirizzo/la dimensione di DA2 non vengono verificati e DA1 mantiene scrivibile l'hash atteso sono vulnerabili. Se un Preloader/DA successivo applica i limiti degli indirizzi o mantiene l'hash immutabile, Carbonara è mitigato.
- L'abilitazione di DAA e la verifica, da parte di DA1/Preloader, dei parametri BOOT_TO (limiti + autenticità di DA2) chiudono la primitive. Chiudere solo la patch dell'hash senza limitare il caricamento lascia comunque un rischio di scrittura arbitraria.

## References

- [1] [Carbonara: l'exploit di MediaTek che nessuno ha servito](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Documentazione dell'exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Codice sorgente di Carbonara in Penumbra](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: sfruttare i Download Agent V6 sottoposti a patch](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
