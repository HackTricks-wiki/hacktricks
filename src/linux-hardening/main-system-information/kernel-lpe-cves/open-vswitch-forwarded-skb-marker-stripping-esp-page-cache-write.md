# Rimozione del marker da skb inoltrati da Open vSwitch per scritture ESP nella page cache

{{#include ../../../banners/hacktricks-training.md}}

Un utile pattern di exploitation del kernel Linux consiste nel **ripulire i metadati di ownership di uno skb senza rimuoverne i frammenti estranei**, quindi instradare quello skb a un consumer che scrive in place. Nel caso di Open vSwitch (OVS), un upcall verso userspace fallito cancella `SKBFL_SHARED_FRAG` da uno skb `MSG_ZEROCOPY` ancora attivo; ESP successivamente decifra direttamente sopra il folio della page cache di un file in sola lettura. Questo consente una scrittura deterministica nella page cache locale ed è stato tracciato come CVE-2026-90049, CVE-2026-89487 e CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Si tratta di un problema della classe Copy Fail/Dirty Frag, non di una classica corruzione della memoria: non sono necessari race o divulgazione di indirizzi, è sufficiente che il file sia leggibile e i byte modificati si trovano nella page cache, non su disco.<sup>[[2]](#references)[[3]](#references)</sup>

## Invariante di sicurezza: i frammenti estranei devono rimanere contrassegnati

`SKBFL_SHARED_FRAG` indica ai consumer che scrivono in place che un frammento dello skb potrebbe fare riferimento a una memoria di cui non hanno la proprietà esclusiva. Il fast path ESP in `esp_input()` può decifrare in place uno skb non lineare e non clonato solo quando `skb_has_shared_frag()` è false; altrimenti, `skb_cow_data()` crea prima una memoria privata. Questo controllo lato consumer è stato aggiunto dopo Dirty Frag.<sup>[[5]](#references)</sup>

L'invariante ha quindi due parti indipendenti:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. I writer in place devono verificare `SKBFL_SHARED_FRAG` e copiare i dati condivisi prima di modificarli.
2. Ogni percorso di clonazione, coalescenza, trasferimento o forwarding deve preservare il marker finché la pagina estranea rimane associata.

Fragnesia ha violato la seconda regola spostando i descrittori dei frammenti in `skb_try_coalesce()`. Il percorso OVS è sottilmente diverso: non trasferisce affatto il frammento; cancella il marker **in place sullo skb originale e poi continua a inoltrarlo**.<sup>[[2]](#references)[[4]](#references)</sup>

## Raggiungibilità di OVS senza privilegi

Il datapath del kernel di OVS è controllato tramite famiglie generic-netlink come `ovs_datapath`, `ovs_vport`, `ovs_flow` e `ovs_packet`. Le operazioni che modificano lo stato usano `GENL_UNS_ADMIN_PERM`, che tiene conto dei namespace: un processo avviato con `unshare -Urn` ottiene `CAP_NET_ADMIN`, necessario per creare un datapath, collegare una veth e installare flow actions nel proprio network namespace. La risoluzione della famiglia OVS può anche caricare automaticamente `openvswitch.ko`; per questa superficie di attacco non servono `CAP_SYS_MODULE` sull'host, `ovs-vsctl` né `ovs-vswitchd`.<sup>[[2]](#references)[[7]](#references)</sup>

La distinzione importante è tra due tipi di upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- Un **flow miss** invia il pacchetto a `ovs-vswitchd`; se l'upcall fallisce, il pacchetto viene normalmente scartato.
- Un'azione esplicita `OVS_ACTION_ATTR_USERSPACE` invia una copia presa in prestito a un port ID selezionato, poi esegue le azioni successive sullo skb originale.

Un attacker può quindi installare un flow strutturato così:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Nessun listener possiede l'ID della porta selezionata, quindi l'azione userspace fallisce in modo prevedibile, mentre la successiva azione `OUTPUT` mantiene in vita il pacchetto originale.<sup>[[1]](#references)[[2]](#references)</sup>

## Causa principale: `skb_tx_error()` su un pacchetto che sopravvive

Il percorso di errore vulnerabile dell'upcall OVS chiama `skb_tx_error(skb)`. Questa funzione era stata progettata per una trasmissione non riuscita, dopo la quale lo skb viene liberato; completa la gestione dello zerocopy tramite `skb_zcopy_clear()`, la cui maschera di flag storicamente rimuoveva anche `SKBFL_SHARED_FRAG`. OVS ignorava l'errore dell'azione userspace e proseguiva con l'elenco delle azioni, violando il contratto di durata della funzione.<sup>[[1]](#references)[[2]](#references)</sup>

La transizione di stato sfruttabile è:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Questo funziona solo quando `skb_zcopy()` trova uno stato zerocopy. Un frammento che contiene solo `SKBFL_SHARED_FRAG` non è sufficiente; `MSG_ZEROCOPY` è utile perché crea `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` e imposta anche `SKBFL_DONT_ORPHAN`. Quest’ultimo fa sì che `skb_orphan_frags()` salti la sostituzione delle pagine esterne durante la copia in userspace di OVS.<sup>[[2]](#references)[[3]](#references)</sup>

## Creazione della primitiva di scrittura

Il trigger end-to-end è composto dai seguenti elementi.<sup>[[2]](#references)[[3]](#references)</sup>

1. Accedere a namespace utente e di rete privati con `unshare -Urn`.
2. Mappare un file target leggibile con `PROT_READ | MAP_SHARED`.
3. Usare un netns mittente separato e una coppia veth; il loopback locale copierebbe le pagine prese in prestito, vanificando la primitiva.
4. Creare un datapath OVS e il flow `USERSPACE`-then-`OUTPUT` che causa l’errore.
5. Installare uno stato XFRM ESP-in-UDP in modalità transport usando `rfc4106(gcm(aes))` e la porta UDP 4500.
6. Inviare un datagramma `MSG_ZEROCOPY` con un iovec strutturato come `[ESP header | mapped file bytes | invalid ICV]`.

Lo stato XFRM usa 20 byte di materiale chiave AES-128-GCM: 16 byte di chiave AES seguiti dai quattro byte di salt RFC 4106. Per un IV esplicito di otto byte scelto, la riservatezza del payload inizia con il blocco contatore `salt || IV || be32(2)`; il valore del contatore 1 maschera invece il risultato dell’autenticazione.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Una volta che OVS rimuove il marker, ESP segue il percorso no-copy ed esegue `plaintext = ciphertext XOR keystream` sul frammento basato sul file. L’autenticazione viene verificata **dopo** questa trasformazione, quindi un ICV non valido composto da soli zeri fa fallire il pacchetto con `-EBADMSG` solo dopo che i byte della page cache sono già stati modificati.<sup>[[2]](#references)</sup>

### Convertire GCM in byte scelti

Per il byte corrente `C` e il byte desiderato `P`, il primo byte del keystream del payload deve essere `C XOR P`. Con la chiave AES e il salt fissi, si esegue una ricerca esaustiva su un suffisso di 16 bit dell’IV esplicito e si precalcola un suffisso per ogni possibile primo byte del keystream:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

L'implementazione pubblica limita il ciphertext a 32 byte e avanza il frammento del file di un byte per ogni pacchetto. Il primo byte scelto sovrascrive il primo byte collaterale del pacchetto precedente; `pread()` aggiorna `C` prima di ogni pacchetto, i byte uguali vengono saltati e l'ultimo pacchetto viene accorciato per evitare che le scritture superino l'intervallo richiesto. In questo modo, una tabella di ricerca con 256 voci trasforma la primitiva in una scrittura nella page cache di contenuti scelti, a livello di byte, con circa un pacchetto per ogni byte diverso.<sup>[[2]](#references)[[3]](#references)</sup>

## Scrittura nella page cache per ottenere root

Un bersaglio pratico è un eseguibile setuid-root esistente. Il PoC sostituisce i primi 160 byte con un ELF statico completo, contenente un singolo `PT_LOAD` a indirizzo fisso con permessi di lettura ed esecuzione, senza `PT_INTERP` e con codice che chiama `setuid(0)` prima di `execve("/bin/sh", ...)`. In questo modo si evitano assunzioni sul punto di ingresso del binario originale, sul layout PIE, sul dynamic loader o sulle rilocazioni.<sup>[[2]](#references)[[3]](#references)</sup>

La modifica è visibile anche tra user namespace, perché la page cache non è isolata nei namespace. Il folio modificato non viene contrassegnato come dirty e quindi non viene scritto sul disco; esegui il bersaglio mentre è residente, poi elimina la corruzione temporanea con `posix_fadvise(..., POSIX_FADV_DONTNEED)`, in modo che le letture successive ricarichino il contenuto originale dal disco.<sup>[[2]](#references)[[3]](#references)</sup>

## Verifiche dell'esposizione e mitigazione

Verifica prima il kernel effettivamente fornito dal vendor. I requisiti rilevanti per l'esposizione sono gli user namespace non privilegiati, la disponibilità o la presenza in memoria di OVS e un'implementazione ESP disponibile.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Aggiorna a un kernel che includa l'intera serie di correzioni; la riparazione finale copre il percorso di ricircolo ed evita di modificare lo stato condiviso di `skb_shinfo()`, chiudendo anche una vulnerabilità correlata in `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Se OVS non viene usato, impedisci il caricamento sia tramite alias sia per nome con una regola `install` di modprobe, invece di affidarti solo a `blacklist`. Se l'host non termina IPsec e ESP è modulare, lo stesso controllo può rimuovere il sink di decrittazione.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Queste regole non sono efficaci quando un modulo è già caricato o la funzionalità è integrata nel kernel. Disabilitare gli user namespace senza privilegi rimuove anche la fonte di capacità legata ai namespace, ma può compromettere browser, Flatpak, Podman e altri carichi di lavoro sandbox/container.<sup>[[2]](#references)</sup>

## Lezioni apprese

Quando si esegue un audit del networking zero-copy, non limitare la ricerca agli helper che copiano o spostano i frammenti. Individua anche gli helper di errore/completamento che azzerano flag raggruppati, quindi verifica che ogni caller rispetti il contratto documentato sul ciclo di vita di skb. Un bit di proprietà della pagina raggruppato con bit del ciclo di vita zerocopy è sensibile dal punto di vista della sicurezza, anche quando il codice che lo azzera non accede direttamente a un frammento.<sup>[[1]](#references)[[2]](#references)</sup>

Una correzione robusta deve coprire tutti i percorsi tramite i quali skb può sopravvivere, inclusi la continuazione dell'azione e il recircolo, e deve tenere conto dei cloni che condividono `skb_shinfo()`. Sul lato del consumer, il fallimento dell'autenticazione non annulla le scritture in chiaro già eseguite da una trasformazione AEAD in-place, quindi i controlli sullo storage esterno devono avvenire prima che inizi la decrittografia.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Serie di correzioni netdev di Doyensec: net: non rimuovere i marker frag zerocopy da uno skb inoltrato](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: la rimozione dei marker dagli skb inoltrati di Open vSwitch consente una LPE deterministica sulla page cache ESP](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Proof of concept `ovs-pagecache-write` di Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Correzione Linux per il percorso di coalescenza originale di Fragnesia (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Controllo Linux dei frammenti condivisi lato consumer ESP (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: uso della modalità Galois/Counter (GCM) in IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Documentazione del datapath kernel di Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
