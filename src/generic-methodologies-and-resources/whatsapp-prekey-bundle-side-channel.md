# Esaurimento e ricarica del bundle Prekey di WhatsApp tramite canale laterale

{{#include ../banners/hacktricks-training.md}}

WhatsApp memorizza una identity key, una signed prekey e una riserva di one-time prekey per ogni dispositivo. Il recupero del bundle di un dispositivo consuma una one-time prekey conservata sul server, anche se il richiedente non invia alcun messaggio. Questo fornisce a un attacker con un account WhatsApp e il numero di telefono del target una sonda **lato server**, distinta dalla [temporizzazione delle ricevute di consegna lato client](side-channel-attacks-on-messaging-protocols.md). L'assenza di una one-time prekey indebolisce anche la forward secrecy dei *messaggi iniziali* di una sessione appena stabilita; da sola, non espone il testo in chiaro.<sup>[[1]](#references)[[2]](#references)</sup>

## Esaminare i bundle dei dispositivi di un target

L'[artifact Prekey Pogo](https://github.com/sbaresearch/prekey-pogo) si associa come sessione companion di WhatsApp e supporta query **manuali** su dispositivi e prekey. Associatelo a un account di test, quindi usate i comandi interattivi `target`, `devices`, `prekey` (dispositivo principale) e `combine` (tutti i dispositivi). L'artifact rilasciato omette deliberatamente le funzioni di esaurimento automatico e di intasamento del server.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Per ogni risposta, registra il JID del dispositivo, il timestamp del bundle `t`, l'ID della signed-prekey `skey.id` e se è presente la `key.id` monouso. L'ID dispositivo `0` corrisponde al telefono; gli ID diversi da zero ai companion. Nelle implementazioni testate nello studio, l'ID iniziale della signed-prekey distingue anche alcuni client: Android parte da `0`, iOS e macOS usano un valore casuale, mentre WhatsApp Web e Windows Desktop partono da `1`. Consideralo un fingerprint dell'implementazione, non una regola immutabile del protocollo.<sup>[[1]](#references)</sup>

## Trasformare i refill in un oracolo dello stato online

Per prima cosa, esegui una calibrazione su un dispositivo che controlli: richiedine ripetutamente il bundle finché il server non smette di restituire una `key` monouso, annotando l'ultimo timestamp e gli ID delle key. Per un dispositivo target, ripeti l'esaurimento e invia una nuova richiesta dopo un intervallo controllato: una nuova key monouso e un timestamp del bundle più recente indicano che il dispositivo ha caricato un nuovo batch. Nei test WhatsApp riportati, il server richiedeva un refill quando restavano meno di 11 key e i client caricavano 812 nuove key. Applica la procedura a ogni JID del dispositivo per distinguere il telefono dai companion. Un refill ritardato **suggerisce soltanto** che un dispositivo è offline: la pianificazione delle attività in background, la perdita della connessione di rete e la latenza di refill specifica del client possono produrre la stessa osservazione. A differenza di un RTT delle ricevute, questo probe non richiede un ciphertext consegnato né una conferma dal dispositivo della vittima.<sup>[[1]](#references)[[2]](#references)</sup>

Ogni query consuma una key monouso, quindi un oracolo persistente richiede un client personalizzato in grado di recuperare prekey ripetutamente; l'artifact pubblico mostra solo query manuali. Mantenere la riserva vuota può far sì che altri utenti stabiliscano nuove sessioni senza una prekey monouso. Questo riduce la forward secrecy dei messaggi iniziali fino a un nuovo ratchet step, ma per sfruttare ciphertext registrati occorre anche accedere al ciphertext E2EE e compromettere in seguito le relative chiavi private a lungo e medio termine. Le sessioni già stabilite non vengono declassate automaticamente.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: indagine sui problemi di sicurezza e privacy nel meccanismo di handshake di WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Il protocollo di accordo sulle chiavi X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artifact di Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
