# Issues GitHub e file del repository come canale C2

{{#include ../banners/hacktricks-training.md}}

Un repository privato può separare lo **stato della sessione** dal **trasferimento del payload**: le issue registrano ogni host e lo stato del relativo handshake, mentre i file del repository trasportano dati cifrati in entrambe le direzioni. Non si tratta semplicemente di interrogare periodicamente il corpo di una issue per ottenere comandi. L’implementazione osservata usa un personal access token (PAT) di GitHub per accedere a entrambe le API.<sup>[[1]](#references)</sup> Per un PAT a granularità fine, creare o aggiornare issue richiede il permesso di scrittura Issues, mentre caricare file richiede il permesso di scrittura Contents. Un PAT classico richiede invece lo scope `repo`. Chiunque ottenga un token con privilegi sufficienti può accedere allo stesso canale.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake di issue e file

Un flusso di lavoro osservato usa un breve ID host esadecimale e la seguente macchina a stati. L’intervallo esatto dell’ID, le stringhe e i prefissi sono marcatori del protocollo, non requisiti dell’API GitHub.<sup>[[1]](#references)</sup>

1. All’avvio, interroga le issue aperte e chiuse con `GET /repos/{owner}/{repo}/issues?state=open` (e `state=closed`) per trovare lo stato delle sessioni precedenti. Crea un’issue aperta intitolata `1[ID]` con il corpo `hel` usando `POST /repos/{owner}/{repo}/issues`.
2. Leggi un file del repository il cui nome inizia con `2[ID]`; contiene la chiave pubblica RSA del server. Genera una nuova chiave di sessione da 16 byte, cifrala con RSA e carica il risultato in un file con prefisso `1[ID]`.
3. Ricava l’IV successivo eseguendo uno XOR tra l’IV incorporato e la chiave di sessione. Per ogni file scambiato, usa la chiave casuale da 16 byte contenuta nel nome del file per cifrarne o decifrarne il contenuto con AES. Il prefisso `2` indica dati dal server all’host; il prefisso `1` indica dati dall’host al server. Il nome del file contiene quindi le informazioni di instradamento e il materiale della chiave specifico del file, mentre l’issue contiene lo stato.
4. Leggi il file successivo con prefisso `2` e verifica che il contenuto decifrato sia uguale a `hel`. Carica le informazioni cifrate sull’host, quindi modifica il corpo dell’issue in `hey` con `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Solo a quel punto avvia il polling dei comandi.

La Contents API di GitHub legge un file tramite `GET /repos/{owner}/{repo}/contents/{path}` e ne crea o sostituisce uno tramite `PUT` sullo stesso percorso. Per i file fino a 1 MB, la risposta JSON predefinita include il contenuto codificato in Base64; per i file tra 1 e 100 MB è necessario usare il raw media type per recuperarne il contenuto. Il corpo della richiesta di caricamento deve contenere un messaggio di commit e il contenuto del file codificato in Base64; per sostituire un file esistente serve anche lo SHA del blob corrente. Questi dettagli dell’API sono distinti dal protocollo di cifratura descritto sopra.<sup>[[2]](#references)[[3]](#references)</sup>

Per un repository di test autorizzato, la parte di controllo delle issue può essere verificata con la REST API (sostituisci il repository e il PAT con quelli di test). Non inserire un token attivo nell’URL, nel corpo di un’issue o in un file sottoposto a commit.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Il meccanismo **non** richiede il titolo della issue, i marker `hel`/`hey` o le specifiche scelte di cifratura mostrate qui: questi elementi identificano una singola implementazione. L’idea riutilizzabile consiste nel separare lo stato mutabile dell’host dagli oggetti cifrati bidirezionali e associare entrambi a un ID host.<sup>[[1]](#references)</sup> Per un altro trasporto basato su GitHub issue, consulta le [note sul custom listener di AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Per un fallback basato sui commenti delle issue che ruota le credenziali del repository invece di trasportare lo stato della sessione, consulta [Servizi web e resolver dead-drop](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operazione FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [Documentazione GitHub – Endpoint REST API per le issue](https://docs.github.com/en/rest/issues/issues)
- [3] [Documentazione GitHub – Endpoint REST API per i contenuti dei repository](https://docs.github.com/en/rest/repos/contents)
