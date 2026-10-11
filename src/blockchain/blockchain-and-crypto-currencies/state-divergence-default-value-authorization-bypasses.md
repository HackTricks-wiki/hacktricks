# Divergenza dello stato e bypass dell'autorizzazione tramite valori predefiniti

{{#include ../../banners/hacktricks-training.md}}

A volte l'autorizzazione dipende da uno stato economico derivato invece che da un ruolo esplicito, per esempio: «il chiamante possiede l'intera supply». Se i valori usati in tale condizione provengono da archivi diversi, una copia duplicata obsoleta può trasformare una legittima scorciatoia basata sulla proprietà in un bypass dell'autorizzazione. Il modulo Provenance marker ha dimostrato la pericolosa combinazione: il saldo aggiornato del chiamante veniva confrontato con i metadati locali del marker relativi alla supply, che non venivano aggiornati per gli asset con supply non fissa.<sup>[[1]](#references)</sup>

## Verificare lo stato duplicato come confine di autorizzazione

Per ogni valore usato da un controllo dei permessi, elencate **tutte le rappresentazioni**: stato canonico del modulo, campi degli oggetti, aggregati memorizzati nella cache, indici, snapshot, record dei bridge e copie replicate off-chain. Poi tracciate ogni percorso di creazione, mint, burn, trasferimento, reset, migrazione e sincronizzazione per determinare quale copia venga aggiornata in ciascuna modalità dell'oggetto. Un campo può essere autorevole in una modalità e puramente informativo in un'altra.<sup>[[1]](#references)</sup>

Un flusso di lavoro pratico per la revisione è:<sup>[[1]](#references)</sup>

1. Individuate le operazioni protette e riducete ogni ramo di autorizzazione a un predicato booleano.
2. Per ogni operando, annotate il relativo archivio, i percorsi di aggiornamento, gli stati del ciclo di vita e la fonte autorevole.
3. Generate transizioni che aggiornino una sola rappresentazione, quindi confrontate tutte le copie.
4. Dopo ogni transizione, tentate di eseguire l'operazione protetta da un account appena creato.
5. Proseguite oltre il bypass: se l'operazione modifica una ACL, autoassegnatevi ruoli persistenti e invocate le normali API privilegiate.

Tra gli schemi sospetti figurano `cachedSupply == balance`, `metadataOwner == caller` o `snapshotShares == currentShares` quando le due parti seguono regole di sincronizzazione diverse. Recuperare un valore autorevole per un operando non rende sicuro il confronto se l'altro operando è obsoleto.<sup>[[1]](#references)</sup>

## Bypass tramite uguaglianza con valori predefiniti

Anche un predicato di uguaglianza non è sicuro quando entrambi gli operandi possono assumere indipendentemente lo stesso valore predefinito. Il controllo seguente concede il «controllo completo della supply» a qualsiasi account vuoto quando `supply` è zero, indipendentemente dal fatto che lo zero derivi da metadati obsoleti o da un oggetto legittimamente privo di fondi.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Passare allo store canonico risolve la divergenza, ma **non** il caso dell'oggetto vuoto. La proprietà di sicurezza deve includere una condizione di validità indipendente; la patch di Provenance usa il supply live della banca e rifiuta un supply nil o pari a zero prima di confrontare il saldo del chiamante.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Applica lo stesso ragionamento a conteggi di quorum, percentuali di proprietà, debito, collaterale, epoch, nonce, timestamp e contatori: `callerValue == protectedValue` non deve autorizzare un chiamante finché il valore protetto non è valido in modo indipendente e non appartiene al dominio previsto.<sup>[[1]](#references)</sup>

## Acquisizione dell'ACL per eseguire operazioni privilegiate legittime

Un bypass in un'operazione di modifica dell'ACL è una primitiva di escalation dei privilegi persistente. Nel caso Provenance, un account senza privilegi e con zero token poteva superare il controllo obsoleto `0 == 0` sull'offerta, concedersi autorizzazioni di amministrazione, mint e prelievo, e quindi usare i normali message handler per creare asset o prelevare fondi dall'escrow. Pertanto, dopo la modifica dell'ACL, l'exploit non richiedeva una seconda vulnerabilità.<sup>[[1]](#references)</sup>

Sequenza generale di exploitation:<sup>[[1]](#references)</sup>

1. Trova un oggetto il cui campo non autorevole differisce dallo stato corrente oppure il cui valore protetto è quello predefinito.
2. Usa un'identità nuova/vuota, in modo che il suo valore locale corrisponda al valore obsoleto/predefinito.
3. Chiama l'endpoint di gestione dei ruoli, trasferimento della proprietà o aggiornamento dei criteri e concediti capacità persistenti.
4. Verifica la persistenza leggendo l'ACL dallo stato canonico.
5. Esegui l'operazione legittima ad alto impatto (creare asset, prelevare fondi, eseguire un upgrade, trasferire la proprietà o modificare i criteri).

Per valutare l'impatto, esamina ogni capacità raggiungibile dal nuovo ruolo invece di fermarti al bypass dell'autorizzazione. Gli account simili a escrow possono custodire asset non correlati all'oggetto i cui metadati obsoleti hanno consentito l'acquisizione.<sup>[[1]](#references)</sup>

## Invarianti e obiettivi di stateful fuzzing

Specifica l'autorizzazione indipendentemente dall'implementazione. Per una scorciatoia basata sull'offerta totale, l'invariante minimo è:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Usa un fuzzer basato su modello/macchina a stati per generare sequenze, non chiamate isolate, che coprano creazione, inizializzazione con valore zero, attivazione/finalizzazione, minting, burning, trasferimenti, reset, migrazioni, chiamate di sync e modifiche ACL. Dopo ogni transizione, confronta le rappresentazioni duplicate e verifica che un account nuovo non possa eseguire azioni protette. Prevedi casi espliciti per zero, un’unità, proprietà parziale, proprietà totale e valori inferiori o superiori a quelli aggiornati.<sup>[[1]](#references)[[2]](#references)</sup>

Le proprietà di regressione più significative sono:<sup>[[1]](#references)[[2]](#references)</sup>

- Un’offerta autorevole pari a zero non implica mai proprietà o privilegi amministrativi.
- I titolari di una quota parziale non possono diventare amministratori quando un’offerta duplicata corrisponde al loro saldo.
- Un titolare effettivo dell’intera offerta mantiene la scorciatoia prevista quando l’offerta corrente è positiva.
- I tentativi non riusciti di concedersi privilegi non modificano l’ACL né abilitano chiamate privilegiate successive.
- Le modifiche di modalità non possono cambiare silenziosamente quale rappresentazione un controllo di autorizzazione considera autorevole.

## References

- [1] [La divergenza dello stato consente accessi non autorizzati (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Correzione dei controlli sull’offerta obsoleti](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Rifiuto dell’offerta pari a zero nella scorciatoia di autorizzazione dell’offerta totale](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
