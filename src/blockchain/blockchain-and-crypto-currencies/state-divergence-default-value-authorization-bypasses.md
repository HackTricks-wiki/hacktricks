# Bypass dell'autorizzazione tramite divergenza dello stato e valori predefiniti

{{#include ../../banners/hacktricks-training.md}}

L'autorizzazione a volte dipende da uno stato economico derivato invece che da un ruolo esplicito, ad esempio: "il chiamante possiede l'intera supply". Se i valori usati in quel predicato provengono da store diversi, un duplicato obsoleto può trasformare una scorciatoia legittima per la proprietà in un authorization bypass. Il modulo Provenance marker ha dimostrato la combinazione pericolosa: un saldo live del chiamante veniva confrontato con metadati della supply locali al marker, che non venivano aggiornati per gli asset con supply non fissa.<sup>[[1]](#references)</sup>

## Verificare lo stato duplicato come confine di autorizzazione

Per ogni valore usato da un controllo dei permessi, elenca **tutte le rappresentazioni**: stato canonico del modulo, campi degli oggetti, aggregati memorizzati nella cache, indici, snapshot, record dei bridge e mirror off-chain. Quindi traccia ogni percorso di creazione, mint, burn, trasferimento, reset, migrazione e sincronizzazione per determinare quale copia viene aggiornata in ciascuna modalità dell'oggetto. Un campo può essere autorevole per una modalità e informativo per un'altra.<sup>[[1]](#references)</sup>

Un workflow pratico di revisione è:<sup>[[1]](#references)</sup>

1. Individua le azioni protette e riduci ogni ramo di autorizzazione a un predicato booleano.
2. Per ogni operando, annota il relativo store, i percorsi di aggiornamento, gli stati del ciclo di vita e la source of truth.
3. Genera transizioni che aggiornino una sola rappresentazione, quindi confronta tutte le copie.
4. Tenta l'azione protetta da un account nuovo dopo ogni transizione.
5. Vai oltre il bypass: se l'azione modifica un ACL, assegnati ruoli persistenti e invoca le normali API privilegiate.

I pattern sospetti includono `cachedSupply == balance`, `metadataOwner == caller` o `snapshotShares == currentShares` quando i due lati hanno regole di sincronizzazione diverse. Interrogare un valore autorevole per un operando non rende sicuro il confronto quando l'altro operando è obsoleto.<sup>[[1]](#references)</sup>

## Bypass dell'uguaglianza con valore predefinito

Un predicato di uguaglianza non è sicuro neanche quando entrambi gli operandi possono assumere indipendentemente lo stesso valore predefinito. Il controllo seguente concede il "controllo dell'intera supply" a qualsiasi account vuoto quando `supply` è zero, indipendentemente dal fatto che lo zero derivi da metadati obsoleti o da un oggetto legittimamente non finanziato.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Passare al canonical store risolve la divergenza, ma **non** il caso dell'oggetto vuoto. La proprietà di sicurezza deve includere una condizione di validità indipendente; la patch Provenance utilizza la supply bancaria live e rifiuta una supply nil o pari a zero prima di confrontarla con il saldo del chiamante.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Applica lo stesso ragionamento a conteggi del quorum, percentuali di ownership, debito, collaterale, epoch, nonce, timestamp e contatori: `callerValue == protectedValue` non deve autorizzare un caller finché il valore protetto non è indipendentemente valido e non appartiene al dominio previsto.<sup>[[1]](#references)</sup>

## Takeover dell'ACL verso operazioni privilegiate legittime

Un bypass in un'operazione di modifica dell'ACL è una primitiva durevole di privilege escalation. Nel caso Provenance, un account non privilegiato con zero token poteva superare il controllo stale `0 == 0` sulla supply, concedersi permessi amministrativi, di mint e di withdrawal, quindi usare i normali message handler per effettuare il mint degli asset o ritirare l'escrow. L'exploit non richiedeva quindi una seconda vulnerabilità dopo la modifica dell'ACL.<sup>[[1]](#references)</sup>

Sequenza generale di exploitation:<sup>[[1]](#references)</sup>

1. Individua un oggetto il cui campo non authoritative differisce dallo stato live, oppure il cui valore protetto è quello di default.
2. Usa un'identità nuova/vuota in modo che il suo valore locale corrisponda a quel valore stale/default.
3. Chiama l'endpoint di role-management, ownership-transfer o policy-update e concediti capability durevoli.
4. Conferma la persistenza leggendo l'ACL dallo stato canonical.
5. Invoca l'operazione legittima ad alto impatto (mint, withdraw, upgrade, trasferimento della ownership o modifica della policy).

Nel valutare l'impatto, esamina ogni capability raggiungibile dal nuovo ruolo invece di fermarti al bypass dell'autorizzazione. Gli account simili a escrow possono custodire asset non correlati all'oggetto i cui metadati stale hanno reso possibile il takeover.<sup>[[1]](#references)</sup>

## Target per invariant e stateful-fuzzing

Specifica l'autorizzazione indipendentemente dall'implementazione. Per una scorciatoia basata sulla supply completa, l'invariant minimo è:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Usa un model/state-machine fuzzer per generare sequenze, non chiamate isolate, che coprano creazione, inizializzazione con valore zero, attivazione/finalizzazione, minting, burning, transfers, reset, migrazioni, chiamate di sync e modifiche all'ACL. Dopo ogni transizione, confronta le rappresentazioni duplicate e verifica che un account appena creato non possa eseguire alcuna azione protetta. Inserisci casi espliciti per valori pari a zero, un'unità, proprietà parziale, proprietà completa, stale-low e stale-high.<sup>[[1]](#references)[[2]](#references)</sup>

Le proprietà di regressione ad alto segnale sono:<sup>[[1]](#references)[[2]](#references)</sup>

- Un supply autorevole pari a zero non implica mai proprietà o amministrazione.
- I partial holders non possono diventare amministratori quando un supply duplicato è uguale al loro balance.
- Un full holder effettivo mantiene lo shortcut previsto quando il supply live è positivo.
- I self-grants falliti non modificano l'ACL né abilitano chiamate privilegiate successive.
- I cambi di modalità non possono modificare silenziosamente quale rappresentazione un controllo di autorizzazione considera autorevole.

## References

- [1] [La divergenza dello stato abilita l'accesso non autorizzato (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Corregge i controlli sul supply obsoleto](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit Provenance c81fd65 - Rifiuta il supply pari a zero nello shortcut di autorizzazione del supply totale](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
