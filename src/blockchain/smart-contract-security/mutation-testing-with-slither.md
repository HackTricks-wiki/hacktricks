# Mutation Testing per Smart Contract (slither-mutate, mewt, MuTON)

La mutation testing "verifica i tuoi test" introducendo sistematicamente piccole modifiche (mutants) nel codice del contract e rieseguendo la test suite. Se un test fallisce, il mutant viene eliminato. Se i test continuano ad avere esito positivo, il mutant sopravvive, rivelando un blind spot che la line/branch coverage non è in grado di rilevare.

Concetto chiave: la coverage mostra che il codice è stato eseguito; la mutation testing mostra se il comportamento è effettivamente verificato.<sup>[[2]](#references)</sup>

## Perché la coverage può ingannare

Considera questo semplice controllo di soglia:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Gli unit test che controllano solo un valore al di sotto e uno al di sopra della soglia possono raggiungere il 100% di line/branch coverage senza verificare il limite di uguaglianza (`==`). Un refactoring a `deposit >= 2 ether` supererebbe comunque questi test, rompendo silenziosamente la logica del protocollo.<sup>[[2]](#references)</sup>

Il mutation testing espone questa lacuna modificando la condizione e verificando che i test falliscano.

Per gli smart contract, i mutant sopravvissuti spesso corrispondono a controlli mancanti relativi a:
- Autorizzazione e limiti dei ruoli
- Invarianti di accounting/trasferimento del valore
- Condizioni di revert e percorsi di errore
- Condizioni limite (`==`, valori zero, array vuoti, valori massimi/minimi)

## Mutation operators con il più alto security signal

Classi di mutazioni utili per l'auditing dei contract:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severità**: sostituire le istruzioni con `revert()` per esporre percorsi non eseguiti
- **Media severità**: commentare le righe / rimuovere la logica per rivelare side effect non verificati
- **Bassa severità**: sostituzioni sottili di operatori o costanti, come `>=` -> `>` o `+` -> `-`
- Altre modifiche comuni: sostituzione di assegnazioni, inversioni booleane, negazione delle condizioni e modifiche dei tipi

Obiettivo pratico: eliminare tutti i mutant significativi e giustificare esplicitamente quelli sopravvissuti che sono irrilevanti o semanticamente equivalenti.

## Perché la mutation syntax-aware è migliore delle regex

I vecchi mutation engine si basavano su regex o riscritture orientate alle righe. Questo funziona, ma presenta importanti limitazioni:<sup>[[1]](#references)</sup>
- Le istruzioni su più righe sono difficili da modificare in modo sicuro
- La struttura del linguaggio non viene compresa, quindi commenti/token possono essere presi di mira in modo errato
- Generare ogni possibile variante su una riga non significativa spreca grandi quantità di runtime

Gli strumenti basati su AST o Tree-sitter migliorano questo aspetto prendendo di mira nodi strutturati invece di righe grezze:<sup>[[1]](#references)</sup>
- **slither-mutate** usa l'AST Solidity di Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter come core agnostico rispetto al linguaggio.<sup>[[6]](#references)</sup>
- **MuTON** si basa su `mewt` e aggiunge il supporto first-class per linguaggi TON come FunC, Tolk e Tact.<sup>[[7]](#references)</sup>

Questo rende i costrutti su più righe e le mutazioni a livello di espressione molto più affidabili rispetto agli approcci basati esclusivamente sulle regex.

## Eseguire il mutation testing con slither-mutate

Requisiti: Slither v0.10.2+.

- Elencare opzioni e mutator:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (capture results and keep a full log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il comando che usi per eseguire i test (ad esempio, `npx hardhat test`, `npm test`).

Gli artifact vengono salvati in `./mutation_campaign` per impostazione predefinita. I mutanti non rilevati (sopravvissuti) vengono copiati lì per l'ispezione.<sup>[[5]](#references)</sup>

### Comprendere l'output

Le righe del report hanno questo aspetto:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi indica l'alias del mutator (ad esempio, `CR` = Comment Replacement).
- `UNCAUGHT` significa che i test sono stati superati con il comportamento mutato → manca un'asserzione.

## Riduzione del runtime: dare priorità ai mutanti più significativi

Le campagne di mutation testing possono richiedere ore o giorni. Suggerimenti per ridurre i costi:<sup>[[1]](#references)[[2]](#references)</sup>
- Ambito: iniziare solo con i contratti/directory critici, quindi espandere.
- Dare priorità ai mutator: se un mutante ad alta priorità su una riga sopravvive (ad esempio `revert()` o comment-out), saltare le varianti a priorità inferiore per quella riga.
- Usare campagne in due fasi: eseguire prima test mirati/veloci, quindi ripetere i test solo sui mutanti non intercettati con l'intera suite.
- Mappare, quando possibile, i target della mutazione a comandi di test specifici (ad esempio, codice di autenticazione -> test di autenticazione).
- Limitare le campagne ai mutanti con severità alta/media quando il tempo è limitato.
- Eseguire i test in parallelo se il runner lo consente; mettere in cache dipendenze/build.
- Fail-fast: interrompere presto quando una modifica dimostra chiaramente una lacuna nelle asserzioni.

I calcoli del runtime sono spietati: `1000 mutants x 5-minute tests ~= 83 hours`, quindi la progettazione della campagna è importante quanto il mutator stesso.<sup>[[1]](#references)</sup>

## Campagne persistenti e triage su larga scala

Un punto debole dei workflow precedenti è il riversamento dei risultati solo in `stdout`. Per le campagne lunghe, questo rende più difficili la sospensione/ripresa, il filtraggio e la revisione.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` migliorano questo aspetto memorizzando mutanti e risultati in campagne basate su SQLite. Vantaggi:<sup>[[1]](#references)</sup>
- Sospendere e riprendere esecuzioni lunghe senza perdere i progressi
- Filtrare solo i mutanti non intercettati in un file o una classe di mutazione specifici
- Esportare/tradurre i risultati in SARIF per gli strumenti di revisione
- Fornire al triage assistito dall'AI insiemi di risultati più piccoli e filtrati invece dei log grezzi del terminale

I risultati persistenti sono particolarmente utili quando il mutation testing diventa parte di una pipeline di audit invece di una revisione manuale una tantum.

## Workflow di triage per i mutanti sopravvissuti

1) Esaminare la riga e il comportamento mutati.
- Riprodurre localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforzare i test per verificare lo stato, non solo i valori restituiti.
- Aggiungere controlli sui limiti di uguaglianza (ad esempio, testare la soglia `==`).
- Verificare le post-condizioni: saldi, supply totale, effetti dell'autorizzazione ed eventi emessi.

3) Sostituire i mock eccessivamente permissivi con comportamenti realistici.
- Assicurarsi che i mock impongano trasferimenti, percorsi di errore ed emissioni di eventi che si verificano on-chain.

4) Aggiungere invarianti per i test fuzz.
- Ad esempio, conservazione del valore, saldi non negativi, invarianti di autorizzazione, supply monotona ove applicabile.

5) Separare i veri positivi dai no-op semantici.
- Esempio: `x > 0` -> `x != 0` è privo di significato quando `x` è unsigned.

6) Eseguire nuovamente la campagna finché i sopravvissuti non vengono eliminati o giustificati esplicitamente.

## Caso di studio: rivelare asserzioni di stato mancanti (protocollo Arkis)

Una campagna di mutation testing durante un audit del protocollo DeFi Arkis ha fatto emergere sopravvissuti come:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l’assegnazione non ha fatto fallire i test, dimostrando l’assenza di post-state assertions. Causa principale: il codice si fidava di un `_cmd.value` controllato dall’utente invece di validare gli effettivi token transfer. Un attacker avrebbe potuto desincronizzare i transfer attesi da quelli effettivi per drenare i fondi. Risultato: rischio di alta severità per la solvibilità del protocollo.<sup>[[2]](#references)[[3]](#references)</sup>

Indicazione: considera i mutant sopravvissuti che influenzano i value transfer, la contabilità o l’access control come ad alto rischio finché non vengono eliminati.

## Non generare ciecamente test per eliminare ogni mutant

La generazione di test basata sulle mutation può ritorcersi contro se l’implementazione attuale è errata. Esempio: mutare `priority >= 2` in `priority > 2` modifica il comportamento, ma la soluzione corretta non è sempre "scrivere un test per `priority == 2`". Quel comportamento potrebbe essere proprio il bug.<sup>[[1]](#references)</sup>

Workflow più sicuro:
- Usa i mutant sopravvissuti per identificare requisiti ambigui
- Valida il comportamento atteso sulla base di specifiche, documentazione del protocollo o reviewer
- Solo dopo codifica il comportamento come test/invariant

Altrimenti rischi di hard-codificare incidenti dell’implementazione nella test suite e ottenere una falsa sicurezza.

## Checklist pratica

- Esegui una campagna mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Preferisci mutator consapevoli della sintassi (AST/Tree-sitter) rispetto alla mutation basata esclusivamente su regex, quando disponibili.
- Analizza i mutant sopravvissuti e scrivi test/invariant che fallirebbero con il comportamento mutato.
- Verifica balances, supply, autorizzazioni ed eventi.
- Aggiungi boundary test (`==`, overflow/underflow, zero-address, zero-amount, array vuoti).
- Sostituisci i mock irrealistici; simula i failure mode.
- Persisti i risultati quando il tooling lo supporta e filtra i mutant non intercettati prima del triage.
- Usa campagne in due fasi o per target per mantenere gestibile il runtime.
- Itera finché tutti i mutant non vengono eliminati oppure giustificati con commenti e motivazioni.

## References

- [1] [Mutation testing per l’era agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Usa la mutation testing per trovare i bug che i tuoi test non rilevano (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Security Review di Arkis DeFi Prime Brokerage (Appendice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentazione di Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
