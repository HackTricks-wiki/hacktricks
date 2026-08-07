# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Il Mutation Testing "testa i tuoi test" introducendo sistematicamente piccole modifiche (mutanti) nel codice del contract e rieseguendo la test suite. Se un test fallisce, il mutante viene ucciso. Se i test continuano a passare, il mutante sopravvive, rivelando un punto cieco che la line/branch coverage non è in grado di rilevare.

Idea chiave: la coverage mostra che il codice è stato eseguito; il mutation testing mostra se il comportamento è effettivamente verificato.<sup>[[2]](#references)</sup>

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
I test unitari che verificano solo un valore al di sotto e uno al di sopra della soglia possono raggiungere il 100% di line/branch coverage senza verificare il limite di uguaglianza (==). Un refactor in `deposit >= 2 ether` supererebbe comunque questi test, rompendo silenziosamente la logica del protocollo.<sup>[[2]](#references)</sup>

Il mutation testing evidenzia questa lacuna mutando la condizione e verificando che i test falliscano.

Per gli smart contract, i mutant sopravvissuti corrispondono frequentemente a controlli mancanti relativi a:
- Autorizzazione e limiti dei ruoli
- Invarianti di accounting/trasferimento del valore
- Condizioni di revert e failure path
- Condizioni limite (`==`, valori zero, array vuoti, valori massimi/minimi)

## Mutation operators con il più alto security signal

Classi di mutazioni utili per l'auditing dei contratti:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: sostituire le istruzioni con `revert()` per evidenziare i path non eseguiti
- **Medium severity**: commentare le righe / rimuovere la logica per rivelare side effect non verificati
- **Low severity**: sostituzioni semplici di operatori o costanti, come `>=` -> `>` o `+` -> `-`
- Altre modifiche comuni: sostituzione delle assegnazioni, inversioni booleane, negazione delle condizioni e modifiche dei tipi

Obiettivo pratico: eliminare tutti i mutant significativi e giustificare esplicitamente quelli sopravvissuti che sono irrilevanti o semanticamente equivalenti.

## Perché la mutation syntax-aware è migliore delle regex

I mutation engine più datati si basavano su regex o riscritture orientate alle righe. Questo funziona, ma presenta importanti limitazioni:<sup>[[1]](#references)</sup>
- Le istruzioni su più righe sono difficili da mutare in modo sicuro
- La struttura del linguaggio non viene compresa, quindi commenti/token possono essere selezionati in modo errato
- Generare ogni possibile variante su una riga poco significativa spreca grandi quantità di runtime

Gli strumenti basati su AST o Tree-sitter migliorano questo aspetto, selezionando nodi strutturati invece di righe grezze:<sup>[[1]](#references)</sup>
- **slither-mutate** usa l'AST Solidity di Slither
- **mewt** usa Tree-sitter come core agnostico rispetto al linguaggio
- **MuTON** si basa su `mewt` e aggiunge il supporto first-class per linguaggi TON come FunC, Tolk e Tact

Questo rende i costrutti su più righe e le mutazioni a livello di espressione molto più affidabili rispetto agli approcci basati esclusivamente sulle regex.

## Eseguire il mutation testing con slither-mutate

Requisiti: Slither v0.10.2+.

- Elencare opzioni e mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Esempio con Foundry (acquisisci i risultati e conserva un log completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il comando con cui esegui i test (ad esempio `npx hardhat test`, `npm test`).

Gli artefatti vengono archiviati in `./mutation_campaign` per impostazione predefinita. I mutanti non rilevati (sopravvissuti) vengono copiati lì per essere analizzati.<sup>[[5]](#references)</sup>

### Comprendere l'output

Le righe del report sono simili a:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi è l'alias del mutator (ad esempio, `CR` = Comment Replacement).
- `UNCAUGHT` indica che i test sono passati con il comportamento mutato → manca un'asserzione.

## Ridurre il runtime: dare priorità ai mutant più rilevanti

Le campagne di mutation testing possono richiedere ore o giorni. Suggerimenti per ridurre i costi:<sup>[[1]](#references)[[2]](#references)</sup>
- Ambito: iniziare solo con i contract/directory critici, quindi espandere.
- Dare priorità ai mutator: se un mutant ad alta priorità su una riga sopravvive (ad esempio `revert()` o il comment-out), saltare le varianti a priorità inferiore per quella riga.
- Usare campagne in due fasi: eseguire prima test mirati/veloci, quindi ripetere i test solo sui mutant uncaught con la suite completa.
- Mappare, quando possibile, i target della mutation a specifici comandi di test (ad esempio, codice auth -> test auth).
- Limitare le campagne ai mutant di severità alta/media quando il tempo è limitato.
- Eseguire i test in parallelo se il runner lo consente; mettere in cache dipendenze/build.
- Fail-fast: interrompere presto quando una modifica dimostra chiaramente una lacuna nelle asserzioni.

La matematica del runtime è brutale: `1000 mutants x 5-minute tests ~= 83 hours`, quindi la progettazione della campagna è importante quanto il mutator stesso.

## Campagne persistenti e triage su larga scala

Una debolezza dei workflow precedenti consiste nel riversare i risultati soltanto su `stdout`. Per le campagne lunghe, questo rende più difficili la sospensione/ripresa, il filtraggio e la revisione.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` migliorano questo aspetto memorizzando mutant ed esiti in campagne basate su SQLite. Vantaggi:<sup>[[1]](#references)</sup>
- Sospendere e riprendere le esecuzioni lunghe senza perdere i progressi
- Filtrare solo i mutant uncaught in un file o una classe di mutation specifici
- Esportare/tradurre i risultati in SARIF per gli strumenti di revisione
- Fornire al triage assistito dall'AI set di risultati più piccoli e filtrati invece dei log grezzi del terminale

I risultati persistenti sono particolarmente utili quando la mutation testing diventa parte di una pipeline di audit anziché una revisione manuale una tantum.

## Workflow di triage per i mutant sopravvissuti

1) Ispezionare la riga e il comportamento mutati.
- Riprodurre localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforzare i test affinché verifichino lo stato, non solo i valori restituiti.
- Aggiungere controlli sui limiti di uguaglianza (ad esempio, testare la soglia `==`).
- Verificare le post-condizioni: saldi, total supply, effetti dell'autorizzazione ed eventi emessi.

3) Sostituire i mock eccessivamente permissivi con comportamenti realistici.
- Assicurarsi che i mock impongano i trasferimenti, i failure path e le emissioni di eventi che si verificano on-chain.

4) Aggiungere invarianti ai test fuzz.
- Ad esempio, conservazione del valore, saldi non negativi, invarianti di autorizzazione e supply monotona dove applicabile.

5) Separare i veri positivi dai no-op semantici.
- Esempio: `x > 0` -> `x != 0` è privo di significato quando `x` è unsigned.

6) Eseguire nuovamente la campagna finché i sopravvissuti non vengono eliminati o giustificati esplicitamente.

## Case study: rivelare asserzioni di stato mancanti (protocollo Arkis)

Una campagna di mutation condotta durante un audit del protocollo DeFi Arkis ha fatto emergere sopravvissuti come:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l’assegnazione non ha fatto fallire i test, dimostrando l’assenza di asserzioni sullo stato finale. Causa principale: il codice si affidava a un `_cmd.value` controllato dall’utente invece di validare i trasferimenti effettivi dei token. Un attacker avrebbe potuto desincronizzare i trasferimenti previsti da quelli effettivi per sottrarre fondi. Risultato: rischio di alta severità per la solvibilità del protocollo.<sup>[[2]](#references)[[3]](#references)</sup>

Indicazione: considera i survivors che influenzano i trasferimenti di valore, la contabilità o il controllo degli accessi come ad alto rischio finché non vengono uccisi.

## Non generare ciecamente test per uccidere ogni mutant

La generazione di test basata sulle mutazioni può ritorcersi contro se l’implementazione attuale è errata. Esempio: mutare `priority >= 2` in `priority > 2` cambia il comportamento, ma la correzione giusta non è sempre "scrivere un test per `priority == 2`". Quel comportamento potrebbe essere esso stesso il bug.<sup>[[1]](#references)</sup>

Workflow più sicuro:
- Usa i mutants sopravvissuti per identificare requisiti ambigui
- Convalida il comportamento previsto sulla base delle specifiche, della documentazione del protocollo o delle revisioni
- Solo allora codifica il comportamento come test/invariant

Altrimenti rischi di fissare nel test suite incidenti dell’implementazione e ottenere una falsa sicurezza.

## Checklist pratica

- Esegui una campaign mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Preferisci mutators consapevoli della sintassi (AST/Tree-sitter) rispetto alla mutation basata solo su regex, quando disponibili.
- Analizza i survivors e scrivi test/invariants che fallirebbero con il comportamento mutato.
- Verifica balances, supply, autorizzazioni ed eventi.
- Aggiungi test dei casi limite (`==`, overflow/underflow, zero-address, zero-amount, array vuoti).
- Sostituisci i mock non realistici; simula i failure modes.
- Conserva i risultati quando il tooling lo supporta e filtra i mutants non intercettati prima del triage.
- Usa campaign in due fasi o per target per mantenere gestibile il runtime.
- Itera finché tutti i mutants non vengono uccisi oppure giustificati con commenti e motivazioni.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
