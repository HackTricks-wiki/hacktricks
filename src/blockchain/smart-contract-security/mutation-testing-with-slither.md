# Mutation Testing per Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Il Mutation Testing "testa i tuoi test" introducendo sistematicamente piccole modifiche (mutanti) nel codice del contract e rieseguendo la test suite. Se un test fallisce, il mutante viene ucciso. Se i test continuano ad avere successo, il mutante sopravvive, rivelando un punto cieco che la line/branch coverage non può rilevare.

Idea chiave: la coverage mostra che il codice è stato eseguito; il Mutation Testing mostra se il comportamento è effettivamente verificato.<sup>[[2]](#references)</sup>

## Perché la coverage può trarre in inganno

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
Gli unit test che controllano solo un valore inferiore e uno superiore alla soglia possono raggiungere il 100% di line/branch coverage senza verificare il limite di uguaglianza (`==`). Un refactor in `deposit >= 2 ether` supererebbe comunque questi test, interrompendo silenziosamente la logica del protocollo.<sup>[[2]](#references)</sup>

Il mutation testing espone questa lacuna modificando la condizione e verificando che i test falliscano.

Per gli smart contract, i mutanti sopravvissuti spesso evidenziano controlli mancanti relativi a:
- Autorizzazione e limiti dei ruoli
- Invarianti di accounting/trasferimento del valore
- Condizioni di revert e percorsi di errore
- Condizioni limite (`==`, valori zero, array vuoti, valori massimi/minimi)

## Mutation operators with the highest security signal

Classi di mutazione utili per l'auditing dei contract:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: sostituire le istruzioni con `revert()` per esporre percorsi non eseguiti
- **Medium severity**: commentare le righe / rimuovere la logica per rivelare side effect non verificati
- **Low severity**: sostituzioni sottili di operatori o costanti, come `>=` -> `>` o `+` -> `-`
- Altre modifiche comuni: sostituzione delle assegnazioni, inversioni dei booleani, negazione delle condizioni e modifiche dei tipi

Obiettivo pratico: eliminare tutti i mutanti significativi e giustificare esplicitamente quelli sopravvissuti che sono irrilevanti o semanticamente equivalenti.

## Why syntax-aware mutation is better than regex

I vecchi mutation engine si basavano su regex o riscritture orientate alle righe. Questo funziona, ma presenta importanti limitazioni:<sup>[[1]](#references)</sup>
- Le istruzioni su più righe sono difficili da modificare in modo sicuro
- La struttura del linguaggio non viene compresa, quindi commenti/token possono essere presi di mira in modo errato
- Generare ogni possibile variante su una riga non affidabile spreca grandi quantità di runtime

Gli strumenti basati su AST o Tree-sitter migliorano questo aspetto prendendo di mira nodi strutturati anziché righe grezze:<sup>[[1]](#references)</sup>
- **slither-mutate** usa l'AST Solidity di Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter come core indipendente dal linguaggio.<sup>[[6]](#references)</sup>
- **MuTON** si basa su `mewt` e aggiunge il supporto di prima classe per linguaggi TON come FunC, Tolk e Tact.<sup>[[7]](#references)</sup>

Questo rende i costrutti su più righe e le mutazioni a livello di espressione molto più affidabili rispetto agli approcci basati esclusivamente su regex.

## Running mutation testing with slither-mutate

Requisiti: Slither v0.10.2+.

- Elencare opzioni e mutator:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Esempio Foundry (cattura i risultati e conserva un log completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il comando che usi per eseguire i test (ad esempio, `npx hardhat test`, `npm test`).

Gli artifact vengono archiviati per impostazione predefinita in `./mutation_campaign`. I mutant non rilevati (sopravvissuti) vengono copiati lì per essere esaminati.<sup>[[5]](#references)</sup>

### Comprendere l'output

Le righe del report hanno il seguente aspetto:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi è l'alias del mutator (ad esempio, `CR` = Comment Replacement).
- `UNCAUGHT` significa che i test sono passati con il comportamento mutato → asserzione mancante.

## Ridurre il runtime: dare priorità ai mutanti più rilevanti

Le campagne di mutation testing possono richiedere ore o giorni. Suggerimenti per ridurre i costi:<sup>[[1]](#references)[[2]](#references)</sup>
- Ambito: inizia solo con i contratti/directory critici, poi espandi.
- Dai priorità ai mutator: se un mutante ad alta priorità su una riga sopravvive (ad esempio `revert()` o il comment-out), salta le varianti a priorità inferiore per quella riga.
- Usa campagne in due fasi: esegui prima test mirati/rapidi, poi ripeti i test solo sui mutanti non intercettati con la suite completa.
- Quando possibile, associa i target della mutation testing a comandi di test specifici (ad esempio codice di autenticazione -> test di autenticazione).
- Quando il tempo è limitato, limita le campagne ai mutanti con severità alta/media.
- Esegui i test in parallelo se il tuo runner lo consente; usa la cache per dipendenze/build.
- Fail-fast: interrompi subito quando una modifica dimostra chiaramente una lacuna nelle asserzioni.

La matematica del runtime è spietata: `1000 mutants x 5-minute tests ~= 83 hours`, quindi la progettazione della campagna è importante quanto il mutator stesso.<sup>[[1]](#references)</sup>

## Campagne persistenti e triage su larga scala

Una debolezza dei workflow più datati è riversare i risultati solo su `stdout`. Per le campagne lunghe, questo rende più difficili la sospensione/ripresa, il filtraggio e la revisione.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` migliorano questo aspetto memorizzando mutanti ed esiti in campagne basate su SQLite. Vantaggi:<sup>[[1]](#references)</sup>
- Sospendere e riprendere esecuzioni lunghe senza perdere i progressi
- Filtrare solo i mutanti non intercettati in un file o una classe di mutazione specifici
- Esportare/tradurre i risultati in SARIF per gli strumenti di revisione
- Fornire al triage assistito dall'AI set di risultati più piccoli e filtrati invece dei log grezzi del terminale

I risultati persistenti sono particolarmente utili quando la mutation testing diventa parte di una pipeline di audit invece di una revisione manuale una tantum.

## Workflow di triage per i mutanti sopravvissuti

1) Ispeziona la riga e il comportamento mutati.
- Riproduci localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforza i test affinché verifichino lo stato, non solo i valori restituiti.
- Aggiungi controlli sui limiti di uguaglianza (ad esempio, testa la soglia `==`).
- Verifica le post-condizioni: saldi, supply totale, effetti dell'autorizzazione ed eventi emessi.

3) Sostituisci i mock eccessivamente permissivi con un comportamento realistico.
- Assicurati che i mock applichino i trasferimenti, i percorsi di errore e le emissioni di eventi che si verificano on-chain.

4) Aggiungi invarianti ai fuzz test.
- Ad esempio, conservazione del valore, saldi non negativi, invarianti di autorizzazione e supply monotona ove applicabile.

5) Separa i veri positivi dai no-op semantici.
- Esempio: `x > 0` -> `x != 0` è privo di significato quando `x` è unsigned.

6) Esegui nuovamente la campagna finché i sopravvissuti non vengono eliminati o esplicitamente giustificati.

## Caso di studio: rivelare asserzioni mancanti sullo stato (protocollo Arkis)

Una campagna di mutation testing durante un audit del protocollo DeFi Arkis ha fatto emergere sopravvissuti come:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l'assegnazione non ha fatto fallire i test, dimostrando l'assenza di post-state assertions. Causa principale: il codice si affidava a un `_cmd.value` controllato dall'utente invece di convalidare i trasferimenti effettivi dei token. Un attacker avrebbe potuto desincronizzare i trasferimenti previsti da quelli effettivi per drenare i fondi. Risultato: rischio di alta gravità per la solvibilità del protocollo.<sup>[[2]](#references)[[3]](#references)</sup>

Indicazione: considera ad alto rischio i mutant sopravvissuti che influiscono sui trasferimenti di valore, sulla contabilità o sul controllo degli accessi, finché non vengono eliminati.

## Non generare ciecamente test per eliminare ogni mutant

La generazione di test basata sulle mutation può ritorcersi contro se l'implementazione attuale è errata. Esempio: modificare `priority >= 2` in `priority > 2` cambia il comportamento, ma la correzione giusta non è sempre "scrivere un test per `priority == 2`". Quel comportamento potrebbe essere esso stesso il bug.<sup>[[1]](#references)</sup>

Workflow più sicuro:
- Usa i mutant sopravvissuti per identificare requisiti ambigui
- Convalida il comportamento previsto sulla base delle specifiche, della documentazione del protocollo o delle revisioni
- Solo dopo codifica il comportamento come test/invariante

Altrimenti rischi di hard-codificare incidenti dell'implementazione nella test suite e di ottenere una falsa sicurezza.

## Checklist pratica

- Esegui una campaign mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Preferisci mutator consapevoli della sintassi (AST/Tree-sitter) rispetto alla mutation basata solo su regex, quando disponibili.
- Fai il triage dei mutant sopravvissuti e scrivi test/invarianti che fallirebbero con il comportamento modificato.
- Verifica balances, supply, autorizzazioni ed eventi.
- Aggiungi boundary test (`==`, overflow/underflow, zero-address, zero-amount, array vuoti).
- Sostituisci i mock irrealistici; simula i failure mode.
- Conserva i risultati quando il tooling lo supporta e filtra i mutant non intercettati prima del triage.
- Usa campaign in due fasi o per target per mantenere gestibile il runtime.
- Itera finché tutti i mutant non vengono eliminati o giustificati con commenti e motivazioni.

## References

- [1] [Mutation testing per l'era agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Usa la mutation testing per trovare i bug che i tuoi test non rilevano (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Security Review di Arkis DeFi Prime Brokerage (Appendice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentazione di Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
