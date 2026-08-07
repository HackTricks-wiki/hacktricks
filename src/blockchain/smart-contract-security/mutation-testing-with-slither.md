# Mutation Testing per Smart Contract (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Il mutation testing "testa i tuoi test" introducendo sistematicamente piccole modifiche (mutanti) nel codice del contract e rieseguendo la test suite. Se un test fallisce, il mutante viene ucciso. Se i test continuano a passare, il mutante sopravvive, rivelando un punto cieco che la line/branch coverage non è in grado di rilevare.

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
I test unitari che verificano solo un valore al di sotto e uno al di sopra della soglia possono raggiungere il 100% di line/branch coverage senza verificare il limite di uguaglianza (==). Un refactoring a `deposit >= 2 ether` supererebbe comunque questi test, interrompendo silenziosamente la logica del protocollo.<sup>[[2]](#references)</sup>

Il mutation testing espone questa lacuna modificando la condizione e verificando che i test falliscano.

Per gli smart contract, i mutanti sopravvissuti spesso corrispondono a controlli mancanti relativi a:
- Autorizzazione e limiti dei ruoli
- Invarianti di contabilizzazione/trasferimento di valore
- Condizioni di revert e percorsi di errore
- Condizioni limite (`==`, valori zero, array vuoti, valori massimi/minimi)

## Mutation operator con il più alto security signal

Classi di mutazione utili per il contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severità**: sostituire le istruzioni con `revert()` per esporre percorsi non eseguiti
- **Media severità**: commentare le righe / rimuovere la logica per rivelare side effect non verificati
- **Bassa severità**: sostituzioni impercettibili di operatori o costanti, come `>=` -> `>` o `+` -> `-`
- Altre modifiche comuni: sostituzione di assegnamenti, inversioni booleane, negazione di condizioni e modifiche dei tipi

Obiettivo pratico: uccidere tutti i mutanti significativi e giustificare esplicitamente quelli sopravvissuti che sono irrilevanti o semanticamente equivalenti.

## Perché la mutazione syntax-aware è migliore delle regex

I precedenti mutation engine si basavano su regex o riscritture orientate alle righe. Questo approccio funziona, ma presenta importanti limitazioni:<sup>[[1]](#references)</sup>
- Le istruzioni su più righe sono difficili da modificare in sicurezza
- La struttura del linguaggio non viene compresa, quindi commenti/token possono essere selezionati in modo errato
- Generare ogni possibile variante su una riga poco significativa spreca grandi quantità di runtime

Gli strumenti basati su AST o Tree-sitter migliorano questo aspetto selezionando nodi strutturati invece di righe grezze:<sup>[[1]](#references)</sup>
- **slither-mutate** utilizza l'AST Solidity di Slither<sup>[[4]](#references)</sup>
- **mewt** utilizza Tree-sitter come core indipendente dal linguaggio<sup>[[6]](#references)</sup>
- **MuTON** si basa su `mewt` e aggiunge il supporto first-class ai linguaggi TON come FunC, Tolk e Tact<sup>[[7]](#references)</sup>

Questo rende le costruzioni su più righe e le mutazioni a livello di espressione molto più affidabili rispetto agli approcci basati esclusivamente sulle regex.

## Eseguire il mutation testing con slither-mutate

Requisiti: Slither v0.10.2+.

- Elencare opzioni e mutator:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Esempio Foundry (acquisisci i risultati e conserva un log completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il comando che usi per eseguire i test (ad es. `npx hardhat test`, `npm test`).

Gli artifacts vengono archiviati in `./mutation_campaign` per impostazione predefinita. I mutant non catturati (sopravvissuti) vengono copiati lì per l'ispezione.<sup>[[5]](#references)</sup>

### Comprendere l'output

Le righe del report hanno questo aspetto:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi è l'alias del mutator (ad esempio, `CR` = Comment Replacement).
- `UNCAUGHT` significa che i test sono passati con il comportamento mutato → assertion mancante.

## Ridurre il runtime: dare priorità ai mutant più rilevanti

Le campagne di mutation testing possono richiedere ore o giorni. Suggerimenti per ridurre i costi:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: iniziare solo con i contratti/directory critici, quindi espandere.
- Dare priorità ai mutator: se un mutant ad alta priorità su una riga sopravvive (ad esempio `revert()` o comment-out), saltare le varianti a priorità inferiore per quella riga.
- Usare campagne in due fasi: eseguire prima test mirati/veloci, quindi ripetere i test solo sui mutant non catturati con la suite completa.
- Mappare, quando possibile, i target della mutation ai comandi di test specifici (ad esempio codice di autenticazione -> test di autenticazione).
- Limitare le campagne ai mutant di severità alta/media quando il tempo è limitato.
- Parallelizzare i test se il runner lo consente; memorizzare nella cache dipendenze/build.
- Fail-fast: interrompere tempestivamente quando una modifica dimostra chiaramente una lacuna nelle assertion.

La matematica del runtime è brutale: `1000 mutants x 5-minute tests ~= 83 hours`, quindi la progettazione della campagna è importante quanto il mutator stesso.<sup>[[1]](#references)</sup>

## Campagne persistenti e triage su larga scala

Una debolezza dei workflow più vecchi consiste nel riversare i risultati solo su `stdout`. Per le campagne lunghe, ciò rende più difficili la sospensione/ripresa, il filtraggio e la revisione.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` migliorano questo aspetto memorizzando mutant ed esiti in campagne basate su SQLite. Vantaggi:<sup>[[1]](#references)</sup>
- Sospendere e riprendere le esecuzioni lunghe senza perdere i progressi
- Filtrare solo i mutant non catturati in un file o in una classe di mutation specifici
- Esportare/tradurre i risultati in SARIF per gli strumenti di revisione
- Fornire al triage assistito dall'AI set di risultati più piccoli e filtrati invece dei log grezzi del terminale

I risultati persistenti sono particolarmente utili quando il mutation testing diventa parte di una pipeline di audit invece di una revisione manuale una tantum.

## Workflow di triage per i mutant sopravvissuti

1) Ispezionare la riga e il comportamento mutati.
- Riprodurre localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforzare i test per verificare lo stato, non solo i valori restituiti.
- Aggiungere controlli sui limiti di uguaglianza (ad esempio, testare la soglia `==`).
- Verificare le post-condition: saldi, total supply, effetti dell'autorizzazione ed eventi emessi.

3) Sostituire i mock eccessivamente permissivi con comportamenti realistici.
- Assicurarsi che i mock applichino i trasferimenti, i failure path e le emissioni di eventi che si verificano on-chain.

4) Aggiungere invariants ai fuzz test.
- Ad esempio, conservazione del valore, saldi non negativi, invariants di autorizzazione, supply monotona dove applicabile.

5) Separare i true positive dai semantic no-op.
- Esempio: `x > 0` -> `x != 0` non ha significato quando `x` è unsigned.

6) Rieseguire la campagna finché i sopravvissuti non vengono eliminati o esplicitamente giustificati.

## Case study: rivelare assertion di stato mancanti (protocollo Arkis)

Una campagna di mutation durante un audit del protocollo DeFi Arkis ha fatto emergere sopravvissuti come:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l’assegnazione non ha interrotto i test, dimostrando l’assenza di asserzioni sullo stato finale. Causa principale: il codice si fidava di un `_cmd.value` controllato dall’utente invece di convalidare gli effettivi trasferimenti di token. Un attaccante avrebbe potuto desincronizzare i trasferimenti previsti da quelli effettivi per prosciugare i fondi. Risultato: rischio di alta gravità per la solvibilità del protocollo.<sup>[[2]](#references)[[3]](#references)</sup>

Indicazione: considera ad alto rischio i mutant sopravvissuti che influenzano i trasferimenti di valore, la contabilità o il controllo degli accessi finché non vengono eliminati.

## Non generare ciecamente test per eliminare ogni mutant

La generazione di test basata sulle mutation può ritorcersi contro se l’implementazione attuale è errata. Esempio: mutare `priority >= 2` in `priority > 2` cambia il comportamento, ma la correzione giusta non è sempre "scrivere un test per `priority == 2`". Quel comportamento potrebbe essere a sua volta il bug.<sup>[[1]](#references)</sup>

Workflow più sicuro:
- Usa i mutant sopravvissuti per identificare requisiti ambigui
- Convalida il comportamento atteso sulla base delle specifiche, della documentazione del protocollo o delle revisioni
- Solo allora codifica il comportamento come test/invariante

In caso contrario, rischi di codificare nella suite di test incidenti dell’implementazione e ottenere una falsa sicurezza.

## Checklist pratica

- Esegui una campagna mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Preferisci mutator consapevoli della sintassi (AST/Tree-sitter) rispetto alla mutation basata solo su regex, quando disponibili.
- Analizza i mutant sopravvissuti e scrivi test/invarianti che fallirebbero con il comportamento mutato.
- Verifica i saldi, la supply, le autorizzazioni e gli eventi.
- Aggiungi test sui valori limite (`==`, overflow/underflow, zero-address, zero-amount, array vuoti).
- Sostituisci i mock irrealistici; simula le modalità di errore.
- Salva i risultati quando il tool lo supporta e filtra i mutant non intercettati prima dell’analisi.
- Usa campagne in due fasi o per target per mantenere gestibile il tempo di esecuzione.
- Continua a iterare finché tutti i mutant non vengono eliminati oppure giustificati con commenti e motivazioni.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
