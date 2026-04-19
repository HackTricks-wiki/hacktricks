# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Il mutation testing "tests your tests" introducendo sistematicamente piccole modifiche (mutants) nel codice del contratto e rieseguendo la test suite. Se un test fallisce, il mutant viene eliminato. Se i test continuano a passare, il mutant sopravvive, rivelando un punto cieco che la coverage di linee/branch non può rilevare.

L'idea chiave: la coverage mostra che il codice è stato eseguito; il mutation testing mostra se il comportamento è davvero verificato.

## Why coverage can deceive

Consider this simple threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
I test unitari che controllano solo un valore sotto e un valore sopra la soglia possono raggiungere il 100% di line/branch coverage pur fallendo nel verificare il boundary di uguaglianza (`==`). Un refactor a `deposit >= 2 ether` passerebbe ancora questi test, rompendo silenziosamente la logica del protocollo.

La mutation testing espone questo gap mutando la condizione e verificando che i test falliscano.

Per i smart contract, i mutanti che sopravvivono spesso corrispondono a controlli mancanti attorno a:
- Authorization e confini dei role
- Accounting/value-transfer invariants
- Revert conditions e failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators con il segnale di sicurezza più alto

Classi di mutation utili per il contract auditing:
- **High severity**: sostituisci le istruzioni con `revert()` per esporre i percorsi non eseguiti
- **Medium severity**: commenta le linee / rimuovi logica per rivelare side effects non verificati
- **Low severity**: swap sottili di operatori o costanti come `>=` -> `>` o `+` -> `-`
- Altre modifiche comuni: replacement delle assignment, boolean flips, negazione delle condition e type changes

Obiettivo pratico: uccidere tutti i mutanti significativi e giustificare esplicitamente i sopravvissuti che sono irrilevanti o semanticamente equivalenti.

## Perché la mutation aware del syntax è migliore di regex

I vecchi mutation engines si basavano su regex o rewrite orientati alle linee. Funziona, ma ha limiti importanti:
- Le istruzioni multi-line sono difficili da mutare in modo sicuro
- La struttura del language non viene compresa, quindi commenti/token possono essere colpiti male
- Generare ogni possibile variante su una weak line spreca grandi quantità di runtime

Gli strumenti basati su AST o Tree-sitter migliorano questo aspetto targettando nodi strutturati invece di linee grezze:
- **slither-mutate** usa l'Solidity AST di Slither
- **mewt** usa Tree-sitter come core agnostico rispetto al language
- **MuTON** si basa su `mewt` e aggiunge supporto first-class per i language TON come FunC, Tolk e Tact

Questo rende i costrutti multi-line e le mutation a livello di expression molto più affidabili rispetto agli approcci solo regex.

## Eseguire la mutation testing con slither-mutate

Requisiti: Slither v0.10.2+.

- Elenca options e mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Esempio di Foundry (cattura i risultati e conserva un log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il modo in cui esegui i test (ad es. `npx hardhat test`, `npm test`).

Gli artifact sono salvati in `./mutation_campaign` per impostazione predefinita. I mutanti non intercettati (sopravvissuti) vengono copiati lì per l'ispezione.

### Comprendere l'output

Le righe del report appaiono così:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi è l'alias del mutator (ad es., `CR` = Comment Replacement).
- `UNCAUGHT` significa che i test sono passati sotto il comportamento mutato → assertion mancante.

## Ridurre il runtime: dare priorità ai mutant più impattanti

Le campagne di mutation possono richiedere ore o giorni. Suggerimenti per ridurre il costo:
- Scope: inizia solo dai contract/directory critici, poi espandi.
- Dai priorità ai mutators: se un mutant ad alta priorità su una riga sopravvive (per esempio `revert()` o comment-out), salta le varianti a priorità più bassa per quella riga.
- Usa campagne in due fasi: esegui prima test mirati/veloci, poi ritesta solo i mutant uncaught con la suite completa.
- Mappa i target di mutation a comandi di test specifici quando possibile (per esempio auth code -> auth tests).
- Limita le campagne ai mutant high/medium severity quando il tempo è stretto.
- Esegui i test in parallelo se il tuo runner lo consente; metti in cache dipendenze/build.
- Fail-fast: fermati presto quando una modifica dimostra chiaramente un gap di assertion.

La matematica del runtime è brutale: `1000 mutants x 5-minute tests ~= 83 hours`, quindi il design della campagna conta tanto quanto il mutator stesso.

## Campagne persistenti e triage su larga scala

Un punto debole dei workflow più vecchi è scaricare i risultati solo su `stdout`. Per campagne lunghe, questo rende più difficile pause/resume, filtraggio e review.

`mewt`/`MuTON` migliorano questo aspetto salvando i mutant e gli esiti in campagne basate su SQLite. Vantaggi:
- Mettere in pausa e riprendere run lunghi senza perdere progresso
- Filtrare solo i mutant uncaught in un file specifico o in una mutation class
- Esportare/tradurre i risultati in SARIF per gli strumenti di review
- Dare all'AI-assisted triage set di risultati più piccoli e filtrati invece di raw terminal logs

I risultati persistenti sono particolarmente utili quando il mutation testing diventa parte di una pipeline di audit invece che di una review manuale una tantum.

## Workflow di triage per i mutant sopravvissuti

1) Ispeziona la riga mutata e il comportamento.
- Riproduci localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforza i test per verificare lo stato, non solo i valori di ritorno.
- Aggiungi controlli di equality-boundary (ad es., testa la soglia `==`).
- Asserisci le post-condition: balances, total supply, effetti di authorization ed eventi emessi.

3) Sostituisci i mock troppo permissivi con comportamenti realistici.
- Assicurati che i mock impongano transfers, failure paths ed emissioni di eventi che avvengono on-chain.

4) Aggiungi invariants per i fuzz tests.
- Ad es., conservation of value, balances non negativi, authorization invariants, supply monotona dove applicabile.

5) Separa i veri positivi dai semantic no-ops.
- Esempio: `x > 0` -> `x != 0` è insignificante quando `x` è unsigned.

6) Riesegui la campagna finché i survivor non vengono eliminati o esplicitamente giustificati.

## Case study: rivelare assertion mancanti sullo stato (Arkis protocol)

Una mutation campaign durante un audit del protocollo Arkis DeFi ha evidenziato survivor come:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l’assegnazione non ha rotto i test, dimostrando l’assenza di assertion sul post-state. Causa principale: il codice si fidava di un `_cmd.value` controllato dall’utente invece di validare i trasferimenti reali dei token. Un attacker poteva desincronizzare i trasferimenti attesi rispetto a quelli effettivi per drenare fondi. Risultato: rischio ad alta severity per la solvibilità del protocollo.

Guidance: Tratta come ad alto rischio i survivor che influenzano value transfers, accounting o access control finché non vengono killed.

## Non generare ciecamente test per uccidere ogni mutant

La generazione di test guidata da mutation può ritorcersi contro se l’implementazione corrente è sbagliata. Esempio: mutare `priority >= 2` in `priority > 2` cambia il comportamento, ma la correzione giusta non è sempre “scrivere un test per `priority == 2`”. Quel comportamento potrebbe essere esso stesso il bug.

Workflow più sicuro:
- Usa i mutant survivors per identificare requisiti ambigui
- Valida il comportamento atteso da specifiche, documentazione del protocollo o reviewer
- Solo dopo codifica quel comportamento come test/invariant

Altrimenti, rischi di fissare nel test suite accidenti dell’implementazione e ottenere una falsa fiducia.

## Checklist pratica

- Esegui una campagna mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Preferisci mutator syntax-aware (AST/Tree-sitter) rispetto a mutation basata solo su regex quando disponibile.
- Fai triage dei survivors e scrivi test/invariant che fallirebbero con il comportamento mutato.
- Assert su balances, supply, authorizations ed events.
- Aggiungi test di boundary (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Sostituisci i mock non realistici; simula i failure modes.
- Persiste i risultati quando il tooling lo supporta, e filtra i mutants non catturati prima del triage.
- Usa campagne in due fasi o per-target per mantenere il runtime gestibile.
- Itera finché tutti i mutants sono killed o giustificati con commenti e rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
