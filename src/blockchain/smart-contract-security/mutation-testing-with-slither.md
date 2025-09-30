# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" introducendo sistematicamente piccole modifiche (mutanti) nel tuo codice Solidity e rieseguendo la suite di test. Se un test fallisce, il mutante viene ucciso. Se i test continuano a passare, il mutante sopravvive, rivelando un punto cieco nella tua suite di test che la copertura di linee/branch non può rilevare.

Idea chiave: la copertura mostra che il codice è stato eseguito; mutation testing mostra se il comportamento è effettivamente asserito.

## Perché la copertura può ingannare

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
I unit test che verificano solo un valore sotto e uno sopra la soglia possono raggiungere il 100% di copertura di linee/branch pur non asserendo il confine di uguaglianza (==). Una rifattorizzazione in `deposit >= 2 ether` passerebbe comunque tali test, compromettendo silenziosamente la logica del protocollo.

Mutation testing evidenzia questa lacuna mutando la condizione e verificando che i test falliscano.

## Operatori di mutazione comuni di Solidity

Slither’s mutation engine applica molte piccole modifiche che cambiano la semantica, come:
- Sostituzione degli operatori: `+` ↔ `-`, `*` ↔ `/`, ecc.
- Sostituzione delle assegnazioni: `+=` → `=`, `-=` → `=`
- Sostituzione delle costanti: valore non nullo → `0`, `true` ↔ `false`
- Negazione/sostituzione della condizione dentro `if`/cicli
- Commentare intere righe (CR: Comment Replacement)
- Sostituire una riga con `revert()`
- Scambio di tipi di dato: es. `int128` → `int64`

Obiettivo: uccidere il 100% dei mutanti generati, oppure giustificare i sopravvissuti con ragionamenti chiari.

## Eseguire mutation testing con slither-mutate

Requisiti: Slither v0.10.2+.

- Elenca opzioni e mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Esempio Foundry (cattura i risultati e mantieni un log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il comando che usi per eseguire i test (es., `npx hardhat test`, `npm test`).

Gli artifacts e i report vengono salvati in `./mutation_campaign` per impostazione predefinita. I mutanti non eliminati (sopravvissuti) vengono copiati lì per l'ispezione.

### Comprendere l'output

Le righe del report appaiono così:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- The tag in brackets is the mutator alias (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` means tests passed under the mutated behavior → missing assertion.

## Ridurre il runtime: dare priorità ai mutanti impattanti

Le campagne di mutation possono richiedere ore o giorni. Suggerimenti per ridurre i costi:
- Scope: Inizia solo con i contratti/directory critici, poi espandi.
- Prioritize mutators: Se un mutante ad alta priorità su una riga sopravvive (es., intera riga commentata), puoi saltare le varianti a priorità inferiore per quella riga.
- Parallelize tests se il tuo runner lo permette; cache dipendenze/build.
- Fail-fast: interrompi presto quando una modifica dimostra chiaramente una lacuna di asserzione.

## Flusso di triage per i mutanti sopravvissuti

1) Ispeziona la riga mutata e il comportamento.
- Riproduci localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforza i test per asserire lo stato, non solo i valori di ritorno.
- Aggiungi controlli di confine di uguaglianza (es., test threshold `==`).
- Asserisci post-condizioni: saldi, total supply, effetti di autorizzazione e eventi emessi.

3) Sostituisci mock troppo permissivi con comportamenti realistici.
- Assicurati che i mock impongano transfers, percorsi di fallimento e emissione di eventi che avvengono on-chain.

4) Aggiungi invarianti per i fuzz tests.
- Es.: conservazione del valore, saldi non negativi, invarianti di autorizzazione, supply monotona dove applicabile.

5) Riesegui slither-mutate fino a quando i sopravvissuti non vengono uccisi o giustificati esplicitamente.

## Caso di studio: rivelare asserzioni di stato mancanti (protocollo Arkis)

Una campagna di mutation durante un audit del protocollo Arkis DeFi ha fatto emergere sopravvissuti come:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Guidance: Treat survivors that affect value transfers, accounting, or access control as high-risk until killed.

## Checklist pratica

- Esegui una campagna mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Fai il triage dei survivors e scrivi test/invarianti che fallirebbero con il comportamento mutato.
- Verifica saldi, supply, autorizzazioni ed eventi.
- Aggiungi test sui limiti (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Sostituisci mock non realistici; simula modalità di failure.
- Itera finché tutti i mutants non sono eliminati o giustificati con commenti e motivazioni.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
