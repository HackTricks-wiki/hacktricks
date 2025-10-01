# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" introducendo sistematicamente piccole modifiche (mutants) nel tuo codice Solidity e rieseguendo la tua test suite. Se un test fallisce, il mutant viene ucciso. Se i test continuano a passare, il mutant sopravvive, rivelando un punto cieco nella tua test suite che la line/branch coverage non può rilevare.

Idea chiave: la copertura mostra che il codice è stato eseguito; mutation testing mostra se il comportamento è effettivamente verificato.

## Perché la copertura può ingannare

Considera questo semplice controllo della soglia:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
I test unitari che verificano solo un valore al di sotto e uno al di sopra della soglia possono raggiungere il 100% di copertura di linee/branch pur non asserendo il confine di uguaglianza (==). Un refactor a `deposit >= 2 ether` passerebbe comunque tali test, rompendo silenziosamente la logica del protocollo.

Il mutation testing mette in luce questa lacuna mutando la condizione e verificando che i test falliscano.

## Common Solidity mutation operators

Il motore di mutazione di Slither applica molte piccole modifiche che cambiano la semantica, come:
- Sostituzione operatori: `+` ↔ `-`, `*` ↔ `/`, etc.
- Sostituzione delle assegnazioni: `+=` → `=`, `-=` → `=`
- Sostituzione delle costanti: diverso da zero → `0`, `true` ↔ `false`
- Negazione/sostituzione delle condizioni all'interno di `if`/cicli
- Commentare intere righe (CR: Comment Replacement)
- Sostituire una riga con `revert()`
- Scambio di tipi di dato: p.es., `int128` → `int64`

Obiettivo: uccidere il 100% dei mutanti generati, o giustificare i superstiti con ragionamenti chiari.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- Elenca le opzioni e i mutatori:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Esempio Foundry (cattura i risultati e conserva un log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il comando che usi per eseguire i test (ad es., `npx hardhat test`, `npm test`).

Gli artifact e i report vengono salvati in `./mutation_campaign` per impostazione predefinita. I mutanti non rilevati (sopravvissuti) vengono copiati lì per l'ispezione.

### Comprendere l'output

Le righe del report appaiono così:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi è l'alias del mutator (es., `CR` = Comment Replacement).
- `UNCAUGHT` indica che i test sono passati con il comportamento mutato → manca un'asserzione.

## Ridurre il runtime: dare priorità ai mutanti più impattanti

Le campagne di mutation possono richiedere ore o giorni. Suggerimenti per ridurre i costi:
- Scope: Inizia solo con i contracts/directories critici, poi espandi.
- Prioritize mutators: se un mutante ad alta priorità su una riga sopravvive (es., l'intera riga commentata), puoi saltare le varianti a priorità inferiore per quella riga.
- Parallelizza i test se il tuo runner lo permette; usa la cache per dependencies/builds.
- Fail-fast: interrompi presto quando una modifica dimostra chiaramente un gap di asserzione.

## Flusso di triage per i mutanti sopravvissuti

1) Ispeziona la linea mutata e il comportamento.
- Riproduci localmente applicando la linea mutata ed eseguendo un test focalizzato.

2) Rafforza i test per asserire lo stato, non solo i valori di ritorno.
- Aggiungi controlli di uguaglianza/limite (es., test threshold `==`).
- Asserisci post-condizioni: balances, total supply, effetti di autorizzazione e eventi emessi.

3) Sostituisci i mock eccessivamente permissivi con comportamenti realistici.
- Assicurati che i mock impongano trasferimenti, percorsi di fallimento e emissioni di eventi che avvengono on-chain.

4) Aggiungi invarianti per i fuzz tests.
- Es., conservazione del valore, saldi non negativi, invarianti di autorizzazione, monotonia dell'offerta dove applicabile.

5) Riesegui slither-mutate finché i mutanti sopravvissuti non vengono eliminati o giustificati esplicitamente.

## Caso di studio: rivelare asserzioni di stato mancanti (Arkis protocol)

Una mutation campaign durante un audit del Arkis DeFi protocol ha fatto emergere dei mutanti sopravvissuti come:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l'assegnazione non ha rotto i test, dimostrando la mancanza di asserzioni sullo stato finale. Causa principale: il codice si fidava di un `_cmd.value` controllato dall'utente invece di validare i trasferimenti effettivi di token. Un attacker poteva desincronizzare trasferimenti attesi e reali per prosciugare fondi. Risultato: rischio di alta severità per la solvibilità del protocollo.

Guidance: Considera i mutanti sopravvissuti che influenzano trasferimenti di valore, contabilità o access control come ad alto rischio finché non vengono eliminati.

## Checklist pratica

- Esegui una campagna mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triaga i mutanti sopravvissuti e scrivi test/invarianti che fallirebbero con il comportamento mutato.
- Verifica saldi, supply, autorizzazioni ed eventi.
- Aggiungi test sui casi limite (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Sostituisci mock irrealistici; simula modalità di errore.
- Itera finché tutti i mutanti non vengono eliminati o giustificati con commenti e razionale.

## Riferimenti

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
