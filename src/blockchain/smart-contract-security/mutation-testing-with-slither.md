# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "testa i tuoi test" introducendo sistematicamente piccole modifiche (mutanti) nel tuo codice Solidity e rieseguendo la tua test suite. Se un test fallisce, il mutante viene ucciso. Se i test continuano a passare, il mutante sopravvive, rivelando un punto cieco nella tua test suite che la copertura delle linee o dei rami non può individuare.

Idea chiave: la copertura indica che il codice è stato eseguito; la mutation testing indica invece se il comportamento è effettivamente verificato.

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
I test unitari che verificano solo un valore sotto e un valore sopra la soglia possono raggiungere il 100% di copertura di linea/branch pur non verificando il vincolo di uguaglianza (==). Un refactor a `deposit >= 2 ether` passerebbe comunque questi test, rompendo silenziosamente la logica del protocollo.

Mutation testing espone questa lacuna mutando la condizione e verificando che i test falliscano.

## Operatori di mutazione comuni in Solidity

Il motore di mutation di Slither applica molte piccole modifiche che cambiano la semantica, come:
- Sostituzione degli operatori: `+` ↔ `-`, `*` ↔ `/`, etc.
- Sostituzione delle assegnazioni: `+=` → `=`, `-=` → `=`
- Sostituzione delle costanti: non-zero → `0`, `true` ↔ `false`
- Negazione/sostituzione della condizione dentro `if`/loop
- Commentare intere righe (CR: Comment Replacement)
- Sostituire una riga con `revert()`
- Scambio dei tipi di dato: ad es., `int128` → `int64`

Obiettivo: kill 100% dei mutanti generati, o giustificare i sopravvissuti con ragionamenti chiari.

## Running mutation testing with slither-mutate

Requisiti: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry esempio (cattura i risultati e mantieni un log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se non usi Foundry, sostituisci `--test-cmd` con il modo in cui esegui i test (ad esempio, `npx hardhat test`, `npm test`).

Gli artifact e i report sono memorizzati in `./mutation_campaign` per default. I mutanti non catturati (sopravvissuti) vengono copiati lì per l'ispezione.

### Comprendere l'output

Le righe del report hanno questo aspetto:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Il tag tra parentesi è l'alias del mutator (es., `CR` = Comment Replacement).
- `UNCAUGHT` significa che i test sono passati sotto il comportamento mutato → asserzione mancante.

## Ridurre i tempi di esecuzione: dare priorità ai mutanti più impattanti

Le campagne di mutation possono richiedere ore o giorni. Consigli per ridurre i costi:
- Ambito: Inizia solo con i contratti/directory critici, poi espandi.
- Prioritizza i mutator: se un mutante ad alta priorità su una riga sopravvive (es., intera riga commentata), puoi saltare le varianti a priorità inferiore per quella riga.
- Parallelizza i test se il tuo runner lo permette; usa la cache per dipendenze/build.
- Fail-fast: fermati presto quando una modifica dimostra chiaramente una lacuna nelle asserzioni.

## Workflow di triage per i mutanti sopravvissuti

1) Ispeziona la riga mutata e il comportamento.
- Riproduci localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforza i test per asserire lo stato, non solo i valori di ritorno.
- Aggiungi controlli sui confini di uguaglianza (es., verifica della soglia `==`).
- Asserisci post-condizioni: saldi, total supply, effetti di autorizzazione e eventi emessi.

3) Sostituisci mock eccessivamente permissivi con comportamenti realistici.
- Assicurati che i mock impongano trasferimenti, percorsi di fallimento e emissioni di eventi che avvengono on-chain.

4) Aggiungi invarianti per i test di fuzzing.
- Es., conservazione del valore, saldi non negativi, invarianti di autorizzazione, supply monotona quando applicabile.

5) Riesegui slither-mutate finché i sopravvissuti non vengono eliminati o giustificati esplicitamente.

## Caso di studio: rivelare asserzioni di stato mancanti (protocollo Arkis)

Una campagna di mutation durante un audit del protocollo DeFi Arkis ha portato alla luce sopravvissuti come:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commentare l'assegnazione non ha fatto fallire i test, dimostrando l'assenza di asserzioni sullo stato post-operazione. Causa principale: il codice si affidava a un `_cmd.value` controllato dall'utente invece di validare i trasferimenti effettivi di token. Un attaccante poteva disallineare i trasferimenti attesi rispetto a quelli effettivi per drenare fondi. Risultato: rischio di alta gravità per la solvibilità del protocollo.

Guidance: Tratta i mutanti sopravvissuti che influenzano trasferimenti di valore, contabilità o controllo degli accessi come ad alto rischio finché non vengono 'killed'.

## Checklist pratica

- Esegui una campagna mirata:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Effettua il triage dei mutanti sopravvissuti e scrivi test/invarianti che fallirebbero con il comportamento mutato.
- Verifica saldi, supply, autorizzazioni ed eventi.
- Aggiungi test ai bordi (`==`, overflow/underflow, indirizzo zero, importo zero, array vuoti).
- Sostituisci i mock irrealistici; simula modalità di fallimento.
- Itera finché tutti i mutanti non vengono 'killed' o giustificati con commenti e motivazioni.

## Riferimenti

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
