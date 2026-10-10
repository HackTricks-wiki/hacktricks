# Mutation Testing per Smart Contract (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Il mutation testing "testa i tuoi test" introducendo sistematicamente piccole modifiche (mutanti) nel codice del contratto e rieseguendo la suite di test. Se un test fallisce, il mutante viene ucciso. Se i test continuano a passare, il mutante sopravvive, rivelando un punto cieco che la copertura di righe/branch non può rilevare.

Idea chiave: la copertura mostra che il codice è stato eseguito; il mutation testing mostra se il comportamento viene effettivamente verificato.<sup>[[2]](#references)</sup>

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

I test unitari che verificano solo un valore inferiore e uno superiore alla soglia possono raggiungere il 100% di line/branch coverage senza verificare il caso di uguaglianza (==). Un refactoring in `deposit >= 2 ether` supererebbe comunque questi test, compromettendo silenziosamente la logica del protocollo.<sup>[[2]](#references)</sup>

Il mutation testing mette in luce questa lacuna modificando la condizione e verificando che i test falliscano.

Negli smart contract, i mutant che sopravvivono spesso indicano controlli mancanti relativi a:
- Autorizzazioni e limiti dei ruoli
- Invarianti di accounting e trasferimento di valore
- Condizioni di revert e percorsi di errore
- Condizioni limite (`==`, valori zero, array vuoti, valori massimi/minimi)

## Operatori di mutazione con il più alto segnale di sicurezza

Classi di mutazione utili per l'audit dei contract:<sup>[[1]](#references)[[2]](#references)</sup>
- **Gravità alta**: sostituire istruzioni con `revert()` per individuare percorsi non eseguiti
- **Gravità media**: commentare righe / rimuovere logica per individuare effetti collaterali non verificati
- **Gravità bassa**: sostituzioni sottili di operatori o costanti, come `>=` -> `>` o `+` -> `-`
- Altre modifiche comuni: sostituzione di assegnazioni, inversioni di valori booleani, negazione di condizioni e modifiche dei tipi

Obiettivo pratico: eliminare tutti i mutant significativi e giustificare esplicitamente quelli sopravvissuti perché irrilevanti o semanticamente equivalenti.

## Perché la mutazione consapevole della sintassi è migliore delle regex

I motori di mutazione precedenti si basavano su regex o riscritture orientate alle righe. Questo funziona, ma presenta importanti limiti:<sup>[[1]](#references)</sup>
- Le istruzioni su più righe sono difficili da modificare in sicurezza
- La struttura del linguaggio non viene compresa, quindi commenti/token possono essere selezionati in modo errato
- Generare ogni possibile variante su una riga debole spreca molto tempo di esecuzione

Gli strumenti basati su AST o Tree-sitter migliorano questo approccio selezionando nodi strutturati invece di righe grezze:<sup>[[1]](#references)</sup>
- **slither-mutate** usa l'AST Solidity di Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter come nucleo indipendente dal linguaggio.<sup>[[6]](#references)</sup>
- **MuTON** si basa su `mewt` e aggiunge il supporto nativo ai linguaggi TON, come FunC, Tolk e Tact.<sup>[[7]](#references)</sup>

Questo rende le modifiche a costrutti su più righe e a livello di espressione molto più affidabili rispetto agli approcci basati solo su regex.

## Eseguire mutation testing con slither-mutate

Requisiti: Slither v0.10.2+.

- Elencare le opzioni e i mutator:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Esempio Foundry (acquisisci i risultati e conserva un log completo):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Se non usi Foundry, sostituisci `--test-cmd` con il comando che usi per eseguire i test (ad esempio, `npx hardhat test`, `npm test`).

Gli artefatti vengono salvati in `./mutation_campaign` per impostazione predefinita. I mutanti non intercettati (sopravvissuti) vengono copiati lì per essere esaminati.<sup>[[5]](#references)</sup>

### Comprendere l’output

Le righe del report sono simili a:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Il tag tra parentesi è l'alias del mutator (ad es., `CR` = Comment Replacement).
- `UNCAUGHT` indica che i test sono passati con il comportamento mutato → manca un'asserzione.

## Ridurre il runtime: dare priorità ai mutanti più impattanti

Le campagne di mutation testing possono durare ore o giorni. Consigli per ridurre i costi:<sup>[[1]](#references)[[2]](#references)</sup>
- Ambito: inizia solo con i contratti e le directory critici, poi amplia l'ambito.
- Dai priorità ai mutator: se un mutante ad alta priorità in una riga sopravvive (ad esempio `revert()` o comment-out), salta le varianti a priorità inferiore per quella riga.
- Usa campagne in due fasi: esegui prima test mirati e veloci, poi ripeti i test solo sui mutanti uncaught con l'intera suite.
- Quando possibile, associa i target delle mutazioni a comandi di test specifici (ad esempio, codice di auth -> test di auth).
- Quando il tempo è limitato, restringi le campagne ai mutanti di severità alta/media.
- Esegui i test in parallelo se il tuo runner lo consente; memorizza nella cache dipendenze e build.
- Fail-fast: interrompi in anticipo quando una modifica dimostra chiaramente una lacuna nelle asserzioni.

I calcoli del runtime sono spietati: `1000 mutants x 5-minute tests ~= 83 hours`, quindi la progettazione della campagna conta quanto il mutator stesso.<sup>[[1]](#references)</sup>

## Campagne persistenti e triage su larga scala

Un punto debole dei workflow meno recenti è che i risultati vengono riversati solo su `stdout`. Nelle campagne lunghe, questo rende più difficili la pausa e la ripresa, il filtraggio e la revisione.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` migliorano la situazione archiviando mutanti ed esiti in campagne basate su SQLite. Vantaggi:<sup>[[1]](#references)</sup>
- Mettere in pausa e riprendere le esecuzioni lunghe senza perdere i progressi
- Filtrare solo i mutanti uncaught in un file specifico o in una classe di mutazione
- Esportare/convertire i risultati in SARIF per gli strumenti di revisione
- Fornire al triage assistito dall'AI insiemi di risultati più piccoli e filtrati, anziché log grezzi del terminale

I risultati persistenti sono particolarmente utili quando il mutation testing diventa parte di una pipeline di audit invece di una revisione manuale occasionale.

## Workflow di triage per i mutanti sopravvissuti

1) Esamina la riga mutata e il comportamento.
   - Riproduci il problema localmente applicando la riga mutata ed eseguendo un test mirato.

2) Rafforza i test verificando lo stato, non solo i valori restituiti.
   - Aggiungi controlli sui valori di confine dell'uguaglianza (ad es., verifica `==` sulla soglia).
   - Verifica le post-condizioni: saldi, offerta totale, effetti dell'autorizzazione ed eventi emessi.

3) Sostituisci i mock eccessivamente permissivi con comportamenti realistici.
   - Assicurati che i mock verifichino i trasferimenti, i percorsi di errore e gli eventi emessi on-chain.

4) Aggiungi invarianti ai test fuzz.
   - Ad es., conservazione del valore, saldi non negativi, invarianti di autorizzazione e offerta monotona, ove applicabile.

5) Distingui i veri positivi dai no-op semantici.
   - Esempio: `x > 0` -> `x != 0` non cambia nulla quando `x` è unsigned.

6) Ripeti la campagna finché i mutanti sopravvissuti non vengono eliminati o esplicitamente giustificati.

## Caso di studio: individuare asserzioni di stato mancanti (protocollo Arkis)

Durante un audit del protocollo DeFi Arkis, una campagna di mutation testing ha rilevato mutanti sopravvissuti come:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Commentare l'assegnazione non ha fatto fallire i test, dimostrando l'assenza di asserzioni sullo stato finale. Causa principale: il codice si fidava di `_cmd.value`, controllato dall'utente, invece di convalidare i trasferimenti effettivi dei token. Un attacker poteva desincronizzare i trasferimenti previsti da quelli effettivi per prosciugare i fondi. Risultato: rischio elevato per la solvibilità del protocollo.<sup>[[2]](#references)[[3]](#references)</sup>

Indicazione: considera ad alto rischio i mutanti sopravvissuti che incidono sui trasferimenti di valore, sulla contabilità o sul controllo degli accessi, finché non vengono eliminati.

## Non generare test alla cieca per eliminare ogni mutante

La generazione di test basata sulle mutazioni può rivelarsi controproducente se l'implementazione attuale è errata. Esempio: mutare `priority >= 2` in `priority > 2` modifica il comportamento, ma la correzione giusta non è sempre «scrivere un test per `priority == 2`». Quel comportamento potrebbe essere proprio il bug.<sup>[[1]](#references)</sup>

Workflow più sicuro:
- Usa i mutanti sopravvissuti per individuare requisiti ambigui
- Verifica il comportamento previsto consultando le specifiche, la documentazione del protocollo o i reviewer
- Solo a quel punto codifica il comportamento come test/invariante

Altrimenti rischi di codificare nel test suite gli effetti accidentali dell'implementazione e di ottenere una falsa sicurezza.

## Checklist pratica

- Esegui una campagna mirata:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Quando disponibili, preferisci mutatori consapevoli della sintassi (AST/Tree-sitter) rispetto a quelli basati solo su regex.
- Esamina i mutanti sopravvissuti e scrivi test/invarianti che fallirebbero con il comportamento mutato.
- Verifica saldi, supply, autorizzazioni ed eventi.
- Aggiungi test sui casi limite (`==`, overflow/underflow, indirizzo zero, importo zero, array vuoti).
- Sostituisci i mock irrealistici; simula le modalità di errore.
- Se lo strumento lo supporta, salva i risultati e filtra i mutanti non intercettati prima dell'analisi.
- Usa campagne in due fasi o per target per mantenere gestibili i tempi di esecuzione.
- Ripeti finché tutti i mutanti non vengono eliminati o giustificati con commenti e motivazioni.

## References

- [1] [Mutation testing per l'era agentica](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Usa il mutation testing per trovare i bug che i tuoi test non rilevano (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revisione della sicurezza di Arkis DeFi Prime Brokerage (Appendice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentazione di Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
