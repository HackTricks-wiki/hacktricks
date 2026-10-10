# Sfruttamento DeFi/AMM: abuso di precisione/arrotondamento degli hook di Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una classe di tecniche di sfruttamento DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica di base con hook personalizzati. Un incidente che ha coinvolto Bunni V2 illustra un errore correlato: un bug nella direzione dell’arrotondamento durante il calcolo dei prelievi sottostimava la liquidità attiva e uno swap successivo ha esposto tale sottostima in un sandwich redditizio.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idea chiave: se un hook implementa contabilità aggiuntiva basata su matematica a virgola fissa, arrotondamento dei tick e logica basata su soglie, un attaccante può creare swap exact-input che attraversano soglie specifiche, facendo sì che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo lo schema e prelevando poi il saldo gonfiato, l’attaccante realizza un profitto, spesso finanziato con un flash loan.

## Contesto: hook di Uniswap v4 e flusso degli swap

- Gli hook sono contratti che PoolManager chiama in specifici punti del ciclo di vita (ad es. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- I pool vengono inizializzati con un PoolKey che include il contratto hook. Un indirizzo hook diverso da zero abilita le callback selezionate per quel pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Gli hook possono restituire **custom delta** che modificano le variazioni finali del saldo di uno swap o di un’operazione di liquidità (contabilità personalizzata). Questi delta vengono regolati come saldi netti al termine della chiamata, quindi ogni errore di arrotondamento nella matematica dell’hook si accumula prima del regolamento.<sup>[[4]](#references)</sup>
- La matematica di base usa formati a virgola fissa come Q64.96 per sqrtPriceX96 e l’aritmetica dei tick con 1.0001^tick. Qualsiasi matematica personalizzata aggiunta deve rispettare attentamente le regole di arrotondamento per evitare derive dell’invariante.<sup>[[12]](#references)[[13]](#references)</sup>
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si muove lungo i tick; l’attraversamento del limite di un tick può attivare/disattivare la liquidità dell’intervallo. Gli hook possono implementare logica aggiuntiva in caso di attraversamento di soglie/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Schema di vulnerabilità: deriva di precisione/arrotondamento nell’attraversamento di soglie

Uno schema tipicamente vulnerabile negli hook personalizzati:

1. L’hook calcola delta di liquidità o saldo per ogni swap usando divisione intera, mulDiv o conversioni a virgola fissa (ad es. conversione tra token e liquidità usando sqrtPrice e intervalli di tick).
2. La logica basata su soglie (ad es. ribilanciamento, ridistribuzione a gradini o attivazione per intervallo) si attiva quando la dimensione dello swap o il movimento del prezzo supera un limite interno.
3. L’arrotondamento viene applicato in modo incoerente (ad es. troncamento verso zero, floor invece di ceil) tra il calcolo diretto e il percorso di regolamento. Le piccole discrepanze non si annullano, ma accreditano l’utente che avvia lo swap.
4. Swap exact-input dimensionati con precisione per superare quelle soglie raccolgono ripetutamente il resto positivo dovuto all’arrotondamento. L’attaccante preleva poi il credito accumulato.

Prerequisiti dell’attacco
- Un pool che usa un hook v4 personalizzato che esegue calcoli aggiuntivi a ogni swap (ad es. un LDF/rebalancer).
- Almeno un percorso di esecuzione in cui l’arrotondamento favorisce chi avvia lo swap durante l’attraversamento delle soglie.
- La possibilità di ripetere molti swap in modo atomico (i flash loan sono ideali per fornire liquidità temporanea e ammortizzare il gas).

## Metodologia pratica dell’attacco

1) Individuare i pool candidati con hook
- Enumerare i pool v4 e verificare che PoolKey.hooks != address(0).
- Esaminare il bytecode/ABI dell’hook alla ricerca di callback: beforeSwap/afterSwap e di eventuali metodi di ribilanciamento personalizzati.
- Cercare calcoli che: dividono per la liquidità, convertono tra importi di token e liquidità o aggregano BalanceDelta con arrotondamento.

2) Modellare la matematica e le soglie dell’hook
- Ricreare la formula di liquidità/ridistribuzione dell’hook: gli input includono tipicamente sqrtPriceX96, tickLower/Upper, currentTick, la commissione e la liquidità netta.
- Mappare le funzioni a soglia/gradino: tick, limiti dei bucket o punti di interruzione LDF. Determinare da quale lato di ogni limite viene arrotondato il delta.
- Individuare dove le conversioni effettuano cast tra uint256/int256, usano SafeCast o si affidano a mulDiv con floor implicito.

3) Calibrare swap exact-input per attraversare i limiti
- Usare simulazioni Foundry/Hardhat per calcolare il Δin minimo necessario a spostare il prezzo appena oltre un limite e attivare il ramo dell’hook.
- Verificare che il regolamento afterSwap accrediti a chi avvia lo swap più del costo, lasciando un BalanceDelta positivo o un credito nella contabilità dell’hook.
- Ripetere gli swap per accumulare credito; poi chiamare il percorso di prelievo/regolamento dell’hook.

In v4, il ciclo dello swap deve essere eseguito da una callback di sblocco di PoolManager; un `amountSpecified` negativo indica exact input e `sqrtPriceLimitX96` deve trovarsi strettamente all’interno dell’intervallo valido. Un limite di prezzo pari a zero causa un revert, quindi lo pseudocodice seguente usa il limite inferiore per uno swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Esempio di harness di test in stile Foundry (pseudocodice)
```solidity
function test_precision_rounding_abuse() public {
    // 1) Arrange: set up pool with hook
    PoolKey memory key = PoolKey({
        currency0: USDC,
        currency1: USDT,
        fee: 500, // 0.05%
        tickSpacing: 10,
        hooks: IHooks(address(bunniHook))
    });
    pm.initialize(key, initialSqrtPriceX96);

    // 2) Determine a boundary‑crossing exactInput
    uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

    // 3) Loop swaps to accrue rounding credit
    // This loop runs inside the PoolManager unlockCallback.
    for (uint i; i < N; ++i) {
        pm.swap(
            key,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -int256(exactIn), // exactInput
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
            }),
            ""
        );
    }

    // 4) Realize inflated credit via hook‑exposed withdrawal
    bunniHook.withdrawCredits(msg.sender);
}
```

Calibrazione di exactInput
- Calcola il target con TickMath core: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in termini di valori reali; il risultato Q64.96 viene arrotondato da TickMath.<sup>[[13]](#references)</sup>
- Approssima un input di token0 (zero-for-one) usando la formula compatibile con Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Applica l’arrotondamento specifico per direzione della routine core.<sup>[[12]](#references)</sup>
- Modifica Δin di ±1 wei intorno al limite per individuare il ramo in cui l’hook arrotonda a tuo favore.

4) Amplifica con i flash loan
- Prendi in prestito un importo nozionale elevato (ad es., 3M USDT o 2000 WETH) per eseguire molte iterazioni in modo atomico.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Esegui il loop di swap calibrato, quindi preleva i fondi e rimborsali all’interno della callback del flash loan.

Struttura base di un flash loan Aave V3
```solidity
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    // run threshold‑crossing swap loop here
    for (uint i; i < N; ++i) {
        _exactInBoundaryCrossingSwap();
    }
    // realize credits / withdraw inflated balances
    bunniHook.withdrawCredits(address(this));
    // repay
    for (uint j; j < assets.length; ++j) {
        IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
    }
    return true;
}
```

5) Uscita e replica cross-chain
- Se gli hook sono distribuiti su più chain, ripeti la stessa calibrazione per ciascuna chain.
- Nell’incidente Bunni, la liquidità dei flash loan e le rotte bridge differivano da una chain all’altra: tieni quindi conto di questi vincoli specifici della chain quando riproduci l’analisi.<sup>[[1]](#references)[[2]](#references)</sup>

## Cause principali degli errori nella matematica degli hook

- Semantiche di arrotondamento miste: mulDiv arrotonda per difetto, mentre i percorsi successivi di fatto arrotondano per eccesso; oppure le conversioni tra token e liquidità applicano arrotondamenti diversi.
- Errori di allineamento dei tick: usare tick non arrotondati in un percorso e arrotondarli in base alla spaziatura dei tick in un altro.
- Problemi di segno/overflow di BalanceDelta durante la conversione tra int256 e uint256 nel settlement.
- Perdita di precisione nelle conversioni Q64.96 (sqrtPriceX96), non rispecchiata nella mappatura inversa.
- Percorsi di accumulo: i resti per swap vengono tracciati come crediti prelevabili dal chiamante invece di essere bruciati o azzerati a somma zero.

## Contabilità personalizzata e amplificazione dei delta

- La contabilità personalizzata di Uniswap v4 consente agli hook di restituire delta che modificano direttamente quanto il chiamante deve o riceve. Se l’hook traccia internamente i crediti, i residui di arrotondamento possono accumularsi nel corso di molte piccole operazioni **prima** del settlement finale.<sup>[[4]](#references)</sup>
- Se l’hook espone un percorso di prelievo compatibile, un attaccante può alternare `swap → withdraw → swap` all’interno della stessa callback di sblocco di PoolManager, costringendo l’hook a ricalcolare i delta su uno stato leggermente diverso mentre i saldi restano in sospeso fino al settlement dello sblocco.<sup>[[4]](#references)[[10]](#references)</sup>
- Quando esamini gli hook, traccia sempre come viene prodotto e regolato BalanceDelta/HookDelta. Un singolo arrotondamento sbilanciato in un ramo può trasformarsi in un credito che si accumula quando i delta vengono ricalcolati ripetutamente.

## Indicazioni difensive

- Test differenziali: confronta la matematica dell’hook con un’implementazione di riferimento basata su aritmetica razionale ad alta precisione e verifica l’uguaglianza o un errore limitato sempre sfavorevole all’utente (mai vantaggioso per il chiamante).
- Test di invarianti/proprietà:
  - La somma dei delta (token, liquidità) nei percorsi di swap e nelle modifiche degli hook deve conservare il valore, al netto delle commissioni.
  - Nessun percorso deve creare un credito netto positivo per chi avvia lo swap dopo iterazioni ripetute di exactInput.
  - Testa le soglie e i limiti dei tick con input di ±1 wei sia per exactInput sia per exactOutput.
- Politica di arrotondamento: centralizza gli helper di arrotondamento in modo che arrotondino sempre a sfavore dell’utente; elimina i cast incoerenti e gli arrotondamenti impliciti per difetto.
- Destinazione dei residui: accumula i residui inevitabili di arrotondamento nella tesoreria del protocollo oppure bruciali; non attribuirli mai a msg.sender.
- Limiti/controlli di sicurezza: imposta importi minimi di swap per i trigger di ribilanciamento; disabilita i ribilanciamenti se i delta sono inferiori a un wei; verifica la plausibilità dei delta rispetto agli intervalli attesi.
- Esamina nel complesso le callback degli hook: beforeSwap/afterSwap e le callback before/after delle modifiche alla liquidità devono concordare sull’allineamento dei tick e sull’arrotondamento dei delta.

## Caso di studio: Bunni V2 (2025‑09‑02)

- Protocollo: Bunni V2, un hook Uniswap v4 che usa una Liquidity Density Function (LDF) per calcolare la densità dei token e le stime della liquidità totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pool interessati: USDC/USDT su Ethereum e weETH/ETH su Unichain, per un totale di circa $8.4M.<sup>[[1]](#references)</sup>
- Passaggio 1 (spinta del prezzo): l’attaccante ha preso in prestito ~3M USDT tramite flash loan e ha effettuato uno swap per portare il tick a ~5000, riducendo il saldo USDC **attivo** a ~28 wei.<sup>[[1]](#references)</sup>
- Passaggio 2 (drenaggio tramite arrotondamento): 44 piccoli prelievi hanno sfruttato l’arrotondamento per difetto in `BunniHubLogic::withdraw()` per ridurre il saldo USDC attivo da 28 wei a 4 wei (-85.7%), bruciando solo una piccola frazione delle quote LP. La liquidità totale è diminuita di ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Passaggio 3 (sandwich con rimbalzo della liquidità): un grande swap ha spostato il tick a ~839,189 (1 USDC ≈ 2.77e36 USDT). Le stime della liquidità si sono invertite e sono aumentate di ~16.8%, consentendo un sandwich in cui l’attaccante ha effettuato lo swap inverso al prezzo gonfiato e ha chiuso l’operazione in profitto.<sup>[[1]](#references)</sup>
- Correzione individuata nel post-mortem: modificare l’aggiornamento del saldo inattivo affinché arrotondi **per eccesso**, impedendo ai micro-prelievi ripetuti di ridurre progressivamente il saldo attivo del pool.<sup>[[1]](#references)</sup>

Riga vulnerabile semplificata (e correzione del post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Checklist di hunting

- La pool usa un indirizzo hooks diverso da zero? Quali callback sono abilitati?
- Ci sono redistribuzioni/ribilanciamenti per swap che usano matematica personalizzata? Ci sono logiche basate su tick/soglie?
- Dove vengono usati divisioni/mulDiv, conversioni Q64.96 o SafeCast? Le semantiche di arrotondamento sono coerenti in tutto il codice?
- È possibile costruire un Δin che superi appena una soglia e attivi un ramo di arrotondamento favorevole? Testare entrambe le direzioni e sia exactInput sia exactOutput.
- L’hook tiene traccia di crediti o delta per singolo chiamante che possono essere ritirati in seguito? Assicurarsi che i residui siano neutralizzati.

## References

- [1] [Analisi post mortem dell’exploit di Bunni (settembre 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit di Bunni V2: analisi completa dell’hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit di Bunni V2: 8,3 milioni di dollari sottratti tramite una falla nella liquidità (riepilogo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper di Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contesto su Uniswap v4 (ricerca di QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Meccanismi di liquidità in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Meccanismi di swap in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks di Uniswap v4 e considerazioni sulla sicurezza](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol di Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol di Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol di Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol di Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
