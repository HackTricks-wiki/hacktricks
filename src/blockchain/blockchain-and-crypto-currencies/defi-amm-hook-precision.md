# Sfruttamento DeFi/AMM: abuso di precisione/arrotondamento degli hook di Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una classe di tecniche di sfruttamento DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica del core con hook personalizzati. Un incidente Bunni V2 illustra un problema correlato: un bug nella direzione dell’arrotondamento durante la contabilizzazione dei prelievi sottostimava la liquidità attiva; in seguito, uno swap ha esposto tale sottostima in un sandwich redditizio.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idea chiave: se un hook implementa una contabilizzazione aggiuntiva basata su matematica a virgola fissa, arrotondamento dei tick e logica basata su soglie, un attaccante può creare swap exact-input che superano soglie specifiche, facendo sì che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo lo schema e prelevando poi il saldo gonfiato, si ottiene un profitto, spesso finanziato con un flash loan.

## Contesto: hook di Uniswap v4 e flusso degli swap

- Gli hook sono contratti che PoolManager chiama in specifici punti del ciclo di vita (ad es., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- I pool vengono inizializzati con un PoolKey che include il contratto hook. Un indirizzo hook diverso da zero abilita le callback selezionate per quel pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Gli hook possono restituire **delta personalizzati** che modificano le variazioni finali dei saldi di uno swap o di un’operazione di liquidità (contabilità personalizzata). Questi delta vengono regolati come saldi netti al termine della chiamata, quindi ogni errore di arrotondamento nella matematica dell’hook si accumula prima del regolamento.<sup>[[4]](#references)</sup>
- La matematica del core usa formati a virgola fissa come Q64.96 per sqrtPriceX96 e l’aritmetica dei tick basata su 1.0001^tick. Qualsiasi matematica personalizzata aggiunta deve rispettare attentamente le regole di arrotondamento per evitare derive dell’invariante.<sup>[[12]](#references)[[13]](#references)</sup>
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si muove lungo i tick; l’attraversamento del limite di un tick può attivare/disattivare la liquidità di un intervallo. Gli hook possono implementare logica aggiuntiva in corrispondenza degli attraversamenti di soglie/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Modello di vulnerabilità: deriva di precisione/arrotondamento al superamento delle soglie

Un tipico schema vulnerabile negli hook personalizzati:

1. L’hook calcola delta di liquidità o saldo per ogni swap usando divisione intera, mulDiv o conversioni a virgola fissa (ad es., da token a liquidità usando sqrtPrice e intervalli di tick).
2. La logica basata su soglie (ad es., ribilanciamento, redistribuzione a scaglioni o attivazione per intervallo) si attiva quando la dimensione dello swap o il movimento del prezzo supera un limite interno.
3. L’arrotondamento viene applicato in modo incoerente (ad es., troncamento verso zero, floor invece di ceil) tra il calcolo diretto e il percorso di regolamento. Le piccole discrepanze non si annullano, ma accreditano invece il chiamante.
4. Swap exact-input dimensionati con precisione per superare tali limiti raccolgono ripetutamente il resto positivo dovuto all’arrotondamento. In seguito, l’attaccante preleva il credito accumulato.

Prerequisiti dell’attacco
- Un pool che utilizza un hook v4 personalizzato che esegue calcoli aggiuntivi a ogni swap (ad es., un LDF/ribilanciatore).
- Almeno un percorso di esecuzione in cui l’arrotondamento favorisce chi avvia lo swap quando vengono superate le soglie.
- Possibilità di ripetere molti swap atomicamente (i flash loan sono ideali per fornire liquidità temporanea e ammortizzare il gas).

## Metodologia pratica dell’attacco

1) Individuare pool candidati con hook
- Enumerare i pool v4 e verificare che PoolKey.hooks != address(0).
- Esaminare bytecode/ABI dell’hook per individuare le callback: beforeSwap/afterSwap e gli eventuali metodi personalizzati di ribilanciamento.
- Cercare calcoli che: dividono per la liquidità, convertono tra quantità di token e liquidità oppure aggregano BalanceDelta con arrotondamento.

2) Modellare la matematica e le soglie dell’hook
- Ricreare la formula di liquidità/redistribuzione dell’hook: gli input includono in genere sqrtPriceX96, tickLower/Upper, currentTick, fee tier e liquidità netta.
- Mappare le funzioni a soglia/gradino: tick, limiti dei bucket o breakpoint LDF. Determinare da quale lato di ogni limite viene arrotondato il delta.
- Individuare i punti in cui le conversioni eseguono cast tra uint256/int256, usano SafeCast o si affidano a mulDiv con floor implicito.

3) Calibrare gli swap exact-input per superare i limiti
- Usare simulazioni Foundry/Hardhat per calcolare il Δin minimo necessario a spostare il prezzo appena oltre un limite e attivare il ramo dell’hook.
- Verificare che il regolamento afterSwap accrediti al chiamante più del costo, lasciando un BalanceDelta positivo o un credito nella contabilizzazione dell’hook.
- Ripetere gli swap per accumulare credito; poi chiamare il percorso di prelievo/regolamento dell’hook.

In v4, il ciclo dello swap deve essere eseguito da una callback di sblocco di PoolManager; un `amountSpecified` negativo indica exact input e `sqrtPriceLimitX96` deve essere strettamente compreso nell’intervallo valido. Un limite di prezzo pari a zero causa un revert, quindi lo pseudocodice seguente usa il limite inferiore per uno swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Approssima un input di token0 (zero-for-one) usando la formula compatibile con Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Rispetta l’arrotondamento specifico della direzione usato dalla routine core.<sup>[[12]](#references)</sup>
- Modifica Δin di ±1 wei intorno al limite per trovare il ramo in cui l’hook arrotonda a tuo favore.

4) Amplificare con flash loan
- Prendi in prestito un importo nominale elevato (ad es., 3M USDT o 2000 WETH) per eseguire molte iterazioni in modo atomico.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Esegui il ciclo di swap calibrato, quindi preleva i fondi e rimborsa il prestito nel callback del flash loan.

Struttura di base di un flash loan Aave V3
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

5) Uscita e replicazione cross-chain
- Se gli hook sono distribuiti su più chain, ripetere la stessa calibrazione per ciascuna chain.
- Nell’incidente di Bunni, la liquidità dei flash loan e le route dei bridge erano diverse da una chain all’altra; tenere quindi conto di questi vincoli specifici della chain quando si riproduce l’analisi.<sup>[[1]](#references)[[2]](#references)</sup>

## Cause principali degli errori matematici negli hook

- Semantiche di arrotondamento miste: mulDiv arrotonda per difetto, mentre i percorsi successivi di fatto arrotondano per eccesso; oppure le conversioni tra token e liquidità applicano arrotondamenti diversi.
- Errori di allineamento dei tick: un percorso usa tick non arrotondati e un altro applica un arrotondamento basato sul tick spacing.
- Problemi di segno/overflow di BalanceDelta durante la conversione tra int256 e uint256 in fase di settlement.
- Perdita di precisione nelle conversioni Q64.96 (sqrtPriceX96), non rispecchiata nella mappatura inversa.
- Percorsi di accumulo: i resti per swap sono contabilizzati come crediti prelevabili dal chiamante, invece di essere bruciati o compensati a somma zero.

## Contabilità personalizzata e amplificazione dei delta

- La contabilità personalizzata di Uniswap v4 consente agli hook di restituire delta che modificano direttamente quanto il chiamante deve pagare o ricevere. Se l’hook tiene traccia internamente dei crediti, i residui di arrotondamento possono accumularsi durante molte operazioni di piccolo importo **prima** del settlement finale.<sup>[[4]](#references)</sup>
- Se l’hook espone un percorso di prelievo compatibile, un attaccante può alternare `swap → withdraw → swap` all’interno della stessa callback di unlock di PoolManager, costringendo l’hook a ricalcolare i delta su uno stato leggermente diverso mentre i saldi restano in sospeso fino al settlement dell’unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Quando si esaminano gli hook, tracciare sempre come vengono prodotti e liquidati BalanceDelta/HookDelta. Un singolo arrotondamento sbilanciato in un ramo può trasformarsi in un credito che si accumula quando i delta vengono ricalcolati ripetutamente.

## Indicazioni difensive

- Test differenziali: confrontare i calcoli dell’hook con un’implementazione di riferimento che usa l’aritmetica razionale ad alta precisione e verificare l’uguaglianza o un errore limitato, sempre a sfavore dell’utente (mai vantaggioso per il chiamante).
- Test di invarianti/proprietà:
  - La somma dei delta (token, liquidità) nei percorsi di swap e negli aggiustamenti dell’hook deve conservare il valore, al netto delle commissioni.
  - Nessun percorso deve creare un credito netto positivo per chi avvia lo swap dopo ripetute iterazioni exactInput.
  - Testare le soglie e i confini dei tick con input di ±1 wei per exactInput/exactOutput.
- Policy di arrotondamento: centralizzare gli helper di arrotondamento in modo che arrotondino sempre a sfavore dell’utente; eliminare cast incoerenti e arrotondamenti per difetto impliciti.
- Destinazione dei residui: accumulare i residui di arrotondamento inevitabili nella tesoreria del protocollo o bruciarli; non attribuirli mai a msg.sender.
- Limitazioni/guardrail: imporre importi minimi di swap per i trigger di ribilanciamento; disabilitare i ribilanciamenti se i delta sono inferiori a un wei; verificare che i delta rientrino negli intervalli previsti.
- Esaminare nel complesso le callback dell’hook: beforeSwap/afterSwap e le callback before/after per le modifiche alla liquidità devono concordare sull’allineamento dei tick e sull’arrotondamento dei delta.

## Caso di studio: Bunni V2 (2025‑09‑02)

- Protocollo: Bunni V2, un hook di Uniswap v4 che usa una Liquidity Density Function (LDF) per calcolare la densità dei token e le stime della liquidità totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pool coinvolti: USDC/USDT su Ethereum e weETH/ETH su Unichain, per un totale di circa $8.4M.<sup>[[1]](#references)</sup>
- Passaggio 1 (spinta del prezzo): l’attaccante ha preso in prestito tramite flash loan circa 3M USDT ed eseguito uno swap per spingere il tick a circa 5000, riducendo il saldo **attivo** di USDC a circa 28 wei.<sup>[[1]](#references)</sup>
- Passaggio 2 (drenaggio tramite arrotondamento): 44 piccoli prelievi hanno sfruttato l’arrotondamento per difetto in `BunniHubLogic::withdraw()` per ridurre il saldo attivo di USDC da 28 wei a 4 wei (-85.7%), bruciando solo una frazione minima delle quote LP. La liquidità totale è diminuita di circa l’84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Passaggio 3 (sandwich con rimbalzo della liquidità): un grande swap ha spostato il tick a circa 839,189 (1 USDC ≈ 2.77e36 USDT). Le stime della liquidità si sono invertite e sono aumentate di circa il 16.8%, consentendo un sandwich in cui l’attaccante ha eseguito lo swap inverso al prezzo gonfiato, uscendo con un profitto.<sup>[[1]](#references)</sup>
- Correzione individuata nel post-mortem: modificare l’aggiornamento del saldo inattivo affinché arrotondi **per eccesso**, impedendo così che ripetuti micro-prelievi riducano progressivamente il saldo attivo del pool.<sup>[[1]](#references)</sup>

Riga vulnerabile semplificata (e correzione del post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Checklist di ricerca

- La pool usa un indirizzo hooks diverso da zero? Quali callback sono abilitate?
- Ci sono redistribuzioni/rebalances per-swap che usano custom math? Ci sono logiche basate su tick/soglie?
- Dove vengono usati divisioni/mulDiv, conversioni Q64.96 o SafeCast? Le semantiche di arrotondamento sono coerenti globalmente?
- Puoi costruire un Δin che superi di poco un confine e produca un ramo di arrotondamento favorevole? Testa entrambe le direzioni e sia exactInput sia exactOutput.
- L’hook tiene traccia di crediti o delta per-caller che possono essere prelevati in seguito? Assicurati che i residui vengano neutralizzati.

## References

- [1] [Analisi post mortem dell’exploit di Bunni (settembre 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit di Bunni V2: analisi completa dell’hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit di Bunni V2: sottratti 8,3 milioni di dollari tramite una falla nella liquidità (riepilogo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper di Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contesto su Uniswap v4 (ricerca di QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Meccaniche della liquidità nel core di Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Meccaniche degli swap nel core di Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks di Uniswap v4 e considerazioni sulla sicurezza](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
