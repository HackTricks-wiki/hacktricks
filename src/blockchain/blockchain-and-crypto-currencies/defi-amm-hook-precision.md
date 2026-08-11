# Exploitation DeFi/AMM: Abuso della precisione/degli arrotondamenti degli Hook di Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una classe di tecniche di exploitation DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica core con hook personalizzati. Un incidente Bunni V2 illustra un failure correlato: un bug nella direzione dell'arrotondamento durante il calcolo dei prelievi sottostimava la liquidità attiva, e uno swap successivo ha esposto tale sottostima in un sandwich redditizio.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idea chiave: se un hook implementa accounting aggiuntivo che dipende da matematica fixed-point, arrotondamento dei tick e logica basata su threshold, un attacker può creare swap exact-input che attraversano threshold specifici, facendo sì che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo il pattern e ritirando successivamente il saldo gonfiato, si realizza un profitto, spesso finanziato con un flash loan.

## Background: hook e flusso degli swap di Uniswap v4

- Gli hook sono contract che il PoolManager chiama in specifici punti del lifecycle (ad es., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- I pool vengono inizializzati con una PoolKey che include il contract dell'hook. Un indirizzo dell'hook diverso da zero abilita le callback selezionate per quel pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Gli hook possono restituire **custom deltas** che modificano le variazioni finali del saldo di uno swap o di un'azione sulla liquidità (custom accounting). Questi delta vengono regolati come saldi netti al termine della chiamata, quindi qualsiasi errore di arrotondamento nella matematica dell'hook si accumula prima della settlement.<sup>[[4]](#references)</sup>
- La matematica core usa formati fixed-point come Q64.96 per sqrtPriceX96 e l'aritmetica dei tick con 1.0001^tick. Qualsiasi matematica personalizzata sovrapposta deve riprodurre attentamente la semantica degli arrotondamenti per evitare drift dell'invariante.<sup>[[12]](#references)[[13]](#references)</sup>
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si muove lungo i tick; l'attraversamento di un confine di tick può attivare/disattivare la liquidità di un range. Gli hook possono implementare logica aggiuntiva sui crossing di threshold/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Archetype della vulnerabilità: drift di precisione/arrotondamento durante il superamento dei threshold

Un pattern tipicamente vulnerabile negli hook personalizzati:

1. L'hook calcola i delta di liquidità o di saldo per ogni swap usando divisione intera, mulDiv o conversioni fixed-point (ad es., da token a liquidità usando sqrtPrice e range di tick).
2. La logica dei threshold (ad es., rebalancing, redistribuzione a step o attivazione per range) viene attivata quando la dimensione dello swap o il movimento del prezzo attraversa un confine interno.
3. L'arrotondamento viene applicato in modo incoerente (ad es., troncamento verso zero, floor invece di ceil) tra il calcolo forward e il percorso di settlement. Le piccole discrepanze non si annullano e accreditano invece il caller.
4. Gli swap exact-input, dimensionati precisamente per attraversare quei confini, raccolgono ripetutamente il resto positivo dell'arrotondamento. L'attacker ritira successivamente il credito accumulato.

Prerequisiti dell'attacco
- Un pool che utilizza un custom v4 hook che esegue matematica aggiuntiva a ogni swap (ad es., un LDF/rebalancer).
- Almeno un execution path in cui l'arrotondamento favorisce l'iniziatore dello swap durante l'attraversamento dei threshold.
- Possibilità di ripetere molti swap atomically (i flash loan sono ideali per fornire liquidità temporanea e ammortizzare il gas).

## Metodologia pratica dell'attacco

1) Identificare i pool candidati con hook
- Enumerare i pool v4 e verificare che PoolKey.hooks != address(0).
- Ispezionare bytecode/ABI dell'hook alla ricerca di callback: beforeSwap/afterSwap e di eventuali metodi personalizzati di rebalancing.
- Cercare matematica che: divide per la liquidità, converte tra quantità di token e liquidità oppure aggrega BalanceDelta con arrotondamento.

2) Modellare la matematica e i threshold dell'hook
- Ricreare la formula di liquidità/redistribuzione dell'hook: gli input includono tipicamente sqrtPriceX96, tickLower/Upper, currentTick, fee tier e liquidità netta.
- Mappare le funzioni threshold/step: tick, confini dei bucket o breakpoint LDF. Determinare su quale lato di ogni confine viene arrotondato il delta.
- Identificare i punti in cui le conversioni eseguono cast tra uint256/int256, usano SafeCast o si affidano a mulDiv con floor implicito.

3) Calibrare gli swap exact-input per attraversare i confini
- Usare simulazioni Foundry/Hardhat per calcolare il Δin minimo necessario a spostare il prezzo appena oltre un confine e attivare il branch dell'hook.
- Verificare che la settlement afterSwap accrediti al caller più del costo, lasciando un BalanceDelta positivo o un credito nell'accounting dell'hook.
- Ripetere gli swap per accumulare credito; quindi chiamare il percorso di withdrawal/settlement dell'hook.

In v4, il loop dello swap deve essere eseguito da una callback di unlock del PoolManager; `amountSpecified` negativo indica exact input e `sqrtPriceLimitX96` deve trovarsi strettamente all'interno del range valido. Un price limit pari a zero causa un revert, quindi il pseudocode seguente usa il limite inferiore per uno swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Esempio di test harness in stile Foundry (pseudocode)
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
- Calcola il target con la core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in termini di valori reali; il risultato Q64.96 viene arrotondato da TickMath.<sup>[[13]](#references)</sup>
- Approssima un input token0 (zero-for-one) usando la formula compatibile con Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Rispetta l’arrotondamento specifico della direzione della routine core.<sup>[[12]](#references)</sup>
- Regola Δin di ±1 wei intorno al limite per trovare il branch in cui l’hook arrotonda a tuo favore.

4) Amplifica con flash loan
- Prendi in prestito un notional elevato (ad esempio, 3M USDT o 2000 WETH) per eseguire molte iterazioni in modo atomico.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Esegui il loop di swap calibrato, quindi effettua il prelievo e il rimborso all’interno del callback del flash loan.

Scheletro del flash loan di Aave V3
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
- Se gli hook sono deployed su più chain, ripetere la stessa calibrazione per ogni chain.
- Nell’incidente Bunni, la liquidità dei flash-loan e le route dei bridge differivano tra le chain; tenere quindi conto di questi vincoli specifici della chain quando si riproduce l’analisi.<sup>[[1]](#references)[[2]](#references)</sup>

## Common root causes in hook math

- Semantiche di rounding miste: `mulDiv` esegue un floor mentre i percorsi successivi effettuano di fatto un arrotondamento per eccesso; oppure le conversioni tra token/liquidità applicano rounding differenti.
- Errori di allineamento dei tick: utilizzo di tick non arrotondati in un percorso e di rounding basato sul tick spacing in un altro.
- Problemi di segno/overflow di `BalanceDelta` durante la conversione tra `int256` e `uint256` in fase di settlement.
- Perdita di precisione nelle conversioni Q64.96 (`sqrtPriceX96`) non rispecchiata nella mappatura inversa.
- Percorsi di accumulo: i resti per swap vengono tracciati come crediti prelevabili dal caller invece di essere bruciati o inclusi in un bilancio zero-sum.

## Custom accounting & delta amplification

- Il custom accounting di Uniswap v4 consente agli hook di restituire delta che modificano direttamente quanto il caller deve o riceve. Se l’hook traccia internamente i crediti, il residuo del rounding può accumularsi attraverso molte operazioni di piccola entità **prima** del settlement finale.<sup>[[4]](#references)</sup>
- Se l’hook espone un withdrawal path compatibile, un attacker può alternare `swap → withdraw → swap` all’interno dello stesso callback di unlock del PoolManager, forzando l’hook a ricalcolare i delta su uno stato leggermente diverso mentre i saldi rimangono pending fino al settlement dell’unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Durante la review degli hook, tracciare sempre come vengono prodotti e sottoposti a settlement `BalanceDelta`/`HookDelta`. Un singolo rounding sbilanciato in un branch può diventare un credito cumulativo quando i delta vengono ricalcolati ripetutamente.

## Defensive guidance

- Differential testing: confrontare la matematica dell’hook con una reference implementation usando aritmetica razionale ad alta precisione e verificare l’uguaglianza o un errore bounded che sia sempre adversarial (mai favorevole al caller).
- Invariant/property tests:
- La somma dei delta (token, liquidità) attraverso i percorsi di swap e gli aggiustamenti dell’hook deve conservare il valore al netto delle fee.
- Nessun percorso dovrebbe creare un credito netto positivo per l’iniziatore dello swap durante iterazioni ripetute di `exactInput`.
- Test delle soglie e dei confini dei tick attorno a input di ±1 wei per `exactInput`/`exactOutput`.
- Rounding policy: centralizzare gli helper di rounding affinché arrotondino sempre a sfavore dell’utente; eliminare cast incoerenti e floor impliciti.
- Settlement sinks: accumulare il residuo inevitabile del rounding nella treasury del protocollo o bruciarlo; non attribuirlo mai a `msg.sender`.
- Rate-limits/guardrails: dimensioni minime degli swap per i trigger di rebalancing; disabilitare i rebalancing se i delta sono inferiori a un wei; verificare la plausibilità dei delta rispetto agli intervalli attesi.
- Esaminare olisticamente i callback degli hook: `beforeSwap`/`afterSwap` e le modifiche alla liquidità `before`/`after` devono concordare sull’allineamento dei tick e sul rounding dei delta.

## Case study: Bunni V2 (2025-09-02)

- Protocollo: Bunni V2, un hook di Uniswap v4 che usa una Liquidity Density Function (LDF) per calcolare la densità dei token e le stime della liquidità totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pool interessati: USDC/USDT su Ethereum e weETH/ETH su Unichain, per un totale di circa 8,4 milioni di dollari.<sup>[[1]](#references)</sup>
- Step 1 (price push): l’attacker ha preso in prestito tramite flash-loan circa 3 milioni di USDT e ha eseguito uno swap per portare il tick a circa 5000, riducendo il saldo USDC **active** a circa 28 wei.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 piccoli prelievi hanno sfruttato il floor rounding in `BunniHubLogic::withdraw()` per ridurre il saldo USDC active da 28 wei a 4 wei (-85,7%), mentre veniva bruciata solo una frazione minima delle LP shares. La liquidità totale è diminuita di circa l’84,4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): un large swap ha spostato il tick a circa 839.189 (1 USDC ≈ 2,77e36 USDT). Le stime della liquidità si sono invertite e sono aumentate di circa il 16,8%, consentendo un sandwich in cui l’attacker ha effettuato lo swap inverso al prezzo gonfiato ed è uscito con un profitto.<sup>[[1]](#references)</sup>
- Fix identificato nel post-mortem: modificare l’aggiornamento dell’idle balance affinché arrotondi **per eccesso**, così che micro-withdrawal ripetuti non facciano più diminuire progressivamente il saldo active del pool.<sup>[[1]](#references)</sup>

Riga vulnerabile semplificata (e fix del post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist di hunting

- Il pool utilizza un indirizzo hooks diverso da zero? Quali callback sono abilitati?
- Sono presenti redistribuzioni/ribilanciamenti per-swap che utilizzano custom math? È presente una logica basata su tick/soglie?
- Dove vengono utilizzati divisioni/mulDiv, conversioni Q64.96 o SafeCast? Le semantiche di arrotondamento sono coerenti globalmente?
- È possibile costruire un Δin che oltrepassi appena una soglia e produca un ramo di arrotondamento favorevole? Testare entrambe le direzioni e sia exactInput sia exactOutput.
- L'hook tiene traccia di crediti o delta per-caller che possono essere ritirati successivamente? Assicurarsi che il residuo venga neutralizzato.

## References

- [1] [Analisi post-mortem dell'exploit di Bunni (settembre 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit di Bunni V2: analisi completa dell'hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit di Bunni V2: $8,3M drenati tramite una falla nella liquidità (riepilogo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper di Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contesto di Uniswap v4 (ricerca di QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Meccanismi della liquidità in Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Meccanismi degli swap in Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks di Uniswap v4 e considerazioni sulla sicurezza](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol di Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol di Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol di Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol di Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
