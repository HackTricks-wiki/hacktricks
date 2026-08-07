# Sfruttamento DeFi/AMM: abuso della precisione e dell’arrotondamento degli hook di Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una classe di tecniche di exploitation DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica core con hook personalizzati. Un incidente recente in Bunni V2 ha sfruttato un difetto di arrotondamento/precisione in una Liquidity Distribution Function (LDF) eseguita a ogni swap, consentendo all’attaccante di accumulare crediti positivi e drenare liquidità.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

L’idea chiave è la seguente: se un hook implementa un accounting aggiuntivo che dipende da matematica fixed-point, arrotondamento dei tick e logica basata su soglie, un attaccante può creare swap exact-input che attraversano soglie specifiche, facendo sì che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo il pattern e ritirando successivamente il saldo gonfiato, si realizza un profitto, spesso finanziato tramite un flash loan.

## Background: hook di Uniswap v4 e flusso degli swap

- Gli hook sono contratti che il PoolManager chiama in specifici punti del ciclo di vita (ad esempio beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- I pool vengono inizializzati con una PoolKey che include l’indirizzo degli hook. Se è diverso da zero, PoolManager esegue callback per ogni operazione rilevante.<sup>[[6]](#references)</sup>
- Gli hook possono restituire **custom deltas** che modificano le variazioni finali del saldo di uno swap o di un’operazione di liquidità (custom accounting). Questi delta vengono regolati come saldi netti al termine della chiamata, quindi qualsiasi errore di arrotondamento nella matematica dell’hook si accumula prima del settlement.<sup>[[5]](#references)</sup>
- La matematica core utilizza formati fixed-point come Q64.96 per sqrtPriceX96 e l’aritmetica dei tick con 1.0001^tick. Qualsiasi matematica personalizzata applicata sopra di essa deve replicare attentamente la semantica di arrotondamento per evitare un drift dell’invariante.<sup>[[4]](#references)[[8]](#references)</sup>
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si muove lungo i tick; l’attraversamento di un confine di tick può attivare/disattivare la liquidità di un range. Gli hook possono implementare logica aggiuntiva al superamento di soglie/tick.<sup>[[5]](#references)</sup>

## Archetype della vulnerabilità: drift di precisione/arrotondamento durante il superamento di soglie

Un pattern tipicamente vulnerabile negli hook personalizzati:

1. L’hook calcola delta di liquidità o di saldo per ogni swap usando divisione intera, mulDiv o conversioni fixed-point (ad esempio, da token a liquidità usando sqrtPrice e i range dei tick).
2. La logica delle soglie (ad esempio, rebalancing, redistribuzione a step o attivazione per range) viene attivata quando la dimensione dello swap o il movimento del prezzo attraversa un confine interno.
3. L’arrotondamento viene applicato in modo incoerente (ad esempio, troncamento verso zero, floor invece di ceil) tra il calcolo forward e il percorso di settlement. Le piccole discrepanze non si annullano e accreditano invece il chiamante.
4. Gli swap exact-input, dimensionati precisamente per attraversare tali confini, raccolgono ripetutamente il resto positivo dell’arrotondamento. L’attaccante ritira in seguito il credito accumulato.

Prerequisiti dell’attacco
- Un pool che utilizza un hook v4 personalizzato e che esegue matematica aggiuntiva a ogni swap (ad esempio, un LDF/rebalancer).
- Almeno un percorso di esecuzione in cui l’arrotondamento favorisce l’iniziatore dello swap durante il superamento delle soglie.
- Possibilità di ripetere molti swap in modo atomico (i flash loan sono ideali per fornire liquidità temporanea e ammortizzare il gas).

## Metodologia pratica dell’attacco

1) Identificare i pool candidati con hook
- Enumerare i pool v4 e verificare che PoolKey.hooks != address(0).
- Esaminare bytecode/ABI dell’hook alla ricerca delle callback: beforeSwap/afterSwap e di eventuali metodi personalizzati di rebalancing.
- Cercare matematica che: divida per la liquidità, converta tra quantità di token e liquidità oppure aggreghi BalanceDelta con arrotondamento.

2) Modellare la matematica e le soglie dell’hook
- Ricreare la formula di liquidità/redistribuzione dell’hook: gli input includono tipicamente sqrtPriceX96, tickLower/Upper, currentTick, il fee tier e la liquidità netta.
- Mappare le funzioni a soglia/step: tick, confini dei bucket o breakpoint dell’LDF. Determinare su quale lato di ogni confine viene applicato l’arrotondamento al delta.
- Identificare i punti in cui le conversioni eseguono cast tra uint256/int256, utilizzano SafeCast o si affidano a mulDiv con floor implicito.

3) Calibrare gli swap exact-input per attraversare i confini
- Utilizzare simulazioni Foundry/Hardhat per calcolare il Δin minimo necessario a spostare il prezzo appena oltre un confine e attivare il branch dell’hook.
- Verificare che il settlement afterSwap accrediti al chiamante più del costo, lasciando un BalanceDelta positivo o un credito nell’accounting dell’hook.
- Ripetere gli swap per accumulare credito; quindi chiamare il percorso di withdrawal/settlement dell’hook.

Esempio di test harness in stile Foundry (pseudocodice)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: address(bunniHook)
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
for (uint i; i < N; ++i) {
pm.swap(
key,
IPoolManager.SwapParams({
zeroForOne: true,
amountSpecified: int256(exactIn), // exactInput
sqrtPriceLimitX96: 0 // allow tick crossing
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Calibrazione di exactInput
- Calcola ΔsqrtP per un tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approssima Δin usando le formule v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Assicurati che la direzione dell'arrotondamento corrisponda alla core math.
- Modifica Δin di ±1 wei intorno al boundary per trovare il branch in cui l'hook arrotonda a tuo vantaggio.

4) Amplifica con flash loans
- Prendi in prestito un notional elevato (ad esempio, 3M USDT o 2000 WETH) per eseguire molte iterazioni in modo atomico.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Esegui il loop di swap calibrato, quindi preleva e rimborsa all'interno del callback del flash loan.

Struttura di flash loan di Aave V3
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
- Se gli hooks sono distribuiti su più chain, ripetere la stessa calibrazione per ogni chain.
- Eseguire il bridge dei proventi verso la chain target e, facoltativamente, effettuare cicli tramite protocolli di lending per offuscare i flussi.<sup>[[2]](#references)</sup>

## Cause principali comuni nella matematica degli hooks

- Semantiche di rounding miste: `mulDiv` esegue il floor mentre i percorsi successivi effettuano di fatto un round up; oppure le conversioni tra token/liquidità applicano rounding diversi.
- Errori di allineamento dei tick: utilizzo di tick non arrotondati in un percorso e di un rounding basato sul tick spacing in un altro.
- Problemi di segno/overflow di `BalanceDelta` durante la conversione tra `int256` e `uint256` in fase di settlement.
- Perdita di precisione nelle conversioni Q64.96 (`sqrtPriceX96`) non replicata nella mappatura inversa.
- Percorsi di accumulo: i resti per swap vengono tracciati come crediti prelevabili dal caller invece di essere bruciati o inclusi in un bilancio zero-sum.

## Custom accounting e amplificazione dei delta

- Il custom accounting di Uniswap v4 consente agli hooks di restituire delta che modificano direttamente quanto il caller deve o riceve. Se l’hook tiene traccia internamente dei crediti, il residuo di rounding può accumularsi attraverso molte operazioni di piccola entità **prima** che avvenga il settlement finale.<sup>[[5]](#references)</sup>
- Questo rende più efficace l’abuso dei boundary/threshold: l’attacker può alternare `swap → withdraw → swap` nella stessa tx, obbligando l’hook a ricalcolare i delta su uno stato leggermente diverso mentre tutti i saldi sono ancora pending.
- Durante la revisione degli hooks, tracciare sempre come `BalanceDelta`/`HookDelta` viene prodotto e sottoposto a settlement. Un singolo rounding distorto in un ramo può trasformarsi in un credito cumulativo quando i delta vengono ricalcolati ripetutamente.

## Indicazioni difensive

- Differential testing: confrontare la matematica dell’hook con un’implementazione di riferimento che utilizzi aritmetica razionale ad alta precisione e verificare l’uguaglianza o un errore limitato che sia sempre avverso (mai favorevole al caller).
- Test di invarianti/proprietà:
- La somma dei delta (token, liquidità) lungo i percorsi di swap e le modifiche dell’hook deve conservare il valore, al netto delle fee.
- Nessun percorso deve creare un credito netto positivo per l’iniziatore dello swap attraverso iterazioni ripetute di `exactInput`.
- Test dei threshold/boundary dei tick intorno a input di ±1 wei sia per `exactInput` sia per `exactOutput`.
- Politica di rounding: centralizzare gli helper di rounding in modo che arrotondino sempre contro l’utente; eliminare cast incoerenti e floor impliciti.
- Settlement sinks: accumulare il residuo inevitabile del rounding nella tesoreria del protocollo o bruciarlo; non attribuirlo mai a `msg.sender`.
- Rate-limits/guardrail: dimensioni minime degli swap per i trigger di rebalancing; disabilitare i rebalancing se i delta sono inferiori a un wei; verificare la plausibilità dei delta rispetto agli intervalli attesi.
- Esaminare olisticamente le callback dell’hook: `beforeSwap`/`afterSwap` e le modifiche alla liquidità `before`/`after` devono essere coerenti sull’allineamento dei tick e sul rounding dei delta.

## Case study: Bunni V2 (2025-09-02)

- Protocollo: Bunni V2 (Uniswap v4 hook) con un LDF applicato per swap per effettuare il rebalancing.<sup>[[7]](#references)</sup>
- Pool interessati: USDC/USDT su Ethereum e weETH/ETH su Unichain, per un totale di circa 8,4 milioni di dollari.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): l’attacker ha preso in prestito tramite flash loan circa 3 milioni di USDT ed eseguito uno swap per spingere il tick a circa 5000, riducendo il saldo USDC **attivo** a circa 28 wei.<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44 prelievi di piccola entità hanno sfruttato il floor rounding in `BunniHubLogic::withdraw()` per ridurre il saldo USDC attivo da 28 wei a 4 wei (-85,7%), mentre veniva bruciata solo una frazione minima delle quote LP. La liquidità totale è stata sottostimata di circa l’84,4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): un large swap ha spostato il tick a circa 839.189 (1 USDC ≈ 2,77e36 USDT). Le stime della liquidità si sono invertite e sono aumentate di circa il 16,8%, consentendo un sandwich in cui l’attacker ha eseguito lo swap inverso al prezzo gonfiato e ha chiuso l’operazione in profitto.<sup>[[7]](#references)</sup>
- Correzione identificata nel post-mortem: modificare l’aggiornamento del saldo idle in modo che arrotondi **per eccesso**, così che i micro-prelievi ripetuti non possano ridurre progressivamente il saldo attivo della pool.<sup>[[7]](#references)</sup>

Riga vulnerabile semplificata (e correzione del post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist di hunting

- Il pool usa un hooks address non-zero? Quali callback sono abilitate?
- Sono presenti redistribuzioni/rebalance per-swap che usano custom math? È presente una logica basata su tick/threshold?
- Dove vengono usati division, mulDiv, conversioni Q64.96 o SafeCast? Le semantiche di rounding sono coerenti globalmente?
- È possibile costruire un Δin che superi appena una boundary e produca un rounding branch favorevole? Testare entrambe le direzioni e sia exactInput sia exactOutput.
- L'hook tiene traccia di crediti o delta per-caller che possono essere ritirati in seguito? Assicurarsi che il residuo venga neutralizzato.

## Riferimenti

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (riepilogo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Analisi completa dell'hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Contesto di Uniswap v4 (ricerca di QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Meccaniche della liquidità nel core di Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Meccaniche degli swap nel core di Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks e considerazioni di sicurezza](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Post Mortem dell'exploit di Bunni (set 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Whitepaper del core di Uniswap v4](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
