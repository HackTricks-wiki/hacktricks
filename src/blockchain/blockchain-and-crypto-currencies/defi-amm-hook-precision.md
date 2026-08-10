# Exploitation di DeFi/AMM: abuso della precisione dell'hook e degli arrotondamenti in Uniswap v4

Questa pagina documenta una classe di tecniche di exploitation DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica del core con custom hook. Un incidente Bunni V2 illustra un errore correlato: un bug nella direzione dell'arrotondamento durante la contabilizzazione dei prelievi sottostimava la liquidità attiva, e uno swap successivo ha esposto tale sottostima in un sandwich redditizio.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idea chiave: se un hook implementa una contabilizzazione aggiuntiva che dipende dalla fixed-point math, dall'arrotondamento dei tick e dalla logica basata su soglie, un attaccante può creare swap exact-input che attraversano soglie specifiche, facendo sì che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo il pattern e prelevando successivamente il balance maggiorato, si realizza un profitto, spesso finanziato con un flash loan.

## Background: hook e flusso degli swap di Uniswap v4

- Gli hook sono contratti che il PoolManager chiama in specifici punti del lifecycle (ad es. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- I pool vengono inizializzati con una PoolKey che include il contratto dell'hook. Un hook address non nullo abilita le callback selezionate per quel pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Gli hook possono restituire **custom delta** che modificano le variazioni finali del balance di uno swap o di un'azione sulla liquidità (custom accounting). Questi delta vengono regolati come net balance alla fine della chiamata, quindi qualsiasi errore di arrotondamento nella matematica dell'hook si accumula prima del settlement.<sup>[[4]](#references)</sup>
- La matematica del core utilizza formati fixed-point come Q64.96 per sqrtPriceX96 e l'aritmetica dei tick con 1.0001^tick. Qualsiasi custom math sovrapposta deve corrispondere attentamente alle semantiche di arrotondamento per evitare un drift dell'invariante.<sup>[[12]](#references)[[13]](#references)</sup>
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si sposta lungo i tick; l'attraversamento di un tick boundary può attivare/disattivare la liquidità di un range. Gli hook possono implementare logiche aggiuntive sugli attraversamenti di soglie/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: drift di precisione/arrotondamento nell'attraversamento delle soglie

Un pattern tipicamente vulnerabile nei custom hook:

1. L'hook calcola i delta di liquidità o balance per ogni swap utilizzando la divisione intera, mulDiv o conversioni fixed-point (ad es., token ↔ liquidità utilizzando sqrtPrice e i range dei tick).
2. La logica delle soglie (ad es., rebalancing, redistribuzione stepwise o attivazione per range) viene attivata quando la dimensione dello swap o il movimento del prezzo attraversa un confine interno.
3. L'arrotondamento viene applicato in modo incoerente (ad es., troncamento verso zero, floor invece di ceil) tra il calcolo forward e il percorso di settlement. Le piccole discrepanze non si annullano e accreditano invece il caller.
4. Gli swap exact-input, dimensionati precisamente per attraversare tali confini, raccolgono ripetutamente il resto positivo dell'arrotondamento. L'attaccante preleva successivamente il credito accumulato.

Precondizioni dell'attacco
- Un pool che utilizza un custom v4 hook il quale esegue matematica aggiuntiva a ogni swap (ad es., un LDF/rebalancer).
- Almeno un execution path in cui l'arrotondamento favorisce l'iniziatore dello swap durante l'attraversamento delle soglie.
- Possibilità di ripetere molti swap atomically (i flash loan sono ideali per fornire liquidità temporanea e ammortizzare il gas).

## Metodologia pratica dell'attacco

1) Identificare i pool candidati con hook
- Enumerare i pool v4 e verificare che PoolKey.hooks != address(0).
- Ispezionare bytecode/ABI dell'hook alla ricerca delle callback: beforeSwap/afterSwap e di eventuali metodi di rebalancing custom.
- Cercare matematica che: divide per la liquidità, converte tra importi di token e liquidità o aggrega BalanceDelta con arrotondamento.

2) Modellare la matematica e le soglie dell'hook
- Ricreare la formula di liquidità/redistribuzione dell'hook: gli input includono tipicamente sqrtPriceX96, tickLower/Upper, currentTick, fee tier e liquidità netta.
- Mappare le funzioni threshold/step: tick, bucket boundary o breakpoint LDF. Determinare su quale lato di ogni confine viene arrotondato il delta.
- Identificare i punti in cui le conversioni eseguono cast tra uint256/int256, utilizzano SafeCast o si affidano a mulDiv con floor implicito.

3) Calibrare gli swap exact-input per attraversare i confini
- Utilizzare simulazioni Foundry/Hardhat per calcolare il Δin minimo necessario a spostare il prezzo appena oltre un confine e attivare il branch dell'hook.
- Verificare che il settlement afterSwap accrediti al caller più del costo, lasciando un BalanceDelta positivo o un credito nella contabilizzazione dell'hook.
- Ripetere gli swap per accumulare credito; quindi chiamare il percorso di withdrawal/settlement dell'hook.

In v4, il loop dello swap deve essere eseguito da una unlock callback del PoolManager; `amountSpecified` negativo indica exact input e `sqrtPriceLimitX96` deve trovarsi strettamente all'interno del range valido. Un price limit pari a zero causa un revert, quindi il pseudocode seguente utilizza il lower bound per uno swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Approssima un input token0 (zero-for-one) usando la formula compatibile con Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Applica l’arrotondamento specifico per la direzione della core routine.<sup>[[12]](#references)</sup>
- Modifica Δin di ±1 wei intorno al limite per trovare il branch in cui l’hook arrotonda a tuo favore.

4) Amplificare con flash loans
- Prendi in prestito un nozionale elevato (ad esempio, 3M USDT o 2000 WETH) per eseguire molte iterazioni atomically.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Esegui il loop di swap calibrato, quindi effettua il prelievo e il rimborso all’interno del callback del flash loan.

Scheletro del flash loan Aave V3
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
- Se gli hook sono distribuiti su più chain, ripetere la stessa calibrazione per ogni chain.
- Nell'incidente Bunni, la liquidità flash-loan e i percorsi bridge differivano per chain; tenere quindi conto di questi vincoli specifici della chain nel riprodurre l'analisi.<sup>[[1]](#references)[[2]](#references)</sup>

## Cause radice comuni nella matematica degli hook

- Semantiche di arrotondamento miste: `mulDiv` arrotonda per difetto mentre i percorsi successivi arrotondano di fatto per eccesso; oppure le conversioni tra token/liquidità applicano arrotondamenti diversi.
- Errori di allineamento dei tick: utilizzo di tick non arrotondati in un percorso e arrotondamento secondo la spaziatura dei tick in un altro.
- Problemi di segno/overflow di `BalanceDelta` durante la conversione tra `int256` e `uint256` in fase di settlement.
- Perdita di precisione nelle conversioni Q64.96 (`sqrtPriceX96`) non rispecchiata nella mappatura inversa.
- Percorsi di accumulo: resti per-swap tracciati come crediti prelevabili dal caller invece di essere eliminati o compensati a somma zero.

## Contabilità personalizzata e amplificazione dei delta

- La contabilità personalizzata di Uniswap v4 consente agli hook di restituire delta che modificano direttamente ciò che il caller deve o riceve. Se l'hook traccia internamente i crediti, il residuo di arrotondamento può accumularsi attraverso molte operazioni di piccola entità **prima** che avvenga il settlement finale.<sup>[[4]](#references)</sup>
- Se l'hook espone un percorso di prelievo compatibile, un attacker può alternare `swap → withdraw → swap` all'interno dello stesso callback di unlock del `PoolManager`, forzando l'hook a ricalcolare i delta su uno stato leggermente diverso mentre i saldi restano in sospeso fino al settlement dell'unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Durante la revisione degli hook, tracciare sempre come vengono prodotti e regolati `BalanceDelta`/`HookDelta`. Un singolo arrotondamento distorto in un ramo può trasformarsi in un credito cumulativo quando i delta vengono ricalcolati ripetutamente.

## Indicazioni difensive

- Differential testing: confrontare la matematica dell'hook con un'implementazione di riferimento usando aritmetica razionale ad alta precisione e asserire l'uguaglianza o un errore limitato che sia sempre avverso all'utente (mai favorevole al caller).
- Test di invarianti/proprietà:
- La somma dei delta (token, liquidità) lungo i percorsi di swap e le modifiche dell'hook deve conservare il valore al netto delle fee.
- Nessun percorso deve creare un credito netto positivo per l'iniziatore dello swap attraverso iterazioni ripetute di `exactInput`.
- Test dei limiti di soglia/tick attorno a input di ±1 wei per `exactInput`/`exactOutput`.
- Policy di arrotondamento: centralizzare gli helper di arrotondamento affinché arrotondino sempre a sfavore dell'utente; eliminare cast incoerenti e arrotondamenti per difetto impliciti.
- Destinazioni di settlement: accumulare il residuo di arrotondamento inevitabile nel tesoro del protocollo o eliminarlo tramite burn; non attribuirlo mai a `msg.sender`.
- Rate-limit/guardrail: dimensioni minime degli swap per i trigger di ribilanciamento; disabilitare i ribilanciamenti se i delta sono inferiori a un wei; verificare la coerenza dei delta rispetto agli intervalli attesi.
- Esaminare i callback degli hook in modo olistico: `beforeSwap`/`afterSwap` e le modifiche alla liquidità `before`/`after` devono concordare sull'allineamento dei tick e sull'arrotondamento dei delta.

## Caso di studio: Bunni V2 (2025-09-02)

- Protocollo: Bunni V2, un hook di Uniswap v4 che usa una Liquidity Density Function (LDF) per calcolare la densità dei token e le stime della liquidità totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pool interessati: USDC/USDT su Ethereum e weETH/ETH su Unichain, per un totale di circa 8,4 milioni di dollari.<sup>[[1]](#references)</sup>
- Step 1 (spinta del prezzo): l'attacker ha preso in prestito tramite flash-loan circa 3 milioni di USDT e ha eseguito uno swap per spingere il tick a circa 5000, riducendo il saldo **attivo** di USDC a circa 28 wei.<sup>[[1]](#references)</sup>
- Step 2 (drain tramite arrotondamento): 44 prelievi di piccola entità hanno sfruttato l'arrotondamento per difetto in `BunniHubLogic::withdraw()` per ridurre il saldo attivo di USDC da 28 wei a 4 wei (-85,7%), mentre veniva bruciata solo una frazione minima delle quote LP. La liquidità totale è diminuita di circa l'84,4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (sandwich del rimbalzo della liquidità): un large swap ha spostato il tick a circa 839.189 (1 USDC ≈ 2,77e36 USDT). Le stime della liquidità si sono invertite e sono aumentate di circa il 16,8%, consentendo un sandwich in cui l'attacker ha effettuato lo swap inverso al prezzo gonfiato ed è uscito con un profitto.<sup>[[1]](#references)</sup>
- Fix individuato nel post-mortem: modificare l'aggiornamento del saldo inattivo affinché arrotondi **per eccesso**, così che i micro-prelievi ripetuti non riducano progressivamente il saldo attivo del pool.<sup>[[1]](#references)</sup>

Riga vulnerabile semplificata (e fix del post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist di hunting

- Il pool utilizza un indirizzo hooks non nullo? Quali callback sono abilitate?
- Sono presenti redistribuzioni/ribilanciamenti per swap che utilizzano custom math? È presente una logica basata su tick/soglie?
- Dove vengono utilizzati divisioni/mulDiv, conversioni Q64.96 o SafeCast? Le semantiche di arrotondamento sono coerenti globalmente?
- È possibile costruire un Δin che superi appena una soglia e produca un rounding branch favorevole? Testare entrambe le direzioni e sia exactInput sia exactOutput.
- L'hook tiene traccia di crediti o delta per caller che possono essere ritirati successivamente? Assicurarsi che il residuo venga neutralizzato.

## References

- [1] [Analisi post-mortem dell'exploit Bunni (settembre 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit di Bunni V2: analisi completa dell'hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit di Bunni V2: 8,3 milioni di dollari sottratti tramite una falla nella liquidità (riepilogo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper di Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contesto di Uniswap v4 (ricerca di QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Meccanismi della liquidità nel core di Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Meccanismi degli swap nel core di Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks di Uniswap v4 e considerazioni sulla sicurezza](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol del core di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey di Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
