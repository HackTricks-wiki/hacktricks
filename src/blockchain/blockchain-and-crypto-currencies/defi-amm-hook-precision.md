# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una classe di tecniche di sfruttamento DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica core con custom hooks. Un incidente recente in Bunni V2 ha sfruttato una falla di arrotondamento/precisione in una Liquidity Distribution Function (LDF) eseguita ad ogni swap, permettendo all'attaccante di accumulare crediti positivi e prosciugare la liquidità.

Idea chiave: se un hook implementa contabilità aggiuntiva che dipende da matematica a punto fisso, arrotondamento di tick e logica basata su soglie, un attaccante può costruire swap exactInput precisi che attraversano soglie specifiche in modo che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo il pattern e poi ritirando il saldo gonfiato si realizza il profitto, spesso finanziato con un flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks sono contratti che il PoolManager chiama in punti specifici del ciclo di vita (es. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools sono inizializzati con un PoolKey che include hooks address. Se non‑zero, PoolManager esegue callback ad ogni operazione rilevante.
- La matematica core usa formati a punto fisso come Q64.96 per sqrtPriceX96 e aritmetica dei tick con 1.0001^tick. Qualsiasi matematica custom sovrapposta deve attentamente rispettare le semantiche di arrotondamento per evitare drift degli invarianti.
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si muove lungo i tick; attraversare un confine di tick può attivare/disattivare la liquidity di range. Gli hook possono implementare logiche extra su crossing di soglie/tick.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Un pattern tipico vulnerabile negli hook custom:

1. L'hook calcola delta di liquidity o di balance per swap usando integer division, mulDiv, o conversioni a punto fisso (es. token ↔ liquidity usando sqrtPrice e tick ranges).
2. La logica di soglia (es. rebalancing, redistribuzione stepwise, o attivazione per range) viene attivata quando la dimensione dello swap o lo spostamento di prezzo oltrepassa un confine interno.
3. L'arrotondamento viene applicato in modo incoerente (es. troncamento verso zero, floor vs ceil) tra il calcolo forward e il percorso di settlement. Piccole discrepanze non si annullano e invece accreditano il caller.
4. Swap exactInput, dimensionati con precisione per straddlare quei confini, raccolgono ripetutamente il resto di arrotondamento positivo. L'attaccante poi ritira il credito accumulato.

Precondizioni per l'attacco
- Un pool che usa un custom v4 hook che esegue matematica aggiuntiva ad ogni swap (es. una LDF/rebalancer).
- Almeno un percorso di esecuzione dove l'arrotondamento favorisce lo swap initiator attraverso crossing di soglie.
- Capacità di ripetere molti swap in modo atomico (i flash loans sono ideali per fornire float temporaneo e ammortizzare il gas).

## Practical attack methodology

1) Identificare pool candidati con hooks
- Enumerare v4 pools e verificare PoolKey.hooks != address(0).
- Ispezionare hook bytecode/ABI per callbacks: beforeSwap/afterSwap e qualsiasi metodo custom di rebalancing.
- Cercare matematica che: divide per liquidity, converte tra token amounts e liquidity, o aggrega BalanceDelta con arrotondamento.

2) Modellare la matematica e le soglie dell'hook
- Ricreare la formula di liquidity/redistribution dell'hook: gli input tipici includono sqrtPriceX96, tickLower/Upper, currentTick, fee tier, e net liquidity.
- Mappare funzioni di soglia/step: ticks, bucket boundaries, o LDF breakpoints. Determinare da quale lato di ogni confine il delta viene arrotondato.
- Identificare dove le conversioni castano tra uint256/int256, usano SafeCast, o fanno affidamento su mulDiv con floor implicito.

3) Tarare swap exact‑input per attraversare i confini
- Usare Foundry/Hardhat simulations per calcolare il Δin minimo necessario a spostare il prezzo appena oltre un confine e triggerare il branch dell'hook.
- Verificare che il settlement afterSwap accrediti il caller più del costo, lasciando un BalanceDelta positivo o un credito nella contabilità dell'hook.
- Ripetere gli swap per accumulare credito; poi chiamare il percorso di withdrawal/settlement dell'hook.

Example Foundry‑style test harness (pseudocode)
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
- Calcola ΔsqrtP per un passo di tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approssima Δin usando le formule v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Assicurati che la direzione di arrotondamento corrisponda alla matematica core.
- Regola Δin di ±1 wei attorno al confine per trovare il ramo in cui l'hook arrotonda a tuo favore.

4) Amplifica con flash loans
- Prendi in prestito un grande nozionale (es., 3M USDT o 2000 WETH) per eseguire molte iterazioni in modo atomico.
- Esegui il loop di swap calibrato, poi preleva e ripaga all'interno del flash loan callback.

Aave V3 flash loan skeleton
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
5) Exit e replicazione cross‑chain
- Se gli hook sono distribuiti su più catene, ripeti la stessa calibrazione per ciascuna catena.
- I proventi del bridge vengono riportati alla chain di destinazione e opzionalmente si cicla tramite protocolli di prestito per offuscare i flussi.

## Cause comuni nella matematica degli hook

- Semantiche di arrotondamento miste: mulDiv esegue floor mentre percorsi successivi arrotondano per eccesso; o le conversioni tra token e liquidità applicano arrotondamenti differenti.
- Errori di allineamento dei tick: uso di tick non arrotondati in un percorso e arrotondamento a spazi di tick in un altro.
- Problemi di segno/overflow di BalanceDelta quando si converte tra int256 e uint256 durante il settlement.
- Perdita di precisione nelle conversioni Q64.96 (sqrtPriceX96) non rispecchiata nella mappatura inversa.
- Percorsi di accumulo: i residui per swap vengono tracciati come crediti prelevabili dal caller invece di essere bruciati/azzerati.

## Linee guida difensive

- Test differenziale: confronta la matematica dell'hook con un'implementazione di riferimento usando aritmetica razionale ad alta precisione e asserisci uguaglianza o un errore limitato che sia sempre avverso (mai favorevole al caller).
- Test di invarianti/proprietà:
- La somma dei delta (token, liquidità) attraverso i percorsi di swap e gli aggiustamenti degli hook deve conservare valore modulo le fee.
- Nessun percorso dovrebbe creare un credito netto positivo per l'iniziatore dello swap su ripetute iterazioni exactInput.
- Test sui limiti/threshold dei tick attorno a input di ±1 wei sia per exactInput che per exactOutput.
- Policy di arrotondamento: centralizza helper di arrotondamento che arrotondano sempre contro l'utente; elimina cast incoerenti e floor impliciti.
- Destinazioni di settlement: accumula i residui di arrotondamento inevitabili nella tesoreria del protocollo o bruciali; non attribuirli mai a msg.sender.
- Rate‑limit/guardrails: dimensione minima degli swap per trigger di rebalancing; disabilita i rebalances se i delta sono sub‑wei; sanity‑check dei delta rispetto ai range attesi.
- Revisiona i callback degli hook in modo olistico: beforeSwap/afterSwap e before/after dei cambi di liquidità devono concordare sull'allineamento dei tick e sull'arrotondamento dei delta.

## Caso di studio: Bunni V2 (2025‑09‑02)

- Protocollo: Bunni V2 (Uniswap v4 hook) con una LDF applicata per swap per ribilanciare.
- Causa principale: errore di arrotondamento/precisione nella contabilizzazione della liquidità LDF durante swap che attraversano soglie; discrepanze per swap accumulate come crediti positivi per il caller.
- Gamba Ethereum: l'attacker ha preso un flash loan di ~3M USDT, eseguito swap exact‑input calibrati su USDC/USDT per accumulare crediti, prelevato saldi gonfiati, rimborsato e instradato i fondi via Aave.
- Gamba UniChain: ha ripetuto l'exploit con un flash loan di 2000 WETH, sottraendo ~1366 WETH e trasferendo su Ethereum tramite bridge.
- Impatto: circa USD 8.3M drenati attraverso le chain. Nessuna interazione utente richiesta; completamente on‑chain.

## Checklist per la ricerca

- Il pool usa un indirizzo hooks non‑zero? Quali callback sono abilitati?
- Ci sono redistribuzioni/rebalances per swap che usano matematiche custom? Qualche logica di tick/soglie?
- Dove sono usate divisioni/mulDiv, conversioni Q64.96, o SafeCast? Le semantiche di arrotondamento sono coerenti globalmente?
- Puoi costruire un Δin che appena oltrepassa un confine e provoca un ramo di arrotondamento favorevole? Testa entrambe le direzioni e sia exactInput che exactOutput.
- L'hook traccia crediti o delta per caller che possono essere prelevati successivamente? Assicurati che il residuo sia neutralizzato.

## Riferimenti

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
