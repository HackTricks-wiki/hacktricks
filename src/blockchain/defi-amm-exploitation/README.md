# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

This page documents a class of DeFi/AMM exploitation techniques against Uniswap v4–style DEXes that extend core math with custom hooks. A recent incident in Bunni V2 leveraged a rounding/precision flaw in a Liquidity Distribution Function (LDF) executed on each swap, enabling the attacker to accrue positive credits and drain liquidity.

Key idea: if a hook implements additional accounting that depends on fixed‑point math, tick rounding, and threshold logic, an attacker can craft exact‑input swaps that cross specific thresholds so that rounding discrepancies accumulate in their favor. Repeating the pattern and then withdrawing the inflated balance realizes profit, often financed with a flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks are contracts that the PoolManager calls at specific lifecycle points (e.g., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools are initialized with a PoolKey including hooks address. If non‑zero, PoolManager performs callbacks on every relevant operation.
- Core math uses fixed‑point formats such as Q64.96 for sqrtPriceX96 and tick arithmetic with 1.0001^tick. Any custom math layered on top must carefully match rounding semantics to avoid invariant drift.
- Swaps can be exactInput or exactOutput. In v3/v4, price moves along ticks; crossing a tick boundary may activate/deactivate range liquidity. Hooks may implement extra logic on threshold/tick crossings.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

A typical vulnerable pattern in custom hooks:

1. The hook computes per‑swap liquidity or balance deltas using integer division, mulDiv, or fixed‑point conversions (e.g., token ↔ liquidity using sqrtPrice and tick ranges).
2. Threshold logic (e.g., rebalancing, stepwise redistribution, or per‑range activation) is triggered when a swap size or price movement crosses an internal boundary.
3. Rounding is applied inconsistently (e.g., truncation toward zero, floor versus ceil) between the forward calculation and the settlement path. Small discrepancies don’t cancel and instead credit the caller.
4. Exact‑input swaps, precisely sized to straddle those boundaries, repeatedly harvest the positive rounding remainder. The attacker later withdraws the accumulated credit.

Attack preconditions
- A pool using a custom v4 hook that performs additional math on each swap (e.g., an LDF/rebalancer). 
- At least one execution path where rounding benefits the swap initiator across threshold crossings.
- Ability to repeat many swaps atomically (flash loans are ideal to supply temporary float and amortize gas). 

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerate v4 pools and check PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI for callbacks: beforeSwap/afterSwap and any custom rebalancing methods.
- Look for math that: divides by liquidity, converts between token amounts and liquidity, or aggregates BalanceDelta with rounding.

2) Model the hook’s math and thresholds
- Recreate the hook’s liquidity/redistribution formula: inputs typically include sqrtPriceX96, tickLower/Upper, currentTick, fee tier, and net liquidity.
- Map threshold/step functions: ticks, bucket boundaries, or LDF breakpoints. Determine which side of each boundary the delta is rounded on.
- Identify where conversions cast between uint256/int256, use SafeCast, or rely on mulDiv with implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Use Foundry/Hardhat simulations to compute the minimal Δin needed to move price just across a boundary and trigger the hook’s branch.
- Verify that afterSwap settlement credits the caller more than the cost, leaving a positive BalanceDelta or credit in the hook’s accounting.
- Repeat swaps to accumulate credit; then call the hook’s withdrawal/settlement path.

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

Calibrating the exactInput
- Compute ΔsqrtP for a tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximate Δin using v3/v4 formulas: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Ensure rounding direction matches core math.
- Adjust Δin by ±1 wei around the boundary to find the branch where the hook rounds in your favor.

4) Amplify with flash loans
- Borrow a large notional (e.g., 3M USDT or 2000 WETH) to run many iterations atomically.
- Execute the calibrated swap loop, then withdraw and repay within the flash loan callback.

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

5) Exit and cross‑chain replication
- If hooks are deployed on multiple chains, repeat the same calibration per chain.
- Bridge proceeds back to the target chain and optionally cycle via lending protocols to obfuscate flows.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Defensive guidance

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
  - Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
  - No path should create positive net credit for the swap initiator over repeated exactInput iterations.
  - Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Hunting checklist

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
