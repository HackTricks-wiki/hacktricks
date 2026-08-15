# Investment Terms

{{#include ../banners/hacktricks-training.md}}

## Spot

Spot trading exchanges an asset for immediate delivery. A limit order specifies the quantity and limit price; it executes only when the market can satisfy that price or better. A market order instead seeks prompt execution at the best prices then available and can experience slippage.<sup>[[4]](#references)</sup>

A stop-limit order has a stop price that activates a limit order. It can constrain the execution price, but it does not guarantee execution if the market moves through the limit.<sup>[[4]](#references)</sup>

## Futures

A futures contract is a standardized agreement to buy or sell a specified commodity or financial instrument at a future date. For example, two parties could agree on a price of $70,000 for one bitcoin with settlement in six months.<sup>[[1]](#references)</sup>

If the settlement price is $80,000, the long side gains and the short side loses relative to the $70,000 contract price. If it is $60,000, the direction is reversed. Actual exchange-traded futures are marked to market and usually closed or rolled before expiration, so this is a simplified illustration.<sup>[[2]](#references)</sup>

Producers and consumers use futures to hedge price risk; other participants use them to seek profit or provide liquidity.<sup>[[1]](#references)</sup>

- A **long position** generally profits when the contract price rises.
- A **short position** generally profits when the contract price falls.<sup>[[2]](#references)</sup>

### Hedging With Futures

If a fund manager expects a portfolio to fall, they might short a sufficiently correlated stock-index futures contract. Gains on the short hedge can offset some portfolio losses; basis risk means the offset is rarely exact. A bitcoin future would hedge bitcoin exposure, not automatically a stock portfolio.

If the hedged market falls, the short futures position may gain while the holdings lose value. If it rises, the holdings may gain while the hedge loses. Hedging reduces selected risk rather than creating a guaranteed profit.<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual contracts are derivatives without a fixed expiration date. Crypto venues commonly use periodic funding payments to help keep their price near the underlying spot price; terms differ by venue.<sup>[[3]](#references)</sup>

Profit and loss changes as the mark price moves. A 1% price move produces approximately a 1% move on the position's notional value before fees and funding, but leverage can make that a much larger percentage of posted collateral.

### Futures with Leverage

**Leverage** allows a trader to control a larger notional position with a smaller margin deposit. Losses are not always limited to the initial margin: liquidation, gaps, fees, and venue rules can produce additional losses.<sup>[[3]](#references)</sup>

For example, $100 of margin at 50x leverage controls a $5,000 position. Ignoring fees, funding, and liquidation mechanics, a favorable 1% move produces a $50 gain (50% of the initial margin), while an adverse 1% move produces a $50 loss. An adverse 2% move corresponds to $100, although a venue will normally liquidate the position before all margin is exhausted.

Leverage magnifies both gains and losses and makes liquidation possible after a comparatively small adverse move.

## Differences Between Futures and Options

An option buyer receives a right, not an obligation, to exercise under the contract terms. The option writer has the corresponding obligation if the buyer exercises. The buyer pays the writer a premium for that right.<sup>[[4]](#references)</sup>

### 1. **Obligation vs. Right:**

* **Futures:** When you buy or sell a futures contract, you're entering a **binding agreement** to buy or sell an asset at a specific price on a future date. Both the buyer and the seller are **obligated** to fulfill the contract at expiration (unless the contract is closed before then).
* **Options:** With options, you have the **right, but not the obligation**, to buy (in the case of a **call option**) or sell (in the case of a **put option**) an asset at a specific price before or at a certain expiration date. The **buyer** has the option to execute, while the **seller** is obligated to fulfill the trade if the buyer decides to exercise the option.

### 2. **Risk:**

* **Futures:** Both sides can suffer substantial losses. Whether loss is mathematically unlimited depends on the position and underlying asset: a short position may have unbounded theoretical loss, while a long position cannot lose more than the notional value if the underlying cannot fall below zero.
* **Options:** A buyer who does not write another option generally risks the premium paid. A naked call writer may face theoretically unlimited loss; other option-writing strategies have different bounded or unbounded risk profiles.

### 3. **Cost:**

* **Futures:** There is no upfront cost beyond the margin required to hold the position, as the buyer and seller are both obligated to complete the trade.
* **Options:** The buyer must pay an **option premium** upfront for the right to exercise the option. This premium is essentially the cost of the option.

### 4. **Profit Potential:**

* **Futures:** The profit or loss is based on the difference between the market price at expiration and the agreed-upon price in the contract.
* **Options:** The buyer profits when the market moves favorably beyond the strike price by more than the premium paid. The seller profits by keeping the premium if the option is not exercised.

## References

- [1] [CFTC - The economic purpose of futures markets](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Futures Market Basics](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Understand the risks of virtual-currency trading](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Option, premium, and exercise](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)

{{#include ../banners/hacktricks-training.md}}
