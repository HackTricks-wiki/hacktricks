# Blockchain & Crypto Currencies

## Basic Terminology

* **Smart contract**: Smart contracts are simply **programs stored on a blockchain that run when predetermined conditions are met**. They typically are used to automate the **execution** of an **agreement** so that all participants can be immediately certain of the outcome, without any intermediary’s involvement or time loss. (From [here](https://www.ibm.com/topics/smart-contracts)).
  * Basically, a smart contract is a **piece of code** that is going to be executed when people access and accept the contract. Smart contracts **run in blockchains** (so the results are stored inmutable) and can be read by the people before accepting them.
* **dApps**: **Decentralised applications** are implemented on top of **smart** **contracts**. They usually have a front-end where the user can interact with the app, the **back-end** is public (so it can be audited) and is implemented as a **smart contract**. Sometimes the use of a database is needed, Ethereum blockchain allocates certain storage to each account.
* **Tokens & coins**: A **coin** is a cryptocurrency that act as **digital** **money** and a **token** is something that **represents **some **value** but it's not a coin.
  * **Utility Tokens**: These tokens allow the user to** access certain service later** (it's something that have some value in a specific environment).
  * **Security Tokens**: These represents the **ownership** or some asset.
* **DeFi**: **Decentralized Finance**.
* **DEX: Decentralized Exchange Platforms**.
* **DAOs**: **Decentralized Autonomous Organizations**.

## Consensus Mechanisms

For a blockchain transaction to be recognized, it must be **appended** to the **blockchain**. Validators (miners) carry out this appending; in most protocols, they **receive a reward** for doing so. For the blockchain to remain secure, it must have a mechanism to **prevent a malicious user or group from taking over a majority of validation**. 

Proof of work, another commonly used consensus mechanism, uses a validation of computational prowess to verify transactions, requiring a potential attacker to acquire a large fraction of the computational power of the validator network.

### Proof Of Work (PoW)

This uses a **validation of computational prowess** to verify transactions, requiring a potential attacker to acquire a large fraction of the computational power of the validator network.\
The **miners** will **select several transactions** and then start **computing the Proof Of Work**. The **miner with the greatest computation resources** is more probably to **finish** **earlier** the Proof of Work and get the fees of all the transactions.

### Proof Of Stake (PoS)

PoS accomplishes this by **requiring that validators have some quantity of blockchain tokens**, requiring **potential attackers to acquire a large fraction of the tokens **on the blockchain to mount an attack.\
In this kind of consensus, the more tokens a miner has, the more probably it will be that the miner will be asked to create the next block.\
Compared with PoW, this greatly **reduced the energy consumption **the miners are expending.

## Bitcoin

### Transactions

A simple **transaction** is a **movement of money** from an address to another one.\
An **address** in bitcoin is the hash of the **public** **key**, therefore, someone in order to make a transaction from an address he needs to know the private key associated to that public key (the address).\
Then, when a **transaction** is performed, it's **signed** with the private key of the address to show that the transaction is **legit**.

The first part of producing a digital signature in Bitcoin can be represented mathematically in the following way:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Where:

* _d_A is the signing **private key**
* _m_ is the **transaction**
* Fhash is the hashing function
* Fsig is the signing algorithm
* Sig is the resulting signature

The signing function (Fsig) produces a signature (Sig) that comprises of two values: R and S:

* Sig = (R, S)

Once R and S have been calculated, they are serialized into a byte stream that is encoded using an international standard encoding scheme that is known as the Distinguished Encoding Rules (or DER). In order to verify that the signature is valid, a signature verification algorithm is used. Verification of a digital signature requires the following:

* Signature (R and S)
* Transaction hash
* The public key that corresponds to the private key that was used to create the signature

Verification of a signature effectively means that only the owner of the private key (that generated the public key) could have produced the signature on the transaction. The signature verification algorithm will return ‘TRUE’ if the signature is indeed valid.

#### Multisignature Transactions

A multi-signature **address** is an address that is associated with more than one ECDSA private key. The simplest type is an m-of-n address - it is associated with n private keys, and sending bitcoins from this address requires signatures from at least m keys. A multi-signature **transaction** is one that sends funds from a multi-signature address.

#### Transactions Fields

Each bitcoin transaction has several fields:

* **Inputs**: The amount and address **from** where **bitcoins** are **being** transferred
* **Outputs**: The address and amounts that each **transferred** to **each** **output**
* **Fee: **The amount of **money** that is **payed** to the **miner** of the transaction
* **Script_sig**: Script signature of the transaction
* **Script_type**: Type of transaction

There are **2 main types** of transactions:

* **P2PKH: "Pay To Public Key Hash"**: This is how transactions are made. You are requiring the **sender** to supply a valid **signature** (from the private key) and **public** **key**. The transaction output script will use the signature and public key and through some cryptographic functions will check **if it matches** with the public key hash, if it does, then the **funds** will be **spendable**. This method conceals your public key in the form of a hash for extra security.
* **P2SH: "Pay To Script Hash": **The outputs of a transaction are just **scripts **(this means the person how want this money send a script) that, if are **executed with specific parameters, will result in a boolean of `true` or `false`**. If a miner runs the output script with the supplied parameters and results in `true`, the **money will be sent to your desired output**. `P2SH` is used for **multi-signature** wallets making the output scripts** logic that checks for multiple signatures before accepting the transaction**. `P2SH` can also be used to allow anyone, or no one, to spend the funds. If the output script of a P2SH transaction is just `1` for true, then attempting to spend the output without supplying parameters will just result in `1` making the money spendable by anyone who tries. This also applies to scripts that return `0`, making the output spendable by no one.

### Lightning Network

This protocol helps to **perform several transactions to a channe**l and **just** **sent** the **final** **state** to the blockchain to save it.\
This **improves** bitcoin blockchain **speed** (it just on allow 7 payments per second) and it allows to create **transactions more difficult to trace** as the channel is created via nodes of the bitcoin blockchain:

![](<../.gitbook/assets/image (611).png>)

Normal use of the Lightning Network consists of **opening a payment channel** by committing a funding transaction to the relevant base blockchain (layer 1), followed by making** any number **of Lightning Network **transactions** that update the tentative distribution of the channel's funds **without broadcasting those to the blockchain**, optionally followed by closing the payment channel by **broadcasting** the **final** **version** of the settlement transaction to distribute the channel's funds.

Note that any of the both members of the channel can stop and send the final state of the channel to the blockchain at any time.

## Bitcoin Privacy Attacks

### Common Input

Theoretically the inputs of one transaction can belong to different users, but in reality that is unusual as it requires extra steps. Therefore, very often it can be assumed that **2 input addresses in the same transaction belongs to the same owner**.

### UTXO Change Address Detection

**UTXO** means** Unspent Transaction Outputs** (UTXOs). In a transaction that uses the output from a previous transaction as an input, the **whole output need to be spent** (to avoid double-spend attacks). Therefore, if the intention was to **send** just **part** of the money from that output to an address and **keep** the **other** **part**,** 2 different outputs **will appear: the **intended** one and a **random new change address** where the rest of the money will be saved.

Then, a watcher can make the assumption that **the new change address generated belong to the owner of the UTXO**.

### Social Networks & Forums

Some people gives data about theirs bitcoin addresses in different webs on Internet. **This make pretty easy to identify the owner of an address**.

### Transaction Graphs

By representing the transactions in graphs, i**t's possible to know with certain probability to where the money of an account were**. Therefore, it's possible to know something about **users** that are **related** in the blockchain. 

### **Unnecessary input heuristic**

Also called the "optimal change heuristic". Consider this bitcoin transaction. It has two inputs worth 2 BTC and 3 BTC and two outputs worth 4 BTC and 1 BTC.

```
2 btc --> 4 btc
3 btc     1 btc
```

Assuming one of the outputs is change and the other output is the payment. There are two interpretations: the payment output is either the 4 BTC output or the 1 BTC output. But if the 1 BTC output is the payment amount then the 3 BTC input is unnecessary, as the wallet could have spent only the 2 BTC input and paid lower miner fees for doing so. This is an indication that the real payment output is 4 BTC and that 1 BTC is the change output.

This is an issue for transactions which have more than one input. One way to fix this leak is to add more inputs until the change output is higher than any input, for example:

```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```

### Forced address reuse

**Forced address reuse** or **incentivized address reuse** is when an adversary pays an (often small) amount of bitcoin to addresses that have already been used on the block chain. The adversary hopes that users or their wallet software **will use the payments as inputs to a larger transaction which will reveal other addresses via the the common-input-ownership** heuristic. These payments can be understood as a way to coerce the address owner into unintentional address reuse.

This attack is sometimes incorrectly called a **dust attack**.

The correct behaviour by wallets is to not spend coins that have landed on an already-used empty addresses.

### Other Blockchain Analysis

* **Exact Payment Amounts**: In order to avoid transactions with a change, the payment needs to be equal to the UTXO (which is highly unexpected). Therefore, a **transaction with no change address are probably transfer between 2 addresses of the same user**.
* **Round Numbers**: In a transaction, if one of the outputs is a "**round number**", it's highly probable that this is a **payment to a human that put that **"round number" **price**, so the other part must be the leftover.
* **Wallet fingerprinting: **A careful analyst sometimes deduce which software created a certain transaction, because the many **different wallet softwares don't always create transactions in exactly the same way**. Wallet fingerprinting can be used to detect change outputs because a change output is the one spent with the same wallet fingerprint.
* **Amount & Timing correlations**: If the person that performed the transaction **discloses** the **time** and/or **amount** of the transaction, it can be easily **discoverable**.

### Traffic analysis

Some organisation **sniffing your traffic** can see you communicating in the bitcoin network.\
If the adversary sees a transaction or block **coming out of your node which did not previously enter**, then it can know with near-certainty that **the transaction was made by you or the block was mined by you**. As internet connections are involved, the adversary will be able to **link the IP address with the discovered bitcoin information**.

An attacker that isn't able to sniff all the Internet traffic but that has **a lot of Bitcoin nodes** in order to stay **closer** to the s**o**urces could be able to know the IP address that are announcing transactions or blocks.\
Also, some wallets periodically rebroadcast their unconfirmed transactions so that they are more likely to propagate widely through the network and be mined.

### Other attacks to find info about the owner of addresses

For more attacks read [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

## Anonymous Bitcoins

### Obtaining Bitcoins Anonymously

* **Cash trades: **Buy bitcoin using cash.
* **Cash substitute: **Buy gift cards or similar and exchange them for bitcoin online.
* **Mining: **Mining is the most anonymous way to obtain bitcoin. This applies to solo-mining as [mining pools](https://en.bitcoin.it/wiki/Pooled_mining) generally know the hasher's IP address.
* **Stealing: **In theory another way of obtaining anonymous bitcoin is to steal them.

### Mixers

A user would** send bitcoins to a mixing service** and the service would **send different bitcoins back to the user**, minus a fee. In theory an adversary observing the blockchain would be** unable to link** the incoming and outgoing transactions.

However, the user needs to trust the mixing service to return the bitcoin and also to not be saving logs about the relations between the money received and sent.\
Some other services can be also used as mixers, like Bitcoin casinos where you can send bitcoins and retrieve them later.

### CoinJoin

**CoinJoin** will **mix several transactions of different users into just one** in order to make more **difficult** for an observer to find out **which input is related to which output**.\
This offers a new level of privacy, however, **some** **transactions** where some input and output amounts are  correlated or are very different from the rest of the inputs and outputs **can still be correlated** by the external observer.

Examples of (likely) CoinJoin transactions IDs on bitcoin's blockchain are `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)****\
**Similar to coinjoin but better and for ethereum you have **[**Tornado Cash**](https://tornado.cash)** (the money is given from miners, so it jus appear in your waller).**

### PayJoin

The type of CoinJoin discussed in the previous section can be easily identified as such by checking for the multiple outputs with the same value. 

PayJoin (also called pay-to-end-point or P2EP) is a special type of CoinJoin between two parties where one party pays the other. The transaction then **doesn't have the distinctive multiple outputs **with the same value, and so is not obviously visible as an equal-output CoinJoin. Consider this transaction:

```
2 btc --> 3 btc
5 btc     4 btc
```

It could be interpreted as a simple transaction paying to somewhere with leftover change (ignore for now the question of which output is payment and which is change). Another way to interpret this transaction is that the 2 BTC input is owned by a merchant and 5 BTC is owned by their customer, and that this transaction involves the customer paying 1 BTC to the merchant. There is no way to tell which of these two interpretations is correct. The result is a coinjoin transaction that breaks the common-input-ownership heuristic and improves privacy, but is also **undetectable and indistinguishable from any regular bitcoin transaction**.

If PayJoin transactions became even moderately used then it would make the **common-input-ownership heuristic be completely flawed in practice**. As they are undetectable we wouldn't even know whether they are being used today. As transaction surveillance companies mostly depend on that heuristic, as of 2019 there is great excitement about the PayJoin idea.

## Bitcoin Privacy Good Practices

### Wallet Synchronization

Bitcoin wallets must somehow obtain information about their balance and history. As of late-2018 the most practical and private existing solutions are to use a **full node wallet **(which is maximally private) and **client-side block filtering** (which is very good).

* **Full node: **Full nodes download the entire blockchain which contains every on-chain [transaction](https://en.bitcoin.it/wiki/Transaction) that has ever happened in bitcoin. So an adversary watching the user's internet connection will not be able to learn which transactions or addresses the user is interested in. 
* **Client-side block filtering: **Client-side block filtering works by having **filters** created that contains all the **addresses** for every transaction in a block. The filters can test whether an** element is in the set**; false positives are possible but not false negatives. A lightweight wallet would **download** all the filters for every **block** in the **blockchain** and check for matches with its **own** **addresses**. Blocks which contain matches would be downloaded in full from the peer-to-peer network, and those blocks would be used to obtain the wallet's history and current balance.

### Tor

Bitcoin network uses a peer-to-peer network, which means that other peers can learn your IP address. This is why it's recommend to **connect through Tor every time you want to interact with the bitcoin network**.

### Avoiding address reuse

**Addresses being used more than once is very damaging to privacy because that links together more blockchain transactions with proof that they were created by the same entity**. The most private and secure way to use bitcoin is to send a brand **new address to each person who pays you**. After the received coins have been spent the address should never be used again. Also, a brand new bitcoin address should be demanded when sending bitcoin. All good bitcoin wallets have a user interface which discourages address reuse.

### Multiple transactions

**Paying** someone with **more than one on-chain transaction** can greatly reduce the power of amount-based privacy attacks such as amount correlation and round numbers. For example, if the user wants to pay 5 BTC to somebody and they don't want the 5 BTC value to be easily searched for, then they can send two transactions for the value of 2 BTC and 3 BTC which together add up to 5 BTC.

### Change avoidance

Change avoidance is where transaction inputs and outputs are carefully chosen to not require a change output at all. **Not having a change output is excellent for privacy**, as it breaks change detection heuristics.

### Multiple change outputs

If change avoidance is not an option then **creating more than one change output can improve privacy**. This also breaks change detection heuristics which usually assume there is only a single change output. As this method uses more block space than usual, change avoidance is preferable.

## Monero

When Monero was developed, the gaping need for **complete anonymity **was what it sought to resolve, and to a large extent, it has filled that void.

## Ethereum

### Gas

Gas refers to the unit that measures the **amount** of **computational** **effort** required to execute specific operations on the Ethereum network. Gas refers to the **fee** required to successfully conduct a **transaction** on Ethereum.

Gas prices are denoted in **gwei**, which itself is a denomination of ETH - each gwei is equal to **0.000000001 ETH** (10-9 ETH). For example, instead of saying that your gas costs 0.000000001 ether, you can say your gas costs 1 gwei. The word 'gwei' itself means 'giga-wei', and it is equal to **1,000,000,000 wei**. Wei itself is the **smallest unit of ETH**.

To calculate the gas that a transaction is going to cost read this example:

Let’s say Jordan has to pay Taylor 1 ETH. In the transaction the gas limit is 21,000 units and the base fee is 100 gwei. Jordan includes a tip of 10 gwei.

Using the formula above we can calculate this as `21,000 * (100 + 10) = 2,310,000 gwei` or 0.00231 ETH.

When Jordan sends the money, 1.00231 ETH will be deducted from Jordan's account. Taylor will be credited 1.0000 ETH. Miner receives the tip of 0.00021 ETH. Base fee of 0.0021 ETH is burned.

Additionally, Jordan can also set a max fee (`maxFeePerGas`) for the transaction. The difference between the max fee and the actual fee is refunded to Jordan, i.e. `refund = max fee - (base fee + priority fee)`. Jordan can set a maximum amount to pay for the transaction to execute and not worry about overpaying "beyond" the base fee when the transaction is executed.

As the base fee is calculated by the network based on demand for block space, this last param: maxFeePerGas helps to control the maximum fee that is going to be payed. 

### Transactions

Notice that in the **Ethereum** network a transaction is performed between 2 addresses and these can be **user or smart contract addresses**.\
**Smart Contracts** are stored in the distributed ledger via a **special** **transaction**.

Transactions, which change the state of the EVM, need to be broadcast to the whole network. Any node can broadcast a request for a transaction to be executed on the EVM; after this happens, a **miner** will **execute** the **transaction** and propagate the resulting state change to the rest of the network.\
Transactions require a **fee** and must be mined to become valid.

A submitted transaction includes the following information:

* `recipient` – the receiving address (if an externally-owned account, the transaction will transfer value. If a contract account, the transaction will execute the contract code)
* `signature` – the identifier of the sender. This is generated when the sender's private key signs the transaction and confirms the sender has authorised this transaction
* `value` – amount of ETH to transfer from sender to recipient (in WEI, a denomination of ETH)
* `data` – optional field to include arbitrary data
* `gasLimit` – the maximum amount of gas units that can be consumed by the transaction. Units of gas represent computational steps
* `maxPriorityFeePerGas` - the maximum amount of gas to be included as a tip to the miner
* `maxFeePerGas` - the maximum amount of gas willing to be paid for the transaction (inclusive of `baseFeePerGas` and `maxPriorityFeePerGas`)

Note that there isn't any field for the origin address, this is because this can be extrapolated from the signature.

## References

* [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

