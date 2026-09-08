# Cryptocurrency Privacy

Cryptocurrency privacy एक protocol और operations संबंधी प्रश्न है, secrecy या immunity का पर्याय नहीं। Public ledgers, exchanges, wallet servers, network peers, merchants और बाद के transactions graph के अलग-अलग हिस्सों को उजागर करते हैं।

प्रत्येक technique के pros/cons/procedure/detection format के लिए [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) से शुरू करें। यह पेज cryptocurrency-विशिष्ट mechanics और operational limits को विस्तार देता है।

{% hint style="danger" %}
यह chapter lawful self-custody और data minimization के लिए है। इसका उपयोग proceeds को launder करने, sanctions/tax/reporting से बचने, prohibited parties के साथ transact करने, regulated provider को गुमराह करने या unlicensed transmission service चलाने के लिए न करें। Privacy technology funds के legal origin या ownership को नहीं बदलती।
{% endhint %}

## Layer के अनुसार threat model

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Identity, funding account, destination, device, IP, time |
| Ledger | Analytics चलाने वाला कोई भी व्यक्ति | Transparent chains पर addresses/outputs, amounts और time; अन्य जगह protocol-specific metadata |
| Wallet backend | RPC provider, explorer, remote node | Address queries, balances, IP, transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP, timing, volume और protocol use |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account और timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, keys, labels, history, screenshots और clipboard |

Self-custody control path से custodian को हटा सकता है, लेकिन ledger, acquisition record, network metadata या endpoint evidence को मिटाता नहीं है।

## Protocol comparison

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh addresses simple address reuse से बचते हैं | Public permanent transaction graph; amount/timing और spending heuristics |
| Bitcoin PayJoin | Receiver input common-input-ownership heuristic को तोड़ सकता है | दोनों wallets को support चाहिए; transaction public रहता है; support असमान है |
| Bitcoin CoinJoin | Coordinated participants के बीच ambiguity बनाता है | Recognizable patterns, pre/post links, consolidation, policy/legal/provider risk |
| Lightning | Onion-routed payments ordinary transfers के रूप में globally published नहीं होते | Channels on-chain open/close होते हैं; endpoints, peers, probes या custodian data का अनुमान लगा सकते हैं |
| Monero | Receiver, amount और sender set के लिए stronger default on-chain confidentiality | Exchange, node, timing, endpoint और counterparty links बने रहते हैं |
| Ethereum/stablecoins | Broad availability और smart-contract interoperability | Public state/actions; RPC metadata; centralized issuers block/freeze/report कर सकते हैं |

## Bitcoin: privacy-preserving baseline

Bitcoin pseudonymous है, anonymous नहीं। Confirmed transactions public और durable होते हैं; address reuse, common-input ownership, change detection और publicly identified addresses clusters बना सकते हैं।<sup>[[1]](#references)</sup>

### Workflow

1. **एक maintained self-custody wallet चुनें।** Official project से download करें, उपलब्ध होने पर signatures/hashes verify करें और security updates लागू करें।
2. **Trusted endpoint पर wallet बनाएं।** Recovery seed को offline record करें; इसे email, chat, screenshots या ordinary cloud notes में कभी न रखें। Significant value रखने से पहले recovery test करें।
3. **Hot wallet में केवल operational value रखें।** Long-term value के लिए उपयुक्त offline/hardware custody का उपयोग करें और ऐसी recovery plan रखें जिसमें seed किसी एक fragile location में expose न हो।
4. **हर transaction के लिए fresh receive address/invoice generate करें।** जब invoice server या authenticated private delivery संभव हो, तब static address publish न करें।
5. **जब संभव हो अपना full node उपयोग करें।** Third-party explorer/electrum server queried addresses और IP metadata जान सकता है। केवल wallet-supported Tor/proxy behavior configure करें; Tor network edge छिपाता है, blockchain graph नहीं।
6. **हर UTXO को privately label करें**—source, owner, purpose और compliance state के साथ। Unrelated identity contexts को co-spend होने से रोकने के लिए coin control enable करें।
7. **Transaction का preview देखें:** selected inputs, change destination, amount, fee, counterparty और क्या spend compartments को merge कर रहा है। अनावश्यक consolidation से बचें।
8. **Lawful records को अलग और encrypted रखें।** Acquisition basis, invoices, authorization और tax/reporting information सुरक्षित रखें, mapping publish किए बिना।
9. **बाद के spending को उसी privacy decision का हिस्सा मानें।** Identified funds के साथ output को co-spend करने पर अच्छी तरह अलग की गई receipt फिर से relink हो सकती है।

Bitcoin Core का privacy documentation बताता है कि full node third-party servers को wallet queries reveal होने से बचाता है, लेकिन transaction broadcast और public history का फिर भी analysis आवश्यक है।<sup>[[2]](#references)</sup>

## PayJoin

PayJoin एक collaborative payment है जिसमें receiver एक input जोड़ता है। इससे यह सरल assumption विफल होता है कि सभी inputs sender के हैं। BIP 78 मूल interactive protocol का वर्णन करता है; draft BIP 77 encrypted mailbox/OHTTP का उपयोग करने वाला asynchronous v2 design परिभाषित करता है।<sup>[[3]](#references)</sup>

Safe use:

1. Confirm करें कि दोनों maintained wallets समान PayJoin version support करते हैं।
2. PayJoin-capable invoice authenticated channel से प्राप्त करें; इसे किसी भी payment request की तरह सुरक्षित रखें।
3. Original amount और destination जाँचें, फिर wallet को proposal/PSBT, fee contribution और prohibited substitutions validate करने दें।
4. Final wallet summary confirm करें। Unexpected output, amount या excessive fee को manually approve न करें।
5. यदि negotiation विफल हो, समझें कि wallet safely ordinary payment पर fallback करता है या नई invoice आवश्यक है।
6. Ownership, accounting और disputes के लिए आवश्यक private receipt/records सुरक्षित रखें।

PayJoin एक chain-analysis heuristic को बेहतर बनाता है; यह payment को parties, acquisition platform, endpoints या public ledger से hide नहीं करता।

## CoinJoin: benefits और limits

CoinJoin कई users को एक transaction में coordinate करता है ताकि input-output mapping कम निश्चित हो। Specific historical Wasabi और Samourai designs पर research में highly recognizable transactions पाए गए और दिखाया गया कि pre/post-mix behavior anonymity को काफी सीमित कर सकता है।<sup>[[4]](#references)</sup> इस result को हर implementation या future version पर लागू नहीं करना चाहिए, लेकिन यह दिखाता है कि “anonymity-set” number कोई guarantee नहीं है।

किसी भी lawful use से पहले:

- current local law, sanctions status, exchange/custodian policy और tax/reporting duties जाँचें;
- official project से प्राप्त maintained, non-custodial software उपयोग करें;
- coordinator model, fees, denial-of-service controls और यह समझें कि current service अभी भी operate करती है या नहीं—zkSNACKs ने 2024 में अपना coordinator बंद कर दिया, हालांकि अन्य Wasabi coordinators मौजूद हो सकते हैं;
- source-of-funds और transaction records privately सुरक्षित रखें;
- किसी और की ओर से unknown funds कभी स्वीकार न करें और untraceable withdrawals का वादा करने वाले custodial “mixer” का उपयोग न करें;
- outputs को source/context के अनुसार अलग रखें और बाद के consolidation से बचें, जो intended ambiguity को नष्ट कर सकता है।

Legal outcomes facts और jurisdiction पर निर्भर होते हैं। 2025 के Samourai guilty pleas knowingly unlicensed money transmitter चलाने और criminal proceeds move करने से संबंधित थे; वे यह स्थापित नहीं करते कि हर collaborative transaction या privacy-seeking user criminal है।<sup>[[5]](#references)</sup>

## Lightning Network

Lightning का Sphinx onion routing इस तरह design किया गया है कि intermediate hop entire route के बजाय अपने predecessor और successor को जाने।<sup>[[6]](#references)</sup> यह blanket anonymity नहीं है: channel funding/closure public है, nodes topology advertise करते हैं, counterparties endpoints जानते हैं, routing/probing balances या parties का अनुमान लगा सकते हैं, और custodial wallet अपने user की account activity देखता है।

बेहतर privacy के लिए:

1. यदि intermediary privacy महत्वपूर्ण है तो maintained non-custodial wallet को प्राथमिकता दें; पहले channel backup/recovery plan करें।
2. हर payment के लिए fresh invoice या offer उपयोग करें। यह assume करने के बजाय verify करें कि exact wallet BOLT 12/route blinding support करता है।
3. अनावश्यक node aliases, contact details और stable network endpoints publish न करें।
4. उपयुक्त होने पर supported privacy network से connect करें, यह समझते हुए कि uptime/timing patterns फिर भी correlate हो सकते हैं।
5. यह न मानें कि off-chain payment का कोई record नहीं होता: sender, receiver, peers, watchtowers, liquidity providers और wallet services observations retain कर सकते हैं।

Published research ने public data और active probing से sender/recipient तथा channel-balance inference प्रदर्शित किया है, हालांकि attacks और mitigations विकसित होते रहते हैं।<sup>[[7]](#references)</sup>

## Monero

Monero outputs के लिए one-time stealth addresses, amounts छिपाने के लिए RingCT और probabilistic sender ambiguity के लिए ring signatures उपयोग करता है; इसके current technical specifications में ring size 16 (15 decoys) document किया गया है।<sup>[[8]](#references)</sup> Transparent ledgers की तुलना में ये on-chain confidentiality के लिए stronger defaults हैं, endpoint या operational mistakes से magic protection नहीं।

### Lawful workflow

1. **Lawfully acquire करें।** Regulated exchange को purchase और withdrawal की जानकारी हो सकती है, भले ही बाद के on-chain details confidential हों। Source, basis और reporting records रखें।
2. **Official maintained wallet install करें** और project instructions के अनुसार download verify करें। Seed का offline backup बनाएं और छोटी amount से restoration test करें।
3. **Maximum wallet-query privacy के लिए local node को प्राथमिकता दें।** यदि यह impractical हो, तो officially supported onion/I2P configuration से reachable trusted remote node चुनें। Remote node IP, requests, timing और transaction IDs log कर सकता है; कुछ lightweight designs view key disclose करते हैं।
4. **हर payer, campaign या invoice के लिए नया subaddress उपयोग करें।** Payer उसी subaddress के repeated use को correlate कर सकता है।<sup>[[9]](#references)</sup>
5. **Incoming contexts को locally label करें।** Separated receipts को operationally merge करने से बचें, जहाँ knowledgeable payer subsequent behavior पहचान सकता हो।
6. **Network metadata सुरक्षित रखें।** Official anonymity-network configuration follow करें; timestamps, intermittent synchronization, bandwidth shape और stream reuse से होने वाले documented leaks को समझें।<sup>[[10]](#references)</sup>
7. **Compliance/audit data private रखें।** View key या transaction proof केवल deliberate रूप से intended auditor/party को disclose करें और ठीक-ठीक समझें कि वह क्या reveal करता है।

Historical traceability studies में bugs और decoy-selection eras शामिल हैं जो बाद में बदल चुके हैं; पुराने success percentages को current transactions पर लागू न करें। इसी तरह, इस chapter की September 2026 research cutoff तक FCMP++ roadmap work है, deployed protection नहीं।<sup>[[11]](#references)</sup>

## Ethereum और stablecoins

Ethereum का अपना privacy material बताता है कि on-chain actions visible हैं और wallet/RPC infrastructure IP तथा metadata exposure बढ़ाता है।<sup>[[12]](#references)</sup> Token transfers, approvals, smart-contract interactions, name services और gas funding सभी identities को connect कर सकते हैं।

Centralized stablecoins issuer control जोड़ते हैं। Current USDC और Tether terms addresses या assets को block/freeze करने और legal/process obligations का पालन करने की powers reserve करते हैं।<sup>[[13]](#references)</sup> वे उपयोगी payment instruments हो सकते हैं, लेकिन censorship resistance या on-chain anonymity की requirement होने पर poor choices हैं।

## Compliance boundaries

- FATF recommendations national law के माध्यम से लागू होती हैं और समय के साथ बदलती हैं; इसके 2026 update में VASP licensing/registration और Travel Rule implementation पर जोर दिया गया है।<sup>[[14]](#references)</sup>
- US में FinCEN अपने goods/services के लिए convertible virtual currency उपयोग करने वाले व्यक्ति को उस business से अलग मानता है जो इसे accept और transmit या exchange करता है; facts और बाद के rules महत्वपूर्ण हैं।<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation में crypto-asset service provider शामिल होने पर originator/beneficiary information आवश्यक है और self-hosted addresses से/पर कुछ transfers के लिए verification rules जोड़े गए हैं।<sup>[[16]](#references)</sup>
- Sanctions और tax duties लागू रहते हैं। आवश्यकतानुसार screen करें, prohibited parties को refuse करें और records रखें; lists और legal status तेजी से बदल सकते हैं।<sup>[[17]](#references)</sup>

Material value, cross-border activity, privacy-enhancing coordination या business-like exchange/transmission से पहले relevant jurisdictions के लिए current professional advice प्राप्त करें।

Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash और BOLT 12 के लिए [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) देखें।

## References

- [1] [Bitcoin.org — अपनी privacy की सुरक्षा करें](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy features](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — एक सरल Payjoin प्रस्ताव](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Bitcoin में Decentralized CoinJoin Implementations को अपनाना और वास्तविक privacy (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet के founders ने guilty plea दी (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Lightning Network में privacy का empirical analysis](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html), और [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Monero की privacy का evolution (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum पर privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Virtual Assets और VASPs पर 2026 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Virtual Currencies को administer, exchange या use करने वाले व्यक्तियों पर FinCEN Regulations का application](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry के लिए Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
