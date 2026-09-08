# Tradecraft de Ofuscação Financeira

A privacidade de pagamentos é um problema de atribuição, não de marca de pagamento. Uma operação deixa evidências quando o valor é adquirido, movimentado, convertido, gasto e entregue. Um endereço em uma public-chain pode ser pseudônimo, enquanto uma exchange, emissora de cartão, comerciante, dispositivo móvel ou câmera de envio identifica a pessoa por trás dele.

Esta página explica padrões de ofuscação financeira usados em cybercrime e operações vinculadas a Estados, para que os defensores possam reconhecê-los. Ela **não** fornece um procedimento de lavagem de dinheiro, evasão de sanções, identidade falsa ou bypass de KYC.

## O grafo de valor de ponta a ponta
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Um ator tenta impedir que qualquer observador veja ambas as pontas. Investigadores fazem o oposto: preservam registros em cada fronteira, normalizam tempo/valor/taxas e identificam o **ponto de reconvergência** onde personas separadas reutilizam um facilitador, dispositivo, conta, merchant ou destino.

## Instrumentos e seus observadores reais

| Instrumento | Oculto do merchant/público | Ainda visível para |
|---|---|---|
| Issuer virtual card/token | número do cartão subjacente | issuer, provedor de rede/token, wallet, conta do merchant e sistemas de entrega |
| Prepaid/gift value | às vezes o nome legal em uma compra comum | varejista/payment rail, serviço de ativação/resgate, câmeras, dispositivo e entrega |
| Cash | ledger público e issuer remoto | contrapartes, câmeras, controles de saque/serial quando aplicável, busca física |
| Bitcoin/new address | nome legal direto | todo observador da blockchain; peers da wallet/rede; serviços de aquisição/off-ramp |
| CoinJoin/PayJoin | heurísticas simples de common-input/payment | transação pública, metadados do coordinator/peer/rede e comportamento posterior de gastos |
| Privacy coin | remetente/destinatário/valor público, dependendo do protocolo | aquisição/off-ramp, endpoint da wallet, observador da rede e contraparte |
| Centralized mixer | vínculo direto entre depósito e saque | operador/logs do mixer, conjuntos de entrada/saída da blockchain e contrapartes |
| Cross-chain bridge/swap | continuidade em uma cadeia | ambas as cadeias, serviço de bridge/swap, restrições de tempo/valor e liquidez |
| OTC/P2P broker | conta de exchange direta em alguns casos | broker, comunicações, movimentação bancária/de cash, contrapartes e dispositivos |

## Cards, valor pré-pago, nominees e mules

### Virtual and masked cards

Um issuer pode criar um número de cartão vinculado a um merchant ou descartável. Isso reduz a exposição do merchant e a reutilização do número entre merchants. O issuer ainda o associa ao cliente, à conta de funding, ao dispositivo, ao IP e à transação. Billing descriptors, conta do merchant, endereço de entrega e dados do navegador continuam vinculáveis.

O marketing de cards “sem nome” não implica settlement anônimo. Issuers e distribuidores regulados podem realizar verificações de identidade, manter registros, impor limites geográficos/de valor e responder a processos legais. Um card obtido por meio de uma identidade roubada acrescenta identity theft; não remove a telemetria do issuer/dispositivo/merchant.

### Prepaid and gift value

Prepaid cards e gift codes separam um resgate posterior do instrumento de pagamento original, mas criam um objeto numerado com eventos de compra, ativação, consulta de saldo e resgate. Os padrões relevantes incluem compras em massa, repetição de denominações logo abaixo dos controles, resgate rápido e distante, um dispositivo consultando muitos saldos ou muitos cards convergindo para um único merchant/conta.

### Nominees, money mules and merchant fronts

Um nominee ou mule fornece uma conta e uma identidade legal que ficam entre o operador e um serviço. As redes podem incluir recruiters, account holders, payment processors, shell merchants e brokers de cash-out. Isso cria distância, mas cada participante acrescenta comunicações, taxas, inconsistência comportamental e uma possível testemunha colaboradora. Front companies acrescentam registros de incorporação, impostos, bancos, diretores, invoices, hospedagem e remessas.

Defensores devem investigar dispositivos/IPs compartilhados, reutilização de beneficiários, contradições de geolocalização, velocidade incompatível com o histórico da conta, transferências circulares, vários remetentes não relacionados convergindo e movimentação imediata posterior. Não presuma que o account holder nomeado seja o ator controlador; trate-o como um node que requer determinação de função.

## Padrões de obfuscation de transações em public-chain

### Address rotation and coin control

Criar um novo endereço para cada recebimento impede a reutilização trivial de endereços, mas as transações ainda podem ser associadas por meio de common inputs, detecção de change, valor/tempo exatos e consolidação posterior. **Coin control** permite que uma wallet escolha quais outputs gastar e evite unir compartments. Isso melhora a higiene; não pode remover um vínculo que já é público.

### Peel chains

Uma peel chain gasta repetidamente um saldo grande, enviando um valor menor para fora e devolvendo o restante a um novo endereço:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
O endereço muda a cada etapa, mas a continuidade do valor, a cadência e a estrutura das transações geralmente formam uma cadeia reconhecível. Hot wallets legítimas de exchanges podem se comportar de forma semelhante, portanto a atribuição exige evidências do serviço/contexto. O DOJ usou a análise de peel-chain em casos de confisco ligados à DPRK.<sup>[[1]](#references)</sup>

### Structuring e fan-out/fan-in

- **Fan-out:** uma fonte se divide em muitos endereços para aumentar a carga de trabalho investigativa ou preparar conversões paralelas.
- **Fan-in:** muitas fontes se consolidam em um único coletor, revelando controle comum ou um serviço.
- **Structuring:** transferências menores repetidas procuram evitar limites de revisão ou se misturar ao volume comum.
- **Commingling:** fundos ilícitos e não relacionados compartilham wallets, pools ou serviços, tornando inseguras alegações proporcionais simplistas.

O formato do grafo é uma pista, não uma prova. Os analistas devem considerar taxas, UTXO/account model, comportamento do serviço e convenções de change.

### CoinJoin e PayJoin

Em um CoinJoin típico, vários participantes contribuem com inputs e recebem outputs em uma única transação colaborativa, geralmente com denominações de output iguais. Isso rompe a suposição de que cada input e output em uma transação tem um único proprietário. O anonymity set é limitado pelo número de participantes e pelo comportamento posterior: change desigual, toxic change, consolidação ou passagem por um serviço conhecido podem reintroduzir vínculos.

O PayJoin modifica um pagamento comum para que tanto o pagador quanto o beneficiário contribuam com inputs, invalidando diretamente a heurística de propriedade por common-input nessa transação. É principalmente um protocolo de privacidade para pagamentos, não um serviço de laundering em massa. A detecção deve evitar declarar que todos os inputs pertencem ao mesmo proprietário e deve expressar incerteza em vez de impor um cluster falso.

### Mixers e tumblers centralizados

Um mixer centralizado aceita depósitos e posteriormente paga moedas diferentes a partir de uma reserva conjunta, geralmente após taxas e atrasos. Sua privacidade depende do tamanho do pool, da política de saque, dos logs, da honestidade do operador e da resistência à apreensão. A análise de tempo/valor de entrada e saída, endereços de depósito, clustering de service wallets e registros podem restringir o conjunto. Os operadores podem roubar os fundos ou manter um mapeamento completo.

A exposição jurídica é substancial e específica de cada jurisdição. Os casos do DOJ contra ChipMixer, Samourai Wallet e desenvolvedores/operadores do Tornado Cash, além da mudança na litigância sobre sanções, mostram que fatos relacionados a protocolo, custódia, controle e transmissão de dinheiro são relevantes; um rótulo como “descentralizado” não é uma conclusão jurídica.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps e bridges

Chain hopping converte um ativo ou o move por uma bridge, interrompendo uma consulta em um único ledger, mas não a continuidade econômica:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analistas correlacionam contratos de bridge/endereços de depósito de serviços, ordem das transações, janela de tempo, taxa de câmbio, taxas, liquidez e valor exclusivo. Swaps repetidos podem ampliar a ambiguidade ao mesmo tempo que adicionam telemetria de provedores/API/wallet. A FATF identifica especificamente chain hopping, mixers, serviços peer-to-peer e moedas com privacidade aprimorada como indicadores de risco quando combinados com um contexto suspeito.<sup>[[3]](#references)</sup>

### NFTs, gambling e compras de comerciantes

Trades de NFT com autonegociação ou conluio podem dar aos fundos uma narrativa aparente de venda; gambling pode trocar depósitos por retiradas; bens podem converter valor digital em inventário revendável. Esses caminhos deixam contas de marketplace, vínculos de criadores/royalties, grafos de wash-trading, histórico de odds/jogadas, logs de dispositivos, evidências de entrega e revenda. Uma perda ou taxa não prova que a proveniência desapareceu.

## Criptomoedas com preservação de privacidade

Os protocolos de privacidade diferem tecnicamente:

- **Monero** usa endereços de uso único, ring signatures e valores confidenciais, reduzindo a visibilidade pública de remetente/destinatário/valor. Observação da rede, comprometimento da wallet, aquisição/off-ramp e registros de contrapartes permanecem fora dessas proteções on-chain.
- **Zcash shielded pools** podem ocultar remetente, destinatário e valor quando transações shielded são usadas; endereços transparentes e transições entre pools permanecem públicos, e os padrões de uso afetam o conjunto de anonimato efetivo.
- **Bitcoin** é transparente por padrão. Novos endereços, CoinJoin, PayJoin e Lightning alteram determinadas suposições de vinculação, mas não tornam todas as camadas privadas.

A tecnologia de privacidade tem usos legítimos de segurança e comerciais. Do ponto de vista investigativo, quando o ledger fornece menos informações, evidências de endpoint, serviço, rede e humanas tornam-se mais importantes. Nunca presuma criminalidade apenas pela escolha de um protocolo que preserva a privacidade.

## Modelo de caso multicamadas da DPRK

As alegações públicas do DOJ e as ações de confisco descrevem um processo composto, não um único truque:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. trabalhadores usaram material de identidade fictício/roubado e VPNs para obter emprego remoto;
2. empregadores pagaram em criptomoedas, incluindo stablecoins;
3. os fundos foram movimentados em quantias menores, atravessaram chains ou tokens, compraram NFTs ou foram misturados;
4. outros fundos roubados entraram em mixers;
5. traders OTC e empresas de fachada converteram valor em pagamentos fiat ou bens;
6. facilitadores, contas e caminhos de blockchain recorrentes permitiram que investigadores reconectassem as camadas.

O Treasury declarou que Lazarus usou o Blender.io para processar parte do roubo da Axie Infinity/Ronin, enquanto o FBI publicou endereços e instou bridges, exchanges, operadores de RPC e empresas de analytics a bloquear fundos vinculados a roubos posteriores do TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

A lição é bidirecional: atores estatais usam serviços comerciais/criminais comuns, e blockchains públicas permitem que defensores sigam o valor mesmo quando os nomes são inicialmente desconhecidos.

## Fluxo de detecção

1. **Preserve os identificadores e registros brutos das transações.** Capturas de tela e valores fiat arredondados são insuficientes.
2. **Normalize ativos e horários.** Registre chain, contrato do token, unidades, horário do bloco, fuso horário do serviço, taxas e fonte da taxa de câmbio.
3. **Classifique a confiança das evidências.** Diferencie um endereço publicado por um serviço, um evento determinístico de contrato, uma heurística de clustering e inteligência externa.
4. **Rastreie ambas as direções.** Encontre a origem do financiamento, a dispersão imediata, a reconvergência, as saídas de bridges, os depósitos em serviços e os gastos/entregas.
5. **Associe evidências off-chain.** KYC de contas, dispositivo, IP, tickets de suporte, chaves de API, registros bancários/de pagamento, envio e comunicação frequentemente resolvem a ambiguidade.
6. **Teste explicações alternativas.** Exchanges, custodians, folha de pagamento e protocolos de privacidade podem produzir fan-in/out ou co-spends sem propriedade beneficiária comum.
7. **Monitore em vez de encerrar prematuramente.** Um output dormente pode tornar-se atribuível quando posteriormente alcançar um serviço.
8. **Aplique as obrigações atuais de sanções/AML com orientação jurídica.** Regras e designações mudam; associação histórica não substitui a análise jurídica atual.

## Modelo seguro de aquisição para red team

Uma equipe autorizada pode precisar que o SOC do alvo não reconheça o pagamento de hosting, enquanto o controlador do engagement mantém a responsabilidade:

- use um cartão de organização específico do engagement ou uma wallet corporativa documentada;
- mantenha corretos os registros de cobrança, fiscais e do provedor;
- separe o operador das funções de aquisição e limite o acesso ao mapa de atribuição;
- nunca use um mule, identidade falsa, cartão roubado, contorno de sanções ou exchanger sem licença;
- registre ativo, valor, proprietário, serviço, data, caminho de reembolso e evidências de teardown;
- divulgue os indicadores relevantes de pagamento/provedor ao controlador após o exercício.

Isso cria **cegueira em relação ao participante do exercício**, não cegueira em relação à lei, ao provedor ou à governança.

## References

- [1] [US DOJ — Estrutura de aplicação da lei sobre criptomoedas (exemplo de peel-chain e investigações da DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Operação de encerramento do ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indicadores de alerta vermelho de Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Representante do Foreign Trade Bank da DPRK acusado de conspirações de lavagem de criptomoedas](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Queixa de confisco referente a US$ 7,74 milhões supostamente lavados para a DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanções contra o Blender.io e fundos do Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — A Coreia do Norte é responsável pelo roubo de 2025 da Bybit](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Aplicação das regulamentações a usuários, administradores e exchangers de moedas virtuais](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
