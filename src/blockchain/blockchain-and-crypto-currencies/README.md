# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são construídas sobre smart contracts e contam com um front-end fácil de usar e um back-end transparente e auditável.
- **Tokens e Coins** se diferenciam porque as coins servem como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
  - **Utility Tokens** concedem acesso a serviços, e **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas e oferece serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de exchange descentralizadas e organizações autônomas descentralizadas.

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.<sup>[[1]](#references)</sup>

## Noções Essenciais sobre Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. Elas são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes Principais:

- **Transações Multisig** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Busca melhorar a escalabilidade do Bitcoin permitindo várias transações dentro de um canal, transmitindo à blockchain apenas o estado final.

## Preocupações com a Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Obtendo Bitcoins Anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. **CoinJoin** combina várias transações para dificultar o rastreamento, enquanto **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários costumam ser motivo de preocupação. Veja uma visão geral simplificada de alguns métodos comuns pelos quais atacantes podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Em geral, é raro que inputs de usuários diferentes sejam combinados em uma única transação, devido à complexidade envolvida. Portanto, **costuma-se presumir que dois endereços de input na mesma transação pertencem ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, precisa ser gasto por completo em uma transação. Se apenas parte dele for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo sua privacidade.

### Exemplo

Para reduzir esse risco, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise de Grafos de Transações**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Heurística de Inputs Desnecessários (Heurística de Troco Ótimo)**

Essa heurística se baseia na análise de transações com vários inputs e outputs para tentar descobrir qual output corresponde ao troco devolvido ao remetente.

### Exemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se adicionar mais entradas fizer com que a saída de troco seja maior do que qualquer entrada individual, isso pode confundir a heurística.

## **Reutilização Forçada de Endereços**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, esperando que o destinatário as combine com outras entradas em transações futuras, vinculando assim os endereços entre si.

### Comportamento Correto da Wallet

As wallets devem evitar usar moedas recebidas em endereços já usados e vazios para prevenir esse privacy leak.

## **Outras Técnicas de Análise de Blockchain**

- **Valores Exatos de Pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Valores Redondos:** Um valor redondo em uma transação sugere que se trata de um pagamento, e a saída com valor não redondo provavelmente é o troco.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de troco.
- **Correlações entre Valores e Horários:** Divulgar horários ou valores de transações pode torná-las rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente válido se uma entidade operar muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques à privacidade e defesas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Bitcoin Anônimas

## Formas de Obter Bitcoins Anonimamente

- **Transações em Dinheiro Vivo**: Adquirir bitcoin usando dinheiro vivo.
- **Alternativas ao Dinheiro Vivo**: Comprar cartões-presente e trocá-los online por bitcoin.
- **Mineração**: A forma mais privada de ganhar bitcoins é por meio da mineração, especialmente quando feita individualmente, pois pools de mineração podem conhecer o endereço IP do minerador. [Informações sobre pools de mineração](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo**: Em teoria, roubar bitcoin poderia ser outra forma de adquiri-lo anonimamente, embora isso seja ilegal e não recomendado.

## Serviços de Mixing

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **outros bitcoins em troca**, dificultando o rastreamento do proprietário original. No entanto, isso exige confiar que o serviço não manterá logs e realmente devolverá os bitcoins. Outras opções de mixing incluem cassinos Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de usuários diferentes em uma só, complicando o processo para quem tenta associar entradas a saídas. Apesar de sua eficácia, transações com quantidades únicas de entradas e saídas ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contracts Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação regular, sem as saídas iguais características do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum das entradas usada por entidades de vigilância de transações.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transações como a acima poderiam ser PayJoin, aumentando a privacidade e permanecendo indistinguíveis de transações bitcoin padrão.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de vigilância**, tornando-a uma evolução promissora na busca por privacidade transacional.

# Melhores práticas de privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Nó completo**: Ao baixar toda a blockchain, um nó completo garante o máximo de privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário tem interesse.
- **Filtragem de blocos no cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem revelar interesses específicos a observadores da rede. Carteiras leves baixam esses filtros e só buscam blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização de Tor para anonimato**

Como Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para a privacidade das transações**

- **Várias transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, frustrando ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem saídas de troco aumenta a privacidade ao dificultar métodos de detecção de troco.
- **Várias saídas de troco**: Se não for possível evitar o troco, gerar várias saídas de troco ainda pode melhorar a privacidade.

# **Monero: um farol de anonimato**

Monero foi projetada para priorizar a privacidade das transações.

# **Ethereum: gas e transações**

## **Entendendo gas**

Gas mede o esforço computacional necessário para executar operações na Ethereum e é precificado em **gwei**. Por exemplo, uma transação que custa 2,310,000 gwei (ou 0.00231 ETH) envolve um limite de gas e uma taxa base, além de uma taxa de prioridade para incentivar a inclusão pelo validador. Os usuários podem definir uma taxa máxima para evitar pagar a mais, e o excedente é reembolsado.<sup>[[5]](#references)</sup>

## **Execução de transações**

As transações na Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuários ou de smart contracts. Elas exigem uma taxa e precisam ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale destacar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para quem deseja usar criptomoedas priorizando privacidade e segurança.

## Red Teaming de Web3 centrado em valor

- Faça o inventário dos componentes que controlam valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas relevantes do MITRE AADAPT a fim de expor caminhos de escalada de privilégios.
- Ensaie cadeias de ataque com flash-loan/oracle/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura Web3

- A adulteração da supply chain de interfaces de carteiras pode alterar payloads EIP-712 imediatamente antes da assinatura, coletando assinaturas válidas para takeover de proxies baseado em delegatecall (por exemplo, sobrescrita do slot-0 de Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstração de contas (ERC-4337)

- Modos comuns de falha em smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas sem assinatura, validação com estado, replay de ERC-1271 e esgotamento de taxas por meio de revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Use Mutation testing para encontrar pontos cegos em conjuntos de testes:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / guests de zkVM

Quando um prover usa uma **zkVM** ou um circuito de prova específico da aplicação para atestar uma alegação, o verificador só aprende que o **programa guest foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma prova válida, embora as **métricas públicas ou o invariante alegado sejam falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de guests de provas

- Trate os bytes de witness/circuito privados como **entrada não confiável controlada por um atacante**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados fora de banda.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente sobre esse valor se torna suspeito.

### Bypass de contadores por tabela de saltos/UB

Se Rust compilar um `match` grande em uma **tabela de saltos**, um discriminante inválido de enum pode produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo indexa além da primeira tabela de saltos e chega a um trecho de código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que relatam métricas impossíveis, como menos gates, menos operações dispendiosas ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure enums controlados pelo atacante e desserializados a partir de dados witness/entrada privada.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/tipo.
- Considere a combinação de `unsafe` + desserialização sem verificações + despacho de opcode grande como de alto risco.
- Faça engenharia reversa do binário gerado quando necessário; o layout da tabela de saltos pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes às quânticas, garanta que os operandos que precisam ser distintos sejam de fato restringidos para que sejam distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

torna-se inseguro se o guest não rejeitar:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Nesse caso, a transição se reduz a:

```text
q = q ^ (q & q) = 0
```

Isso cria uma **primitiva de reset determinística**, quebrando as premissas de reversibilidade e possibilitando cálculos não intencionais com menor custo. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam as verificações funcionais enquanto contornam o modelo de custo que o verificador acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers do guest com codificações malformadas de witness/entrada privada.
- Verifique a validação do intervalo do enum antes do despacho de opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas inválidas de instrução.
- Compare os contadores informados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Autorização Dependente do Estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se estiver pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps com cruzamento de limites amplificados por flash loans), confira:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados com múltiplos ativos que armazenam saldos virtuais em cache e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prova de participação - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chave pública e chave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [O que são transações com múltiplas assinaturas? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transações | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e taxas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidade - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos a prova de conhecimento zero da Google sobre criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curvas elípticas contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de prova de conceito da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
