# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Contratos Inteligentes** são programas executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são construídas sobre contratos inteligentes e contam com uma interface front-end intuitiva e um back-end transparente e auditável.
- **Tokens e moedas** diferem porque as moedas funcionam como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
  - **Tokens de utilidade** dão acesso a serviços, e **tokens de segurança** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas e oferece serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de exchange descentralizadas e organizações autônomas descentralizadas.

## Mecanismos de Consenso

Os mecanismos de consenso garantem que as transações na blockchain sejam validadas de forma segura e consensual:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com o PoW.<sup>[[1]](#references)</sup>

## Fundamentos do Bitcoin

### Transações

As transações de Bitcoin transferem fundos entre endereços. Elas são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes principais:

- **Transações multisignature** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **taxas** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Busca melhorar a escalabilidade do Bitcoin permitindo várias transações em um canal e transmitindo à blockchain apenas o estado final.

## Preocupações com a Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Como Adquirir Bitcoins Anonimamente

Os métodos incluem transações em dinheiro, mineração e uso de mixers. **CoinJoin** mistura várias transações para dificultar o rastreamento, enquanto **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários costumam ser motivo de preocupação. Veja uma visão geral simplificada de alguns métodos comuns que atacantes podem usar para comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Em geral, é raro que inputs de usuários diferentes sejam combinados em uma única transação, devido à complexidade envolvida. Por isso, **costuma-se presumir que dois endereços de input na mesma transação pertencem ao mesmo proprietário**.

## **UTXO Change Address Detection**

Uma UTXO, ou **saída de transação não gasta**, precisa ser totalmente gasta em uma transação. Se apenas parte dela for enviada a outro endereço, o restante vai para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo sua privacidade.

### Exemplo

Para reduzir esse risco, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a titularidade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise de Grafos de Transações**

As transações podem ser representadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística se baseia na análise de transações com vários inputs e outputs para tentar identificar qual output é o troco que retorna ao remetente.

### Exemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se adicionar mais inputs fizer com que o valor de troco seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, na esperança de que o destinatário as combine com outros inputs em transações futuras, vinculando assim os endereços.

### Comportamento Correto da Carteira

As carteiras devem evitar usar moedas recebidas em endereços já usados e vazios para prevenir esse leak de privacidade.

## **Outras Técnicas de Análise de Blockchain**

- **Valores Exatos de Pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Valores Redondos:** Um valor redondo em uma transação sugere que ela é um pagamento, sendo provável que o output com valor não redondo seja o troco.
- **Fingerprinting de Carteira:** Carteiras diferentes têm padrões exclusivos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de troco.
- **Correlações de Valor e Horário:** Divulgar horários ou valores de transações pode torná-las rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente verdadeiro se uma entidade operar muitos nós de Bitcoin, aumentando sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Anônimas de Bitcoin

## Como Obter Bitcoins Anonimamente

- **Transações em Dinheiro:** Adquirir bitcoin usando dinheiro em espécie.
- **Alternativas ao Dinheiro:** Comprar gift cards e trocá-los por bitcoin online.
- **Mineração:** O método mais privado para ganhar bitcoins é por meio da mineração, especialmente quando feita individualmente, pois os mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outra forma de adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Serviços de Mixing

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **outros bitcoins em troca**, o que dificulta rastrear o proprietário original. No entanto, isso exige confiar que o serviço não mantenha logs e realmente devolva os bitcoins. Casinos de Bitcoin são uma alternativa para mixing.

## CoinJoin

**CoinJoin** combina várias transações de usuários diferentes em uma só, dificultando a tarefa de quem tenta associar inputs a outputs. Apesar de sua eficácia, transações com valores exclusivos de inputs e outputs ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contracts do Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante de CoinJoin, **PayJoin** (ou P2EP), disfarça uma transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação comum, sem os outputs iguais característicos de CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum dos inputs usada por entidades de vigilância de transações.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transações como a acima poderiam ser PayJoin, aumentando a privacidade sem deixar de ser indistinguíveis de transações bitcoin padrão.

**O uso de PayJoin poderia prejudicar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade das transações.

# Boas práticas para privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Nó completo**: Ao baixar a blockchain inteira, um nó completo garante o máximo de privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário tem interesse.
- **Filtragem de blocos no cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem revelar interesses específicos aos observadores da rede. Carteiras leves baixam esses filtros e buscam blocos completos apenas quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar o Tor para mascarar seu endereço IP e aumentar a privacidade ao interagir com a rede.

## **Como evitar a reutilização de endereços**

Para proteger a privacidade, é essencial usar um endereço novo em cada transação. A reutilização de endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para a privacidade das transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, frustrando ataques à privacidade.
- **Como evitar o troco**: Optar por transações que não exigem saídas de troco aumenta a privacidade ao dificultar métodos de detecção de troco.
- **Múltiplas saídas de troco**: Se não for possível evitar o troco, gerar várias saídas de troco ainda pode melhorar a privacidade.

# **Monero: um farol de anonimato**

O Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: gas e transações**

## **Entendendo o gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum e é precificado em **gwei**. Por exemplo, uma transação que custa 2,310,000 gwei (ou 0.00231 ETH) envolve um limite de gas e uma taxa base, além de uma taxa de prioridade para incentivar a inclusão pelo validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais; o excedente é reembolsado.<sup>[[5]](#references)</sup>

## **Executando transações**

As transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contract. Elas exigem uma taxa e precisam ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale notar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para quem deseja interagir com criptomoedas priorizando a privacidade e a segurança.

## Red Teaming Web3 centrado em valor

- Faça o inventário dos componentes que movimentam valor (signatários, oráculos, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas relevantes do MITRE AADAPT para revelar caminhos de escalonamento de privilégios.
- Ensaie cadeias de ataque com flash loans/oráculos/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura Web3

- A adulteração da cadeia de suprimentos de interfaces de carteiras pode alterar payloads EIP-712 imediatamente antes da assinatura, obtendo assinaturas válidas para assumir o controle de proxies baseados em delegatecall (por exemplo, sobrescrita do slot 0 de masterCopy do Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstração de conta (ERC-4337)

- Os modos comuns de falha em smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas sem assinatura, validação com estado, replay de ERC-1271 e drenagem de taxas por meio de revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Testes de mutação para encontrar pontos cegos em conjuntos de testes:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / guests de zkVM

Quando um provador usa uma **zkVM** ou um circuito de prova específico da aplicação para atestar uma afirmação, o verificador só aprende que o **programa guest foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um provador malicioso poderá gerar uma prova válida mesmo que as **métricas públicas ou o invariante declarado sejam falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura em guests de provas

- Trate witness privado/bytes do circuito como **entrada não confiável controlada por um atacante**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com helpers sem validação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados por outro meio.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente sobre esse valor se torna suspeito.

### Bypass de contadores por jump table / UB

Se o Rust compilar um `match` grande como uma **jump table**, um discriminante de enum inválido pode resultar em **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo indexa além da primeira jump table e chega ao código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que relatam métricas impossíveis, como menos gates, menos operações caras ou outros recursos limitados falsificados.

Lista de verificação da revisão:

- Procure enums controlados por atacantes e desserializados a partir de witness/entrada privada.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Trate `unsafe` + desserialização sem verificações + despacho de opcode grande como uma combinação de alto risco.
- Faça engenharia reversa do binário emitido quando necessário; o layout da jump table pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes aos quânticos, garanta que os operandos que devem ser distintos sejam realmente restringidos para serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

torna-se inseguro se o convidado não rejeitar:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Nesse caso, a transição colapsa em:

```text
q = q ^ (q & q) = 0
```

Isso cria uma **primitiva de reset determinística**, quebrando as suposições de reversibilidade e permitindo computações não pretendidas mais baratas. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custos que o verificador acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers guest com codificações malformadas de witness/entradas privadas.
- Garanta a validação dos limites de enum antes do despacho de opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas de instrução inválidas.
- Compare os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest estiver com bugs.

## Autorização Dependente do Estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se estiver pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps com amplificação por flash loan que cruzam limites), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multiativos que armazenam em cache saldos virtuais e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prova de participação - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chave pública e chave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [O que são transações multisig? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transações | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e taxas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidade - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos a prova de conhecimento zero do Google para criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curva elíptica contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de prova de conceito da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
