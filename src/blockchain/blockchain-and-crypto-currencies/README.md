# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos básicos

- **Contratos inteligentes** são programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações descentralizadas (dApps)** são construídas sobre contratos inteligentes e contam com uma interface front-end fácil de usar e um back-end transparente e auditável.
- **Tokens e moedas** diferem porque as moedas funcionam como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
  - **Tokens de utilidade** dão acesso a serviços, e **tokens de segurança** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas e oferece serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de exchange descentralizadas e organizações autônomas descentralizadas.

## Mecanismos de consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com o PoW.<sup>[[1]](#references)</sup>

## Fundamentos do Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. Elas são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes principais:

- **Transações multisig** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **entradas** (origem dos fundos), **saídas** (destino), **taxas** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo aumentar a escalabilidade do Bitcoin, permitindo várias transações dentro de um canal e transmitindo à blockchain apenas o estado final.

## Preocupações com a privacidade do Bitcoin

Ataques à privacidade, como **Propriedade comum das entradas** e **Detecção de endereço de troco de UTXO**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** aumentam o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Obtendo Bitcoins anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. O **CoinJoin** combina várias transações para dificultar o rastreamento, enquanto o **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos ataques à privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários costumam ser motivo de preocupação. Veja um resumo simplificado de alguns métodos comuns que atacantes podem usar para comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Hipótese de propriedade comum das entradas**

Geralmente, é raro combinar entradas de diferentes usuários em uma única transação devido à complexidade envolvida. Por isso, **costuma-se supor que dois endereços de entrada na mesma transação pertencem ao mesmo proprietário**.

## **Detecção de endereço de troco de UTXO**

Um UTXO, ou **saída de transação não gasta**, deve ser gasto integralmente em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem supor que esse novo endereço pertence ao remetente, comprometendo sua privacidade.

### Exemplo

Para mitigar isso, serviços de mistura ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em redes sociais e fóruns**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise do grafo de transações**

As transações podem ser representadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Heurística de entrada desnecessária (heurística de troco ideal)**

Essa heurística se baseia na análise de transações com várias entradas e saídas para tentar adivinhar qual saída é o troco que retorna ao remetente.

### Exemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se a adição de mais entradas fizer com que a saída de troco seja maior do que qualquer entrada individual, isso pode confundir a heurística.

## **Reutilização forçada de endereços**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, na esperança de que o destinatário as combine com outras entradas em transações futuras, vinculando assim os endereços entre si.

### Comportamento correto da carteira

As carteiras devem evitar usar moedas recebidas em endereços vazios que já foram usados para prevenir esse vazamento de privacidade.

## **Outras técnicas de análise de blockchain**

- **Valores exatos de pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Valores redondos:** Um valor redondo em uma transação sugere que se trata de um pagamento, e que a saída com valor não redondo provavelmente é o troco.
- **Identificação da carteira:** Diferentes carteiras têm padrões exclusivos de criação de transações, permitindo que analistas identifiquem o software usado e, possivelmente, o endereço de troco.
- **Correlações entre valores e horários:** A divulgação dos horários ou valores das transações pode torná-las rastreáveis.

## **Análise de tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente válido se uma entidade operar muitos nós Bitcoin, ampliando sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques à privacidade e defesas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações anônimas de Bitcoin

## Maneiras de obter bitcoins anonimamente

- **Transações em dinheiro:** Obter bitcoin usando dinheiro em espécie.
- **Alternativas ao dinheiro:** Comprar cartões-presente e trocá-los online por bitcoin.
- **Mineração:** A maneira mais privada de ganhar bitcoins é por meio da mineração, especialmente quando feita individualmente, pois pools de mineração podem conhecer o endereço IP do minerador. [Informações sobre pools de mineração](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outra maneira de obtê-lo anonimamente, embora isso seja ilegal e não seja recomendado.

## Serviços de mixing

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **outros bitcoins em troca**, o que dificulta rastrear o proprietário original. No entanto, isso exige confiar que o serviço não mantenha logs e realmente devolva os bitcoins. Outras opções de mixing incluem cassinos de Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de diferentes usuários em uma só, dificultando o processo para quem tenta associar entradas a saídas. Apesar de sua eficácia, transações com valores exclusivos de entrada e saída ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contracts do Ethereum que separa depósitos de saques posteriores, veja [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação normal, sem as saídas iguais características do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum das entradas usada por entidades que monitoram transações.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transações como a acima poderiam ser PayJoin, aumentando a privacidade e permanecendo indistinguíveis das transações bitcoin padrão.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca por privacidade nas transações.

# Boas práticas para privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Full node**: Ao baixar toda a blockchain, um full node garante o máximo de privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem quais transações ou endereços interessam ao usuário.
- **Filtragem de blocos no cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Carteiras leves baixam esses filtros e só buscam blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar o Tor para mascarar seu endereço IP e aumentar a privacidade ao interagir com a rede.

## **Prevenção da reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço para cada transação. A reutilização de endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As carteiras modernas desestimulam a reutilização de endereços por meio de seu design.

## **Estratégias para a privacidade das transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação e impedir ataques à privacidade.
- **Evitar troco**: Optar por transações que não exijam outputs de troco aumenta a privacidade ao prejudicar os métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se não for possível evitar o troco, gerar vários outputs de troco ainda pode melhorar a privacidade.

# **Monero: um farol de anonimato**

O Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: gas e transações**

## **Entendendo gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum e é precificado em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, além de uma taxa de prioridade para incentivar sua inclusão por um validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais; o excedente é reembolsado.<sup>[[5]](#references)</sup>

## **Execução de transações**

As transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuários ou de smart contracts. Elas exigem uma taxa e precisam ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale destacar que o endereço do remetente é deduzido da assinatura, dispensando sua inclusão nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para quem deseja utilizar criptomoedas priorizando a privacidade e a segurança.

## Value-Centric Web3 Red Teaming

- Faça um inventário dos componentes que movimentam valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas MITRE AADAPT relevantes a fim de expor caminhos de escalonamento de privilégios.
- Simule cadeias de ataque com flash-loan/oracle/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura Web3

- A adulteração da supply chain das interfaces de carteira pode alterar payloads EIP-712 imediatamente antes da assinatura, obtendo assinaturas válidas para takeovers de proxy baseados em delegatecall (por exemplo, sobrescrita do slot-0 de masterCopy do Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos comuns de falha em smart accounts incluem ignorar o controle de acesso do `EntryPoint`, campos de gas sem assinatura, validação com estado, replay de ERC-1271 e drenagem de taxas por meio de revert após a validação.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Use mutation testing para encontrar pontos cegos nas suítes de testes:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / guests de zkVM

Quando um prover usa uma **zkVM** ou um circuito de prova específico da aplicação para atestar uma afirmação, o verificador só fica sabendo que o **programa guest foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma prova válida mesmo que as **métricas públicas ou a invariante alegada sejam falsas**.<sup>[[7]](#references)</sup>

### Desserialização insegura em guests de prova

- Trate bytes de witness/circuito privados como **entrada não confiável controlada por um atacante**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados fora de banda.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora dos limites**, todo `match` subsequente sobre esse valor se torna suspeito.

### Bypass de contadores por jump table / UB

Se Rust converter um `match` grande em uma **jump table**, um discriminante de enum inválido pode produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora dos limites indexa além da primeira jump table e chega a um trecho de código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que informam métricas impossíveis, como menos gates, menos operações caras ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure enums controlados pelo atacante e desserializados a partir de witness/entrada privada.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Trate `unsafe` + desserialização sem validação + dispatch de opcode grande como uma combinação de alto risco.
- Faça engenharia reversa do binário emitido quando necessário; o layout da jump table pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes a quânticos, garanta que os operandos que devem ser distintos sejam realmente restringidos para serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

torna-se inseguro se o sistema convidado não rejeitar:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Nesse caso, a transição se reduz a:

```text
q = q ^ (q & q) = 0
```

Isso cria uma **primitiva de reset determinística**, quebrando as premissas de reversibilidade e permitindo cálculos não intencionais mais baratos. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custos que o verificador acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers guest com codificações malformadas de witness/entrada privada.
- Valide os intervalos de enum antes do despacho de opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas de instrução inválidas.
- Compare os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Autorização Dependente do Estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se estiver pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps com flash-loan que cruzam limites), confira:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados de múltiplos ativos que armazenam saldos virtuais em cache e podem ser envenenados quando `supply == 0`, estude:

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
- [7] [Trail of Bits - Superamos a prova de conhecimento zero do Google para criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curva elíptica contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de prova de conceito da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
