# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Contratos Inteligentes** são programas executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são construídas com base em contratos inteligentes e contam com uma interface amigável para o usuário e um back-end transparente e auditável.
- **Tokens e moedas** diferem porque as moedas funcionam como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
  - **Utility Tokens** dão acesso a serviços, e **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas e oferece serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de exchange descentralizadas e organizações autônomas descentralizadas.

Para ver a terminologia de ordens à vista, futuros, alavancagem e opções usada nos mercados de cripto, consulte [Termos de Investimento](investment-terms.md).

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende do poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com o PoW.<sup>[[1]](#references)</sup>

## Noções Básicas sobre Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. Elas são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes Principais:

- **Transações Multisig** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **entradas** (origem dos fundos), **saídas** (destino), **taxas** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Busca ampliar a escalabilidade do Bitcoin, permitindo várias transações em um canal e transmitindo à blockchain apenas o estado final.

## Preocupações com a Privacidade do Bitcoin

Ataques à privacidade, como **Propriedade Comum das Entradas** e **Detecção de Endereços de Troco UTXO**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** aumentam o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Como Adquirir Bitcoins Anonimamente

Os métodos incluem transações em dinheiro, mineração e uso de mixers. O **CoinJoin** combina várias transações para dificultar o rastreamento, enquanto o **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários costumam ser motivo de preocupação. Veja um resumo simplificado de alguns métodos comuns que atacantes podem usar para comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Suposição de Propriedade Comum das Entradas**

Em geral, é raro combinar entradas de usuários diferentes em uma única transação, devido à complexidade envolvida. Por isso, **costuma-se presumir que dois endereços de entrada na mesma transação pertencem ao mesmo proprietário**.

## **Detecção de Endereços de Troco UTXO**

Um UTXO, ou **Saída de Transação Não Gasta**, deve ser gasto integralmente em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar esse problema, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, o que facilita **vincular o endereço ao seu proprietário**.

## **Análise do Grafo de Transações**

As transações podem ser representadas visualmente como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Heurística de Entradas Desnecessárias (Heurística de Troco Ótimo)**

Essa heurística se baseia na análise de transações com várias entradas e saídas para tentar identificar qual saída é o troco devolvido ao remetente.

### Exemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se adicionar mais inputs fizer com que o change output seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Reutilização Forçada de Endereços**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, na esperança de que o destinatário as combine com outros inputs em transações futuras, vinculando assim os endereços entre si.

### Comportamento Correto da Wallet

As wallets devem evitar usar coins recebidos em endereços já usados e vazios para prevenir esse privacy leak.

## **Outras Técnicas de Análise de Blockchain**

- **Valores Exatos de Pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Números Redondos:** Um número redondo em uma transação sugere que se trata de um pagamento, sendo provável que o output com valor não redondo seja o troco.
- **Fingerprinting de Wallets:** Wallets diferentes têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e possivelmente o endereço de troco.
- **Correlações de Valores e Horários:** Divulgar horários ou valores de transações pode torná-las rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente válido se uma entidade operar muitos nós Bitcoin, o que aumenta sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques à privacidade e defesas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Bitcoin Anônimas

## Maneiras de Obter Bitcoins Anonimamente

- **Transações em Dinheiro:** Obter bitcoin usando dinheiro em espécie.
- **Alternativas ao Dinheiro:** Comprar cartões-presente e trocá-los online por bitcoin.
- **Mineração:** A maneira mais privada de ganhar bitcoins é por meio da mineração, especialmente quando feita individualmente, pois os pools de mineração podem conhecer o endereço IP do minerador. [Informações sobre pools de mineração](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outra maneira de obtê-lo anonimamente, embora seja ilegal e não recomendado.

## Serviços de Mixing

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **outros bitcoins em troca**, dificultando o rastreamento do proprietário original. No entanto, isso exige confiar que o serviço não mantenha logs e realmente devolva os bitcoins. Opções alternativas de mixing incluem cassinos Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de usuários diferentes em uma só, dificultando a correspondência entre inputs e outputs. Apesar de sua eficácia, transações com tamanhos únicos de input e output ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contracts Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação comum, sem os outputs iguais característicos do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum dos inputs usada por entidades que monitoram transações.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transações como a acima poderiam ser PayJoin, aumentando a privacidade e permanecendo indistinguíveis de transações padrão de bitcoin.

**A utilização de PayJoin poderia prejudicar significativamente os métodos tradicionais de vigilância**, tornando-a um desenvolvimento promissor na busca pela privacidade transacional.

# Boas práticas de privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Nó completo**: Ao baixar toda a blockchain, um nó completo garante o máximo de privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário tem interesse.
- **Filtragem de blocos no lado do cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Carteiras leves baixam esses filtros e só buscam blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP e aumentar a privacidade ao interagir com a rede.

## **Prevenção da reutilização de endereços**

Para proteger a privacidade, é fundamental usar um novo endereço em cada transação. A reutilização de endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para privacidade nas transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação e impedir ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem saídas de troco aumenta a privacidade ao prejudicar os métodos de detecção de troco.
- **Múltiplas saídas de troco**: Se não for possível evitar o troco, gerar várias saídas de troco ainda pode melhorar a privacidade.

# **Monero: um farol de anonimato**

Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: gas e transações**

## **Entendendo o gas**

Gas mede o esforço computacional necessário para executar operações na Ethereum, com preço em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, além de uma taxa de prioridade para incentivar sua inclusão por um validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais; o excedente é reembolsado.<sup>[[5]](#references)</sup>

## **Execução de transações**

As transações na Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuários ou de smart contracts. Elas exigem uma taxa e precisam ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale notar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para quem deseja usar criptomoedas priorizando a privacidade e a segurança.

## Red Teaming de valor no Web3

- Faça o inventário dos componentes que movimentam valor (signatários, oráculos, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas MITRE AADAPT relevantes para expor caminhos de escalada de privilégios.
- Ensaie cadeias de ataque com flash loans, oráculos, credenciais e ataques cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura no Web3

- A adulteração da cadeia de suprimentos das interfaces de carteiras pode modificar payloads EIP-712 imediatamente antes da assinatura, obtendo assinaturas válidas para takeover de proxies baseados em delegatecall (por exemplo, sobrescrita do slot 0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstração de contas (ERC-4337)

- Modos de falha comuns em smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas sem assinatura, validação com estado, replay de ERC-1271 e drenagem de taxas por meio de revert após a validação.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Testes de mutação para encontrar pontos cegos nas suítes de teste:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / guests de zkVM

Quando um provador usa uma **zkVM** ou um circuito de prova específico de uma aplicação para atestar uma afirmação, o verificador só está aprendendo que o **programa guest foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um provador malicioso poderá gerar uma prova que seja validada embora as **métricas públicas ou o invariante alegado sejam falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de guests de prova

- Trate os bytes privados do witness/circuito como **entrada não confiável controlada por um atacante**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados por outro meio.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente sobre esse valor se torna suspeito.

### Bypass de jump table / UB

Se Rust compilar um `match` grande como uma **jump table**, um discriminante de enum inválido pode causar **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo acessa uma posição além da primeira jump table e cai em código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que relatam métricas impossíveis, como menos gates, menos operações caras ou outros recursos limitados falsificados.

Lista de verificação:

- Procure enums controlados pelo atacante e desserializados a partir de witness/entrada privada.
- Inspecione declarações `match` repetidas sobre o mesmo campo de opcode/kind.
- Trate `unsafe` + desserialização sem verificação + despacho de opcode grande como uma combinação de alto risco.
- Faça engenharia reversa do binário emitido quando necessário; o layout da jump table pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes aos quânticos, certifique-se de que os operandos que precisam ser distintos sejam realmente restringidos para serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

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

Isso cria uma **primitiva de redefinição determinística**, quebrando as suposições de reversibilidade e possibilitando cálculos não intencionais mais baratos. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custo que o verificador acredita estar sendo aplicado.

### Advice do provador sub-restringido e aritmética modular

Os valores carregados de uma **pilha de advice/testemunhos são controlados pelo provador**, mesmo quando são descritos como quocientes, restos, inversos ou dicas pré-calculados. Uma prova apenas estabelece que o testemunho satisfaz as restrições implementadas; não estabelece que o cálculo pretendido foi realizado se essas restrições omitem uma verificação de tipo, intervalo ou forma canônica.<sup>[[13]](#references)</sup>

Para uma redução ou função auxiliar de divisão euclidiana, audite a relação inteira completa, não apenas a subtração ou multiplicação final. Cada limb de `q` e `r` deve estar restrito à largura declarada, a reconstrução `x = q * m + r` deve valer na representação inteira pretendida, e o limite canônico `0 <= r < m` deve ser aplicado. Valide um valor **antes** de passá-lo a uma instrução mais estreita `u32`/`u64`; uma operação de largura reduzida não prova retroativamente que o elemento de campo original ou o valor de múltiplos limbs tinha o tipo esperado.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

A falha `mod_12289` no Miden ilustra o padrão de exploit: o quociente era verificado como um valor de 64 bits com dois limbs, mas o resto fornecido por advice chegava a `u32overflowing_sub` sem validação equivalente. Um prover malicioso poderia coordenar valores inválidos de quociente/resto para que as restrições de subtração implementadas continuassem satisfeitas, enquanto o procedimento retornava um resto não matemático. Como esse resultado alimentava a verificação Falcon, a falha de soundness podia ser escalada para falsificar assinaturas de autorização, em vez de apenas produzir um resultado aritmético incorreto.<sup>[[13]](#references)</sup>

### Auditoria de VMs criptográficas com pilha implícita

Linguagens baseadas em pilha ocultam operandos; portanto, primeiro converta as instruções em uma IR na qual cada valor consumido e produzido pela pilha seja uma expressão com proveniência. Em seguida, um pipeline de análise conservador pode:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construir o grafo de chamadas e inferir os efeitos das procedures sobre a pilha de entrada/saída.
2. Executar simbolicamente as instruções compatíveis e converter o fluxo de controle em expressões SSA/estruturadas.
3. Propagar fatos abstratos como `Unknown`, `ProvenU32`, `Bool`, proveniência de valores e inicialização local até atingir um ponto fixo.
4. Sinalizar valores derivados de advice que chegam a operações aritméticas tipadas ou sinks que exigem valores diferentes de zero sem um sanitizer em **todos** os caminhos de entrada.
5. Comparar as assinaturas declaradas e inferidas e verificar se cada saída preserva os valores da pilha pertencentes ao chamador.

Trate uma assinatura desconhecida ou uma construção não compatível como uma **lacuna de análise**, não como um resultado limpo. Chamadas dinâmicas, loops que não preservam a pilha e branches com efeitos diferentes sobre a pilha podem impossibilitar o rastreamento confiável das posições da pilha; um decompiler mais seguro rejeita ou marca esses casos em vez de gerar pseudocódigo plausível, porém incorreto.<sup>[[10]](#references)[[13]](#references)</sup>

Nas junções do fluxo de controle, mantenha uma propriedade apenas quando ela for válida em todos os predecessores (por exemplo, `ProvenU32 join Unknown = Unknown`). Diferencie também a convergência do ponto fixo de atingir um limite de iterações: somente uma sobreaproximação convergida e confiável pode justificar tratar a ausência de um diagnóstico como evidência de que todas as execuções representadas satisfazem a propriedade.<sup>[[11]](#references)</sup>

### Use obrigações de prova para expor precondições ocultas

Para conjuntos pequenos de instruções, traduza os procedimentos em um modelo executável de VM formal e prove tanto o resultado quanto a transformação completa da pilha. O teorema deve cobrir a terminação, as entradas tipadas, o prefixo de saída esperado e a preservação da pilha do chamador que não foi modificada. Audite a declaração do teorema com o mesmo cuidado que a prova: o kernel pode validar uma prova de uma afirmação enfraquecida por acidente.<sup>[[12]](#references)[[13]](#references)</sup>

Hipóteses inesperadas são descobertas úteis. Na revisão do Miden, uma prova para rotação à direita de 64 bits exigiu `shift mod 32 != 0`, revelando um caso-limite que falhava para entradas grandes quando o deslocamento era múltiplo de 32; outra prova descobriu que `wrapping_mul` de 256 bits descartava valores da pilha pertencentes ao chamador. Adicione o caso-limite descoberto aos testes e, em seguida, corrija a implementação ou fortaleça deliberadamente a precondição pública, em vez de aceitar silenciosamente a suposição adicional.<sup>[[12]](#references)[[13]](#references)</sup>

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers do guest com codificações malformadas de witness/entrada privada.
- Verifique a validação do intervalo do enum antes do despacho do opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas inválidas de instrução.
- Rastreie cada origem de advice/witness até cada sink aritmético tipado e exija validação em todos os caminhos.<sup>[[11]](#references)[[13]](#references)</sup>
- Teste helpers aritméticos com limbs não canônicos, restos fora do intervalo e valores-limite para deslocamentos.<sup>[[12]](#references)[[13]](#references)</sup>
- Verifique a altura da pilha e a preservação dos valores abaixo dos argumentos declarados do procedimento em cada retorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Compare os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Autorização dependente do estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se estiver pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps amplificados por flash loan que cruzam limites), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados com múltiplos ativos que armazenam em cache saldos virtuais e podem ser envenenados quando `supply == 0`, consulte:

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
- [7] [Trail of Bits - Superamos a prova de conhecimento zero do Google sobre criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Proteção de criptomoedas de curva elíptica contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de prova de conceito da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arquitetura do decompiler MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Mecanismo de análise estática MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modelo MASM-to-Lean e provas de correção](https://github.com/trailofbits/masm-lean)
- [13] [Auditoria na era da IA (boa o suficiente)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
