# Pagamentos Digitais Privados

{{#include ../banners/hacktricks-training.md}}

A privacidade de pagamentos é a divulgação controlada de dados de transações. Ela não é uma forma de tornar fundos ilegais legítimos, sonegar impostos ou sanções, burlar KYC, usar identidades falsas ou ocultar um engagement não autorizado. Um pagamento pode ser privado em relação a um comerciante e, ainda assim, permanecer totalmente visível para um emissor, uma rede, um empregador, uma autoridade fiscal ou um investigador.

O [Catálogo de Técnicas de Pagamento Anônimo](anonymous-payment-techniques.md) é o inventário normalizado com `Pros`, `Cons`, `Procedure` passo a passo e lawful, e `Detection` para cada família. Esta página detalha métodos de pagamento convencionais.

{% hint style="danger" %}
Nunca use contas roubadas, identidades sintéticas, money mules, residência fictícia ou declarações falsas sobre a origem dos fundos, divisão de transações (“structuring”) ou brokers opacos de “cartões sem KYC”. Verifique a legislação atual e os termos dos provedores em todas as jurisdições relevantes.
{% endhint %}

## Defina a propriedade de privacidade

Identifique o observador antes de escolher um rail:

| Observador | Dados típicos | Controle útil | O que permanece |
|---|---|---|---|
| Comerciante | Nome, e-mail, endereço, token do cartão, IP/dispositivo, cesta | Checkout como convidado, mínimo de dados opcionais, cartão virtual específico para o comerciante | Dados de entrega, conta e telemetria antifraude |
| Emissor/processador de pagamentos | Identidade legal, origem dos fundos, comerciante, valor, horário, dispositivo | Escolher um provedor regulamentado com bons termos de privacidade/segurança | O provedor ainda processa e pode reter/divulgar registros |
| Empregador/proprietário do engagement | Despesa, operador e finalidade | Orçamento separado para o engagement e ledger com controle de acesso | A governança legítima exige atribuição interna |
| Observador de blockchain pública | Endereços, fluxos, valores e horários, dependendo da chain | Protocolo apropriado e disciplina de wallet | Aquisição, endpoints e gastos posteriores podem reassociar a atividade |
| Operador de rede/RPC/node | IP, consultas da wallet, broadcasts de transações | Node local ou rede de privacidade adequada | O comportamento temporal e dos endpoints ainda pode permitir correlação |
| Observador físico | Rosto, localização, veículo, CCTV, recibo | Privacidade situacional comum | Dinheiro em espécie não torna uma pessoa fisicamente invisível |

O CFPB descreve apps de pagamento como capazes de coletar dados de identidade, dispositivo, localização, contatos, transações e comportamento; as regras estaduais de privacidade não necessariamente impedem a monetização ou todo uso secundário.<sup>[[1]](#references)</sup> Leia o aviso real do provedor em vez de inferir privacidade a partir do nome de um produto.

## Compare métodos de pagamento

| Método | Benefício de privacidade | Principais observadores/conexões | Uso apropriado |
|---|---|---|---|
| Dinheiro em espécie | Nenhum ledger de rede de pagamentos | Beneficiário, câmeras, testemunhas, regras de declaração de dinheiro | Compras locais legítimas onde aceito |
| Cartão pré-pago/gift card open-loop | Separa o número do cartão de um cartão principal | Vendedor, provedor de ativação/registro, origem dos fundos, comerciante | Orçamento ou compartimentalização limitada por comerciante |
| Número de cartão virtual/uso único | Oculta o PAN reutilizável do comerciante; revogação fácil | O emissor ainda conhece a identidade e a transação | Compartimentalização de comerciantes online |
| Token de mobile wallet | Dispositivo/comerciante recebe um token em vez do PAN subjacente | Provedor da wallet, emissor, rede de pagamentos e comerciante | Segurança da credencial, não anonimato |
| Transferência bancária/app | Trilha de auditoria conveniente | Banco/app, contraparte e identidade vinculada | Pagamentos organizacionais sujeitos a responsabilização |
| Cryptocurrency | Varia conforme o protocolo; self-custody pode reduzir a exposição ao custodiante | Ledger público ou protocolo de privacidade, exchange, endpoint, contraparte | Transferências legítimas após análise específica do protocolo |

## Dinheiro em espécie

O dinheiro em espécie ainda é considerado importante para privacidade e inclusão, e evita um registro na rede de pagamentos.<sup>[[2]](#references)</sup> Ele não impede CCTV, testemunhas, localização do dispositivo, recibos, rastreamento de números de série em casos especiais ou declarações exigidas por lei.

### Fluxo lawful

1. Verifique a aceitação e os limites locais para dinheiro em espécie antes da transação. Os limites variam por país e tipo de parte e mudam com o tempo.
2. Faça a compra comum em uma única transação honesta. **Nunca a divida** para evitar um limite ou declaração.
3. Recuse o rastreamento opcional de fidelidade ou a coleta para marketing. Forneça com veracidade os dados exigidos para garantia, segurança, entrega, impostos ou pela lei.
4. Mantenha o comprovante de compra necessário e os registros contábeis exigidos em armazenamento criptografado, com uma data de retenção.
5. Para uma organização, solicite o reembolso pelo processo aprovado e registre operador, autorização, finalidade, valor, data e recibo.

Nos Estados Unidos, determinadas atividades comerciais ou profissionais devem apresentar o Formulário 8300 para recebimentos em dinheiro superiores a US$ 10.000, incluindo transações relacionadas; dividir intencionalmente as transações pode constituir structuring ilegal por si só.<sup>[[3]](#references)</sup> Outras jurisdições são diferentes — por exemplo, a Espanha publica sua própria restrição legal a pagamentos em dinheiro.<sup>[[4]](#references)</sup>

## Cartões pré-pagos e gift cards

“Pré-pago” não significa anônimo. Uma loja, emissor, administrador do programa, banco de funding e comerciante podem correlacionar compra, ativação, dispositivo, IP, localização e gastos. Recargas, acesso a ATM, uso internacional, limites maiores ou proteção contra perda normalmente exigem registro.

As orientações ao consumidor dos EUA explicam que os emissores podem solicitar dados de identidade para verificação legal e podem recusar um cartão registrado quando a verificação falha.<sup>[[5]](#references)</sup> As regras da FinCEN definem quais programas pré-pagos e participantes têm obrigações de AML.<sup>[[6]](#references)</sup> Na UE, as exceções restritas para e-money anônimo foram reduzidas pela Diretiva (UE) 2018/843; o Regulamento (UE) 2024/1624 altera novamente o framework, mas geralmente será aplicável a partir de **10 de julho de 2027**; portanto, não o descreva como já vigente em 2026.<sup>[[7]](#references)</sup>

Use valor pré-pago somente quando obtido legalmente de um emissor identificável, quando seus termos permitirem o uso pretendido e quando o benefício for orçamento ou separação de uma credencial de pagamento principal. Evite mercados de revenda e brokers que anunciem cartões “sem nome” não verificáveis: o valor pode ter sido roubado, já resgatado, estar restrito geograficamente ou sujeito a apreensão.

## Cartões virtuais e tokens de wallet

Um número de cartão virtual (VCN) geralmente é emitido por trás de uma conta real e verificada. Números específicos para comerciantes ou de uso único reduzem o impacto de breaches e a correlação do PAN entre comerciantes; eles **não** ocultam a transação do emissor. A tokenização de rede substitui de forma semelhante uma credencial de cartão por um token limitado.<sup>[[8]](#references)</sup>

### Fluxo compartimentalizado por comerciante

1. Abra uma conta com um emissor regulamentado usando dados corretos de identidade, residência e funding.
2. Proteja-a com uma senha exclusiva, MFA resistente a phishing quando disponível, alertas de login e códigos de recuperação armazenados offline.
3. Gere um VCN bloqueado para o comerciante ou de uso único. Defina um limite razoável de valor/tempo, se houver suporte.
4. Use checkout como convidado e omita apenas campos **opcionais** de perfil, fidelidade e marketing. Forneça dados corretos de cobrança, entrega e impostos quando exigidos.
5. Evite fazer login em provedores de identidade não relacionados; use um compartimento de navegador para o engagement/conta e o caminho de rede aprovado.
6. Salve o recibo e o mapeamento entre VCN e finalidade em um ledger interno criptografado.
7. Congele ou revogue o número após o período de reembolso/chargeback; monitore a conta principal em busca de autorizações inesperadas.

A Capital One e o Google documentam que os números virtuais permanecem vinculados à conta subjacente, enquanto a EMVCo/Visa descreve a tokenização como substituição de credencial e restrição de domínio, e não como anonimato do pagador.<sup>[[8]](#references)</sup>

## Entrega, contas e reembolsos

O pagamento é apenas uma aresta no grafo de vinculação:

- Um cartão exclusivo é inutilizado pela reutilização de e-mail pessoal, telefone, perfil de navegador, endereço IP ou conta de fidelidade.
- A entrega física normalmente exige um destinatário e uma localização legítimos. Não use o endereço de uma pessoa não envolvida nem se passe por um residente. Serviços de recebimento comerciais aprovados são mais seguros do que dados fabricados.
- Bens digitais podem registrar identidade da conta, IP, dispositivo, fingerprint, ativação da licença e downloads.
- Os reembolsos geralmente retornam ao rail original. Solicitações para receber fundos e encaminhá-los/reembolsá-los em outro lugar são um alerta de fraude e money mule.
- Descrições do comerciante, texto da fatura e notificações de envio podem expor uma compra sensível a delegados da conta; configure deliberadamente o acesso e os alertas.

## Compras de Red-Team autorizadas

Um engagement deve ser discreto externamente e sujeito a responsabilização internamente:

1. Obtenha escopo por escrito, finalidade, limite de gastos, aprovador, comerciantes/ativos permitidos e regra de reembolso.
2. Use uma conta de pagamento controlada pela organização e um VCN ou subconta separado por engagement ou comerciante.
3. Mantenha dados corretos de cobrança e registro com os provedores. A privacidade do registro público pode minimizar a exposição, mas não autoriza mentir.
4. Mantenha um ledger criptografado com operador, aprovação, finalidade, data, valor, contraparte, identificador do ativo e recibo.
5. Faça a triagem das contrapartes conforme exigido e siga as obrigações do provedor, de sanções, fiscais e de declaração.
6. Conceda ao setor financeiro apenas o acesso necessário; conceda aos operadores somente a capacidade limitada de gastos necessária.
7. Feche ou congele as credenciais de pagamento durante o teardown, concilie cobranças/reembolsos pendentes e retenha os registros de acordo com a política.

Para escolhas específicas de crypto, continue em [Privacidade de Cryptocurrency](cryptocurrency-privacy.md). Para a infraestrutura mantida por essas compras, consulte [Infraestrutura de Red-Team autorizada](authorized-red-team-infrastructure.md).

## Checklist de verificação

- [ ] A propriedade de privacidade desejada e os observadores foram registrados.
- [ ] As regras do provedor, comerciante e jurisdição foram verificadas recentemente.
- [ ] As declarações de identidade e origem dos fundos são verdadeiras.
- [ ] Os dados opcionais do comerciante foram minimizados sem impedir a verificação exigida.
- [ ] As conexões de funding, dispositivo, rede, conta, entrega e reembolso são compreendidas.
- [ ] Não há envolvimento de evasão de limites, contraparte proibida, mule, credencial roubada ou identidade de terceiros.
- [ ] Recibos, aprovações, registros fiscais e informações de recuperação exigidos estão criptografados e sob controle de acesso.

## References

- [1] [US CFPB — Solicitação de informações sobre a coleta, uso e monetização de dados de pagamentos do consumidor e outros dados financeiros pessoais](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Banco Central Europeu — Estudo sobre as atitudes dos consumidores em relação a pagamentos na área do euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instruções para o Formulário 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Agência Tributária Espanhola — Declaração de pagamentos em dinheiro](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Por que estão me solicitando informações pessoais para ativar ou registrar um cartão pré-pago?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) e [Posso ter um cartão pré-pago recusado?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Regra final sobre acesso pré-pago](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Diretiva (UE) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Uso de cartões de crédito virtuais](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
