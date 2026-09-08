# Pagamentos digitais privados

A privacidade de pagamentos é a divulgação controlada dos dados de uma transação. Ela não é uma forma de legitimar fundos ilegais, sonegar impostos ou sanções, burlar KYC, usar identidades falsas ou ocultar um engagement não autorizado. Um pagamento pode ser privado em relação a um merchant e, ainda assim, permanecer totalmente visível para um issuer, uma network, um empregador, uma autoridade fiscal ou um investigador.

O [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) é o inventário normalizado com `Pros`, `Cons`, `Procedure` passo a passo e lawful, e `Detection` para cada família. Esta página amplia os métodos de pagamento convencionais.

{% hint style="danger" %}
Nunca use contas roubadas, identidades sintéticas, money mules, residência fictícia ou declarações falsas de origem dos fundos, divisão de transações (“structuring”) ou brokers opacos de “no-KYC card”. Verifique a legislação vigente e os termos dos providers em todas as jurisdições relevantes.
{% endhint %}

## Defina a propriedade de privacidade

Identifique o observador antes de escolher um rail:

| Observador | Dados típicos | Controle útil | O que permanece |
|---|---|---|---|
| Merchant | Nome, e-mail, endereço, token do cartão, IP/dispositivo, cesta | Guest checkout, dados opcionais mínimos, virtual card específico para o merchant | Dados de entrega, conta e telemetria antifraude |
| Issuer/payment processor | Identidade legal, origem dos fundos, merchant, valor, horário, dispositivo | Escolher um provider regulado com bons termos de privacidade/segurança | O provider ainda processa e pode reter/divulgar registros |
| Empregador/dono do engagement | Despesa, operador e finalidade | Orçamento separado do engagement e ledger com controle de acesso | A governança legítima exige atribuição interna |
| Observador de blockchain pública | Endereços, fluxos, valores e horários, dependendo da chain | Protocolo adequado e disciplina de wallet | Aquisição, endpoints e gastos posteriores podem relinkar a atividade |
| Operador de network/RPC/node | IP, consultas da wallet, broadcasts de transações | Node local ou network de privacidade adequada | O timing e o comportamento do endpoint ainda podem ser correlacionados |
| Observador físico | Rosto, localização, veículo, CCTV, recibo | Privacidade situacional comum | Cash não torna uma pessoa fisicamente invisível |

O CFPB descreve payment apps como capazes de coletar dados de identidade, dispositivo, localização, contatos, transações e comportamento; as regras estaduais de privacidade não impedem necessariamente a monetização ou todo uso secundário.<sup>[[1]](#references)</sup> Leia o aviso real do provider em vez de inferir privacidade a partir do nome de um produto.

## Compare os métodos de pagamento

| Método | Benefício de privacidade | Principais observadores/links | Uso apropriado |
|---|---|---|---|
| Cash | Nenhum ledger de payment network | Destinatário, câmeras, testemunhas, regras de declaração de cash | Compras locais legais onde aceito |
| Open-loop prepaid/gift card | Separa o número do cartão de um cartão principal | Vendedor, provider de ativação/registro, origem dos fundos, merchant | Orçamento ou compartimentalização limitada por merchant |
| Virtual/one-time card number | Oculta o PAN reutilizável do merchant; revogação fácil | O issuer ainda conhece a identidade e a transação | Compartimentalização de merchants online |
| Mobile-wallet token | O dispositivo/merchant recebe um token em vez do PAN subjacente | Wallet provider, issuer, payment network e merchant | Segurança da credencial, não anonimato |
| Bank transfer/app | Trilha de auditoria conveniente | Bank/app, contraparte e identidade vinculada | Pagamentos organizacionais responsabilizáveis |
| Cryptocurrency | Varia conforme o protocolo; self-custody pode reduzir a exposição ao custodian | Ledger público ou privacy protocol, exchange, endpoint, contraparte | Transferências legais após análise específica do protocolo |

## Cash

Cash ainda é considerado importante para privacidade e inclusão, e evita um registro na payment network.<sup>[[2]](#references)</sup> Ele não impede CCTV, testemunhas, localização do dispositivo, recibos, rastreamento por número de série em casos especiais ou declarações legais.

### Fluxo legal

1. Verifique a aceitação e os limites locais de cash antes da transação. Os limites variam por país e tipo de parte e mudam com o tempo.
2. Faça a compra comum em uma única transação honesta. **Nunca a divida** para evitar um limite ou declaração.
3. Recuse o rastreamento opcional de loyalty ou a coleta para marketing. Forneça de forma verdadeira os dados exigidos para garantia, segurança, entrega, impostos ou por lei.
4. Mantenha o comprovante de compra necessário e os registros contábeis exigidos em armazenamento criptografado, com uma data de retenção.
5. Para uma organização, solicite o reembolso pelo processo aprovado e registre operador, autorização, finalidade, valor, data e recibo.

Nos Estados Unidos, determinadas atividades comerciais ou profissionais devem apresentar o Form 8300 para recebimentos em cash superiores a US$ 10.000, incluindo transações relacionadas; separar transações intencionalmente pode constituir structuring ilegal.<sup>[[3]](#references)</sup> Outras jurisdições são diferentes — por exemplo, a Espanha publica sua própria restrição legal a pagamentos em cash.<sup>[[4]](#references)</sup>

## Prepaid e gift cards

“Prepaid” não significa anônimo. Uma loja, issuer, program manager, funding bank e merchant podem correlacionar compra, ativação, dispositivo, IP, localização e gastos. Recargas, acesso a ATM, uso internacional, limites maiores ou proteção contra perda normalmente exigem registro.

A orientação ao consumidor dos EUA explica que os issuers podem solicitar dados de identidade para verificação legal e podem recusar um cartão registrado quando a verificação falha.<sup>[[5]](#references)</sup> As regras da FinCEN definem quais programas prepaid e participantes têm obrigações de AML.<sup>[[6]](#references)</sup> Na UE, as exceções restritas para e-money anônimo foram reduzidas pela Directive (EU) 2018/843; a Regulation (EU) 2024/1624 altera novamente o framework, mas geralmente aplica-se a partir de **10 de julho de 2027**. Portanto, não a descreva como já vigente em 2026.<sup>[[7]](#references)</sup>

Use valor prepaid somente quando obtido legalmente de um issuer identificável, seus termos permitirem o uso pretendido e o benefício for orçamento ou separação de uma credencial de pagamento principal. Evite mercados de revenda e brokers que anunciam cards “no-name” não verificáveis: o valor pode ser roubado, já resgatado, restrito geograficamente ou sujeito a apreensão.

## Virtual cards e wallet tokens

Um virtual card number (VCN) normalmente é emitido por trás de uma conta real e verificada. Números específicos para merchants ou de uso único reduzem o risco de breach e a correlação do PAN entre merchants; eles **não** ocultam a transação do issuer. A tokenização de network substitui de modo semelhante uma credencial de cartão por um token restrito.<sup>[[8]](#references)</sup>

### Fluxo compartimentalizado por merchant

1. Abra uma conta com um issuer regulado usando dados corretos de identidade, residência e funding.
2. Proteja-a com uma senha exclusiva, MFA resistente a phishing quando disponível, alertas de login e recovery codes armazenados offline.
3. Gere um VCN vinculado ao merchant ou de uso único. Defina um limite razoável de valor/tempo, se houver suporte.
4. Use guest checkout e omita apenas campos **opcionais** de perfil, loyalty e marketing. Forneça dados corretos de cobrança, entrega e impostos quando exigidos.
5. Evite fazer login em identity providers não relacionados; use um compartimento de browser do engagement/conta e o network path aprovado.
6. Salve o recibo e o mapeamento entre VCN e finalidade em um ledger interno criptografado.
7. Congele ou revogue o número após o período de refund/chargeback; monitore a conta principal quanto a autorizações inesperadas.

A Capital One e o Google documentam que os números virtuais permanecem vinculados à conta subjacente, enquanto EMVCo/Visa descrevem a tokenização como substituição de credencial e restrição de domínio, e não como anonimato do pagador.<sup>[[8]](#references)</sup>

## Entrega, contas e refunds

O pagamento é apenas uma extremidade do grafo de vinculação:

- Um cartão exclusivo é inutilizado pela reutilização de um e-mail pessoal, telefone, perfil de browser, endereço IP ou conta de loyalty.
- A entrega física normalmente exige um destinatário e uma localização legais. Não use o endereço de uma pessoa não envolvida nem se passe por um residente. Serviços aprovados de recebimento empresarial são mais seguros do que dados fabricados.
- Bens digitais podem registrar identidade da conta, IP, fingerprint do dispositivo, ativação da licença e downloads.
- Refunds normalmente retornam ao rail original. Solicitações para receber fundos e encaminhá-los ou devolvê-los por outro meio são sinais de fraude e money mule.
- Descrições do merchant, texto da invoice e notificações de envio podem expor uma compra sensível a delegados da conta; defina deliberadamente o acesso e os alertas.

## Compras de red team autorizadas

Um engagement deve ser discreto externamente e responsabilizável internamente:

1. Obtenha o escopo por escrito, a finalidade, o limite de gastos, o aprovador, os merchants/assets permitidos e a regra de reembolso.
2. Use uma conta de pagamento controlada pela organização e um VCN ou subaccount separado por engagement ou merchant.
3. Mantenha dados corretos de cobrança e registrant com os providers. A privacidade do registro público pode minimizar a exposição, mas não autoriza mentir.
4. Mantenha um ledger criptografado com operador, aprovação, finalidade, data, valor, contraparte, identificador do asset e recibo.
5. Faça o screening das contrapartes conforme exigido e siga as obrigações do provider, de sanções, fiscais e de declaração.
6. Dê ao setor financeiro somente o acesso necessário; dê aos operadores somente a capacidade limitada de gastos de que precisam.
7. Feche ou congele as credenciais de pagamento durante o teardown, reconcilie cobranças/refunds pendentes e retenha os registros conforme a política.

Para escolhas específicas de crypto, continue em [Cryptocurrency Privacy](cryptocurrency-privacy.md). Para a infraestrutura que essas compras apoiam, consulte [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Checklist de verificação

- [ ] A propriedade de privacidade desejada e os observadores foram registrados.
- [ ] As regras do provider, merchant e jurisdição foram verificadas recentemente.
- [ ] As declarações de identidade e origem dos fundos são verdadeiras.
- [ ] Os dados opcionais do merchant foram minimizados sem impedir a verificação exigida.
- [ ] As vinculações de funding, dispositivo, network, conta, entrega e refund são compreendidas.
- [ ] Não há evasão de limites, contraparte proibida, mule, credencial roubada ou identidade de terceiros envolvida.
- [ ] Recibos, aprovações, registros fiscais e informações de recuperação exigidos estão criptografados e têm controle de acesso.

## References

- [1] [US CFPB — Solicitação de informações sobre a coleta, uso e monetização de dados de pagamentos do consumidor e outros dados financeiros pessoais](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Estudo sobre as atitudes de pagamento dos consumidores na área do euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instruções para o Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Declaração de pagamentos em cash](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Por que estão solicitando informações pessoais para ativar ou registrar um cartão prepaid?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) e [Posso ter um cartão prepaid recusado?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Regra final sobre Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Uso de virtual credit cards](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
