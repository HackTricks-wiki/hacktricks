# Infraestrutura de Red Team Autorizada

{{#include ../banners/hacktricks-training.md}}

Para dispositivos duráveis no local, use o design [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) e o runbook de suspeita de descoberta.

Para um red team profissional, o objetivo é a **atribuição controlada**, não a imunidade à responsabilização. O alvo não deve ver trivialmente o IP residencial ou as contas pessoais de um operador, enquanto o responsável pelo engagement deve conseguir identificar a origem, interromper a operação, lidar com denúncias de abuso, preservar evidências e comprovar a autorização.

Esta página é a baseline de deployment para um engagement legal. Para o tradecraft de adversários que ela pretende emular — incluindo ORBs comprometidos, residential relays, fronting, dead drops e nearby wireless pivots — comece por [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) e [Government and APT Case Studies](government-and-apt-case-studies.md), depois reproduza a telemetria necessária nos [authorized labs](authorized-adversary-emulation-labs.md).

A NIST define regras de engagement (ROE) como restrições preestabelecidas que concedem autoridade para atividades de testing definidas.<sup>[[1]](#references)</sup> A arquitetura de privacidade não pode ampliar essa autoridade.

## Escolha um padrão de egress

| Padrão | Melhor uso | O alvo vê | O provider/observador local vê | Responsabilização |
|---|---|---|---|---|
| VPN/jump host fornecido pelo cliente | Maioria dos assessments | Faixa de endereços do cliente | Identidade do cliente e acesso do operador | Mais forte |
| Bastion da organização de red team | Egress controlado e repetível | Faixa da organização | Hosting provider e organização | Forte |
| VPS específico do engagement | Isolar clientes/campanhas | Endereço do VPS | Conta do host, billing, logs do control plane e de acesso | Forte se documentado |
| VPN comercial aprovada | Research/scanning permitido pelo provider e pelas ROE | Egress compartilhado/dedicado da VPN | Conta da VPN e conexão de origem | Médio |
| Tor Browser | Web research que exige desvinculação do destino | Saída do Tor | Rede local vê Tor/bridge; o destino vê Tor | Não adequado para atribuição de origem por allowlist |
| Drop on-site aprovado pelo cliente | Simulação interna | Dispositivo/endereço no local | Rede do local e provider do túnel remoto | Forte se inventariado |
| Wi-Fi guest legal | Uso administrativo/research de baixo risco | IP público do local ou egress do túnel | Local, ISP, VPN/Tor | Fraco e fisicamente observável |

Para a maioria dos trabalhos, um egress fixo fornecido pelo cliente ou controlado pela organização é mais seguro e rápido do que serviços de anonimato para consumidores. Ele também permite que os defensores façam allowlist, monitorem ou deliberadamente **não** façam allowlist de faixas de origem conhecidas, de acordo com o design do exercício.

## Anexo de infraestrutura das ROE

Registre antes do deployment:

- entidades legais que concedem e recebem autorização;
- alvos exatos e exclusões explícitas;
- horários de início/fim, fuso horário e técnicas permitidas;
- IPs de origem, nomes de autonomous systems/providers, domínios, redirectors, infraestrutura de e-mail e identificadores de dispositivos no local;
- se phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence ou serviços de terceiros são permitidos;
- aprovações do cliente e do provider, incluindo qualquer referência de pre-notification;
- frase de emergency stop, contatos de abuso 24/7 do cliente e do provider e tempo máximo de resposta;
- classes de dados que podem ser coletadas, encryption, acesso, retenção e exclusão;
- requisitos de evidências e logging, incluindo quem mantém o mapeamento entre a infraestrutura pública e o operador;
- teardown, expiração de domínio, revogação de certificados, rotação de credenciais, recuperação de dispositivos e atestado final.

Verifique se os IPs públicos e domínios são realmente controlados pela parte autorizadora ou estão explicitamente incluídos no escopo. A NIST SP 800-115 recomenda confirmar que os endereços públicos dos alvos estão sob a jurisdição da organização antes do testing.<sup>[[2]](#references)</sup>

## Egress rápido específico do engagement

### Workflow de build

1. **Crie uma conta/projeto do engagement** sob a organização de red team, usando dados precisos de billing e ownership. Separe roles, API keys, budgets e audit logs dos demais clientes.
2. **Verifique a policy de cada provider.** Providers de cloud, VPS, CDN, domínio, e-mail e VPN têm regras diferentes. A AWS, por exemplo, permite assessments especificados, mas exige aprovação prévia para C2 hospedado/covert simulations e proíbe as atividades listadas.<sup>[[3]](#references)</sup>
3. **Aloque endereços de egress fixos** e inclua-os no anexo das ROE. Evite a rotação rápida de IPs/recursos; ela complica a resposta a incidentes e pode violar a policy do provider.
4. **Hardenize o management:** SSH somente com chaves ou um management plane identity-aware, MFA resistente a phishing, rede administrativa separada, least privilege, imagens atualizadas, nenhuma porta administrativa pública e armazenamento encrypted de secrets.
5. **Crie um caminho full-tunnel** do endpoint do operador até o bastion. Roteie DNS e IPv6 deliberadamente e aplique um firewall deny quando o túnel estiver inativo.
6. **Restrinja destinos e portas outbound** ao escopo autorizado quando possível. Aplique rate limit a scanners e coloque técnicas irreversíveis/destrutivas atrás de um approval gate separado.
7. **Faça logging para responsabilização, não para vigilância:** autenticação do operador, alterações de configuração, início/parada, endereço de origem, destino dentro do escopo e identificadores de ferramentas/jobs. Evite payload/credential capture, a menos que seja exigido pelo exercício e protegido pelo data plan.
8. **Valide por meio de um endpoint controlado** pertencente à organização: IPv4/IPv6 observados, caminho do DNS, reverse DNS, clock, comportamento da source port, falha/reconexão e contato de abuso do provider.
9. **Compartilhe o mapa de atribuição com segurança** com o controller do exercício ou um contato de escrow acordado. Não o publique para a equipe do alvo se a detecção às cegas fizer parte do teste.

### Arquitetura
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Um VPS é pseudônimo apenas para o destino. O host pode ter registros de contato, cobrança, identidade, source-IP, API, dispositivo, localização e uso; somente o histórico do AWS CloudTrail visível ao cliente pode expor atividades de gerenciamento.<sup>[[4]](#references)</sup> Pagar pela hospedagem com cryptocurrency não apaga esses registros.

## Domínios e certificados

- Use uma conta de registrar específica do engagement, pertencente à organização.
- Ative registrar lock, DNSSEC quando compatível, MFA/security keys e auto-renew apenas para o período aprovado.
- Use registration privacy para reduzir a exposição pública, não para deturpar as informações do registrante. A política da ICANN exige que os registrars coletem os dados de registro mesmo quando a exibição pública é redigida ou feita por proxy.<sup>[[5]](#references)</sup>
- Evite nomes que personifiquem ilegalmente partes não relacionadas. Typosquatting/lookalike domains exigem aprovação explícita do cliente e do provider.
- Faça o inventário de DNS, certificados, configuração de CDN/redirector e analytics de terceiros que poderiam expor operators ou clientes.
- No teardown, remova records, revogue certificados/tokens, preserve as evidências acordadas e decida se o domínio deve ser retido defensivamente.

## Authorized on-site drop nodes

Um Raspberry Pi ou appliance similar só é aceitável quando o proprietário da propriedade/rede e o cliente autorizarem explicitamente seu posicionamento e comportamento exatos. Um plano seguro:

1. Registre o serial do dispositivo, MAC/política de private-MAC, foto, proprietário, localização exata aprovada, fonte de energia, prazo de recuperação e contato para adulteração.
2. Use uma imagem mínima assinada, secrets criptografados, armazenamento somente leitura ou recuperável, host firewall, atualizações automáticas de segurança quando viável e nenhuma credencial padrão.
3. Configure comunicação somente de saída para um endpoint nomeado do engagement. Não exponha um listener não autenticado.
4. Faça allowlist dos destinos e capabilities. Packet capture, credential collection, wireless impersonation e lateral movement devem ser explicitamente autorizados individualmente.
5. Use mutual authentication, chaves de curta duração, remote kill, health reporting e limites de bandwidth.
6. Garanta que perda ou roubo não revele credenciais reutilizáveis ou dados do cliente.
7. Agende a recuperação e o secure wipe/decommission; obtenha um registro de recuperação assinado.

Não esconda hardware em um café, hotel, escritório compartilhado, propriedade de vizinho ou local público sem a permissão por escrito do proprietário/operator.

## Guest networks e travel routers

Se um cenário autorizado exigir acesso de convidado:

- verifique o SSID e a acceptable-use policy com o local/cliente;
- use um travel router pertencente à organização ou um bridge device de baixa confiança para isolar a workstation privilegiada;
- complete os captive portals fora da workstation privilegiada;
- inicie o tunnel aprovado antes do tráfego de assessment;
- confirme que os dispositivos tethered realmente usam esse tunnel;
- presuma que o local pode correlacionar associação de rádio, portal, presença física e registros de câmera/pagamento;
- nunca contorne access control, clone outro dispositivo, ataque Wi-Fi ou deixe equipamentos para trás.

## Separação operacional

- Um cliente/engagement por endpoint compartment, cloud project, conjunto de secrets, grupo de domínios, conjunto de redirectors e evidence store.
- Nenhum email pessoal, browser sync, número de telefone, cloud drive, chave SSH/GPG, identidade de code-signing ou reembolso de pagamento fora dos sistemas aprovados da organização.
- Não reutilize configurações distintivas de payload, callback paths, certificados ou repositórios públicos entre clientes, a menos que o design do exercício aceite fingerprinting.
- Defina uma kill date e um alerta de orçamento para a infraestrutura. Sistemas órfãos se tornam um risco tanto para o cliente quanto para a Internet.
- Preserve atribuição interna suficiente para investigar acidentes. “No logs” geralmente é incompatível com as obrigações profissionais de evidência e segurança.

## Cego para os defensores, atribuível ao controller

Quando o objetivo do exercício é medir a detecção, em vez de testar uma allowlist, o SOC alvo pode permanecer cego sem tornar a operação não responsabilizável:

1. O controller do exercício aprova toda source pública, domínio, certificado e dispositivo on-site, mas mantém a lista fora do alcance do SOC.
2. O controller armazena o mapa source-to-engagement/operator em um vault criptografado separado, com emergency access de duas pessoas.
3. Cada tarefa do operator recebe um manifest assinado contendo escopo, janela de tempo, source compartment e job identifier irreversível. O alvo nunca precisa ver o manifest durante a operação normal.
4. Os eventos de auditoria do bastion são encadeados ou enviados append-only para o storage do controller, para que um operator não possa reescrever silenciosamente a atribuição após um incidente.
5. Um contato 24/7 de provider-abuse mantém uma verification phrase/reference que confirma a autorização sem divulgar publicamente o cliente.
6. Todo path implementa um stop channel out-of-band que não depende do assessment C2, da rede alvo ou da conta de um único operator.
7. Antes do live testing, envie canaries benignos de cada source. Confirme que o controller consegue resolvê-los e interrompê-los dentro do tempo de resposta do ROE.
8. Após o exercício, compare a telemetria do SOC com o ledger do controller, divulgue a lista de sources e explique as detecções ausentes/incorretas.

Não adicione anti-forensics, destruição de logs, relays comprometidos ou subscriber identities falsas. Isso prejudica o testing responsável em vez de melhorá-lo.

## Checklist de teardown

- [ ] O controller do exercício confirma a interrupção.
- [ ] C2, tunnels, redirectors, email, VPN e scheduled jobs estão desativados.
- [ ] Os dispositivos on-site foram recuperados fisicamente e reconciliados.
- [ ] Tokens, API keys, chaves SSH, certificados e credenciais capturadas foram revogados/rotacionados.
- [ ] DNS e cloud resources foram removidos ou transferidos para retenção defensiva.
- [ ] Os dados do cliente foram devolvidos, retidos ou destruídos de acordo com o contrato.
- [ ] Os registros financeiros, de auditoria e de autorização necessários permanecem criptografados e com acesso controlado.
- [ ] Os casos de provider-abuse foram encerrados e o cliente recebeu os indicadores finais de source.
- [ ] Um segundo operator verifica que nenhuma infraestrutura permanece ativa.

## References

- [1] [NIST CSRC — Regras de Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guia Técnico para Testes e Avaliação de Segurança da Informação](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Política de Suporte ao Cliente para Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Aviso de Privacidade](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Política de Dados de Registro](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
