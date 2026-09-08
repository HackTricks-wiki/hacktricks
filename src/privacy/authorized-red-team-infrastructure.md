# Infraestrutura Autorizada de Red Team

Para dispositivos duráveis instalados no local, use o design [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) e o runbook de descoberta suspeita.

Para um red team profissional, o objetivo é a **atribuição controlada**, não a imunidade à responsabilização. O alvo não deve conseguir ver trivialmente o IP residencial ou as contas pessoais de um operador, enquanto o responsável pelo engagement deve ser capaz de identificar a origem, interromper a operação, tratar denúncias de abuso, preservar evidências e comprovar a autorização.

Esta página é a baseline de deployment para um engagement legal. Para o adversary tradecraft que ela pretende emular — incluindo ORBs comprometidos, relays residenciais, fronting, dead drops e pivots wireless próximos — comece por [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) e [Government and APT Case Studies](government-and-apt-case-studies.md), e então reproduza a telemetria necessária nos [authorized labs](authorized-adversary-emulation-labs.md).

O NIST define regras de engagement (ROE) como restrições preestabelecidas que concedem autoridade para atividades de teste definidas.<sup>[[1]](#references)</sup> A arquitetura de privacidade não pode ampliar essa autoridade.

## Escolha um padrão de egress

| Padrão | Melhor uso | O que o alvo vê | O que o provider/observador local vê | Responsabilização |
|---|---|---|---|---|
| VPN/jump host fornecido pelo cliente | A maioria das avaliações | Faixa de endereços do cliente | Identidade do cliente e acesso do operador | Mais forte |
| Bastion da organização de red team | Egress controlado e repetível | Faixa da organização | Hosting provider e organização | Forte |
| VPS específico do engagement | Isolar clientes/campanhas | Endereço do VPS | Conta do host, billing, control plane e access logs | Forte se documentado |
| VPN comercial aprovada | Research/scanning permitido pelo provider e pelas ROE | Egress de VPN compartilhado/dedicado | Conta da VPN e conexão de origem | Médio |
| Tor Browser | Web research que exige desvinculação do destino | Saída do Tor | Rede local vê Tor/bridge; o destino vê Tor | Pouco adequado para atribuição de origem por allowlist |
| Drop on-site aprovado pelo cliente | Simulação interna | Dispositivo/endereço no local | Rede do local e remote tunnel provider | Forte se inventariado |
| Wi-Fi de visitante legal | Uso administrativo/research de baixo risco | IP público do local ou egress do tunnel | Local, ISP, VPN/Tor | Fraco e fisicamente observável |

Na maioria dos trabalhos, um egress fixo fornecido pelo cliente ou controlado pela organização é mais seguro e rápido do que serviços de anonimato para consumidores. Ele também permite que os defensores façam allowlist, monitorem ou deliberadamente **não** façam allowlist de faixas de origem conhecidas, de acordo com o design do exercício.

## Anexo de infraestrutura de ROE

Registre antes do deployment:

- entidades legais que concedem e recebem autorização;
- alvos exatos e exclusões explícitas;
- horários de início/fim, fuso horário e técnicas permitidas;
- IPs de origem, nomes de autonomous systems/providers, domínios, redirectors, infraestrutura de email e identificadores de dispositivos on-site;
- se phishing, C2, captura de credenciais, wireless testing, acesso físico, denial-of-service, persistência ou serviços de terceiros são permitidos;
- aprovações do cliente e do provider, incluindo qualquer referência de pre-notification;
- frase de emergency stop, contatos de abuso do cliente e do provider disponíveis 24/7 e tempo máximo de resposta;
- classes de dados que podem ser coletadas, encryption, acesso, retenção e exclusão;
- requisitos de evidências e logging, incluindo quem mantém o mapeamento entre a infraestrutura pública e o operador;
- teardown, expiração de domínios, revogação de certificados, rotação de credenciais, recuperação de dispositivos e atestado final.

Verifique se os IPs públicos e domínios são realmente controlados pela parte autorizadora ou estão explicitamente incluídos no scope. O NIST SP 800-115 recomenda confirmar que os endereços públicos dos alvos estão sob a autoridade da organização antes do testing.<sup>[[2]](#references)</sup>

## Egress rápido específico do engagement

### Fluxo de construção

1. **Crie uma conta/projeto do engagement** sob a organização de red team usando dados precisos de billing e ownership. Separe roles, API keys, budgets e audit logs dos demais clientes.
2. **Verifique a policy de cada provider.** Providers de Cloud, VPS, CDN, domínio, email e VPN têm regras diferentes. A AWS, por exemplo, permite avaliações especificadas, mas exige aprovação prévia para C2 hospedado/covert simulations e proíbe as atividades listadas.<sup>[[3]](#references)</sup>
3. **Aloque endereços de egress fixos** e inclua-os no anexo de ROE. Evite a rápida rotação de IPs/recursos; isso dificulta a resposta a incidentes e pode violar a policy do provider.
4. **Harden o gerenciamento:** SSH somente com chaves ou um management plane identity-aware, MFA resistente a phishing, rede de administração separada, least privilege, imagens com patches, nenhuma porta de administração pública e armazenamento criptografado de secrets.
5. **Crie um caminho full-tunnel** do endpoint do operador até o bastion. Roteie DNS e IPv6 deliberadamente e aplique um firewall deny quando o tunnel estiver inativo.
6. **Restrinja destinos e portas de saída** ao scope autorizado quando possível. Aplique rate limit a scanners e coloque técnicas irreversíveis/destrutivas atrás de um gate de aprovação separado.
7. **Faça logging para responsabilização, não vigilância:** autenticação do operador, alterações de configuração, início/parada, endereço de origem, destino dentro do scope e identificadores de tool/job. Evite captura de payload/credenciais, a menos que seja exigida pelo exercício e protegida pelo plano de dados.
8. **Valide por meio de um endpoint controlado** pela organização: IPv4/IPv6 observado, caminho de DNS, reverse DNS, clock, comportamento da source port, falha/reconexão e contato de abuso do provider.
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
Um VPS é pseudônimo apenas para o destino. O host pode manter registros de contato, cobrança, identidade, IP de origem, API, dispositivo, localização e uso; somente o histórico do AWS CloudTrail visível ao cliente pode expor atividades de gerenciamento.<sup>[[4]](#references)</sup> Pagar pela hospedagem com criptomoeda não apaga esses registros.

## Domains and certificates

- Use uma conta de registrar específica para o engagement, pertencente à organização.
- Ative o bloqueio do registrar, DNSSEC quando houver suporte, MFA/security keys e a renovação automática somente durante o período aprovado.
- Use privacidade de registro para reduzir a exposição pública, não para falsificar informações do registrante. A política da ICANN exige que os registrars coletem os dados de registro mesmo quando a exibição pública é ocultada ou feita por proxy.<sup>[[5]](#references)</sup>
- Evite nomes que personifiquem ilegalmente partes não relacionadas. Typosquatting/lookalike domains exigem aprovação explícita do cliente e do provider.
- Faça o inventário de DNS, certificados, configuração de CDN/redirector e analytics de terceiros que possam causar leak de operadores ou clientes.
- No teardown, remova os registros, revogue certificados/tokens, preserve as evidências acordadas e decida se o domain deve ser mantido defensivamente.

## Authorized on-site drop nodes

Um Raspberry Pi ou appliance semelhante só é aceitável quando o proprietário da propriedade/rede e o cliente autorizarem explicitamente sua localização e comportamento exatos. Um plano seguro:

1. Registre o serial do dispositivo, MAC/política de MAC privado, foto, proprietário, local exato aprovado, fonte de energia, prazo de recuperação e contato para adulteração.
2. Use uma imagem mínima assinada, secrets criptografados, armazenamento somente leitura ou recuperável, host firewall, atualizações de segurança automáticas quando viável e nenhuma credencial padrão.
3. Configure comunicação somente de saída para um endpoint de engagement nomeado. Não exponha um listener não autenticado.
4. Faça allowlist de destinos e capacidades. Packet capture, credential collection, wireless impersonation e lateral movement devem ser autorizados explicitamente, cada um deles.
5. Use autenticação mútua, chaves de curta duração, remote kill, relatórios de integridade e limites de largura de banda.
6. Garanta que perda ou roubo não revele credenciais reutilizáveis ou dados do cliente.
7. Agende a recuperação e o secure wipe/decommission; obtenha um registro de recuperação assinado.

Não esconda hardware em um café, hotel, escritório compartilhado, propriedade de vizinho ou local público sem a permissão por escrito do proprietário/operador.

## Guest networks and travel routers

Se um cenário autorizado exigir acesso de convidado:

- verifique o SSID e a política de uso aceitável com o local/cliente;
- use um travel router pertencente à organização ou um dispositivo bridge de baixa confiança para isolar a workstation privilegiada;
- conclua os captive portals fora da workstation privilegiada;
- inicie o túnel aprovado antes do tráfego de assessment;
- confirme que os dispositivos tethered realmente usam esse túnel;
- presuma que o local pode correlacionar associação de rádio, portal, presença física e registros de câmeras/pagamentos;
- nunca contorne controles de acesso, clone outro dispositivo, ataque Wi-Fi ou deixe equipamentos para trás.

## Operational separation

- Um cliente/engagement por endpoint compartment, cloud project, secrets set, domain group, redirector set e evidence store.
- Nenhum email pessoal, browser sync, número de telefone, cloud drive, chave SSH/GPG, identidade de code-signing ou reembolso de pagamento fora dos sistemas aprovados da organização.
- Não reutilize configurações distintas de payload, callback paths, certificados ou public repositories entre clientes, a menos que o design do exercício aceite fingerprinting.
- Dê à infraestrutura uma data de encerramento e um alerta de orçamento. Sistemas órfãos tornam-se um risco tanto para o cliente quanto para a Internet.
- Preserve atribuição interna suficiente para investigar acidentes. “No logs” geralmente é incompatível com evidências profissionais e obrigações de segurança.

## Blind to defenders, attributable to the controller

Quando o objetivo do exercício é medir a detecção, em vez de testar uma allowlist, o SOC alvo pode permanecer às cegas sem tornar a operação não responsabilizável:

1. O controller do exercício aprova cada source público, domain, certificado e dispositivo on-site, mas mantém a lista fora do alcance do SOC.
2. O controller armazena o mapa source-to-engagement/operator em um vault criptografado separado, com acesso emergencial por duas pessoas.
3. Cada trabalho do operador recebe um manifest assinado contendo escopo, janela de tempo, source compartment e job identifier irreversível. O alvo nunca precisa ver o manifest durante a operação normal.
4. Os eventos de auditoria do bastion são encadeados ou enviados em modo append-only para o armazenamento do controller, para que um operador não possa reescrever silenciosamente a atribuição após um incidente.
5. Um contato 24/7 de provider-abuse mantém uma frase/referência de verificação que confirma a autorização sem divulgar publicamente o cliente.
6. Cada path implementa um canal de parada out-of-band que não dependa do assessment C2, da rede alvo ou da conta de um único operador.
7. Antes dos testes em produção, envie canaries benignos de cada source. Confirme que o controller consegue resolvê-los e interrompê-los dentro do tempo de resposta do ROE.
8. Após o exercício, compare a telemetria do SOC com o ledger do controller, divulgue a lista de sources e explique as detecções ausentes/incorretas.

Não adicione anti-forensics, destruição de logs, relays comprometidos ou identidades falsas de assinantes. Isso prejudica testes responsabilizáveis em vez de aprimorá-los.

## Teardown checklist

- [ ] O controller do exercício confirma a parada.
- [ ] C2, túneis, redirectors, mail, VPN e scheduled jobs são desativados.
- [ ] Os dispositivos on-site são recuperados fisicamente e reconciliados.
- [ ] Tokens, API keys, chaves SSH, certificados e credenciais capturadas são revogados/rotacionados.
- [ ] DNS e recursos cloud são removidos ou transferidos para retenção defensiva.
- [ ] Os dados do cliente são devolvidos, retidos ou destruídos conforme o contrato.
- [ ] Os registros financeiros, de auditoria e de autorização necessários permanecem criptografados e com acesso controlado.
- [ ] Os casos de provider-abuse são encerrados e o cliente recebe os source indicators finais.
- [ ] Um segundo operador verifica que nenhuma infraestrutura permanece ativa.

## References

- [1] [NIST CSRC — Regras de Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guia Técnico para Testes e Avaliação de Segurança da Informação](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Política de Suporte ao Cliente para Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Aviso de Privacidade](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Política de Dados de Registro](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
