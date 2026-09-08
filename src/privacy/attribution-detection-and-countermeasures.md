# Atribuição, Detecção e Contramedidas

A infraestrutura de evasão de atribuição é projetada para tornar indicadores individuais descartáveis. Os defensores devem preservar evidências brutas, modelar relacionamentos e buscar comportamentos que persistam mesmo após uma mudança de IP, domínio ou persona.

## Hierarquia de evidências

| Evidência | Útil para | Principal ressalva |
|---|---|---|
| IP/ASN/geolocalização de origem | localizar a saída visível e o provedor | a saída pode ser um relay, NAT ou vítima; a geolocalização é aproximada |
| DNS passivo/registro | histórico da infraestrutura e co-hosting | privacidade/redação e shared hosting criam lacunas |
| Fingerprint de certificado/TLS/HTTP | agrupar deployments repetidos | software comum e mimetismo criam falsos positivos |
| Temporização do fluxo e formato dos bytes | vincular estágios de relay e beacons recorrentes | CDNs/NAT e visibilidade limitada reduzem a certeza |
| Processo/identidade do endpoint | explicar por que uma conexão ocorreu | não está presente em edge/IoT; o atacante pode usar ferramentas nativas |
| Auditoria de Cloud/CDN/API | identificar o tenant e o controle da infraestrutura | a retenção e o acesso legal/do provedor variam |
| Pagamento/conta/dispositivo | conectar a aquisição a uma pessoa/entidade | é necessário considerar nominees, comprometimento e dispositivos compartilhados |
| Implant/configuração apreendido | revelar chaves, peers, controllers e vínculos de build | a integridade da coleta e o momento da apreensão são importantes |
| Evidência humana/física | conectar o evento digital ao local/operador | intrusiva, dependente da jurisdição e requer tratamento rigoroso |

Nenhuma linha isolada deve sustentar uma atribuição estatal de alta confiança. Use hipóteses concorrentes e indique qual observação falsificaria cada uma delas.

## Telemetria mínima

1. **DNS:** cliente, consulta, tipo, respostas, TTL, código de resposta, resolver e timestamp.
2. **Fluxo de rede:** origem/destino/porta, início/fim, pacotes/bytes, flags TCP e localização do sensor.
3. **TLS/HTTP:** SNI quando visível, certificado, protocolo negociado, fingerprint do cliente/servidor, método, categoria de authority/path, status e contagem de bytes. Proteja URLs completas sensíveis.
4. **Identidade:** resultado da autenticação, fator/certificado/dispositivo, origem, aplicação, ID da sessão e decisão de risco.
5. **Endpoint:** processo iniciador, processo pai, usuário, assinatura/hash do binário e destino.
6. **Dispositivo de edge/rede:** diferença de configuração, login administrativo, integridade de processo/arquivo/firmware, interface e logs de fluxo.
7. **Cloud/SaaS/CDN:** ator, tenant/projeto, ação de API, origem, objeto/recurso, token e resultado.
8. **Wireless/NAC:** estação, flag de MAC randomizado, AP, sinal, identidade/certificado EAP, VLAN/IP atribuído e postura.

Sincronize os relógios, mantenha os fusos horários originais, documente os limites de NAT/proxy e retenha histórico suficiente para sobreviver a um nó ORB de 31 dias.

## Construir um grafo de atribuição

Represente as observações como nós e arestas tipados:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Nós úteis incluem IP, prefixo, ASN, domínio, conta DNS, certificado/chave, fingerprint semelhante a JA3/JA4, gramática HTTP, hash de arquivo/configuração, tenant cloud, API token, e-mail, persona, instrumento de pagamento e dispositivo físico. Cada aresta precisa de `first_seen`, `last_seen`, sensor/fonte, confiança e indicação de ser observada ou inferida.

A densidade do grafo, por si só, é enganosa: uma CDN ou autoridade certificadora conecta muitos atores não relacionados. Dê mais peso às relações raras controladas pelo operador—mesma conta de API, chave SSH, allowlist de origem, corpo de resposta exclusivo ou protocolo de controle—do que à hospedagem comum.

## ORB e busca por roteadores comprometidos

### A partir de um exit observado

1. Determine se o endereço pertence a hospedagem, rede residencial, móvel, educacional ou empresarial; não descarte fontes residenciais.
2. Colete DNS histórico, serviços/certificados, portas abertas e comportamento observado de scanning/exploitation durante um período delimitado.
3. Procure peers que compartilhem fingerprints raros de serviço, destinos de controller, material de certificado ou timing de rotação.
4. Classifique as funções prováveis: acesso, traversal, exit/staging ou administração.
5. Verifique se múltiplos clusters de intrusion não relacionados usaram o mesmo pool; a multi-tenancy enfraquece a atribuição direta do ator, mas fortalece a hipótese de ORB.
6. Monitore novos nós que correspondam ao perfil da função depois que os IPs antigos desaparecerem.

### No proprietário da rede

- Gere alertas para novas interfaces de gerenciamento expostas à Internet e autenticação padrão/legada.
- Envie alterações de configuração de roteadores/firewalls/VPN e autenticações administrativas para fora do dispositivo.
- Estabeleça uma baseline das conexões de saída da infraestrutura que normalmente inicia poucas sessões.
- Detecte novos processos de proxy/listener, túneis, tarefas agendadas, alterações de firmware e DNS inesperado.
- Substitua dispositivos em fim de vida; um reboot que remove malware volátil não corrige a exposição.
- Restrinja o gerenciamento a um plano de administração autenticado e a fontes conhecidas.

A Mandiant recomenda monitorar a infraestrutura ORB como uma entidade em evolução, pois o bloqueio de IPs de curta duração não captura a topologia e o ciclo de vida.<sup>[[1]](#references)</sup>

## Fast-flux e análise de dynamic-DNS

Agregue por domínio registrado e por uma janela deslizante. Uma pontuação prática pode combinar:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Investigue domínios com vários recursos independentes, não apenas um limite. Compare-os com um modelo de permissão de CDN/anti-DDoS e verifique a rotação dos servidores de nomes autoritativos para distinguir single flux de double flux. Para DGAs, adicione picos de NXDOMAIN por cliente, distribuição de comprimento/caracteres, consultas sincronizadas entre hosts e o processo que as gera. A orientação atual da MITRE também enfatiza alterações de alta frequência, TTL baixo e correlação entre processo e rede.<sup>[[2]](#references)</sup>

## Detecção de domain-fronting

Quando o endpoint corporativo ou um ponto de inspeção autorizado tiver ambas as identidades, compare:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Aumente a confiança quando SNI e authority pertencerem a tenants não relacionados, o processo não for um cliente aprovado, a sessão for periódica/de longa duração e a origem interna for rara. SNI vazio é uma característica a ser registrada, não algo automaticamente malicioso. ECH pode ocultar o SNI na rede, portanto os logs do endpoint, DNS e do provider/CDN tornam-se mais importantes. A MITRE documenta tanto variantes com SNI incompatível quanto com SNI em branco.<sup>[[3]](#references)</sup>

## Detecção de sequência de dead-drop resolver

O comportamento de alto sinal é uma sequência, não um domínio bloqueado:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Faça hunting em toda a frota por caminhos de objetos idênticos, hashes de respostas, identificadores de API e destinos subsequentes. Preserve o conteúdo obtido, pois o ator pode editá-lo ou excluí-lo. Restrinja APIs de serviços desnecessárias e exija que aplicações aprovadas usem proxies corporativos, mas considere ferramentas de desenvolvimento e automação. O MITRE lista GitHub, fóruns, documentos e serviços sociais/web em procedimentos reais.<sup>[[4]](#references)</sup>

## Clustering de redirectors e deployments reutilizáveis

Mesmo quando os domínios e endereços mudam, os operadores frequentemente fazem redeploy da mesma automação. Faça clustering com base em combinações de:

- campos de certificado/reutilização de chaves e momento da emissão;
- versão do TLS/ordem de cipher/extensão e comportamento do servidor;
- status HTTP idêntico, ordem dos headers, comportamento de cache, ícone/corpo e página de erro;
- pares de portas incomuns e cadeias de redirecionamento;
- padrão de provedor DNS/servidor de nomes e programação de TTL;
- momento do deployment, disponibilidade e janela de manutenção;
- exposição da origem back-end ou allowlists idênticas.

Uma única página genérica do Nginx é uma evidência fraca. Várias correspondências raras e independentes, combinadas com continuidade temporal, podem justificar uma hipótese de cluster de infraestrutura.

## Detecção de proxy residencial e sessões impossíveis

Mantenha a identidade da sessão acima da camada de IP. Sinalize combinações como:

- um fingerprint de sessão/dispositivo muda de países/ASNs mais rapidamente do que seria possível em uma viagem;
- um IP de consumidor muda a cada requisição enquanto os cookies e a identidade TLS/browser permanecem fixos;
- o dispositivo local alegado apresenta latência/fuso horário/idioma incompatíveis com o exit;
- um endereço alterna entre populações de contas não relacionadas ou exibe comportamento de proxy backconnect;
- uma sessão privilegiada aparece a partir de acesso residencial sem o certificado de dispositivo da organização.

Carrier NAT, ferramentas de acessibilidade, VPNs corporativas e viagens produzem anomalias benignas. Exija autenticação step-up ou investigação, em vez de bloqueio irreversível baseado exclusivamente em rótulos de “proxy residencial”.

## Detecção de dispositivos wireless e encobertos

Correlacione RADIUS/NAC com o AP e o contexto físico:

1. encontre combinações conta–dispositivo–AP vistas pela primeira vez;
2. identifique credenciais usadas sem um certificado/postura EAP gerenciado;
3. compare sessões simultâneas e a presença no crachá/prédio;
4. inspecione sinais excepcionalmente fracos/de borda e movimentação entre APs;
5. procure em endpoints gerenciados próximos por scanning wireless, uma interface bridge/NAT recém-habilitada, adaptadores virtuais ou túneis;
6. faça o inventário de novas atividades em portas de switch, DHCP, rede USB e PoE;
7. realize uma varredura RF/física autorizada quando as evidências a justificarem.

Isso detecta tanto um caminho de vizinho mais próximo no estilo APT28 quanto um dispositivo deixado durante um exercício. A randomização de MAC não deve ser tratada como identidade ou prova de culpa.

## Detecção de atribuição financeira

- Preserve a cadeia, o token, o endereço, a transação e os identificadores de bloco exatos.
- Siga o valor por change, peel chains, fan-out/in, mixers, bridges e depósitos em serviços, rotulando as heurísticas.
- Correlacione horário, valor menos taxas, evento de contrato, liquidez e saque na cadeia de destino.
- Obtenha ou preserve registros legais de exchanges, bridges, comerciantes, contas, dispositivos e entregas.
- Verifique entidades/endereços sancionados atuais e derivados de acordo com o programa aplicável; não dependa de uma lista estática antiga.
- Trate o uso de protocolos de privacidade como um fator de contexto de risco, não como prova de irregularidade.

Os red flags da FATF são explicitamente contextuais: padrão incomum, valor/frequência, geografia, origem dos fundos e serviços que aumentam o anonimato tornam-se significativos em conjunto.<sup>[[5]](#references)</sup>

## Deception e canaries

Defensores podem criar sinais de alta confiança sem tentar desanonimizar usuários comuns:

- credenciais ou documentos exclusivos que nunca deveriam sair de um sistema;
- endpoints administrativos falsos e compartilhamentos decoy;
- nomes DNS instrumentados incorporados apenas em artefatos controlados;
- chaves de cloud canary sem uso legítimo;
- uma identidade Wi-Fi decoy que nenhum dispositivo gerenciado possui.

Defina o escopo e governe a deception cuidadosamente. Um canary deve identificar o uso indevido de um ativo do próprio defensor, não coletar tráfego não relacionado de terceiros.

## Prioridades de countermeasures

1. Remova routers, VPNs e appliances expostos à Internet sem suporte.
2. Exija MFA resistente a phishing e certificados vinculados ao dispositivo, incluindo acesso interno/wireless.
3. Centralize logs suficientemente imutáveis de identidade, endpoint, DNS, fluxo, proxy, cloud e dispositivos de rede.
4. Restrinja o gerenciamento e o egress; faça o inventário de todos os serviços acessíveis externamente.
5. Monitore DNS, transparência de certificados e configurações de cloud em busca de ativos não autorizados.
6. Preserve visibilidade do processo para a rede e no nível de objetos de SaaS.
7. Pratique investigações entre camadas e a coordenação com provedores vizinhos.
8. Acompanhe clusters de infraestrutura e comportamentos, não apenas blocklists de IP.

## Disciplina analítica

Use linguagem de confiança:

- **Observed:** o registro do sensor/provedor mostra diretamente a relação.
- **Strongly supported:** várias observações independentes favorecem essa hipótese em relação às alternativas.
- **Assessed:** inferência baseada nas premissas e evidências declaradas.
- **Unknown:** a visibilidade ausente impede uma conclusão.

Mantenha sempre pelo menos duas hipóteses: infraestrutura operada pelo ator versus intermediário comprometido/compartilhado; um ator versus serviço multi-tenant; evasão deliberada versus comportamento legítimo de privacidade/CDN. A capacidade de explicar a incerteza faz parte de uma detecção correta.

## References

- [1] [Google Cloud/Mandiant — Atores de espionagem ligados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicadores de red flags de Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Atores da RPC comprometem e mantêm acesso persistente](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Orientação aprimorada de visibilidade e hardening para infraestrutura de comunicações](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
