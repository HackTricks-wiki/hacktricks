# Playbooks de Privacidade Operacional

{{#include ../banners/hacktricks-training.md}}

Estes playbooks combinam os controles do restante desta seção. São pontos de partida, não garantias: atualize o modelo de ameaças sempre que um novo observador, conta, dispositivo, localização, pagamento, arquivo ou contraparte entrar no fluxo de trabalho.

## Verificação preliminar universal

1. Escreva o objetivo legítimo e o que deve permanecer privado **de quem**.
2. Registre as identidades, dispositivos, redes, contas, meios de pagamento, contrapartes, localizações físicas e dados que a atividade irá envolver.
3. Identifique o observador provável mais poderoso e a consequência de uma falha.
4. Confirme a autorização, a legislação aplicável, os termos do provedor e a política organizacional.
5. Decida o que deve permanecer atribuível internamente para segurança, resposta a incidentes, contabilidade e auditoria.
6. Escolha o menor compartimento funcional; estabeleça seus caminhos de recuperação e desligamento antes de usá-lo.
7. Teste o compartimento contra um serviço controlado, incluindo IP/DNS/IPv6, identidade do navegador, metadados de documentos, extrato do pagamento e leak de notificações.

Use o modelo detalhado em [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Linha de base de privacidade cotidiana

Objetivo: reduzir o rastreamento comercial, o account takeover e a exposição desnecessária sem tentar se tornar anônimo.

- Use um OS mantido com criptografia completa de disco, atualizações automáticas, bloqueio de tela e secure boot quando disponível.
- Primeiro, configure o password manager, o email de recuperação e o MFA/security keys resistente a phishing.
- Revise as permissões dos aplicativos, o histórico de localização, os identificadores de publicidade, a sincronização na cloud e as conexões com contas de terceiros.
- Use um navegador mainstream com poucas extensões, proteção contra rastreamento, HTTPS e perfis separados para navegação profissional/pessoal/de alto risco.
- Use aliases de private relay ou endereços de email distintos por relacionamento; não use um número de telefone pessoal quando ele for apenas opcional.
- Prefira mensagens com criptografia end-to-end para o conteúdo, lembrando que participantes, horários, grupos e endpoints continuam sendo metadados.
- Remova metadados dos arquivos deliberadamente e inspecione a cópia exportada — não o original — antes de publicar.
- Use tokens de virtual-card ou wallet para compartimentar credenciais de pagamento; não os chame de anônimos.
- Faça backup do material de recuperação criptografado e teste a restauração.

## Publicação pseudônima

Objetivo: impedir que leitores casuais e plataformas vinculem trivialmente uma publicação a uma identidade civil. Isso não impede uma investigação direcionada conduzida por um adversário capaz.

1. Defina se a plataforma, o provedor de hosting, os leitores, os contatos, a rede local, o provedor de pagamento ou um processo judicial fazem parte do modelo de ameaças.
2. Crie um contexto dedicado de endpoint/conta a partir de uma baseline limpa. Desative a sincronização pessoal do navegador, documentos na cloud, upload de contatos e previews de notificações.
3. Crie a conta pseudônima por meio do compartimento de rede escolhido. Não reutilize usernames, avatares, canais de recuperação, boilerplate de escrita ou login de um identity provider pessoal.
4. Use o Tor Browser quando a unlinkability do destino for mais importante que a velocidade; não adicione extensões, não redimensione/personalize excessivamente o navegador nem abra documentos baixados enquanto estiver online em uma sessão comum do desktop.
5. Redija usando um processo que não incorpore nomes de templates pessoais, autores de revisões, caminhos de impressora, GPS/EXIF, thumbnails ou camadas ocultas. Exporte uma cópia e inspecione-a com ferramentas de metadados apropriadas.
6. Verifique o conteúdo em busca de fatos autoidentificáveis: datas únicas, detalhes do local de trabalho, clima/fuso horário local, reflexos, áudio de fundo, hábitos linguísticos e reutilização de texto de publicações anteriores.
7. Use um canal de resposta separado. Trate todo contato direto, anexo e link como uma possível tentativa de correlação ou phishing.
8. Se houver dinheiro envolvido, use o método lícito que exponha apenas os dados necessários. Presuma que a plataforma e o intermediário regulado possam conhecer o beneficiário, mesmo que os leitores não conheçam.
9. Publique e, em seguida, inspecione o resultado público a partir de um contexto limpo diferente. Registre o que a plataforma adicionou ou transformou.
10. Mantenha uma cadência planejada apenas se ela não criar uma fingerprint comportamental estável; aposente o compartimento em vez de reutilizá-lo silenciosamente.

Para jornalismo sério, ativismo, abuso doméstico ou risco em nível estatal, obtenha ajuda personalizada de uma organização experiente em segurança digital; uma checklist estática não consegue modelar a legislação local ou um adversário ativo.

## Authorized red-team engagement

Objetivo: manter as identidades pessoais e as redes domésticas dos operadores fora da telemetria do alvo, preservando a autorização, o controle e a resposta a incidentes.

### Antes da janela de início

- Finalize o anexo de infraestrutura do ROE, alvos/exclusões, ranges de origem, datas, parada de emergência e permissões de terceiros/provedores.
- Aloque um perfil ou VM dedicado do operador, secrets do engagement, armazenamento de evidências, projeto na cloud, domínios e orçamento.
- Prefira o egress fornecido pelo cliente ou um bastion fixo controlado pela organização. Teste o comportamento de IPv4/IPv6/DNS em full-tunnel e a política fail-closed.
- Armazene o mapeamento entre operador e infraestrutura pública com o controlador do exercício ou com o contato de escrow acordado.
- Estabeleça rate limits, allowlists de destino e aprovação separada para ações destrutivas, wireless, físicas, de phishing ou de coleta de credenciais.
- Use um meio de pagamento controlado pela organização e registre as aprovações internamente.

### Durante o engagement

- Comece pelo endpoint e túnel aprovados; verifique o egress observado antes do tráfego de assessment.
- Mantenha contas pessoais, dispositivos, números de telefone, repositórios, chaves SSH/GPG e sincronização na cloud fora do compartimento.
- Registre operador/job, início/fim, origem, destino dentro do escopo e alterações de configuração sem coletar conteúdo desnecessário do cliente.
- Pare diante de ambiguidade no escopo, sistemas inesperados de terceiros, notificação de abuso do provedor, impacto à segurança, equipamento perdido ou perda de contato com o controlador.
- Nunca improvise usando o Wi-Fi de um vizinho, credenciais roubadas, um SIM/conta não aprovado ou hardware escondido em um local.

### Fim do engagement

- Pare os jobs e o C2; recupere os dispositivos drop aprovados; revogue tokens, credenciais e certificados.
- Reconcilie infraestrutura, domínios, endereços de origem, despesas, dados e casos com provedores com base no inventário.
- Devolva/exclua/conserve os dados do cliente de acordo com o contrato, preserve o mínimo necessário de evidências de auditoria e peça a um segundo operador para verificar o desligamento.

Consulte [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) para obter o guia completo de criação e teardown.

## Compra ou doação privada lícita

Objetivo: minimizar a divulgação ao comerciante ou ao público, cumprindo as obrigações do emissor, contábeis, fiscais e de sanções.

1. Liste quem não deve saber o quê: público, comerciante, intermediário de pagamento, empregador/delegado da conta familiar, serviço de entrega ou observador da blockchain.
2. Verifique as regras locais, o destinatário/contraparte, os termos do provedor, os limites de dinheiro em espécie e as necessidades de manutenção de registros.
3. Escolha o meio:
- dinheiro em espécie para pagamentos locais lícitos aceitos, sem registro na rede de pagamentos;
- um cartão virtual/regulado específico do comerciante para separação de credenciais online;
- cryptocurrency somente após analisar os vínculos de aquisição, ledger, backend da wallet, rede, contraparte e gastos posteriores.
4. Use os dados obrigatórios verdadeiros e omita apenas informações opcionais de fidelidade/marketing. Não use a identidade/endereço de outra pessoa nem divida uma transação para contornar um limite.
5. Separe o contexto do navegador/conta do comerciante e evite login social, programa de fidelidade ou canais pessoais de recuperação não relacionados.
6. Confirme o que aparece em extratos, recibos, notificações, remessas e listas públicas de doadores.
7. Armazene criptografadas as evidências necessárias de recibo/imposto/autorização; revogue as credenciais de pagamento descartáveis após o período de reembolso.

Consulte [Private Digital Payments](private-digital-payments.md) e [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Viagens e redes não confiáveis

Objetivo: proteger dados e contas em redes não administradas pelo usuário — não ocultar atividades não autorizadas.

- Atualize os dispositivos e baixe as credenciais/mapas necessários antes da viagem.
- Minimize os dados armazenados; use criptografia completa de disco, desbloqueio forte, planejamento de recuperação remota e procedimentos de dispositivo desligado em fronteiras/situações de risco físico apropriados à orientação jurídica.
- Verifique o SSID/portal captive do local. Prefira um hotspot pessoal quando apropriado, mas lembre-se dos registros do assinante e da localização celular.
- Use uma VPN aprovada full/forced para dados organizacionais; verifique se os dispositivos tethered a compartilham e teste o comportamento de IPv6/DNS.
- Use um travel router para isolamento de clientes e uma política reproduzível, não como garantia de anonimato.
- Trate carregadores USB públicos, computadores emprestados, impressoras públicas e sistemas compartilhados de salas de reunião como ameaças separadas.
- Presuma que presença física, identificadores de rádio, login no portal, câmeras e registros de pagamento/localização podem correlacionar a visita.

Os detalhes de comparação e configuração estão em [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Resposta a falhas e exposição

Quando um compartimento sofre leak ou pode ser vinculado:

1. Pare a atividade se a continuidade aumentar o dano; use a parada de emergência do engagement quando aplicável.
2. Preserve as evidências necessárias sem espalhar dados sensíveis. Registre o horário exato, o indicador observado e os ativos afetados.
3. Notifique o proprietário/controlador/contato de segurança apropriado. Não oculte um incidente para preservar uma narrativa de privacidade.
4. Revogue sessões, tokens, credenciais de pagamento e acesso à infraestrutura; altere os secrets a partir de um endpoint conhecido como limpo.
5. Determine quais arestas fizeram a ligação: endpoint, recuperação de conta, rede, pagamento, metadados, conteúdo, comportamento, contraparte ou presença física.
6. Trate todo o compartimento afetado como comprometido. Não altere apenas o username ou o IP de saída.
7. Cumpra as obrigações de notificação de breach, provedor, cliente, financeiras e legais.
8. Reconstrua somente após alterar o processo que causou a ligação; documente o controle e teste-o.

## Auditoria periódica

- [ ] O modelo de ameaças e as premissas legais/do provedor foram revisados conforme um cronograma datado.
- [ ] Dispositivos, contas, aliases, domínios, caminhos de rede e credenciais de pagamento foram inventariados.
- [ ] Os caminhos de recuperação não atravessam compartimentos inesperadamente.
- [ ] O comportamento de full-tunnel, DNS, IPv6 e fail-closed foi testado.
- [ ] Arquivos públicos e perfis foram verificados quanto a metadados/reutilização de conteúdo.
- [ ] Os nós/backends de wallet e as premissas dos protocolos de crypto continuam atuais.
- [ ] Logs e recibos são mínimos, criptografados, controlados por acesso e mantidos dentro do período de retenção.
- [ ] Compartimentos antigos e a infraestrutura do engagement foram totalmente aposentados.
{{#include ../banners/hacktricks-training.md}}
