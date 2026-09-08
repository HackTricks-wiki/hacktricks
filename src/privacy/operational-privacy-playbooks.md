# Playbooks de Privacidade Operacional

Estes playbooks combinam os controles do restante desta seção. São pontos de partida, não garantias: atualize o threat model sempre que um novo observador, conta, dispositivo, localização, pagamento, arquivo ou contraparte entrar no workflow.

## Preflight universal

1. Escreva o objetivo legítimo e o que deve permanecer privado **de quem**.
2. Registre as identidades, dispositivos, redes, contas, meios de pagamento, contrapartes, localizações físicas e dados que a atividade acessará.
3. Identifique o observador provável mais poderoso e a consequência de uma falha.
4. Confirme a autorização, a legislação aplicável, os termos do provedor e a política organizacional.
5. Decida o que deve permanecer atribuível internamente para segurança, resposta a incidentes, contabilidade e auditoria.
6. Escolha o menor compartment viável; estabeleça seus caminhos de recuperação e shutdown antes do uso.
7. Teste o compartment contra um serviço controlado, incluindo IP/DNS/IPv6, identidade do navegador, metadados do documento, extrato de pagamento e notification leakage.

Use o modelo detalhado em [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Baseline de privacidade cotidiana

Objetivo: reduzir tracking comercial, account takeover e exposição desnecessária sem tentar se tornar anônimo.

- Use um OS mantido com full-disk encryption, atualizações automáticas, screen lock e secure boot quando disponível.
- Configure primeiro o password manager, o email de recuperação e o MFA/security keys resistente a phishing.
- Revise permissões de aplicativos, histórico de localização, identificadores de publicidade, cloud sync e conexões com contas de terceiros.
- Use um navegador mainstream com poucas extensões, tracking protection, HTTPS e perfis separados para navegação de trabalho/pessoal/alto risco.
- Use aliases de private relay ou endereços de email distintos por relacionamento; não use um número de telefone pessoal quando ele for apenas opcional.
- Prefira messaging com end-to-end encryption para o conteúdo, lembrando que participantes, horários, grupos e endpoints continuam sendo metadata.
- Remova metadados dos arquivos deliberadamente e inspecione a cópia exportada — não o original — antes de publicar.
- Use tokens de virtual-card ou wallet para compartmentalization de credenciais de pagamento; não os chame de anônimos.
- Faça backup do material de recuperação criptografado e teste a restauração.

## Publicação pseudônima

Objetivo: impedir que leitores e plataformas casuais vinculem trivialmente uma publicação a uma identidade civil. Isso não derrota uma investigação direcionada conduzida por um adversário capaz.

1. Defina se a plataforma, o provedor de hosting, os leitores, os contatos, a rede local, o provedor de pagamento ou o processo legal fazem parte do threat model.
2. Crie um contexto dedicado de endpoint/conta a partir de um baseline limpo. Desative a sincronização pessoal do navegador, documentos na nuvem, upload de contatos e previews de notificações.
3. Crie a conta pseudônima por meio do compartment de rede escolhido. Não reutilize usernames, avatares, canais de recuperação, boilerplate de escrita ou login de um identity provider pessoal.
4. Use Tor Browser quando a unlinkability do destino for mais importante que a velocidade; não adicione extensões, redimensione/personalize excessivamente o navegador nem abra documentos baixados enquanto estiver online em uma sessão comum de desktop.
5. Elabore o conteúdo com um processo que não incorpore nomes de templates pessoais, autores de revisão, caminhos de impressora, GPS/EXIF, thumbnails ou camadas ocultas. Exporte uma cópia e inspecione-a com ferramentas de metadata apropriadas.
6. Verifique o conteúdo em busca de fatos autoidentificáveis: datas únicas, detalhes do local de trabalho, clima/fuso horário local, reflexos, áudio de fundo, hábitos linguísticos e reutilização de texto de publicações anteriores.
7. Use um canal separado para respostas. Trate todo contato direto, anexo e link como uma possível tentativa de correlação ou phishing.
8. Se houver dinheiro envolvido, use o método legal que exponha apenas os dados necessários. Presuma que a plataforma e o intermediário regulado podem conhecer o beneficiário, mesmo que os leitores não conheçam.
9. Publique e depois inspecione o resultado público a partir de um contexto limpo diferente. Registre o que a plataforma adicionou ou transformou.
10. Mantenha uma cadência planejada apenas se ela não criar uma fingerprint comportamental estável; aposente o compartment em vez de reutilizá-lo silenciosamente.

Para jornalismo sério, ativismo, violência doméstica ou risco em nível estatal, obtenha ajuda personalizada de uma organização experiente em segurança digital; uma checklist estática não consegue modelar a legislação local ou um adversário ativo.

## Engajamento autorizado de red-team

Objetivo: manter as identidades pessoais e as redes domésticas dos operadores fora da telemetria do alvo, preservando autorização, controle e resposta a incidentes.

### Antes da janela de início

- Finalize o anexo de infraestrutura do ROE, alvos/exclusões, ranges de origem, datas, emergency stop e permissões de terceiros/provedores.
- Aloque um perfil ou VM dedicado do operador, secrets do engagement, armazenamento de evidências, projeto cloud, domínios e orçamento.
- Prefira o egress fornecido pelo cliente ou um bastion fixo controlado pela organização. Teste o comportamento de full-tunnel IPv4/IPv6/DNS e a política fail-closed.
- Armazene o mapeamento entre operador e infraestrutura pública com o controller do exercício ou com o contato de escrow acordado.
- Estabeleça rate limits, allowlists de destino e aprovação separada para ações destrutivas, wireless, físicas, de phishing ou de coleta de credenciais.
- Use um meio de pagamento controlado pela organização e registre as aprovações internamente.

### Durante o engagement

- Comece pelo endpoint e tunnel aprovados; verifique o egress observado antes do tráfego de assessment.
- Mantenha contas pessoais, dispositivos, números de telefone, repositórios, chaves SSH/GPG e cloud sync fora do compartment.
- Registre operador/job, início/fim, origem, destino dentro do escopo e alterações de configuração sem coletar conteúdo desnecessário do cliente.
- Interrompa diante de ambiguidade de escopo, sistemas inesperados de terceiros, notification de abuso do provedor, impacto à segurança, equipamento perdido ou perda de contato com o controller.
- Nunca improvise usando o Wi-Fi de um vizinho, credenciais roubadas, um SIM/conta não aprovados ou hardware escondido em um local.

### Fim do engagement

- Interrompa jobs e C2; recupere os drop devices aprovados; revogue tokens, credenciais e certificados.
- Reconcilie infraestrutura, domínios, endereços de origem, despesas, dados e casos com provedores em relação ao inventário.
- Retorne/exclua/retenha os dados do cliente de acordo com o contrato, preserve o mínimo de evidências de auditoria necessário e peça a um segundo operador para verificar o shutdown.

Consulte [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) para o guia completo de build e teardown.

## Compra ou doação privada legal

Objetivo: minimizar a divulgação ao comerciante ou ao público, cumprindo as obrigações do emissor, contábeis, fiscais e de sanções.

1. Liste quem não deve saber o quê: público, comerciante, intermediário de pagamento, empregador/delegado da conta familiar, serviço de entrega ou observador da blockchain.
2. Verifique as regras locais, o destinatário/contraparte, os termos do provedor, os limites de dinheiro em espécie e as necessidades de manutenção de registros.
3. Escolha o meio:
- dinheiro em espécie para pagamentos locais legais aceitos, sem registro na rede de pagamentos;
- um cartão virtual regulamentado/específico do comerciante para separação de credenciais online;
- cryptocurrency somente após analisar aquisição, ledger, backend da wallet, rede, contraparte e vínculos com gastos posteriores.
4. Use dados verdadeiros obrigatórios e omita apenas informações opcionais de fidelidade/marketing. Não use a identidade/endereço de outra pessoa nem divida uma transação em torno de um limite.
5. Separe o contexto do navegador/conta do comerciante e evite login social, programa de fidelidade ou canais pessoais de recuperação não relacionados.
6. Confirme o que aparece em extratos, recibos, notificações, envio e listas públicas de doadores.
7. Armazene as evidências obrigatórias de recibo/imposto/autorização criptografadas; revogue credenciais de pagamento descartáveis após o período de reembolso.

Consulte [Private Digital Payments](private-digital-payments.md) e [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Viagens e redes não confiáveis

Objetivo: proteger dados e contas em redes não administradas pelo usuário — não ocultar atividades não autorizadas.

- Atualize os dispositivos e baixe as credenciais/mapas necessários antes da viagem.
- Minimize os dados armazenados; use full-disk encryption, desbloqueio forte, planejamento de recuperação remota e procedimentos com o dispositivo desligado para fronteiras/riscos físicos, conforme orientação legal.
- Verifique o SSID/captive portal do local. Prefira um hotspot pessoal quando apropriado, mas lembre-se dos registros de assinante e localização da rede celular.
- Use uma VPN aprovada full/forced para dados organizacionais; verifique se os dispositivos tethered compartilham a VPN e teste o comportamento de IPv6/DNS.
- Use um travel router para isolamento de clientes e uma política reproduzível, não como garantia de anonimato.
- Trate carregadores USB públicos, computadores emprestados, impressoras públicas e sistemas compartilhados de salas de reunião como ameaças separadas.
- Presuma que presença física, identificadores de rádio, login no portal, câmeras e registros de pagamento/localização podem correlacionar a visita.

Os detalhes de comparação e configuração estão em [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Resposta a falha e exposição

Quando um compartment sofre leak ou pode ser vinculado:

1. Interrompa a atividade se a continuidade aumentar o dano; use o emergency stop do engagement quando aplicável.
2. Preserve as evidências necessárias sem espalhar dados sensíveis. Registre o horário exato, o indicador observado e os ativos afetados.
3. Notifique o proprietário/controller/contato de segurança apropriado. Não oculte um incidente para preservar uma narrativa de privacidade.
4. Revogue sessões, tokens, credenciais de pagamento e acesso à infraestrutura; faça rotate dos secrets a partir de um endpoint reconhecidamente limpo.
5. Determine quais edges fizeram a ligação: endpoint, recuperação de conta, rede, pagamento, metadata, conteúdo, comportamento, contraparte ou presença física.
6. Trate todo o compartment afetado como burned. Não altere apenas seu username ou IP de saída.
7. Cumpra as obrigações de notificação de breach, provedor, cliente, financeiras e legais.
8. Reconstrua somente após alterar o processo que causou a ligação; documente o controle e teste-o.

## Auditoria periódica

- [ ] O threat model e as premissas legais/de provedor foram revisados conforme um cronograma datado.
- [ ] Dispositivos, contas, aliases, domínios, caminhos de rede e credenciais de pagamento foram inventariados.
- [ ] Os caminhos de recuperação não atravessam compartments inesperadamente.
- [ ] O comportamento de full-tunnel, DNS, IPv6 e fail-closed foi testado.
- [ ] Arquivos e perfis públicos foram verificados quanto a metadata/reutilização de conteúdo.
- [ ] Os nodes/backends de wallet e as premissas dos protocolos crypto permanecem atuais.
- [ ] Logs e recibos são mínimos, criptografados, têm acesso controlado e estão dentro do período de retenção.
- [ ] Compartments antigos e a infraestrutura de engagement foram totalmente aposentados.
