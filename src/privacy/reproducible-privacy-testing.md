# Testes de Privacidade Reproduzíveis

{{#include ../banners/hacktricks-training.md}}

Uma configuração de privacidade não está concluída quando se conecta. Ela está concluída quando seu limite declarado foi testado durante o uso normal, falhas, recuperação e desmontagem. Teste contra infraestrutura que você possui ou está autorizado a inspecionar; sites públicos de “leak test” tornam-se outro observador.

## Crie um pequeno ambiente de testes autorizado

Use três funções, idealmente em provedores/redes separados:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Registre antes de cada teste:

- ID do teste, início/fim em UTC, operador e autorização;
- endpoint/versões do OS e do cliente e hash da configuração;
- observações esperadas de IPv4, IPv6, DNS, TLS, conta, pagamento e aspectos físicos;
- quais logs serão inspecionados e seus relógios/fusos horários;
- regra de aprovação/reprovação e horário da desmontagem.

Nunca teste primeiro uma identidade sensível. Use uma conta sintética e valores canário exclusivos e inofensivos pertencentes ao tester.

## Teste do caminho de rede

### 1. Capture a linha de base

Antes de habilitar o caminho de privacidade, registre as rotas locais e os resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
No macOS, use `route -n get default`, `netstat -rn -f inet6` e `scutil --dns`. Salve a saída somente no armazenamento controlado de evidências; ela pode conter identificadores locais.

### 2. Conecte-se e inspecione o roteamento

Ative o namespace da VPN/Tor/workload e, em seguida, verifique a rota selecionada para endereços públicos controlados:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Substitua os endereços da documentação pelos endereços do servidor de teste. Confirme que a interface/tabela selecionada corresponde ao design.

### 3. Observe de ambas as extremidades

Defina a URL do endpoint sob seu controle e, em seguida, solicite um caminho inofensivo exclusivo:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Use um domínio controlado pelo tester, TLS autenticado e um token de caminho não sensível. Inspecione o log do servidor para verificar:

- endereço/ASN de origem e egress esperado;
- IPv4 versus IPv6;
- comportamento de Host/SNI visível no endpoint;
- user agent e headers da aplicação;
- horário exato e reutilização da requisição.

Não adicione `X-Forwarded-For`, headers de debug exclusivos ou cookies que contenham identidade a uma requisição supostamente separada.

### 4. Teste DNS com um canary próprio

Configure uma zona de teste autoritativa cujos query logs você controle. Consulte um label aleatório exclusivo através do compartimento:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Inspecione o log autoritativo. Normalmente, ele vê o recursive resolver, não necessariamente o cliente. Compare esse resolver com o design pretendido de DNS do VPN/Tor/aplicação. Um site público aleatório de DNS leak não é necessário.

### 5. Teste o comportamento fail-closed

Mantenha um loop de requisições benignas direcionado ao endpoint sob seu controle e, em seguida, interrompa o privacy path. A carga de trabalho deve falhar, em vez de mudar para uma interface física. Verifique ambas as famílias de endereços e o DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Repita durante:

- travamento do processo do túnel;
- troca de Wi-Fi para Ethernet ou hotspot;
- suspensão/retomada;
- renovação do DHCP;
- estado do captive portal;
- reconexão do provedor/expiração da chave.

Para um namespace/container Linux, interrompa o túnel e verifique se ele não tem outra rota padrão ou resolvedor:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Os nomes e comandos variam conforme a implantação. Não os cole em um host de produção remoto sem recuperação pelo console.

### 6. Inspecione sockets e pacotes locais

Com autorização, verifique qual processo/interface realmente se comunica:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Substitua `TEST_SERVER_IP` pelo endereço explícito sob seu controle; evite a captura ampla de usuários não relacionados. A interface física deve enxergar o peer do túnel/bridge, enquanto o tráfego com destino claro deve existir somente na camada pretendida.

## Teste de Tor e onion-service

1. No Tor Browser, visite a página de verificação de conexão do Tor Project e confirme o uso do Tor. Não trate isso como prova de identidade.<sup>[[1]](#references)</sup>
2. Visite o endpoint HTTPS sob seu controle com um canary exclusivo e confirme que ele detecta um exit do Tor, nenhum cookie identificável e o contexto padrão do navegador.
3. Selecione **New Identity**, visite novamente com um canary diferente e verifique se o estado local foi limpo conforme esperado. A alteração do IP de saída não é garantida nem é o objetivo do New Identity.
4. Para um onion service, acesse-o somente pelo Tor Browser. Confirme que o host do serviço não possui nenhum listener público com uma varredura externa autorizada e que as respostas da aplicação não contêm hostname/IP público.
5. Inspecione o DNS/HTTP de saída da origem, templates, páginas de erro, e-mail/webhooks e assets de terceiros. Qualquer fetch direto pode divulgar a origem ou a conta do operador.
6. Se a autorização do cliente estiver habilitada, confirme que um Tor Browser limpo e sem credenciais não consegue se conectar e que um com credenciais consegue.
7. Faça a rotação de uma chave de autorização de teste e confirme que o cliente revogado perde o acesso sem alterar a identidade do onion.

## Teste de compartimentação do navegador

Crie uma página controlada que registre somente os campos necessários para o teste, com um período curto de retenção. Compare os compartimentos pessoal e de privacidade quanto a:

- cookies/local storage/service workers e cache;
- estado de sincronização/login do navegador;
- idioma, fuso horário, dimensões da tela/janela e fontes;
- candidatos de WebRTC/rede;
- permissões e modificações visíveis para extensões;
- dados de user-agent TLS/HTTP no servidor.

Não tente tornar o Tor Browser “mais aleatório”. A condição de aprovação é a similaridade com o conjunto de anonimato padrão e a ausência de estado pessoal, não a diferença máxima em relação ao navegador pessoal.

Teste copiar/colar, arrastar/soltar, abertura de arquivos baixados, sugestões do gerenciador de senhas e botões de provedores de identidade. Esses são meios frequentes de conexão entre compartimentos.

## Teste de isolamento do sistema operacional

### Tails

1. Comece com um arquivo/canary benigno em uma sessão sem Persistent Storage.
2. Desligue completamente, reinicie e confirme que ele desapareceu.
3. Habilite somente uma categoria de persistência necessária, repita o teste e confirme que o estado não relacionado do navegador/aplicação não foi retido.
4. Verifique se o Unsafe Browser não pode ser usado após o login no portal para atividades sensíveis e se as aplicações Tor se reconectam normalmente.

### Whonix/Qubes

1. Pare o Gateway/net qube e prove que o Workstation/app qube não consegue acessar IPv4, IPv6 ou DNS.
2. Tente somente o caminho de clipboard/arquivo entre qubes explicitamente configurado e confirme que outros caminhos de pastas/dispositivos compartilhados estão ausentes.
3. Abra um documento de teste benigno em um disposable qube, feche-o e confirme que o estado desaparece.
4. Verifique se o vault qube não possui NetVM e não pode adquirir um por meio de uma alteração de template/default.
5. Crie/restaure um snapshot de uma VM de teste e inspecione se o estado que contém identidade retorna inesperadamente.

## Teste de metadados de comunicação

Para cada messenger selecionado:

1. Crie participantes exclusivos para teste em dispositivos sob seu controle.
2. Registre o que o cadastro exige: telefone, conta da app store, IP, push service, nome de usuário ou convite.
3. Envie uma mensagem benigna enquanto inspeciona previews de notificações, desktops vinculados, wearables e backups.
4. Verifique os códigos de segurança/segurança por um caminho independente.
5. Desabilite recibos/push ou habilite transports Tor/locais, um de cada vez, e observe as alterações de confiabilidade/metadados.
6. Exporte ou restaure um backup de teste e documente exatamente quais perfil, contatos e histórico ele contém.
7. Perca/revoque um dispositivo de teste e confirme que os participantes restantes veem a alteração esperada de chave/dispositivo.

Não faça testes entrando em contato com pessoas não envolvidas nem gerando tráfego abusivo.

## Teste de sanitização de arquivos

1. Calcule o hash e preserve o original em armazenamento de evidências criptografado:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Crie uma cópia limpa usando o processo específico do formato em [Comunicações e Compartilhamento com Preservação de Privacidade](privacy-preserving-communications-and-sharing.md).
3. Compare os inventários de metadados:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Renderize/abra a cópia em um contexto descartável. Verifique conteúdo oculto, anexos, links, formulários, camadas, miniaturas e identificadores visuais.
5. Pesquise somente na cópia preparada por strings conhecidas de autor/e-mail/caminho de canary.
6. Calcule o hash da saída final e peça a uma segunda pessoa para verificar o arquivo exato que será publicado.

A ausência na saída do ExifTool não é prova de anonimato; os elementos internos do formato, os pixels, a prosa e os registros de distribuição permanecem.

## Teste de privacidade de pagamentos

Use o menor valor permitido ou uma rede de teste/sandbox oficial:

1. Descreva a visualização esperada para pagador, recebedor/comerciante, emissor/exchange, rede/nó, ledger público e contador/controlador.
2. Crie uma fatura/contexto de comerciante de teste exclusivo, sem identidade falsa.
3. Pague uma vez e, em seguida, colete seu próprio recibo, extrato, dashboard do comerciante, log da wallet/do nó e a visualização da blockchain pública, quando aplicável.
4. Verifique se o valor, timestamp, endereço/token, conta, IP/dispositivo, entrega e rota de reembolso correspondem à tabela de observadores.
5. No Bitcoin, inspecione a reutilização de endereços, os inputs selecionados, o troco e a consolidação posterior na visualização de coin-control da wallet.
6. Para protocolos shielded, verifique o pool/caminho real e o que uma viewing key revela; não infira privacidade com base no branding da wallet.
7. Para e-cash/Taler, teste backup/recovery, reembolso e resgate com pequeno valor; documente os registros de fronteira da mint/exchange/federação.
8. Revogue um cartão virtual/credencial de teste e confirme que uma autorização posterior falha, mantendo compreendido o tratamento legítimo de reembolsos.
9. Faça a conciliação e retenha as evidências fiscais/de autorização exigidas de forma criptografada.

Nunca crie transferências circulares, divisão de valores para atingir limiares, compras falsas ou reembolsos suspeitos como um “teste de privacidade”.

## Exercício autorizado de accountability de red-team

Antes do exercício, realize um tabletop e um exercício técnico:

1. Um operador lança um canary benigno de cada caminho de origem aprovado.
2. O SOC alvo registra o que detecta sem receber a identidade do operador, caso o blind testing seja pretendido.
3. O controlador do exercício resolve origem → engagement → operador a partir do mapa em escrow e do job record assinado.
4. O controlador envia o emergency stop; o operador e o proprietário da infraestrutura demonstram o desligamento dentro do prazo do ROE.
5. O abuse desk do provedor recebe o contato 24/7 correto e a referência de autorização.
6. As evidências mostram o alvo, horário, ferramenta/job e operador sem reter conteúdo de payload desnecessário.
7. Um segundo operador verifica a revogação das credenciais e a desmontagem dos recursos.

Reprove a revisão de prontidão se o SOC puder ver trivialmente a infraestrutura pessoal/residencial **ou** se o controlador não puder atribuir e interromper rapidamente a origem.

## Modelo de registro de teste
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Verificação da conexão](https://check.torproject.org/)
- [2] [WireGuard — Roteamento e namespaces de rede](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ e orientações sobre metadados](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Guia técnico para testes e avaliação de segurança da informação](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
