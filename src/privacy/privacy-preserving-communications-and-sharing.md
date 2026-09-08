# Comunicações e compartilhamento com preservação da privacidade

A criptografia de ponta a ponta protege o conteúdo. Ela não oculta automaticamente a conta, o número de telefone, o grafo de contatos, o endereço IP, o push token, a prévia da notificação, o momento, os metadados dos arquivos ou o comportamento do destinatário. Selecione uma ferramenta com base nos metadados que ela remove e nos observadores que introduz.

## Compare modelos de comunicação

| Ferramenta/modelo | Propriedade útil | Observadores e limitações restantes |
|---|---|---|
| Signal | E2EE madura; usernames podem iniciar contato sem compartilhar o número; sealed sender reduz os metadados do serviço | O número de telefone é necessário para o registro; o serviço, o provedor de push, os contatos e os endpoints mantêm algumas observações |
| SimpleX | Nenhum identificador de usuário global; filas por contato; transporte Tor opcional | Momento/transporte do relay, serviço de push, convites e endpoints; ecossistema mais novo/menor |
| Briar | Sincronização direta; Tor online; Bluetooth/Wi-Fi offline; nenhum armazenamento central de mensagens | Contatos e endpoints; observadores de rádio locais; focado em Android; ambos os lados devem estar disponíveis ou usar o Mailbox |
| OnionShare | Transferência/recebimento/chat/site direto por meio de um serviço onion temporário; nenhum provedor de armazenamento | O computador do remetente é o serviço; quem possui o link descobre o acesso; o momento e os endpoints permanecem |
| Arquivo criptografado com `age` | Criptografia simples para a chave do destinatário, independente do transporte | O transporte vê remetente/destinatário/momento/tamanho; nomes de arquivos/metadados de arquivo e endpoints permanecem |
| Email comum + TLS | Criptografia do canal entre servidores | Normalmente, ambos os provedores de email podem ler o conteúdo e manter metadados de roteamento/conta |

## Signal: contato privado sem divulgar o número

Os usernames do Signal podem iniciar um chat sem revelar o número de telefone do usuário ao novo contato, mas um número de telefone continua sendo necessário para o registro.<sup>[[1]](#references)</sup> O sealed sender é uma proteção incremental de metadados, não uma resistência a toda correlação de IP/momento.<sup>[[2]](#references)</sup>

### Fluxo de trabalho

1. Instale o Signal pela loja de aplicativos/projeto oficial e atualize primeiro o sistema operacional.
2. Registre-se com um número que você esteja legalmente autorizado a usar. Não use ativações de SMS alugadas, o número de outra pessoa ou uma conta de provedor obtida com identidade falsa.
3. Em **Configurações → Privacidade → Número de telefone**, defina quem pode ver o número e quem pode encontrar a conta pelo número de acordo com o modelo de ameaça.
4. Crie um username para descoberta por novos contatos. Compartilhe seu link/QR exato por meio de um canal já autenticado; usernames podem mudar e não são o nome do perfil.
5. Desative o upload/permissões de contatos se a conveniência não compensar a vinculação e adicione contatos manualmente quando a plataforma oferecer suporte.
6. Abra os detalhes do contato e compare o safety number/QR por um segundo canal ou pessoalmente antes de enviar conteúdo sensível.
7. Revise dispositivos vinculados, registration lock/PIN, prévias de notificações, segurança da tela, retransmissão de chamadas, padrões de mensagens que desaparecem e comportamento de backup.
8. Envie uma mensagem de teste não sensível e faça uma chamada. Inspecione os rastros na tela de bloqueio, no desktop, em dispositivos vestíveis e nas notificações em nuvem de ambos os lados.
9. Trate um safety number alterado ou um dispositivo vinculado inesperado como um evento de investigação, não como um alerta a ser descartado automaticamente.

Não misture uma foto de perfil pseudônima, biografia, participação em grupos ou rotina com um contexto identificável do Signal.

## SimpleX: conexões por contato sem um identificador global

O SimpleX roteia mensagens por meio de filas unidirecionais e não atribui um identificador de usuário em toda a rede. A própria política ainda documenta sessões de transporte, dados temporários do servidor, tradeoffs de notificações push e responsabilidade do endpoint.<sup>[[3]](#references)</sup>

### Fluxo de trabalho

1. Baixe um cliente mantido pelo projeto/loja oficial e verifique o publisher. Use um perfil dedicado do sistema operacional/aplicativo quando as identidades não puderem ser misturadas.
2. Crie um perfil **local** com um nome de exibição e uma imagem específicos do contexto. Excluir o aplicativo sem um backup pode causar a perda do perfil e das conexões.
3. Na primeira inicialização, escolha deliberadamente o modo de notificação. O push móvel instantâneo pode expor metadados adicionais à infraestrutura da Apple/Google.
4. Crie um link de convite de uso único para um contato. Transfira-o por um canal autenticado; qualquer pessoa que obtenha um convite ativo poderá tentar usá-lo.
5. Após a conexão, abra os detalhes do contato e compare o código de segurança pessoalmente ou por um canal independente verificado.<sup>[[4]](#references)</sup>
6. Use um perfil incognito por grupo, quando houver suporte, em vez de reutilizar o mesmo perfil em grupos não relacionados.
7. Configure o transporte Tor compatível com o cliente se a rede/servidor local não dever ver o IP direto. Confirme a conexão após a alteração; não force um proxy de sistema sem suporte.
8. Revise confirmações de entrega, prévias de links, chamadas, downloads automáticos e exportação/backup do banco de dados. Cada item altera a exposição de metadados ou do endpoint.
9. Teste a recuperação em um dispositivo reserva isolado sem executar um estado de perfil ativo duplicado; o projeto alerta que cópias concorrentes podem interromper as conversas.

A ausência de um identificador global não impede que um contato identifique o usuário por meio do conteúdo, da reutilização do perfil, da entrega do convite, do momento ou do grafo social.

## Briar: mensagens diretas e resistentes a interrupções

O Briar sincroniza diretamente entre dispositivos, por meio do Tor quando online e por Bluetooth/Wi-Fi durante interrupções locais. O modelo de ameaça oficial pressupõe apenas monitoramento adversarial limitado de rádio de curto alcance, portanto a rede sem fio local não é invisível.<sup>[[5]](#references)</sup>

### Fluxo de trabalho

1. Instale a distribuição oficial do Briar e verifique a origem do pacote. Use um dispositivo Android compatível com atualizações de segurança atuais.
2. Crie uma conta local com um nickname exclusivo para o contexto e uma senha forte. Não existe um caminho de redefinição de senha; teste se o segredo de desbloqueio pode ser recuperado.
3. Adicione contatos presencialmente escaneando os QR codes uns dos outros quando possível. Isso autentica o contato e evita o envio de um link por um canal correlacionável.
4. Nas configurações de conectividade, habilite apenas os transportes necessários: Tor/Internet, Wi-Fi e/ou Bluetooth. Desative os rádios locais quando não forem necessários.
5. Para entrega assíncrona, avalie o Briar Mailbox em um dispositivo dedicado e alimentado; inventarie-o e proteja-o fisicamente como um servidor de mensagens.
6. Envie um teste benigno enquanto a Internet estiver disponível e, em seguida, teste o caminho planejado para interrupções com a Internet desativada em um local autorizado pelo proprietário.
7. Inspecione backups do Android, prévias de notificações, capturas de tela e conteúdo exportado. O armazenamento local criptografado fica exposto quando o endpoint é desbloqueado/comprometido.
8. Remova contatos/dispositivos perdidos e encerre todo o contexto se a posse física ou a senha da conta forem comprometidas.

## OnionShare: transferência temporária direta

O OnionShare executa um serviço onion no computador do remetente/destinatário; os arquivos não são carregados para um provedor de armazenamento, e o tráfego é criptografado de ponta a ponta dentro do Tor.<sup>[[6]](#references)</sup> A URL onion completa é uma bearer capability e deve ser protegida.

### Fluxo de compartilhamento de arquivos pela GUI

1. Instale o OnionShare pela distribuição oficial assinada e o Tor Browser no lado do destinatário.
2. Coloque **cópias sanitizadas** dos arquivos em um diretório de staging dedicado. Não aponte o OnionShare para um diretório pessoal home.
3. Abra **Compartilhar arquivos**, adicione somente os arquivos preparados, mantenha a proteção por chave privada/acesso habilitada e mantenha **Parar o compartilhamento após os arquivos serem enviados** habilitado para um destinatário.
4. Inicie o compartilhamento e envie a URL onion completa por um canal E2EE já autenticado. Não a cole em email, rastreadores de issues ou chats públicos.
5. O destinatário abre a URL no Tor Browser, verifica com o remetente os nomes/tamanhos esperados dos arquivos e faz o download.
6. Ambos os lados comparam um digest SHA-256 previamente combinado ou entregue separadamente para garantir a integridade quando o próprio arquivo for o limite de segurança.
7. Confirme que o OnionShare parou após o download; caso contrário, pare-o manualmente e feche o aplicativo.
8. Exclua a cópia preparada de acordo com a política de retenção e inspecione as configurações de histórico/log do OnionShare para identificar divulgação não intencional de nomes de arquivos.

### Fluxo de trabalho da CLI

A CLI oficial aceita arquivos como argumentos posicionais e para após o compartilhamento único concluído padrão. Em um host com a CLI oficial/Tor instalado:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Entregue a URL completa com segurança. Não adicione `--public`, `--no-autostop-sharing`, registro detalhado do nome do arquivo ou persistência, a menos que o modelo de ameaça exija explicitamente a exposição resultante.<sup>[[7]](#references)</sup>

Trate os documentos recebidos como hostis. Abra-os em uma VM descartável/renderizador no estilo Dangerzone, em vez de no host que contém a identidade.

## Criptografe um arquivo de forma independente com `age`

A criptografia independente do transporte é útil quando um provedor de armazenamento/email pode visualizar o objeto. Ela não oculta o remetente, o destinatário, o tamanho, o horário ou o nome do arquivo, a menos que esses aspectos sejam tratados separadamente.

### Configuração do destinatário
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Autentique a string do destinatário público por meio de um segundo canal. Em seguida, o remetente executa:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
O destinatário descriptografa para um novo caminho:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
A CLI oficial avisa que `-o` sobrescreve uma saída existente; portanto, use um novo diretório e verifique o digest/conteúdo antes de movê-la.<sup>[[8]](#references)</sup> Nunca envie o arquivo de identidade junto com o texto cifrado.

## Pipeline reproduzível de sanitização de arquivos

A remoção de metadados é específica ao formato. Preserve um original criptografado quando a autenticidade, a análise forense ou a cadeia de custódia forem importantes; opere em uma cópia.

### Exemplo de JPEG
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Isso segue a orientação mais segura do ExifTool para JPEG: remover cegamente todas as tags também pode remover informações de cor.<sup>[[9]](#references)</sup> Em seguida, inspecione visualmente os pixels em busca de rostos, reflexos, telas, pontos de referência e padrões únicos de danos/ruído.

### Fluxo de trabalho para Office/PDF

1. Mantenha o original editável criptografado e offline em relação ao contexto de publicação.
2. Remova comentários, alterações controladas, slides/planilhas ocultos, arquivos incorporados, modelos pessoais e propriedades do documento no aplicativo de autoria.
3. Exporte um novo PDF a partir de um perfil limpo dedicado; não use a opção “imprimir” em uma impressora na cloud.
4. Inspecione com ferramentas cientes do formato e também com um renderizador visual descartável:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Pesquise a saída renderizada por nomes, caminhos, endereços de e-mail e texto de revisão. A rasterização pode remover estruturas ativas, mas prejudica a acessibilidade/pesquisa e não remove o conteúdo visível nem o estilo de escrita.
6. Gere o hash do artefato final e transfira **somente** essa cópia pelo compartimento de publicação.

## Privacy Pass: autorização anônima para designers de serviços

O Privacy Pass separa a **emissão** do **resgate** de tokens. Uma origem pode saber que um cliente possui um token aprovado pelo emissor sem saber da interação específica de emissão desse cliente. A reutilização de um token, metadados exclusivos, timing ou conluio podem reintroduzir a vinculabilidade.<sup>[[10]](#references)</sup>

Padrão de implantação segura:

1. Defina a afirmação que o token comprova (por exemplo, elegibilidade para limite de taxa), e não uma identidade global oculta.
2. Use a arquitetura e os protocolos de emissão padronizados; não implemente criptografia de assinaturas cegas do zero.
3. Separe a administração do emissor/atestado e da origem quando a propriedade desejada exigir isso.
4. Minimize os metadados públicos/privados dos tokens e garanta que os conjuntos de anonimato sejam grandes o suficiente.
5. Emita lotes antes do uso, quando houver suporte, para que o horário de emissão não corresponda trivialmente ao horário de resgate.
6. Resgate cada token uma única vez, valide o desafio vinculado à origem e exclua o estado de tokens expirados.
7. Impeda que cookies, registro de IP e contas de aplicação anulem silenciosamente a propriedade de privacidade do token.
8. Teste se os logs do emissor e da origem podem associar um evento controlado de emissão e resgate usando timing, metadados ou erros exclusivos.

O Privacy Pass é um recurso da aplicação, não algo que um usuário possa adicionar a uma conta arbitrária.

## Lista de verificação de autenticação de comunicações

- [ ] O contato/convite/chave foi autenticado de forma independente.
- [ ] A exposição do número de telefone, nome de usuário, perfil, grupo e upload de contatos é compreendida.
- [ ] Observadores de IP direto, relay, Tor, provedor de push e rádio local estão listados.
- [ ] Pré-visualizações de notificações, wearables, desktops vinculados e backups foram testados.
- [ ] Os arquivos foram higienizados, criptografados quando necessário e abertos em um contexto descartável.
- [ ] A recuperação funciona sem conectar identidades não relacionadas.
- [ ] Logs, histórico e serviços temporários de compartilhamento têm uma regra de encerramento/retenção.

## References

- [1] [Signal — Privacidade de números de telefone e nomes de usuário](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Política de privacidade e condições de uso](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Guia de privacidade e segurança](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Como funciona](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Design de segurança](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Uso avançado e CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI e uso oficiais](https://github.com/FiloSottile/age)
- [9] [FAQ do ExifTool — Remoção segura de metadados](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Arquitetura do Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
