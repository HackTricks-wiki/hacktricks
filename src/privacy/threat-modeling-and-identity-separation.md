# Modelagem de Ameaças e Separação de Identidades

A falha de anonimato mais comum não é uma criptografia quebrada. É a **vinculação**: um identificador, padrão de tempo, dispositivo, conta, pagamento, arquivo ou hábito humano conecta dois contextos que deveriam permanecer separados.

## Crie um modelo de ameaças de privacidade

O plano de segurança de seis perguntas da EFF é uma base sólida: o que deve ser protegido, contra quem, o impacto e a probabilidade de falha, o esforço disponível e os aliados que podem ajudar.<sup>[[1]](#references)</sup> Torne-o operacional com uma pequena tabela:

| Ativo/ação | Observador | Dados observáveis | Rota de correlação | Controle | Risco residual |
|---|---|---|---|---|---|
| Pesquisar um cliente | ISP | Metadados de destino/tempo | Registro do assinante residencial | Tor Browser | Uso de Tor visível; correlação ponta a ponta |
| Conta pseudônima | Plataforma | IP, navegador, dados de recuperação | Telefone/email/foto reutilizados | Contexto e alias dedicados | Correlação de escrita/grafo social |
| Compra online | Comerciante | Conta, entrega, cartão tokenizado | Endereço e histórico da conta | Checkout como convidado, campos mínimos, cartão virtual | Emissor e transportadora mantêm registros |
| Tráfego de Red Team | Alvo/cliente | IP de origem e comportamento | Registros do provedor/engajamento | Saída dedicada e autorizada | Deliberadamente atribuível durante uma escalada |

Revise a tabela sempre que o local, provedor, dispositivo, contraparte ou consequências mudarem.

## Desenhe o grafo de vinculabilidade

Trate cada identidade como um nó separado. Adicione uma aresta para cada atributo compartilhado:

- email ou endereço de recuperação;
- número de telefone ou upload da agenda de contatos;
- nome de usuário, avatar, foto, biografia ou estilo de escrita/código;
- senha, conta de sincronização de passkeys ou pergunta de recuperação;
- dispositivo, ID de publicidade, perfil do navegador, cookies, fontes ou extensões;
- endereço IP, fuso horário, idioma, programação ou status online simultâneo;
- cartão bancário, conta de exchange, cluster de wallet, endereço de entrega ou programa de fidelidade;
- campos de autor do documento, localização EXIF, marcas da impressora ou proprietário do compartilhamento na nuvem;
- colega, participação em grupos e grafo social.

Uma aresta não é automaticamente fatal, mas indica qual observador pode fazer a conexão. A EFF alerta especificamente que números de telefone, endereços de email e fotografias reutilizadas podem vincular perfis.<sup>[[2]](#references)</sup>

## Crie um compartimento passo a passo

1. **Dê um nome ao contexto e aos vínculos proibidos.** Exemplo: `client-red-2026`, proibido para email pessoal, perfis de navegador domésticos, métodos de pagamento pessoais e clientes não relacionados.
2. **Escolha o limite de isolamento.** Em ordem crescente de força: perfil de navegador separado → conta de SO separada → VM/qube separado → dispositivo dedicado. Uma aba separada ou janela privada não é um limite de segurança.
3. **Crie identificadores novos dentro desse limite.** Use um email/alias específico do contexto, nome de usuário, cofre ou coleção do gerenciador de senhas e chaves de autenticação. Não adicione um canal de recuperação pessoal se a impossibilidade de vinculação ao provedor for importante.
4. **Escolha uma política de rede.** Decida se o contexto sempre usará uma VPN do cliente, VPS de engagement, VPN confiável ou Tor. Imponha roteamento fail-closed quando possível.
5. **Escolha uma política de pagamento.** O método de pagamento deve corresponder ao modelo do observador; um cartão virtual pode ocultar o PAN do comerciante, mas ainda identifica o cliente para o emissor.
6. **Defina regras de transferência de dados.** Prefira transferências deliberadas e estritamente delimitadas. Trate a área de transferência, pastas compartilhadas, dispositivos USB, sincronização na nuvem, impressoras e screenshots como possíveis pontes.
7. **Registre as datas de criação e encerramento.** Defina quais evidências devem ser mantidas para contratos/impostos/conformidade e quais dados transitórios devem expirar.
8. **Teste a existência de vínculos antes do uso.** Inspecione as configurações da conta, campos de recuperação, perfil público, IP/DNS, estado do navegador, metadados dos arquivos e painéis dos provedores.

{% hint style="warning" %}
Não invente informações de identidade quando um serviço ou a lei exigir identificação precisa. Um compartimento de privacidade trata de minimização e separação de dados, não de fraude de identidade ou de contornar a devida diligência do cliente.
{% endhint %}

## Base de endpoint e conta

- Use hardware compatível e instale prontamente atualizações do SO, navegador, wallet e firmware.
- Ative a criptografia do dispositivo e use um código de acesso forte. A criptografia em repouso ajuda quando um dispositivo desligado é perdido ou apreendido, mas não enquanto malware ou uma sessão desbloqueada puder ler os dados.<sup>[[3]](#references)</sup>
- Use senhas exclusivas e geradas aleatoriamente em um gerenciador de senhas.
- Prefira autenticação resistente a phishing, como WebAuthn/passkeys ou chaves de segurança de hardware, quando o modelo de ameaças permitir o modelo de recuperação/sincronização. O NIST observa que OTPs digitados manualmente não são resistentes a phishing porque um impostor pode retransmiti-los.<sup>[[4]](#references)</sup>
- Mantenha os códigos de recuperação offline e separados do endpoint. Verifique se uma conta de passkeys sincronizada une identidades que deveriam permanecer separadas.
- Desative permissões desnecessárias de localização, contatos, microfone, câmera, Bluetooth, ID de publicidade e execução em segundo plano.
- Não misture sincronização pessoal na nuvem, sincronização do navegador, contas de gerenciadores de senhas ou lojas de aplicativos em um contexto de alta separação.

## Privacidade do navegador

Browser fingerprinting usa configuração, dispositivo, ambiente e comportamento observáveis para identificar ou correlacionar um usuário. Limpar cookies ou alterar endereços IP não o impede de forma confiável, e o W3C considera implausível a eliminação técnica completa por meios amplamente implantados.<sup>[[5]](#references)</sup>

Para privacidade comum:

1. Use um navegador mantido, com modo somente HTTPS e proteção forte contra rastreamento.
2. Bloqueie rastreamento de terceiros e faça partitioning do estado quando houver suporte.
3. Use perfis de navegador separados para contextos genuinamente separados.
4. Desative permissões desnecessárias e limpe os dados dos sites em uma programação definida.
5. Evite entrar em contas ricas em identidade enquanto realiza pesquisas sensíveis não relacionadas.

Para anonimato na web, use o **Tor Browser em sua configuração padrão**. Não faça proxy de um navegador comum através do Tor: o Tor Project alerta que navegadores comuns podem vazar por DNS/WebRTC, estado persistente, fontes, plugins e diferenças de fingerprint.<sup>[[6]](#references)</sup> Evite extensões extras, tamanhos incomuns de janela, fontes personalizadas e preferências que façam o navegador se destacar.<sup>[[7]](#references)</sup>

## Comunicações e metadados

Metadados incluem remetente, destinatário, horário, localização e outros contextos, mesmo quando o conteúdo da mensagem está criptografado.<sup>[[8]](#references)</sup>

- Prefira ferramentas com criptografia ponta a ponta, metadados minimizados no servidor e protocolos/clientes abertos quando for prático.
- Verifique contatos sensíveis usando um canal independente ou pessoalmente. Os números de segurança do Signal foram projetados para essa verificação.<sup>[[9]](#references)</sup>
- Os nomes de usuário do Signal podem iniciar um contato sem compartilhar um número de telefone, mas ainda é necessário um número de telefone para se registrar; configure deliberadamente a visibilidade/detectabilidade do número de telefone.<sup>[[9]](#references)</sup>
- Mensagens que desaparecem reduzem as cópias retidas; os destinatários ainda podem fotografar, copiar, encaminhar ou arquivar o conteúdo.
- O email normalmente expõe metadados de roteamento. Mesmo provedores focados em privacidade não podem tornar uma mensagem criptografada ponta a ponta quando a outra parte usa email comum, a menos que ambas as partes usem um método E2EE compatível. A Proton, por exemplo, documenta que emails comuns enviados para outros provedores usam TLS e permanecem legíveis pelo provedor destinatário.<sup>[[10]](#references)</sup>
- Separe as agendas de contatos e não envie contatos pessoais para uma conta pseudônima.

## Arquivos, fotos e autoria

O Tails alerta que fotografias podem conter dados da câmera e de localização, e documentos de escritório podem conter campos de autor e horário de criação.<sup>[[11]](#references)</sup>

Antes de compartilhar:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Em seguida, reabra a cópia limpa em um visualizador isolado e verifique:

- propriedades do documento, comentários, alterações controladas, planilhas/apresentações ocultas, miniaturas e anexos;
- EXIF/XMP/IPTC, GPS, timestamps, nomes de dispositivos/software e IDs exclusivos;
- reflexos visíveis, pontos de referência, conteúdo de telas, vozes, rostos e sons de fundo;
- nome do arquivo, caminhos dentro de arquivos compactados, proprietário do compartilhamento na cloud, certificado de assinatura e histórico de revisões.

A sanitização pode danificar evidências ou autenticidade. Preserve um original criptografado quando a cadeia de custódia ou uma verificação posterior for importante. A estilometria e o estilo de programação também podem relacionar a autoria; a remoção de metadata não altera o estilo humano.

## Padrões comuns de falha

- Fazer login em uma conta pessoal por meio de uma conexão “anônima”.
- Reutilizar um telefone de recuperação, avatar, nome de usuário, chave pública, wallet ou endereço de doação.
- Operar duas identidades ao mesmo tempo a partir de contextos correlacionados.
- Copiar texto/arquivos por meio de uma área de transferência pessoal na cloud ou de uma pasta compartilhada.
- Instalar extensões distintas do Tor Browser ou alterar muitos padrões.
- Confiar em uma alegação de “no logs” sem entender o que é registrado, por quanto tempo e por quais subcontratados.
- Presumir que um telefone secundário é anônimo enquanto viaja junto com um telefone pessoal. A EFF observa que a localização celular e o deslocamento conjunto podem correlacionar os dispositivos.<sup>[[3]](#references)</sup>
- Tratar a criptografia como exclusão; endpoints e destinatários podem manter o texto em claro.

## Lista de verificação

- [ ] O contexto não contém endereço pessoal de recuperação, telefone, conta de sincronização ou mídia reutilizada, a menos que isso tenha sido aceito intencionalmente.
- [ ] O caminho de rede pretendido está ativo e falha de modo seguro.
- [ ] O fuso horário, a localidade, as extensões e as permissões do navegador/dispositivo correspondem ao plano.
- [ ] Nenhuma conta pessoal está aberta no compartimento.
- [ ] Os arquivos foram inspecionados e sanitizados; os originais são tratados separadamente.
- [ ] Os contatos são autenticados por um segundo canal.
- [ ] A metadata visível ao provedor e o período de retenção são compreendidos.
- [ ] Os procedimentos de desmontagem, retenção de evidências e recuperação de contas estão documentados.

## References

- [1] [EFF Surveillance Self-Defense — Seu plano de segurança](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Protegendo-se nas redes sociais](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Participando de um protesto](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Gerenciamento de autenticação e autenticadores](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Mitigando o fingerprinting de navegador em especificações da Web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Usando o Tor com outros navegadores](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins e complementos no Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Por que a metadata de comunicação é importante](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Privacidade do número de telefone e nomes de usuário: análise aprofundada](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — O que é criptografado no Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Avisos: o Tails é seguro, mas não é mágico](https://tails.net/doc/about/warnings/index.en.html)
