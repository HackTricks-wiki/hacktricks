# Sistemas operacionais focados em privacidade

Sistemas operacionais focados em privacidade reduzem erros de roteamento e persistência, mas nenhum consegue compensar comportamentos identificáveis ou hardware comprometido.

## Escolha o modelo de isolamento

| Sistema | Melhor uso | Persistência | Aplicação de rede | Principal desvantagem |
|---|---|---|---|---|
| **Tor Browser em um OS mantido** | Navegação ocasional e anônima na web | O estado do navegador normalmente é limitado à sessão | Apenas o tráfego do navegador | Os demais aplicativos e o host permanecem fora do Tor |
| **Tails** | Sessões portáteis, amnésicas e de finalidade única | Persistent Storage criptografado opcional | O tráfego da Internet é forçado pelo Tor | Reinicializações e atrito no fluxo de trabalho; confiança no firmware/hardware |
| **Whonix** | Aplicativos persistentes que precisam de roteamento forçado pelo Tor | VMs persistentes | Separação entre Gateway e Workstation | O host/hypervisor e a mistura de identidades continuam sendo fatores |
| **Qubes-Whonix** | Forte separação entre compartimentos para usuários avançados | Por qube | Qubes de rede dedicados e Whonix | Requisitos de hardware e complexidade operacional |

## Tails

O Tails inicializa independentemente a partir de mídia removível, roteia o tráfego da Internet pelo Tor e foi projetado para deixar o mínimo de estado local. Seus próprios avisos enfatizam que ele não pode proteger contra BIOS/firmware/hardware comprometidos, divulgações identificáveis, metadados de arquivos ou um observador poderoso correlacionando as duas pontas.<sup>[[1]](#references)</sup>

### Fluxo de trabalho do Tails para uma única finalidade

1. Baixe o Tails do site oficial em um computador confiável e atualizado e siga o processo oficial de verificação/instalação.
2. Use uma unidade USB compatível apenas para inicializar o Tails; não a use também como unidade geral de transferência de arquivos.
3. Inicialize em um hardware sob seu controle físico. Um OS live não pode neutralizar um keylogger de hardware ou firmware malicioso.
4. Mantenha o Persistent Storage desativado, a menos que o fluxo de trabalho realmente precise dele. Se ativado, persista apenas as categorias necessárias e use uma passphrase forte.
5. Conecte-se a uma rede legal. Se um captive portal for inevitável, use o Unsafe Browser do Tails apenas para o portal, não divulgue nenhuma identidade desnecessária, feche-o imediatamente e conecte-se ao Tor antes de qualquer atividade sensível.<sup>[[2]](#references)</sup>
6. Configure uma bridge do Tor se a visibilidade direta ou o bloqueio do Tor forem relevantes.
7. Realize **uma identidade/finalidade contextual por sessão**. O Tails recomenda reiniciar entre atividades que não devem ser vinculadas.<sup>[[1]](#references)</sup>
8. Inspecione e sanitize os arquivos antes de publicá-los. Não abra documentos ativos baixados em um aplicativo que possa contornar o contexto pretendido.
9. Desligue completamente ao terminar e mantenha o USB fisicamente seguro.

## Whonix

O Whonix separa um **Gateway** de roteamento Tor de uma **Workstation** cujos aplicativos não podem descobrir diretamente o IP externo. Isso reduz significativamente erros de proxy/DNS, mas o host, o hypervisor, o comportamento e os documentos ainda podem revelar a identidade. O Whonix alerta explicitamente contra usar uma Workstation para várias identidades ou combinar atividades anônimas e não anônimas.<sup>[[3]](#references)</sup>

### Fluxo de trabalho por compartimentos

1. Verifique a imagem do Whonix e a plataforma de virtualização usando fontes oficiais.
2. Aplique patches no host, no hypervisor, no Gateway e na Workstation antes do uso.
3. Clone uma Workstation nova para cada identidade ou engagement; nunca clone uma VM depois que um estado associado à identidade tiver sido introduzido.
4. Mantenha contas pessoais, pastas compartilhadas do host, sincronização da área de transferência, dispositivos USB e dados de horário/localização fora da Workstation.
5. Use snapshots para recuperação, não como substituto para backups ou separação de identidades.
6. Confirme que a Workstation não consegue acessar a Internet quando o Gateway está parado.
7. Para arquivos especialmente arriscados, use uma VM/qube descartável e exporte apenas um resultado sanitizado.

## Qubes OS e Qubes-Whonix

O Qubes implementa segurança por compartimentação com qubes baseados em Xen. Seu design limita que um comprometimento em um domínio alcance automaticamente os demais, mas os aplicativos dentro do **mesmo** qube não são isolados uns dos outros.<sup>[[4]](#references)</sup> Qubes descartáveis fornecem um estado novo para sites, arquivos e dispositivos não confiáveis.<sup>[[5]](#references)</sup>

Um layout prático:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Regras:

- Dê a cada qube um nível de confiança e uma finalidade de identidade.
- Mantenha os segredos em um qube de cofre offline e use operações explícitas de cópia/arquivo entre qubes.
- Abra arquivos e links não solicitados em disposables.
- Encaminhe apenas os qubes pretendidos pelo Whonix ou por um qube de VPN dedicado.
- Identifique as janelas de forma distinta e interrompa qubes não relacionados durante trabalhos sensíveis.
- Não presuma que dois qubes impedem a correlação se compartilharem contas, conteúdo, horários ou pagamentos.

## Verificação e manutenção

- Verifique as assinaturas/somas de verificação do instalador seguindo as instruções oficiais.
- Aplique patches primeiro nos templates e depois reinicie os qubes/VMs dependentes.
- Confirme o comportamento de negação de rede, DNS, IPv6, relógio, clipboard, diretórios compartilhados e atribuição de USB.
- Revise o Persistent Storage e os snapshots das VMs em busca de dados antigos que contenham informações de identidade.
- Mantenha backups offline criptografados de seeds/chaves e teste a restauração em um ambiente isolado.
- Reconstrua um compartimento após suspeitar de comprometimento; alterar o IP de saída é insuficiente.

## References

- [1] [Tails — Avisos: Tails é seguro, mas não é mágico](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Como entrar em uma rede usando um portal cativo](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Limitações do Whonix e do Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Objetivos de design de segurança](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Como usar disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
