# Injeção de sinal no forward link VSAT

{{#include ../../banners/hacktricks-training.md}}

Um terminal VSAT normalmente trata o downlink de satélite como tráfego vindo do hub do operador. Em um sistema DVB-RCS, esse forward link pode transportar tanto pacotes IP de usuário quanto mensagens de controle do modem. Se o receptor não autenticar uma mensagem antes de processá-la, um sinal injetado localmente pode atravessar a fronteira de confiança entre rádio e plano de controle. Isso é **injeção de downlink no terminal**, não um uplink para o satélite nem uma interceptação passiva do downlink. O resultado demonstrado depende da implementação do protocolo e da autenticação de mensagens do modem, não apenas do DVB-RCS.<sup>[[1]](#references)[[2]](#references)</sup>

## Teste em um laboratório com RF contida

Use um terminal próprio, seu firmware e um SDR conectado à entrada de recepção do modem por meio de atenuação adequada, ou uma configuração com RF blindada. Não transmita em um canal de satélite ativo. Primeiro, registre a portadora de inicialização, a taxa de símbolos e o ID da população configurados no terminal; esses dados orientam a aquisição do forward link.<sup>[[1]](#references)[[3]](#references)</sup> A cadeia de aquisição DVB-RCS usa a Network Information Table (NIT) para localizar a RCS Map Table (RMT) e, em seguida, a Program Association Table (PAT) e a Program Map Table (PMT) para localizar os fluxos de sinalização do forward link. Um terminal pode sintonizar várias portadoras de transport stream antes de chegar ao fluxo de dados.<sup>[[3]](#references)</sup>

1. Decodifique ou reconstrua o transport stream de inicialização do alvo e inspecione sua NIT, RMT, IDs de serviço, packet IDs (PIDs) e tratamento da referência de clock. Compare o padrão com o parser e os logs do alvo; uma ordenação ou descritores específicos do fornecedor podem impedir que um fluxo válido de outra forma seja aceito.
2. No transmissor de laboratório, encapsule uma sonda UDP inofensiva como `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` e envie-a por um SDR sink ao caminho de recepção isolado. Mantenha o Program Clock Reference (PCR) do transport stream consistente com a taxa de bytes, ou o modem poderá perder a sincronização antes de processar a sonda.
3. Confirme tanto o **lock do demodulador** quanto o recebimento da sonda em um endpoint interno próprio. O lock, por si só, prova apenas que a camada física aceitou a forma de onda. Em seguida, verifique se a *sinalização* de gerenciamento ou atualização sem autenticação está exposta, sem instalar uma imagem nem alterar a configuração do serviço.

O caso MDM2200 publicado usou um módulo de origem do GNU Radio para DVB-RCS/MPE/MPEG-TS e `gr-dtv` para modulação DVB-S2. O modem exigiu detalhes de inicialização específicos do alvo: um SDT antes da PAT/PMT, um descritor de conteúdo RCS com table ID `0x3E` e um byte privado da RMT igual a `0x01` para seu modo GSE/4CPM. Não presuma que esses valores funcionarão em outro terminal.<sup>[[1]](#references)</sup> Os pesquisadores também observaram que, na configuração testada, pacotes MPE multicast chegavam aos modems receptores; portanto, o direcionamento não se limitava a um endereço MAC unicast conhecido.<sup>[[1]](#references)</sup> Uma análise separada encontrou sinalização desprotegida de controle e atualização de software no sistema estudado, mas essa constatação precisa ser verificada em cada implementação.<sup>[[2]](#references)</sup>

Um túnel IPsec ou VPN para o tráfego de usuário não autentica a sinalização DVB-RCS anterior nem o parser de atualização do próprio modem. Em uma avaliação autorizada, diferencie a proteção criptográfica do **IP de usuário**, do **controle do forward link** e do tráfego de **manutenção/recuperação**, em vez de considerar um túnel seguro de usuário como prova de que a injeção de rádio está bloqueada.<sup>[[1]](#references)[[2]](#references)</sup>

Para uma inspeção inicial de I/Q, consulte [análise de sinais de rádio](../hardware-hacking/radio.md). Para inspecionar o firmware e o parser no nível da placa, consulte [análise de firmware](../firmware-analysis/). Volte à [visão geral de Radio Hacking](./) para ver outras interfaces.

## References

- [1] [Bisping et al. - Ataques de injeção de sinal sem fio contra modems satelitais VSAT (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: revelando problemas de segurança inerentes às práticas atuais de sistemas VSAT (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Canal de interação DVB para sistemas de distribuição via satélite](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
