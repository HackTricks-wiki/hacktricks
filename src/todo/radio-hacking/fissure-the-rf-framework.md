# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Entendimento e reverse engineering de sinais baseado em SDR independente de frequência**

FISSURE é um framework open-source de RF e reverse engineering projetado para todos os níveis de habilidade, com hooks para detecção e classificação de sinais, descoberta de protocolos, execução de ataques, manipulação de IQ, análise de vulnerabilidades, automação e AI/ML. O framework foi desenvolvido para promover a integração rápida de módulos de software, rádios, protocolos, dados de sinais, scripts, flow graphs, material de referência e ferramentas de terceiros. FISSURE é um facilitador de workflows que mantém o software em um único local e permite que as equipes se atualizem facilmente enquanto compartilham a mesma configuração-base comprovada para distribuições Linux específicas.<sup>[[1]](#references)[[2]](#references)</sup>

O framework e as ferramentas incluídas no FISSURE foram projetados para detectar a presença de energia de RF, entender as características de um sinal, coletar e analisar amostras, desenvolver técnicas de transmissão e/ou injeção e criar payloads ou mensagens personalizados. O FISSURE contém uma biblioteca crescente de informações sobre protocolos e sinais para auxiliar na identificação, criação de pacotes e fuzzing. Existem recursos de arquivamento online para baixar arquivos de sinais e criar playlists para simular tráfego e testar sistemas.

A base de código Python e a interface de usuário amigáveis permitem que iniciantes aprendam rapidamente sobre ferramentas e técnicas populares envolvendo RF e reverse engineering. Educadores de cybersecurity e engenharia podem aproveitar o material integrado ou utilizar o framework para demonstrar suas próprias aplicações do mundo real. Desenvolvedores e pesquisadores podem usar o FISSURE em suas tarefas diárias ou apresentar suas soluções de ponta a um público mais amplo. À medida que a conscientização e o uso do FISSURE crescem na comunidade, também crescerão a extensão de seus recursos e a abrangência da tecnologia que ele engloba.

**Informações adicionais**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Primeiros passos

**Compatível**

Há três branches dentro do FISSURE para facilitar a navegação pelos arquivos e reduzir a redundância de código. A branch Python2\_maint-3.7 contém uma base de código desenvolvida com Python2, PyQt4 e GNU Radio 3.7; a branch Python3\_maint-3.8 é desenvolvida com Python3, PyQt5 e GNU Radio 3.8; e a branch Python3\_maint-3.10 é desenvolvida com Python3, PyQt5 e GNU Radio 3.10.

|   Sistema operacional   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Em andamento (beta)**

Esses sistemas operacionais ainda estão em status beta. Eles estão em desenvolvimento e sabe-se que vários recursos estão ausentes. Os itens no installer podem entrar em conflito com programas existentes ou não ser instalados até que o status seja removido.

|     Sistema operacional     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Algumas ferramentas de software não funcionam em todos os sistemas operacionais. Consulte [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalação**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Isso instalará as dependências de software do PyQt necessárias para iniciar as GUIs de instalação, caso não sejam encontradas.

Em seguida, selecione a opção que melhor corresponde ao seu sistema operacional (ela deverá ser detectada automaticamente se o seu sistema operacional corresponder a uma das opções).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Recomenda-se instalar o FISSURE em um sistema operacional limpo para evitar conflitos existentes. Selecione todas as caixas de seleção recomendadas (botão Default) para evitar erros durante o uso das diversas ferramentas do FISSURE. Haverá várias solicitações durante a instalação, principalmente relacionadas a permissões elevadas e nomes de usuário. Se um item contiver uma seção "Verify" no final, o instalador executará o comando seguinte e destacará o item da caixa de seleção em verde ou vermelho, dependendo da ocorrência de erros produzidos pelo comando. Os itens selecionados sem uma seção "Verify" permanecerão pretos após a instalação.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abra um terminal e digite:
```
fissure
```
Consulte o menu Help do FISSURE para obter mais detalhes sobre o uso.

## Detalhes

**Componentes**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Recursos**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de sinais**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulação de IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Consulta de sinais**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconhecimento de padrões**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataques**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlists de sinais**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria de imagens**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Criação de pacotes**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integração com Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora de CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

A seguir está uma lista de hardware "compatível", com diferentes níveis de integração:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lições

O FISSURE inclui vários guias úteis para familiarização com diferentes tecnologias e técnicas. Muitos incluem etapas para usar diversas ferramentas integradas ao FISSURE.

* [Lição 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lição 2: Dissectores Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lição 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lição 4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lição 5: Rastreamento de radiossondas](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lição 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lição 7: Tipos de dados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lição 8: Blocos GNU Radio personalizados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lição 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lição 10: Exames de rádio amador](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lição 11: Ferramentas Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Adicionar mais tipos de hardware, protocolos RF, parâmetros de sinal e ferramentas de análise
* [ ] Oferecer suporte a mais sistemas operacionais
* [ ] Desenvolver material didático sobre o FISSURE (ataques RF, Wi-Fi, GNU Radio, PyQt etc.)
* [ ] Criar um condicionador de sinais, um extrator de características e um classificador de sinais com técnicas de AI/ML selecionáveis
* [ ] Implementar mecanismos de demodulação recursiva para produzir um bitstream a partir de sinais desconhecidos
* [ ] Migrar os principais componentes do FISSURE para um esquema genérico de implantação de nós sensores

## Contribuição

Sugestões para melhorar o FISSURE são muito bem-vindas. Deixe um comentário na página de [Discussões](https://github.com/ainfosec/FISSURE/discussions) ou no Discord Server caso tenha alguma ideia sobre os seguintes tópicos:

* Sugestões de novos recursos e alterações de design
* Ferramentas de software com etapas de instalação
* Novas lições ou material adicional para lições existentes
* Protocolos RF de interesse
* Mais tipos de hardware e SDR para integração
* Scripts de análise de IQ em Python
* Correções e melhorias na instalação

As contribuições para melhorar o FISSURE são essenciais para acelerar seu desenvolvimento. Todas as contribuições são muito apreciadas. Caso queira contribuir por meio do desenvolvimento de código, faça um fork do repositório e crie um pull request:

1. Faça um fork do projeto
2. Crie sua branch de recurso (`git checkout -b feature/AmazingFeature`)
3. Faça commit das suas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Envie as alterações para a branch (`git push origin feature/AmazingFeature`)
5. Abra um pull request

A criação de [Issues](https://github.com/ainfosec/FISSURE/issues) para chamar atenção para bugs também é bem-vinda.

## Colaboração

Entre em contato com o departamento de Desenvolvimento de Negócios da Assured Information Security, Inc. (AIS) para propor e formalizar oportunidades de colaboração com o FISSURE — seja dedicando tempo à integração do seu software, contando com as pessoas talentosas da AIS para desenvolver soluções para seus desafios técnicos ou integrando o FISSURE a outras plataformas/aplicações.

## Licença

GPL-3.0

Para obter detalhes sobre a licença, consulte o arquivo LICENSE.

## Contato

Entre no Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Siga no Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Desenvolvimento de Negócios - Assured Information Security, Inc. - bd@ainfosec.com

## Créditos

Reconhecemos e agradecemos a estes desenvolvedores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Agradecimentos

Agradecimentos especiais ao Dr. Samuel Mantravadi e a Joseph Reith por suas contribuições para este projeto.

## Referências

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
