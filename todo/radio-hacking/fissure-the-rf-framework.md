# FISSURE - O Framework RF

**Entendimento e Engenharia Reversa Baseados em SDR Independentes de Frequência**

FISSURE é um framework de engenharia reversa e RF de código aberto projetado para todos os níveis de habilidade, com ganchos para detecção e classificação de sinais, descoberta de protocolo, execução de ataque, manipulação de IQ, análise de vulnerabilidade, automação e AI/ML. O framework foi construído para promover a integração rápida de módulos de software, rádios, protocolos, dados de sinal, scripts, fluxogramas, material de referência e ferramentas de terceiros. FISSURE é um habilitador de fluxo de trabalho que mantém o software em um local e permite que as equipes se atualizem facilmente enquanto compartilham a mesma configuração de linha de base comprovada para distribuições Linux específicas.

O framework e as ferramentas incluídas no FISSURE são projetados para detectar a presença de energia RF, entender as características de um sinal, coletar e analisar amostras, desenvolver técnicas de transmissão e/ou injeção e criar payloads ou mensagens personalizadas. FISSURE contém uma biblioteca crescente de informações de protocolo e sinal para ajudar na identificação, criação de pacotes e fuzzing. Capacidades de arquivo online existem para baixar arquivos de sinal e criar listas de reprodução para simular tráfego e testar sistemas.

O código Python amigável e a interface do usuário permitem que iniciantes aprendam rapidamente sobre ferramentas e técnicas populares envolvendo RF e engenharia reversa. Educadores em cibersegurança e engenharia podem aproveitar o material integrado ou utilizar o framework para demonstrar suas próprias aplicações do mundo real. Desenvolvedores e pesquisadores podem usar o FISSURE para suas tarefas diárias ou para expor suas soluções de ponta a um público mais amplo. À medida que a conscientização e o uso do FISSURE crescem na comunidade, também crescerá a extensão de suas capacidades e a amplitude da tecnologia que ele abrange.

**Informações Adicionais**

* [Página AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slides GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Paper GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Vídeo GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcrição do Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Começando

**Suportado**

Existem três branches dentro do FISSURE para facilitar a navegação de arquivos e reduzir a redundância de código. O branch Python2\_maint-3.7 contém uma base de código construída em torno do Python2, PyQt4 e GNU Radio 3.7; o branch Python3\_maint-3.8 é construído em torno do Python3, PyQt5 e GNU Radio 3.8; e o branch Python3\_maint-3.10 é construído em torno do Python3, PyQt5 e GNU Radio 3.10.

|   Sistema Operacional   |   Branch FISSURE   |
| :---------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Em Progresso (beta)**

Esses sistemas operacionais ainda estão em status beta. Eles estão em desenvolvimento e vários recursos estão faltando. Itens no instalador podem entrar em conflito com programas existentes ou falhar na instalação até que o status seja removido.

|     Sistema Operacional     |    Branch FISSURE   |
| :-------------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Certas ferramentas de software não funcionam para todos os sistemas operacionais. Consulte [Software e Conflitos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalação**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Isso instalará as dependências de software do PyQt necessárias para iniciar as GUIs de instalação, caso não sejam encontradas.

Em seguida, selecione a opção que melhor corresponda ao seu sistema operacional (deve ser detectado automaticamente se o seu SO corresponder a uma opção).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Recomenda-se instalar o FISSURE em um sistema operacional limpo para evitar conflitos existentes. Selecione todas as caixas de seleção recomendadas (botão padrão) para evitar erros ao operar as várias ferramentas dentro do FISSURE. Haverá várias solicitações durante a instalação, principalmente solicitando permissões elevadas e nomes de usuário. Se um item contiver uma seção "Verificar" no final, o instalador executará o comando que segue e destacará o item da caixa de seleção em verde ou vermelho, dependendo se houver erros produzidos pelo comando. Itens marcados sem uma seção "Verificar" permanecerão pretos após a instalação.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abra um terminal e digite:
```
fissure
```
Consulte o menu de ajuda do FISSURE para obter mais detalhes sobre o uso.

## Detalhes

**Componentes**

* Painel de controle
* Central Hub (HIPRFISR)
* Identificação de Sinal Alvo (TSI)
* Descoberta de Protocolo (PD)
* Fluxo de Gráfico e Executor de Script (FGE)

![componentes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capacidades**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de Sinal**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulação de IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Busca de Sinal**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconhecimento de Padrões**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataques**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listas de Reprodução de Sinal**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria de Imagens**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Criação de Pacotes**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integração Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Registro**_            |

**Hardware**

A seguir, uma lista de hardware "suportado" com vários níveis de integração:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lições

O FISSURE vem com vários guias úteis para se familiarizar com diferentes tecnologias e técnicas. Muitos incluem etapas para usar várias ferramentas integradas ao FISSURE.

* [Lições1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lições2: Dissectors Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lições3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lições4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lições5: Rastreamento de Radiossonda](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lições6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lições7: Tipos de Dados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lições8: Blocos GNU Radio Personalizados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lições9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lições10: Exames de Rádio Amador](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lições11: Ferramentas Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Adicionar mais tipos de hardware, protocolos RF, parâmetros de sinal, ferramentas de análise
* [ ] Suportar mais sistemas operacionais
* [ ] Desenvolver material de aula em torno do FISSURE (Ataques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Criar um condicionador de sinal, extrator de recursos e classificador de sinal com técnicas AI/ML selecionáveis
* [ ] Implementar mecanismos de demodulação recursiva para produzir um fluxo de bits a partir de sinais desconhecidos
* [ ] Transição dos principais componentes do FISSURE para um esquema de implantação de nó de sensor genérico

## Contribuindo

Sugestões para melhorar o FISSURE são fortemente encorajadas. Deixe um comentário na página de [Discussões](https://github.com/ainfosec/FISSURE/discussions) ou no servidor Discord se tiver alguma ideia sobre o seguinte:

* Novas sugestões de recursos e mudanças de design
* Ferramentas de software com etapas de instalação
* Novas lições ou material adicional para lições existentes
* Protocolos RF de interesse
* Mais tipos de hardware e SDR para integração
* Scripts de análise IQ em Python
* Correções e melhorias de instalação

Contribuições para melhorar o FISSURE são cruciais para acelerar seu desenvolvimento. Todas as contribuições que você fizer são muito apreciadas. Se você deseja contribuir por meio do desenvolvimento de código, faça um fork do repositório e crie uma solicitação de pull:

1. Faça um fork do projeto
2. Crie sua branch de recurso (`git checkout -b feature/AmazingFeature`)
3. Faça commit de suas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Envie para a branch (`git push origin feature/AmazingFeature`)
5. Abra uma solicitação de pull

A criação de [Issues](https://github.com/ainfosec/FISSURE/issues) para chamar a atenção para bugs também é bem-vinda.

## Colaborando

Entre em contato com o Desenvolvimento de Negócios da Assured Information Security, Inc. (AIS) para propor e formalizar quaisquer oportunidades de colaboração do FISSURE - seja dedicando tempo para integrar seu software, tendo as pessoas talentosas da AIS desenvolvendo soluções para seus desafios técnicos ou integrando o FISSURE em outras plataformas/aplicações.

## Licença

GPL-3.0

Para detalhes da licença, consulte o arquivo LICENSE.

## Contato

Junte-se ao servidor Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Siga no Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Desenvolvimento de Negócios - Assured Information Security, Inc. - bd@ainfosec.com

## Créditos

Reconhecemos e somos gratos a esses desenvolvedores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Agradecimentos

Agradecimentos especiais ao Dr. Samuel Mantravadi e Joseph Reith por suas contribuições para este projeto.
