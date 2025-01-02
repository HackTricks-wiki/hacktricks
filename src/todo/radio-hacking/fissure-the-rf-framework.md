# FISSURE - The RF Framework

**Compreensão e Engenharia Reversa de Sinais SDR Independentes de Frequência**

FISSURE é um framework de RF e engenharia reversa de código aberto projetado para todos os níveis de habilidade, com ganchos para detecção e classificação de sinais, descoberta de protocolos, execução de ataques, manipulação de IQ, análise de vulnerabilidades, automação e IA/ML. O framework foi construído para promover a integração rápida de módulos de software, rádios, protocolos, dados de sinal, scripts, gráficos de fluxo, material de referência e ferramentas de terceiros. FISSURE é um facilitador de fluxo de trabalho que mantém o software em um único local e permite que as equipes se atualizem facilmente enquanto compartilham a mesma configuração base comprovada para distribuições específicas do Linux.

O framework e as ferramentas incluídas no FISSURE são projetados para detectar a presença de energia RF, entender as características de um sinal, coletar e analisar amostras, desenvolver técnicas de transmissão e/ou injeção e criar cargas úteis ou mensagens personalizadas. O FISSURE contém uma biblioteca crescente de informações sobre protocolos e sinais para auxiliar na identificação, criação de pacotes e fuzzing. Existem capacidades de arquivo online para baixar arquivos de sinal e construir playlists para simular tráfego e testar sistemas.

A base de código Python amigável e a interface do usuário permitem que iniciantes aprendam rapidamente sobre ferramentas e técnicas populares envolvendo RF e engenharia reversa. Educadores em cibersegurança e engenharia podem aproveitar o material embutido ou utilizar o framework para demonstrar suas próprias aplicações do mundo real. Desenvolvedores e pesquisadores podem usar o FISSURE para suas tarefas diárias ou para expor suas soluções de ponta a um público mais amplo. À medida que a conscientização e o uso do FISSURE crescem na comunidade, também crescerá a extensão de suas capacidades e a abrangência da tecnologia que abrange.

**Informações Adicionais**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Começando

**Suportado**

Existem três ramificações dentro do FISSURE para facilitar a navegação de arquivos e reduzir a redundância de código. A ramificação Python2\_maint-3.7 contém uma base de código construída em torno do Python2, PyQt4 e GNU Radio 3.7; a ramificação Python3\_maint-3.8 é construída em torno do Python3, PyQt5 e GNU Radio 3.8; e a ramificação Python3\_maint-3.10 é construída em torno do Python3, PyQt5 e GNU Radio 3.10.

|   Sistema Operacional   |   Ramificação FISSURE   |
| :---------------------: | :---------------------: |
|  Ubuntu 18.04 (x64)    | Python2\_maint-3.7     |
| Ubuntu 18.04.5 (x64)   | Python2\_maint-3.7     |
| Ubuntu 18.04.6 (x64)   | Python2\_maint-3.7     |
| Ubuntu 20.04.1 (x64)   | Python3\_maint-3.8     |
| Ubuntu 20.04.4 (x64)   | Python3\_maint-3.8     |
|  KDE neon 5.25 (x64)   | Python3\_maint-3.8     |

**Em Andamento (beta)**

Esses sistemas operacionais ainda estão em status beta. Eles estão em desenvolvimento e vários recursos são conhecidos por estarem ausentes. Itens no instalador podem entrar em conflito com programas existentes ou falhar na instalação até que o status seja removido.

|     Sistema Operacional     |    Ramificação FISSURE   |
| :-------------------------: | :----------------------: |
| DragonOS Focal (x86\_64)   |  Python3\_maint-3.8     |
|    Ubuntu 22.04 (x64)      | Python3\_maint-3.10     |

Nota: Certas ferramentas de software não funcionam para todos os sistemas operacionais. Consulte [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalação**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Isso instalará as dependências de software PyQt necessárias para iniciar as GUIs de instalação, caso não sejam encontradas.

Em seguida, selecione a opção que melhor corresponde ao seu sistema operacional (deve ser detectado automaticamente se o seu SO corresponder a uma opção).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

É recomendável instalar o FISSURE em um sistema operacional limpo para evitar conflitos existentes. Selecione todas as caixas de seleção recomendadas (botão padrão) para evitar erros ao operar as várias ferramentas dentro do FISSURE. Haverá vários prompts durante a instalação, principalmente solicitando permissões elevadas e nomes de usuário. Se um item contiver uma seção "Verificar" no final, o instalador executará o comando que se segue e destacará o item da caixa de seleção em verde ou vermelho, dependendo se algum erro for produzido pelo comando. Itens marcados sem uma seção "Verificar" permanecerão pretos após a instalação.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abra um terminal e digite:
```
fissure
```
Consulte o menu de Ajuda do FISSURE para mais detalhes sobre o uso.

## Detalhes

**Componentes**

* Dashboard
* Central Hub (HIPRFISR)
* Identificação de Sinal Alvo (TSI)
* Descoberta de Protocólos (PD)
* Gráfico de Fluxo & Executor de Script (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capacidades**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de Sinal**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulação de IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Busca de Sinal**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconhecimento de Padrão**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataques**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlists de Sinal**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria de Imagens**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Criação de Pacotes**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integração com Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora de CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Registro**_            |

**Hardware**

A seguir está uma lista de hardware "suportado" com diferentes níveis de integração:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lições

O FISSURE vem com vários guias úteis para se familiarizar com diferentes tecnologias e técnicas. Muitos incluem etapas para usar várias ferramentas que estão integradas ao FISSURE.

* [Lição1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lição2: Dissectores Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lição3: Troca de Som](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lição4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lição5: Rastreamento de Radiossonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lição6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lição7: Tipos de Dados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lição8: Blocos GNU Radio Personalizados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lição9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lição10: Exames de Rádio Amador](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lição11: Ferramentas Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roteiro

* [ ] Adicionar mais tipos de hardware, protocolos RF, parâmetros de sinal, ferramentas de análise
* [ ] Suportar mais sistemas operacionais
* [ ] Desenvolver material de aula em torno do FISSURE (Ataques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Criar um condicionador de sinal, extrator de características e classificador de sinal com técnicas AI/ML selecionáveis
* [ ] Implementar mecanismos de demodulação recursiva para produzir um bitstream a partir de sinais desconhecidos
* [ ] Transitar os principais componentes do FISSURE para um esquema de implantação de nó sensor genérico

## Contribuindo

Sugestões para melhorar o FISSURE são fortemente encorajadas. Deixe um comentário na página de [Discussões](https://github.com/ainfosec/FISSURE/discussions) ou no Servidor Discord se você tiver alguma ideia sobre o seguinte:

* Sugestões de novas funcionalidades e mudanças de design
* Ferramentas de software com etapas de instalação
* Novas lições ou material adicional para lições existentes
* Protocolos RF de interesse
* Mais tipos de hardware e SDR para integração
* Scripts de análise de IQ em Python
* Correções e melhorias de instalação

Contribuições para melhorar o FISSURE são cruciais para acelerar seu desenvolvimento. Quaisquer contribuições que você fizer são muito apreciadas. Se você deseja contribuir através do desenvolvimento de código, por favor, faça um fork do repositório e crie um pull request:

1. Fork o projeto
2. Crie sua branch de funcionalidade (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Adicionar alguma AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um pull request

Criar [Issues](https://github.com/ainfosec/FISSURE/issues) para chamar a atenção para bugs também é bem-vindo.

## Colaborando

Entre em contato com a Assured Information Security, Inc. (AIS) Desenvolvimento de Negócios para propor e formalizar quaisquer oportunidades de colaboração com o FISSURE – seja dedicando tempo para integrar seu software, tendo as pessoas talentosas da AIS desenvolvendo soluções para seus desafios técnicos, ou integrando o FISSURE em outras plataformas/aplicações.

## Licença

GPL-3.0

Para detalhes da licença, consulte o arquivo LICENSE.

## Contato

Junte-se ao Servidor Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Siga no Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Desenvolvimento de Negócios - Assured Information Security, Inc. - bd@ainfosec.com

## Créditos

Reconhecemos e somos gratos a esses desenvolvedores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Agradecimentos

Agradecimentos especiais ao Dr. Samuel Mantravadi e Joseph Reith por suas contribuições a este projeto.
