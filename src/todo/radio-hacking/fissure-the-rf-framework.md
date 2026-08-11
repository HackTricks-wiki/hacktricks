# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Entendimento e Engenharia Reversa de Sinais Baseados em SDR Independente de Frequência**

FISSURE é um framework open-source de RF e engenharia reversa projetado para todos os níveis de habilidade, com integrações para detecção e classificação de sinais, descoberta de protocolos, execução de ataques, manipulação de IQ, análise de vulnerabilidades, automação e AI/ML. O framework foi criado para promover a integração rápida de módulos de software, rádios, protocolos, dados de sinais, scripts, flow graphs, material de referência e ferramentas de terceiros. FISSURE é um facilitador de workflows que mantém o software em um único local e permite que as equipes se familiarizem rapidamente enquanto compartilham a mesma configuração de referência comprovada para distribuições Linux específicas.<sup>[[1]](#references)[[2]](#references)</sup>

O framework e as ferramentas incluídas no FISSURE foram projetados para detectar energia de RF, caracterizar sinais, coletar e analisar amostras, desenvolver técnicas de transmissão ou injeção e criar payloads ou mensagens personalizados. FISSURE também fornece informações sobre protocolos e sinais para identificação, criação de pacotes e fuzzing, além de arquivos e playlists para simulação e teste de tráfego.<sup>[[1]](#references)[[2]](#references)</sup>

A base de código Python e a interface gráfica ajudam iniciantes a aprender ferramentas de RF e engenharia reversa. Educadores podem usar as lições integradas, enquanto desenvolvedores e pesquisadores podem integrar seus próprios módulos e workflows. As versões atuais também oferecem suporte a nós sensores distribuídos, integração com TAK, workflows de geolocalização e deployments do Apptainer específicos para cada função.<sup>[[1]](#references)[[3]](#references)</sup>

**Informações Adicionais**

* [Página do AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slides do GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artigo do GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Vídeo do GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcrição do Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Primeiros Passos

**Compatibilidade**

Atualmente, o FISSURE usa o branch **`Python3`** para desenvolvimento ativo com PyQt5 e GNU Radio 3.8 ou 3.10. O branch obsoleto **`Python2_maint-3.7`** continua disponível para sistemas operacionais mais antigos e ferramentas de terceiros que exigem GNU Radio 3.7. Os antigos nomes de branch `Python3_maint-3.8` e `Python3_maint-3.10` são históricos; a seleção da versão de manutenção do GNU Radio agora é feita a partir do branch `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Sistema Operacional | Branch do FISSURE | Branch padrão do GNU Radio |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | use uma versão Linux compatível | use a versão correspondente |

**Em Andamento (beta)**

Estes sistemas operacionais ainda estão em status beta. Eles estão em desenvolvimento e sabe-se que vários recursos estão ausentes. Os itens do instalador podem entrar em conflito com programas existentes ou não conseguir ser instalados até que esse status seja removido.

| Sistema Operacional | Branch do FISSURE | Branch padrão do GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Algumas ferramentas de terceiros não funcionam em todos os sistemas operacionais. Consulte a documentação atual de [Conflitos Conhecidos e Software de Terceiros](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) antes de instalar.<sup>[[3]](#references)</sup>

**Instalação**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
A etapa do submódulo baixa os módulos GNU Radio out-of-tree usados pelo FISSURE e é necessária ao instalar esses módulos. O instalador também instalará as dependências PyQt ausentes necessárias para iniciar suas GUIs de instalação.<sup>[[3]](#references)</sup>

Em seguida, selecione a opção que melhor corresponde ao seu sistema operacional (ela deverá ser detectada automaticamente se o seu sistema operacional corresponder a uma das opções).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Recomenda-se instalar o FISSURE em um sistema operacional limpo para evitar conflitos existentes. Selecione todas as caixas de seleção recomendadas (botão Default) para evitar erros ao operar as diversas ferramentas do FISSURE. Haverá várias solicitações durante a instalação, principalmente solicitando permissões elevadas e nomes de usuário. Se um item contiver uma seção "Verify" ao final, o instalador executará o comando subsequente e destacará o item da caixa de seleção em verde ou vermelho, dependendo de serem produzidos erros pelo comando. Os itens marcados sem uma seção "Verify" permanecerão pretos após a instalação.

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

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de sinais**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulação de IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Busca de sinais**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconhecimento de padrões**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlists de sinais**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria de imagens**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Criação de pacotes**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integração com Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora de CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

O hardware a seguir possui diferentes níveis de integração com o FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lições

O FISSURE inclui vários guias úteis para se familiarizar com diferentes tecnologias e técnicas. Muitos incluem etapas para usar várias ferramentas integradas ao FISSURE.

* [Lição 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lição 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lição 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lição 4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lição 5: Rastreamento de radiossondas](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lição 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lição 7: Tipos de dados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lição 8: Blocos personalizados do GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lição 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lição 10: Exames de Ham Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lição 11: Ferramentas de Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lição 12: Criação de USBs inicializáveis](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lição 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lição 14: Ventiladores de teto](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] Adicionar mais tipos de hardware, protocolos de RF, parâmetros de sinal e ferramentas de análise
* [ ] Oferecer suporte a mais sistemas operacionais
* [ ] Desenvolver material didático sobre o FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt etc.)
* [ ] Criar um condicionador de sinais, um extrator de características e um classificador de sinais com técnicas de AI/ML selecionáveis
* [ ] Implementar mecanismos de demodulação recursiva para produzir um bitstream a partir de sinais desconhecidos
* [ ] Migrar os principais componentes do FISSURE para um esquema genérico de implantação de nós sensores

## Contribuição

Sugestões para melhorar o FISSURE são muito bem-vindas. Deixe um comentário na página de [Discussions](https://github.com/ainfosec/FISSURE/discussions) ou no Discord Server se tiver alguma ideia sobre os seguintes tópicos:

* Sugestões de novos recursos e alterações de design
* Ferramentas de software com etapas de instalação
* Novas lições ou material adicional para lições existentes
* Protocolos de RF de interesse
* Mais tipos de hardware e SDR para integração
* Scripts de análise de IQ em Python
* Correções e melhorias na instalação

As contribuições para melhorar o FISSURE são cruciais para acelerar seu desenvolvimento. Qualquer contribuição que você fizer será muito apreciada. Se quiser contribuir por meio do desenvolvimento de código, faça um fork do repo e crie um pull request:

1. Faça um fork do projeto
2. Crie sua feature branch (`git checkout -b feature/AmazingFeature`)
3. Faça commit das suas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Faça push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um pull request

A criação de [Issues](https://github.com/ainfosec/FISSURE/issues) para chamar a atenção para bugs também é bem-vinda.

## Colaboração

Entre em contato com o departamento de Business Development da Assured Information Security, Inc. (AIS) para propor e formalizar quaisquer oportunidades de colaboração com o FISSURE, seja dedicando tempo à integração do seu software, contando com o desenvolvimento de soluções pela talentosa equipe da AIS para seus desafios técnicos ou integrando o FISSURE a outras plataformas/aplicações.

## Licença

GPL-3.0

Para obter detalhes sobre a licença, consulte o arquivo LICENSE.

## Contato

Participe do Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Siga no Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Créditos

Reconhecemos e agradecemos a estes desenvolvedores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Agradecimentos

Agradecimentos especiais ao Dr. Samuel Mantravadi e a Joseph Reith por suas contribuições para este projeto.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
