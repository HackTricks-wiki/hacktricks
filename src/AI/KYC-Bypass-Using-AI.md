# Bypass de KYC Usando IA

{{#include ../banners/hacktricks-training.md}}

Modelos generativos podem ser usados para **bypass de fluxos de KYC baseados em navegador, verificação de idade e prova de vida biométrica**. O ponto fraco geralmente **não** é o transporte ou o provedor cloud de prova de vida, mas o **limite de confiança da câmera**: um navegador desktop geralmente confia em qualquer dispositivo que `getUserMedia()` exponha como webcam.<sup>[[1]](#references)</sup>

## Cadeia de Ataque Prática

1. **Gere mídia compatível com os desafios** usando um modelo de video-to-video, com um ator de origem e uma imagem de referência da vítima.<sup>[[1]](#references)</sup>
2. **Injete o fluxo forjado antes da assinatura ou do upload**, por exemplo, usando uma câmera virtual Linux criada com `v4l2loopback` e alimentada pelo OBS ou FFmpeg.<sup>[[3]](#references)</sup>
3. Permita que o navegador e o SDK do fornecedor (WebRTC, AWS etc.) **capturem, assinem e façam upload dos frames controlados pelo atacante como se tivessem vindo de uma webcam real**.<sup>[[2]](#references)</sup>

Isso é importante durante avaliações porque chunks assinados de WebSocket ou o framing proprietário do SDK podem tornar a **adulteração na camada de rede** impraticável, enquanto a **injeção na camada da câmera** continua funcionando.<sup>[[1]](#references)</sup>

## Abordagens de Teste de Alto Valor

- **Aceitação de webcam virtual**: se o fluxo funcionar a partir de um navegador desktop, teste se OBS, `v4l2loopback` ou câmeras virtuais do fornecedor são aceitos como periféricos normais.<sup>[[1]](#references)</sup>
- **Redirecionamento da Camera API em dispositivos móveis**: fluxos móveis nativos ainda podem estar vulneráveis quando hooks do Frida interceptam APIs da câmera e substituem buffers do sensor por frames de um MP4 ou de uma câmera virtual baseada em emulador.
- **Enfraquecimento de constraints**: páginas que exigem `deviceId`, `frameRate`, `width`, `height` ou `facingMode` exatos às vezes podem ser bypassadas fazendo monkeypatch de `navigator.mediaDevices.getUserMedia` e substituindo constraints rígidas por intervalos mais amplos.<sup>[[4]](#references)</sup>
- **Geração de baixa qualidade com pós-processamento**: gere o vídeo mais barato que o modelo consiga renderizar de forma confiável e, em seguida, use upscaling do FFmpeg ou interpolação de frames para atender aos requisitos de captura.
- **Desafios ativos previsíveis**: sequências repetidas de movimentos da cabeça ou flashes de luz merecem ser gravadas e reproduzidas por meio de um fluxo generativo.
- **Detecção de replay fraca**: alterações simples na cena, como mudanças de recorte ou posição, mudanças em overlays ou movimentos leves, podem ser suficientes quando a lógica anti-replay verifica apenas a similaridade superficial entre frames.<sup>[[1]](#references)</sup>

## Diferenças de Confiança entre Mobile e Desktop

Aplicativos móveis nativos podem aumentar o custo do atacante com:<sup>[[1]](#references)</sup>

- **atestation do sensor ou do Secure Element** para buffers da câmera;
- sinais de **integridade da execução**, como **Play Integrity** ou **App Attest**;
- **correlação de movimento** entre o vídeo e os dados de telemetria do acelerômetro ou giroscópio.

Fluxos web em desktop geralmente não possuem uma cadeia de confiança equivalente para a câmera e, portanto, costumam ser o caminho de menor resistência.<sup>[[1]](#references)</sup>

## Observações para Revisão Defensiva

Ao revisar uma integração de KYC ou prova de vida, verifique se ela:<sup>[[1]](#references)</sup>

- permite um **fallback para navegador desktop** em um fluxo que foi modelado contra ameaças apenas para captura móvel;
- depende principalmente de **prova de vida algorítmica** sem uma forte escalada para análise humana em sessões suspeitas;
- usa **desafios estáveis ou previsíveis** que podem ser pré-gravados e inseridos em um pipeline de geração;
- detecta **monkeypatching de `getUserMedia`**, câmeras virtuais, telemetria de hardware inconsistente do navegador ou ausência de atestation do dispositivo.<sup>[[1]](#references)</sup>

## Referências

- [1] [Synacktiv - KYC: Bypass da verificação de idade usando modelos generativos de vídeo](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
