# Bypass de KYC usando AI

{{#include ../banners/hacktricks-training.md}}

Modelos generativos podem ser usados para **bypassar fluxos de KYC baseados em navegador, verificação de idade e liveness biométrico**. O ponto fraco geralmente **não** é o transporte nem o provedor cloud de liveness, mas o **limite de confiança da câmera**: um navegador desktop normalmente confia em qualquer dispositivo que `getUserMedia()` exponha como webcam.

## Cadeia de Ataque Prática

1. **Gere mídia compatível com o challenge** usando um modelo de video-to-video a partir de um ator de origem e de uma imagem de referência da vítima.
2. **Injete o stream forjado antes da assinatura ou do upload**, por exemplo por meio de uma câmera virtual Linux criada com `v4l2loopback` e alimentada pelo OBS ou FFmpeg.
3. Permita que o navegador e o SDK do fornecedor (WebRTC, AWS etc.) **capturem, assinem e façam upload dos frames controlados pelo atacante como se viessem de uma webcam real**.

Isso é importante durante assessments porque chunks WebSocket assinados ou o framing proprietário do SDK podem tornar a **adulteração na camada de rede** impraticável, enquanto a **injeção na camada da câmera** continua funcionando.

## Ângulos de Teste de Alto Valor

- **Aceitação de webcam virtual**: se o fluxo funciona em um navegador desktop, teste se OBS, `v4l2loopback` ou câmeras virtuais do fornecedor são aceitos como periféricos normais.
- **Redirecionamento da Camera API em dispositivos mobile**: fluxos mobile nativos ainda podem ser vulneráveis quando hooks do Frida interceptam APIs da câmera e substituem os buffers do sensor por frames de um MP4 ou de uma câmera virtual baseada em emulador.
- **Enfraquecimento de constraints**: páginas que exigem `deviceId`, `frameRate`, `width`, `height` ou `facingMode` exatos às vezes podem ser bypassadas com monkeypatch de `navigator.mediaDevices.getUserMedia`, substituindo constraints rígidos por intervalos mais amplos.
- **Geração de baixa qualidade com pós-processamento**: gere o vídeo mais barato que o modelo consiga renderizar de forma confiável e, em seguida, use upscaling do FFmpeg ou interpolação de frames para atender aos requisitos de captura.
- **Challenges ativos previsíveis**: sequências repetidas de movimentos da cabeça ou flashes de luz podem valer a pena ser gravadas e reproduzidas por meio de um fluxo generativo.
- **Detecção fraca de replay**: perturbações simples da cena, como alterações de crop ou posição, mudanças em overlays ou pequenos movimentos, podem ser suficientes quando a lógica anti-replay verifica apenas a similaridade superficial entre frames.

## Diferenças de Confiança entre Mobile e Desktop

Aplicativos mobile nativos podem aumentar o custo do atacante com:

- **attestation do sensor ou do Secure Element** para buffers da câmera;
- sinais de **integridade da execução**, como **Play Integrity** ou **App Attest**;
- **correlação de movimento** entre o vídeo e a telemetria do acelerômetro ou giroscópio.

Fluxos web desktop geralmente não têm uma cadeia de confiança equivalente para a câmera e, portanto, costumam ser o caminho de menor resistência.

## Notas de Revisão Defensiva

Ao revisar uma integração de KYC ou liveness, verifique se ela:

- permite um **fallback para navegador desktop** em um fluxo que foi modelado contra ameaças apenas para captura mobile;
- depende principalmente de **liveness algorítmico** sem uma escalada humana forte para sessões suspeitas;
- usa **challenges estáveis ou previsíveis** que podem ser pré-gravados e alimentados em um pipeline de geração;
- detecta **monkeypatch de `getUserMedia`**, câmeras virtuais, telemetria de hardware inconsistente do navegador ou ausência de attestation do dispositivo.

## Referências

- [Synacktiv - KYC: Bypass de verificação de idade usando modelos generativos de vídeo](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
