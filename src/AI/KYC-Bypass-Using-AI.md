# Bypass de KYC usando AI

{{#include ../banners/hacktricks-training.md}}

Modelos generativos podem ser usados para **bypassar fluxos de KYC baseados em navegador, verificação de idade e liveness biométrico**. O ponto fraco geralmente **não** é o transporte nem o provedor de liveness na cloud, mas a **fronteira de confiança da câmera**: um navegador desktop normalmente confia em qualquer dispositivo que `getUserMedia()` exponha como webcam.<sup>[[1]](#references)</sup>

## Cadeia de Ataque Prática

1. **Gere mídia compatível com os desafios** usando um modelo video-to-video, com um ator de origem e uma imagem de referência da vítima.<sup>[[1]](#references)</sup>
2. **Injete o stream forjado antes da assinatura ou do upload**, por exemplo, por meio de uma câmera virtual Linux criada com `v4l2loopback` e alimentada pelo OBS ou FFmpeg.<sup>[[3]](#references)</sup>
3. Permita que o navegador e o SDK do fornecedor (WebRTC, AWS etc.) **capturem, assinem e façam upload dos frames controlados pelo atacante como se tivessem vindo de uma webcam real**.<sup>[[2]](#references)</sup>

Isso é importante durante assessments porque chunks assinados de WebSocket ou o framing proprietário do SDK podem tornar a **adulteração na camada de rede** impraticável, enquanto a **injeção na camada da câmera** continua funcionando.<sup>[[1]](#references)</sup>

## Abordagens de Teste de Alto Valor

- **Aceitação de webcam virtual**: se o fluxo funcionar a partir de um navegador desktop, teste se OBS, `v4l2loopback` ou câmeras virtuais do fornecedor são aceitos como periféricos normais.<sup>[[1]](#references)</sup>
- **Redirecionamento da API da câmera em dispositivos móveis**: fluxos nativos ainda podem ser vulneráveis quando a instrumentação em runtime, como o Frida, aplica hooks nas APIs da câmera e substitui os buffers do sensor por frames de um arquivo MP4 ou de uma câmera virtual baseada em emulador. Isso exige controle do ambiente de execução do cliente e deve ser avaliado junto com sinais de root/jailbreak e de integridade da aplicação.<sup>[[1]](#references)</sup>
- **Enfraquecimento de constraints**: páginas que exigem `deviceId`, `frameRate`, `width`, `height` ou `facingMode` exatos às vezes podem ser bypassadas aplicando monkeypatch em `navigator.mediaDevices.getUserMedia` e substituindo constraints rígidas por intervalos mais amplos.<sup>[[4]](#references)</sup>
- **Geração de baixa qualidade com pós-processamento**: teste se um vídeo gerado de baixo custo pode ser ampliado ou interpolado entre frames com FFmpeg o suficiente para atender às constraints de captura.<sup>[[1]](#references)</sup>
- **Desafios ativos previsíveis**: sequências repetidas de movimentos da cabeça ou flashes de luz merecem ser gravadas e reproduzidas por meio de um fluxo generativo.
- **Detecção de replay fraca**: perturbações simples na cena, como alterações de crop ou posição, mudanças em overlays ou pequenos movimentos, podem ser suficientes quando a lógica anti-replay verifica apenas similaridade superficial entre frames.<sup>[[1]](#references)</sup>

## Diferenças de Confiança entre Mobile e Desktop

Aplicativos móveis nativos podem aumentar o custo do atacante com:<sup>[[1]](#references)</sup>

- **sinais de proveniência ou atestação baseados em hardware**, incluindo evidências respaldadas pelo Secure Element quando a plataforma e a stack de captura realmente as expõem;
- sinais de **integridade da execução**, como **Play Integrity** ou **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **correlação de movimento** entre o vídeo e a telemetria do acelerômetro ou giroscópio.

Fluxos web desktop geralmente não possuem uma cadeia de confiança equivalente para a câmera, portanto normalmente são o caminho de menor resistência.<sup>[[1]](#references)</sup>

## Observações para Revisão Defensiva

Ao revisar uma integração de KYC ou liveness, verifique se ela:<sup>[[1]](#references)</sup>

- permite um **fallback para navegador desktop** em um fluxo cujo threat model considerava apenas a captura móvel;
- depende principalmente de **liveness algorítmico** sem uma escalada humana robusta para sessões suspeitas;
- usa **desafios estáveis ou previsíveis** que podem ser pré-gravados e enviados a um pipeline de geração;
- detecta **monkeypatching de `getUserMedia`**, câmeras virtuais, telemetria de hardware inconsistente do navegador ou ausência de atestação do dispositivo.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass da verificação de idade usando modelos generativos de vídeo](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — API Play Integrity](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
