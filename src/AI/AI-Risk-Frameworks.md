# AI 위험

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp는 AI 시스템에 영향을 줄 수 있는 상위 10가지 machine learning 취약점을 식별했습니다. 이러한 취약점은 데이터 중독(data poisoning), model inversion, 적대적 공격(adversarial attacks) 등 다양한 보안 문제로 이어질 수 있습니다. 이러한 취약점을 이해하는 것은 안전한 AI 시스템을 구축하는 데 중요합니다.

상위 10가지 machine learning 취약점의 최신 상세 목록은 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 프로젝트를 참조하세요.

- **Input Manipulation Attack**: 공격자가 **들어오는 데이터**에 작고 종종 눈에 보이지 않는 변경을 추가하여 모델이 잘못된 결정을 내리게 합니다.\
*예시*: 정지 표지판에 소량의 페인트를 칠해 자율주행차가 속도 제한 표지판으로 "인식"하게 만듭니다.

- **Data Poisoning Attack**: **학습 세트(training set)**가 악의적으로 오염되어 모델에 해로운 규칙을 학습시킵니다.\
*예시*: 악성 바이너리가 안티바이러스 학습 코퍼스에 "정상"으로 잘못 라벨링되어 유사한 악성코드가 나중에 탐지되지 않게 합니다.

- **Model Inversion Attack**: 출력값을 탐색하여 공격자가 원본 입력의 민감한 특징을 재구성하는 **역(逆) 모델**을 구축합니다.\
*예시*: 암 진단 모델의 예측값으로부터 환자의 MRI 이미지를 재생성하는 경우.

- **Membership Inference Attack**: 공격자는 자신이 관심 있는 **특정 레코드**가 학습에 사용되었는지 자신감(confidence) 차이를 관찰해 테스트합니다.\
*예시*: 한 사람의 은행 거래가 사기 탐지 모델의 학습 데이터에 포함되었는지 확인하는 경우.

- **Model Theft**: 반복적인 쿼리로 공격자는 의사결정 경계를 학습하여 **모델의 동작을 복제(clone)** 합니다(및 지적 재산권 침해).\
*예시*: ML-as-a-Service API에서 충분한 Q&A 쌍을 수집해 근사한 로컬 모델을 만드는 경우.

- **AI Supply‑Chain Attack**: **ML 파이프라인**의 어떤 구성 요소(데이터, 라이브러리, 사전학습된 weights, CI/CD 등)를 침해하면 하류 모델들이 오염됩니다.\
*예시*: 모델 허브의 악성 의존성이 감염되어 많은 앱에 백도어가 있는 감성분석 모델을 설치하는 경우.

- **Transfer Learning Attack**: 악의적 로직이 **사전학습된 모델(pre‑trained model)**에 심겨지고 피해자의 작업에 맞춰 fine‑tuning해도 남아 있습니다.\
*예시*: 숨겨진 트리거가 있는 vision backbone이 의료 영상으로 적응된 이후에도 라벨을 뒤집어 버리는 경우.

- **Model Skewing**: 미묘하게 편향되거나 잘못 라벨된 데이터가 **모델의 출력**을 공격자 의도에 맞게 이동시킵니다.\
*예시*: 스팸 필터가 향후 유사한 메일을 통과시키도록 스팸 이메일을 "정상(ham)"으로 라벨링하여 주입하는 경우.

- **Output Integrity Attack**: 공격자는 모델 자체가 아닌 전송 중에 **모델 예측을 변경**하여 하류 시스템을 속입니다.\
*예시*: 파일 격리 단계에 도달하기 전에 악성분류기의 "malicious" 판정을 "benign"으로 바꾸는 경우.

- **Model Poisoning** --- 쓰기 권한을 얻은 후 종종 **모델 파라미터** 자체를 직접 타겟으로 변경하여 동작을 바꿉니다.\
*예시*: 운영 중인 사기탐지 모델의 가중치를 조정하여 특정 카드의 거래가 항상 승인되게 하는 경우.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)은 AI 시스템과 관련된 다양한 위험을 개략적으로 설명합니다:

- **Data Poisoning**: 악의적 행위자가 학습/튜닝 데이터를 변경하거나 주입하여 정확도를 저하시키거나 백도어를 심거나 결과를 왜곡하여 전체 데이터 라이프사이클에 걸쳐 모델 무결성을 해칩니다.

- **Unauthorized Training Data**: 저작권이 있거나 민감하거나 허가되지 않은 데이터셋을 도입하면 모델이 사용해서는 안 되는 데이터로부터 학습하게 되어 법적, 윤리적, 성능상의 책임이 발생합니다.

- **Model Source Tampering**: 공급망 또는 내부자에 의한 모델 코드, 의존성, weights의 조작은 훈련 전 또는 중에 숨겨진 로직을 삽입하여 재학습 후에도 지속될 수 있습니다.

- **Excessive Data Handling**: 약한 데이터 보존 및 거버넌스 통제는 시스템이 필요 이상으로 개인 데이터를 저장하거나 처리하게 해 노출 및 규정 준수 위험을 높입니다.

- **Model Exfiltration**: 공격자가 모델 파일/weights를 탈취하면 지적 재산 손실이 발생하고 모방 서비스나 후속 공격을 가능하게 합니다.

- **Model Deployment Tampering**: 공격자가 모델 아티팩트나 서빙 인프라를 수정하면 실행 중인 모델이 검증된 버전과 달라져 동작이 변경될 수 있습니다.

- **Denial of ML Service**: API를 폭주시키거나 “sponge” 입력을 보내면 연산/에너지가 소모되어 모델이 오프라인이 되는 전형적인 DoS 공격과 유사한 상태를 초래할 수 있습니다.

- **Model Reverse Engineering**: 대량의 입력-출력 쌍을 수집해 공격자가 모델을 복제하거나 distill하여 모방 제품과 맞춤형 적대적 공격을 촉진할 수 있습니다.

- **Insecure Integrated Component**: 취약한 플러그인, 에이전트 또는 업스트림 서비스는 공격자가 AI 파이프라인 내에 코드 주입 또는 권한 상승을 허용할 수 있습니다.

- **Prompt Injection**: 시스템 의도를 덮어쓰는 지침을 밀반입하기 위해(직접 또는 간접적으로) 프롬프트를 조작하여 모델이 의도하지 않은 명령을 수행하게 만듭니다.

- **Model Evasion**: 신중하게 설계된 입력은 모델을 오분류하게 하거나 hallucinate하게 만들거나 허용되지 않은 콘텐츠를 출력하게 하여 안전성과 신뢰를 침식합니다.

- **Sensitive Data Disclosure**: 모델이 학습 데이터나 사용자 컨텍스트에서 개인적이거나 기밀인 정보를 노출하여 프라이버시 및 규정 위반을 초래합니다.

- **Inferred Sensitive Data**: 모델이 제공되지 않은 개인 속성을 추론하여 새로운 프라이버시 피해를 생성합니다.

- **Insecure Model Output**: 정제되지 않은 응답이 사용자나 하류 시스템에 유해한 코드, 허위정보 또는 부적절한 콘텐츠를 전달합니다.

- **Rogue Actions**: 자율 통합된 에이전트가 적절한 사용자 감독 없이 의도치 않은 실제 작업(파일 쓰기, API 호출, 구매 등)을 실행합니다.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 위험을 이해하고 완화하기 위한 포괄적인 프레임워크를 제공합니다. 이 매트릭스는 공격자가 AI 모델에 대해 사용할 수 있는 다양한 공격 기법과 전술, 그리고 AI 시스템을 사용해 다양한 공격을 수행하는 방법을 분류합니다.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 활성 세션 토큰이나 클라우드 API 자격증명을 훔쳐 권한 없이 유료 클라우드 호스팅 LLM을 호출합니다. 접근은 종종 피해자의 계정을 프론트하는 reverse proxy를 통해 재판매됩니다(예: "oai-reverse-proxy" 배포). 결과로는 금전적 손실, 정책 외 모델 오남용, 그리고 피해자 테넌트에 대한 귀속(attribution) 문제가 발생할 수 있습니다.

TTPs:
- 감염된 개발자 머신이나 브라우저에서 토큰을 수집; CI/CD 비밀을 훔치거나, 판매된 쿠키를 구매합니다.
- 실제 제공자로의 요청을 전달하여 업스트림 키를 숨기고 다수의 고객을 다중화하는 reverse proxy를 세팅합니다.
- 기업용 가드레일과 속도 제한을 우회하기 위해 직접 base-model endpoint를 남용합니다.

Mitigations:
- 토큰을 디바이스 지문, IP 범위, 클라이언트 attestation에 바인딩; 짧은 만료 시간을 적용하고 MFA로 갱신합니다.
- 키 권한은 최소화(도구 접근 금지, 가능한 경우 읽기 전용); 이상 징후 시 로테이션합니다.
- 정책 게이트웨이 뒤에서 서버 측에서 모든 트래픽을 종료하여 경로별 쿼터, 안전 필터, 테넌트 격리를 시행합니다.
- 이상 사용 패턴(갑작스런 지출 급증, 비정상 지역, UA 문자열 등)을 모니터링하고 의심 세션을 자동으로 취소합니다.
- 장기 고정 API 키 대신 mTLS 또는 IdP가 발급한 서명된 JWT를 선호합니다.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
