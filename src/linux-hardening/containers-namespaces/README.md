# Containers e Namespaces

{{#include ../../banners/hacktricks-training.md}}

Um container é um processo Linux executado com uma configuração de isolamento e privilégios. Avalie em conjunto o runtime, os recursos do host montados, as capabilities concedidas e as configurações de namespace. A [visão geral da segurança de containers](container-security/README.md) explica essas camadas e contém links para cada controle.

- [Escalonamento de privilégios do Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) aborda o acesso à interface de gerenciamento do containerd.
- [Escalonamento de privilégios do RunC](runc-privilege-escalation.md) aborda técnicas de escalonamento específicas do runtime.
- [Segurança de containers](container-security/README.md) explica runtimes, APIs expostas, riscos de imagens, montagens sensíveis, containers privilegiados, avaliação e proteções como namespaces, seccomp e controle de acesso obrigatório.
{{#include ../../banners/hacktricks-training.md}}
