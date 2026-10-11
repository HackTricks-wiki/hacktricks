# Contenedores y espacios de nombres

{{#include ../../banners/hacktricks-training.md}}

Un contenedor es un proceso de Linux que se ejecuta con una configuración de aislamiento y privilegios. Evalúa en conjunto el entorno de ejecución, los recursos del host montados, las capabilities concedidas y la configuración de los espacios de nombres. El [resumen de seguridad de contenedores](container-security/README.md) explica estas capas y enlaza a cada control.

- [Escalada de privilegios en Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) se centra en el acceso a la interfaz de administración de containerd.
- [Escalada de privilegios en RunC](runc-privilege-escalation.md) abarca material de escalada específico del entorno de ejecución.
- [Seguridad de contenedores](container-security/README.md) explica los entornos de ejecución, las API expuestas, los riesgos de las imágenes, los montajes sensibles, los contenedores privilegiados, la evaluación y las protecciones, como los espacios de nombres, seccomp y el control de acceso obligatorio.
{{#include ../../banners/hacktricks-training.md}}
