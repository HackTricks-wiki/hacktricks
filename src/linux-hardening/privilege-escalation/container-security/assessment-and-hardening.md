# Evaluación y Endurecimiento

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Una buena evaluación de contenedores debería responder dos preguntas paralelas. Primero, ¿qué puede hacer un atacante desde la carga de trabajo actual? Segundo, ¿qué decisiones del operador hicieron eso posible? Las herramientas de enumeración ayudan con la primera pregunta, y las recomendaciones de endurecimiento ayudan con la segunda. Mantener ambos en una sola página hace que la sección sea más útil como referencia de campo en lugar de solo un catálogo de técnicas de escape.

## Herramientas de enumeración

Un número de herramientas siguen siendo útiles para caracterizar rápidamente un entorno de contenedores:

- `linpeas` puede identificar muchos indicadores de contenedor, sockets montados, conjuntos de capabilities, sistemas de archivos peligrosos y pistas de breakout.
- `CDK` se centra específicamente en entornos de contenedores e incluye enumeración además de algunas comprobaciones automatizadas de escape.
- `amicontained` es ligero y útil para identificar restricciones de contenedor, capabilities, exposición de namespace y clases probables de breakout.
- `deepce` es otro enumerador enfocado en contenedores con comprobaciones orientadas a breakout.
- `grype` es útil cuando la evaluación incluye revisión de vulnerabilidades de paquetes de imagen en lugar de solo análisis de escape en runtime.

El valor de estas herramientas es la rapidez y la cobertura, no la certeza. Ayudan a revelar la postura aproximada rápidamente, pero los hallazgos interesantes aún necesitan interpretación manual frente al actual runtime, namespace, capability y mount model.

## Prioridades de endurecimiento

Los principios de endurecimiento más importantes son conceptualmente simples aunque su implementación varíe según la plataforma. Evita contenedores privilegiados. Evita sockets de runtime montados. No des a los contenedores rutas del host con permisos de escritura a menos que haya una razón muy específica. Usa user namespaces o rootless execution cuando sea factible. Elimina todas las capabilities y vuelve a añadir solo las que el workload realmente necesita. Mantén seccomp, AppArmor y SELinux habilitados en lugar de desactivarlos para resolver problemas de compatibilidad de aplicaciones. Limita los recursos para que un contenedor comprometido no pueda trivialmente negar el servicio al host.

La higiene de imagen y de build importa tanto como la postura en runtime. Usa imágenes mínimas, reconstruye con frecuencia, escanéalas, exige procedencia cuando sea práctico y mantiene los secretos fuera de las capas. Un contenedor que se ejecuta como non-root con una imagen pequeña y una superficie reducida de syscall y capability es mucho más fácil de defender que una imagen grande y de conveniencia que se ejecuta con root equivalente al host y con herramientas de depuración preinstaladas.

## Ejemplos de agotamiento de recursos

Los controles de recursos no son glamorosos, pero forman parte de la seguridad de contenedores porque limitan el radio de impacto de una compromisión. Sin límites de memoria, CPU o PID, un simple shell puede ser suficiente para degradar el host o cargas de trabajo vecinas.

Ejemplos de pruebas que afectan al host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estos ejemplos son útiles porque muestran que no todos los resultados peligrosos de un contenedor son un "escape" limpio. Los límites débiles de cgroup aún pueden convertir la ejecución de código en un impacto operativo real.

## Herramientas de hardening

Para entornos centrados en Docker, `docker-bench-security` sigue siendo una línea base útil de auditoría en el host porque comprueba problemas de configuración comunes frente a directrices de benchmark ampliamente reconocidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
La herramienta no es un sustituto del modelado de amenazas, pero sigue siendo valiosa para encontrar valores predeterminados descuidados de daemon, mount, network y runtime que se acumulan con el tiempo.

## Comprobaciones

Usa estos como comandos rápidos de primera pasada durante la evaluación:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Un proceso root con amplias capacidades y `Seccomp: 0` merece atención inmediata.
- Montajes sospechosos y sockets de runtime a menudo ofrecen un camino más rápido hacia el impacto que cualquier kernel exploit.
- La combinación de una postura de runtime débil y límites de recursos laxos suele indicar un entorno de contenedores generalmente permisivo en lugar de un único error aislado.
{{#include ../../../banners/hacktricks-training.md}}
