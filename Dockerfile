FROM ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image:latest

# Variable de idioma (cambia "master" a "es" si lo quieres en español, etc.)
ARG HT_LANG=master
ENV HT_LANG=${HT_LANG}

# Configuración de git y preparación
RUN mkdir -p ~/.ssh && \
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts && \
    git config --global --add safe.directory /app

# Copiamos el repo clonado en CapRover al contenedor
WORKDIR /app
COPY . /app

# Selecciona idioma y construye la documentación
RUN git checkout ${HT_LANG} && git pull

# Exponemos el puerto que usará mdbook
EXPOSE 3000

# Ejecuta mdbook en modo servidor
CMD ["bash", "-c", "MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0 --port 3000"]
