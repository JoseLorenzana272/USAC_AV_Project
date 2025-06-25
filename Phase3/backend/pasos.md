# Pasos para usar el archivo intermedio y el main

## Crear el entorno virtual

### Se utiliza el siguiente comando

python3 -m venv env

### Activa el entorno virtual

source env/bin/activate

---

## Pasos para usar

Se debe de instalar las siguientes librerias para poder usar el `archivo intermedio.c`

- sudo apt update
- sudo apt install libcurl4-openssl-dev libjson-c-dev build-essential

Para usar intermedio.c

- gcc -o usac_av_client client.c -lcurl -ljson-c

- sudo ./intermedio -m

En python se usan los siguiente comandos dentro del entorno virtaul ya creado

- pip install flask flask-cors flask-socketio eventlet
- python3 main.py
