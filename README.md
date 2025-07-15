# Escáner Externo de Cámaras IP (`scannerwpip.py`)

Este script permite detectar cámaras IP potencialmente vulnerables expuestas a Internet, utilizando peticiones HTTP/HTTPS a rutas específicas conocidas y analizando respuestas en busca de evidencias típicas de dispositivos de videovigilancia mal configurados.

## Características principales

- Escaneo de miles de IPs y puertos aleatorios de países específicos (simulación).
- Detección basada en encabezados, cuerpos de respuesta y patrones sensibles.
- Verificación en múltiples rutas comunes usadas por cámaras IP.
- Análisis de respuestas en formato JSON y HTML.
- Resultados exportados en formato `.json`.
- Compatible con Python 3.8 o superior.

## Instalación

Requiere Python 3.8+ y los siguientes paquetes:

```bash
pip install requests urllib3

Uso
Ejecutar desde terminal:

python scannerwpip.py -c US -n 1000 -T 40 --timeout 3 --delay 0.2 --verbose


Parámetros disponibles
Opción	Descripción
-c	Código del país para generar IPs (ej: CN, US, EU).
-n	Número de objetivos a escanear (por defecto: 1000).
-T	Número de hilos para escaneo concurrente (por defecto: 50).
--timeout	Tiempo máximo por solicitud en segundos (por defecto: 3).
--delay	Retardo aleatorio entre solicitudes para evadir detección (s).
--verbose	Activa salida detallada en consola.

Ejemplo simple

python scannerwpip.py -c CN -n 500 --verbose


Metodología
Se generan IPs aleatorias en rangos públicos comunes por país.

Se escanean múltiples puertos usados por cámaras IP y NVRs.

Se realizan solicitudes GET a rutas específicas, detectando:

Encabezados como Server o WWW-Authenticate que revelen marcas.

Respuestas JSON con campos como DeviceType, Brand, Model.

Indicadores en texto plano como “ip camera”, “login”, etc.

Estructura del resultado
Al detectar una posible cámara IP, se almacena la información en un archivo .json con la siguiente estructura:

{
  "timestamp": "2025-07-15T14:22:01.123456",
  "target": "45.10.23.88:8080",
  "url": "http://45.10.23.88:8080/login.rsp",
  "status": 200,
  "findings": [
    "Servidor de cámara: Hikvision-Webs",
    "Patrón de cámara vulnerable detectado"
  ]
}



Advertencia de uso
Esta herramienta es exclusivamente para fines educativos, auditorías de seguridad con consentimiento o entornos de laboratorio. El uso no autorizado en redes ajenas podría considerarse ilegal.

El autor no se hace responsable por el uso indebido de este script. Utilícelo bajo su propia responsabilidad y siempre con autorización previa.



# Escáner Automático de Vulnerabilidades en Cámaras IP (`scanner.py`)

Este script permite escanear automáticamente la red local en busca de dispositivos IoT o cámaras IP mal configuradas, vulnerables o que expongan información sensible a través de rutas y servicios conocidos. Funciona sin intervención manual previa, adaptándose a la red activa detectada.

## Características destacadas

- Detección automática de la red local y rangos IP activos
- Verificación de puertos y rutas sensibles en dispositivos IoT
- Análisis de contenido JSON o texto para identificar datos expuestos
- Identificación de credenciales, configuraciones o parámetros sensibles
- Exportación automática de resultados en formatos JSON y CSV

## Requisitos

- Python 3.8 o superior (recomendable python 12)
- Paquetes necesarios:

```bash
pip install requests psutil netifaces urllib3

Uso
Ejecutar desde terminal:

python scanner.py -m network --threads 30 --timeout 4

Parámetros disponibles
Opción	Descripción
-m, --mode	Modo de escaneo (network, patterns, random)
-T, --threads	Número de hilos de escaneo concurrentes (por defecto: 20)
--timeout	Tiempo máximo de espera por solicitud, en segundos (por defecto: 3)
--show-interfaces	Muestra la interfaz activa y su dirección IP detectada

Modos disponibles
network: escaneo activo de la red local (ARP, ping y escaneo de puertos)

patterns: generación de IPs según patrones comunes (192.168.x.y, 10.0.x.y)

random: generación aleatoria de targets en redes privadas

Metodología del escaneo
Detecta la IP y red local automáticamente (conexión real o puerta de enlace).

Genera listas de IPs con puertos comunes de cámaras IP y dispositivos IoT.

En cada IP: realiza múltiples solicitudes HTTP/HTTPS a rutas vulnerables conocidas.

Detecta campos como user, admin, password, login en respuestas JSON o HTML.

Clasifica el objetivo como potencialmente vulnerable si se encuentra información sensible.

Resultados generados
Al finalizar, se generan dos archivos en la misma carpeta:

auto_scan_YYYYMMDD_HHMMSS.json: resultados detallados con contenido y rutas específicas

auto_scan_YYYYMMDD_HHMMSS.csv: resumen para revisión rápida o carga en hojas de cálculo

Ejemplo de resultado (JSON)


{
  "timestamp": "2025-07-15T13:55:40.123Z",
  "target": "192.168.1.105:8080",
  "url": "http://192.168.1.105:8080/device.rsp?opt=user&cmd=list",
  "protocol": "http",
  "path": "/device.rsp?opt=user&cmd=list",
  "status_code": 200,
  "findings": [
    "Campo 'user': admin...",
    "Patrón: \"password\":\"123456\"..."
  ],
  "data": {
    "user": "admin",
    "password": "123456",
    "model": "IPCamX"
  }
}


Rutas y patrones incluidos
El script incluye más de 15 rutas comunes que exponen información en cámaras y DVRs, y patrones como:

Campos user, admin, password, login, pwd

Archivos .rsp, .cgi, .json, .jpg

Firmas de cámaras tipo HiSilicon, ONVIF, Foscam, Axis, etc.

Advertencia de uso
Este programa ha sido diseñado únicamente para:

Fines académicos

Laboratorios personales

Auditorías autorizadas

Cualquier uso en redes ajenas sin consentimiento puede constituir una violación legal. El autor no se responsabiliza por usos no autorizados. Úsese siempre de forma ética y legal.
