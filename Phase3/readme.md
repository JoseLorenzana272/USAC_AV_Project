# 🛡️ USAC-AV: Sistema Antivirus con Syscalls Personalizadas

## Teamates

| Full name | carné |
|---|---|
| José Lorenzana | 202206560 |
| Roberto García | 202201724 |
| Javier Avila | 202200392 |
| Diego Gomez | 201908327 |

## Archivo Intermedio y backend

### 📦 Estructura General

``` bash
fases3/
├── intermedio.c       # Cliente en C que usa syscalls
├── intermedio         # Ejecutable compilado
├── main.py            # Backend Flask
└── usac_antivirus.db  # Base de datos SQLite (generada automáticamente)
```

---

### ⚙️ Parte 1: Cliente en C (`intermedio`)

#### 🧱 ¿Qué hace?

- Llama a syscalls personalizadas del kernel Linux para recolectar estadísticas del sistema y procesos activos.
- Construye un objeto JSON con los datos recolectados.
- Envía ese JSON al backend Flask vía HTTP (`POST /api/stats`).
- Opcionalmente escanea archivos y maneja una cuarentena.

#### 🔧 Syscalls utilizadas

| Syscall               | Nº   | Propósito                          |
|----------------------|------|------------------------------------|
| `sys_scan_processes` | 551  | Listar procesos activos            |
| `sys_get_page_faults`| 552  | Obtener fallos de página por PID   |
| `sys_scan_file`      | 553  | Escanear archivo                   |
| `sys_quarantine_file`| 554  | Mover archivo a cuarentena         |
| `sys_get_quarantine_list`| 555 | Ver archivos en cuarentena      |
| `sys_restore_file`   | 556  | Restaurar archivo desde cuarentena |
| `sys_antivirus_stats`| 557  | Obtener estadísticas del sistema   |

#### 🚀 Ejecución

```bash
gcc -o intermedio intermedio.c -lcurl -ljson-c
sudo ./intermedio -m               # Monitoreo 
```

---

### 🌐 Parte 2: Backend Flask (`main.py`)

#### 🧱 Lo que realiza

- Recibe estadísticas desde el cliente C.
- Las guarda en una base de datos SQLite (`usac_antivirus.db`).
- Analiza los datos en busca de anomalías.
- Genera alertas si detecta condiciones críticas (alto uso de memoria, muchos fallos de página, etc).
- Expone endpoints para visualización y consumo de datos.

#### 📁 Base de datos

Contiene 4 tablas:

- `system_stats` → Estadísticas globales.
- `processes` → Procesos más relevantes.
- `alerts` → Alertas generadas.
- `quarantine` → Archivos sospechosos.

#### 🔌 Endpoints disponibles

| Método | URL                   | Función                          |
|--------|------------------------|----------------------------------|
| POST   | `/api/stats`          | Recibe datos del cliente         |
| GET    | `/api/stats`          | Últimos datos registrados        |
| GET    | `/api/stats/history`  | Historial de estadísticas        |
| GET    | `/api/alerts`         | Ver alertas                      |
| GET    | `/api/quarantine`     | Ver archivos en cuarentena       |
| WS     | `/` (WebSocket)       | Enviar datos en tiempo real      |

#### 🚀 Ejecucion

```bash
pip install flask flask-cors flask-socketio eventlet
python3 main.py
```

---

### 📈 Flujo General de Datos

1. `intermedio` ejecuta syscalls y genera un JSON con estadísticas reales del sistema.
2. Envía ese JSON al backend (`POST /api/stats`).
3. El backend lo guarda, analiza, genera alertas y transmite vía WebSocket.
4. Opcionalmente, los datos pueden ser visualizados por un dashboard web o cliente.

![alt text](./images/graphviz.svg)

---
