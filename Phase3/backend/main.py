#!/usr/bin/env python3
"""
USAC Antivirus Backend API
Backend servidor para recibir datos del cliente C y servir al dashboard web
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
import logging
import os
from collections import deque
import signal
import sys

# Configuración
app = Flask(__name__)
app.config['SECRET_KEY'] = 'usac-av-secret-key-2025'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('usac_av.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Variables globales para almacenar datos en memoria
latest_stats = {}
stats_history = deque(maxlen=100)  # Últimas 100 lecturas
connected_clients = set()
db_lock = threading.Lock()

# Base de datos
DB_FILE = 'usac_antivirus.db'

def init_database():
    """Inicializar base de datos SQLite"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Tabla para estadísticas del sistema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    memoria_usada INTEGER,
                    memoria_libre INTEGER,
                    memoria_cache INTEGER,
                    swap_usada INTEGER,
                    fallos_menores INTEGER,
                    fallos_mayores INTEGER,
                    paginas_activas INTEGER,
                    paginas_inactivas INTEGER
                )
            ''')
            
            # Tabla para procesos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stats_id INTEGER,
                    nombre TEXT,
                    pid INTEGER,
                    memoria_pct REAL,
                    memoria_rss INTEGER,
                    estado INTEGER,
                    fallos_menores INTEGER,
                    fallos_mayores INTEGER,
                    FOREIGN KEY (stats_id) REFERENCES system_stats (id)
                )
            ''')
            
            # Tabla para alertas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    resolved BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Tabla para archivos en cuarentena
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    original_path TEXT,
                    quarantine_date INTEGER NOT NULL,
                    file_hash TEXT,
                    threat_level INTEGER,
                    restored BOOLEAN DEFAULT FALSE
                )
            ''')
            
            conn.commit()
            logger.info("Base de datos inicializada correctamente")
            
    except Exception as e:
        logger.error(f"Error al inicializar base de datos: {e}")

def save_stats_to_db(stats_data):
    """Guardar estadísticas en base de datos"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Insertar estadísticas del sistema
            cursor.execute('''
                INSERT INTO system_stats 
                (timestamp, memoria_usada, memoria_libre, memoria_cache, swap_usada,
                 fallos_menores, fallos_mayores, paginas_activas, paginas_inactivas)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                stats_data.get('timestamp', int(time.time())),
                stats_data.get('memoria_usada', 0),
                stats_data.get('memoria_libre', 0),
                stats_data.get('memoria_cache', 0),
                stats_data.get('swap_usada', 0),
                stats_data.get('fallos_menores', 0),
                stats_data.get('fallos_mayores', 0),
                stats_data.get('paginas_activas', 0),
                stats_data.get('paginas_inactivas', 0)
            ))
            
            stats_id = cursor.lastrowid
            
            # Insertar procesos
            if 'procesos_top' in stats_data:
                for proc in stats_data['procesos_top']:
                    cursor.execute('''
                        INSERT INTO processes 
                        (stats_id, nombre, pid, memoria_pct, memoria_rss, estado,
                         fallos_menores, fallos_mayores)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        stats_id,
                        proc.get('nombre', ''),
                        proc.get('pid', 0),
                        proc.get('memoria_pct', 0.0),
                        proc.get('memoria_rss', 0),
                        proc.get('estado', 0),
                        proc.get('fallos_menores', 0),
                        proc.get('fallos_mayores', 0)
                    ))
            
            conn.commit()
            
    except Exception as e:
        logger.error(f"Error al guardar estadísticas en BD: {e}")

def analyze_anomalies(stats_data):
    """Analizar datos para detectar anomalías"""
    alerts = []
    
    try:
        # Verificar uso excesivo de memoria
        total_mem = stats_data.get('memoria_usada', 0) + stats_data.get('memoria_libre', 0)
        if total_mem > 0:
            mem_usage_pct = (stats_data.get('memoria_usada', 0) / total_mem) * 100
            if mem_usage_pct > 90:
                alerts.append({
                    'type': 'memory',
                    'severity': 'critical',
                    'message': f'Uso crítico de memoria: {mem_usage_pct:.1f}%',
                    'details': json.dumps(stats_data)
                })
            elif mem_usage_pct > 80:
                alerts.append({
                    'type': 'memory',
                    'severity': 'warning',
                    'message': f'Alto uso de memoria: {mem_usage_pct:.1f}%',
                    'details': json.dumps(stats_data)
                })
        
        # Verificar uso excesivo de swap
        swap_used = stats_data.get('swap_usada', 0)
        if swap_used > 1024 * 1024:  # > 1GB
            alerts.append({
                'type': 'swap',
                'severity': 'warning',
                'message': f'Alto uso de swap: {swap_used // (1024*1024)} GB',
                'details': json.dumps({'swap_usada': swap_used})
            })
        
        # Verificar procesos con alto uso de memoria
        if 'procesos_top' in stats_data:
            for proc in stats_data['procesos_top'][:5]:  # Top 5
                if proc.get('memoria_pct', 0) > 20:
                    alerts.append({
                        'type': 'process',
                        'severity': 'warning',
                        'message': f'Proceso {proc.get("nombre")} usando {proc.get("memoria_pct", 0):.1f}% de memoria',
                        'details': json.dumps(proc)
                    })
        
        # Verificar fallos de página excesivos
        major_faults = stats_data.get('fallos_mayores', 0)
        if major_faults > 10000:
            alerts.append({
                'type': 'page_faults',
                'severity': 'warning',
                'message': f'Alto número de fallos de página mayores: {major_faults}',
                'details': json.dumps({'fallos_mayores': major_faults})
            })
        
        # Guardar alertas en base de datos
        if alerts:
            save_alerts_to_db(alerts)
            
    except Exception as e:
        logger.error(f"Error al analizar anomalías: {e}")
    
    return alerts

def save_alerts_to_db(alerts):
    """Guardar alertas en base de datos"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            timestamp = int(time.time())
            
            for alert in alerts:
                cursor.execute('''
                    INSERT INTO alerts (timestamp, type, severity, message, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    alert['type'],
                    alert['severity'],
                    alert['message'],
                    alert['details']
                ))
            
            conn.commit()
            
    except Exception as e:
        logger.error(f"Error al guardar alertas: {e}")

@app.route('/')
def index():
    """Página principal con información básica de la API"""
    return jsonify({
        'name': 'USAC Antivirus Backend API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'POST /api/stats': 'Recibir estadísticas del cliente',
            'GET /api/stats': 'Obtener últimas estadísticas',
            'GET /api/stats/history': 'Obtener histórico de estadísticas',
            'GET /api/alerts': 'Obtener alertas activas',
            'GET /api/quarantine': 'Obtener archivos en cuarentena',
            'WebSocket /': 'Actualizaciones en tiempo real'
        }
    })

@app.route('/api/stats', methods=['POST'])
def receive_stats():
    """Recibir estadísticas del cliente C"""
    try:
        stats_data = request.get_json()
        if not stats_data:
            return jsonify({'error': 'No data received'}), 400
        
        # Agregar timestamp si no existe
        if 'timestamp' not in stats_data:
            stats_data['timestamp'] = int(time.time())
        
        # Actualizar datos globales
        global latest_stats
        with db_lock:
            latest_stats = stats_data.copy()
            stats_history.append(stats_data.copy())
        
        # Analizar anomalías
        alerts = analyze_anomalies(stats_data)
        
        # Guardar en base de datos
        save_stats_to_db(stats_data)
        
        # Enviar a clientes WebSocket
        socketio.emit('stats_update', {
            'stats': stats_data,
            'alerts': alerts
        })
        
        logger.info(f"Estadísticas recibidas: Memoria {stats_data.get('memoria_usada', 0)} KB")
        
        return jsonify({
            'status': 'success',
            'message': 'Stats received successfully',
            'alerts_generated': len(alerts)
        })
        
    except Exception as e:
        logger.error(f"Error al recibir estadísticas: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_latest_stats():
    """Obtener últimas estadísticas"""
    with db_lock:
        return jsonify(latest_stats)

@app.route('/api/stats/history', methods=['GET'])
def get_stats_history():
    """Obtener histórico de estadísticas"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM system_stats 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [desc[0] for desc in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
        return jsonify({
            'history': results,
            'count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error al recibir estadísticas: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_database()
    socketio.run(app, host='0.0.0.0', port=5000)
