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
import subprocess

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

# Variables globales
latest_stats = {}
stats_history = deque(maxlen=100)
connected_clients = set()
db_lock = threading.Lock()

# Base de datos
DB_FILE = 'usac_antivirus.db'

def init_database():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
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
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
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
    alerts = []
    try:
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
        swap_used = stats_data.get('swap_usada', 0)
        if swap_used > 1024 * 1024:
            alerts.append({
                'type': 'swap',
                'severity': 'warning',
                'message': f'Alto uso de swap: {swap_used // (1024*1024)} GB',
                'details': json.dumps({'swap_usada': swap_used})
            })
        if 'procesos_top' in stats_data:
            for proc in stats_data['procesos_top'][:5]:
                if proc.get('memoria_pct', 0) > 20:
                    alerts.append({
                        'type': 'process',
                        'severity': 'warning',
                        'message': f'Proceso {proc.get("nombre")} usando {proc.get("memoria_pct", 0):.1f}% de memoria',
                        'details': json.dumps(proc)
                    })
        major_faults = stats_data.get('fallos_mayores', 0)
        if major_faults > 10000:
            alerts.append({
                'type': 'page_faults',
                'severity': 'warning',
                'message': f'Alto número de fallos de página mayores: {major_faults}',
                'details': json.dumps({'fallos_mayores': major_faults})
            })
        if alerts:
            save_alerts_to_db(alerts)
    except Exception as e:
        logger.error(f"Error al analizar anomalías: {e}")
    return alerts

def save_alerts_to_db(alerts):
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
            'POST /api/quarantine': 'Poner archivo en cuarentena',
            'POST /api/restore': 'Restaurar archivo de cuarentena',
            'WebSocket /': 'Actualizaciones en tiempo real'
        }
    })

@app.route('/api/stats', methods=['POST'])
def receive_stats():
    try:
        stats_data = request.get_json()
        if not stats_data:
            return jsonify({'error': 'No data received'}), 400
        if 'timestamp' not in stats_data:
            stats_data['timestamp'] = int(time.time())
        global latest_stats
        with db_lock:
            latest_stats = stats_data.copy()
            stats_history.append(stats_data.copy())
        alerts = analyze_anomalies(stats_data)
        save_stats_to_db(stats_data)
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
    with db_lock:
        return jsonify(latest_stats)

@app.route('/api/stats/history', methods=['GET'])
def get_stats_history():
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
        logger.error(f"Error al obtener historial: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/quarantine', methods=['GET'])
def get_quarantine_list():
    try:
        result = subprocess.run(['./usac_av_client', '-q'], capture_output=True, text=True)
        output = result.stdout
        error = result.stderr
        if result.returncode != 0:
            logger.error(f"Error al listar cuarentena: {error}")
            return jsonify({'status': 'error', 'message': error}), 500
        files = []
        for line in output.splitlines():
            if line.startswith("[INFO]") or line.startswith("====="):
                continue
            if "No files in quarantine" in line:
                break
            # Extraer número y nombre de archivo (e.g., "1. test.txt")
            parts = line.split(". ", 1)
            if len(parts) == 2:
                filename = parts[1].strip()
                # Intentar obtener original_path del archivo .meta
                try:
                    with open(f"/var/quarantine/{filename}.meta", 'r') as f:
                        original_path = f.read().strip()
                except:
                    original_path = f"/unknown/{filename}"
                files.append({'filename': filename, 'original_path': original_path})
        return jsonify({
            'status': 'success',
            'quarantine_list': files
        })
    except Exception as e:
        logger.error(f"Error al obtener lista de cuarentena: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/quarantine', methods=['POST'])
def quarantine_file():
    try:
        data = request.get_json()
        path = data.get('path')
        if not path:
            return jsonify({'status': 'error', 'message': 'Path is required'}), 400
        result = subprocess.run(['./usac_av_client', '-s', path], capture_output=True, text=True)
        output = result.stdout
        error = result.stderr
        if result.returncode != 0:
            logger.error(f"Error al poner en cuarentena: {error}")
            return jsonify({'status': 'error', 'message': error}), 500
        if "Archivo limpio" in output:
            return jsonify({'status': 'success', 'message': f'File {path} is clean'})
        elif "Archivo MALICIOSO" in output or "Archivo sospechoso" in output:
            filename = os.path.basename(path)
            return jsonify({
                'status': 'success',
                'message': f'File {filename} successfully quarantined to /var/quarantine/{filename}'
            })
        else:
            return jsonify({'status': 'error', 'message': output}), 500
    except Exception as e:
        logger.error(f"Error al poner en cuarentena: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/restore', methods=['POST'])
def restore_file():
    try:
        data = request.get_json()
        filename = data.get('filename')
        if not filename:
            return jsonify({'status': 'error', 'message': 'Filename is required'}), 400
        result = subprocess.run(['./usac_av_client', '-r', filename], capture_output=True, text=True)
        output = result.stdout
        error = result.stderr
        if result.returncode != 0:
            logger.error(f"Error al restaurar: {error}")
            return jsonify({'status': 'error', 'message': error}), 500
        return jsonify({
            'status': 'success',
            'message': f'File {filename} restored successfully'
        })
    except Exception as e:
        logger.error(f"Error al restaurar: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    init_database()
    socketio.run(app, host='0.0.0.0', port=5000)