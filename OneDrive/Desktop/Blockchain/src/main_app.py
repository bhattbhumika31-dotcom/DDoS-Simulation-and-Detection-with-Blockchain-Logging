import threading
import time
import json
import os
from flask import Flask, render_template, jsonify
from src.networking_module import ServerHandler, TrafficSimulator
from src.detection_module import DetectionModule
from src.blockchain_logger import BlockchainLogger
from src.evaluation_module import EvaluationModule

HOST = '127.0.0.1'
PORT = 8080
LOG_FILE = 'logs/blockchain_log.json'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_FOLDER = os.path.join(BASE_DIR, 'templates')

app = Flask(__name__, template_folder=TEMPLATES_FOLDER)

app_context = {
    'logger': BlockchainLogger(LOG_FILE),
    'detector': DetectionModule(),
    'evaluator': EvaluationModule(LOG_FILE),
    'server_thread': None,
    'sim_thread': None,
    'server_running': False,
    'simulation_running': False,
    'attack_mode': False,
    'server_address': f"{HOST}:{PORT}"
}

if not os.path.exists('logs'):
    os.makedirs('logs')
if not os.path.exists(LOG_FILE):
    app_context['logger'].initialize_log()

def start_server_handler():
    global app_context
    logger = app_context['logger']
    detector = app_context['detector']
    
    server_handler = ServerHandler(HOST, PORT, logger, detector)
    
    app_context['server_thread'] = threading.Thread(target=server_handler.start, daemon=True)
    app_context['server_thread'].start()
    app_context['server_running'] = True
    print(f"Backend ServerHandler started on {HOST}:{PORT}")


def start_traffic_simulator(attack=False):
    global app_context
    app_context['attack_mode'] = attack
    
    simulator = TrafficSimulator(HOST, PORT, attack)
    
    app_context['sim_thread'] = threading.Thread(target=simulator.start, daemon=True)
    app_context['sim_thread'].start()
    app_context['simulation_running'] = True
    print(f"Traffic simulation started (Attack Mode: {attack})")


def stop_simulation_threads():
    global app_context
    if app_context['sim_thread'] and app_context['sim_thread'].is_alive():
        TrafficSimulator.stop_flag.set()
        app_context['sim_thread'].join(timeout=1)
    app_context['simulation_running'] = False
    print("Simulation threads stopped.")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    global app_context
    
    server_alive = app_context['server_thread'] and app_context['server_thread'].is_alive()
    
    sim_alive = app_context['sim_thread'] and app_context['sim_thread'].is_alive()

    is_valid, validation_msg = app_context['logger'].validate_chain()
    
    return jsonify({
        'server_status': 'Running' if server_alive else 'Stopped',
        'simulation_status': 'Running' if sim_alive else 'Stopped',
        'attack_mode': app_context['attack_mode'],
        'server_address': app_context['server_address'],
        'log_length': app_context['logger'].get_chain_length(),
        'log_chain_valid': is_valid,
        'log_validation_message': validation_msg
    })


@app.route('/api/logs', methods=['GET'])
def get_logs():
    global app_context
    try:
        logs = app_context['logger'].get_recent_logs(25)
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/start/<mode>', methods=['POST'])
def start_simulation(mode):
    global app_context
    
    if app_context['simulation_running']:
        return jsonify({'message': 'Simulation already running. Stop it first.'}), 400

    if mode == 'attack':
        start_traffic_simulator(attack=True)
        return jsonify({'message': 'DDoS Attack Simulation Started.'}), 200
    elif mode == 'normal':
        start_traffic_simulator(attack=False)
        return jsonify({'message': 'Normal Traffic Simulation Started.'}), 200
    else:
        return jsonify({'message': 'Invalid mode specified.'}), 400


@app.route('/api/simulation/stop', methods=['POST'])
def stop_simulation():
    global app_context
    if not app_context['simulation_running']:
        return jsonify({'message': 'Simulation is already stopped.'}), 200
    
    stop_simulation_threads()
    return jsonify({'message': 'Simulation Stopped Successfully.'}), 200


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    global app_context
    try:
        metrics = app_context['evaluator'].calculate_metrics()
        return jsonify(metrics), 200
    except Exception as e:
        print(f"Error calculating metrics: {e}")
        return jsonify({'error': 'Could not calculate metrics. Check if log file exists and is valid.'}), 500


if __name__ == '__main__':
    start_server_handler()
    
    print(f"\n🌐 Starting Flask Dashboard on http://{HOST}:5000/")
    app.run(host=HOST, port=5000)
