from flask import Flask, jsonify, request, render_template 
import threading
import time
import signal
import sys
import os

try:
    from src.networking_module import ServerHandler, TrafficSimulator, HOST, PORT
    
    from src.blockchain_logger import BlockchainLogger
    from src.detection_module import DetectionModule
    
except ImportError as e:
    print(f"ERROR: Could not import necessary modules. Ensure 'src/' directory exists and contains all three .py files.")
    print(f"Details: {e}")
    sys.exit(1)


app = Flask(__name__)
ORCHESTRATOR = None 

class DDoSSimulatorOrchestrator:
    def __init__(self):
        self.logger = BlockchainLogger()
        self.detector = DetectionModule()
        
        self.simulation_thread = None
        self.server_thread = None
        self.stop_event = threading.Event()
        self.is_running = False
        self.attack_mode = False
        
        self.server_handler = ServerHandler(HOST, PORT, self.logger, self.detector, self.stop_event)
        
        print("Orchestrator: System initialized.")

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            print("Orchestrator: Server already running.")
            return

        print("Orchestrator: Starting ServerHandler...")
        self.server_thread = threading.Thread(target=self.server_handler.start, daemon=True)
        self.server_thread.start()
        time.sleep(0.5) 

    def start_simulation(self, mode: str):
        if self.is_running:
            return {"status": "error", "message": "Simulation is already running. Stop it first."}

        self.stop_event.clear() 
        self.detector.reset_metrics_for_new_simulation() 
        self.attack_mode = (mode == 'attack')
        
        self.simulator = TrafficSimulator(HOST, PORT, 
                                          is_attack_mode=self.attack_mode, 
                                          stop_event=self.stop_event)

        print(f"Orchestrator: Starting TrafficSimulator in {mode.upper()} mode...")
        
        self.simulation_thread = threading.Thread(target=self.simulator.start, daemon=True)
        self.simulation_thread.start()
        self.is_running = True
        
        return {"status": "success", "message": f"Simulation started in {mode.upper()} mode."}

    def stop_simulation(self):
        if not self.is_running:
            return {"status": "error", "message": "No active simulation to stop."}

        print("Orchestrator: Initiating simulation stop...")
        self.stop_event.set() 

        if self.simulator:
            self.simulator.stop() 
        
        time.sleep(0.1) 
        
        self.is_running = False
        self.attack_mode = False
        print("Orchestrator: Simulation stopped.")
        return {"status": "success", "message": "Simulation stopped. Check dashboard for final log."}


@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    global ORCHESTRATOR
    if not ORCHESTRATOR:
        return jsonify({
            "server_status": "Stopped", "simulation_status": "Stopped", "attack_mode": False,
            "server_address": f"{HOST}:{PORT}", "log_length": 0, "log_chain_valid": False, 
            "log_validation_message": "System not fully initialized."
        }), 200

    chain_valid, validation_msg = ORCHESTRATOR.logger.is_chain_valid()
    
    server_running = ORCHESTRATOR.server_thread.is_alive() if ORCHESTRATOR.server_thread else False
    
    return jsonify({
        "server_status": "Running" if server_running else "Stopped",
        "simulation_status": "Running" if ORCHESTRATOR.is_running else "Stopped",
        "attack_mode": ORCHESTRATOR.attack_mode,
        "server_address": f"{HOST}:{PORT}",
        "log_length": len(ORCHESTRATOR.logger.chain),
        "log_chain_valid": chain_valid,
        "log_validation_message": validation_msg
    }), 200

@app.route('/api/logs', methods=['GET'])
def get_logs():
    global ORCHESTRATOR
    if not ORCHESTRATOR:
        return jsonify({"logs": []}), 200

    return jsonify({"logs": ORCHESTRATOR.logger.get_chain_data()}), 200

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    global ORCHESTRATOR
    if not ORCHESTRATOR:
        return jsonify({}), 200
        
    return jsonify(ORCHESTRATOR.detector.get_metrics()), 200

@app.route('/api/simulation/<action>', methods=['POST'])
@app.route('/api/simulation/<action>/<mode>', methods=['POST'])
def control_simulation(action, mode=None):
    global ORCHESTRATOR
    
    if action == 'start':
        if mode not in ['normal', 'attack']:
            return jsonify({"status": "error", "message": "Invalid mode specified. Use 'normal' or 'attack'."}), 400
        response = ORCHESTRATOR.start_simulation(mode)
        return jsonify(response), 200
    
    elif action == 'stop':
        response = ORCHESTRATOR.stop_simulation()
        return jsonify(response), 200
        
    else:
        return jsonify({"status": "error", "message": "Invalid action. Use 'start' or 'stop'."}), 400


def signal_handler(sig, frame):
    print('\nOrchestrator: Caught shutdown signal. Stopping services...')
    if ORCHESTRATOR:
        ORCHESTRATOR.stop_simulation()
        
    if ORCHESTRATOR and ORCHESTRATOR.server_thread:
        ORCHESTRATOR.stop_event.set()
        ORCHESTRATOR.server_handler.stop() 
        ORCHESTRATOR.server_thread.join(1) 
    sys.exit(0)

def init_orchestrator():
    global ORCHESTRATOR
    if ORCHESTRATOR is None:
        ORCHESTRATOR = DDoSSimulatorOrchestrator()
        ORCHESTRATOR.start_server() 
        
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    init_orchestrator()

    print("\n------------------------------------------------------")
    print("DDoS Shield Simulation Ready.")
    print(f"Traffic Handler running on TCP {HOST}:{PORT}")
    print("Dashboard available via Flask web server.")
    print("------------------------------------------------------")
    print("To access the dashboard, open your browser to the address below.")
    print("Press Ctrl+C to shut down gracefully.")
    print("------------------------------------------------------\n")
    try:
        app.run(host='0.0.0.0', debug=False, use_reloader=False) 
    except KeyboardInterrupt:
        pass
