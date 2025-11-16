from flask import Flask, jsonify
import time
import random
import threading
import json
import hashlib

try:
    from .detection_module import DetectionModule, MAX_REQUESTS_PER_WINDOW, TIME_WINDOW_SECONDS
    from .blockchain_logger import BlockchainLogger
    from .evaluation_module import EvaluationModule
except ImportError:
    print("WARNING: Could not import one or more modules using relative paths (e.g., from .detection_module import...).")
    print("If you are running main_app.py directly, Python may not support 'from .module' syntax.")
    print("Please ensure your modules are named correctly and in the same directory, or use absolute imports.")
    try:
        from detection_module import DetectionModule, MAX_REQUESTS_PER_WINDOW, TIME_WINDOW_SECONDS
        from blockchain_logger import BlockchainLogger
        from evaluation_module import EvaluationModule
    except ImportError:
        print("\nFATAL ERROR: Required external modules (detection, logger, evaluation) were not found.")
        print("Please check your file names and folder structure.")
        pass

HOST = '0.0.0.0'
PORT = 5000

detector = DetectionModule()
logger = BlockchainLogger()
evaluator = EvaluationModule()

simulation_running = False
simulation_mode = 'normal'
simulation_thread = None

app = Flask(__name__)

@app.route('/api/simulation/<action>', methods=['POST'])
@app.route('/api/simulation/<action>/<mode>', methods=['POST'])
def control_simulation(action, mode=None):
    global simulation_running, simulation_mode, simulation_thread

    print(f"\n[Flask] Received control command: {action} with mode: {mode}")

    if action == 'start':
        if simulation_running:
            return jsonify({"status": "error", "message": "Simulation is already running."}), 400
        
        if mode not in ['normal', 'attack']:
            return jsonify({"status": "error", "message": "Invalid simulation mode. Use 'normal' or 'attack'."}), 400

        simulation_mode = mode
        simulation_running = True
        
        simulation_thread = threading.Thread(target=_run_simulation_loop)
        simulation_thread.daemon = True
        simulation_thread.start()
        
        return jsonify({"status": "ok", "message": f"Simulation started in {mode.upper()} mode."})
    
    elif action == 'stop':
        if not simulation_running:
            return jsonify({"status": "error", "message": "Simulation is already stopped."}), 400
        
        simulation_running = False
        return jsonify({"status": "ok", "message": "Simulation stop requested. Stopping traffic loop..."})

    return jsonify({"status": "error", "message": "Invalid action."}), 400

@app.route('/api/status')
def get_status():
    global simulation_running, simulation_mode
    is_valid, validation_msg = logger.is_chain_valid() 
    
    return jsonify({
        "server_status": "Running",
        "server_address": f"http://{HOST}:{PORT}",
        "simulation_status": "Running" if simulation_running else "Stopped",
        "attack_mode": simulation_mode == 'attack',
        "log_length": logger.get_chain_length(),
        "log_chain_valid": is_valid,
        "log_validation_message": validation_msg
    })

@app.route('/api/logs')
def get_logs():
    return jsonify({"logs": logger.get_recent_logs(25)}) 

@app.route('/api/metrics')
def get_metrics():
    logs = logger.get_full_chain()
    metrics = evaluator.calculate_metrics(logs)
    
    last_10_logs = logs[-10:] if len(logs) >= 10 else logs
    
    total_rps, attack_rps, normal_rps = 0, 0, 0
    if len(last_10_logs) > 1:
        time_span = last_10_logs[-1]['timestamp'] - last_10_logs[0]['timestamp']
        
        if time_span > 0:
            total_rps = len(last_10_logs) / time_span
            
            ATTACK_SIM_IP = "192.168.1.100" 
            attack_count = sum(1 for log in last_10_logs if log['ip_address'] == ATTACK_SIM_IP)
            normal_count = len(last_10_logs) - attack_count
            
            attack_rps = attack_count / time_span
            normal_rps = normal_count / time_span

    metrics['total_rps'] = round(total_rps, 2)
    metrics['attack_rps'] = round(attack_rps, 2)
    metrics['normal_rps'] = round(normal_rps, 2)
    
    return jsonify(metrics)

def _run_simulation_loop():
    global simulation_running, simulation_mode
    
    def get_normal_ip(i):
        return f"10.0.0.{1 + (i % 4)}"
        
    attack_ip = "192.168.1.100"
    i = 0
    
    detector.ip_request_history = {} 

    print(f"\n[SIM] Simulation loop started in {simulation_mode.upper()} mode...")
    
    while simulation_running:
        ip = get_normal_ip(i)
        is_actual_attack = False
        sleep_time = 0.5
        
        if simulation_mode == 'attack':
            if random.random() < 0.8:
                ip = attack_ip
                is_actual_attack = True
                sleep_time = 0.05
            else:
                sleep_time = 0.2

        detection_status = detector.check_traffic(ip)
        
        is_flagged = detection_status == "detected"
        
        logger.create_block(ip, detection_status, is_flagged, is_actual_attack)
        
        i += 1
        time.sleep(sleep_time)

    print(f"\n[SIM] Simulation loop stopped.")
    simulation_mode = 'normal'

@app.route('/')
def index():
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Shield: Detection & Blockchain Logging Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Space+Mono:wght@400;700&display=swap');
        
        body {{ 
            font-family: 'Inter', sans-serif; 
            background-color: #0c1523;
            color: #E0E7FF;
        }}
        .console-bg {{ 
            background-color: #1A374D;
            border: 1px solid #3C5B6F;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.5), 0 0 15px rgba(255, 215, 0, 0.2);
        }}
        .log-container {{ 
            font-family: 'Space Mono', monospace; 
            font-size: 0.8rem; 
            height: 400px; 
            overflow-y: scroll; 
            scrollbar-color: #FFD700 #1A374D; 
        }}
        .log-container::-webkit-scrollbar {{ width: 8px; }}
        .log-container::-webkit-scrollbar-thumb {{ background-color: #FFD700; border-radius: 4px; }}
        .log-container::-webkit-scrollbar-track {{ background-color: #1A374D; }}

        .status-dot {{ height: 10px; width: 10px; border-radius: 50%; display: inline-block; box-shadow: 0 0 5px currentColor; }}
        .running {{ background-color: #38A169; color: #38A169; }}
        .stopped {{ background-color: #E53E3E; color: #E53E3E; }}
        .unknown {{ background-color: #FFD700; color: #FFD700; }}
        .valid {{ background-color: #38A169; color: #38A169; }}
        .invalid {{ background-color: #E53E3E; color: #E53E3E; }}

        #log-entries tr:nth-child(even) {{ background-color: rgba(255, 255, 255, 0.05); }}
        #log-entries tr:hover {{ background-color: rgba(255, 215, 0, 0.2) !important; }}
        
        .glow-title {{ 
            text-shadow: 0 0 15px rgba(255, 215, 0, 0.7), 0 0 30px rgba(255, 215, 0, 0.4);
        }}

    </style>
</head>
<body class="p-4 md:p-8">

<div class="max-w-7xl mx-auto">
    <header class="text-center mb-10">
        <h1 class="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-yellow-300 to-yellow-500 glow-title">
            DDoS Shield: Detection & Blockchain Logging
        </h1>
        <p class="text-gray-400 mt-2 text-sm">Team Lead: Bhumika Bhatt | Logging: Manasi Sharma | Detection: Mansi Kabdal | Simulation: Saachi Aggarwal</p>
    </header>

    <section class="console-bg p-6 rounded-xl shadow-2xl mb-10">
        <h2 class="text-2xl font-bold mb-4 text-yellow-300 border-b border-gray-600 pb-2 flex items-center">
            <span class="mr-3">🎮</span> Simulation Control
        </h2>
        <div class="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0 md:space-x-4">
            
            <div class="flex space-x-3 w-full md:w-auto">
                <button id="start-normal-btn" onclick="controlSimulation('start', 'normal')"
                        class="flex-1 px-6 py-3 bg-blue-700 hover:bg-blue-600 text-white font-bold rounded-lg transition duration-200 shadow-lg hover:shadow-blue-500/50 disabled:opacity-30 disabled:shadow-none">
                    Start Normal Traffic
                </button>
                <button id="start-attack-btn" onclick="controlSimulation('start', 'attack')"
                        class="flex-1 px-6 py-3 bg-red-600 hover:bg-red-500 text-white font-bold rounded-lg transition duration-200 shadow-lg hover:shadow-red-500/50 disabled:opacity-30 disabled:shadow-none">
                    Start DDoS Attack
                </button>
            </div>
            
            <button id="stop-btn" onclick="controlSimulation('stop')"
                    class="w-full md:w-auto px-6 py-3 bg-gray-600 hover:bg-gray-500 text-white font-bold rounded-lg transition duration-200 shadow-lg disabled:opacity-30 disabled:shadow-none">
                Stop Simulation
            </button>
        </div>
        <p id="message-box" class="mt-4 text-center font-bold"></p>
    </section>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-10">
        
        <section class="console-bg p-6 rounded-xl shadow-xl">
            <h2 class="text-xl font-bold mb-4 text-yellow-300 flex items-center border-b border-gray-600 pb-2"><span class="mr-2">📡</span> System Status</h2>
            <ul class="space-y-4">
                <li class="flex justify-between items-center text-sm">
                    <span>Backend Server:</span>
                    <span id="server-status" class="font-bold">
                        <span class="status-dot unknown"></span> Unknown
                    </span>
                </li>
                <li class="flex justify-between items-center text-sm">
                    <span>Traffic Simulation:</span>
                    <span id="simulation-status" class="font-bold">
                        <span class="status-dot unknown"></span> Unknown
                    </span>
                </li>
                <li class="flex justify-between items-center text-sm">
                    <span>Attack Mode:</span>
                    <span id="attack-mode" class="font-bold text-gray-300">N/A</span>
                </li>
                <li class="flex justify-between items-center text-sm">
                    <span>Server Address:</span>
                    <span id="server-address" class="font-bold text-gray-400 text-xs font-mono">N/A</span>
                </li>
            </ul>
        </section>
        
        <section class="console-bg p-6 rounded-xl shadow-xl">
            <h2 class="text-xl font-bold mb-4 text-yellow-300 flex items-center border-b border-gray-600 pb-2"><span class="mr-2">🔒</span> Log Integrity (Manasi Sharma)</h2>
            <ul class="space-y-4">
                <li class="flex justify-between items-center text-sm">
                    <span>Log Chain Length:</span>
                    <span id="log-length" class="font-bold text-yellow-300 text-lg">0</span>
                </li>
                <li class="flex justify-between items-center text-sm">
                    <span>Chain Status:</span>
                    <span id="log-chain-valid" class="font-bold">
                        <span class="status-dot unknown"></span> Pending
                    </span>
                </li>
                <li class="col-span-2 mt-4 pt-2 border-t border-gray-700">
                    <span class="text-xs text-gray-400 block mb-1">Validation Message:</span>
                    <p id="validation-msg" class="text-sm break-words text-gray-400 font-mono"></p>
                </li>
            </ul>
        </section>

        <section class="console-bg p-6 rounded-xl shadow-xl">
            <h2 class="text-xl font-bold mb-4 text-yellow-300 flex items-center border-b border-gray-600 pb-2"><span class="mr-2">📊</span> Detection Metrics (Mansi Kabdal)</h2>
            
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-3">
                    <div class="flex justify-between items-center text-sm">
                        <span>Total Requests:</span>
                        <span id="metric-total" class="font-bold text-gray-300">N/A</span>
                    </div>
                    <div class="flex justify-between items-center text-sm">
                        <span>True Positive (TP):</span>
                        <span id="metric-tp" class="font-bold text-green-400 text-lg">N/A</span>
                    </div>
                    <div class="flex justify-between items-center text-sm">
                        <span>False Positive (FP):</span>
                        <span id="metric-fp" class="font-bold text-red-500 text-lg">N/A</span>
                    </div>
                    <div class="flex justify-between items-center text-sm pt-2 border-t border-gray-700">
                        <span>Accuracy:</span>
                        <span id="metric-accuracy" class="font-bold text-yellow-400 text-xl">N/A</span>
                    </div>
                </div>
                
                <div class="flex items-center justify-center">
                    <canvas id="detectionChart"></canvas>
                </div>
            </div>
        </section>
    </div>

    <section class="console-bg p-6 rounded-xl shadow-2xl mb-10">
        <h2 class="text-2xl font-bold mb-4 text-yellow-300 border-b border-gray-600 pb-2 flex items-center">
            <span class="mr-3">📈</span> Real-Time Traffic Rate (Requests/Second)
        </h2>
        <div class="h-64">
            <canvas id="trafficChart"></canvas>
        </div>
    </section>

    <section class="console-bg p-6 rounded-xl shadow-2xl">
        <h2 class="text-2xl font-bold mb-4 text-yellow-300 border-b border-gray-600 pb-2 flex items-center">
            <span class="mr-3">📜</span> Real-Time Traffic Log
        </h2>
        <div id="log-console" class="log-container p-3 rounded-lg bg-black/50 border border-gray-700">
            <table class="w-full text-left table-fixed">
                <thead>
                    <tr class="bg-[#1A374D] sticky top-0 text-xs">
                        <th class="w-1/6 p-2 text-yellow-400">TIME</th>
                        <th class="w-1/6 p-2 text-yellow-400">IP ADDRESS</th>
                        <th class="w-1/6 p-2 text-yellow-400">CLASSIFICATION</th>
                        <th class="w-1/2 p-2 text-yellow-400">BLOCK HASH (INTEGRITY)</th>
                    </tr>
                </thead>
                <tbody id="log-entries">
                </tbody>
            </table>
        </div>
    </section>
</div>

<script>
    const API_STATUS = '/api/status';
    const API_LOGS = '/api/logs';
    const API_METRICS = '/api/metrics';
    const API_CONTROL = '/api/simulation';

    let trafficChart;
    let detectionChart;
    let rpsHistory = {{
        labels: [],
        normal: [],
        attack: [],
    }};
    const MAX_HISTORY = 20;

    const fetchData = async (url) => {{
        try {{
            const response = await fetch(url);
            if (!response.ok) {{
                console.error(`Fetch error on ${{url}}: HTTP status ${{response.status}}`);
                throw new Error(`HTTP error! status: ${{response.status}}`);
            }}
            return await response.json();
        }} catch (error) {{
            console.error(`Error fetching ${{url}}:`, error);
            if (url === API_STATUS) {{
                document.getElementById('message-box').textContent = `Connection error: Could not reach Flask server.`;
                document.getElementById('message-box').className = 'mt-4 text-center font-bold text-red-400';
            }}
            return null;
        }}
    }};
    
    const initializeCharts = () => {{
        const chartOptions = {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
                legend: {{ labels: {{ color: '#E0E7FF' }} }}, 
                tooltip: {{ mode: 'index', intersect: false }}
            }},
            scales: {{
                x: {{ ticks: {{ color: '#9BB8CD' }}, grid: {{ color: '#3C5B6F' }} }}, 
                y: {{ ticks: {{ color: '#9BB8CD' }}, grid: {{ color: '#3C5B6F' }} }}
            }}
        }};

        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        trafficChart = new Chart(trafficCtx, {{
            type: 'line',
            data: {{
                labels: rpsHistory.labels,
                datasets: [
                    {{
                        label: 'Normal RPS',
                        data: rpsHistory.normal,
                        borderColor: '#81E6D9', 
                        backgroundColor: 'rgba(129, 230, 217, 0.15)',
                        tension: 0.4
                    }},
                    {{
                        label: 'Attack RPS',
                        data: rpsHistory.attack,
                        borderColor: '#E53E3E', 
                        backgroundColor: 'rgba(229, 62, 62, 0.15)',
                        tension: 0.4
                    }}
                ]
            }},
            options: {{ ...chartOptions, scales: {{ ...chartOptions.scales, y: {{ ...chartOptions.scales.y, beginAtZero: true }} }} }}
        }});

        const detectionCtx = document.getElementById('detectionChart').getContext('2d');
        detectionChart = new Chart(detectionCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['True Positives (TP)', 'False Positives (FP)', 'True Negatives (TN)', 'False Negatives (FN)'],
                datasets: [{{
                    data: [0, 0, 0, 0], 
                    backgroundColor: ['#38A169', '#E53E3E', '#81E6D9', '#FFD700'], 
                    hoverOffset: 4
                }}]
            }},
            options: {{ 
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {{ 
                    legend: {{ display: false }}, 
                    tooltip: {{ callbacks: {{ label: (context) => {{
                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                        const value = context.parsed;
                        const percentage = total > 0 ? ((value / total) * 100).toFixed(1) + '%' : '0%';
                        return `${{context.label}}: ${{value}} (${{percentage}})`;
                    }}}}}}
                }}
            }}
        }});
    }};


    const updateStatus = (data) => {{
        if (!data) return;

        const serverStatusEl = document.getElementById('server-status');
        serverStatusEl.innerHTML = `<span class="status-dot ${{data.server_status === 'Running' ? 'running' : 'stopped'}}"></span> ${{data.server_status}}`;
        document.getElementById('server-address').textContent = data.server_address || 'http://127.0.0.1:5000';

        const simStatusEl = document.getElementById('simulation-status');
        const simRunning = data.simulation_status === 'Running';
        simStatusEl.innerHTML = `<span class="status-dot ${{simRunning ? 'running' : 'stopped'}}"></span> ${{data.simulation_status}}`;
        
        document.getElementById('start-normal-btn').disabled = simRunning;
        document.getElementById('start-attack-btn').disabled = simRunning;
        document.getElementById('stop-btn').disabled = !simRunning;
        
        document.getElementById('attack-mode').textContent = data.attack_mode ? 'ATTACK MODE ACTIVE' : 'NORMAL TRAFFIC';
        document.getElementById('attack-mode').className = `font-bold text-sm ${{data.attack_mode ? 'text-red-500' : 'text-green-400'}}`;

        const logValidEl = document.getElementById('log-chain-valid');
        const validationMsgEl = document.getElementById('validation-msg');
        const logLengthEl = document.getElementById('log-length');

        logLengthEl.textContent = data.log_length;

        if (data.log_chain_valid) {{
            logValidEl.innerHTML = `<span class="status-dot valid"></span> VALID & SEALED`;
            logValidEl.className = 'font-bold text-green-400';
        }} else {{
            logValidEl.innerHTML = `<span class="status-dot invalid"></span> **TAMPERED!**`;
            logValidEl.className = 'font-bold text-red-500 animate-pulse'; 
        }}
        validationMsgEl.textContent = data.log_validation_message || 'Chain is healthy. All logs verified.';
    }};
    
    const updateMetrics = (data) => {{
        if (!data) return;

        const tp = data.true_positives || 0;
        const fp = data.false_positives || 0;
        const tn = data.true_negatives || 0; 
        const fn = data.false_negatives || 0; 
        const total = data.total_requests || 0;
        const accuracy = total > 0 ? (tp + tn) / total : 0;

        document.getElementById('metric-tp').textContent = tp;
        document.getElementById('metric-fp').textContent = fp;
        document.getElementById('metric-total').textContent = total;

        const accuracyText = (accuracy * 100).toFixed(2) + '%';
        document.getElementById('metric-accuracy').textContent = accuracyText;

        if (detectionChart) {{
            detectionChart.data.datasets[0].data = [tp, fp, tn, fn];
            detectionChart.update();
        }}

        if (trafficChart) {{
            const now = new Date().toLocaleTimeString('en-US', {{hour:'2-digit', minute:'2-digit', second:'2-digit'}});
            const currentNormalRPS = data.normal_rps || 0; 
            const currentAttackRPS = data.attack_rps || 0;

            rpsHistory.labels.push(now);
            rpsHistory.normal.push(currentNormalRPS);
            rpsHistory.attack.push(currentAttackRPS);

            if (rpsHistory.labels.length > MAX_HISTORY) {{
                rpsHistory.labels.shift();
                rpsHistory.normal.shift();
                rpsHistory.attack.shift();
            }}

            trafficChart.data.labels = rpsHistory.labels;
            trafficChart.data.datasets[0].data = rpsHistory.normal;
            trafficChart.data.datasets[1].data = rpsHistory.attack;
            trafficChart.update();
        }}
    }};

    const updateLogs = (data) => {{
        if (!data || !data.logs) return;

        const logTable = document.getElementById('log-entries');
        logTable.innerHTML = ''; 
        
        const logs = data.logs.slice().reverse(); 
        
        logs.forEach(log => {{
            const row = logTable.insertRow();
            
            const date = new Date(log.timestamp * 1000);
            const timeString = date.toLocaleTimeString('en-US', {{hour: '2-digit', minute:'2-digit', second:'2-digit', hour12: false}});
            
            let statusClass = '';
            let statusText = log.detection_status;

            if (log.is_actual_attack && log.detection_status !== 'detected') {{
                    statusClass = 'text-yellow-500'; // Potential False Negative/Unflagged Attack
                    statusText = 'ATTACK (UNFLAGGED)';
            }} else if (log.detection_status === 'detected') {{
                   statusClass = 'text-red-500 font-extrabold';
                   statusText = '🚨 ATTACK DETECTED';
            }} else {{
                   statusClass = 'text-green-400';
                   statusText = 'NORMAL';
            }}

            row.insertCell().textContent = timeString;
            row.insertCell().textContent = log.ip_address || '0.0.0.0'; 
            row.insertCell().innerHTML = `<span class="${{statusClass}} font-bold text-xs uppercase">${{statusText}}</span>`;
            row.insertCell().textContent = log.hash ? log.hash.substring(0, 16) + '...' : 'GENESIS/N/A';

            row.className = 'transition duration-100 border-b border-gray-800';
            row.cells[0].className = 'p-2 text-gray-500 font-mono';
            row.cells[1].className = 'p-2 text-gray-300 font-mono';
            row.cells[2].className = 'p-2';
            row.cells[3].className = 'p-2 text-xs text-gray-400 truncate font-mono';
        }});
    }};

    const refreshDashboard = async () => {{
        await Promise.all([
            fetchData(API_STATUS).then(updateStatus),
            fetchData(API_LOGS).then(updateLogs),
            fetchData(API_METRICS).then(updateMetrics) 
        ]);
    }};

    const controlSimulation = async (action, mode = null) => {{
        const endpoint = `${{API_CONTROL}}/${{action}}${{mode ? '/' + mode : ''}}`;
        
        document.getElementById('message-box').textContent = `[CMD] Attempting to send '${{action}} ${{mode || ''}}' request...`;
        document.getElementById('message-box').className = 'mt-4 text-center font-bold text-yellow-400';

        try {{
            const response = await fetch(endpoint, {{ method: 'POST' }});
            const result = await response.json();
            
            document.getElementById('message-box').textContent = `[RESPONSE] ${{result.message}}`;
            document.getElementById('message-box').className = 'mt-4 text-center font-bold ' + (response.ok ? 'text-green-400' : 'text-red-500');
        }} catch (error) {{
            console.error('Error controlling simulation:', error);
            document.getElementById('message-box').textContent = `[ERROR] Failed to send control command: ${{error.message}}`;
            document.getElementById('message-box').className = 'mt-4 text-center font-bold text-red-500';
        }}
    }};
    
    // Initialize charts and start the refresh interval
    window.onload = () => {{
        initializeCharts();
        refreshDashboard();
        setInterval(refreshDashboard, 1000); // Refresh every 1 second
    }};

</script>
</body>
</html>
"""

if __name__ == '__main__':
    # Flask runner requires host and port configuration
    # Note: Flask's built-in reloader can cause the simulation thread to run twice. 
    # For a stable simulation, run with use_reloader=False
    print(f"\n--- Starting Flask Server on http://{HOST}:{PORT} ---")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
