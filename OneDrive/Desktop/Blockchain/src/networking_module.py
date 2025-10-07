# Saachi Aggarwal - Networking and Traffic Simulation Module

import socket
import threading
import time
import random

# --- Configuration (Must match main_app.py) ---
HOST = '127.0.0.1'
PORT = 8080
TRAFFIC_INTERVAL_NORMAL = 1.0  # Seconds between normal requests
TRAFFIC_INTERVAL_ATTACK = 0.05 # Seconds between attack requests

# --- Server Handler (The 'Victim' Service) ---

class ServerHandler:
    """
    Implements a simple TCP server that listens for traffic requests, logs them,
    and passes them to the Detection Module.
    
    This acts as the 'victim' application in the simulation.
    """
    def __init__(self, host, port, logger, detector):
        self.host = host
        self.port = port
        self.logger = logger
        self.detector = detector
        self.running = threading.Event() # Used to signal the server loop to stop
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(0.5) # Non-blocking timeout for graceful shutdown
        print(f"ServerHandler: Initializing TCP server at {self.host}:{self.port}")
        
    def handle_request(self, conn, addr):
        """Processes a single connection and logs the event."""
        ip = addr[0]
        
        try:
            # Receive data (simulates processing the request body)
            conn.recv(1024) 
            
            # --- Integration with Detection Module (Mansi Kabdal) ---
            # Check the IP against the current threshold rules
            detection_status = self.detector.check_traffic(ip)
            
            # Simulated response to client
            response = f"HTTP/1.1 200 OK\n\nStatus: {detection_status}"
            conn.sendall(response.encode('utf-8'))

            # --- Integration with Blockchain Logger (Manasi Sharma) ---
            # Use the IP range to determine if this request was part of the simulated attack 
            # (Ground Truth for the Evaluation Module)
            is_attack = ip.startswith('192.0.2.') 
            
            self.logger.create_block(
                ip=ip, 
                detection_status=detection_status,
                is_attack=is_attack 
            )

        except Exception as e:
            # Log unexpected errors but ignore common socket/timeout errors during high load
            # print(f"Server Handler Error processing request from {ip}: {e}")
            pass 
        finally:
            conn.close()

    def start(self):
        """Binds the socket and starts listening for incoming connections."""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5) # Max 5 queued connections
            self.running.set()
            print(f"Server Handler: Listening for traffic...")

            while self.running.is_set():
                try:
                    # Attempt to accept a connection with a timeout
                    conn, addr = self.sock.accept()
                    # Use a new thread to handle the request instantly
                    thread = threading.Thread(target=self.handle_request, args=(conn, addr), daemon=True)
                    thread.start()
                except socket.timeout:
                    # Timeout is necessary to check the self.running flag periodically
                    continue
                except Exception as e:
                    if self.running.is_set():
                         print(f"Server Handler: Listener error: {e}")
                    break

        except Exception as e:
            print(f"Server Handler: Failed to bind or start: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stops the server gracefully."""
        if self.running.is_set():
            self.running.clear()
            self.sock.close()
            print("Server Handler: Stopped listening.")

# --- Traffic Simulator (The 'Client' Activity) ---

class TrafficSimulator:
    """
    Generates simulated network traffic (normal or DDoS attack) toward the server.
    """
    # Global flag to signal all simulator threads to stop
    stop_flag = threading.Event()

    def __init__(self, host, port, is_attack_mode=False):
        self.host = host
        self.port = port
        self.is_attack_mode = is_attack_mode
        # Use common internal IPs for normal traffic
        self.normal_ips = [f"192.168.1.{i}" for i in range(10, 20)] 
        # Use a distinct, reserved IP range for simulated attack traffic (192.0.2.0/24 is TEST-NET-3)
        self.attack_ips = [f"192.0.2.{i}" for i in range(100, 110)]
        self.num_attackers = 10 if is_attack_mode else 0

    def send_request(self, ip_address):
        """Simulates a client sending a request to the server."""
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Bind the client socket to the spoofed/simulated source IP
            client_socket.bind((ip_address, 0)) 
            client_socket.settimeout(1)
            client_socket.connect((self.host, self.port))
            
            # Send a basic request payload (simulating an HTTP GET)
            payload = "GET / HTTP/1.1\r\nHost: server\r\n\r\n"
            client_socket.sendall(payload.encode('utf-8'))
            
            # Read response from the server (handled by ServerHandler)
            client_socket.recv(1024) 
            
        except ConnectionRefusedError:
            # Server is likely stopped
            pass
        except socket.timeout:
            # Request took too long
            pass
        except Exception:
            # Catch all other socket errors gracefully
            pass
        finally:
            if client_socket:
                client_socket.close()

    def normal_traffic_loop(self):
        """Generates random normal traffic."""
        while not self.stop_flag.is_set():
            # Pick a random normal IP
            ip = random.choice(self.normal_ips)
            self.send_request(ip)
            time.sleep(TRAFFIC_INTERVAL_NORMAL) # Wait for the slow interval

    def attack_traffic_loop(self, attacker_ip):
        """Generates high-frequency attack traffic from a specific IP."""
        while not self.stop_flag.is_set():
            self.send_request(attacker_ip)
            time.sleep(TRAFFIC_INTERVAL_ATTACK) # Short wait for burst

    def start(self):
        """Starts the normal and, optionally, the attack threads."""
        TrafficSimulator.stop_flag.clear()
        
        # Start normal traffic thread
        norm_thread = threading.Thread(target=self.normal_traffic_loop, daemon=True)
        norm_thread.start()
        
        print("Simulator: Normal traffic generation started.")
        
        # Start attack threads if in attack mode
        if self.is_attack_mode:
            for ip in self.attack_ips:
                attack_thread = threading.Thread(target=self.attack_traffic_loop, args=(ip,), daemon=True)
                attack_thread.start()
                
            print(f"Simulator: DDoS attack simulation started from {len(self.attack_ips)} IP(s).")

    @classmethod
    def stop_all(cls):
        """Sets the global flag to stop all simulator threads."""
        cls.stop_flag.set()
        print("Simulator: Stopping all traffic threads...")
