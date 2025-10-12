import socket
import threading
import time
import random

HOST = '127.0.0.1'
PORT = 8080
TRAFFIC_INTERVAL_NORMAL = 1.0
TRAFFIC_INTERVAL_ATTACK = 0.05

class ServerHandler:
    def __init__(self, host, port, logger, detector):
        self.host = host
        self.port = port
        self.logger = logger
        self.detector = detector
        self.running = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(0.5)
        print(f"ServerHandler: Initializing TCP server at {self.host}:{self.port}")
        
    def handle_request(self, conn, addr):
        ip = addr[0]
        
        try:
            conn.recv(1024)
            
            detection_status = self.detector.check_traffic(ip)
            
            response = f"HTTP/1.1 200 OK\n\nStatus: {detection_status}"
            conn.sendall(response.encode('utf-8'))

            is_attack = ip.startswith('192.0.2.')
            
            self.logger.create_block(
                ip=ip,
                detection_status=detection_status,
                is_attack=is_attack
            )

        except Exception as e:
            pass
        finally:
            conn.close()

    def start(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running.set()
            print(f"Server Handler: Listening for traffic...")

            while self.running.is_set():
                try:
                    conn, addr = self.sock.accept()
                    thread = threading.Thread(target=self.handle_request, args=(conn, addr), daemon=True)
                    thread.start()
                except socket.timeout:
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
        if self.running.is_set():
            self.running.clear()
            self.sock.close()
            print("Server Handler: Stopped listening.")

class TrafficSimulator:
    stop_flag = threading.Event()

    def __init__(self, host, port, is_attack_mode=False):
        self.host = host
        self.port = port
        self.is_attack_mode = is_attack_mode
        self.normal_ips = [f"192.168.1.{i}" for i in range(10, 20)]
        self.attack_ips = [f"192.0.2.{i}" for i in range(100, 110)]
        self.num_attackers = 10 if is_attack_mode else 0

    def send_request(self, ip_address):
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.bind((ip_address, 0))
            client_socket.settimeout(1)
            client_socket.connect((self.host, self.port))
            
            payload = "GET / HTTP/1.1\r\nHost: server\r\n\r\n"
            client_socket.sendall(payload.encode('utf-8'))
            
            client_socket.recv(1024)
            
        except ConnectionRefusedError:
            pass
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            if client_socket:
                client_socket.close()

    def normal_traffic_loop(self):
        while not self.stop_flag.is_set():
            ip = random.choice(self.normal_ips)
            self.send_request(ip)
            time.sleep(TRAFFIC_INTERVAL_NORMAL)

    def attack_traffic_loop(self, attacker_ip):
        while not self.stop_flag.is_set():
            self.send_request(attacker_ip)
            time.sleep(TRAFFIC_INTERVAL_ATTACK)

    def start(self):
        TrafficSimulator.stop_flag.clear()
        
        norm_thread = threading.Thread(target=self.normal_traffic_loop, daemon=True)
        norm_thread.start()
        
        print("Simulator: Normal traffic generation started.")
        
        if self.is_attack_mode:
            for ip in self.attack_ips:
                attack_thread = threading.Thread(target=self.attack_traffic_loop, args=(ip,), daemon=True)
                attack_thread.start()
                
            print(f"Simulator: DDoS attack simulation started from {len(self.attack_ips)} IP(s).")

    @classmethod
    def stop_all(cls):
        cls.stop_flag.set()
        print("Simulator: Stopping all traffic threads...")
