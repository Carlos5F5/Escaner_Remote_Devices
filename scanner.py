import requests
import json
import re
import csv
import argparse
import ipaddress
import socket
import subprocess
import random
import psutil
import netifaces
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Generator
import urllib3

# Desabilitar warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AutoTargetScanner:
    def __init__(self, threads: int = 20, timeout: int = 3):
        self.threads = threads
        self.timeout = timeout
        
        # Puertos comunes para dispositivos IoT/cámaras
        self.TARGET_PORTS = [80, 81, 8000, 8080, 554, 8888, 9999, 8081, 8090, 8888, 9000]
        
        # Rutas de vulnerabilidades
        self.CANDIDATE_PATHS = [
            '/device.rsp?opt=user&cmd=list',
            '/login.rsp',
            '/system.rsp',
            '/cgi-bin/user.cgi?action=get',
            '/cgi-bin/admin.cgi?action=get',
            '/config.json',
            '/api/users',
            '/api/system/info',
            '/web/cgi-bin/hi3510/param.cgi?cmd=getuser',
            '/tmpfs/auto.jpg',
            '/cgi-bin/nobody/Machine.cgi?action=get_capability',
            '/onvif/device_service',
            '/axis-cgi/admin/param.cgi?action=list&group=Brand',
            '/cgi-bin/magicBox.cgi?action=getSystemInfo'
        ]
        
        # Patrones de detección
        self.SENSITIVE_PATTERNS = [
            re.compile(r'"user(?:name)?"\s*:\s*"[^"]+', re.IGNORECASE),
            re.compile(r'"admin"\s*:\s*"[^"]+', re.IGNORECASE),
            re.compile(r'"pass(?:word)?"\s*:\s*"[^"]+', re.IGNORECASE),
            re.compile(r'"pwd"\s*:\s*"[^"]+', re.IGNORECASE),
            re.compile(r'"login"\s*:\s*"[^"]+', re.IGNORECASE),
        ]
        
        self.SENSITIVE_FIELDS = ['user', 'username', 'admin', 'password', 'pass', 'pwd', 'login']
        
        # Interfaces a ignorar (virtuales, VPN, etc.)
        self.IGNORED_INTERFACES = [
            'vmware', 'virtualbox', 'vethernet', 'loopback', 'teredo', 'isatap',
            'bluetooth', 'vmnet', 'vnic', 'docker', 'hyperv', 'wsl', 'memu'
        ]
        
        self.results = []
        self.live_hosts = []
    
    def get_active_network_interface(self) -> Optional[Tuple[str, str]]:
        """Detecta la interfaz de red activa principal"""
        try:
            # Método 1: Usando netifaces para obtener la ruta por defecto
            try:
                import netifaces
                
                # Obtener gateway por defecto
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    default_gateway = gateways['default'][netifaces.AF_INET]
                    interface = default_gateway[1]
                    
                    # Obtener IP de la interfaz
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        print(f"[*] Interfaz principal detectada: {interface} -> {ip}")
                        return ip, interface
            except ImportError:
                pass
            
            # Método 2: Usando psutil
            try:
                import psutil
                
                # Obtener estadísticas de red
                net_stats = psutil.net_if_stats()
                net_addrs = psutil.net_if_addrs()
                
                # Buscar interfaz activa con gateway
                for interface, stats in net_stats.items():
                    if (stats.isup and 
                        not any(ignored in interface.lower() for ignored in self.IGNORED_INTERFACES)):
                        
                        if interface in net_addrs:
                            for addr in net_addrs[interface]:
                                if addr.family == socket.AF_INET:
                                    ip = addr.address
                                    
                                    # Verificar si tiene gateway (conexión a Internet)
                                    if self.has_internet_connection(ip):
                                        print(f"[*] Interfaz principal detectada: {interface} -> {ip}")
                                        return ip, interface
            except ImportError:
                pass
            
            # Método 3: Conexión de prueba para detectar IP saliente
            try:
                # Conectar a un servidor externo para ver qué IP local usa
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    # Conectar a DNS de Google
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    
                    # Verificar que no sea una IP virtual
                    if not any(ignored in self.get_interface_name(local_ip).lower() 
                              for ignored in self.IGNORED_INTERFACES):
                        print(f"[*] IP principal detectada por conexión: {local_ip}")
                        return local_ip, "unknown"
                        
            except Exception as e:
                print(f"[!] Error en detección por conexión: {e}")
            
            # Método 4: Fallback usando ipconfig/ifconfig
            return self.get_ip_from_system_command()
            
        except Exception as e:
            print(f"[!] Error detectando interfaz activa: {e}")
            return None
    
    def get_interface_name(self, ip: str) -> str:
        """Obtiene el nombre de la interfaz para una IP dada"""
        try:
            import psutil
            net_addrs = psutil.net_if_addrs()
            
            for interface, addrs in net_addrs.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == ip:
                        return interface
        except:
            pass
        return "unknown"
    
    def has_internet_connection(self, local_ip: str) -> bool:
        """Verifica si una IP local tiene conexión a Internet"""
        try:
            # Intentar conexión HTTP simple
            response = requests.get("http://httpbin.org/ip", timeout=3)
            return response.status_code == 200
        except:
            try:
                # Intentar ping a gateway común
                ip_parts = local_ip.split('.')
                if len(ip_parts) == 4:
                    gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', gateway],
                        capture_output=True,
                        timeout=2
                    )
                    return result.returncode == 0
            except:
                pass
        return False
    
    def get_ip_from_system_command(self) -> Optional[Tuple[str, str]]:
        """Obtiene IP usando comandos del sistema"""
        try:
            # Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_adapter = ""
                
                for line in lines:
                    line = line.strip()
                    
                    # Detectar adaptador
                    if "Adaptador" in line:
                        current_adapter = line
                        continue
                    
                    # Buscar IP
                    if "Dirección IPv4" in line and ":" in line:
                        ip = line.split(":")[-1].strip()
                        
                        # Verificar que no sea una interfaz virtual
                        if (not any(ignored in current_adapter.lower() 
                                  for ignored in self.IGNORED_INTERFACES) and
                            not ip.startswith("169.254") and  # Link-local
                            ip != "127.0.0.1"):  # Loopback
                            
                            # Verificar si tiene puerta de enlace
                            gateway_found = False
                            for i, next_line in enumerate(lines[lines.index(line):lines.index(line)+5]):
                                if "Puerta de enlace" in next_line and ":" in next_line:
                                    gateway = next_line.split(":")[-1].strip()
                                    if gateway and gateway != "":
                                        gateway_found = True
                                        break
                            
                            if gateway_found:
                                print(f"[*] IP principal detectada: {ip} (Adaptador: {current_adapter})")
                                return ip, current_adapter
            
            # Linux/macOS fallback
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'src' in line:
                        ip = line.split('src')[1].split()[0]
                        print(f"[*] IP principal detectada (Linux): {ip}")
                        return ip, "unknown"
                        
        except Exception as e:
            print(f"[!] Error obteniendo IP del sistema: {e}")
        
        return None
    
    def get_local_network_ranges(self) -> List[str]:
        """Detecta rangos de red locales automáticamente"""
        ranges = []
        
        # Detectar interfaz principal
        network_info = self.get_active_network_interface()
        
        if network_info:
            ip, interface = network_info
            
            # Generar rango de red basado en la IP principal
            try:
                # Asumir máscara /24 para redes domésticas
                ip_obj = ipaddress.IPv4Address(ip)
                
                # Determinar la red según la clase de IP
                if ip.startswith('192.168.'):
                    ip_parts = ip.split('.')
                    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                elif ip.startswith('10.'):
                    ip_parts = ip.split('.')
                    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                elif ip.startswith('172.'):
                    ip_parts = ip.split('.')
                    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                else:
                    # Para otras redes, asumir /24
                    ip_parts = ip.split('.')
                    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
                ranges.append(network)
                print(f"[*] Red principal detectada: {network}")
                
            except Exception as e:
                print(f"[!] Error generando rango de red: {e}")
        
        # Agregar rangos comunes como backup
        common_ranges = [
            '192.168.1.0/24',
            '192.168.0.0/24',
            '192.168.2.0/24',
            '10.0.0.0/24',
            '10.0.1.0/24',
            '172.16.0.0/24'
        ]
        
        # Agregar rangos comunes que no estén ya incluidos
        for common_range in common_ranges:
            if common_range not in ranges:
                ranges.append(common_range)
        
        return ranges[:3]  # Limitar a 3 rangos para eficiencia
    
    def generate_random_targets(self, count: int = 1000) -> List[str]:
        """Genera targets aleatorios en rangos comunes"""
        targets = []
        
        # Usar la red principal si está disponible
        ranges = self.get_local_network_ranges()
        
        for _ in range(count):
            # Seleccionar rango aleatorio
            range_choice = random.choice(ranges)
            network = ipaddress.IPv4Network(range_choice, strict=False)
            
            # Generar IP aleatoria en el rango
            ip = str(network.network_address + random.randint(1, network.num_addresses - 2))
            port = random.choice(self.TARGET_PORTS)
            targets.append(f"{ip}:{port}")
        
        return targets
    
    def scan_network_range(self, cidr: str) -> List[str]:
        """Escanea un rango de red para encontrar hosts activos"""
        print(f"[*] Escaneando rango: {cidr}")
        live_hosts = []
        
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            
            # Limitar el escaneo para evitar demasiados hosts
            max_hosts = min(254, network.num_addresses - 2)
            
            def ping_host(ip):
                try:
                    # Ping simple
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', str(ip)] if hasattr(subprocess, 'run') else
                        ['ping', '-n', '1', '-w', '1000', str(ip)],
                        capture_output=True,
                        timeout=2
                    )
                    if result.returncode == 0:
                        return str(ip)
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for ip in list(network.hosts())[:max_hosts]:
                    futures.append(executor.submit(ping_host, ip))
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                        print(f"[+] Host activo: {result}")
        
        except Exception as e:
            print(f"[!] Error escaneando {cidr}: {e}")
        
        return live_hosts
    
    def port_scan_host(self, ip: str) -> List[str]:
        """Escanea puertos específicos en un host"""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_port, port): port for port in self.TARGET_PORTS}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def discover_targets_network(self) -> List[str]:
        """Descubre targets en la red local"""
        print("[*] Iniciando descubrimiento de targets en red local...")
        targets = []
        
        # Obtener rangos de red basados en la interfaz principal
        ranges = self.get_local_network_ranges()
        
        for cidr in ranges:
            # Escanear hosts activos
            live_hosts = self.scan_network_range(cidr)
            
            for host in live_hosts:
                # Escanear puertos en cada host
                open_ports = self.port_scan_host(host)
                
                for port in open_ports:
                    targets.append(f"{host}:{port}")
                    print(f"[+] Target encontrado: {host}:{port}")
        
        return targets
    
    def generate_targets_from_patterns(self) -> List[str]:
        """Genera targets basados en patrones comunes de dispositivos IoT"""
        targets = []
        
        # Obtener la red principal
        network_info = self.get_active_network_interface()
        
        if network_info:
            ip, _ = network_info
            ip_parts = ip.split('.')
            
            # Generar targets en la misma red
            if len(ip_parts) == 4:
                base_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                
                # Rangos comunes para dispositivos IoT
                ranges = [
                    range(1, 255),      # Todo el rango
                    range(100, 200),    # Rango medio
                    range(200, 255),    # Rango alto
                ]
                
                for host_range in ranges:
                    for host_num in host_range:
                        target_ip = f"{base_network}.{host_num}"
                        for port in self.TARGET_PORTS:
                            targets.append(f"{target_ip}:{port}")
        
        # Agregar patrones comunes como fallback
        common_patterns = [
            ('192.168.1.{}', range(100, 200)),
            ('192.168.0.{}', range(100, 200)),
            ('10.0.0.{}', range(100, 150)),
        ]
        
        for ip_pattern, host_range in common_patterns:
            for host_num in host_range:
                ip = ip_pattern.format(host_num)
                for port in self.TARGET_PORTS:
                    targets.append(f"{ip}:{port}")
        
        return targets
    
    def detect_sensitive_content(self, data: Dict) -> Tuple[bool, List[str]]:
        """Detección de contenido sensible"""
        findings = []
        
        # Verificar campos sensibles
        for field in self.SENSITIVE_FIELDS:
            if field in data:
                value = str(data[field])
                if value and value.lower() not in ['', 'null', 'none', '0']:
                    findings.append(f"Campo '{field}': {value[:50]}...")
        
        # Búsqueda con regex
        data_str = json.dumps(data, ensure_ascii=False)
        for pattern in self.SENSITIVE_PATTERNS:
            matches = pattern.findall(data_str)
            for match in matches:
                if match not in findings:
                    findings.append(f"Patrón: {match[:50]}...")
        
        return len(findings) > 0, findings
    
    def scan_target(self, ip_port: str) -> Optional[Dict]:
        """Escanea un target específico"""
        host, port = ip_port.split(':')
        
        for protocol in ['http', 'https']:
            base_url = f"{protocol}://{host}:{port}"
            
            for path in self.CANDIDATE_PATHS:
                try:
                    url = f"{base_url}{path}"
                    response = requests.get(
                        url,
                        timeout=self.timeout,
                        verify=False,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if isinstance(data, (dict, list)):
                                is_vulnerable, findings = self.detect_sensitive_content(data)
                                
                                if is_vulnerable:
                                    return {
                                        'timestamp': datetime.now().isoformat(),
                                        'target': ip_port,
                                        'url': url,
                                        'protocol': protocol,
                                        'path': path,
                                        'status_code': response.status_code,
                                        'findings': findings,
                                        'data': data
                                    }
                        except json.JSONDecodeError:
                            # Verificar contenido de texto
                            content = response.text
                            if any(kw in content.lower() for kw in ['user', 'admin', 'pass']):
                                return {
                                    'timestamp': datetime.now().isoformat(),
                                    'target': ip_port,
                                    'url': url,
                                    'protocol': protocol,
                                    'path': path,
                                    'status_code': response.status_code,
                                    'findings': ['Contenido sensible detectado'],
                                    'content': content[:500]
                                }
                except requests.RequestException:
                    continue
        
        return None
    
    def save_results(self, prefix: str = 'auto_scan'):
        """Guarda resultados"""
        if not self.results:
            print("[!] No se encontraron vulnerabilidades.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON detallado
        json_file = f"{prefix}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # CSV para análisis
        csv_file = f"{prefix}_{timestamp}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'URL', 'Protocol', 'Findings'])
            
            for result in self.results:
                findings_str = '; '.join(result.get('findings', []))
                writer.writerow([
                    result['target'],
                    result['url'],
                    result['protocol'],
                    findings_str
                ])
        
        print(f"[*] Resultados guardados: {json_file}, {csv_file}")
    
    def run_auto_scan(self, mode: str = 'network'):
        """Ejecuta escáner automático"""
        print(f"[*] Iniciando escáner automático (modo: {mode})")
        
        if mode == 'network':
            targets = self.discover_targets_network()
        elif mode == 'patterns':
            targets = self.generate_targets_from_patterns()
        elif mode == 'random':
            targets = self.generate_random_targets(500)
        else:
            targets = self.discover_targets_network()
        
        if not targets:
            print("[!] No se generaron targets.")
            return
        
        print(f"[*] Escaneando {len(targets)} targets...")
        
        # Escanear targets
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        print(f"[VULNERABLE] {result['target']} --> {result['path']}")
                except Exception as e:
                    pass  # Silenciar errores para no saturar la salida
        
        print(f"\n[*] Escáner completado. Encontradas {len(self.results)} vulnerabilidades.")
        self.save_results()

def main():
    parser = argparse.ArgumentParser(description='Scanner Automático de Vulnerabilidades Mejorado')
    parser.add_argument('-m', '--mode', choices=['network', 'patterns', 'random'], 
                       default='network', help='Modo de generación de targets')
    parser.add_argument('-T', '--threads', type=int, default=20, help='Número de hilos')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout en segundos')
    parser.add_argument('--show-interfaces', action='store_true', 
                       help='Mostrar todas las interfaces de red detectadas')
    
    args = parser.parse_args()
    
    scanner = AutoTargetScanner(threads=args.threads, timeout=args.timeout)
    
    if args.show_interfaces:
        print("[*] Detectando interfaces de red...")
        network_info = scanner.get_active_network_interface()
        if network_info:
            print(f"[*] Interfaz principal: {network_info[1]} -> {network_info[0]}")
        else:
            print("[!] No se pudo detectar la interfaz principal")
        return
    
    scanner.run_auto_scan(mode=args.mode)

if __name__ == "__main__":
    main()