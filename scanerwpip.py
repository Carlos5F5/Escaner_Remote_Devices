import requests
import json
import re
import csv
import argparse
import ipaddress
import socket
import random
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import urllib3

# Deshabilitar advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ExternalCameraScanner:
    def __init__(self, threads=50, timeout=3, delay=0.1, verbose=False):
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.results = []
        self.scanned_count = 0
        self.found_count = 0
        self.CAMERA_PORTS = [
            80, 81, 554, 8000, 8080, 8081, 8090, 8888, 9000, 9999,
            1024, 1080, 1935, 4321, 5000, 5555, 6667, 7000, 7777,
            8001, 8002, 8008, 8010, 8011, 8060, 8086, 8087, 8089,
            8181, 8888, 9001, 9002, 9080, 9090, 9091, 10000, 10001
        ]

        self.CAMERA_PATHS = [
            '/device.rsp?opt=user&cmd=list', '/system.rsp?opt=user&cmd=list',
            '/login.rsp', '/config.json', '/tmpfs/auto.jpg',
            '/snapshot.jpg', '/image.jpg', '/cgi-bin/guest/Video.cgi?media=JPEG',
            '/PSIA/Custom/SelfExt/userCheck', '/ISAPI/Security/users',
            '/cgi-bin/user.cgi?action=get', '/axis-cgi/basicdeviceinfo.cgi',
            '/cgi/admin/preset.cgi?usr=admin&pwd=admin&cmd=get',
            '/config/getuser?index=0', '/cgi-bin/CGIProxy.fcgi?cmd=getUserList',
            '/cgi-bin/admin/admin.cgi?cmd=getUserList', '/SnapshotJPEG?Resolution=640x480&Quality=Standard',
            '/stw-cgi/system.cgi?msubmenu=systeminfo&action=view',
            '/onvif/device_service', '/web/cgi-bin/hi3510/param.cgi?cmd=getuser'
        ]

        self.CAMERA_PATTERNS = [
            re.compile(r'"user(?:name)?"\s*:\s*"admin"', re.IGNORECASE),
            re.compile(r'"pass(?:word)?"\s*:\s*"(?:admin|123456|password)"', re.IGNORECASE),
            re.compile(r'"DeviceType"\s*:\s*"(?:Camera|IPC|DVR|NVR)"', re.IGNORECASE),
            re.compile(r'"Brand"\s*:\s*"(?:Hikvision|Dahua|Axis|Foscam)"', re.IGNORECASE),
            re.compile(r'"Model"\s*:\s*"[^"]*(?:Camera|IPC|DVR|NVR)', re.IGNORECASE),
            re.compile(r'WWW-Authenticate.*realm="(?:Camera|IPC|DVR|NVR)', re.IGNORECASE),
        ]

        self.USER_AGENTS = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (X11; Linux x86_64)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)'
        ]
    def generate_country_targets(self, country_code: str = "CN", count: int = 1000) -> List[str]:
        country_ranges = {
            "CN": ['27.0.0.0/8', '36.0.0.0/8', '58.0.0.0/8'],
            "US": ['23.0.0.0/8', '24.0.0.0/8', '45.0.0.0/8'],
            "EU": ['77.0.0.0/8', '78.0.0.0/8', '91.0.0.0/8'],
        }
        ranges = country_ranges.get(country_code.upper(), country_ranges["CN"])
        targets = []

        for _ in range(count):
            net = ipaddress.IPv4Network(random.choice(ranges))
            rand_ip = str(net.network_address + random.randint(0, min(net.num_addresses - 1, 65535)))
            port = random.choice(self.CAMERA_PORTS)
            targets.append(f"{rand_ip}:{port}")
        return targets

    def detect_camera_vulnerability(self, response, url: str) -> Tuple[bool, List[str]]:
        findings = []
        headers = response.headers

        if 'Server' in headers and any(k in headers['Server'].lower() for k in ['hikvision', 'camera']):
            findings.append(f"Servidor de cámara: {headers['Server']}")

        if 'WWW-Authenticate' in headers and 'camera' in headers['WWW-Authenticate'].lower():
            findings.append(f"Auth de cámara: {headers['WWW-Authenticate']}")

        try:
            data = response.json()
            for field in ['DeviceType', 'Brand', 'Model', 'Version']:
                if field in data:
                    findings.append(f"{field}: {data[field]}")

            data_str = json.dumps(data)
            for pattern in self.CAMERA_PATTERNS:
                if pattern.search(data_str):
                    findings.append("Patrón de cámara vulnerable detectado")
                    break

        except Exception:
            content = response.text.lower()
            if 'ip camera' in content or 'login' in content:
                findings.append("Login de cámara detectado")

        return len(findings) > 0, findings
    def scan_target(self, ip_port: str) -> Optional[Dict]:
        if self.delay > 0:
            time.sleep(random.uniform(0, self.delay))
        self.scanned_count += 1
        host, port = ip_port.split(':')

        if self.verbose and self.scanned_count % 10 == 0:
            print(f"[VERBOSE] Escaneando {ip_port}...")

        for protocol in ['http', 'https']:
            for path in self.CAMERA_PATHS:
                url = f"{protocol}://{host}:{port}{path}"
                try:
                    headers = {
                        'User-Agent': random.choice(self.USER_AGENTS),
                        'Accept': '*/*',
                        'Connection': 'close'
                    }
                    resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=False)
                    if resp.status_code in [200, 401, 403]:
                        is_cam, findings = self.detect_camera_vulnerability(resp, url)
                        if is_cam:
                            self.found_count += 1
                            if self.verbose:
                                print(f"[DETECTADO] {ip_port} -> {findings[0]}")
                            return {
                                'timestamp': datetime.now().isoformat(),
                                'target': ip_port,
                                'url': url,
                                'status': resp.status_code,
                                'findings': findings
                            }
                except requests.RequestException:
                    continue
        return None
    def save_results(self):
        if not self.results:
            print("[!] No se encontraron cámaras vulnerables.")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"camaras_detectadas_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"[✔] Resultados guardados en: {filename}")
    def run_external_scan(self, country='CN', count=1000):
        print(f"[*] Iniciando escaneo en país: {country} con {count} IPs")
        targets = self.generate_country_targets(country, count)
        print(f"[*] Generados {len(targets)} objetivos")
        print(f"[*] Estimado: {(len(targets) * self.timeout / self.threads / 60):.1f} minutos\n")

        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_target, target): target for target in targets}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception:
                    continue

        print(f"\n[*] Escaneo completado en {(time.time() - start) / 60:.2f} minutos")
        print(f"[*] Encontradas {len(self.results)} cámaras de {self.scanned_count} escaneadas")
        self.save_results()
def main():
    parser = argparse.ArgumentParser(description='Scanner de cámaras IP expuestas')
    parser.add_argument('-c', '--country', default='CN', help='Código de país (ej: CN, US, EU)')
    parser.add_argument('-n', '--count', type=int, default=1000, help='Número de targets')
    parser.add_argument('-T', '--threads', type=int, default=50, help='Número de hilos')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout en segundos')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay entre peticiones')
    parser.add_argument('--verbose', action='store_true', help='Mostrar salida detallada')

    args = parser.parse_args()

    print("=" * 60)
    print("ADVERTENCIA: Uso solo educativo o con autorización expresa.")
    print("=" * 60)
    if input("¿Continuar? (y/N): ").lower() not in ['y', 'yes', 'sí', 'si']:
        print("Cancelado.")
        return

    scanner = ExternalCameraScanner(
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose
    )

    scanner.run_external_scan(country=args.country, count=args.count)

if __name__ == "__main__":
    main()
