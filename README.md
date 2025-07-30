# Analisis-de-la-red
Echo por: Matias Martinez, Aralim Muela y David Techera
"""
Escáner de Red y Gestión de Recursos por Aula
"""

import os
import sys
import subprocess
import ipaddress
import socket
import threading
import time
from datetime import datetime
import sqlite3

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
        self.scan_results = {}
        self.db_name = "recursos_aula.db"
        self.init_database()
    
    def init_database(self):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS aulas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre VARCHAR(50) NOT NULL,
                    sector VARCHAR(50),
                    capacidad INTEGER,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''            )
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recursos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre VARCHAR(100) NOT NULL,
                    tipo VARCHAR(50),
                    marca VARCHAR(50),
                    modelo VARCHAR(50),
                    direccion_ip VARCHAR(15),
                    direccion_mac VARCHAR(17),
                    conectividad VARCHAR(20),
                    estado VARCHAR(20) DEFAULT 'activo',
                    aula_id INTEGER,
                    fecha_registro TIMESTAMP DEFAULT current_timestamp,
                    FOREIGN KEY (aula_id) REFERENCES aulas(id)
                )
            '''            )
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre VARCHAR(100) NOT NULL,
                    tipo VARCHAR(20), -- docente, estudiante
                    email VARCHAR(100),
                    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''            )
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS uso_recursos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id INTEGER,
                    recurso_id INTEGER,
                    fecha_uso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tiempo_uso INTEGER, -- en minutos
                    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
                    FOREIGN KEY (recurso_id) REFERENCES recursos(id)
                )
            ''')
            
            conn.commit()
            conn.close()
            print("Base de datos inicializada correctamente")
            
        except Exception as e:
            print(f"Error inicializando base de datos: {e}")
    
    def ping_host(self, ip):
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', '1', '-w', '1000', str(ip)]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def get_mac_address(self, ip):
        try:
            if os.name == 'nt':
                cmd = ['arp', '-a', str(ip)]
            else:
                cmd = ['arp', '-n', str(ip)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if str(ip) in line:
                        import re
                        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                        match = re.search(mac_pattern, line)
                        if match:
                            return match.group(0).replace('-', ':').upper()
            return "No disponible"
            
        except Exception:
            return "No disponible"
    
    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except:
            return f"host-{str(ip).split('.')[-1]}"
    
    def scan_network_range(self, network_range):
        print(f"\nIniciando escaneo de red: {network_range}")
        print("=" * 50)
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            active_count = 0
            total_ips = len(list(network.hosts()))
            
            print(f"Escaneando {total_ips} direcciones IP...")
            
            for i, ip in enumerate(network.hosts(), 1):
                progress = (i / total_ips) * 100
                print(f"\rProgreso: {progress:.1f}% ({i}/{total_ips})", end='', flush=True)
                
                if self.ping_host(ip):
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_address(ip)
                    
                    device_info = {
                        'ip': str(ip),
                        'hostname': hostname,
                        'mac': mac,
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    self.active_hosts.append(device_info)
                    self.scan_results[str(ip)] = device_info
                    active_count += 1
            
            print(f"\n\nEscaneo completado. Dispositivos activos encontrados: {active_count}")
            return self.active_hosts
            
        except Exception as e:
            print(f"\nError durante el escaneo: {e}")
            return []
    
    def scan_ip_list(self, ip_list):
        print(f"\nEscaneando lista de IPs específicas")
        print("=" * 50)
        
        active_count = 0
        
        for ip in ip_list:
            try:
                print(f"Escaneando {ip}...", end=' ', flush=True)
                
                if self.ping_host(ip):
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_address(ip)
                    
                    device_info = {
                        'ip': str(ip),
                        'hostname': hostname,
                        'mac': mac,
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    self.active_hosts.append(device_info)
                    self.scan_results[str(ip)] = device_info
                    active_count += 1
                    print("ACTIVO")
                else:
                    print("No responde")
                    
            except Exception as e:
                print(f"Error: {e}")
        
        print(f"\nEscaneo completado. Dispositivos activos: {active_count}")
        return self.active_hosts
    
    def save_to_database(self, aula_nombre="Aula por defecto", sector="Sector A"):
        if not self.active_hosts:
            print("No hay dispositivos para guardar en la base de datos")
            return
        
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM aulas WHERE nombre = ?", (aula_nombre,))
            aula = cursor.fetchone()
            
            if not aula:
                cursor.execute(
                    "INSERT INTO aulas (nombre, sector, capacidad) VALUES (?, ?, ?)",
                    (aula_nombre, sector, len(self.active_hosts))
                )
                aula_id = cursor.lastrowid
            else:
                aula_id = aula[0]
            
            for device in self.active_hosts:
                device_type = self.classify_device(device['hostname'], device['mac'])
                
                cursor.execute('''
                    INSERT OR REPLACE INTO recursos 
                    (nombre, tipo, direccion_ip, direccion_mac, conectividad, aula_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    device['hostname'],
                    device_type,
                    device['ip'],
                    device['mac'],
                    'WiFi/Ethernet',
                    aula_id
                ))
            
            conn.commit()
            conn.close()
            
            print(f"Datos guardados en la base de datos ({len(self.active_hosts)} dispositivos)")
            
        except Exception as e:
            print(f"Error guardando en base de datos: {e}")
    
    def classify_device(self, hostname, mac):
        hostname_lower = hostname.lower()
        
        if any(keyword in hostname_lower for keyword in ['printer', 'print', 'hp', 'canon', 'epson']):
            return 'Impresora'
        elif any(keyword in hostname_lower for keyword in ['proj', 'projector']):
            return 'Proyector'
        elif any(keyword in hostname_lower for keyword in ['laptop', 'notebook']):
            return 'Laptop'
        elif any(keyword in hostname_lower for keyword in ['desktop', 'pc', 'workstation']):
            return 'PC Escritorio'
        elif any(keyword in hostname_lower for keyword in ['router', 'gateway', 'ap', 'access']):
            return 'Equipo de Red'
        elif any(keyword in hostname_lower for keyword in ['android', 'iphone', 'mobile']):
            return 'Dispositivo Móvil'
        else:
            return 'Dispositivo Genérico'
    
    def display_results(self):
        if not self.active_hosts:
            print("No hay dispositivos activos para mostrar")
            return
        
        print("\n" + "="*80)
        print("                    DISPOSITIVOS ACTIVOS ENCONTRADOS")
        print("="*80)
        print(f"{'IP':<15} {'Hostname':<25} {'MAC Address':<18} {'Tipo':<15}")
        print("-"*80)
        
        for device in self.active_hosts:
            device_type = self.classify_device(device['hostname'], device['mac'])
            print(f"{device['ip']:<15} {device['hostname']:<25} {device['mac']:<18} {device_type:<15}")
        
        print("-"*80)
        print(f"Total de dispositivos activos: {len(self.active_hosts)}")
        print(f"Hora del escaneo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    

    
    def view_database_records(self):
        if not os.path.exists(self.db_name):
            print("No existe base de datos. Guarda algunos dispositivos primero.")
            return
        
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM recursos")
            total_recursos = cursor.fetchone()[0]
            
            if total_recursos == 0:
                print("No hay dispositivos guardados en la base de datos.")
                conn.close()
                return
            
            print("\n" + "="*80)
            print("                    DISPOSITIVOS EN BASE DE DATOS")
            print("="*80)
            
            cursor.execute('''
                SELECT r.direccion_ip, r.nombre, r.direccion_mac, r.tipo, 
                       a.nombre as aula, a.sector, r.fecha_registro
                FROM recursos r
                LEFT JOIN aulas a ON r.aula_id = a.id
                ORDER BY a.nombre, r.direccion_ip
            ''')
            
            records = cursor.fetchall()
            current_aula = None
            
            for record in records:
                ip, hostname, mac, tipo, aula, sector, fecha = record
                
                if current_aula != aula:
                    if current_aula is not None:
                        print("-"*80)
                    print(f"\nAULA: {aula} - SECTOR: {sector}")
                    print("-"*80)
                    print(f"{'IP':<15} {'Hostname':<25} {'MAC':<18} {'Tipo':<15} {'Fecha'}")
                    print("-"*80)
                    current_aula = aula
                
                fecha_corta = fecha.split()[0] if fecha else "N/A"
                print(f"{ip:<15} {hostname:<25} {mac:<18} {tipo:<15} {fecha_corta}")
            
            print("-"*80)
            print(f"Total de dispositivos en base de datos: {total_recursos}")
            
            cursor.execute("SELECT COUNT(*) FROM aulas")
            total_aulas = cursor.fetchone()[0]
            print(f"Total de aulas registradas: {total_aulas}")
            
            conn.close()
            
        except Exception as e:
            print(f"Error accediendo a la base de datos: {e}")
    
    def get_network_info(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            
            print(f"Información de Red Local:")
            print(f"   IP Local: {local_ip}")
            print(f"   Red: {network}")
            print(f"   Gateway probable: {list(network.hosts())[0]}")
            
            return str(network)
            
        except Exception as e:
            print(f"Error obteniendo información de red: {e}")
            return "192.168.1.0/24"

def main():
    print("="*60)
    print("    ESCÁNER DE RED - GESTIÓN DE RECURSOS POR AULA")
    print("="*60)
    
    scanner = NetworkScanner()
    
    while True:
        print("\nOPCIONES DISPONIBLES:")
        print("1. Escanear red automáticamente")
        print("2. Escanear rango de red específico")
        print("3. Escanear IPs específicas")
        print("4. Mostrar resultados actuales")
        print("5. Guardar en base de datos")
        print("6. Ver información de red local")
        print("7. Ver datos guardados en base de datos")
        print("8. Salir")
        
        try:
            opcion = input("\nSelecciona una opción (1-8): ").strip()
            
            if opcion == '1':
                network_range = scanner.get_network_info()
                scanner.scan_network_range(network_range)
                scanner.display_results()
                
            elif opcion == '2':
                print("\nEjemplos de rangos:")
                print("  - 192.168.1.0/24 (toda la red)")
                print("  - 192.168.1.1-50 (rango específico)")
                
                network_range = input("Ingresa el rango de red (ej: 192.168.1.0/24): ").strip()
                if network_range:
                    scanner.scan_network_range(network_range)
                    scanner.display_results()
                
            elif opcion == '3':
                print("\nIngresa las IPs separadas por comas:")
                print("Ejemplo: 192.168.1.1, 192.168.1.10, 192.168.1.100")
                
                ip_input = input("IPs a escanear: ").strip()
                if ip_input:
                    ip_list = [ip.strip() for ip in ip_input.split(',')]
                    scanner.scan_ip_list(ip_list)
                    scanner.display_results()
                
            elif opcion == '4':
                scanner.display_results()
                
            elif opcion == '5':
                if scanner.active_hosts:
                    aula = input("Nombre del aula (Enter para 'Aula por defecto'): ").strip()
                    sector = input("Sector (Enter para 'Sector A'): ").strip()
                    
                    scanner.save_to_database(
                        aula if aula else "Aula por defecto",
                        sector if sector else "Sector A"
                    )
                else:
                    print("No hay dispositivos para guardar. Realiza un escaneo primero.")
                
            elif opcion == '6':
                scanner.get_network_info()
                
            elif opcion == '7':
                scanner.view_database_records()
                
            elif opcion == '8':
                print("\n¡Gracias por usar el Escáner de Red!")
                break
                
            else:
                print("Opción no válida. Por favor selecciona 1-8.")
                
        except KeyboardInterrupt:
            print("\n\nOperación cancelada por el usuario.")
        except Exception as e:
            print(f"\nError inesperado: {e}")

if __name__ == "__main__":
    main()
