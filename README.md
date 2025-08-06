# PROTOCOLO INTEGRAL DE RESPUESTA ANTE INCIDENTES DE RANSOMWARE
## Manual de Procedimientos para Empresas de Ciberseguridad

### **ÍNDICE GENERAL**

1. **MARCO GENERAL Y DEFINICIONES**
2. **FASE 0: PREPARACIÓN Y PREVENCIÓN**
3. **FASE 1: DETECCIÓN Y ALERTA INICIAL**
4. **FASE 2: TRIAJE Y EVALUACIÓN PRELIMINAR**
5. **FASE 3: CONTENCIÓN**
6. **FASE 4: PRESERVACIÓN DE EVIDENCIA DIGITAL**
7. **FASE 5: ANÁLISIS FORENSE Y TÉCNICO**
8. **FASE 6: ERRADICACIÓN**
9. **FASE 7: RECUPERACIÓN**
10. **FASE 8: POST-INCIDENTE**
11. **ASPECTOS LEGALES Y COMPLIANCE**
12. **COORDINACIÓN CON AUTORIDADES**
13. **GESTIÓN DE COMUNICACIONES**
14. **ANEXOS Y PLANTILLAS**
15. **MÉTRICAS Y KPIs**

---

## **1. MARCO GENERAL Y DEFINICIONES**

### **1.1 Objetivo del Protocolo**
Establecer un procedimiento sistemático, repetible y auditable para la gestión integral de incidentes de ransomware, garantizando la preservación de evidencia digital, el cumplimiento normativo y la máxima eficacia en la recuperación.

### **1.2 Alcance**
- Aplicable a todos los clientes con contrato de respuesta ante incidentes
- Cubre ransomware de cifrado, exfiltración y doble extorsión
- Incluye variantes: Crypto-ransomware, Locker ransomware, Ransomware-as-a-Service (RaaS)

### **1.3 Niveles de Severidad**

**CRÍTICO (P1)**
- Infraestructura crítica afectada
- Más del 50% de sistemas comprometidos
- Servicios esenciales interrumpidos
- Tiempo de respuesta: Inmediato (< 15 minutos)

**ALTO (P2)**
- Sistemas de producción afectados
- 25-50% de infraestructura comprometida
- Riesgo de propagación alta
- Tiempo de respuesta: < 1 hora

**MEDIO (P3)**
- Sistemas no críticos afectados
- < 25% de infraestructura
- Propagación contenida
- Tiempo de respuesta: < 4 horas

### **1.4 Equipo de Respuesta (IRT)**

**Estructura mínima:**
- Líder de Incidente (Incident Commander)
- Analista Forense Senior
- Especialista en Malware
- Administrador de Sistemas
- Asesor Legal/Compliance
- Responsable de Comunicaciones

---

## **2. FASE 0: PREPARACIÓN Y PREVENCIÓN**

### **2.1 Kit de Respuesta Rápida**

**Hardware:**
- Estaciones forenses con write-blockers
- Discos duros externos (mínimo 10TB)
- Dispositivos USB con herramientas forenses
- Cables de red cruzados y switches aislados
- Etiquetas de evidencia y precintos

**Software Base:**
- FTK Imager / dd / dc3dd
- Volatility Framework
- KAPE (Kroll Artifact Parser)
- Process Hacker / Process Monitor
- Wireshark / NetworkMiner
- IDA Pro / Ghidra
- CyberChef
- YARA rules actualizadas
- Herramientas de descifrado conocidas

### **2.2 Documentación Previa del Cliente**

**Inventario crítico:**
- Topología de red actualizada
- Inventario de sistemas críticos
- Matriz de dependencias
- Políticas de backup y retención
- Contactos de emergencia 24/7
- Credenciales de emergencia (en sobre sellado)

### **2.3 Baseline de Seguridad**
- Hashes de archivos de sistema limpios
- Configuraciones de referencia
- Logs históricos (mínimo 90 días)
- Listado de procesos normales
- Conexiones de red habituales

---

## **3. FASE 1: DETECCIÓN Y ALERTA INICIAL**

### **3.1 Recepción de la Alerta (0-15 minutos)**

**Checklist inmediato:**
```
[ ] Registrar hora exacta de notificación
[ ] Abrir ticket con código único: INC-[YYYY-MM-DD]-[SECUENCIAL]
[ ] Activar grabación de llamada (si aplica)
[ ] Identificar persona de contacto y validar autorización
[ ] Obtener descripción inicial del problema
[ ] Preguntar si han tomado alguna acción
[ ] Solicitar que NO apaguen equipos
[ ] Advertir sobre NO pagar rescate
[ ] Confirmar disponibilidad de acceso remoto
[ ] Activar equipo IRT según severidad
```

### **3.2 Cuestionario Inicial Estructurado**

**Preguntas críticas primera llamada:**

1. **Detección:**
   - ¿Cuándo se detectó el incidente? (fecha y hora exacta)
   - ¿Quién lo detectó y cómo?
   - ¿Hay mensaje de rescate visible? ¿Puede enviarnos captura?
   - ¿Qué extensión tienen los archivos cifrados?

2. **Alcance inicial:**
   - ¿Cuántos equipos están afectados (aproximadamente)?
   - ¿Están afectados servidores? ¿Cuáles?
   - ¿Funcionan los servicios críticos?
   - ¿Pueden acceder a archivos compartidos?

3. **Acciones tomadas:**
   - ¿Han apagado algún equipo?
   - ¿Han desconectado la red?
   - ¿Han intentado restaurar backups?
   - ¿Alguien ha contactado con los atacantes?

4. **Contexto:**
   - ¿Ha habido actividad inusual en días previos?
   - ¿Cambios recientes en sistemas o personal?
   - ¿Incidentes de phishing reportados?
   - ¿Actualizaciones o instalaciones recientes?

### **3.3 Instrucciones Inmediatas al Cliente**

**Script estándar:**
"Hemos registrado su incidente como CRÍTICO. Por favor, siga estas instrucciones exactamente:

1. **NO APAGUE** ningún equipo afectado - necesitamos preservar evidencia en memoria
2. **DESCONECTE** inmediatamente los cables de red de equipos afectados
3. **DOCUMENTE** con fotos el mensaje de rescate si está visible
4. **DETENGA** cualquier backup programado inmediatamente
5. **AISLE** la WiFi si hay equipos conectados
6. **PREPARE** un espacio de trabajo para nuestro equipo
7. **REÚNA** al personal de IT disponible

Le llamaremos en 15 minutos con el plan de acción."

---

## **4. FASE 2: TRIAJE Y EVALUACIÓN PRELIMINAR**

### **4.1 Análisis Remoto Inicial (15-45 minutos)**

**Si hay acceso remoto disponible:**

```powershell
# Comandos Windows para evaluación rápida
# Ejecutar desde equipo no afectado con privilegios

# 1. Identificar procesos sospechosos
Get-Process | Export-Csv "processes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
Get-CimInstance Win32_Process | Select ProcessId, ParentProcessId, CommandLine, CreationDate | Export-Csv "process_details.csv"

# 2. Conexiones de red activas
netstat -anob > netstat_output.txt
Get-NetTCPConnection | Export-Csv "tcp_connections.csv"

# 3. Tareas programadas recientes
schtasks /query /fo CSV /v > scheduled_tasks.csv
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Export-Csv "active_tasks.csv"

# 4. Servicios nuevos o modificados
Get-Service | Export-Csv "services.csv"
Get-WmiObject win32_service | Select Name, DisplayName, PathName, StartMode, State, StartName | Export-Csv "service_details.csv"

# 5. Archivos modificados recientemente
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select FullName, LastWriteTime, Length | Export-Csv "recent_files.csv"

# 6. Eventos críticos
wevtutil epl Security security_events.evtx
wevtutil epl System system_events.evtx
wevtutil epl Application application_events.evtx

# 7. Usuarios y sesiones
query user > active_users.txt
net user > local_users.txt
net localgroup administrators > admin_users.txt
```

### **4.2 Identificación Rápida del Ransomware**

**Indicadores clave para identificación:**

1. **Extensión de archivos:**
   - Documentar extensión exacta (.locked, .encrypted, .cry, etc.)
   - Verificar si mantiene extensión original (file.doc.locked)
   
2. **Nota de rescate:**
   - Nombre del archivo (README.txt, DECRYPT_INSTRUCTIONS.html, etc.)
   - Contenido exacto (copiar texto completo)
   - Direcciones Bitcoin/Monero
   - Emails o sitios Tor de contacto

3. **Patrón de cifrado:**
   - ¿Cifra archivos completos o parcialmente?
   - ¿Respeta ciertos directorios? (Windows, Program Files)
   - ¿Tamaño de archivos cifrados vs originales?

### **4.3 Matriz de Evaluación de Impacto**

| Sistema/Servicio | Estado | Criticidad | Datos Afectados | Backup Disponible | Prioridad Recuperación |
|-----------------|---------|------------|-----------------|-------------------|----------------------|
| Active Directory | Parcial | CRÍTICA | Usuarios/GPOs | Sí - 24h antiguo | 1 |
| SQL Server Prod | Cifrado | CRÍTICA | Base datos clientes | Sí - 12h antiguo | 2 |
| File Server | Cifrado | ALTA | Documentos compartidos | No | 3 |
| Exchange | Operativo | CRÍTICA | N/A | Sí - Tiempo real | N/A |

---

## **5. FASE 3: CONTENCIÓN**

### **5.1 Contención Inmediata (Primeras 2 horas)**

**Nivel 1 - Aislamiento de Red:**
```bash
# Firewall - Bloquear todo tráfico saliente excepto al equipo de respuesta
iptables -A OUTPUT -j DROP
iptables -A OUTPUT -d [IP_EQUIPO_RESPUESTA] -j ACCEPT

# Windows Firewall
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="IR_Team" dir=out action=allow remoteip=[IP_EQUIPO_RESPUESTA]

# Deshabilitar WiFi y Bluetooth
netsh interface set interface "Wi-Fi" admin=disable
```

**Nivel 2 - Contención de Propagación:**
```powershell
# Deshabilitar shares administrativos
net share C$ /delete
net share ADMIN$ /delete
net share IPC$ /delete

# Deshabilitar RDP temporalmente
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# Bloquear ejecución desde carpetas comunes de ransomware
$paths = @("%TEMP%", "%APPDATA%", "%LOCALAPPDATA%")
foreach ($path in $paths) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths" -Name $path -Value $path -PropertyType String
}
```

### **5.2 Identificación del Vector de Entrada**

**Vectores comunes a investigar:**

1. **RDP Comprometido:**
   - Revisar logs de Event ID 4624, 4625 (intentos de login)
   - Buscar IPs extranjeras en conexiones RDP
   - Verificar cuentas con privilegios recién creadas

2. **Email/Phishing:**
   - Revisar logs de Exchange/Office 365
   - Buscar attachments sospechosos (.doc, .xls con macros, .zip)
   - Entrevistar usuarios sobre emails sospechosos

3. **Vulnerabilidades Explotadas:**
   - Verificar parches pendientes críticos
   - Revisar logs de IIS/Apache por exploits conocidos
   - Buscar webshells en directorios web

4. **Software/Updates Maliciosos:**
   - Revisar software instalado recientemente
   - Verificar integridad de updates recientes
   - Buscar software crackeado o no licenciado

### **5.3 Contención Avanzada**

**Creación de Honeypots Internos:**
```powershell
# Crear archivos señuelo para detectar ransomware activo
$honeyDir = "C:\__HONEYPOT_NO_TOCAR__"
New-Item -ItemType Directory -Path $honeyDir -Force
1..100 | ForEach-Object {
    $file = "$honeyDir\documento_importante_$_.docx"
    "Contenido de prueba" | Out-File $file
    # Monitorizar estos archivos para detectar cifrado
}

# Script de monitoreo
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $honeyDir
$watcher.EnableRaisingEvents = $true
Register-ObjectEvent $watcher "Changed" -Action {
    Write-Host "ALERTA: Ransomware activo detectado!" -ForegroundColor Red
    # Acción automática de contención
    Stop-Computer -Force
}
```

---

## **6. FASE 4: PRESERVACIÓN DE EVIDENCIA DIGITAL**

### **6.1 Cadena de Custodia**

**Documento de Evidencia Digital:**
```
FORMULARIO DE CADENA DE CUSTODIA
================================
Caso #: INC-2024-001
Fecha/Hora Recolección: [YYYY-MM-DD HH:MM:SS]
Recolectado por: [Nombre, Cargo, Firma]
Testigo: [Nombre, Cargo, Firma]

EVIDENCIA:
----------
ID Evidencia: EVD-001
Tipo: [Imagen Disco/Memoria/Logs/Malware]
Dispositivo Origen: [Hostname/IP/Marca/Modelo/Serial]
Método Adquisición: [dd/FTK/Encase/Otro]
Hash MD5: [32 caracteres]
Hash SHA256: [64 caracteres]
Ubicación Almacenamiento: [Servidor/Path]

TRANSFERENCIAS:
--------------
Fecha/Hora | De | A | Propósito | Firma
[Registro de cada transferencia]
```

### **6.2 Adquisición Forense Completa**

**A. Memoria Volátil (RAM):**
```bash
# Windows - Usando DumpIt
DumpIt.exe /Q /T RAM_[HOSTNAME]_[TIMESTAMP]

# Linux - Usando LiME
insmod lime.ko "path=/media/usb/ram.lime format=lime"

# Validación
sha256sum ram.lime > ram.lime.sha256

# Análisis inicial con Volatility
volatility -f ram.lime imageinfo
volatility -f ram.lime pslist > processes.txt
volatility -f ram.lime netscan > connections.txt
volatility -f ram.lime cmdline > commandlines.txt
```

**B. Imagen de Disco:**
```bash
# Imagen forense bit-a-bit
# Windows con FTK Imager CLI
ftkimager.exe \\.\PhysicalDrive0 D:\Evidence\disk.E01 --case-number INC-001 --evidence-number EVD-001 --verify

# Linux con dc3dd
dc3dd if=/dev/sda of=/media/evidence/disk.dd hash=sha256 log=acquisition.log

# Crear imagen de muestra infectada (1 sistema completo mínimo)
# Mantener sistema infectado aislado pero encendido para análisis
```

**C. Artefactos Específicos de Ransomware:**

```powershell
# Recolección automatizada de artefactos
$evidencePath = "E:\Evidence\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidencePath

# 1. Registro de Windows
reg save HKLM\SYSTEM "$evidencePath\SYSTEM.hiv"
reg save HKLM\SOFTWARE "$evidencePath\SOFTWARE.hiv"
reg save HKLM\SECURITY "$evidencePath\SECURITY.hiv"
reg save HKU\.DEFAULT "$evidencePath\DEFAULT.hiv"

# 2. Archivos de Ransomware
$ransomwareFiles = @(
    "*.exe", "*.dll", "*.bat", "*.ps1", "*.vbs",
    "*decrypt*", "*readme*", "*howto*", "*restore*"
)
foreach ($pattern in $ransomwareFiles) {
    Get-ChildItem -Path C:\ -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
    Copy-Item -Destination "$evidencePath\suspicious_files\" -Force
}

# 3. Muestras de archivos cifrados (mínimo 20)
$encrypted = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.Extension -match '\.(locked|encrypted|enc|cry)'} |
    Select-Object -First 20
$encrypted | Copy-Item -Destination "$evidencePath\encrypted_samples\" -Force

# 4. Logs críticos
$logPaths = @(
    "C:\Windows\System32\winevt\Logs\*.evtx",
    "C:\Windows\System32\LogFiles\**\*.log",
    "C:\inetpub\logs\LogFiles\**\*.log"
)
foreach ($logPath in $logPaths) {
    Copy-Item -Path $logPath -Destination "$evidencePath\logs\" -Recurse -Force
}

# 5. Archivos de hibernación y paginación
Copy-Item "C:\hiberfil.sys" "$evidencePath\" -Force -ErrorAction SilentlyContinue
Copy-Item "C:\pagefile.sys" "$evidencePath\" -Force -ErrorAction SilentlyContinue

# 6. Hash de toda la evidencia
Get-ChildItem -Path $evidencePath -Recurse | 
    Get-FileHash -Algorithm SHA256 | 
    Export-Csv "$evidencePath\evidence_hashes.csv"
```

### **6.3 Preservación para Colaboración con Autoridades**

**Kit Especial para Policía/Europol/INCIBE:**

```
EVIDENCE_PACK_AUTHORITIES/
├── 01_MALWARE_SAMPLES/
│   ├── ransomware.exe (con contraseña: infected)
│   ├── ransomware.exe.sha256
│   └── analysis_report.pdf
├── 02_ENCRYPTED_FILES/
│   ├── original_files/ (si se tienen)
│   ├── encrypted_samples/ (20 archivos mínimo)
│   └── file_comparison.xlsx
├── 03_RANSOM_NOTES/
│   ├── ransom_note_original.txt
│   ├── screenshots/
│   └── translations.docx
├── 04_NETWORK_INDICATORS/
│   ├── c2_communications.pcap
│   ├── tor_addresses.txt
│   ├── bitcoin_addresses.txt
│   └── iocs.json (formato STIX/TAXII)
├── 05_SYSTEM_ARTIFACTS/
│   ├── registry_keys.reg
│   ├── scheduled_tasks.xml
│   ├── persistence_mechanisms.docx
│   └── timeline.csv
├── 06_LOGS/
│   ├── security_events.evtx
│   ├── firewall_logs.txt
│   └── execution_logs.csv
└── CHAIN_OF_CUSTODY.pdf
```

**Preparación del paquete:**
```bash
# Comprimir con contraseña para envío seguro
7z a -p[PASSWORD] -mhe=on evidence_pack.7z EVIDENCE_PACK_AUTHORITIES/

# Generar reporte ejecutivo para autoridades
# Incluir: Timeline, TTPs (MITRE ATT&CK), IOCs, Impacto
```

---

## **7. FASE 5: ANÁLISIS FORENSE Y TÉCNICO**

### **7.1 Análisis Estático del Malware**

**Herramientas y proceso:**

```python
# Script de análisis automático inicial
import hashlib
import pefile
import yara
import json
from datetime import datetime

def analyze_ransomware(file_path):
    analysis = {
        "timestamp": datetime.now().isoformat(),
        "file": file_path,
        "hashes": {},
        "pe_info": {},
        "strings": [],
        "yara_matches": []
    }
    
    # Cálculo de hashes
    with open(file_path, 'rb') as f:
        content = f.read()
        analysis["hashes"]["md5"] = hashlib.md5(content).hexdigest()
        analysis["hashes"]["sha1"] = hashlib.sha1(content).hexdigest()
        analysis["hashes"]["sha256"] = hashlib.sha256(content).hexdigest()
    
    # Análisis PE
    pe = pefile.PE(file_path)
    analysis["pe_info"]["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    analysis["pe_info"]["compile_time"] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
    analysis["pe_info"]["sections"] = []
    
    for section in pe.sections:
        analysis["pe_info"]["sections"].append({
            "name": section.Name.decode().rstrip('\x00'),
            "virtual_size": section.Misc_VirtualSize,
            "entropy": section.get_entropy()
        })
    
    # Aplicar reglas YARA
    rules = yara.compile('ransomware_rules.yar')
    matches = rules.match(file_path)
    analysis["yara_matches"] = [str(match) for match in matches]
    
    return json.dumps(analysis, indent=2)
```

**Indicadores comunes por familia:**

| Familia | Extensión | Nota Rescate | Particularidades |
|---------|-----------|--------------|------------------|
| Conti | .CONTI | readme.txt | Doble extorsión, exfiltra antes |
| REvil | .[random] | [random]-readme.txt | RaaS, usa Salsa20 + RSA |
| Ryuk | .RYK | RyukReadMe.txt | Targeted, post-Trickbot |
| LockBit | .lockbit | Restore-My-Files.txt | Fast encryption, StealBit |
| BlackCat | .[random] | RECOVER-[random].txt | Rust-based, Linux/Windows |

### **7.2 Análisis Dinámico**

**Sandbox aislado:**
```bash
# Configuración de ambiente controlado
# VM con snapshots limpios, sin conexión a red de producción

# Monitoreo con Process Monitor
procmon.exe /BackingFile:ransomware_activity.pml /Quiet /Minimized

# Monitoreo de red con fakenet-ng
python fakenet.py --config-file fakenet.config

# Ejecución controlada
# Registrar: APIs llamadas, archivos creados/modificados, 
# registro modificado, conexiones de red intentadas
```

### **7.3 Análisis de Propagación y Lateral Movement**

```powershell
# Búsqueda de evidencia de movimiento lateral
# Event IDs clave a buscar:

# Logon events
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625,4648,4672} |
    Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-30)} |
    Export-Csv lateral_movement_events.csv

# RDP
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';ID=1149}

# PowerShell execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4103,4104}

# Scheduled tasks
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';ID=106,200,201}

# Service creation
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045}
```

### **7.4 Timeline Reconstruction**

```python
# Crear timeline forense completo
import csv
from datetime import datetime

def create_timeline(events_sources):
    timeline = []
    
    # Fuentes: MFT, Event Logs, Registry, Prefetch, USN Journal
    for source in events_sources:
        for event in source:
            timeline.append({
                'timestamp': event['time'],
                'source': event['source'],
                'action': event['action'],
                'details': event['details'],
                'artifact': event['artifact']
            })
    
    # Ordenar cronológicamente
    timeline.sort(key=lambda x: x['timestamp'])
    
    # Identificar ventana de compromiso
    infection_window = identify_infection_window(timeline)
    
    return timeline, infection_window
```

---

## **8. FASE 6: ERRADICACIÓN**

### **8.1 Limpieza Completa del Sistema**

**Checklist de erradicación:**

```powershell
# 1. Eliminar archivos del ransomware
$ransomwarePaths = @(
    "C:\Users\*\AppData\Local\Temp\*",
    "C:\Users\*\AppData\Roaming\*",
    "C:\Windows\Temp\*",
    "C:\ProgramData\*"
)

foreach ($path in $ransomwarePaths) {
    Get-ChildItem -Path $path -Include "*.exe","*.dll","*.bat" -Recurse |
    Where-Object {$_.CreationTime -gt $infectionDate} |
    Remove-Item -Force -Confirm:$false
}

# 2. Eliminar persistencia en registro
$regKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

foreach ($key in $regKeys) {
    # Revisar y eliminar entradas sospechosas
    Get-ItemProperty -Path $key | Format-List
}

# 3. Eliminar tareas programadas maliciosas
Get-ScheduledTask | Where-Object {$_.Date -gt $infectionDate} |
    Unregister-ScheduledTask -Confirm:$false

# 4. Restaurar configuración de shadow copies
vssadmin delete shadows /all /quiet
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%

# 5. Limpiar servicios comprometidos
Get-Service | Where-Object {$_.Status -eq 'Stopped' -and $_.StartType -eq 'Disabled'} |
    Set-Service -StartupType Manual

# 6. Resetear políticas de grupo
gpupdate /force
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose
```

### **8.2 Validación de Limpieza**

```powershell
# Script de validación post-limpieza
function Test-SystemClean {
    $issues = @()
    
    # Verificar no hay procesos sospechosos
    $suspiciousProcesses = Get-Process | Where-Object {
        $_.Path -match "AppData|Temp" -or
        $_.Company -eq $null -or
        $_.Description -eq $null
    }
    if ($suspiciousProcesses) {
        $issues += "Procesos sospechosos encontrados"
    }
    
    # Verificar no hay archivos cifrados
    $encryptedFiles = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.Extension -match '\.(locked|encrypted|enc)'}
    if ($encryptedFiles) {
        $issues += "Archivos cifrados aún presentes"
    }
    
    # Verificar servicios
    $suspiciousServices = Get-Service | Where-Object {
        $_.DisplayName -match "decrypt|ransom|crypto" -or
        $_.BinaryPathName -match "AppData|Temp"
    }
    if ($suspiciousServices) {
        $issues += "Servicios sospechosos encontrados"
    }
    
    return $issues
}
```

---

## **9. FASE 7: RECUPERACIÓN**

### **9.1 Estrategia de Recuperación**

**Árbol de decisión:**

```
¿Existe descifrador gratuito?
├── SÍ → Aplicar descifrador
│   └── Validar integridad de archivos
└── NO → ¿Backups disponibles?
    ├── SÍ → Evaluar backups
    │   ├── ¿Backups limpios? (pre-infección)
    │   │   ├── SÍ → Restaurar desde backup
    │   │   └── NO → Buscar backup más antiguo
    │   └── Validar integridad post-restauración
    └── NO → Evaluar opciones
        ├── Reconstrucción manual
        ├── Recuperación parcial (shadow copies)
        └── Negociación (último recurso)
```

### **9.2 Proceso de Restauración desde Backup**

**Validación pre-restauración:**

```powershell
# 1. Verificar que el backup no está infectado
# Montar backup en sistema aislado
$backupPath = "\\backup-server\backups\pre-infection"
$testPath = "E:\backup_validation"

# Escanear backup
Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" `
    -ArgumentList "-Scan -ScanType 3 -File $backupPath" -Wait

# 2. Verificar integridad del backup
$backupHashes = Import-Csv "backup_checksums.csv"
foreach ($file in $backupHashes) {
    $currentHash = Get-FileHash -Path "$backupPath\$($file.Path)" -Algorithm SHA256
    if ($currentHash.Hash -ne $file.Hash) {
        Write-Warning "Integridad comprometida: $($file.Path)"
    }
}

# 3. Restauración gradual
# Primero: Controladores de dominio
# Segundo: Servicios críticos (SQL, Exchange)
# Tercero: File servers
# Último: Workstations
```

### **9.3 Restauración sin Backups**

**Técnicas de recuperación alternativas:**

1. **Shadow Copies (si existen):**
```powershell
# Listar shadow copies disponibles
vssadmin list shadows /for=C:

# Montar shadow copy
mklink /d C:\ShadowRestore \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Copiar archivos necesarios
robocopy C:\ShadowRestore C:\Recovered /E /COPYALL /R:3 /W:10
```

2. **Herramientas de recuperación:**
```bash
# PhotoRec para recuperación de archivos borrados
photorec /d /recovery_dir /cmd device search

# TestDisk para recuperación de particiones
testdisk /cmd device analyze
```

3. **Descifradores conocidos:**
```python
# Base de datos de descifradores
decryptors = {
    "Dharma": "https://www.nomoreransom.org/uploads/Dharma_Decryptor.zip",
    "STOP": "https://download.bleepingcomputer.com/demonslay335/STOPDecrypter.zip",
    "GandCrab": "https://labs.bitdefender.com/wp-content/uploads/downloads/gandcrab-decryptor/",
    # Mantener actualizada esta lista
}
```

### **9.4 Rebuild Completo**

**Cuando es necesario reconstruir desde cero:**

```powershell
# Plan de rebuild
$rebuildPlan = @{
    "Fase1" = @{
        "Acciones" = @(
            "Instalación limpia de OS",
            "Hardening inicial",
            "Instalación de antivirus/EDR",
            "Aplicación de todos los parches"
        )
        "Tiempo" = "4 horas"
    }
    "Fase2" = @{
        "Acciones" = @(
            "Restauración de Active Directory",
            "Configuración de red",
            "Políticas de grupo"
        )
        "Tiempo" = "8 horas"
    }
    "Fase3" = @{
        "Acciones" = @(
            "Instalación de aplicaciones",
            "Restauración de datos",
            "Validación de servicios"
        )
        "Tiempo" = "12 horas"
    }
}
```

---

## **10. FASE 8: POST-INCIDENTE**

### **10.1 Informe Técnico Detallado**

**Estructura del informe final:**

```markdown
# INFORME DE INCIDENTE DE RANSOMWARE
## Referencia: INC-2024-XXX

### RESUMEN EJECUTIVO
- **Fecha del incidente:** [DD/MM/YYYY]
- **Ransomware identificado:** [Familia/Variante]
- **Sistemas afectados:** [Número y tipos]
- **Datos comprometidos:** [Volumen y criticidad]
- **Tiempo de inactividad:** [Horas/Días]
- **Vector de entrada:** [Confirmado/Probable]
- **Estado actual:** [Resuelto/En monitoreo]

### CRONOLOGÍA DETALLADA
| Fecha/Hora | Evento | Evidencia | Acción Tomada |
|------------|--------|-----------|---------------|
| [Timestamps precisos de cada evento] |

### ANÁLISIS TÉCNICO
#### Vector de Infección
[Descripción detallada del método de entrada]

#### Indicadores de Compromiso (IOCs)
- **Hashes de archivos:**
  - SHA256: [hash]
  - MD5: [hash]
- **IPs maliciosas:**
  - [IP:Puerto] - [Descripción]
- **Dominios C2:**
  - [dominio.com] - [Propósito]
- **Rutas de archivos:**
  - [C:\Path\to\malware.exe]
- **Claves de registro:**
  - [HKLM\Software\...]

#### Técnicas MITRE ATT&CK
| Táctica | Técnica | ID | Evidencia |
|---------|---------|-----|-----------|
| Initial Access | Phishing | T1566 | Email con macro |
| Execution | PowerShell | T1059.001 | Logs de PS |
| Persistence | Registry Run Keys | T1547.001 | RegKey created |
| Defense Evasion | Obfuscation | T1027 | Packed executable |
| Impact | Data Encrypted | T1486 | Ransomware execution |

### IMPACTO EN EL NEGOCIO
- **Sistemas críticos afectados:** [Lista]
- **Tiempo de inactividad:** [Total en horas]
- **Datos perdidos:** [Si aplica]
- **Costes estimados:**
  - Respuesta al incidente: [€]
  - Pérdida de productividad: [€]
  - Recuperación: [€]
  - Total: [€]

### ACCIONES DE RECUPERACIÓN
[Detalle de todas las acciones tomadas]

### RECOMENDACIONES
#### Inmediatas (0-7 días)
1. [Acción crítica 1]
2. [Acción crítica 2]

#### Corto plazo (1-4 semanas)
1. [Mejora de seguridad 1]
2. [Mejora de seguridad 2]

#### Largo plazo (1-6 meses)
1. [Proyecto de mejora 1]
2. [Proyecto de mejora 2]

### LECCIONES APRENDIDAS
[Qué funcionó bien, qué falló, qué mejorar]

### ANEXOS
- Anexo A: Logs completos
- Anexo B: Capturas de pantalla
- Anexo C: Análisis de malware
- Anexo D: Comunicaciones con el atacante
```

### **10.2 Mejoras de Seguridad Post-Incidente**

**Plan de hardening obligatorio:**

```powershell
# 1. Implementación de políticas de ejecución restrictivas
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force

# 2. AppLocker/WDAC
New-AppLockerPolicy -Xml .\AppLockerPolicy.xml -PackageApps -Enforce

# 3. Deshabilitación de protocolos legacy
# SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# LLMNR
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force

# 4. Segmentación de red mejorada
# Implementar VLANs, microsegmentación, Zero Trust

# 5. MFA obligatorio
# Especialmente para: RDP, VPN, Admin accounts, Email

# 6. Backup 3-2-1 mejorado
# 3 copias, 2 medios diferentes, 1 offsite/offline

# 7. EDR/XDR deployment
# Instalar en TODOS los endpoints
```

### **10.3 Programa de Mejora Continua**

**Simulacros y testing:**

```python
# Programa de simulacros trimestrales
simulation_schedule = {
    "Q1": {
        "tipo": "Tabletop Exercise",
        "escenario": "Ransomware via email",
        "participantes": ["IT", "Management", "Legal"],
        "duración": "4 horas"
    },
    "Q2": {
        "tipo": "Purple Team",
        "escenario": "Lateral movement post-compromiso",
        "participantes": ["SOC", "IT", "Red Team externo"],
        "duración": "2 días"
    },
    "Q3": {
        "tipo": "Simulación completa",
        "escenario": "Doble extorsión con exfiltración",
        "participantes": ["Toda la organización"],
        "duración": "1 semana"
    },
    "Q4": {
        "tipo": "Recovery test",
        "escenario": "Restauración desde backup",
        "participantes": ["IT", "Proveedores backup"],
        "duración": "48 horas"
    }
}
```

---

## **11. ASPECTOS LEGALES Y COMPLIANCE**

### **11.1 Notificaciones Obligatorias**

**España - Marco Legal:**

```
NOTIFICACIÓN AEPD (Agencia Española de Protección de Datos)
============================================================
Plazo: 72 horas desde conocimiento de la brecha
Canal: https://sedeagpd.gob.es/
Requisitos RGPD Art. 33:

1. Naturaleza de la violación
2. Categorías y número aproximado de interesados
3. Categorías y número aproximado de registros
4. Consecuencias probables
5. Medidas adoptadas o propuestas
6. Datos de contacto del DPO

Plantilla:
----------
Fecha y hora del incidente: [YYYY-MM-DD HH:MM]
Fecha y hora de detección: [YYYY-MM-DD HH:MM]
Tipo de brecha: [Confidencialidad/Integridad/Disponibilidad]
Datos afectados: [Categorías según RGPD]
Número de afectados: [Estimación]
Medidas técnicas previas: [Cifrado, pseudonimización, etc.]
Medidas adoptadas: [Lista de acciones]
Riesgo para los derechos: [Alto/Medio/Bajo]
Notificación a interesados: [Sí/No - Justificación]
```

**INCIBE-CERT:**
```
Portal: https://www.incibe-cert.es/
Teléfono 24/7: 017
Email: incidencias@incibe-cert.es

Información requerida:
- Tipo de organización
- Sector de actividad
- Sistemas afectados
- Impacto estimado
- Necesidad de ayuda técnica
```

**Notificación a Aseguradoras:**
```
CRITICAL: Notificar en primeras 24-48h para no perder cobertura
Documentación necesaria:
- Póliza y número de siniestro
- Descripción del incidente
- Estimación inicial de daños
- Acciones tomadas
- Preservación de evidencia
```

### **11.2 Consideraciones sobre Pago de Rescate**

**Marco legal y riesgos:**

```
ADVERTENCIA LEGAL:
==================
1. El pago NO garantiza recuperación
2. Puede constituir financiación del terrorismo (Art. 576 CP)
3. Sanciones OFAC si el grupo está sancionado
4. Obligación de reportar a autoridades
5. Puede violar póliza de seguros

Si el cliente insiste en pagar:
--------------------------------
[ ] Documentar la decisión por escrito
[ ] Informar de todos los riesgos legales
[ ] Notificar a autoridades competentes
[ ] Verificar listas de sanciones
[ ] Involucrar a asesoría legal
[ ] Documentar toda comunicación
[ ] Usar intermediario especializado
[ ] Mantener evidencia de todo
```

### **11.3 Gestión de Responsabilidades**

```python
# Matriz RACI para el incidente
responsabilidades = {
    "Decisión de pago": {
        "Responsible": "CEO/Board",
        "Accountable": "CEO",
        "Consulted": ["Legal", "CISO", "Insurance"],
        "Informed": ["Employees", "Stakeholders"]
    },
    "Notificación AEPD": {
        "Responsible": "DPO",
        "Accountable": "CEO",
        "Consulted": ["Legal", "CISO"],
        "Informed": ["Board", "Afectados"]
    },
    "Comunicación pública": {
        "Responsible": "PR/Comunicación",
        "Accountable": "CEO",
        "Consulted": ["Legal", "CISO", "DPO"],
        "Informed": ["Todos"]
    }
}
```

---

## **12. COORDINACIÓN CON AUTORIDADES**

### **12.1 Cuerpos de Seguridad del Estado**

**Policía Nacional - Unidad de Delitos Telemáticos:**
```
Contacto: delitos.telematicos@policia.es
Teléfono: 091
Documentación requerida:
- Denuncia formal
- Informe técnico preliminar
- Evidencias digitales (formato EnCase/FTK)
- Logs de sistema
- Comunicaciones con atacantes
```

**Guardia Civil - Grupo de Delitos Telemáticos:**
```
Contacto: gdt@guardiacivil.org
Teléfono: 062
Especialización: Infraestructuras críticas
```

### **12.2 Colaboración con Europol**

**Preparación de documentación para Europol:**

```bash
# Estructura de carpetas para Europol
EUROPOL_PACKAGE/
├── 01_EXECUTIVE_SUMMARY/
│   ├── incident_summary.pdf (EN)
│   └── technical_summary.pdf (EN)
├── 02_MALWARE_ANALYSIS/
│   ├── static_analysis/
│   ├── dynamic_analysis/
│   └── yara_rules.yar
├── 03_NETWORK_FORENSICS/
│   ├── pcap_files/
│   ├── netflow_data/
│   └── c2_infrastructure.json
├── 04_INDICATORS/
│   ├── iocs_stix2.json
│   ├── iocs_misp.json
│   └── iocs_human_readable.xlsx
├── 05_ATTRIBUTION/
│   ├── ttp_analysis.pdf
│   ├── code_similarities.pdf
│   └── infrastructure_overlaps.pdf
└── 06_VICTIM_IMPACT/
    ├── affected_systems.xlsx
    ├── data_categories.pdf
    └── financial_impact.pdf

# Formato STIX 2.1 para IOCs
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--[UUID]",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "pattern": "[file:hashes.SHA256 = 'hash_value']",
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00Z",
    "labels": ["malicious-activity"],
    "description": "Ransomware variant X"
}
```

### **12.3 Colaboración Internacional**

**FBI IC3 (si hay nexo con EEUU):**
```
Portal: https://ic3.gov
Información requerida:
- Dirección Bitcoin/Monero
- Emails del atacante
- Pérdidas estimadas en USD
```

**No More Ransom Project:**
```
Upload de muestras: https://www.nomoreransom.org/crypto-sheriff.php
Compartir inteligencia sobre nuevas variantes
```

---

## **13. GESTIÓN DE COMUNICACIONES**

### **13.1 Comunicación Interna**

**Templates por audiencia:**

```markdown
# EMPLEADOS - Comunicación Inicial
Asunto: Incidente de Seguridad - Acción Requerida

Estimado equipo,

Hemos detectado un incidente de seguridad que está afectando algunos de nuestros sistemas. Nuestro equipo de IT está trabajando activamente en resolver la situación.

ACCIONES INMEDIATAS REQUERIDAS:
1. NO enciendan equipos apagados
2. NO conecten dispositivos USB
3. Si su equipo muestra un mensaje extraño, NO lo apague
4. Contacten a IT inmediatamente si detectan algo inusual

Proporcionaremos actualizaciones cada 4 horas.

Contacto de emergencia: [Teléfono IT]

# CONSEJO DE ADMINISTRACIÓN
Asunto: Incidente Crítico de Ransomware - Briefing Ejecutivo

Resumen:
- Incidente detectado: [Fecha/Hora]
- Sistemas afectados: [%]
- Impacto en operaciones: [Descripción]
- Pérdida estimada: [€]
- Tiempo de recuperación estimado: [Horas/Días]
- Acciones en curso: [Lista]
- Decisiones requeridas: [Lista]

Próxima actualización: [Hora]
```

### **13.2 Comunicación Externa**

**Clientes/Proveedores:**
```markdown
# Notificación a Clientes

Estimado [Cliente],

Le informamos que [Empresa] ha experimentado un incidente de seguridad que temporalmente afecta [servicios específicos]. 

Estado actual:
- Sus datos están [seguros/siendo evaluados]
- Servicios afectados: [Lista]
- Servicios operativos: [Lista]

Acciones tomadas:
- Activación de protocolo de respuesta
- Colaboración con autoridades
- Implementación de medidas de contención

Le mantendremos informado de cualquier desarrollo relevante.

Para consultas: [Email/Teléfono dedicado]
```

### **13.3 Gestión de Medios**

**Declaración de prensa:**
```
[EMPRESA] GESTIONA INCIDENTE DE CIBERSEGURIDAD

[Ciudad, Fecha] - [Empresa] confirma que ha detectado y está gestionando activamente un incidente de ciberseguridad. 

Puntos clave:
• Detección temprana permitió activación inmediata de protocolos
• Colaboración activa con autoridades competentes
• No hay evidencia de [exfiltración de datos/impacto en clientes]
• Operaciones [parcialmente/totalmente] restauradas

"Nuestra prioridad es la seguridad de los datos de nuestros clientes y la continuidad del servicio. Hemos tomado medidas inmediatas y estamos trabajando las 24 horas para resolver completamente la situación" - [Portavoz]

Para más información:
[Contacto de prensa]
[Email dedicado]
```

---

## **14. ANEXOS Y PLANTILLAS**

### **14.1 Checklist Maestro de Respuesta**

```markdown
# CHECKLIST DE RESPUESTA RÁPIDA - RANSOMWARE

## HORA 0-1: RESPUESTA INMEDIATA
[ ] Activar equipo de respuesta
[ ] Abrir ticket de incidente
[ ] Evaluar severidad (P1/P2/P3)
[ ] Notificar a management
[ ] Aislar sistemas afectados
[ ] Preservar evidencia en memoria
[ ] Detener propagación
[ ] Identificar paciente cero
[ ] Documentar mensaje de rescate
[ ] Iniciar grabación de llamadas

## HORA 1-4: CONTENCIÓN Y ANÁLISIS
[ ] Crear imagen forense
[ ] Recolectar logs críticos
[ ] Identificar variante de ransomware
[ ] Mapear sistemas afectados
[ ] Evaluar backups disponibles
[ ] Buscar descifradores conocidos
[ ] Identificar vector de entrada
[ ] Preparar comunicación interna
[ ] Notificar aseguradora
[ ] Documentar timeline

## HORA 4-24: INVESTIGACIÓN Y DECISIÓN
[ ] Análisis forense completo
[ ] Determinar alcance total
[ ] Evaluar opciones de recuperación
[ ] Decisión sobre pago (si aplica)
[ ] Notificar autoridades (INCIBE/Policía)
[ ] Preparar plan de recuperación
[ ] Comunicación con stakeholders
[ ] Análisis de malware
[ ] Búsqueda de IOCs
[ ] Preparar evidencia para autoridades

## DÍA 1-3: RECUPERACIÓN
[ ] Ejecutar plan de recuperación
[ ] Limpieza de sistemas
[ ] Restauración desde backups
[ ] Validación de integridad
[ ] Monitoreo intensivo
[ ] Notificación AEPD (si aplica)
[ ] Comunicación externa (si necesaria)
[ ] Actualización de stakeholders
[ ] Parcheo de vulnerabilidades
[ ] Hardening de sistemas

## DÍA 3-7: ESTABILIZACIÓN
[ ] Verificación de erradicación completa
[ ] Restauración de operaciones normales
[ ] Monitoreo continuo
[ ] Análisis de logs post-incidente
[ ] Actualización de IOCs
[ ] Compartir inteligencia
[ ] Documentación final
[ ] Cálculo de impacto
[ ] Preparación informe final
[ ] Reunión post-mortem

## SEMANA 2+: POST-INCIDENTE
[ ] Informe final completo
[ ] Lecciones aprendidas
[ ] Actualización de procedimientos
[ ] Mejoras de seguridad
[ ] Formación adicional
[ ] Simulacros de respuesta
[ ] Revisión de seguros
[ ] Auditoría de seguridad
[ ] Implementación de mejoras
[ ] Seguimiento con autoridades
```

### **14.2 Contactos de Emergencia**

```yaml
CONTACTOS CRÍTICOS 24/7:
========================

Internos:
  CISO: 
    - Móvil: +34 XXX XXX XXX
    - Email: ciso@empresa.com
  CTO:
    - Móvil: +34 XXX XXX XXX
  Legal:
    - Móvil: +34 XXX XXX XXX
  DPO:
    - Móvil: +34 XXX XXX XXX

Autoridades:
  INCIBE-CERT:
    - Teléfono: 017
    - Email: incidencias@incibe-cert.es
  Policía Nacional:
    - Urgencias: 091
    - Delitos Telemáticos: delitos.telematicos@policia.es
  Guardia Civil:
    - Urgencias: 062
    - GDT: gdt@guardiacivil.org
  AEPD:
    - Web: https://sedeagpd.gob.es/
    - Teléfono: 900 293 183

Externos:
  Seguro Ciber:
    - 24/7: +34 XXX XXX XXX
    - Siniestros: siniestros@aseguradora.com
  Proveedor Backup:
    - Soporte: +34 XXX XXX XXX
  Negociador Ransomware:
    - Empresa: [Nombre]
    - Contacto: +XX XXX XXX XXX

Herramientas Online:
  ID Ransomware: https://id-ransomware.malwarehunterteam.com/
  No More Ransom: https://www.nomoreransom.org/
  Have I Been Pwned: https://haveibeenpwned.com/
  VirusTotal: https://www.virustotal.com/
```

### **14.3 Formularios y Plantillas Adicionales**

**A. Formulario de Entrevista a Usuario Afectado:**
```markdown
ENTREVISTA USUARIO AFECTADO
============================
Fecha: ___________  Hora: ___________
Entrevistador: ___________________
Entrevistado: ____________________

1. ¿Cuándo notó el problema por primera vez?
2. ¿Qué estaba haciendo justo antes?
3. ¿Abrió algún email o archivo inusual?
4. ¿Visitó algún sitio web nuevo?
5. ¿Instaló software recientemente?
6. ¿Compartió credenciales con alguien?
7. ¿Notó comportamiento extraño días antes?
8. ¿Recibió llamadas sospechosas?
9. ¿Conectó dispositivos USB?
10. ¿Trabajó desde ubicación diferente?

Notas adicionales:
_________________________________
```

**B. Registro de Decisiones Críticas:**
```markdown
REGISTRO DE DECISIÓN
====================
Fecha/Hora: _____________
Decisión: _______________
Tomada por: _____________
Consultados: ____________
Justificación: __________
Riesgos asumidos: _______
Alternativas consideradas: ___
Resultado esperado: _____
Seguimiento: ____________
```

---

## **15. MÉTRICAS Y KPIs**

### **15.1 Métricas de Respuesta**

```python
# KPIs críticos para medir efectividad
metricas_respuesta = {
    "Tiempo de Detección (MTTD)": {
        "objetivo": "< 1 hora",
        "medición": "Desde infección hasta detección",
        "actual": ""
    },
    "Tiempo de Respuesta (MTTR)": {
        "objetivo": "< 4 horas",
        "medición": "Desde detección hasta contención",
        "actual": ""
    },
    "Tiempo de Recuperación (RTO)": {
        "objetivo": "< 24 horas para sistemas críticos",
        "medición": "Desde incidente hasta operación normal",
        "actual": ""
    },
    "Pérdida de Datos (RPO)": {
        "objetivo": "< 4 horas de datos perdidos",
        "medición": "Edad del último backup utilizable",
        "actual": ""
    },
    "Tasa de Recuperación": {
        "objetivo": "> 95%",
        "medición": "% de datos recuperados exitosamente",
        "actual": ""
    },
    "Costo del Incidente": {
        "componentes": [
            "Horas de inactividad",
            "Recursos de respuesta",
            "Pérdida de productividad",
            "Daño reputacional",
            "Multas/sanciones"
        ],
        "total": ""
    }
}
```

### **15.2 Dashboard de Seguimiento**

```sql
-- Query para dashboard de monitoreo post-incidente
SELECT 
    DATE(timestamp) as fecha,
    COUNT(CASE WHEN event_type = 'suspicious_process' THEN 1 END) as procesos_sospechosos,
    COUNT(CASE WHEN event_type = 'network_anomaly' THEN 1 END) as anomalias_red,
    COUNT(CASE WHEN event_type = 'file_encryption' THEN 1 END) as intentos_cifrado,
    COUNT(CASE WHEN event_type = 'failed_login' THEN 1 END) as login_fallidos,
    AVG(response_time) as tiempo_respuesta_promedio
FROM security_events
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(timestamp)
ORDER BY fecha DESC;
```

---

## **CONCLUSIÓN**

Este protocolo integral proporciona un marco completo y detallado para la respuesta efectiva ante incidentes de ransomware. Es crítico:

1. **Mantener el protocolo actualizado** con nuevas variantes y técnicas
2. **Realizar simulacros regulares** para mantener al equipo preparado
3. **Preservar siempre evidencia** incluso después de resolver el incidente
4. **Documentar exhaustivamente** cada caso para mejorar continuamente
5. **Colaborar con la comunidad** compartiendo IOCs y experiencias

**Recuerde**: La preparación y la respuesta rápida son las claves para minimizar el impacto de un ataque de ransomware. Este protocolo debe ser revisado y actualizado trimestralmente basándose en las lecciones aprendidas y la evolución del panorama de amenazas.

---

**Última actualización**: [Fecha]  
**Versión**: 2.0  
**Clasificación**: USO INTERNO - CONFIDENCIAL  
**Próxima revisión**: [Fecha + 3 meses]