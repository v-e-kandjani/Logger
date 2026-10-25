//go:build windows_installer

package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed logger-agent.exe
var embeddedAgentBinary []byte

const (
	defaultInstallDir = `C:\Program Files\LOGGER Agent`
	serviceName        = "LoggerAgent"
	serviceDisplayName = "Valtrivo LogSeal Endpoint Agent"
	serviceDescription = "Valtrivo LogSeal native endpoint security and continuous telemetry collection daemon."
)

var version = "v0.1.12"

type Config struct {
	ServerURL            string `json:"server_url"`
	EnrollmentToken      string `json:"enrollment_token"`
	InsecureTLS          bool   `json:"insecure_tls"`
	LogLevel             string `json:"log_level"`
	DataDir              string `json:"data_dir"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	IdentityFile         string `json:"identity_file"`
}

func main() {
	serverURL := flag.String("server", "", "LogSeal Server URL (e.g. http://10.34.33.40:8080)")
	enrollToken := flag.String("token", "", "Enrollment token (lp_ea_...)")
	installDir := flag.String("dir", defaultInstallDir, "Target installation directory")
	insecure := flag.Bool("insecure", false, "Allow insecure TLS certificates")
	silent := flag.Bool("silent", false, "Unattended silent installation")
	flag.BoolVar(silent, "q", false, "Unattended silent installation (shorthand)")
	uninstall := flag.Bool("uninstall", false, "Uninstall Logger Agent service and remove files")
	flag.BoolVar(uninstall, "u", false, "Uninstall Logger Agent service (shorthand)")
	showVersion := flag.Bool("version", false, "Show installer version")
	flag.BoolVar(showVersion, "v", false, "Show installer version (shorthand)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Valtrivo LogSeal Windows Agent Installer %s\n", version)
		return
	}

	if *uninstall {
		runUninstall(*installDir, *silent)
		return
	}

	runInstall(*serverURL, *enrollToken, *installDir, *insecure, *silent)
}

func printBanner() {
	fmt.Println("==================================================================")
	fmt.Println("      VALTRIVO LOGSEAL - WINDOWS ENDPOINT AGENT INSTALLER         ")
	fmt.Printf("                         Version %s\n", version)
	fmt.Println("==================================================================")
	fmt.Println()
}

func runInstall(serverURL, token, targetDir string, insecure, silent bool) {
	if !silent {
		printBanner()
	}

	// Interactive prompts if missing in non-silent mode
	if !silent {
		if serverURL == "" {
			fmt.Print("Enter LogSeal Server URL [http://localhost:8080]: ")
			var input string
			fmt.Scanln(&input)
			input = strings.TrimSpace(input)
			if input == "" {
				serverURL = "http://localhost:8080"
			} else {
				serverURL = input
			}
		}

		if token == "" {
			fmt.Print("Enter Enrollment Token (lp_ea_...): ")
			fmt.Scanln(&token)
			token = strings.TrimSpace(token)
		}
	}

	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	if token == "" {
		if !silent {
			fmt.Println("[WARNING] No enrollment token provided. Agent will wait for manual configuration.")
		}
		token = "<TOKEN>"
	}

	logMsg(silent, "[*] Installation Directory : %s", targetDir)
	logMsg(silent, "[*] LogSeal Server URL      : %s", serverURL)

	dataDir := filepath.Join(targetDir, "data")
	binaryPath := filepath.Join(targetDir, "logger-agent.exe")
	uninstallerPath := filepath.Join(targetDir, "uninstall.exe")
	configPath := filepath.Join(targetDir, "config.json")
	identityPath := filepath.Join(targetDir, "identity.json")

	// 1. Create directories
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fatalMsg(silent, "Failed to create installation directory: %v", err)
	}

	// 2. Stop running service and terminate any running agent processes
	logMsg(silent, "[*] Stopping existing Logger Agent service and active processes...")
	_ = exec.Command("net.exe", "stop", serviceName).Run()
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	_ = exec.Command("taskkill.exe", "/F", "/IM", "logger-agent.exe", "/T").Run()

	// Wait up to 5 seconds for file locks to be completely released
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			break
		}
		if f, err := os.OpenFile(binaryPath, os.O_WRONLY, 0755); err == nil {
			f.Close()
			break
		}
		_ = exec.Command("taskkill.exe", "/F", "/IM", "logger-agent.exe", "/T").Run()
	}

	// Clean up any stale backup files
	_ = os.Remove(binaryPath + ".old")
	_ = os.Remove(binaryPath + ".new")

	logMsg(silent, "[*] Extracting agent binary...")
	if len(embeddedAgentBinary) == 0 {
		fatalMsg(silent, "Embedded agent binary is empty. Please ensure logger-agent.exe was embedded during build.")
	}

	// Write agent binary, with fallback rename if still locked
	if err := os.WriteFile(binaryPath, embeddedAgentBinary, 0755); err != nil {
		oldBackup := fmt.Sprintf("%s.old.%d", binaryPath, time.Now().Unix())
		_ = os.Rename(binaryPath, oldBackup)
		if writeErr := os.WriteFile(binaryPath, embeddedAgentBinary, 0755); writeErr != nil {
			fatalMsg(silent, "Failed to write agent binary to %s: %v", binaryPath, writeErr)
		}
	}

	// Also copy installer itself as uninstaller
	if selfPath, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(selfPath); err == nil {
			_ = os.WriteFile(uninstallerPath, data, 0755)
		}
	}

	// 3. Write config.json
	logMsg(silent, "[*] Writing configuration...")
	cfg := Config{
		ServerURL:            serverURL,
		EnrollmentToken:      token,
		InsecureTLS:          insecure,
		LogLevel:             "info",
		DataDir:              dataDir,
		HeartbeatIntervalSec: 30,
		IdentityFile:         identityPath,
	}

	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fatalMsg(silent, "Failed to generate config JSON: %v", err)
	}

	if err := os.WriteFile(configPath, cfgBytes, 0644); err != nil {
		fatalMsg(silent, "Failed to write config file to %s: %v", configPath, err)
	}

	// Write uninstall.bat helper
	uninstallBatPath := filepath.Join(targetDir, "uninstall.bat")
	uninstallBatContent := `@echo off
echo ==================================================================
echo       VALTRIVO LOGSEAL - WINDOWS AGENT UNINSTALLER
echo ==================================================================
echo.
echo [*] Stopping and removing LoggerAgent Windows Service...
net stop LoggerAgent >nul 2>&1
sc.exe stop LoggerAgent >nul 2>&1
taskkill.exe /F /IM logger-agent.exe /T >nul 2>&1
sc.exe delete LoggerAgent >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\LoggerAgent" /f >nul 2>&1
echo [✓] Windows Service and Registry entries successfully removed.
echo [*] Removing application files...
start /b "" cmd /c "ping -n 3 127.0.0.1 >nul & rmdir /s /q \"%~dp0\""
echo [✓] Valtrivo LogSeal Agent has been completely uninstalled.
echo.
pause
`
	_ = os.WriteFile(uninstallBatPath, []byte(uninstallBatContent), 0755)

	// 4. Register Windows Service
	logMsg(silent, "[*] Registering Windows Service '%s'...", serviceName)
	// Stop and remove previous service instance if exists
	exec.Command("cmd.exe", "/c", fmt.Sprintf("sc.exe stop %s >nul 2>&1 & sc.exe delete %s >nul 2>&1", serviceName, serviceName)).Run()
	time.Sleep(500 * time.Millisecond)

	// Create service using native PowerShell New-Service (immune to sc.exe escaping quirks)
	psCmd := fmt.Sprintf(`New-Service -Name "%s" -BinaryPathName '"%s"' -DisplayName "%s" -StartupType Automatic -Description "%s"`,
		serviceName, binaryPath, serviceDisplayName, serviceDescription)
	ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
	if out, err := ps.CombinedOutput(); err != nil {
		// Fallback to cmd.exe with verbatim sc.exe quoting
		fallbackCmd := fmt.Sprintf(`sc.exe create %s binPath= "\"%s\"" start= auto DisplayName= "%s"`, serviceName, binaryPath, serviceDisplayName)
		cmd := exec.Command("cmd.exe", "/c", fallbackCmd)
		if fbOut, fbErr := cmd.CombinedOutput(); fbErr != nil {
			logMsg(silent, "[!] Warning creating service: %v (%s), fallback: %v (%s)", err, string(out), fbErr, string(fbOut))
		}
		exec.Command("cmd.exe", "/c", fmt.Sprintf(`sc.exe description %s "%s"`, serviceName, serviceDescription)).Run()
	}

	// Configure failure recovery
	exec.Command("cmd.exe", "/c", fmt.Sprintf("sc.exe failure %s reset= 86400 actions= restart/5000/restart/10000/restart/30000", serviceName)).Run()

	// 5. Register in Windows Add/Remove Programs (Registry)
	regBase := `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\` + serviceName
	exec.Command("reg.exe", "add", regBase, "/v", "DisplayName", "/t", "REG_SZ", "/d", serviceDisplayName, "/f").Run()
	exec.Command("reg.exe", "add", regBase, "/v", "DisplayVersion", "/t", "REG_SZ", "/d", version, "/f").Run()
	exec.Command("reg.exe", "add", regBase, "/v", "Publisher", "/t", "REG_SZ", "/d", "Valtrivo", "/f").Run()
	exec.Command("reg.exe", "add", regBase, "/v", "InstallLocation", "/t", "REG_SZ", "/d", targetDir, "/f").Run()
	exec.Command("reg.exe", "add", regBase, "/v", "UninstallString", "/t", "REG_SZ", "/d", fmt.Sprintf(`"%s" -uninstall`, uninstallerPath), "/f").Run()

	// 6. Start service
	logMsg(silent, "[*] Starting %s service...", serviceName)
	startCmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("Start-Service -Name '%s'", serviceName))
	if out, err := startCmd.CombinedOutput(); err != nil {
		netCmd := exec.Command("cmd.exe", "/c", fmt.Sprintf("net start %s", serviceName))
		if nOut, nErr := netCmd.CombinedOutput(); nErr != nil {
			logMsg(silent, "[!] Notice starting service: %v (%s). Checking status...", err, string(out)+string(nOut))
		}
	}

	time.Sleep(1 * time.Second)

	if !silent {
		fmt.Println()
		fmt.Println("==================================================================")
		fmt.Println(" [✓] VALTRIVO LOGSEAL AGENT SUCCESSFULLY INSTALLED!               ")
		fmt.Println("==================================================================")
		fmt.Printf(" Service Name     : %s\n", serviceName)
		fmt.Printf(" Binary Location  : %s\n", binaryPath)
		fmt.Printf(" Configuration    : %s\n", configPath)
		fmt.Printf(" Data Directory   : %s\n", dataDir)
		fmt.Printf(" Uninstaller      : %s\n", uninstallBatPath)
		fmt.Println(" Verify Command   : Get-Service LoggerAgent")
		fmt.Println("==================================================================")
		fmt.Println()
		fmt.Println("Press Enter to finish...")
		var wait string
		fmt.Scanln(&wait)
	}
}

func runUninstall(targetDir string, silent bool) {
	if !silent {
		printBanner()
		fmt.Println("[*] Stopping and removing LoggerAgent Windows Service...")
	}

	_ = exec.Command("net.exe", "stop", serviceName).Run()
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	_ = exec.Command("taskkill.exe", "/F", "/IM", "logger-agent.exe", "/T").Run()
	time.Sleep(1 * time.Second)
	_ = exec.Command("sc.exe", "delete", serviceName).Run()

	// Clean registry
	regBase := `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\` + serviceName
	exec.Command("reg.exe", "delete", regBase, "/f").Run()

	logMsg(silent, "[✓] Service unregistered and removed from Windows.")

	// Schedule directory cleanup via detached cmd process so running executable isn't blocked
	if targetDir != "" {
		cleanupCmd := fmt.Sprintf(`ping -n 3 127.0.0.1 >nul & rmdir /s /q "%s"`, targetDir)
		_ = exec.Command("cmd.exe", "/c", cleanupCmd).Start()
	}

	if !silent {
		fmt.Println("[✓] Uninstallation completed successfully. All files scheduled for removal.")
		fmt.Println("Press Enter to exit...")
		var wait string
		fmt.Scanln(&wait)
	}
}

func logMsg(silent bool, format string, a ...interface{}) {
	if !silent {
		fmt.Printf(format+"\n", a...)
	}
}

func fatalMsg(silent bool, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	if !silent {
		fmt.Printf("\n[ERROR] %s\n", msg)
		fmt.Println("Press Enter to exit...")
		var wait string
		fmt.Scanln(&wait)
	}
	log.Fatal(msg)
}
