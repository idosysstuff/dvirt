package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type VM struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Memory        int      `json:"memory"`
	CPUs          int      `json:"cpus"`
	DiskSize      int      `json:"disk_size"`
	Status        string   `json:"status"`
	Arch          string   `json:"arch"`
	MAC           string   `json:"mac"`
	Bridge        string   `json:"bridge"`
	VLAN          int      `json:"vlan"`
	Pid           int      `json:"pid,omitempty"`
	Command       []string `json:"-"`
	ISO           string   `json:"iso,omitempty"`
	VNCPort       int      `json:"vnc_port"`
	QMPSocketPath string   `json:"-"` // Putanja do QMP socketa za kontrolu
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Type      string `json:"type"` // "info", "error", "success"
}

type VMManager struct {
	VMs       map[string]*VM
	VMsDir    string
	ImagesDir string
	Logs      []LogEntry
	LogFile   *os.File
	mutex     sync.RWMutex
	logMutex  sync.RWMutex
}

type NetworkInterface struct {
	Name     string   `json:"name"`
	MAC      string   `json:"mac"`
	IPs      []string `json:"ips"`
	IsUp     bool     `json:"is_up"`
	IsBridge bool     `json:"is_bridge"`
}

func NewVMManager(vmsDir, imagesDir string) *VMManager {
	err := os.MkdirAll(vmsDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create VMs directory: %v", err)
	}

	err = os.MkdirAll(imagesDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create images directory: %v", err)
	}

	// Kreiranje ISO direktorijuma ako ne postoji
	isoDir := filepath.Join(imagesDir, "iso")
	err = os.MkdirAll(isoDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create ISO directory: %v", err)
	}

	// Kreiranje direktorijuma za logove
	logsDir := "./logs"
	err = os.MkdirAll(logsDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	// Kreiranje log fajla sa današnjim datumom
	currentDate := time.Now().Format("2006-01-02")
	logFilePath := filepath.Join(logsDir, fmt.Sprintf("logs-%s.txt", currentDate))
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to create log file: %v", err)
	}

	return &VMManager{
		VMs:       make(map[string]*VM),
		VMsDir:    vmsDir,
		ImagesDir: imagesDir,
		Logs:      make([]LogEntry, 0),
		LogFile:   logFile,
		mutex:     sync.RWMutex{},
		logMutex:  sync.RWMutex{},
	}
}

func (mgr *VMManager) AddLog(message string, logType string) {
	mgr.logMutex.Lock()
	defer mgr.logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	entry := LogEntry{
		Timestamp: timestamp,
		Message:   message,
		Type:      logType,
	}

	mgr.Logs = append(mgr.Logs, entry)

	// Keep only last 100 logs in memory
	if len(mgr.Logs) > 100 {
		mgr.Logs = mgr.Logs[len(mgr.Logs)-100:]
	}

	// Also log to console
	log.Printf("[%s] %s", logType, message)

	// Log to file
	if mgr.LogFile != nil {
		logLine := fmt.Sprintf("[%s] [%s] %s\n", timestamp, logType, message)
		if _, err := mgr.LogFile.WriteString(logLine); err != nil {
			log.Printf("Failed to write to log file: %v", err)
		}
	}

	// Ako je ponoć, kreiraj novi log fajl za novi dan
	currentDate := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("logs-%s.txt", currentDate)
	if mgr.LogFile != nil && !strings.HasSuffix(mgr.LogFile.Name(), logFileName) {
		// Zatvaramo postojeći log fajl
		mgr.LogFile.Close()

		// Otvaramo novi log fajl za današnji dan
		logsDir := "./logs"
		logFilePath := filepath.Join(logsDir, logFileName)
		newLogFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to create new log file: %v", err)
		} else {
			mgr.LogFile = newLogFile
			log.Printf("Switched to new log file: %s", logFilePath)
		}
	}
}

func generateMAC() string {
	mac := fmt.Sprintf("52:54:00:%02x:%02x:%02x",
		100+os.Getpid()%100,
		100+os.Getpid()/100%100,
		100+os.Getpid()/10000%100)
	return mac
}

func getNetworkInterfaces() []NetworkInterface {
	result := []NetworkInterface{}

	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range interfaces {
		// Preskačemo loopback
		if iface.Name == "lo" {
			continue
		}

		netIface := NetworkInterface{
			Name:     iface.Name,
			MAC:      iface.HardwareAddr.String(),
			IsUp:     (iface.Flags & net.FlagUp) != 0,
			IsBridge: strings.HasPrefix(iface.Name, "br") || strings.HasPrefix(iface.Name, "virbr"),
		}

		addresses, err := iface.Addrs()
		if err == nil {
			for _, addr := range addresses {
				netIface.IPs = append(netIface.IPs, addr.String())
			}
		}

		result = append(result, netIface)
	}

	return result
}

func detectDefaultInterface() string {
	interfaces := getNetworkInterfaces()

	// Prvo tražimo bridge interfejse
	for _, iface := range interfaces {
		if iface.IsUp && iface.IsBridge {
			return iface.Name
		}
	}

	// Zatim tražimo bilo koji interfejs koji je UP
	for _, iface := range interfaces {
		if iface.IsUp && iface.Name != "lo" {
			return iface.Name
		}
	}

	return "virbr0"
}

// Pomoćna funkcija za proveru da li niz sadrži element
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (mgr *VMManager) CreateVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var vm VM
	body, err := io.ReadAll(r.Body)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to read request body: %v", err), "error")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &vm)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to parse JSON: %v", err), "error")
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	if vm.Name == "" {
		mgr.AddLog("VM creation failed: name is required", "error")
		http.Error(w, "VM name is required", http.StatusBadRequest)
		return
	}

	vm.ID = fmt.Sprintf("vm-%s", vm.Name)
	vm.Status = "stopped"
	vm.Arch = "x86-64-v2-AES"
	vm.MAC = generateMAC()

	// Koristi prosleđeni interfejs ili podrazumevani
	if vm.Bridge == "" {
		vm.Bridge = detectDefaultInterface()
	}

	if vm.Memory <= 0 {
		vm.Memory = 2048
	}
	if vm.CPUs <= 0 {
		vm.CPUs = 2
	}
	if vm.DiskSize <= 0 {
		vm.DiskSize = 20
	}

	// Provera ISO fajla ako je naveden
	if vm.ISO != "" {
		if _, err := os.Stat(vm.ISO); os.IsNotExist(err) {
			mgr.AddLog(fmt.Sprintf("ISO fajl '%s' ne postoji", vm.ISO), "error")
			http.Error(w, fmt.Sprintf("ISO file does not exist: %s", vm.ISO), http.StatusBadRequest)
			return
		}
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	if _, exists := mgr.VMs[vm.ID]; exists {
		mgr.AddLog(fmt.Sprintf("VM '%s' already exists", vm.Name), "error")
		http.Error(w, "VM with this name already exists", http.StatusConflict)
		return
	}

	// Dodeli VNC port
	vm.VNCPort = 5900 + len(mgr.VMs)

	diskPath := filepath.Join(mgr.VMsDir, fmt.Sprintf("%s.qcow2", vm.ID))
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", diskPath, fmt.Sprintf("%dG", vm.DiskSize))
	err = cmd.Run()
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to create disk image for '%s': %v", vm.Name, err), "error")
		http.Error(w, fmt.Sprintf("Failed to create disk image: %v", err), http.StatusInternalServerError)
		return
	}

	mgr.VMs[vm.ID] = &vm
	mgr.AddLog(fmt.Sprintf("VM '%s' created successfully", vm.Name), "success")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(vm)
}

func (mgr *VMManager) StartVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := r.URL.Query().Get("id")
	if vmID == "" {
		mgr.AddLog("Start VM failed: VM ID is required", "error")
		http.Error(w, "VM ID is required", http.StatusBadRequest)
		return
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	vm, exists := mgr.VMs[vmID]
	if !exists {
		mgr.AddLog(fmt.Sprintf("Start VM failed: VM '%s' not found", vmID), "error")
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	if vm.Status == "running" {
		mgr.AddLog(fmt.Sprintf("VM '%s' is already running", vm.Name), "info")
		http.Error(w, "VM is already running", http.StatusConflict)
		return
	}

	diskPath := filepath.Join(mgr.VMsDir, fmt.Sprintf("%s.qcow2", vm.ID))

	// Kreiramo QMP socket za komunikaciju
	socketsDir := filepath.Join(mgr.VMsDir, "sockets")
	err := os.MkdirAll(socketsDir, 0755)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to create sockets directory: %v", err), "error")
		http.Error(w, fmt.Sprintf("Failed to create sockets directory: %v", err), http.StatusInternalServerError)
		return
	}

	vm.QMPSocketPath = filepath.Join(socketsDir, fmt.Sprintf("%s.sock", vm.ID))

	// Automatski briši socket ako već postoji
	if _, err := os.Stat(vm.QMPSocketPath); err == nil {
		os.Remove(vm.QMPSocketPath)
	}

	// Osnovni argumenti za QEMU
	args := []string{
		"-name", vm.Name,
		"-machine", "type=q35,accel=kvm",
		"-cpu", vm.Arch,
		"-m", fmt.Sprintf("%d", vm.Memory),
		"-smp", fmt.Sprintf("cores=%d", vm.CPUs),
		"-drive", fmt.Sprintf("file=%s,format=qcow2", diskPath),
	}

	// Dodaj ISO ako je naveden
	if vm.ISO != "" {
		if _, err := os.Stat(vm.ISO); os.IsNotExist(err) {
			mgr.AddLog(fmt.Sprintf("ISO fajl '%s' ne postoji, nastavljam bez njega", vm.ISO), "warning")
		} else {
			args = append(args, "-cdrom", vm.ISO)
			args = append(args, "-boot", "d")
			mgr.AddLog(fmt.Sprintf("Dodajem ISO: %s", vm.ISO), "info")
		}
	} else {
		args = append(args, "-boot", "c")
	}

	// Mrežna konfiguracija
	args = append(args,
		"-netdev", fmt.Sprintf("bridge,id=net0,br=%s", vm.Bridge),
		"-device", fmt.Sprintf("virtio-net-pci,netdev=net0,mac=%s", vm.MAC),
	)

	// VLAN podešavanja ako su navedena
	if vm.VLAN > 0 {
		args = append(args, "-netdev", fmt.Sprintf("vlan=%d", vm.VLAN))
	}

	// VNC konfiguracija
	// Port bez prefiksa - npr. 5900 -> 0, 5901 -> 1
	vncDisplay := vm.VNCPort - 5900
	args = append(args, "-vnc", fmt.Sprintf(":%d", vncDisplay))

	// QMP socket za komunikaciju
	args = append(args, "-qmp", fmt.Sprintf("unix:%s,server,nowait", vm.QMPSocketPath))

	// Pozadinski režim
	args = append(args, "-daemonize")

	vm.Command = append([]string{"qemu-system-x86_64"}, args...)
	cmd := exec.Command(vm.Command[0], vm.Command[1:]...)
	err = cmd.Start()
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to start VM '%s': %v", vm.Name, err), "error")
		http.Error(w, fmt.Sprintf("Failed to start VM: %v", err), http.StatusInternalServerError)
		return
	}

	vm.Pid = cmd.Process.Pid
	vm.Status = "running"
	mgr.AddLog(fmt.Sprintf("VM '%s' started successfully. VNC pristup na portu %d, QMP socket: %s",
		vm.Name, vm.VNCPort, vm.QMPSocketPath), "success")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vm)
}

func (mgr *VMManager) StopVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := r.URL.Query().Get("id")
	if vmID == "" {
		mgr.AddLog("Stop VM failed: VM ID is required", "error")
		http.Error(w, "VM ID is required", http.StatusBadRequest)
		return
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	vm, exists := mgr.VMs[vmID]
	if !exists {
		mgr.AddLog(fmt.Sprintf("Stop VM failed: VM '%s' not found", vmID), "error")
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	if vm.Status != "running" {
		mgr.AddLog(fmt.Sprintf("VM '%s' is not running", vm.Name), "info")
		http.Error(w, "VM is not running", http.StatusConflict)
		return
	}

	// Pokušaj da gracefully zaustavimo VM slanjem SIGTERM signala
	process, err := os.FindProcess(vm.Pid)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to find VM process '%s' (PID %d): %v", vm.Name, vm.Pid, err), "error")
		http.Error(w, fmt.Sprintf("Failed to find VM process: %v", err), http.StatusInternalServerError)
		return
	}

	// Slanje SIGTERM signala za graceful shutdown
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to send SIGTERM to VM '%s': %v", vm.Name, err), "error")

		// Ako SIGTERM ne radi, pokušaj direktno kill kao fallback
		killErr := process.Kill()
		if killErr != nil {
			mgr.AddLog(fmt.Sprintf("Also failed to kill VM '%s': %v", vm.Name, killErr), "error")
			http.Error(w, fmt.Sprintf("Failed to stop VM: %v", err), http.StatusInternalServerError)
			return
		}
		mgr.AddLog(fmt.Sprintf("VM '%s' forcefully killed after failed graceful stop", vm.Name), "warning")
	} else {
		mgr.AddLog(fmt.Sprintf("Sent SIGTERM to VM '%s'", vm.Name), "info")
	}

	// Sačekaj kratko da se VM zaustavi
	time.Sleep(1 * time.Second)

	vm.Status = "stopped"
	vm.Pid = 0
	mgr.AddLog(fmt.Sprintf("VM '%s' stopped successfully", vm.Name), "success")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vm)
}

func (mgr *VMManager) KillVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := r.URL.Query().Get("id")
	if vmID == "" {
		mgr.AddLog("Kill VM failed: VM ID is required", "error")
		http.Error(w, "VM ID is required", http.StatusBadRequest)
		return
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	vm, exists := mgr.VMs[vmID]
	if !exists {
		mgr.AddLog(fmt.Sprintf("Kill VM failed: VM '%s' not found", vmID), "error")
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	if vm.Status != "running" {
		mgr.AddLog(fmt.Sprintf("VM '%s' is not running", vm.Name), "info")
		http.Error(w, "VM is not running", http.StatusConflict)
		return
	}

	process, err := os.FindProcess(vm.Pid)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to find VM process for '%s': %v", vm.Name, err), "error")
		http.Error(w, fmt.Sprintf("Failed to find VM process: %v", err), http.StatusInternalServerError)
		return
	}

	err = process.Kill()
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to kill VM '%s': %v", vm.Name, err), "error")
		http.Error(w, fmt.Sprintf("Failed to kill VM process: %v", err), http.StatusInternalServerError)
		return
	}

	vm.Status = "stopped"
	vm.Pid = 0
	mgr.AddLog(fmt.Sprintf("VM '%s' killed successfully with SIGKILL", vm.Name), "success")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vm)
}

func (mgr *VMManager) RemoveVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := r.URL.Query().Get("id")
	if vmID == "" {
		mgr.AddLog("Remove VM failed: VM ID is required", "error")
		http.Error(w, "VM ID is required", http.StatusBadRequest)
		return
	}

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	vm, exists := mgr.VMs[vmID]
	if !exists {
		mgr.AddLog(fmt.Sprintf("Remove VM failed: VM '%s' not found", vmID), "error")
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	// Ako je VM pokrenuta, prvo je zaustavimo
	if vm.Status == "running" {
		// Ubij process
		process, err := os.FindProcess(vm.Pid)
		if err == nil {
			process.Kill()
		}
	}

	// Pokušaj da nađemo i uklonimo disk fajl
	diskPath := filepath.Join(mgr.VMsDir, fmt.Sprintf("%s.qcow2", vm.ID))
	if _, err := os.Stat(diskPath); err == nil {
		os.Remove(diskPath)
	}

	// Pokušaj da nađemo i uklonimo QMP socket
	if vm.QMPSocketPath != "" {
		if _, err := os.Stat(vm.QMPSocketPath); err == nil {
			os.Remove(vm.QMPSocketPath)
		}
	}

	delete(mgr.VMs, vm.ID)
	mgr.AddLog(fmt.Sprintf("VM '%s' removed successfully", vm.Name), "success")

	w.WriteHeader(http.StatusNoContent)
}

func (mgr *VMManager) ListVMs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	vms := make([]*VM, 0, len(mgr.VMs))
	for _, vm := range mgr.VMs {
		vms = append(vms, vm)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vms)
}

func (mgr *VMManager) GetVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := r.URL.Query().Get("id")
	if vmID == "" {
		mgr.AddLog("Get VM failed: VM ID is required", "error")
		http.Error(w, "VM ID is required", http.StatusBadRequest)
		return
	}

	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	vm, exists := mgr.VMs[vmID]
	if !exists {
		mgr.AddLog(fmt.Sprintf("Get VM failed: VM '%s' not found", vmID), "error")
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vm)
}

func (mgr *VMManager) GetLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mgr.logMutex.RLock()
	defer mgr.logMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mgr.Logs)
}

// Endpoint za dobijanje statusa VM-a
func (mgr *VMManager) GetVMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := r.URL.Query().Get("id")
	if vmID == "" {
		mgr.AddLog("Get VM status failed: VM ID is required", "error")
		http.Error(w, "VM ID is required", http.StatusBadRequest)
		return
	}

	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	vm, exists := mgr.VMs[vmID]
	if !exists {
		mgr.AddLog(fmt.Sprintf("Get VM status failed: VM '%s' not found", vmID), "error")
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	// Jednostavan odgovor sa statusom VM-a
	response := map[string]interface{}{
		"id":       vm.ID,
		"name":     vm.Name,
		"status":   vm.Status,
		"pid":      vm.Pid,
		"vnc_port": vm.VNCPort,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Endpoint za dobijanje mrežnih interfejsa
func (mgr *VMManager) GetNetworkInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	interfaces := getNetworkInterfaces()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interfaces)
}

// Endpoint za listanje ISO fajlova
func (mgr *VMManager) ListISOFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	isoFiles := []map[string]string{}

	// Prvo proveri ISO direktorijum u vm-images
	isoDir := filepath.Join(mgr.ImagesDir, "iso")
	files, err := os.ReadDir(isoDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".iso") {
				isoPath := filepath.Join(isoDir, file.Name())
				isoFiles = append(isoFiles, map[string]string{
					"path":     isoPath,
					"name":     file.Name(),
					"location": "iso",
				})
			}
		}
	}

	// Zatim proveri direktorijum sa slikama
	files, err = os.ReadDir(mgr.ImagesDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".iso") {
				isoPath := filepath.Join(mgr.ImagesDir, file.Name())

				// Preskočimo ako već postoji u listi
				exists := false
				for _, iso := range isoFiles {
					if iso["path"] == isoPath {
						exists = true
						break
					}
				}

				if !exists {
					isoFiles = append(isoFiles, map[string]string{
						"path":     isoPath,
						"name":     file.Name(),
						"location": "images",
					})
				}
			}
		}
	}

	// Zatim proveri trenutni direktorijum
	currentDir, err := os.Getwd()
	if err == nil {
		files, err := os.ReadDir(currentDir)
		if err == nil {
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".iso") {
					isoPath := filepath.Join(currentDir, file.Name())

					// Preskočimo ako već postoji u listi
					exists := false
					for _, iso := range isoFiles {
						if iso["path"] == isoPath {
							exists = true
							break
						}
					}

					if !exists {
						isoFiles = append(isoFiles, map[string]string{
							"path":     isoPath,
							"name":     file.Name(),
							"location": "current",
						})
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(isoFiles)
}

// Endpoint za upload ISO datoteka
func (mgr *VMManager) UploadISO(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Maksimalna veličina fajla: 4GB
	err := r.ParseMultipartForm(4 << 30)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to parse multipart form: %v", err), "error")
		http.Error(w, fmt.Sprintf("Failed to parse multipart form: %v", err), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("isoFile")
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to get file: %v", err), "error")
		http.Error(w, fmt.Sprintf("Failed to get file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Provera da li je fajl ISO
	if !strings.HasSuffix(strings.ToLower(handler.Filename), ".iso") {
		mgr.AddLog("File is not an ISO image", "error")
		http.Error(w, "File must be an ISO image", http.StatusBadRequest)
		return
	}

	// Kreiranje ISO direktorijuma (za svaki slučaj)
	isoDir := filepath.Join(mgr.ImagesDir, "iso")
	err = os.MkdirAll(isoDir, 0755)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to create ISO directory: %v", err), "error")
		http.Error(w, fmt.Sprintf("Failed to create ISO directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Čuvanje fajla
	filePath := filepath.Join(isoDir, handler.Filename)
	dst, err := os.Create(filePath)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to create destination file: %v", err), "error")
		http.Error(w, fmt.Sprintf("Failed to create destination file: %v", err), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Kopiranje sadržaja
	_, err = io.Copy(dst, file)
	if err != nil {
		mgr.AddLog(fmt.Sprintf("Failed to copy file content: %v", err), "error")
		http.Error(w, fmt.Sprintf("Failed to copy file content: %v", err), http.StatusInternalServerError)
		return
	}

	mgr.AddLog(fmt.Sprintf("ISO file '%s' uploaded successfully", handler.Filename), "success")

	// Vraćanje putanje do ISO fajla
	response := map[string]string{
		"message":  "ISO file uploaded successfully",
		"path":     filePath,
		"filename": handler.Filename,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Zatvori sve resurse pri zatvaranju aplikacije
func (mgr *VMManager) Cleanup() {
	// Zatvaranje log datoteke
	if mgr.LogFile != nil {
		mgr.AddLog("Shutting down QEMU VM Manager", "info")
		mgr.LogFile.Close()
	}
}

func main() {
	// Kreiranje osnovnih direktorijuma
	vmManager := NewVMManager("./vm-storage", "./vm-images")
	vmManager.AddLog("QEMU VM Manager started", "info")

	// Registrujemo cleanup funkciju koja će se izvršiti pri zatvaranju aplikacije
	defer vmManager.Cleanup()

	// Provera da li index.html postoji
	if _, err := os.Stat("index.html"); os.IsNotExist(err) {
		log.Printf("UPOZORENJE: index.html fajl nije pronađen! Web interfejs neće biti dostupan.")
		vmManager.AddLog("index.html fajl nije pronađen. Koristite samo API interfejs.", "warning")
	} else {
		vmManager.AddLog("index.html fajl učitan", "info")
	}

	// Prikaži informacije o mrežnim interfejsima
	interfaces := getNetworkInterfaces()
	for _, iface := range interfaces {
		ipStr := strings.Join(iface.IPs, ", ")
		if ipStr == "" {
			ipStr = "nema IP-a"
		}
		log.Printf("Interfejs: %s, MAC: %s, IP: %s, %s",
			iface.Name,
			iface.MAC,
			ipStr,
			map[bool]string{true: "UP", false: "DOWN"}[iface.IsUp])
	}

	mux := http.NewServeMux()

	// API endpointi za VM
	mux.HandleFunc("/api/vms/create", vmManager.CreateVM)
	mux.HandleFunc("/api/vms/start", vmManager.StartVM)
	mux.HandleFunc("/api/vms/stop", vmManager.StopVM)
	mux.HandleFunc("/api/vms/kill", vmManager.KillVM)
	mux.HandleFunc("/api/vms/remove", vmManager.RemoveVM)
	mux.HandleFunc("/api/vms/list", vmManager.ListVMs)
	mux.HandleFunc("/api/vms/get", vmManager.GetVM)
	mux.HandleFunc("/api/vms/status", vmManager.GetVMStatus)
	mux.HandleFunc("/api/logs", vmManager.GetLogs)

	// Dodatni API endpointi
	mux.HandleFunc("/api/network-interfaces", vmManager.GetNetworkInterfaces)
	mux.HandleFunc("/api/iso-files", vmManager.ListISOFiles)
	mux.HandleFunc("/api/upload-iso", vmManager.UploadISO)

	// Serviranje statičkih fajlova (index.html)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "index.html")
	})

	port := "8080"
	fmt.Printf("Server sluša na portu :%s\n", port)
	log.Printf("Direktorijumi za VM-ove: ./vm-storage i ./vm-images\n")
	log.Printf("ISO direktorijum: ./vm-images/iso\n")
	log.Printf("Log direktorijum: ./logs\n")
	log.Printf("Otvori http://localhost:%s/ u browseru za pristup web interfejsu\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
