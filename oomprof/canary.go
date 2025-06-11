package oomprof

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func Canary(percent float64) {
	// Get total system memory and calculate percentage
	totalMemMB := getTotalMemoryMB()
	mb := int(float64(totalMemMB) * percent / 100.0)
	log.Printf("Canary: Total system memory: %d MB, allocating %d MB (%.1f%%)", totalMemMB, mb, percent)
	
	// Ballast allocation
	space := make([]byte, 1024*1024*mb)
	// touch every page
	for i := 0; i < len(space); i += 4096 {
		space[i] = 0xFF
	}
	log.Printf("Canary: initial allocation of %d MB complete", mb)
	
	// Keep allocating more memory to ensure we become the OOM target
	allocations := [][]byte{space}
	for {
		// Allocate another chunk of memory every second
		additionalMB := 100
		newSpace := make([]byte, 1024*1024*additionalMB)
		// Touch every page
		for i := 0; i < len(newSpace); i += 4096 {
			newSpace[i] = 0xFF
		}
		allocations = append(allocations, newSpace)
		totalMB := mb + len(allocations)*additionalMB - additionalMB
		log.Printf("Canary: total allocation now %d MB", totalMB)
		time.Sleep(1 * time.Second)
	}
}

func Rescore(pid int) error {
	// write 1000 to /proc/<pid>/oom_score_adj
	oomAdjPath := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
	log.Printf("writing oom_score_adj for canary process %d to %s", pid, oomAdjPath)
	if err := os.WriteFile(oomAdjPath, []byte("1000"), 0644); err != nil {
		return err
	}
	contents, err := os.ReadFile(oomAdjPath)
	if err != nil {
		return err
	}
	// parse contents into int
	scr, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil {
		return err
	}
	log.Printf("oom_score_adj for canary process %d is set to %d", pid, scr)
	return nil
}

func getTotalMemoryMB() int {
	// Read /proc/meminfo to get total memory
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		log.Printf("Error reading /proc/meminfo: %v, defaulting to 8000MB", err)
		return 8000
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// MemTotal is in KB
				totalKB, err := strconv.Atoi(fields[1])
				if err == nil {
					return totalKB / 1024 // Convert to MB
				}
			}
		}
	}
	log.Println("Could not find MemTotal in /proc/meminfo, defaulting to 8000MB")
	return 8000
}

func LaunchOOMCanary(canaryProc string) {
	go func() {
		for {
			// launch myself with --canary arg
			c := exec.Command(canaryProc, "--canary")
			if err := c.Start(); err != nil {
				log.Fatalf("error starting canary process: %v", err)
			}
			// get pid of the canary process
			pid := c.Process.Pid
			if err := Rescore(pid); err != nil {
				log.Fatalf("error scoring canary process: %v", err)
			}
			// wait for it to finish
			if err := c.Wait(); err != nil {
				log.Printf("error waiting for canary process: %v", err)
			}
			// Sleep for a second to let the kernel OOM killer work, this should
			// probably wait for the identified target to be oom killed and only then
			// restart canary.
			time.Sleep(1 * time.Second)
		}
	}()
}
