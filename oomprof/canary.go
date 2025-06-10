package oomprof

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func Canary(mb int) {
	// Ballast, make configurable
	space := make([]byte, 1024*1024*mb)
	// touch every page
	for i := 0; i < len(space); i += 4096 {
		space[i] = 0xFF
	}
	// Spin forever
	for {
		time.Sleep(1 * time.Second)
	}
}

func LaunchOOMCanary() {
	go func() {
		for {
			// launch myself with --canary arg
			c := exec.Command(os.Args[0], "--canary")
			if err := c.Start(); err != nil {
				log.Fatalf("error starting canary process: %v", err)
			}
			// get pid of the canary process
			pid := c.Process.Pid
			// write 1000 to /proc/<pid>/oom_score_adj
			oomAdjPath := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
			log.Printf("writing oom_score_adj for canary process %d to %s", pid, oomAdjPath)
			if err := os.WriteFile(oomAdjPath, []byte("1000"), 0644); err != nil {
				log.Fatalf("error writing to %s: %v", oomAdjPath, err)
			}
			contents, err := os.ReadFile(oomAdjPath)
			if err != nil {
				log.Fatalf("error reading oom_score_adj: %v", err)
			}
			// parse contents into int
			scr, err := strconv.Atoi(string(contents))
			if err != nil {
				log.Fatalf("error parsing oom_score_adj: %v", err)
			}
			log.Printf("oom_score_adj for canary process %d is set to %d", pid, scr)
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
