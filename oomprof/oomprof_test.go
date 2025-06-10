//go:build linux

package oomprof

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPass(t *testing.T) {
}

func TestOOM(t *testing.T) {
	//t.Skip()
	go func() {
		err := SetupOomProf()
		t.Log(err)
	}()

	// Start canary
	can := exec.Command("./oompa.taux", "--canary")

	err := can.Start()
	require.NoError(t, err)

	// Start target process which will consume all memory
	go func() {
		for {
			out, err := exec.Command("./oomer.taux").CombinedOutput()
			//err := oomer.Start()
			require.NoError(t, err)
			//err = oomer.Wait()
			if err != nil {
				// we were killed
				t.Log("oomer killed: ", err)
				break
			}
			t.Log(out)
			// go around again, sometimes we don't oom
			t.Log("oomer didn't get killed")
		}
	}()

	err = can.Wait()
	// err should be kill'd
	t.Log("canary killed: ", err)
}
