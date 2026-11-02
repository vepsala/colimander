package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// IO is where a step's commands read and write. The CLI passes its terminal; a job
// passes its log file and no input. Using a file rather than a pipe matters there:
// `colima start` leaves background processes holding its output open, and waiting
// on a pipe would hang.
type IO struct {
	In       *os.File
	Out, Err io.Writer
}

func (o IO) command(stdin io.Reader, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = o.Out, o.Err
	if stdin != nil {
		cmd.Stdin = stdin
	} else if o.In != nil {
		cmd.Stdin = o.In
	}
	return cmd
}

// BootVM writes the profile's config and runs `colima start`.
func BootVM(m *Marker, o IO) error {
	if err := WriteColimaConfig(m); err != nil {
		return fmt.Errorf("write colima.yaml: %w", err)
	}
	emptyMnt, err := ensureEmptyMount(m.Name)
	if err != nil {
		return fmt.Errorf("create empty mount stub: %w", err)
	}
	fmt.Fprintf(o.Out, "Starting %q (no host home mount; %d CPU / %d GiB RAM / %d GiB disk)\n",
		m.Name, m.CPU, m.Memory, m.Disk)
	// The --mount with our empty dir is the trick that suppresses Colima's
	// $HOME and /tmp/colima-<profile> defaults at the lima.yaml layer.
	return o.command(nil, "colima", "start", m.Name, "--mount", emptyMnt+":r").Run()
}

// EnsureSwap idempotently creates and activates a /swapfile of the requested
// size inside the VM and persists it in /etc/fstab. Safe to call on every
// start — if a /swapfile is already active at the right size, this is a no-op.
func EnsureSwap(profile string, gib int, o IO) error {
	script := fmt.Sprintf(`set -e
DESIRED_BYTES=$(( %d * 1024 * 1024 * 1024 ))
if swapon --show=NAME,SIZE --bytes --noheadings 2>/dev/null | awk '$1=="/swapfile"{print $2}' | grep -qx "$DESIRED_BYTES"; then
  exit 0
fi
sudo swapoff /swapfile 2>/dev/null || true
sudo rm -f /swapfile
sudo fallocate -l %dG /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile > /dev/null
sudo swapon /swapfile
grep -q "^/swapfile " /etc/fstab || echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
`, gib, gib)
	return o.command(strings.NewReader(script), "colima", "ssh", "-p", profile, "--", "bash", "-s").Run()
}

// ImportDir copies a host directory into the VM at /home/<vmuser>/<basename>.
// Caller is responsible for ensuring the VM is running. On a terminal, it polls
// the VM target with `du -sb` and rewrites a single progress line.
func ImportDir(profile, srcDir string, o IO) error {
	abs, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("import-dir %q: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("import-dir %q is not a directory", abs)
	}
	vmUser, err := VMUserName()
	if err != nil {
		return err
	}
	instance := LimaInstanceName(profile)
	dest := fmt.Sprintf("%s:/home/%s/", instance, vmUser)
	vmTarget := fmt.Sprintf("/home/%s/%s", vmUser, filepath.Base(abs))

	fmt.Fprintf(o.Out, "Importing %s into %s%s ...\n", abs, dest, filepath.Base(abs))

	srcSize, sizeErr := dirAppSize(abs)

	cmd := o.command(nil, "limactl", "cp", "-r", abs, dest)
	cmd.Env = append(os.Environ(), "LIMA_HOME="+LimaHome())
	if err := cmd.Start(); err != nil {
		return err
	}

	tty := isTTY(o.Out)
	stop := make(chan struct{})
	done := make(chan struct{})
	if sizeErr == nil && srcSize > 0 && tty {
		go func() {
			defer close(done)
			progressLoop(profile, vmTarget, srcSize, stop, o.Out)
		}()
	} else {
		close(done)
	}

	waitErr := cmd.Wait()
	close(stop)
	<-done

	if tty && sizeErr == nil && srcSize > 0 {
		if waitErr == nil {
			fmt.Fprintf(o.Out, "\r  %s imported.%s\n", humanSize(srcSize), strings.Repeat(" ", 40))
		} else {
			fmt.Fprintf(o.Out, "\r%s\r", strings.Repeat(" ", 80))
		}
	}
	return waitErr
}

func dirAppSize(p string) (int64, error) {
	var total int64
	err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func progressLoop(profile, vmPath string, total int64, stop <-chan struct{}, out io.Writer) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	start := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			n, err := vmPathBytes(profile, vmPath)
			if err != nil {
				continue
			}
			pct := float64(n) / float64(total) * 100
			if pct > 100 {
				pct = 100
			}
			elapsed := time.Since(start).Round(time.Second)
			fmt.Fprintf(out, "\r  %s / %s  (%3.0f%%)  %s elapsed   ",
				humanSize(n), humanSize(total), pct, elapsed)
		}
	}
}

func vmPathBytes(profile, path string) (int64, error) {
	out, err := exec.Command("colima", "ssh", "-p", profile, "--", "du", "-sb", path).Output()
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return 0, errors.New("empty du output")
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

func humanSize(n int64) string {
	const (
		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
	)
	switch {
	case n >= gib:
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(gib))
	case n >= mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(mib))
	case n >= kib:
		return fmt.Sprintf("%.0f KiB", float64(n)/float64(kib))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// DepStatus is one required tool, found or not.
type DepStatus struct {
	Bin     string `json:"bin"`
	OK      bool   `json:"ok"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Install string `json:"install,omitempty"`
}

var requiredDeps = []struct{ bin, versionFlag, install string }{
	{"colima", "version", "brew install colima"},
	{"limactl", "--version", "brew install lima"},
	{"docker", "--version", "comes with colima; if missing, brew install docker"},
	{"git", "--version", "preinstalled on macOS; otherwise brew install git"},
}

// CheckDeps looks for every tool setup needs.
func CheckDeps() []DepStatus {
	out := make([]DepStatus, 0, len(requiredDeps))
	for _, d := range requiredDeps {
		st := DepStatus{Bin: d.bin, Install: d.install}
		path, err := exec.LookPath(d.bin)
		if err == nil {
			st.OK, st.Path = true, path
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if b, err := exec.CommandContext(ctx, path, d.versionFlag).Output(); err == nil {
				st.Version = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
			}
			cancel()
		}
		out = append(out, st)
	}
	return out
}

const ghTimeout = 30 * time.Second

// GHCurrentLogin asks gh who the host user is. It's an allowed owner of every sandbox.
func GHCurrentLogin() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ghTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "api", "user", "--jq", ".login").Output()
	if err != nil {
		return "", fmt.Errorf("gh api user: %w (is `gh auth status` healthy?)", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GHOrgs lists the orgs the host user can offer to a sandbox.
func GHOrgs() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ghTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "api", "user/orgs", "--paginate", "--jq", ".[].login").Output()
	if err != nil {
		return nil, fmt.Errorf("gh api user/orgs: %w", err)
	}
	var orgs []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			orgs = append(orgs, l)
		}
	}
	return orgs, nil
}
