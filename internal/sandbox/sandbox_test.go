package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secret = "fly-super-secret-token"

// setup gives a test a private HOME and a colima that does what the script says.
func setup(t *testing.T, script string) string {
	t.Helper()
	home, err := os.MkdirTemp("", "cm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	bin := filepath.Join(home, "bin")
	os.MkdirAll(bin, 0o755)
	if err := os.WriteFile(filepath.Join(bin, "colima"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	return home
}

func hooks() Hooks {
	return Hooks{
		SaveConfig:     func(Spec, Secrets) error { return nil },
		Forget:         func(string) error { return nil },
		ActivateBroker: func(string, IO) error { return nil },
		EnableEgress:   func(string, IO) error { return nil },
	}
}

func goodRequest() Request {
	return Request{Name: "demo", CPU: "2", Memory: "4", Disk: "20", Swap: "0", StartBroker: true}
}

func spec(t *testing.T, r Request) (Spec, Secrets) {
	t.Helper()
	s, sec, err := r.Spec("test", "me", []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	return s, sec
}

func wait(t *testing.T, j *Jobs, id string, states ...string) Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := j.Get(id)
		if !ok {
			t.Fatal("job vanished")
		}
		for _, s := range states {
			if job.State == s {
				return job
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, _ := j.Get(id)
	t.Fatalf("job stuck in %s: %+v", job.State, job)
	return job
}

func stateOf(job Job, id string) StepStatus {
	for _, s := range job.Steps {
		if s.ID == id {
			return s
		}
	}
	return StepStatus{}
}

func TestValidateName(t *testing.T) {
	setup(t, "")
	for name, ok := range map[string]bool{
		"demo": true, "a": true, "a-1": true, "-a": false, "": false, "Demo": false, "a_b": false, "a/b": false, "..": false,
		strings.Repeat("a", 31): true, strings.Repeat("a", 32): false,
		// Colima reads these as another profile.
		"colima": false, "colima-other": false,
	} {
		if err := ValidateName(name); (err == nil) != ok {
			t.Errorf("ValidateName(%q) = %v", name, err)
		}
	}
	os.MkdirAll(ProfileDir("taken"), 0o755) // an unmanaged profile: no marker
	if err := ValidateName("taken"); err == nil {
		t.Error("should refuse a name with an existing Colima profile")
	}
}

func TestValidateNumbers(t *testing.T) {
	for _, s := range []string{"", " ", "x", "1.5", "0", "-1"} {
		if ValidatePositiveInt(s) == nil {
			t.Errorf("ValidatePositiveInt(%q) passed", s)
		}
	}
	if ValidatePositiveInt(" 2 ") != nil {
		t.Error("spaces around a number are fine")
	}
	if ValidateNonNegativeInt("0") != nil || ValidateNonNegativeInt("-1") == nil {
		t.Error("swap accepts 0 and refuses negatives")
	}
	s, _, err := Request{CPU: " 2 ", Memory: "4", Disk: "20", Swap: " 0"}.Spec("v", "me", nil)
	if err != nil || s.CPU != 2 || s.Swap != 0 {
		t.Errorf("Spec = %+v, %v", s, err)
	}
}

func TestImportPaths(t *testing.T) {
	home := setup(t, "")
	dir := filepath.Join(home, "proj")
	os.MkdirAll(dir, 0o755)
	file := filepath.Join(home, "file")
	os.WriteFile(file, nil, 0o644)

	for path, ok := range map[string]bool{
		dir: true, "~/proj": true, "  ~/proj ": true, "~": true,
		"": false, file: false, filepath.Join(home, "missing"): false,
		"proj": false, "./proj": false, "../proj": false, "~other/proj": false,
	} {
		if err := ValidateImportPathFromApp(path); (err == nil) != ok {
			t.Errorf("ValidateImportPathFromApp(%q) = %v", path, err)
		}
	}
	got, err := NormalizeImportPath("  ~/proj ")
	if err != nil || got != dir {
		t.Errorf("NormalizeImportPath = %q, %v", got, err)
	}
	r := goodRequest()
	r.Import, r.ImportPath = true, "~/proj"
	if s, _ := spec(t, r); s.ImportPath != dir {
		t.Errorf("spec path = %q", s.ImportPath)
	}
	r.Import = false
	if s, _ := spec(t, r); s.ImportPath != "" {
		t.Error("a path left behind after turning import off must not be used")
	}
}

func TestRequestValidate(t *testing.T) {
	setup(t, "")
	if errs := goodRequest().Validate(true); len(errs) != 0 {
		t.Fatalf("good request: %v", errs)
	}
	r := goodRequest()
	r.EnableFly, r.EnableDoppler, r.Packages, r.Egress, r.StartBroker = true, true, []string{"nope"}, true, false
	errs := r.Validate(true)
	for _, f := range []string{"fly_token", "doppler_token", "doppler_projects", "packages", "egress"} {
		if errs[f] == "" {
			t.Errorf("no error for %s: %v", f, errs)
		}
	}
	for _, f := range []string{"fly_token", "doppler_token"} {
		if strings.Contains(errs[f], secret) {
			t.Error("error quotes token")
		}
	}
}

func TestFlyBlankMeansAllAppsAndDopplerSplits(t *testing.T) {
	r := goodRequest()
	r.EnableFly, r.FlyToken = true, "  t  "
	r.EnableDoppler, r.DopplerToken, r.DopplerProjects = true, "d", "a, b,"
	s, sec, err := r.Spec("v", "me", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.FlyApps) != 1 || s.FlyApps[0] != "*" || len(s.Projects) != 2 || sec.Fly != "t" {
		t.Errorf("%+v %s", s, sec.Fly)
	}
}

func TestSecretsDoNotPrint(t *testing.T) {
	sec := Secrets{Fly: secret}
	data, _ := json.Marshal(sec)
	if strings.Contains(string(data)+fmt.Sprint(sec), secret) {
		t.Error("Secrets printed a token")
	}
}

func TestJobSucceedsAndKeepsTokenOutOfEverything(t *testing.T) {
	home := setup(t, `echo "time=now level=info msg=\"starting colima\""`)
	var gotToken string
	h := hooks()
	h.SaveConfig = func(_ Spec, sec Secrets) error { gotToken = sec.Fly; return nil }
	dir := filepath.Join(home, "jobs")
	j := NewJobs(dir, h, nil)
	r := goodRequest()
	r.EnableFly, r.FlyToken, r.Packages, r.Egress = true, secret, []string{"opencode"}, true
	s, sec := spec(t, r)
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	job := wait(t, j, started.ID, JobSucceeded, JobFailed)
	if job.State != JobSucceeded {
		t.Fatalf("job failed: %+v", job)
	}
	if gotToken != secret {
		t.Error("the token didn't reach SaveConfig")
	}
	want := []string{"prepare", "boot", "broker", "baseline", "package:opencode", "egress"}
	if len(job.Steps) != len(want) {
		t.Fatalf("steps = %+v", job.Steps)
	}
	for i, id := range want {
		if job.Steps[i].ID != id || job.Steps[i].State != StepDone {
			t.Errorf("step %d = %+v", i, job.Steps[i])
		}
	}
	if job.HostsNote != HostsCommand || len(job.Notes) == 0 {
		t.Error("a finished job must say how to sync /etc/hosts")
	}
	if job.CanCleanup || job.CanRetry {
		t.Error("a finished job offers no destroy or retry")
	}
	m, _ := LoadMarker("demo")
	if m == nil || m.CPU != 2 {
		t.Errorf("marker = %+v", m)
	}

	status, _ := json.Marshal(j.List())
	if strings.Contains(string(status), secret) {
		t.Error("status JSON holds the token")
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		data, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if strings.Contains(string(data), secret) {
			t.Errorf("%s holds the token", f.Name())
		}
		info, _ := f.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", f.Name(), info.Mode().Perm())
		}
	}
}

func TestSoftFailureIsAWarning(t *testing.T) {
	setup(t, `case "$1" in ssh) echo tmux-broke; exit 3;; esac`)
	j := NewJobs(filepath.Join(os.Getenv("HOME"), "jobs"), hooks(), nil)
	s, sec := spec(t, goodRequest())
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	job := wait(t, j, started.ID, JobSucceeded, JobFailed)
	base := stateOf(job, "baseline")
	if job.State != JobSucceeded || base.State != StepWarning || !strings.Contains(base.Error, "exit status 3") || !strings.Contains(base.Output, "tmux-broke") {
		t.Errorf("job %s, baseline %+v", job.State, base)
	}
}

func TestFailureAtAStepThenRetry(t *testing.T) {
	home := setup(t, `case "$1" in start) if [ -f "$HOME/heal" ]; then exit 0; fi; echo disk-full >&2; exit 7;; list) echo '{"name":"demo"}';; delete) echo "$@" >> "$HOME/deleted";; esac`)
	j := NewJobs(filepath.Join(home, "jobs"), hooks(), nil)
	s, sec := spec(t, goodRequest())
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	job := wait(t, j, started.ID, JobFailed, JobSucceeded)
	if job.State != JobFailed || job.FailedStep != "Boot the VM" || !strings.Contains(job.Error, "exit status 7") {
		t.Fatalf("%+v", job)
	}
	boot := stateOf(job, "boot")
	if boot.State != StepFailed || !strings.Contains(boot.Output, "disk-full") {
		t.Errorf("boot = %+v", boot)
	}
	if stateOf(job, "prepare").State != StepDone || stateOf(job, "baseline").State != StepPending {
		t.Errorf("steps = %+v", job.Steps)
	}
	if !job.CanRetry || !job.CanCleanup || !job.VMExists {
		t.Errorf("should offer retry and clean-up: %+v", job)
	}

	// A second job refuses the name while this one holds it.
	if _, err := j.Start(s, sec); err == nil {
		t.Error("the name is taken")
	}

	os.WriteFile(filepath.Join(home, "heal"), nil, 0o644)
	if _, err := j.Retry(job.ID); err != nil {
		t.Fatal(err)
	}
	job = wait(t, j, job.ID, JobSucceeded, JobFailed)
	if job.State != JobSucceeded || job.Error != "" || stateOf(job, "boot").State != StepDone {
		t.Errorf("after retry: %+v", job)
	}
	if _, err := j.Cleanup(job.ID); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("clean-up of a finished job: %v", err)
	}
}

func TestPrepareFailureLeavesNothing(t *testing.T) {
	home := setup(t, "")
	h := hooks()
	forgot := false
	h.SaveConfig = func(Spec, Secrets) error { return errors.New("vault locked") }
	h.Forget = func(string) error { forgot = true; return nil }
	j := NewJobs(filepath.Join(home, "jobs"), h, nil)
	s, sec := spec(t, goodRequest())
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	job := wait(t, j, started.ID, JobFailed)
	if !strings.Contains(job.Error, "vault locked") || job.CanRetry || job.CanCleanup || job.VMExists {
		t.Errorf("%+v", job)
	}
	if _, err := os.Stat(ProfileDir("demo")); err == nil || !forgot {
		t.Error("prepare should undo itself")
	}
	if _, err := j.Retry(job.ID); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("retry: %v", err)
	}
}

func TestCleanupOnlyTouchesWhatTheJobCreated(t *testing.T) {
	home := setup(t, `case "$1" in start) exit 1;; list) echo '{"name":"demo"}';; delete) echo "$@" >> "$HOME/deleted";; esac`)
	j := NewJobs(filepath.Join(home, "jobs"), hooks(), nil)
	s, sec := spec(t, goodRequest())
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	job := wait(t, j, started.ID, JobFailed)

	// Someone else's profile took over the name: marker with another identity.
	m := s.Marker()
	m.CreatedAt = m.CreatedAt.Add(time.Hour)
	WriteMarker(m)
	if v, _ := j.Get(job.ID); v.CanCleanup || v.CanRetry {
		t.Error("the profile isn't this job's any more")
	}
	if _, err := j.Cleanup(job.ID); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("clean-up: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "deleted")); err == nil {
		t.Fatal("deleted a VM it didn't create")
	}

	WriteMarker(s.Marker())
	if _, err := j.Cleanup(job.ID); err != nil {
		t.Fatal(err)
	}
	job = wait(t, j, job.ID, JobCleaned, JobFailed)
	if job.State != JobCleaned {
		t.Fatalf("%+v", job)
	}
	got, _ := os.ReadFile(filepath.Join(home, "deleted"))
	if strings.TrimSpace(string(got)) != "delete -f demo" {
		t.Errorf("colima got %q", got)
	}
	if _, err := os.Stat(ProfileDir("demo")); err == nil {
		t.Error("the profile dir should be gone")
	}
}

func TestCleanupKeepsFilesWhenDeleteFails(t *testing.T) {
	home := setup(t, `case "$1" in start) exit 1;; list) echo '{"name":"demo"}';; delete) echo stuck >&2; exit 5;; esac`)
	j := NewJobs(filepath.Join(home, "jobs"), hooks(), nil)
	s, sec := spec(t, goodRequest())
	started, _ := j.Start(s, sec)
	job := wait(t, j, started.ID, JobFailed)
	j.Cleanup(job.ID)
	job = wait(t, j, job.ID, JobFailed)
	if !strings.Contains(job.CleanupError, "stuck") || !job.CanCleanup {
		t.Errorf("%+v", job)
	}
	if m, _ := LoadMarker("demo"); m == nil {
		t.Error("the marker must stay while the VM may still exist")
	}
}

func TestOneJobAtATime(t *testing.T) {
	home := setup(t, `case "$1" in start) while [ ! -f "$HOME/go" ]; do sleep 0.02; done;; esac`)
	j := NewJobs(filepath.Join(home, "jobs"), hooks(), nil)
	s, sec := spec(t, goodRequest())
	first, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	r := goodRequest()
	r.Name = "other"
	s2, sec2 := spec(t, r)
	if _, err := j.Start(s2, sec2); !errors.Is(err, ErrBusy) {
		t.Errorf("second start: %v", err)
	}
	if err := j.Dismiss(first.ID); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("dismiss while running: %v", err)
	}
	os.WriteFile(filepath.Join(home, "go"), nil, 0o644)
	wait(t, j, first.ID, JobSucceeded)
	if err := j.Dismiss(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := j.Get(first.ID); ok {
		t.Error("dismissed job still listed")
	}
	if m, _ := LoadMarker("demo"); m == nil {
		t.Error("dismiss must not touch the sandbox")
	}
}

func TestRestartReportsInterruptedJob(t *testing.T) {
	home := setup(t, `case "$1" in start) while [ ! -f "$HOME/go" ]; do sleep 0.02; done;; esac`)
	dir := filepath.Join(home, "jobs")
	j := NewJobs(dir, hooks(), nil)
	s, sec := spec(t, goodRequest())
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	for stateOf(mustGet(t, j, started.ID), "boot").State != StepRunning {
		time.Sleep(10 * time.Millisecond)
	}
	// A new manager reading the same directory is what a restarted daemon does.
	after := NewJobs(dir, hooks(), nil)
	job := mustGet(t, after, started.ID)
	if job.State != JobFailed || !job.Interrupted || job.FailedStep != "Boot the VM" || !job.CanRetry || !job.CanCleanup {
		t.Errorf("%+v", job)
	}
	os.WriteFile(filepath.Join(home, "go"), nil, 0o644)
	wait(t, j, started.ID, JobSucceeded) // lets the first manager's goroutine finish before cleanup
}

func mustGet(t *testing.T, j *Jobs, id string) Job {
	t.Helper()
	job, ok := j.Get(id)
	if !ok {
		t.Fatal("no job")
	}
	return job
}

func TestLastLineReadsColimaLogs(t *testing.T) {
	got := lastLine("x\ntime=\"t\" level=info msg=\"creating and starting ...\" context=vm\n")
	if got != "creating and starting ..." {
		t.Errorf("got %q", got)
	}
}

// The real `colima delete` removes the profile directory, marker and all.
func TestCleanupWhenColimaRemovesTheDirectory(t *testing.T) {
	home := setup(t, `case "$1" in start) exit 1;; list) echo '{"name":"demo"}';; delete) rm -rf "$HOME/.colima/demo";; esac`)
	forgot := false
	h := hooks()
	h.Forget = func(string) error { forgot = true; return nil }
	j := NewJobs(filepath.Join(home, "jobs"), h, nil)
	s, sec := spec(t, goodRequest())
	started, err := j.Start(s, sec)
	if err != nil {
		t.Fatal(err)
	}
	wait(t, j, started.ID, JobFailed)
	if _, err := j.Cleanup(started.ID); err != nil {
		t.Fatal(err)
	}
	job := wait(t, j, started.ID, JobCleaned, JobFailed)
	if job.State != JobCleaned || !forgot {
		t.Errorf("state %s (%s), tokens forgotten: %v", job.State, job.CleanupError, forgot)
	}
}
