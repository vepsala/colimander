package sandbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Job and step states. A job is running, then succeeded or failed. A failed job can
// run again from the failed step, or be cleaned up, which ends in cleaned.
const (
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
	JobCleaning  = "cleaning"
	JobCleaned   = "cleaned"

	StepPending = "pending"
	StepRunning = "running"
	StepDone    = "done"
	StepWarning = "warning" // a soft step failed; the rest carried on
	StepFailed  = "failed"
)

// HostsCommand is what to run for <name>.local to work. The daemon has no terminal
// to answer sudo, so it never touches /etc/hosts itself.
const HostsCommand = "colimander hosts-sync"

// StepStatus is one step as the app sees it.
type StepStatus struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Soft       bool       `json:"soft,omitempty"`
	State      string     `json:"state"`
	Error      string     `json:"error,omitempty"`
	Output     string     `json:"output,omitempty"` // end of the step's output, when it failed
	Detail     string     `json:"detail,omitempty"` // latest output, while it runs
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	LogOffset  int64      `json:"log_offset,omitempty"`
}

// Job is one creation. This struct is what's stored and what the app polls, so it
// holds nothing secret: tokens only ever live in the running step's closure.
type Job struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	State     string       `json:"state"`
	Spec      Spec         `json:"spec"`
	Steps     []StepStatus `json:"steps"`
	CreatedAt time.Time    `json:"created_at"`

	FailedStep   string `json:"failed_step,omitempty"`
	Error        string `json:"error,omitempty"`
	Interrupted  bool   `json:"interrupted,omitempty"` // the daemon stopped mid-step
	CleanupError string `json:"cleanup_error,omitempty"`

	// Worked out on every read from what's really on disk, never stored.
	VMExists   bool   `json:"vm_exists"`
	CanRetry   bool   `json:"can_retry"`
	CanCleanup bool   `json:"can_cleanup"`
	Notes      []Note `json:"notes,omitempty"`
	HostsNote  string `json:"hosts_command,omitempty"`
}

// ErrBusy means a job is already running. One at a time keeps a name's claim simple
// and stops several VMs from booting and downloading at once.
var ErrBusy = errors.New("another sandbox is being created; wait for it to finish")

// ErrNotAllowed means the action doesn't apply to the job as it is now.
var ErrNotAllowed = errors.New("that isn't possible for this job right now")

// Jobs runs creations and remembers them across daemon restarts.
type Jobs struct {
	dir   string
	hooks Hooks
	audit func(name, action, detail string)

	mu   sync.Mutex
	jobs map[string]*Job
}

// NewJobs loads earlier jobs from dir. One that was mid-step when the daemon stopped
// is reported as failed, since nothing is watching it any more.
func NewJobs(dir string, h Hooks, audit func(name, action, detail string)) *Jobs {
	j := &Jobs{dir: dir, hooks: h, audit: audit, jobs: map[string]*Job{}}
	if audit == nil {
		j.audit = func(string, string, string) {}
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var job Job
		if err := json.Unmarshal(data, &job); err != nil || job.ID == "" {
			continue
		}
		switch job.State {
		case JobRunning:
			job.State, job.Interrupted = JobFailed, true
			job.Error = "The daemon stopped while this step was running, so its result isn't known. Commands it started may still be finishing."
			for i := range job.Steps {
				if s := &job.Steps[i]; s.State == StepRunning {
					s.State, s.Error = StepFailed, "interrupted"
					job.FailedStep = s.Label
				}
			}
			j.save(&job)
		case JobCleaning:
			job.State, job.Interrupted = JobFailed, true
			job.CleanupError = "The daemon stopped during clean-up. Try again."
			j.save(&job)
		}
		j.jobs[job.ID] = &job
	}
	return j
}

func (j *Jobs) logPath(id string) string { return filepath.Join(j.dir, id+".log") }

// save writes a job atomically. Callers hold mu, or own the job before it's shared.
func (j *Jobs) save(job *Job) {
	stored := *job
	stored.VMExists, stored.CanRetry, stored.CanCleanup, stored.Notes, stored.HostsNote = false, false, false, nil, ""
	data, err := json.MarshalIndent(&stored, "", "  ")
	if err != nil {
		return
	}
	if os.MkdirAll(j.dir, 0o700) != nil {
		return
	}
	tmp := filepath.Join(j.dir, job.ID+".tmp")
	if os.WriteFile(tmp, data, 0o600) == nil {
		os.Rename(tmp, filepath.Join(j.dir, job.ID+".json"))
	}
}

// Start begins creating a sandbox and returns at once. The tokens go no further than
// the prepare step's closure.
func (j *Jobs) Start(s Spec, sec Secrets) (Job, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, job := range j.jobs {
		if job.State == JobRunning || job.State == JobCleaning {
			return Job{}, ErrBusy
		}
	}
	if err := ValidateName(s.Name); err != nil {
		return Job{}, err
	}
	steps := Steps(s, sec, j.hooks)
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Job{}, err
	}
	job := &Job{ID: hex.EncodeToString(id[:]), Name: s.Name, State: JobRunning, Spec: s, CreatedAt: time.Now().UTC()}
	for _, st := range steps {
		job.Steps = append(job.Steps, StepStatus{ID: st.ID, Label: st.Label, Soft: st.Soft, State: StepPending})
	}
	j.jobs[job.ID] = job
	j.save(job)
	j.audit(s.Name, "CREATE-SANDBOX", "")
	go j.run(job, steps, 0)
	return j.view(job), nil
}

// Retry runs a failed job again from the step that failed. The tokens were stored
// in the prepare step, so a job that didn't get past it can't be retried.
func (j *Jobs) Retry(id string) (Job, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job := j.jobs[id]
	if job == nil {
		return Job{}, os.ErrNotExist
	}
	for _, other := range j.jobs {
		if other.State == JobRunning || other.State == JobCleaning {
			return Job{}, ErrBusy
		}
	}
	if !j.canRetry(job) {
		return Job{}, ErrNotAllowed
	}
	from := 0
	for i := range job.Steps {
		if job.Steps[i].State == StepFailed {
			from = i
			break
		}
	}
	for i := from; i < len(job.Steps); i++ {
		s := &job.Steps[i]
		*s = StepStatus{ID: s.ID, Label: s.Label, Soft: s.Soft, State: StepPending}
	}
	job.State, job.FailedStep, job.Error, job.Interrupted, job.CleanupError = JobRunning, "", "", false, ""
	j.save(job)
	j.audit(job.Name, "RETRY-SANDBOX", "")
	go j.run(job, Steps(job.Spec, Secrets{}, j.hooks), from)
	return j.view(job), nil
}

func (j *Jobs) run(job *Job, steps []Step, from int) {
	logf, err := os.OpenFile(j.logPath(job.ID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		j.mu.Lock()
		defer j.mu.Unlock()
		s := &job.Steps[from]
		s.State, s.Error = StepFailed, err.Error()
		job.State, job.FailedStep, job.Error = JobFailed, s.Label, err.Error()
		j.save(job)
		return
	}
	defer logf.Close()
	o := IO{Out: logf, Err: logf}
	for i := from; i < len(steps); i++ {
		offset, _ := logf.Seek(0, io.SeekEnd)
		now := time.Now().UTC()
		j.mu.Lock()
		s := &job.Steps[i]
		s.State, s.StartedAt, s.LogOffset = StepRunning, &now, offset
		j.save(job)
		j.mu.Unlock()

		err := safely(steps[i].Run, o)

		end := time.Now().UTC()
		j.mu.Lock()
		s.FinishedAt = &end
		switch {
		case err == nil:
			s.State = StepDone
		case steps[i].Soft:
			s.State, s.Error, s.Output = StepWarning, err.Error(), tailFrom(j.logPath(job.ID), offset)
		default:
			s.State, s.Error, s.Output = StepFailed, err.Error(), tailFrom(j.logPath(job.ID), offset)
			job.State, job.FailedStep, job.Error = JobFailed, s.Label, err.Error()
			j.save(job)
			j.mu.Unlock()
			j.audit(job.Name, "CREATE-SANDBOX-FAILED", s.Label)
			return
		}
		j.save(job)
		j.mu.Unlock()
	}
	j.mu.Lock()
	job.State = JobSucceeded
	j.save(job)
	j.mu.Unlock()
}

// safely stops a bug in a step from leaving a job running forever.
func safely(run func(IO) error, o IO) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return run(o)
}

func (j *Jobs) canRetry(job *Job) bool {
	return job.State == JobFailed && len(job.Steps) > 0 && job.Steps[0].ID == stepPrepare &&
		job.Steps[0].State == StepDone && job.Spec.owns()
}

// Cleanup deletes the VM and everything else a failed job made. It only acts on the
// profile whose marker this job wrote.
func (j *Jobs) Cleanup(id string) (Job, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job := j.jobs[id]
	if job == nil {
		return Job{}, os.ErrNotExist
	}
	if job.State != JobFailed || !job.Spec.owns() {
		return Job{}, ErrNotAllowed
	}
	job.State, job.CleanupError = JobCleaning, ""
	j.save(job)
	go func() {
		err := j.destroy(job)
		j.mu.Lock()
		defer j.mu.Unlock()
		if err != nil {
			job.State, job.CleanupError = JobFailed, err.Error()
		} else {
			job.State, job.Interrupted = JobCleaned, false
			j.audit(job.Name, "CLEANUP-SANDBOX", "")
		}
		j.save(job)
	}()
	return j.view(job), nil
}

func (j *Jobs) destroy(job *Job) error {
	name := job.Spec.Name
	logf, err := os.OpenFile(j.logPath(job.ID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	// Ask Colima only if it knows the VM: a boot that failed early leaves nothing to
	// delete. If it can't be asked, leave things alone and say why.
	exists, err := colimaHasProfile(name)
	if err != nil {
		return err
	}
	if exists {
		offset, _ := logf.Seek(0, io.SeekEnd)
		cmd := exec.Command("colima", "delete", "-f", name)
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("colima delete: %w\n%s", err, tailFrom(j.logPath(job.ID), offset))
		}
	}
	// Colima removes the profile's directory itself, marker included. If a marker is
	// still there it has to be ours: the delete took time, so check again.
	if m, err := LoadMarker(name); err != nil || (m != nil && !job.Spec.owns()) {
		return fmt.Errorf("%s no longer belongs to this job, so it was left alone", ProfileDir(name))
	}
	if err := os.RemoveAll(ProfileDir(name)); err != nil {
		return fmt.Errorf("cleanup %s: %w", ProfileDir(name), err)
	}
	os.RemoveAll(EmptyMountPath(name))
	if j.hooks.Forget != nil {
		if err := j.hooks.Forget(name); err != nil {
			return fmt.Errorf("the VM is gone, but its stored tokens couldn't be removed: %w", err)
		}
	}
	return nil
}

func colimaHasProfile(name string) (bool, error) {
	out, err := exec.Command("colima", "list", "--json").Output()
	if err != nil {
		return false, fmt.Errorf("colima list: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		var e struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// Dismiss forgets a finished job. It changes nothing but the job's own record.
func (j *Jobs) Dismiss(id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	job := j.jobs[id]
	if job == nil {
		return os.ErrNotExist
	}
	if job.State == JobRunning || job.State == JobCleaning {
		return ErrNotAllowed
	}
	delete(j.jobs, id)
	os.Remove(filepath.Join(j.dir, id+".json"))
	os.Remove(j.logPath(id))
	return nil
}

// List returns every job, newest first.
func (j *Jobs) List() []Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Job, 0, len(j.jobs))
	for _, job := range j.jobs {
		out = append(out, j.view(job))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out
}

// Get returns one job.
func (j *Jobs) Get(id string) (Job, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job := j.jobs[id]
	if job == nil {
		return Job{}, false
	}
	return j.view(job), true
}

// view copies a job for reading and fills in what depends on the disk now.
func (j *Jobs) view(job *Job) Job {
	v := *job
	v.Steps = append([]StepStatus(nil), job.Steps...)
	v.VMExists = job.Spec.owns()
	v.CanRetry = j.canRetry(job)
	v.CanCleanup = job.State == JobFailed && v.VMExists
	if job.State == JobSucceeded {
		v.Notes, v.HostsNote = NextSteps(job.Spec), HostsCommand
	}
	for i := range v.Steps {
		if s := &v.Steps[i]; s.State == StepRunning {
			s.Detail = lastLine(tailFrom(j.logPath(job.ID), s.LogOffset))
		}
		v.Steps[i].LogOffset = 0
	}
	return v
}

const tailBytes = 4096

// tailFrom returns the end of a log written since offset, as readable text.
func tailFrom(path string, offset int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ""
	}
	if info.Size()-offset > tailBytes {
		offset = info.Size() - tailBytes
	}
	buf := make([]byte, info.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	buf = bytes.ToValidUTF8(buf, nil)
	return strings.TrimSpace(ansiRE.ReplaceAllString(string(buf), ""))
}

var (
	ansiRE   = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	colimaRE = regexp.MustCompile(`msg="((?:[^"\\]|\\.)*)"`)
)

// lastLine picks what to show under a running step. Colima logs logfmt without a
// terminal, so it shows just the message.
func lastLine(s string) string {
	lines := strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' })
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if m := colimaRE.FindStringSubmatch(l); m != nil {
			l = strings.ReplaceAll(m[1], `\"`, `"`)
		}
		if len(l) > 160 {
			l = l[:160] + "…"
		}
		return l
	}
	return ""
}
