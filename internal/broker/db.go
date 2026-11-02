package broker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// DBPort is where agents connect. Loopback only: VMs reach it through Lima, and
// nothing off the Mac can use a leaked credential.
const DBPort = 15488

// DBAdminSocket is the database proxy's management UI, for the Mac app.
func DBAdminSocket() string { return filepath.Join(stateDir(), "db-admin.sock") }

func dbConfigPath() string { return filepath.Join(stateDir(), "db.yaml") }

// writeDBConfig creates the proxy's config once. It stays editable afterwards.
func writeDBConfig() error {
	_, err := os.Stat(dbConfigPath())
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dir := stateDir()
	cfg := fmt.Sprintf(`# Database proxy settings. Agents use the connection strings shown in the app.
listen: 127.0.0.1:%d
public_addr: host.lima.internal:%d
admin_socket: %q
database: %q
master_key_file: %q
hash_salt: %q
approval:
  mode: dashboard
  timeout: 5m
tls:
  mode: self_signed
  required: true
  hosts: [host.lima.internal, host.docker.internal, localhost]
  cache_dir: %q
`, DBPort, DBPort, DBAdminSocket(), filepath.Join(dir, "db.sqlite"), filepath.Join(dir, "master.key"),
		hex.EncodeToString(salt), filepath.Join(dir, "db-certs"))
	return os.WriteFile(dbConfigPath(), []byte(cfg), 0o600)
}

// startDBProxy runs the database proxy as a child process and restarts it if it
// dies. It's separate so a bug in parsing an agent's SQL can't reach the GitHub,
// Fly and Doppler credentials in this process.
func startDBProxy() (stop func()) {
	// The proxy's database holds connection names and rules in plain text.
	if err := os.Chmod(stateDir(), 0o700); err != nil {
		log.Printf("database proxy not started: %v", err)
		return func() {}
	}
	if err := writeDBConfig(); err != nil {
		log.Printf("database proxy not started: %v", err)
		return func() {}
	}
	self, err := os.Executable()
	if err != nil {
		log.Printf("database proxy not started: %v", err)
		return func() {}
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			runDBProxyOnce(self, done)
			select {
			case <-done:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}

func runDBProxyOnce(self string, done <-chan struct{}) {
	logf, err := os.OpenFile(filepath.Join(stateDir(), "db.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("database proxy log: %v", err)
		return
	}
	defer logf.Close()
	cmd := exec.Command(self, "db", "serve", "-config", dbConfigPath(), "-exit-with-stdin")
	cmd.Stdout, cmd.Stderr = logf, logf
	// The child exits when this pipe closes, including when this process dies.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("database proxy: %v", err)
		return
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		log.Printf("database proxy: %v", err)
		return
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		log.Printf("database proxy exited: %v", err)
	case <-done:
		stdin.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
}
