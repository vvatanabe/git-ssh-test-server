package gitssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	RepoDir            string
	ShellPath          string
	PublicKeyCallback  PublicKeyCallback
	GitRequestTransfer GitRequestTransfer

	Signer ssh.Signer
	Logger Logger

	inShutdown   int32 // 0 or 1. accessed atomically (non-zero means we're in Shutdown)
	mu           sync.Mutex
	listeners    map[*net.Listener]struct{}
	listenerWg   sync.WaitGroup
	activeConn   map[*ssh.ServerConn]struct{}
	activeConnWg sync.WaitGroup
	doneChan     chan struct{}
	onShutdown   []func()
}

var ErrServerClosed = errors.New("gitssh: Server closed")

func (srv *Server) Serve(lis net.Listener) error {

	if srv.Logger == nil {
		srv.Logger = &defaultLogger{}
	}

	if srv.PublicKeyCallback == nil {
		return errors.New("public key callback is required")
	}

	if srv.GitRequestTransfer == nil {
		srv.GitRequestTransfer = LocalGitRequestTransfer(srv.ShellPath)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: srv.PublicKeyCallback,
	}
	cfg.AddHostKey(srv.Signer)

	if !srv.trackListener(&lis, true) {
		return ErrServerClosed
	}
	defer srv.trackListener(&lis, false)

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-srv.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.Logger.Errorf("gitssh: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		go srv.handleConn(conn, cfg)
	}
}

func (srv *Server) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()

	sConn, reqs, globalReqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		srv.Logger.Errorf("failed to new server conn %v", err)
		return
	}

	go ssh.DiscardRequests(globalReqs)

	for newChan := range reqs {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		srv.handleChannel(newChan, sConn.Permissions)
	}
}

func (srv *Server) handleChannel(newChan ssh.NewChannel, perms *ssh.Permissions) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		srv.Logger.Errorf("failed to accept channel %v", err)
		return
	}
	defer ch.Close()

	var wg sync.WaitGroup
	for req := range reqs {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		cmdStr, repoPath := splitPayload(req.Payload)
		if cmdStr == "" || repoPath == "" {
			req.Reply(false, nil)
			continue
		}
		wg.Add(1)
		go func(req *ssh.Request) {
			defer wg.Done()
			srv.handleGitRequest(ch, req, perms, cmdStr, filepath.Join(srv.RepoDir, repoPath))
		}(req)
	}
	wg.Wait()
}

func (srv *Server) handleGitRequest(ch ssh.Channel, req *ssh.Request, perms *ssh.Permissions, packCmd, repoPath string) {
	var err error
	defer func() {
		var code uint8
		if err != nil {
			code = 1
		}
		ch.SendRequest("exit-status", false, []byte{0, 0, 0, code})
		ch.Close()
	}()
	err = srv.GitRequestTransfer(ch, req, perms, packCmd, repoPath)
}

type PublicKeyCallback func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)

type GitRequestTransfer func(ch ssh.Channel, req *ssh.Request, perms *ssh.Permissions, gitCmd, repoPath string) error

func LocalGitRequestTransfer(shellPath string) GitRequestTransfer {
	return func(ch ssh.Channel, req *ssh.Request, perms *ssh.Permissions, packCmd, repoPath string) error {
		if err := req.Reply(true, nil); err != nil {
			return fmt.Errorf("failed to reply request: %w", err)
		}
		switch packCmd {
		case "git-receive-pack":
			return GitReceivePack(shellPath, repoPath, ch, ch.Stderr())
		case "git-upload-pack":
			return GitUploadPack(shellPath, repoPath, ch, ch.Stderr())
		default:
			return fmt.Errorf("no support command: %s", packCmd)
		}
	}
}

func GitReceivePack(shellPath, dir string, rw, rwe io.ReadWriter) error {
	return gitPack(shellPath, dir, "git-receive-pack", rw, rwe)
}

func GitUploadPack(shellPath, dir string, rw, rwe io.ReadWriter) error {
	return gitPack(shellPath, dir, "git-upload-pack", rw, rwe)
}

func gitPack(shellPath, dir, packCmd string, rw, rwe io.ReadWriter) error {
	cmd := newGitPackCmd(shellPath, packCmd, dir)

	stdin, stdout, stderr, err := getPipes(cmd)
	if err != nil {
		return err
	}
	defer func() {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
	}()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start git-receive-pack: %w", err)
	}
	defer cmd.Wait()

	return forwardIO(stdin, stdout, stderr, rw, rwe)
}

func getPipes(cmd *exec.Cmd) (stdin io.WriteCloser, stdout, stderr io.ReadCloser, err error) {
	defer func() {
		if err != nil {
			if stdin != nil {
				stdin.Close()
			}
			if stdout != nil {
				stdout.Close()
			}
			if stderr != nil {
				stderr.Close()
			}
		}
	}()
	stdin, err = cmd.StdinPipe()
	if err != nil {
		err = fmt.Errorf("failed to get stdin: %w", err)
		return
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("failed to get stdout: %w", err)
		return
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		err = fmt.Errorf("failed to get stderr: %w", err)
		return
	}
	return
}

func newGitPackCmd(shellPath, packCmd, repoPath string) *exec.Cmd {
	cmd := exec.Command(shellPath, "-c", fmt.Sprintf("%s '%s'", packCmd, repoPath))
	cmd.Dir = repoPath
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func forwardIO(stdin io.WriteCloser, stdout, stderr io.ReadCloser, rw, rwe io.ReadWriter) error {
	go func() {
		io.Copy(stdin, rw)
		stdin.Close()
	}()
	_, err := io.Copy(rw, stdout)
	if err != nil {
		return fmt.Errorf("failed to copy stdout: %w", err)
	}
	_, err = io.Copy(rwe, stderr)
	if err != nil {
		return fmt.Errorf("failed to copy stderr: %w", err)
	}
	return nil
}

func splitPayload(payload []byte) (packCmd, repoPath string) {

	payloadStr := string(payload)
	i := strings.Index(payloadStr, "git")
	if i == -1 {
		return
	}

	cmdArgs := strings.Split(payloadStr[i:], " ")

	if len(cmdArgs) != 2 {
		return
	}

	cmd := cmdArgs[0]
	if !(cmd == "git-receive-pack" || cmd == "git-upload-pack") {
		return
	}

	path := cmdArgs[1]
	path = strings.Trim(path, "'")

	if len(strings.Split(path, "/")) != 3 {
		return
	}

	packCmd = cmd
	repoPath = path
	return
}

func (srv *Server) trackListener(ln *net.Listener, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.listeners == nil {
		srv.listeners = make(map[*net.Listener]struct{})
	}
	if add {
		if srv.shuttingDown() {
			return false
		}
		srv.listeners[ln] = struct{}{}
		srv.listenerWg.Add(1)
	} else {
		delete(srv.listeners, ln)
		srv.listenerWg.Done()
	}
	return true
}

func (srv *Server) shuttingDown() bool {
	return atomic.LoadInt32(&srv.inShutdown) != 0
}

func (srv *Server) trackConn(sConn *ssh.ServerConn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.activeConn == nil {
		srv.activeConn = make(map[*ssh.ServerConn]struct{})
	}
	if add {
		srv.activeConn[sConn] = struct{}{}
		srv.activeConnWg.Add(1)
	} else {
		delete(srv.activeConn, sConn)
		srv.activeConnWg.Done()
	}
}

func (srv *Server) getDoneChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.getDoneChanLocked()
}

func (srv *Server) getDoneChanLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

func (srv *Server) closeDoneChanLocked() {
	ch := srv.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by s.mu.
		close(ch)
	}
}

func (srv *Server) closeListenersLocked() error {
	var err error
	for ln := range srv.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
		delete(srv.listeners, ln)
	}
	return err
}

func (srv *Server) RegisterOnShutdown(f func()) {
	srv.mu.Lock()
	srv.onShutdown = append(srv.onShutdown, f)
	srv.mu.Unlock()
}

func (srv *Server) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&srv.inShutdown, 1)

	srv.mu.Lock()
	lnerr := srv.closeListenersLocked()
	srv.closeDoneChanLocked()
	for _, f := range srv.onShutdown {
		go f()
	}
	srv.mu.Unlock()

	finished := make(chan struct{}, 1)
	go func() {
		srv.listenerWg.Wait()
		srv.activeConnWg.Wait()
		finished <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finished:
		return lnerr
	}
}

type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}
type defaultLogger struct {
}

func (d defaultLogger) Infof(format string, args ...interface{}) {
}

func (d defaultLogger) Errorf(format string, args ...interface{}) {
}

func (d defaultLogger) Fatalf(format string, args ...interface{}) {
}
