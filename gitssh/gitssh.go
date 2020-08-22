package gitssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	RepoDir            string
	ShellPath          string
	PublicKeyCallback  PublicKeyCallback
	GitRequestTransfer GitRequestTransfer

	Signer ssh.Signer
	Logger Logger
}

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

	for {
		conn, err := lis.Accept()
		if err != nil {
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
