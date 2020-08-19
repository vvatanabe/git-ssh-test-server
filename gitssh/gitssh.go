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
		cmd := newGitPackCmd(shellPath, packCmd, repoPath)

		stdin, stdout, stderr, err := getPipes(cmd)
		if err != nil {
			return err
		}
		defer func() {
			stdin.Close()
			stdout.Close()
			stderr.Close()
		}()

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start cmd: %w", err)
		}
		defer cmd.Wait()

		if err := req.Reply(true, nil); err != nil {
			return fmt.Errorf("failed to reply request: %w", err)
		}

		return forwardChannel(stdin, stdout, stderr, ch)
	}
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

func forwardChannel(stdin io.WriteCloser, stdout, stderr io.ReadCloser, ch ssh.Channel) error {
	go func() {
		io.Copy(stdin, ch)
		stdin.Close()
	}()
	_, err := io.Copy(ch, stdout)
	if err != nil {
		return fmt.Errorf("failed to copy stdout: %w", err)
	}
	_, err = io.Copy(ch.Stderr(), stderr)
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
