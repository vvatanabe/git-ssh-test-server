package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vvatanabe/git-ssh-test-server/gitssh"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

const (
	cmdName       = "git-ssh-test-server"
	envPrefix     = "GIT_SSH_"
	dotSSHDirName = ".ssh"

	defaultConfigDirName = "." + cmdName

	defaultPort               = 22
	defaultTCPHealthCheckPort = 80
	defaultShellPath          = "/usr/bin/git-shell"

	defaultRepoDirName        = "git/repo"
	defaultAuthorizedKeysName = "authorized_keys"
	defaultHostPrivateKeyName = "id_rsa"

	flagNameConfig             = "config"
	flagNamePort               = "port"
	flagNameTCPHealthCheckPort = "tcp_health_check_port"
	flagNameRepoDir            = "repo_dir"
	flagNameShellPath          = "shell_path"
	flagNameAuthorizedKeysPath = "authorized_keys_path"
	flagNameHostPrivateKeyPath = "host_private_key_path"
)

type Config struct {
	Port               int    `mapstructure:"port"`
	TCPHealthCheckPort int    `mapstructure:"tcp_health_check_port"`
	RepoDir            string `mapstructure:"repo_dir"`
	ShellPath          string `mapstructure:"shell_path"`
	AuthorizedKeysPath string `mapstructure:"authorized_keys_path"`
	HostPrivateKeyPath string `mapstructure:"host_private_key_path"`
}

var (
	config Config
	sugar  *zap.SugaredLogger
)

func main() {

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		zap.NewAtomicLevel(),
	))
	defer logger.Sync() // flushes buffer, if any
	sugar = logger.Sugar()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		sugar.Fatalf("failed to get user home dir: %v", err)
	}
	defaultConfigFile := filepath.Join(homeDir, defaultConfigDirName, "config.yaml")
	if !exists(defaultConfigFile) {
		defaultConfigFile = filepath.Join(homeDir, defaultConfigDirName, "config.yml")
	}

	defaultRepoDir := path.Join(homeDir, defaultRepoDirName)
	defaultAuthorizedKeysPath := path.Join(homeDir, dotSSHDirName, defaultAuthorizedKeysName)
	defaultPrivateKey := path.Join(homeDir, dotSSHDirName, defaultHostPrivateKeyName)

	rootCmd := &cobra.Command{
		Use:     cmdName,
		Run:     run,
		Version: FmtVersion(),
	}

	flags := rootCmd.PersistentFlags()

	flags.StringP(flagNameConfig, "c", defaultConfigFile, fmt.Sprintf("config file path [%s]", getEnvVarName(flagNameConfig)))
	flags.Int(flagNamePort, defaultPort, fmt.Sprintf("port number for SSH [%s]", getEnvVarName(flagNamePort)))
	flags.Int(flagNameTCPHealthCheckPort, 0, fmt.Sprintf("port number for TCP Health Check [%s] (listen only when you specify port)", getEnvVarName(flagNameTCPHealthCheckPort)))
	flags.StringP(flagNameRepoDir, "", defaultRepoDir, fmt.Sprintf("git repositories dir path [%s]", getEnvVarName(flagNameRepoDir)))
	flags.StringP(flagNameShellPath, "", defaultShellPath, fmt.Sprintf("git shell path [%s]", getEnvVarName(flagNameShellPath)))
	flags.StringP(flagNameAuthorizedKeysPath, "", defaultAuthorizedKeysPath, fmt.Sprintf("authorized keys path [%s]", getEnvVarName(flagNameAuthorizedKeysPath)))
	flags.StringP(flagNameHostPrivateKeyPath, "", defaultPrivateKey, fmt.Sprintf("host's private key path [%s]", getEnvVarName(flagNameHostPrivateKeyPath)))

	_ = viper.BindPFlag(flagNamePort, flags.Lookup(flagNamePort))
	_ = viper.BindPFlag(flagNameTCPHealthCheckPort, flags.Lookup(flagNameTCPHealthCheckPort))
	_ = viper.BindPFlag(flagNameRepoDir, flags.Lookup(flagNameRepoDir))
	_ = viper.BindPFlag(flagNameShellPath, flags.Lookup(flagNameShellPath))
	_ = viper.BindPFlag(flagNameAuthorizedKeysPath, flags.Lookup(flagNameAuthorizedKeysPath))
	_ = viper.BindPFlag(flagNameHostPrivateKeyPath, flags.Lookup(flagNameHostPrivateKeyPath))

	cobra.OnInitialize(func() {
		configFile, err := flags.GetString(flagNameConfig)
		if err != nil {
			sugar.Fatalf("failed to get config file path: %v", err)
		}
		viper.SetConfigFile(configFile)
		viper.SetConfigType("yaml")
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
		viper.SetEnvPrefix(envPrefix)
		viper.AutomaticEnv()
		if exists(configFile) {
			if err := viper.ReadInConfig(); err != nil {
				sugar.Fatalf("failed to read config: %v", err)
			}
		} else {
			sugar.Infof("not found a config file: %v", configFile)
		}
		if err := viper.Unmarshal(&config); err != nil {
			sugar.Fatalf("failed to unmarshal config: %v", err)
		}
	})

	if err := rootCmd.Execute(); err != nil {
		sugar.Fatalf("failed to run cmd: %v", err)
	}

}

func getEnvVarName(s string) string {
	return strings.ToUpper(envPrefix + s)
}

func run(c *cobra.Command, args []string) {

	sugar.Infof("config: %#v", config)

	ready := make(chan struct{}, 1)
	if config.TCPHealthCheckPort > 0 {
		go func() {
			<-ready
			tcpLis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.TCPHealthCheckPort))
			if err != nil {
				sugar.Fatalf("failed to listen tcp: %v", err)
			}
			sugar.Infof("start to serve on tcp port: %d", config.TCPHealthCheckPort)
			for {
				conn, err := tcpLis.Accept()
				if err != nil {
					sugar.Errorf("failed to accept tcp: %v", err)
					continue
				}
				conn.Close()
			}
		}()
	}

	hostPrivateKey, err := ioutil.ReadFile(config.HostPrivateKeyPath)
	if err != nil {
		sugar.Fatalf("failed to read private key: %s %v", config.HostPrivateKeyPath, err)
	}
	hostPrivateKeySigner, err := ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		sugar.Fatalf("failed to parse private key: %s %v", config.HostPrivateKeyPath, err)
	}

	authorizedKeysBytes, err := ioutil.ReadFile(config.AuthorizedKeysPath)
	if err != nil {
		sugar.Fatalf("failed to load authorized_keys: %s %v", config.AuthorizedKeysPath, err)
	}

	authorizedKeys := make(map[string]struct{})
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			sugar.Fatalf("failed to parse authorized_keys, err: %v", err)
		}
		authorizedKeys[string(pubKey.Marshal())] = struct{}{}
		authorizedKeysBytes = rest
	}

	sshLis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		sugar.Fatalf("failed to listen ssh: %v", err)
	}
	s := gitssh.Server{
		RepoDir:            config.RepoDir,
		Signer:             hostPrivateKeySigner,
		PublicKeyCallback:  loggingPublicKeyCallback(authorizedKeys),
		GitRequestTransfer: loggingGitRequestTransfer(config.ShellPath),
		Logger: &zapLogger{
			sugar: sugar,
		},
	}
	sugar.Infof("start to serve on ssh port: %d", config.Port)
	ready <- struct{}{}
	if err := s.Serve(sshLis); err != nil {
		sugar.Errorf("failed to serve: %v", err)
	}

}

func loggingPublicKeyCallback(authorizedKeys map[string]struct{}) gitssh.PublicKeyCallback {
	return func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		startTime := time.Now()
		session := hex.EncodeToString(metadata.SessionID())
		var err error
		defer func() {
			finishTime := time.Now()
			sugar.Infow("PUBLIC_KEY_AUTH",
				"session", session,
				"user", metadata.User(),
				"remote_addr", getRemoteAddr(metadata.RemoteAddr()),
				"client_version", string(metadata.ClientVersion()),
				"key_type", key.Type(),
				"elapsed", finishTime.Sub(startTime),
				"error", err)
		}()
		if _, ok := authorizedKeys[string(key.Marshal())]; !ok {
			err = errors.New("failed to authorize")
			return nil, err
		}
		return &ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"SESSION": session,
			},
		}, nil
	}
}
func loggingGitRequestTransfer(shellPath string) gitssh.GitRequestTransfer {
	t := gitssh.LocalGitRequestTransfer(shellPath)
	return func(ch ssh.Channel, req *ssh.Request, perms *ssh.Permissions, packCmd, repoPath string) error {
		startTime := time.Now()
		chs := &ChannelWithSize{
			Channel: ch,
		}
		var err error
		defer func() {
			finishTime := time.Now()

			payload := string(req.Payload)
			i := strings.Index(payload, "git")
			if i > -1 {
				payload = payload[i:]
			}

			sugar.Infow("GIT_SSH_REQUEST",
				"session", perms.Extensions["SESSION"],
				"type", req.Type,
				"payload", payload,
				"size", chs.Size(),
				"elapsed", finishTime.Sub(startTime),
				"error", err)
		}()
		err = t(chs, req, perms, packCmd, repoPath)
		return err
	}
}

type ChannelWithSize struct {
	ssh.Channel
	size int64
}

func (ch *ChannelWithSize) Size() int64 {
	return ch.size
}

func (ch *ChannelWithSize) Write(data []byte) (int, error) {
	written, err := ch.Channel.Write(data)
	ch.size += int64(written)
	return written, err
}

type zapLogger struct {
	sugar *zap.SugaredLogger
}

func (z *zapLogger) Infof(format string, args ...interface{}) {
	z.sugar.Infof(format, args...)
}

func (z *zapLogger) Errorf(format string, args ...interface{}) {
	z.sugar.Errorf(format, args...)
}

func (z *zapLogger) Fatalf(format string, args ...interface{}) {
	z.sugar.Fatalf(format, args...)
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func getRemoteAddr(addr net.Addr) string {
	s := addr.String()
	if strings.ContainsRune(s, ':') {
		host, _, _ := net.SplitHostPort(s)
		return host
	}
	return s
}
