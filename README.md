# git-ssh-test-server ![Go](https://github.com/vvatanabe/git-ssh-test-server/workflows/Go/badge.svg)

Git SSH Test Server is an example server that implements the Git SSH Protocol. It is intended to be used for testing the Git SSH and is not in a production ready state.

Git SSH Server is written in Go, with pre-compiled binaries available for Mac, Linux.

## Installation

### GoBinaries

You can easily install it by making a curl request to [gobinaries.com](http://gobinaries.com/). You don't have to install Go.

```sh
$ curl -sf https://gobinaries.com/vvatanabe/git-ssh-test-server| sh
```

### Go

If you have the Go(go1.14+) installed, you can also install it with go get command.

```sh
$ go get github.com/vvatanabe/git-ssh-test-server
```

If the installation fails, set the environment variable `GO111MODULE` to `on` by the following command.

```
# Bash
$ export GO111MODULE=on
```

### GitHub Release Page

Built binaries are available on Github releases:  
https://github.com/vvatanabe/git-ssh-test-server/releases

## Synopsis

```
$ git-ssh-test-server [flags]
```

## Flags

```
    --authorized_keys_path string    authorized keys path [GIT_SSH_AUTHORIZED_KEYS_PATH] (default "~/.ssh/authorized_keys")
-c, --config string                  config file path [GIT_SSH_CONFIG] (default "~/.git-ssh-test-server/config.yml")
-h, --help                           help for git-ssh-test-server
    --host_private_key_path string   host's private key path [GIT_SSH_HOST_PRIVATE_KEY_PATH] (default "~/.ssh/id_rsa")
    --port int                       port number for SSH [GIT_SSH_PORT] (default 22)
    --repo_dir string                git repositories dir path [GIT_SSH_REPO_DIR] (default "~/git/repo")
    --shell_path string              git shell path [GIT_SSH_SHELL_PATH] (default "/usr/bin/git-shell")
    --tcp_health_check_port int      port number for TCP Health Check [GIT_SSH_TCP_HEALTH_CHECK_PORT] (listen only when you specify port)
-v, --version                        version for git-ssh-test-server
```

## Config File

### Default Config File

Default par is `~/.git-ssh-test-server/config.yml`.

Default config file extension can be either `.yml` or `.yaml`.

### YAML Structure

```yaml
authorized_keys_path: /home/foo/.ssh/authorized_keys
host_private_key_path:  /home/foo/.ssh/id_rsa
port: 2222
repo_dir: /home/foo/git/repo
shell_path: "/usr/bin/git-shell"
tcp_health_check_port: 5000
```

## Bugs and Feedback

For bugs, questions and discussions please use the GitHub Issues.
