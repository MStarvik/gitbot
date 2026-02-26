package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

type WebhookPayload struct {
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Ref string `json:"ref"`
}

func parseRemoteURL(url string) (string, error) {
	if strings.HasPrefix(url, "git@") {
		parts := strings.SplitN(url, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid SSH URL format: %s", url)
		}
		path := parts[1]
		pathParts := strings.Split(path, "/")
		if len(pathParts) < 2 {
			return "", fmt.Errorf("invalid SSH URL path: %s", path)
		}
		return strings.TrimSuffix(path, ".git"), nil
	} else if after, ok := strings.CutPrefix(url, "https://"); ok {
		trimmed := after
		parts := strings.Split(trimmed, "/")
		if len(parts) < 2 {
			return "", fmt.Errorf("invalid HTTPS URL format: %s", url)
		}
		path := strings.Join(parts[1:], "/")
		return strings.TrimSuffix(path, ".git"), nil
	}
	return "", fmt.Errorf("unsupported URL format: %s", url)
}

func getAuth(keyfile string) ssh.AuthMethod {
	if keyfile == "" {
		return nil
	}

	key, err := ssh.NewPublicKeysFromFile("git", keyfile, "")
	if err != nil {
		log.Printf("Failed to load SSH key from %s: %v", keyfile, err)
		return nil
	}

	key.HostKeyCallback, err = ssh.NewKnownHostsCallback("/etc/ssh/ssh_known_hosts")
	if err != nil {
		log.Printf("Failed to create known hosts callback: %v", err)
		return nil
	}

	return key
}

func runCommand(command string) error {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()
	return cmd.Run()
}

func defaultResponse(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

type Gitbot struct {
	repo     *git.Repository
	worktree *git.Worktree

	remoteName string
	repoName   string
	refName    plumbing.ReferenceName

	auth        ssh.AuthMethod
	secret      []byte
	preCommand  string
	postCommand string
}

func makeGitbot(repoPath string, keyfile string, secret string, preCommand string, postCommand string) (*Gitbot, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %v", err)
	}

	head, err := repo.Head()
	if err != nil {
		log.Fatalf("Failed to get current branch: %v", err)
	}
	refName := head.Name()

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to get worktree: %v", err)
	}

	remotes, err := repo.Remotes()
	if err != nil {
		log.Fatalf("Failed to get remotes: %v", err)
	}
	if len(remotes) == 0 {
		log.Fatal("No remotes found in repository")
	}

	remote := remotes[0].Config()
	if len(remote.URLs) == 0 {
		log.Fatal("No URLs found in remote configuration")
	}

	remoteName := remote.Name
	repoName, err := parseRemoteURL(remote.URLs[0])
	if err != nil {
		log.Fatalf("Failed to parse remote URL: %v", err)
	}

	return &Gitbot{
		repo:     repo,
		worktree: worktree,

		remoteName: remoteName,
		repoName:   repoName,
		refName:    refName,

		auth:        getAuth(keyfile),
		secret:      []byte(secret),
		preCommand:  preCommand,
		postCommand: postCommand,
	}, nil
}

func (gb *Gitbot) Reset(fetch bool) {
	if gb.preCommand != "" {
		runCommand(gb.preCommand)
	}

	if fetch {
		err := gb.repo.Fetch(&git.FetchOptions{
			RemoteName: gb.remoteName,
			Auth:       gb.auth,
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			log.Printf("Failed to fetch remote: %v", err)
			return
		}
	}

	remoteBranchName := fmt.Sprintf("refs/remotes/%s/%s", gb.remoteName, gb.refName.Short())
	remoteRef, err := gb.repo.Reference(plumbing.ReferenceName(remoteBranchName), true)
	if err != nil {
		log.Printf("Failed to get remote reference %s: %v", remoteBranchName, err)
		return
	}

	err = gb.worktree.Reset(&git.ResetOptions{
		Mode:   git.HardReset,
		Commit: remoteRef.Hash(),
	})
	if err != nil {
		log.Printf("Failed to reset worktree: %v", err)
		return
	}

	if gb.postCommand != "" {
		runCommand(gb.postCommand)
	}
}

func (gb *Gitbot) isBehind() (bool, error) {
	err := gb.repo.Fetch(&git.FetchOptions{
		RemoteName: gb.remoteName,
		Auth:       gb.auth,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return false, fmt.Errorf("failed to fetch remote: %v", err)
	}

	localRef, err := gb.repo.Reference(gb.refName, true)
	if err != nil {
		return false, fmt.Errorf("failed to get local reference: %v", err)
	}

	remoteBranchName := fmt.Sprintf("refs/remotes/%s/%s", gb.remoteName, gb.refName.Short())
	remoteRef, err := gb.repo.Reference(plumbing.ReferenceName(remoteBranchName), true)
	if err != nil {
		return false, fmt.Errorf("failed to get remote reference %s: %v", remoteBranchName, err)
	}

	localCommit := localRef.Hash()
	remoteCommit := remoteRef.Hash()

	if localCommit == remoteCommit {
		return false, nil
	}

	return true, nil
}

func (gb *Gitbot) webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		defaultResponse(w, http.StatusInternalServerError)
		return
	}

	if len(gb.secret) > 0 {
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			defaultResponse(w, http.StatusUnauthorized)
			return
		}

		mac := hmac.New(sha256.New, gb.secret)
		mac.Write(body)
		digest := fmt.Sprintf("sha256=%x", mac.Sum(nil))

		if !hmac.Equal([]byte(signature), []byte(digest)) {
			defaultResponse(w, http.StatusUnauthorized)
			return
		}
	}

	var payload WebhookPayload
	err = json.Unmarshal(body, &payload)
	if err != nil {
		log.Printf("Failed to parse JSON payload: %v", err)
		defaultResponse(w, http.StatusBadRequest)
		return
	}

	if payload.Repository.FullName != gb.repoName {
		defaultResponse(w, http.StatusBadRequest)
		return
	}

	if payload.Ref != gb.refName.String() {
		defaultResponse(w, http.StatusBadRequest)
		return
	}

	log.Printf("Received valid webhook, updating...")

	go gb.Reset(true)
}

func main() {
	port := flag.Int("port", 80, "Port to listen on")
	keyfile := flag.String("keyfile", "", "Path to SSH private key for authentication")
	secret := flag.String("secret", "", "Secret token for authentication")
	preCommand := flag.String("pre-command", "", "Command to run before updating")
	postCommand := flag.String("post-command", "", "Command to run after updating")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		log.Fatal("Usage: updater [--port <port>] [--keyfile <kefile>] [--secret <secret>] [--pre-command <pre_command>] [--post-command <post_command>] <repo-path>")
	}
	repoPath := args[0]

	gitbot, err := makeGitbot(repoPath, *keyfile, *secret, *preCommand, *postCommand)
	if err != nil {
		log.Fatalf("Failed to initialize Gitbot: %v", err)
	}

	log.Printf("Repository: %s", gitbot.repoName)
	log.Printf("Reference: %s", gitbot.refName)
	log.Printf("Remote: %s", gitbot.remoteName)

	isBehind, err := gitbot.isBehind()
	if err != nil {
		log.Fatalf("Failed to check if repository is behind remote: %v", err)
	} else if isBehind {
		log.Printf("Local repository is behind remote, updating...")
		gitbot.Reset(false)
	}

	http.HandleFunc("POST /", gitbot.webhookHandler)

	address := fmt.Sprintf(":%d", *port)
	log.Printf("Listening on %s", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
