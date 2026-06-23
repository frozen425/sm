package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	oauth2Service "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	grpcMetadata "google.golang.org/grpc/metadata"
)

const (
	projectsConst = "projects"
	latestConst   = "latest"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Register secure file cleanup on exit
	defer cleanupFiles()

	// Parse CLI flags
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	envFile := flag.String("env-file", ".env.tpl", "Path to the environment template file")
	project := flag.String("project", "", "GCP Project ID (optional, auto-detected by default)")
	service := flag.String("service", "", "Service or component name for secret scoping (optional)")
	component := flag.String("component", "", "Component name (alias for -service)")
	reason := flag.String("request-reason", "", "Justification reason for GCP Audit Logs (optional)")
	cliToken := flag.String("token", "", "Direct GCP OAuth2 access token to use (optional)")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("sm version %s (commit: %s, built at: %s)\n", version, commit, date)
		return
	}

	// Handle command arguments
	args := flag.Args()

	// Support "sm status" command directly
	if len(args) > 0 && args[0] == "status" {
		runStatus(*project, *service, *reason, *cliToken)
		return
	}

	// Support "sm login" command directly
	if len(args) > 0 && args[0] == "login" {
		runLogin()
		return
	}

	if len(args) == 0 {
		log.Fatalf("Error: No target command specified. Usage: sm run -- [command] [args...]")
	}

	// Verify "run" command if provided
	if args[0] == "run" {
		if len(args) < 2 {
			log.Fatalf("Error: No command specified after 'run'. Usage: sm run -- [command]")
		}
		args = args[1:]
	}

	// Resolve component alias
	serviceName := *service
	if serviceName == "" {
		serviceName = *component
	}
	if serviceName == "" {
		serviceName = os.Getenv("SERVICE_NAME")
	}
	if serviceName == "" {
		serviceName = os.Getenv("COMPONENT_NAME")
	}

	// Cap serviceName to 63 characters (standard GCP resource label limit)
	if len(serviceName) > 63 {
		log.Printf("Warning: service name flag exceeds 63 characters. Truncating to 63 characters.")
		serviceName = serviceName[:63]
	}

	// 1. Load template file variables if it exists
	tplVars := make(map[string]string)
	if *envFile != "" {
		if _, err := os.Stat(*envFile); err == nil {
			var err error
			tplVars, err = parseEnvTpl(*envFile)
			if err != nil {
				log.Fatalf("Failed to parse environment template file %s: %v", *envFile, err)
			}
		} else if *envFile != ".env.tpl" {
			log.Fatalf("Error: Environment template file %s does not exist.", *envFile)
		}
	}

	// 2. Load local overrides from .env.local if it exists
	localOverrides := make(map[string]string)
	if _, err := os.Stat(".env.local"); err == nil {
		var err error
		localOverrides, err = parseEnvTpl(".env.local")
		if err != nil {
			log.Printf("Warning: Failed to parse .env.local file: %v", err)
		}
	}

	// 3. Precedence resolution and secrets checking
	resolvedEnv := make(map[string]string)
	secretsToResolve := make(map[string]string)

	for k, v := range tplVars {
		// Check parent shell env
		shellVal := os.Getenv(k)
		if shellVal != "" {
			if !strings.HasPrefix(shellVal, "sm://") {
				resolvedEnv[k] = shellVal
				continue
			} else {
				secretsToResolve[k] = shellVal
				continue
			}
		}

		// Check .env.local
		localVal, ok := localOverrides[k]
		if ok {
			if !strings.HasPrefix(localVal, "sm://") {
				resolvedEnv[k] = localVal
				continue
			} else {
				secretsToResolve[k] = localVal
				continue
			}
		}

		// Check if it requires GCP Secret Manager resolution
		if strings.HasPrefix(v, "sm://") {
			secretsToResolve[k] = v
			continue
		}

		// Use static value from .env.tpl
		resolvedEnv[k] = v
	}

	// Also check if any parent shell env variable is explicitly set to sm://
	for _, envPair := range os.Environ() {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) == 2 {
			k := parts[0]
			v := parts[1]
			if strings.HasPrefix(v, "sm://") {
				// Only resolve if it hasn't been resolved or overridden already
				if _, ok := resolvedEnv[k]; !ok {
					// Check if it's already in secretsToResolve (which would have come from tplVars or .env.local)
					if _, ok := secretsToResolve[k]; !ok {
						secretsToResolve[k] = v
					}
				}
			}
		}
	}

	needsGCP := len(secretsToResolve) > 0
	var loggingClient *logging.Client
	var email string = "Unknown"
	var projectID string
	var envName string = "localdev"

	if needsGCP {
		// 1. Auto-detect project ID
		projectID = detectProject(*project)
		if projectID == "" {
			log.Fatalf("Error: Could not determine GCP project. Set GOOGLE_CLOUD_PROJECT, active gcloud project, or pass via --project flag.")
		}

		// 2. Auto-detect environment
		envName = detectEnvironment(projectID)

		// 3. Set up GCP Client (handling Access Token override or ADC credentials)
		ctx := context.Background()
		token := resolveToken(*cliToken)
		ts, err := getGCPTokenSource(ctx, token)
		if err != nil {
			log.Fatalf("Failed to retrieve GCP credentials: %v", err)
		}

		client, err := secretmanager.NewClient(ctx, option.WithTokenSource(ts), option.WithUserAgent("sm/1.0.0"))
		if err != nil {
			log.Fatalf("Failed to initialize GCP Secret Manager client: %v", err)
		}
		defer func() { _ = client.Close() }()

		// Fetch identity email using oauth2 service for audit logging
		oauthService, err := oauth2Service.NewService(ctx, option.WithTokenSource(ts))
		if err == nil {
			userinfo, errInfo := oauthService.Userinfo.Get().Do()
			if errInfo == nil {
				email = userinfo.Email
			}
		}

		// Initialize GCP Cloud Logging client (best-effort)
		logClient, err := logging.NewClient(ctx, projectID, option.WithTokenSource(ts), option.WithUserAgent("sm/1.0.0"))
		if err == nil {
			loggingClient = logClient
			defer func() { _ = loggingClient.Close() }()
		}

		// 4. Attach request reason for Audit Logging
		auditReason := *reason
		if auditReason == "" {
			if serviceName != "" {
				auditReason = fmt.Sprintf("sm env injection for %s", serviceName)
			} else {
				auditReason = "sm env injection"
			}
		}
		ctx = withRequestReason(ctx, auditReason)

		// 5. Try to pre-fetch all secret names in project to optimize queries
		availableSecrets, listErr := getAvailableSecrets(ctx, client, projectID)
		if listErr != nil {
			log.Printf("Warning: Failed to list secrets in project %s (%v). Falling back to direct secret accessor requests.", projectID, listErr)
			availableSecrets = nil
		}

		// 6. Resolve secrets and write file destinations if requested
		cmdName := filepath.Base(args[0])
		for k, uri := range secretsToResolve {
			destFile, cleanURI := extractDestination(uri)

			// Resolve actual secret payload value
			val, err := resolveVariable(ctx, client, k, cleanURI, projectID, envName, serviceName, availableSecrets)
			if err != nil {
				fatalError(loggingClient, email, serviceName, envName, cmdName, "Failed to resolve secret for %s: %v", k, err)
			}

			// If file injection requested
			if destFile != "" {
				absPath, err := filepath.Abs(destFile)
				if err != nil {
					fatalError(loggingClient, email, serviceName, envName, cmdName, "Failed to resolve absolute path for %s destination %s: %v", k, destFile, err)
				}

				if err := writeSecretToFile(absPath, val); err != nil {
					fatalError(loggingClient, email, serviceName, envName, cmdName, "Failed to write secret to file %s for key %s: %v", absPath, k, err)
				}
				registerCleanup(absPath)
				resolvedEnv[k] = absPath
			} else {
				resolvedEnv[k] = val
			}
		}

		// Log "started" event to Cloud Logging
		if loggingClient != nil {
			lg := loggingClient.Logger("sm-audit")
			lg.Log(logging.Entry{
				Payload: map[string]interface{}{
					"event":          "started",
					"service":        serviceName,
					"env":            envName,
					"identity":       email,
					"command":        filepath.Base(args[0]),
					"request_reason": auditReason,
				},
				Severity: logging.Info,
			})
		}
	}

	// Execute target command with merged environment
	// #nosec G204
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = mergeEnviron(os.Environ(), resolvedEnv)

	// Forward OS signals for clean shutdown in child process and cleanup on signal exit
	forwardSignals(cmd)

	// Run the subprocess and exit with the same exit code
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	// Log "finished" event to Cloud Logging
	if loggingClient != nil {
		lg := loggingClient.Logger("sm-audit")
		severity := logging.Info
		if exitCode != 0 {
			severity = logging.Error
		}
		lg.Log(logging.Entry{
			Payload: map[string]interface{}{
				"event":     "finished",
				"service":   serviceName,
				"env":       envName,
				"identity":  email,
				"command":   filepath.Base(args[0]),
				"exit_code": exitCode,
			},
			Severity: severity,
		})
	}

	if err != nil {
		cleanupFiles()
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		log.Fatalf("Failed to execute command: %v", err)
	}
}

// detectProject resolves the target GCP Project ID
func detectProject(cliProject string) string {
	if cliProject != "" {
		return cliProject
	}
	if p := os.Getenv("GOOGLE_CLOUD_PROJECT"); p != "" {
		return p
	}
	if p := os.Getenv("GCP_PROJECT"); p != "" {
		return p
	}

	// Fallback to active gcloud config
	gcloudPath, err := exec.LookPath("gcloud")
	if err == nil && isSecureGcloudPath(gcloudPath) {
		// #nosec G204
		cmd := exec.Command(gcloudPath, "config", "get-value", "project")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			p := strings.TrimSpace(stdout.String())
			if p != "" && !strings.Contains(p, "unset") && !strings.Contains(p, "Error") {
				return p
			}
		}
	}

	// Fallback to Compute Engine metadata server
	if metadata.OnGCE() {
		if p, err := metadata.ProjectIDWithContext(context.Background()); err == nil && p != "" {
			return p
		}
	}

	return ""
}

// detectEnvironment determines the active environment tier
func detectEnvironment(projectID string) string {
	for _, envVar := range []string{"APP_ENV", "ENV", "NODE_ENV", "ENVIRONMENT"} {
		if val := os.Getenv(envVar); val != "" {
			return strings.ToLower(val)
		}
	}

	projectLower := strings.ToLower(projectID)
	envs := []string{"prod", "production", "staging", "stage", "test", "dev", "development", "localdev", "local"}
	for _, env := range envs {
		if strings.HasSuffix(projectLower, "-"+env) || strings.Contains(projectLower, "-"+env+"-") {
			switch env {
			case "production":
				return "prod"
			case "development":
				return "dev"
			case "stage":
				return "staging"
			default:
				return env
			}
		}
	}

	return "localdev"
}

// sanitizeReason filters the request justification to alphanumeric and space characters to prevent base64 encoding in logs
func sanitizeReason(reason string) string {
	var sb strings.Builder
	for _, r := range reason {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' {
			sb.WriteRune(r)
		}
	}
	res := strings.TrimSpace(sb.String())
	if res == "" {
		return "sm env injection"
	}
	if len(res) > 256 {
		res = res[:256]
	}
	return res
}

func withRequestReason(ctx context.Context, reason string) context.Context {
	sanitized := sanitizeReason(reason)
	return grpcMetadata.AppendToOutgoingContext(ctx, "x-goog-request-reason", sanitized)
}

// toKebabCase converts a string (like DATABASE_URL) to kebab-case (database-url)
func toKebabCase(s string) string {
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return strings.ToLower(s)
}

// generateCandidates generates a prioritized list of potential secret names
func generateCandidates(key, env, service string) []string {
	kebab := toKebabCase(key)
	original := key
	envUpper := strings.ToUpper(env)
	var candidates []string

	// 1. Service-scoped candidates
	if service != "" {
		svcKebab := toKebabCase(service)
		svcUpper := strings.ToUpper(service)
		candidates = append(candidates,
			fmt.Sprintf("%s-%s-%s", svcKebab, kebab, env),
			fmt.Sprintf("%s-%s-%s", service, original, env),
			fmt.Sprintf("%s-%s-%s", svcKebab, original, env),
			fmt.Sprintf("%s-%s-%s", service, kebab, env),

			fmt.Sprintf("%s-%s-%s", svcKebab, kebab, envUpper),
			fmt.Sprintf("%s-%s-%s", service, original, envUpper),
			fmt.Sprintf("%s-%s-%s", svcKebab, original, envUpper),
			fmt.Sprintf("%s-%s-%s", service, kebab, envUpper),

			fmt.Sprintf("%s-%s-%s", env, svcKebab, kebab),
			fmt.Sprintf("%s-%s-%s", env, service, original),
			fmt.Sprintf("%s-%s-%s", envUpper, svcKebab, kebab),
			fmt.Sprintf("%s-%s-%s", envUpper, service, original),

			fmt.Sprintf("%s-%s", svcKebab, kebab),
			fmt.Sprintf("%s-%s", service, original),
			fmt.Sprintf("%s-%s", svcUpper, original),
		)
	}

	// 2. Environment-scoped candidates
	candidates = append(candidates,
		fmt.Sprintf("%s-%s", env, kebab),
		fmt.Sprintf("%s-%s", env, original),
		fmt.Sprintf("%s-%s", envUpper, kebab),
		fmt.Sprintf("%s-%s", envUpper, original),

		fmt.Sprintf("%s-%s", kebab, env),
		fmt.Sprintf("%s-%s", original, env),
		fmt.Sprintf("%s-%s", kebab, envUpper),
		fmt.Sprintf("%s-%s", original, envUpper),
	)

	// 3. Plain candidates
	candidates = append(candidates,
		kebab,
		original,
	)

	// Deduplicate preserving order
	seen := make(map[string]bool)
	var result []string
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			result = append(result, c)
		}
	}
	return result
}

// getAvailableSecrets fetches a set of all secret IDs present in the active GCP project
func getAvailableSecrets(ctx context.Context, client *secretmanager.Client, projectID string) (map[string]bool, error) {
	secrets := make(map[string]bool)
	parent := fmt.Sprintf("projects/%s", projectID)
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: parent,
	}
	it := client.ListSecrets(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		parts := strings.Split(resp.Name, "/")
		secretID := parts[len(parts)-1]
		secrets[secretID] = true
	}
	return secrets, nil
}

// fetchSecretValue retrieves the payload value of the matched secret
func fetchSecretValue(ctx context.Context, client *secretmanager.Client, projectID, secretName, version string) (string, error) {
	if version == "" {
		version = latestConst
	}
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", projectID, secretName, version)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}
	resp, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", err
	}
	return string(resp.Payload.Data), nil
}

// isVersionIdentifier checks if a string represents a valid version identifier
func isVersionIdentifier(s string) bool {
	if s == latestConst {
		return true
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

// ParseURI parses standard sm:// URIs or fully qualified Secret Manager resource paths
func ParseURI(uri string, defaultProject string) (project, secret, version string, err error) {
	path := strings.TrimPrefix(uri, "sm://")
	path = strings.Trim(path, "/")
	if path == "" || path == "auto" {
		return defaultProject, "", latestConst, nil
	}

	parts := strings.Split(path, "/")
	switch len(parts) {
	case 1:
		project = defaultProject
		secret = parts[0]
		version = latestConst
	case 2:
		if parts[0] == projectsConst {
			return "", "", "", fmt.Errorf("invalid path starting with projects but incomplete")
		}
		if isVersionIdentifier(parts[1]) {
			project = defaultProject
			secret = parts[0]
			version = parts[1]
		} else {
			project = parts[0]
			secret = parts[1]
			version = latestConst
		}
	case 3:
		project = parts[0]
		secret = parts[1]
		version = parts[2]
	case 4:
		if parts[0] == projectsConst && parts[2] == "secrets" {
			project = parts[1]
			secret = parts[3]
			version = latestConst
		} else {
			return "", "", "", fmt.Errorf("invalid secret path structure: %s", uri)
		}
	case 6:
		if parts[0] == projectsConst && parts[2] == "secrets" && parts[4] == "versions" {
			project = parts[1]
			secret = parts[3]
			version = parts[5]
		} else {
			return "", "", "", fmt.Errorf("invalid secret path structure: %s", uri)
		}
	default:
		return "", "", "", fmt.Errorf("invalid secret URI: %s", uri)
	}

	return project, secret, version, nil
}

// resolveVariable returns the resolved value for a template/environment variable
func resolveVariable(ctx context.Context, client *secretmanager.Client, key, val, defaultProject, env, service string, availableSecrets map[string]bool) (string, error) {
	if !strings.HasPrefix(val, "sm://") {
		return val, nil
	}

	proj, sec, ver, err := ParseURI(val, defaultProject)
	if err != nil {
		return "", err
	}

	if sec == "" {
		candidates := generateCandidates(key, env, service)

		if availableSecrets != nil {
			var matchedCandidate string
			for _, c := range candidates {
				if availableSecrets[c] {
					matchedCandidate = c
					break
				}
			}
			if matchedCandidate == "" {
				return "", fmt.Errorf("no matching secret found in GCP Secret Manager for key %s (tried: %v)", key, candidates)
			}
			return fetchSecretValue(ctx, client, proj, matchedCandidate, ver)
		}

		// Fallback: try accessing candidates one by one
		var lastErr error
		for _, c := range candidates {
			val, err := fetchSecretValue(ctx, client, proj, c, ver)
			if err == nil {
				return val, nil
			}
			lastErr = err
		}
		return "", fmt.Errorf("failed to resolve secret for key %s (tried: %v). Last error: %v", key, candidates, lastErr)
	}

	return fetchSecretValue(ctx, client, proj, sec, ver)
}

// parseEnvTpl reads variables from a .env.tpl file
func parseEnvTpl(filename string) (map[string]string, error) {
	// #nosec G304
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// Strip quotes if any
		if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
			(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
			val = val[1 : len(val)-1]
		}
		env[key] = val
	}
	return env, scanner.Err()
}

// mergeEnviron merges standard system environment variables with resolved custom values
func mergeEnviron(base []string, overrides map[string]string) []string {
	envMap := make(map[string]string)
	for _, e := range base {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	for k, v := range overrides {
		envMap[k] = v
	}

	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// forwardSignals registers OS signals listener to redirect them to target command process
func forwardSignals(cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for sig := range sigs {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
			if sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == syscall.SIGQUIT {
				cleanupFiles()
				os.Exit(130)
			}
		}
	}()
}

var cleanupRegistry []string

func registerCleanup(path string) {
	cleanupRegistry = append(cleanupRegistry, path)
}

func cleanupFiles() {
	for _, f := range cleanupRegistry {
		if f != "" {
			_ = os.Remove(f)
		}
	}
}

// resolveToken checks CLI flag and env vars for direct GCP access token
func resolveToken(cliToken string) string {
	if cliToken != "" {
		return cliToken
	}
	if t := os.Getenv("GCP_ACCESS_TOKEN"); t != "" {
		return t
	}
	if t := os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN"); t != "" {
		return t
	}
	return ""
}

// getGCPTokenSource returns a token source from direct token or ADC credentials
func getGCPTokenSource(ctx context.Context, token string) (oauth2.TokenSource, error) {
	if token != "" {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}), nil
	}
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}
	return creds.TokenSource, nil
}

// extractDestination parses query parameters and extracts destination path if any
func extractDestination(uri string) (string, string) {
	if !strings.HasPrefix(uri, "sm://") {
		return "", uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", uri
	}
	dest := u.Query().Get("destination")
	cleanURI := uri
	if idx := strings.Index(uri, "?"); idx != -1 {
		cleanURI = uri[:idx]
	}
	return dest, cleanURI
}

// writeSecretToFile writes data to path with 0600 file permissions
func writeSecretToFile(path string, data string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0600)
}

// runStatus implements the diagnostics status command
func runStatus(projectFlag, serviceFlag, reasonFlag, cliToken string) {
	ctx := context.Background()

	fmt.Println("GCP Environment Status:")

	// 1. Resolve project
	projectID := detectProject(projectFlag)
	if projectID != "" {
		fmt.Printf("  Active Project ID : %s\n", projectID)
	} else {
		fmt.Println("  Active Project ID : [Error: Could not determine active project]")
	}

	// 2. Resolve operating environment
	envName := "localdev"
	if projectID != "" {
		envName = detectEnvironment(projectID)
	}
	fmt.Printf("  Operating Env     : %s\n", envName)

	// 3. Resolve identity
	token := resolveToken(cliToken)
	ts, err := getGCPTokenSource(ctx, token)
	if err != nil {
		fmt.Printf("  Authenticated As  : [Error: Failed to obtain credentials - %v]\n", err)
		fmt.Println("  Secret Manager API: Unaccessible (Credentials not found)")
		os.Exit(1)
	}

	var email string
	oauthService, err := oauth2Service.NewService(ctx, option.WithTokenSource(ts))
	if err == nil {
		userinfo, errInfo := oauthService.Userinfo.Get().Do()
		if errInfo == nil {
			email = userinfo.Email
		} else {
			email = fmt.Sprintf("Token active (Email lookup failed: %v)", errInfo)
		}
	} else {
		email = fmt.Sprintf("Token active (OAuth2 service init failed: %v)", err)
	}
	fmt.Printf("  Authenticated As  : %s\n", email)

	// 4. Test connection
	client, err := secretmanager.NewClient(ctx, option.WithTokenSource(ts), option.WithUserAgent("sm/1.0.0"))
	if err != nil {
		fmt.Printf("  Secret Manager API: Connection Failed (%v)\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	auditReason := reasonFlag
	if auditReason == "" {
		if serviceFlag != "" {
			auditReason = fmt.Sprintf("sm status check for %s", serviceFlag)
		} else {
			auditReason = "sm status check"
		}
	}
	ctx = withRequestReason(ctx, auditReason)

	_, listErr := getAvailableSecrets(ctx, client, projectID)
	if listErr != nil {
		fmt.Printf("  Secret Manager API: Access Failed (%v)\n", listErr)
		os.Exit(1)
	}

	fmt.Println("  Secret Manager API: Accessible (Successfully listed secrets)")
}

// runLogin triggers the GCP application-default login flow
func runLogin() {
	gcloudPath, err := exec.LookPath("gcloud")
	if err != nil || !isSecureGcloudPath(gcloudPath) {
		log.Fatalf("Error: 'gcloud' CLI not found in PATH or failed execution safety checks.\nPlease install Google Cloud SDK securely to authenticate: https://cloud.google.com/sdk/docs/install")
	}

	fmt.Println("Authenticating sm (Secret Manager)...")
	// #nosec G204
	cmd := exec.Command(gcloudPath, "auth", "application-default", "login")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// #nosec G204
	err = cmd.Run()
	if err != nil {
		log.Fatalf("Failed to run gcloud login: %v", err)
	}
}

// fatalError logs a fatal bootstrap error to stderr and GCP Cloud Logging (if active), cleans up, and exits
func fatalError(loggingClient *logging.Client, email, serviceName, envName, cmdName string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("Error: %s", msg)

	if loggingClient != nil {
		lg := loggingClient.Logger("sm-audit")
		_ = lg.LogSync(context.Background(), logging.Entry{
			Payload: map[string]interface{}{
				"event":      "bootstrap_failed",
				"service":    serviceName,
				"env":        envName,
				"identity":   email,
				"command":    cmdName,
				"error":      msg,
			},
			Severity: logging.Error,
		})
	}

	cleanupFiles()
	os.Exit(1)
}

// isSecureGcloudPath checks if the resolved gcloud executable path is secure
func isSecureGcloudPath(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Reject paths in known world-writable or insecure locations
	insecureDirs := []string{
		"/tmp",
		"/var/tmp",
		"/dev/shm",
		os.TempDir(),
	}
	for _, dir := range insecureDirs {
		if strings.HasPrefix(absPath, dir) {
			return false
		}
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return false
	}

	// Ensure the file is not world-writable
	mode := info.Mode()
	if mode&0002 != 0 {
		return false
	}

	// Read the first 1024 bytes of the file to verify the Google Cloud SDK header
	// #nosec G304
	file, err := os.Open(absPath)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()

	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return false
	}
	content := string(buf[:n])

	// Verify the preamble/copyright header for shell script wrappers (macOS/Linux)
	// and cmd/powershell wrappers (Windows)
	hasGoogleCopyright := strings.Contains(content, "Google Inc.") || strings.Contains(content, "Google LLC")
	hasPreamble := strings.Contains(content, "<cloud-sdk-sh-preamble>") || strings.Contains(content, "cloud-sdk")

	// If it is a binary (rare but possible), we bypass content inspection,
	// but for script wrappers we verify the signature
	if !strings.HasPrefix(content, "#!") && !strings.Contains(content, "@echo") {
		// Fallback for binaries: verify path and permission controls only
		return true
	}

	return hasGoogleCopyright || hasPreamble
}
