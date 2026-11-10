package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernaxis/xcertm/internal/app"
	"github.com/kernaxis/xcertm/internal/config"
	urfave "github.com/urfave/cli/v3"
)

func rootFlags() []urfave.Flag {
	return []urfave.Flag{
		&urfave.StringFlag{Name: "config", Usage: "Optional YAML configuration file"},
		&urfave.StringFlag{Name: "state-dir", Usage: "Persistent store root (default depends on executing host)"},
		&urfave.StringFlag{Name: "environment", Usage: "ACME environment: production or staging"},
		&urfave.BoolFlag{Name: "staging", Usage: "Use Let's Encrypt staging"},
		&urfave.DurationFlag{Name: "timeout", Value: 10 * time.Minute, Usage: "Maximum duration of a lifecycle command"},
		&urfave.BoolFlag{Name: "json", Usage: "Write public results as JSON"},
	}
}

func selectionFlags() []urfave.Flag {
	return []urfave.Flag{&urfave.StringFlag{Name: "certificate", Usage: "Stable managed certificate ID"}, &urfave.BoolFlag{Name: "all", Usage: "Select all configured or stored certificates"}}
}
func destinationFlags() []urfave.Flag {
	return []urfave.Flag{
		&urfave.StringSliceFlag{Name: "destination", Usage: "Select a destination ID (repeatable)"},
		&urfave.StringFlag{Name: "type", Usage: "Explicit destination type: filesystem or dsm"},
		&urfave.StringFlag{Name: "directory", Usage: "Existing filesystem destination directory"},
		&urfave.StringFlag{Name: "key-file", Usage: "Private key output filename"},
		&urfave.StringFlag{Name: "certificate-file", Usage: "Full-chain output filename"},
		&urfave.StringFlag{Name: "dsm-certificate-id", Usage: "Existing DSM entry ID (omitting both selectors creates a managed entry)"},
		&urfave.BoolFlag{Name: "dsm-default", Usage: "Deploy to the DSM default entry instead of creating a managed entry"},
	}
}
func issuanceFlags() []urfave.Flag {
	flags := []urfave.Flag{
		&urfave.StringFlag{Name: "email", Usage: "ACME contact email"},
		&urfave.BoolFlag{Name: "accept-tos", Usage: "Accept the ACME CA's terms for account creation"},
		&urfave.StringSliceFlag{Name: "domain", Usage: "Requested DNS name (repeatable, quote wildcards)"},
		&urfave.StringFlag{Name: "dns", Usage: "Configured DNS provider name or cloudflare/ovh"},
		&urfave.StringFlag{Name: "zone", Usage: "Explicit DNS zone (useful for restricted API keys)"},
		&urfave.StringFlag{Name: "ovh-endpoint", Usage: "OVH endpoint: ovh-eu, ovh-ca, ovh-us"},
		&urfave.BoolFlag{Name: "deploy", Usage: "Also deploy the obtained or reused generation"},
		&urfave.BoolFlag{Name: "force", Usage: "Explicitly request a new generation even if not due"},
		&urfave.StringFlag{Name: "renew-before", Usage: "Renewal window, e.g. 20d (default: final third of lifetime)"},
		&urfave.StringSliceFlag{Name: "resolver", Usage: "DNS resolver IP with optional port (repeatable)"},
		&urfave.DurationFlag{Name: "propagation-timeout", Value: 2 * time.Minute, Usage: "Maximum time to confirm DNS TXT propagation"},
	}
	for _, name := range []string{"cloudflare-token", "ovh-application-key", "ovh-application-secret", "ovh-consumer-key"} {
		flags = append(flags, &urfave.StringFlag{Name: name + "-env", Usage: "Credential environment variable name"}, &urfave.StringFlag{Name: name + "-file", Usage: "Private credential file path"})
	}
	return flags
}

func lifecycleCommands() []*urfave.Command {
	commands := []*urfave.Command{}
	for _, name := range []string{"issue", "renew", "deploy"} {
		name := name
		flags := append(selectionFlags(), destinationFlags()...)
		if name != "deploy" {
			flags = append(flags, issuanceFlags()...)
		}
		commands = append(commands, &urfave.Command{Name: name, Usage: map[string]string{"issue": "Obtain and store a certificate generation", "renew": "Renew certificates when due", "deploy": "Deploy an already stored certificate generation"}[name], Flags: flags, Action: func(ctx context.Context, c *urfave.Command) error { return runLifecycle(ctx, c, name) }})
	}
	commands = append(commands, &urfave.Command{Name: "list", Usage: "List certificates already in the persistent store", Action: inspectList}, &urfave.Command{Name: "show", Usage: "Show stored certificate generations and deployment observations", ArgsUsage: "<certificate-id>", Action: inspectShow})
	return commands
}

func load(c *urfave.Command) (config.Config, string, string, error) {
	cfg, err := config.Load(c.String("config"))
	if err != nil {
		return cfg, "", "", err
	}
	root := cfg.StateDir
	if root == "" {
		root = config.DefaultStateDir("/")
	}
	if c.IsSet("state-dir") {
		root = c.String("state-dir")
	}
	if root == "" {
		return cfg, "", "", errors.New("state directory must not be empty")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return cfg, "", "", err
	}
	env := cfg.ACME.Environment
	if env == "" {
		env = "production"
	}
	if c.IsSet("environment") {
		env = c.String("environment")
	}
	if c.Bool("staging") {
		if c.IsSet("environment") && env != "staging" {
			return cfg, "", "", errors.New("--staging conflicts with --environment")
		}
		env = "staging"
	}
	if env != "production" && env != "staging" {
		return cfg, "", "", errors.New("environment must be production or staging")
	}
	return cfg, root, env, nil
}

func requests(c *urfave.Command, cfg config.Config, service *app.Service, environment string, issuance bool) ([]config.Request, error) {
	if c.Args().Present() {
		return nil, errors.New("use --certificate or --all; unexpected positional arguments")
	}
	id := c.String("certificate")
	if c.Bool("all") == (id != "") {
		return nil, errors.New("select --certificate or --all, exclusively")
	}
	ids := []string{id}
	if c.Bool("all") {
		ids = nil
		for id := range cfg.Certificates {
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			var err error
			ids, err = service.WorkIDs()
			if err != nil {
				return nil, err
			}
		}
		slices.Sort(ids)
	}
	jobs := []config.Request{}
	owners := map[string]string{}
	for _, id := range ids {
		request := config.Request{ID: id, ACME: cfg.ACME, Destinations: map[string]config.Destination{}}
		if certificate, ok := cfg.Certificates[id]; ok {
			request.Certificate = certificate
			request.Provider = cfg.DNSProviders[certificate.DNSProvider]
		} else {
			previous, err := service.LastRequest(id, environment)
			if err == nil {
				request = previous
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
		// Own a fresh destination map for this invocation, without mutating YAML
		// data or a previous operation's parameters.
		destinations := map[string]config.Destination{}
		for key, value := range request.Destinations {
			destinations[key] = value
		}
		for key, value := range cfg.Destinations {
			destinations[key] = value
		}
		request.Destinations = destinations
		request.ACME.Environment = environment
		if cfg.ACME.Email != "" {
			request.ACME.Email = cfg.ACME.Email
		}
		if cfg.ACME.AcceptTOS {
			request.ACME.AcceptTOS = true
		}
		if c.IsSet("email") {
			request.ACME.Email = c.String("email")
		}
		if c.IsSet("accept-tos") {
			request.ACME.AcceptTOS = c.Bool("accept-tos")
		}
		if c.IsSet("domain") {
			request.Certificate.Domains = c.StringSlice("domain")
		}
		if c.IsSet("dns") {
			name := c.String("dns")
			request.Certificate.DNSProvider = name
			if provider, ok := cfg.DNSProviders[name]; ok {
				request.Provider = provider
			} else {
				request.Provider = config.Provider{Type: name}
			}
		}
		if c.IsSet("zone") {
			request.Provider.Zone = c.String("zone")
		}
		if c.IsSet("ovh-endpoint") {
			request.Provider.Endpoint = c.String("ovh-endpoint")
		}
		credential := func(prefix string, env, file *string) {
			if c.IsSet(prefix + "-env") {
				*env = c.String(prefix + "-env")
				*file = ""
			}
			if c.IsSet(prefix + "-file") {
				*file = c.String(prefix + "-file")
				*env = ""
			}
		}
		for _, prefix := range []string{"cloudflare-token", "ovh-application-key", "ovh-application-secret", "ovh-consumer-key"} {
			if c.IsSet(prefix+"-env") && c.IsSet(prefix+"-file") {
				return nil, fmt.Errorf("choose --%s-env or --%s-file, exclusively", prefix, prefix)
			}
		}
		credential("cloudflare-token", &request.Provider.APITokenEnv, &request.Provider.APITokenFile)
		if c.IsSet("cloudflare-token-env") || c.IsSet("cloudflare-token-file") {
			request.Provider.APIToken = nil
		}
		credential("ovh-application-key", &request.Provider.ApplicationKeyEnv, &request.Provider.ApplicationKeyFile)
		credential("ovh-application-secret", &request.Provider.ApplicationSecretEnv, &request.Provider.ApplicationSecretFile)
		credential("ovh-consumer-key", &request.Provider.ConsumerKeyEnv, &request.Provider.ConsumerKeyFile)
		if c.IsSet("renew-before") {
			request.Certificate.RenewBefore = c.String("renew-before")
		}
		if c.IsSet("destination") {
			request.Certificate.Destinations = c.StringSlice("destination")
		}
		if c.IsSet("type") || c.IsSet("directory") || c.IsSet("dsm-default") || c.IsSet("dsm-certificate-id") || c.IsSet("key-file") || c.IsSet("certificate-file") {
			if len(request.Certificate.Destinations) != 1 {
				return nil, errors.New("explicit destination flags require exactly one --destination")
			}
			key := request.Certificate.Destinations[0]
			d := request.Destinations[key]
			if c.IsSet("type") {
				d.Type = c.String("type")
			}
			if c.IsSet("directory") {
				d.Directory = c.String("directory")
			}
			if c.IsSet("key-file") {
				d.KeyFile = c.String("key-file")
			}
			if c.IsSet("certificate-file") {
				d.CertificateFile = c.String("certificate-file")
			}
			if c.IsSet("dsm-certificate-id") {
				d.CertificateID = c.String("dsm-certificate-id")
				d.Default = false
			}
			if c.IsSet("dsm-default") {
				d.Default = c.Bool("dsm-default")
				if d.Default {
					d.CertificateID = ""
				}
			}
			request.Destinations[key] = d
		}
		if err := request.Validate(issuance); err != nil {
			return nil, fmt.Errorf("certificate %q: %w", id, err)
		}
		for _, dest := range request.Certificate.Destinations {
			if owner, ok := owners[dest]; ok && owner != id {
				return nil, fmt.Errorf("destination %q is selected for multiple certificates", dest)
			}
			owners[dest] = id
		}
		jobs = append(jobs, request)
	}
	return jobs, nil
}

func runLifecycle(ctx context.Context, c *urfave.Command, action string) error {
	cfg, root, environment, err := load(c)
	if err != nil {
		return err
	}
	resolvers := append([]string(nil), cfg.Resolvers...)
	if c.IsSet("resolver") {
		resolvers = c.StringSlice("resolver")
	}
	resolver, err := config.Resolver(resolvers)
	if err != nil {
		return err
	}
	options := app.Options{Resolver: resolver, PropagationTimeout: c.Duration("propagation-timeout")}
	if action != "deploy" && c.Duration("propagation-timeout") <= 0 {
		return errors.New("propagation-timeout must be positive")
	}
	service := app.New(root, options)
	jobs, err := requests(c, cfg, service, environment, action != "deploy")
	if err != nil {
		return err
	}
	if c.Duration("timeout") <= 0 {
		return errors.New("timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, c.Duration("timeout"))
	defer cancel()
	var combined error
	results := []app.Outcome{}
	for _, job := range jobs {
		jobOptions := options
		jobOptions.Progress = func(message string) { fmt.Fprintf(c.Root().ErrWriter, "[%s] %s\n", job.ID, message) }
		runner := app.New(root, jobOptions)
		jobOptions.Progress(fmt.Sprintf("Using state store %q (%s)", root, environment))
		if action != "deploy" {
			selection := "system configuration"
			if len(resolvers) > 0 {
				selection = strings.Join(resolvers, ", ")
			}
			jobOptions.Progress("DNS resolver: " + selection)
		}
		var outcome app.Outcome
		if action == "deploy" {
			outcome, err = runner.Deploy(ctx, job)
		} else {
			outcome, err = runner.Issue(ctx, job, app.RunOptions{Renew: action == "renew", Deploy: c.Bool("deploy"), Force: c.Bool("force")})
		}
		results = append(results, outcome)
		if err != nil {
			combined = errors.Join(combined, fmt.Errorf("certificate %q: %w", job.ID, err))
		}
		if !c.Bool("json") {
			status := outcome.State
			if err != nil {
				status = "failed"
			}
			generation := ""
			if outcome.GenerationID != "" {
				generation = ", generation " + outcome.GenerationID
			}
			if _, writeErr := fmt.Fprintf(c.Root().Writer, "%s: %s%s (%s)\n", job.ID, status, generation, environment); writeErr != nil {
				return writeErr
			}
			for _, d := range outcome.Deployments {
				if _, err := fmt.Fprintf(c.Root().Writer, "  %s: generation %s, completed=%t\n", d.DestinationID, d.GenerationID, d.Completed); err != nil {
					return err
				}
			}
		}
	}
	if c.Bool("json") {
		combined = errors.Join(combined, json.NewEncoder(c.Root().Writer).Encode(results))
	}
	return combined
}

func inspection(c *urfave.Command) (*app.Service, string, error) {
	_, root, environment, err := load(c)
	if err != nil {
		return nil, "", err
	}
	filter := ""
	if c.IsSet("environment") || c.IsSet("staging") {
		filter = environment
	}
	return app.New(root, app.Options{}), filter, nil
}

func inspectList(_ context.Context, c *urfave.Command) error {
	if c.Args().Present() {
		return errors.New("list does not accept positional arguments")
	}
	service, filter, err := inspection(c)
	if err != nil {
		return err
	}
	rows, err := service.List(filter)
	if err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Root().Writer).Encode(rows)
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(c.Root().Writer, "No stored certificates.")
		return err
	}
	w := tabwriter.NewWriter(c.Root().Writer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CERTIFICATE\tENVIRONMENT\tGENERATION\tEXPIRES (UTC)\tDNS NAMES\tDEPLOYMENTS")
	for _, row := range rows {
		status := []string{}
		for _, d := range row.Deployments {
			state := "pending"
			if d.Completed {
				state = "completed"
			}
			status = append(status, d.ID+":"+state+"@"+d.GenerationID)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", row.ID, row.Environment, row.GenerationID, row.NotAfter.UTC().Format(time.RFC3339), strings.Join(row.Domains, ", "), strings.Join(status, ", "))
	}
	return w.Flush()
}

func inspectShow(_ context.Context, c *urfave.Command) error {
	if c.Args().Len() != 1 {
		return errors.New("show requires one stored certificate ID")
	}
	service, filter, err := inspection(c)
	if err != nil {
		return err
	}
	rows, err := service.Show(c.Args().First(), filter)
	if err != nil {
		return err
	}
	if c.Bool("json") {
		return json.NewEncoder(c.Root().Writer).Encode(rows)
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(c.Root().Writer, "Certificate: %s\nEnvironment: %s\nGeneration: %s\nDNS names: %s\nValid from: %s\nExpires: %s\nValidated at: %s\nIssuer: %s\nPublic key: %s\nSHA-256: %s\nProvenance: %s %s\nIssuance pending: %t\n", row.ID, row.Environment, row.GenerationID, strings.Join(row.Domains, ", "), row.NotBefore.UTC().Format(time.RFC3339), row.NotAfter.UTC().Format(time.RFC3339), row.ValidatedAt.UTC().Format(time.RFC3339), row.Issuer, row.PublicKeyAlgorithm, row.Fingerprint, row.Provenance.Source, row.Provenance.Reference, row.IssuancePending); err != nil {
			return err
		}
		for _, d := range row.Deployments {
			if _, err := fmt.Fprintf(c.Root().Writer, "  Destination: %s (%s), generation: %s, completed: %t\n", d.ID, d.Type, d.GenerationID, d.Completed); err != nil {
				return err
			}
		}
	}
	return nil
}
