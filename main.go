package main

import (
	"crypto"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/go-logr/zapr"
	"github.com/jlewi/hmacproxy/pkg/hmacauth"
	"github.com/jlewi/hydros/pkg/util"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/spf13/cobra"
)

const (
	GitHubHeader = "X-Hub-Signature-256"
)

func newRootCmd() *cobra.Command {
	var level string
	var jsonLog bool
	var file string
	opts := &HmacProxyOpts{
		// This is the algorithm used by github
		// TODO(jeremu): I don't think we can get rid of this. Its only used by the code paths that sign requests
		// and we want to remove that functionality from the proxy.
		Digest: HmacProxyDigest{
			Name: "sha256",
			ID:   crypto.SHA256,
		},
	}
	rootCmd := &cobra.Command{
		Short: "hmac proxy service",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			util.SetupLogger(level, !jsonLog)
		},
		Run: func(cmd *cobra.Command, args []string) {
			log := zapr.NewLogger(zap.L())

			err := func() error {
				if err := opts.Validate(); err != nil {
					return err
				}

				address := ":" + strconv.Itoa(opts.Port)

				f, err := os.Open(file)
				if err != nil {
					return errors.Wrapf(err, "Could not open mappings file %v", file)
				}

				d := yaml.NewDecoder(f)

				if err := d.Decode(&opts.Mappings); err != nil {
					return errors.Wrapf(err, "Could not decode Mappings object from file %v", file)
				}

				handler, err := NewHTTPProxyHandler(opts)
				if err != nil {
					return err
				}
				server := &http.Server{Addr: address, Handler: handler}
				log.Info("starting hmacproxy server", "address", address)

				if opts.SslCert != "" {
					err = server.ListenAndServeTLS(opts.SslCert, opts.SslKey)
				} else {
					err = server.ListenAndServe()
				}
				return err
			}()
			if err != nil {
				fmt.Printf("hmacproxy failed with error: %+v", err)
				os.Exit(1)
			}
		},
	}

	rootCmd.PersistentFlags().StringVarP(&level, "level", "", "info", "The logging level.")
	rootCmd.PersistentFlags().BoolVarP(&jsonLog, "json-logs", "", true, "Enable json logging.")

	rootCmd.Flags().IntVarP(&opts.Port, "port", "", 0, "Port on which to listen for requests")
	rootCmd.Flags().StringVarP(&opts.Secret, "secret", "", "", "Secret key")
	rootCmd.Flags().StringVarP(&opts.SignHeader, "sign-header", "", GitHubHeader, "Header containing request signature")

	rootCmd.Flags().StringVarP(&file, "mappings", "m", "", "YAML file containing the Mappings listing the proxied paths")
	rootCmd.Flags().StringVar(&opts.SslCert, "ssl-cert", "", "Path to the server's SSL certificate")
	rootCmd.Flags().StringVar(&opts.SslKey, "ssl-key", "", "Path to the key for -ssl-cert")

	rootCmd.MarkFlagRequired("secret")
	rootCmd.MarkFlagRequired("mappings")

	return rootCmd
}

func newComputeHMAC() *cobra.Command {
	opts := &HmacProxyOpts{
		// Always set Auth to true; signing requests is no longer supported
		// This is the algorithm used by github
		// TODO(jeremu): I don't think we can get rid of this. Its only used by the code paths that sign requests
		// and we want to remove that functionality from the proxy.
		Digest: HmacProxyDigest{
			Name: "sha256",
			ID:   crypto.SHA256,
		},
		Port: 8080,

		SignHeader: GitHubHeader,
	}
	var file string
	cmd := &cobra.Command{
		Use:   "compute",
		Short: "compute the hmac of the given file",
		Run: func(cmd *cobra.Command, args []string) {

			err := func() error {
				if err := opts.Validate(); err != nil {
					return err
				}

				auth := hmacauth.NewHmacAuth(opts.Digest.ID, []byte(opts.Secret), "someheader", nil, true)
				f, err := os.Open(file)
				if err != nil {
					return errors.Wrapf(err, "could not read path %v", file)
				}

				req, err := http.NewRequest("POST", "doesn't, matter", f)
				if err != nil {
					return err
				}
				sig := auth.RequestSignature(req)
				fmt.Printf("Signture:\n%v", sig)
				return err
			}()
			if err != nil {
				fmt.Printf("hmacproxy failed with error: %v", err)
			}
		},
	}

	cmd.Flags().StringVarP(&opts.Secret, "secret", "", "", "Secret key")
	cmd.Flags().StringVar(&file, "file", "f", "The file containing the payload to comput the signature off")

	return cmd
}

func main() {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(newComputeHMAC())
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Command failed with error: %+v", err)
		os.Exit(1)
	}
}
