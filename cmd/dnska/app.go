package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/rokkerruslan/dnska/internal/app"
)

func NewAppCommand(l zerolog.Logger) *cobra.Command {
	var opts struct {
		EndpointsFilePath      string
		Resolver               string
		SSLCertificateFilePath string
		SSLKeyFilePath         string
	}

	cmd := cobra.Command{
		Use:   "app",
		Short: "Run DNS server application",
		RunE: func(cmd *cobra.Command, args []string) error {
			signals := make(chan os.Signal, 1)
			defer close(signals)
			defer signal.Stop(signals)

			signal.Notify(signals, os.Interrupt)
			defer signal.Reset(os.Interrupt)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			application, err := app.New(app.Opts{
				EndpointsFilePath:      opts.EndpointsFilePath,
				Resolver:               opts.Resolver,
				SSLCertificateFilePath: opts.SSLCertificateFilePath,
				SSLKeyFilePath:         opts.SSLKeyFilePath,

				L: l,
			})
			if err != nil {
				return err
			}

			go func() {
				defer cancel()
				defer application.Shutdown()

				<-signals
			}()

			if err := application.Run(ctx); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&opts.EndpointsFilePath, "endpoints-file-path", "./configs/endpoints.example.toml",
		"path to endpoints configuration on OS filesystem")
	cmd.Flags().StringVar(&opts.SSLCertificateFilePath, "ssl-certificate-file-path", "./configs/localhost.crt",
		"path to SSL certificate for on OS filesystem for HTTPS endpoint")
	cmd.Flags().StringVar(&opts.SSLKeyFilePath, "ssl-key-file-path", "./configs/localhost.key",
		"path to SSL key on OS filesystem for HTTPS endpoint")
	cmd.Flags().StringVar(&opts.Resolver, "resolver", "udp",
		"type of resolver to use, udp - use iterative udp resolver, doh - use dns over https resolver")

	return &cmd
}
