package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	endpoints2 "github.com/rokkerruslan/dnska/internal/endpoints"
	resolve2 "github.com/rokkerruslan/dnska/internal/resolve"
)

type Opts struct {
	EndpointsFilePath      string
	Resolver               string
	SSLCertificateFilePath string
	SSLKeyFilePath         string

	L zerolog.Logger
}

type App struct {
	endpoints []endpoints2.Endpoint

	l zerolog.Logger
}

func New(opts Opts) (*App, error) {
	endpointsList, err := setup(opts)
	if err != nil {
		return nil, err
	}

	return &App{
		endpoints: endpointsList,
		l:         opts.L,
	}, nil
}

func (a *App) Run(_ context.Context) error {
	if err := a.bootstrap(); err != nil {
		return fmt.Errorf("failed to bootstrap: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(len(a.endpoints))

	for i := range a.endpoints {
		endpoint := a.endpoints[i]

		go func() {
			endpoint.Start(wg.Done)
		}()
	}

	wg.Wait()

	return nil
}

func (a *App) Shutdown() {
	for _, endpoint := range a.endpoints {
		if err := endpoint.Stop(); err != nil {
			a.l.Printf("failed to stop endpoint %s :: error=%s", endpoint.Name(), err)
		}
	}
}

func (a *App) bootstrap() error {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	go func() {
		err := http.ListenAndServe(":8888", mux) // todo: use same server for https
		if err != nil {
			a.l.Printf("listen and serve error: %v", err)
		}
	}()

	return nil
}

type endpointsFileConfigurationV0 struct {
	LocalAddress      string `toml:"local-address"`
	LocalAddressHTTPS string `toml:"local-address-https"`
}

func (efc endpointsFileConfigurationV0) InstantiateEndpoints(l zerolog.Logger, resolv, sslCertificateFilePath, sslKeyFilePath string) ([]endpoints2.Endpoint, error) {
	var resolver resolve2.Resolver
	switch resolv {
	case "udp":
		resolver = resolve2.NewCacheResolver( // todo: choose resolver on start
			resolve2.NewBlacklistResolver(resolve2.BlacklistResolverOpts{
				AutoReloadInterval: time.Hour,
				BlacklistURL:       "http://github.com/black",
				Pass: resolve2.NewChainResolver(
					l,
					resolve2.NewStaticResolver(l),
					resolve2.NewIterativeResolver(l)),
			}))
	case "doh":
		resolver = resolve2.NewCacheResolver(
			resolve2.NewBlacklistResolver(resolve2.BlacklistResolverOpts{
				AutoReloadInterval: time.Hour,
				BlacklistURL:       "http://github.com/black",
				Pass: resolve2.NewChainResolver(
					l,
					resolve2.NewStaticResolver(l),
					resolve2.NewDoHResolver(l)),
			}))
	default:
		return nil, fmt.Errorf("invalid resolver type: %s, available resolvers are udp, doh", resolv)
	}

	udpLocalAddr, err := netip.ParseAddrPort(efc.LocalAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local addr: %v", err)
	}
	httpsLocalAddr, err := netip.ParseAddrPort(efc.LocalAddressHTTPS)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve https local addr: %v", err)
	}
	tcpLocalAddr := udpLocalAddr

	httpsParams := endpoints2.HTTPSEndpointParams{
		Addr:            httpsLocalAddr,
		Resolver:        resolver,
		CertificatePath: sslCertificateFilePath,
		KeyPath:         sslKeyFilePath,
		L:               l,
	}

	endpoints := []endpoints2.Endpoint{endpoints2.NewUDPEndpoint(udpLocalAddr, resolver, l),
		endpoints2.NewTCPEndpoint(tcpLocalAddr, resolver, l), endpoints2.NewHTTPSEndpoint(httpsParams)}
	return endpoints, nil
}

func setup(opts Opts) ([]endpoints2.Endpoint, error) {
	var config endpointsFileConfigurationV0
	if _, err := toml.DecodeFile(opts.EndpointsFilePath, &config); err != nil {
		return nil, err
	}

	return config.InstantiateEndpoints(opts.L, opts.Resolver, opts.SSLCertificateFilePath, opts.SSLKeyFilePath)
}
