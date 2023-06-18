package endpoints

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/rokkerruslan/dnska/internal/limits"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/rs/zerolog"

	"github.com/rokkerruslan/dnska/internal/resolve"
	"github.com/rokkerruslan/dnska/pkg/proto"
)

func NewHTTPSEndpoint(params HTTPSEndpointParams) *HTTPSEndpoint {
	return &HTTPSEndpoint{
		addr:            params.Addr,
		resolver:        params.Resolver,
		certificatePath: params.CertificatePath,
		keyPath:         params.KeyPath,
		l:               params.L,
	}
}

type HTTPSEndpoint struct {
	addr            netip.AddrPort
	resolver        resolve.Resolver
	certificatePath string
	keyPath         string
	resolver2       resolve.ResolverV2
	l               zerolog.Logger

	onStop func()
}

type HTTPSEndpointParams struct {
	Addr            netip.AddrPort
	Resolver        resolve.Resolver
	CertificatePath string
	KeyPath         string
	L               zerolog.Logger
}

func (h *HTTPSEndpoint) Name() string {
	return "https"
}

func (h *HTTPSEndpoint) Start(onStop func()) {
	h.onStop = onStop

	http.HandleFunc("/dns-query", h.handleResolve)

	h.l.Printf("https :: starts on %v", h.addr)

	err := http.ListenAndServeTLS(h.addr.String(), "./configs/localhost.crt", "./configs/localhost.key", nil)
	if err != nil {
		h.l.Printf("https :: failed to start https endpoint, err=%v", err)
		return
	}
}

func (h *HTTPSEndpoint) Stop() error {
	h.onStop()

	return nil
}

func (h *HTTPSEndpoint) handleResolve(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		h.handleResolveGet(w, req)
	case "POST":
		h.handleResolvePost(w, req)
	default:
		h.WriteError(w, fmt.Sprintf("Unsupported method: %v, only GET or POST methods are supported", req.Method), http.StatusBadRequest)
	}
}

func (h *HTTPSEndpoint) handleResolveGet(w http.ResponseWriter, req *http.Request) {
	h.l.Printf("trace :: https :: handling GET request url:=%v", req.URL.String())

	query := req.URL.Query()

	msg := query.Get("dns")
	if msg == "" {
		h.WriteError(w, "\"dns\" query parameter is required", http.StatusBadRequest)
		return
	}

	startTs := time.Now()

	message, err := base64.RawURLEncoding.DecodeString(msg)
	if err != nil {
		h.l.Printf("https :: url decoding failed :: error=%v", err)
		h.WriteError(w, "url decoding failed", http.StatusBadRequest)
		return
	}

	h.l.Printf("%v", message)

	if len(message) > limits.UDPPayloadSizeLimit {
		h.WriteError(w, "dns message exceeded 512 byte", http.StatusRequestURITooLong)
		return
	}

	dec := proto.NewDecoder()
	inMsg, err := dec.Decode(message)
	if err != nil {
		packetDecodeErrorsTotal.Inc()
		h.l.Printf("https :: failed to decode message :: error=%v", err)
		h.WriteError(w, "failed to decode message", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outMsg, err := h.resolver.Resolve(ctx, inMsg)
	if err != nil {
		h.l.Printf("https :: failed to lookup :: error=%v", err)
		h.WriteError(w, "failed to lookup", http.StatusInternalServerError)
		return
	}

	enc := proto.NewEncoder(make([]byte, 512))

	buf, err := enc.Encode(outMsg)
	if err != nil {
		packetEncodeErrorsTotal.Inc()
		h.l.Printf("https :: failed to encode message :: error=%v", err)
		h.WriteError(w, "failed to encode message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprint(len(buf)))
	if _, err := w.Write(buf); err != nil {
		h.l.Printf("https :: failed to write response :: error=%v", err)
		return
	}

	h.l.Printf("trace :: https GET :: total time is %v :: q=%s", time.Since(startTs), inMsg.Question[0].Name)

	successesProcessedOpsTotal.Inc()
}

func (h *HTTPSEndpoint) handleResolvePost(w http.ResponseWriter, req *http.Request) {
	h.l.Printf("trace :: https :: handling POST request url:=%v", req.URL.String())

	startTs := time.Now()

	contentType := req.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		h.WriteError(w, "unsupported media type, only application/dns-message is supported", http.StatusUnsupportedMediaType)
		return
	}

	message, err := io.ReadAll(req.Body)
	if err != nil {
		h.l.Printf("https :: failed to read request body :: error=%v", err)
		h.WriteError(w, "failed to read body", http.StatusInternalServerError)
		return
	}

	if len(message) > limits.UDPPayloadSizeLimit {
		h.WriteError(w, "dns message exceeded 512 byte", http.StatusRequestEntityTooLarge)
		return
	}

	dec := proto.NewDecoder()
	inMsg, err := dec.Decode(message)
	if err != nil {
		packetDecodeErrorsTotal.Inc()
		h.l.Printf("https :: failed to decode message :: error=%v", err)
		h.WriteError(w, "failed to decode message", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outMsg, err := h.resolver.Resolve(ctx, inMsg)
	if err != nil {
		h.l.Printf("https :: failed to lookup :: error=%v", err)
		h.WriteError(w, "failed to lookup", http.StatusInternalServerError)
		return
	}

	enc := proto.NewEncoder(make([]byte, 512))

	buf, err := enc.Encode(outMsg)
	if err != nil {
		packetEncodeErrorsTotal.Inc()
		h.l.Printf("https :: failed to encode message :: error=%v", err)
		h.WriteError(w, "failed to encode message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprint(len(buf)))
	if _, err := w.Write(buf); err != nil {
		h.l.Printf("https :: failed to write response :: error=%v", err)
		return
	}

	h.l.Printf("trace :: https POST :: total time is %v :: q=%s", time.Since(startTs), inMsg.Question[0].Name)

	successesProcessedOpsTotal.Inc()
}

func (h *HTTPSEndpoint) WriteError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	if _, err := w.Write([]byte(msg)); err != nil {
		h.l.Printf("https :: failed to write response :: error=%v", err)
	}
}
