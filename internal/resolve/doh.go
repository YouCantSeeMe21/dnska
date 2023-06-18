package resolve

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/rokkerruslan/dnska/internal/limits"
	"github.com/rokkerruslan/dnska/pkg/proto"
	"github.com/rs/zerolog"
	"io"
	"net/http"
	"net/url"
)

type DoHResolverOpts struct {
	l zerolog.Logger
}

// DoHResolver is DNS over HTTPS resolver
// https://datatracker.ietf.org/doc/html/rfc8484
type DoHResolver struct {
	l zerolog.Logger
}

func NewDoHResolver(l zerolog.Logger) *DoHResolver {
	return &DoHResolver{
		l: l,
	}
}

func (dohr *DoHResolver) Resolve(ctx context.Context, in proto.Message) (proto.Message, error) {
	enc := proto.NewEncoder(make([]byte, limits.UDPPayloadSizeLimit))

	outBuf, err := enc.Encode(in)
	if err != nil {
		return proto.Message{}, fmt.Errorf("failed to encode: %v", err)
	}

	params := url.Values{}
	params.Add("dns", base64.RawURLEncoding.EncodeToString(outBuf))

	headers := http.Header{}
	headers.Add("accept", "application/dns-message")

	req := &http.Request{
		Method: http.MethodGet,
		Header: headers,
		URL: &url.URL{
			Scheme:   "https",
			Host:     "dns.google",
			Path:     "/dns-query",
			RawQuery: params.Encode(),
		},
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return proto.Message{}, fmt.Errorf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proto.Message{}, fmt.Errorf("unexpected response code: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return proto.Message{}, fmt.Errorf("failed to read body: %v", err)
	}

	dec := proto.NewDecoder()

	outMsg, err := dec.Decode(body)
	if err != nil {
		return proto.Message{}, fmt.Errorf("failed to decode body: %v", err)
	}

	dohr.l.Printf("https resolver finished")

	return outMsg, nil
}
