package dzh

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// UsageEvent es el resumen mínimo que mateprobe envía al terminar un `audit`: solo conteos y datos del cliente.
// NUNCA incluye rutas, nombres de proyecto, nombres de paquetes, versiones ni los avisos encontrados.
type UsageEvent struct {
	ClientVersion string `json:"client_version"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Command       string `json:"command"`
	Status        string `json:"status"`               // complete | partial
	ProjectID     string `json:"project_id,omitempty"` // hash truncado, no reversible a una ruta
	Components    int    `json:"components"`
	Advisories    int    `json:"advisories"`
	Affected      int    `json:"affected"`
	Undetermined  int    `json:"undetermined"`
	OutOfRange    int    `json:"out_of_range"`
}

// ReportUsage envía el resumen. Es de mejor esfuerzo: el llamador ignora el error.
func (c *Client) ReportUsage(ctx context.Context, e UsageEvent) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Host == "" {
		return err
	}
	body, _ := json.Marshal(e)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.JoinPath(usagePath).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(apiKeyHeader, c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}
