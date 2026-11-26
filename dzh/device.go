package dzh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
	"io"
	"net/http"
	"net/url"
)

// Autorización de dispositivo (`mateprobe login`): el CLI no maneja contraseñas ni captcha; el usuario aprueba el
// código en el panel de DayZeroHub (ya logueado) y el CLI canjea el device_code por su API key personal.
const (
	devicePath      = "/api/cli/device"
	deviceTokenPath = "/api/cli/device/token"
)

// ErrPending indica que el usuario todavía no aprobó el código.
var ErrPending error = pendingError{}

// ErrExpired indica que el código venció o ya fue canjeado.
var ErrExpired error = expiredError{}

// pendingError y expiredError son los centinelas ErrPending/ErrExpired; su texto se resuelve al usarlos, con el idioma ya fijado.
type pendingError struct{}

func (pendingError) Error() string {
	return i18n.Tr("autorización pendiente", "authorization pending")
}

type expiredError struct{}

func (expiredError) Error() string {
	return i18n.Tr("el código venció; ejecutá `mateprobe login` de nuevo", "the code expired; run `mateprobe login` again")
}

// Device es la respuesta de StartDevice.
type Device struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) (int, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Host == "" {
		return 0, errors.New(i18n.Tr("URL base inválida", "invalid base URL"))
	}
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.JoinPath(path).String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf(i18n.Tr("error de red: %w", "network error: %w"), err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 == 2 && out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf(i18n.Tr("JSON inválido en la respuesta: %w", "invalid JSON in the response: %w"), err)
		}
	}
	return resp.StatusCode, nil
}

// StartDevice pide un código de autorización para esta instalación.
func (c *Client) StartDevice(ctx context.Context, name string) (Device, error) {
	var d Device
	st, err := c.postJSON(ctx, devicePath, map[string]string{"name": name}, &d)
	if err != nil {
		return d, err
	}
	if st == http.StatusTooManyRequests {
		return d, errors.New(i18n.Tr("demasiados intentos; esperá un rato y reintentá", "too many attempts; wait a while and try again"))
	}
	if st != http.StatusCreated || d.DeviceCode == "" {
		return d, &Error{st, i18n.Tr("no se pudo iniciar la autorización", "could not start the authorization")}
	}
	return d, nil
}

// PollDevice canjea el device_code. Devuelve ErrPending mientras el usuario no apruebe.
func (c *Client) PollDevice(ctx context.Context, deviceCode string) (string, error) {
	var out struct {
		APIKey string `json:"api_key"`
	}
	st, err := c.postJSON(ctx, deviceTokenPath, map[string]string{"device_code": deviceCode}, &out)
	if err != nil {
		return "", err
	}
	switch {
	case st == http.StatusOK && out.APIKey != "":
		return out.APIKey, nil
	case st == http.StatusPreconditionRequired:
		return "", ErrPending
	case st == http.StatusGone:
		return "", ErrExpired
	case st == http.StatusTooManyRequests:
		return "", ErrPending // seguimos esperando; el intervalo ya es prudente
	}
	return "", &Error{st, i18n.Tr("respuesta inesperada al canjear el código", "unexpected response when exchanging the code")}
}
