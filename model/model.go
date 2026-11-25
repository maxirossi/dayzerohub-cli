// Package model define el modelo de resultados de mateprobe.
//
// Se mantienen separados: el resultado del objetivo (TargetResult), las
// respuestas HTTP observadas (Response), los hallazgos tecnológicos
// (Technology) y los errores (Error). Es el contrato JSON versionado que
// consumirán integraciones futuras (p. ej. MateAudit).
package model

import "time"

// SchemaVersion identifica la versión del esquema JSON. Se incrementa ante
// cambios incompatibles.
const SchemaVersion = "1.0"

// Estados de un objetivo. Distinguen tres situaciones diferentes:
//   - StatusUnreachable: no se pudo consultar (ninguna respuesta HTTP).
//   - StatusNoTechnologies: hubo respuesta, pero no se detectó nada.
//   - StatusDetected: se detectaron tecnologías.
//
// StatusIncomplete se usa cuando la ejecución se interrumpió antes de terminar.
const (
	StatusUnreachable    = "unreachable"
	StatusNoTechnologies = "no_technologies"
	StatusDetected       = "detected"
	StatusIncomplete     = "incomplete"
)

// Tipos de detección.
const (
	DetectionDeclared  = "declared"  // la respuesta lo declara explícitamente (p. ej. Server: nginx/1.24.0)
	DetectionSignature = "signature" // una firma/patrón coincidió con el contenido
	DetectionInferred  = "inferred"  // deducido de otra tecnología; nunca observado directamente
)

// Niveles de confianza cualitativa.
const (
	ConfidenceHigh    = "high"
	ConfidenceMedium  = "medium"
	ConfidenceLow     = "low"
	ConfidenceUnknown = "unknown"
)

// Clases de error.
const (
	ErrDNS        = "dns"
	ErrConnection = "connection"
	ErrTimeout    = "timeout"
	ErrTLS        = "tls"
	ErrHTTP       = "http"
	ErrCanceled   = "canceled"
	ErrOther      = "other"
)

// Report es el resultado completo de una ejecución.
type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          ToolInfo       `json:"tool"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    time.Time      `json:"finished_at"`
	Interrupted   bool           `json:"interrupted"`
	NotStarted    int            `json:"not_started"` // objetivos que no llegaron a procesarse
	Settings      Settings       `json:"settings"`
	Summary       Summary        `json:"summary"`
	Targets       []TargetResult `json:"targets"`
}

// ToolInfo identifica el programa que generó el reporte.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Engine  string `json:"engine"` // motor de firmas utilizado
}

// Settings refleja la configuración efectiva relevante para interpretar el reporte.
type Settings struct {
	Concurrency    int     `json:"concurrency"`
	RatePerSecond  float64 `json:"rate_per_second"`
	TimeoutSeconds float64 `json:"timeout_seconds"`
	MaxRedirects   int     `json:"max_redirects"`
	MaxBodyBytes   int64   `json:"max_body_bytes"`
	MaxAddresses   int     `json:"max_addresses"`
	// TLSValidationDisabled es true si se usó --insecure: los certificados NO se validaron.
	TLSValidationDisabled bool     `json:"tls_validation_disabled"`
	FollowExternal        bool     `json:"follow_external_redirects"`
	AllowedHosts          []string `json:"allowed_hosts,omitempty"`
	Excluded              []string `json:"excluded,omitempty"`
	Resolve               []string `json:"resolve,omitempty"`
	Ports                 []string `json:"ports,omitempty"`
}

// Summary agrega contadores por estado.
type Summary struct {
	Targets        int `json:"targets"`
	Detected       int `json:"detected"`
	NoTechnologies int `json:"no_technologies"`
	Unreachable    int `json:"unreachable"`
	Incomplete     int `json:"incomplete"`
	Technologies   int `json:"technologies"`
	Errors         int `json:"errors"`
}

// TargetResult es el resultado de un objetivo expandido.
type TargetResult struct {
	Input        string       `json:"input"`  // texto original (o la expresión de la que proviene)
	Target       string       `json:"target"` // objetivo normalizado
	Status       string       `json:"status"`
	Responses    []Response   `json:"responses"`
	Technologies []Technology `json:"technologies"`
	Errors       []Error      `json:"errors"`
}

// Response es una respuesta HTTP observada (una por salto de la cadena).
type Response struct {
	Hop           int                 `json:"hop"` // 0 = solicitud inicial
	IsFinal       bool                `json:"is_final"`
	InitialURL    string              `json:"initial_url"`   // URL con la que arrancó la cadena
	RequestedURL  string              `json:"requested_url"` // URL solicitada en este salto
	FinalURL      string              `json:"final_url"`     // última URL de la cadena
	Chain         []string            `json:"chain"`         // URLs solicitadas, en orden
	RemoteIP      string              `json:"remote_ip,omitempty"`
	Status        int                 `json:"status"`
	ContentType   string              `json:"content_type,omitempty"`
	Title         string              `json:"title,omitempty"`
	Headers       map[string][]string `json:"headers"`
	DurationMS    int64               `json:"duration_ms"`
	BodyBytes     int64               `json:"body_bytes"`
	BodyTruncated bool                `json:"body_truncated"`
	Redirect      *Redirect           `json:"redirect,omitempty"`
	TLS           *TLSInfo            `json:"tls,omitempty"`
}

// Redirect describe una redirección recibida en una respuesta.
type Redirect struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
	Followed bool   `json:"followed"`
	Reason   string `json:"reason"` // motivo cuando no se siguió, o "same_host"/"allowed"
}

// TLSInfo contiene datos TLS básicos.
type TLSInfo struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	ServerName  string    `json:"server_name"` // SNI enviado
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	// Verified es true solo si la cadena y el nombre se validaron.
	Verified bool `json:"verified"`
	// ValidationDisabled es true cuando se ejecutó con --insecure.
	ValidationDisabled bool `json:"validation_disabled"`
}

// Technology es un hallazgo tecnológico asociado a una respuesta concreta.
type Technology struct {
	Name         string     `json:"name"`
	Category     string     `json:"category"`
	Categories   []string   `json:"categories,omitempty"`
	Version      string     `json:"version,omitempty"` // vacío = desconocida
	Detection    string     `json:"detection"`
	Confidence   string     `json:"confidence"`
	Engine       string     `json:"engine"` // motor y/o regla responsable
	Evidence     []Evidence `json:"evidence"`
	EvidenceNote string     `json:"evidence_note,omitempty"`
	URL          string     `json:"url"`  // URL de la respuesta donde se observó
	Host         string     `json:"host"` // hostname de esa respuesta
	// External es true si el hostname observado difiere del objetivo.
	External bool `json:"external"`
}

// Evidence es un fragmento sanitizado que respalda una detección.
type Evidence struct {
	Source  string `json:"source"`            // header, cookie, meta, html, resource, inference
	Name    string `json:"name,omitempty"`    // nombre de cabecera/cookie/etc.
	Snippet string `json:"snippet,omitempty"` // fragmento acotado y sanitizado
}

// Error es un fallo clasificado.
type Error struct {
	Class   string `json:"class"`
	URL     string `json:"url"`
	Message string `json:"message"`
}
