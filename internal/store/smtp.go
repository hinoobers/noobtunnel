package store

import (
	"errors"
	"net/mail"
	"strings"
)

// SMTPConfig is stored in auth.json, which is readable only by the server.
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
}

func (c *SMTPConfig) Validate() error {
	c.Host = strings.TrimSpace(c.Host)
	c.Username = strings.TrimSpace(c.Username)
	c.From = strings.TrimSpace(c.From)
	if c.Host == "" && c.Port == 0 && c.Username == "" && c.Password == "" && c.From == "" {
		return nil
	}
	if c.Host == "" || strings.ContainsAny(c.Host, "/:@ \r\n\t") {
		return errors.New("store: enter a valid SMTP host")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("store: enter a valid SMTP port")
	}
	if c.Security != "tls" && c.Security != "starttls" {
		return errors.New("store: SMTP requires TLS or STARTTLS")
	}
	if c.Username == "" || c.Password == "" {
		return errors.New("store: SMTP username and password are required")
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil || from.Address != c.From || strings.ContainsAny(c.From, "\r\n") {
		return errors.New("store: enter a valid sender address")
	}
	return nil
}

func (a *Auth) SMTP() SMTPConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.st.SMTP
}

func (a *Auth) SetSMTP(cfg SMTPConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.SMTP = cfg
	return a.saveLocked()
}
