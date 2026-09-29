package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func (s *Server) handleSMTP(w http.ResponseWriter, r *http.Request) {
	if !principalFrom(r).canAdmin() {
		writeJSON(w, http.StatusForbidden, errBody("only admins can configure SMTP"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := s.auth.SMTP()
		writeJSON(w, http.StatusOK, map[string]any{"smtp": smtpView(cfg)})
	case http.MethodPost:
		var body struct {
			Host          string `json:"host"`
			Port          int    `json:"port"`
			Security      string `json:"security"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			From          string `json:"from"`
			TestRecipient string `json:"testRecipient"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		previous := s.auth.SMTP()
		cfg := store.SMTPConfig{Host: body.Host, Port: body.Port, Security: body.Security, Username: body.Username, Password: body.Password, From: body.From}
		if cfg.Password == "" {
			cfg.Password = previous.Password
		}
		if err := cfg.Validate(); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if body.TestRecipient != "" {
			if err := sendSMTP(r.Context(), cfg, body.TestRecipient, "noobtunnel SMTP test", "Noobtunnel can send email through this SMTP connection.\n"); err != nil {
				writeJSON(w, http.StatusBadGateway, errBody("SMTP test failed: "+err.Error()))
				return
			}
		}
		if err := s.auth.SetSMTP(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not save SMTP settings"))
			return
		}
		s.recordEvent("settings", "SMTP settings updated")
		writeJSON(w, http.StatusOK, map[string]any{"smtp": smtpView(cfg), "tested": body.TestRecipient != ""})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

func smtpView(c store.SMTPConfig) map[string]any {
	return map[string]any{"host": c.Host, "port": c.Port, "security": c.Security, "username": c.Username, "from": c.From, "hasPassword": c.Password != "", "configured": c.Host != ""}
}

func sendSMTP(ctx context.Context, cfg store.SMTPConfig, recipient, subject, body string) error {
	if err := store.ValidateEmailForSMTP(recipient); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if cfg.Security == "tls" {
		secure := tls.Client(conn, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
		if err := secure.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = secure
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if cfg.Security == "starttls" {
		if err := client.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
		return err
	}
	if err := client.Mail(cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(recipient); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	message := "From: " + cfg.From + "\r\nTo: " + recipient + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n")
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
