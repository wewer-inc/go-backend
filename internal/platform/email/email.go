package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"

	"github.com/rs/zerolog"
)

// Mailer sends transactional emails.
type Mailer interface {
	Send(ctx context.Context, to, subject, htmlBody string) error
}

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     int
	From     string
	Password string
	UseTLS   bool
}

// SMTPMailer sends real emails via SMTP.
type SMTPMailer struct {
	cfg Config
}

func NewSMTPMailer(cfg Config) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

func (m *SMTPMailer) Send(_ context.Context, to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.From, m.cfg.Password, m.cfg.Host)

	msg := []byte(
		"From: " + m.cfg.From + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" +
			htmlBody,
	)

	if m.cfg.UseTLS {
		tlsCfg := &tls.Config{ServerName: m.cfg.Host} //nolint:gosec
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
		if err := client.Mail(m.cfg.From); err != nil {
			return fmt.Errorf("smtp mail: %w", err)
		}
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("smtp rcpt: %w", err)
		}
		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		defer w.Close()
		if _, err := w.Write(msg); err != nil {
			return fmt.Errorf("smtp write: %w", err)
		}
		return nil
	}

	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, msg)
}

// NoopMailer logs emails instead of sending — use in development.
type NoopMailer struct {
	log zerolog.Logger
}

func NewNoopMailer(log zerolog.Logger) *NoopMailer {
	return &NoopMailer{log: log}
}

func (m *NoopMailer) Send(_ context.Context, to, subject, _ string) error {
	m.log.Info().
		Str("to", to).
		Str("subject", subject).
		Msg("email: (noop) would have sent email")
	return nil
}
