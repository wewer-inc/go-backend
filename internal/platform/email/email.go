package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
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
	Mode     config.SMTPMode
}

const (
	defaultSendTimeout = 10 * time.Second
	maxSendAttempts    = 3
)

// SMTPMailer sends real emails via SMTP.
type SMTPMailer struct {
	cfg Config
}

func NewSMTPMailer(cfg Config) *SMTPMailer {
	if cfg.Mode == "" {
		cfg.Mode = config.SMTPStartTLS
	}
	return &SMTPMailer{cfg: cfg}
}

// Send delivers an email, honouring the context deadline and retrying transient
// failures with backoff. If ctx has no deadline, a default timeout is applied so
// a hung SMTP server can never block the caller indefinitely.
func (m *SMTPMailer) Send(ctx context.Context, to, subject, htmlBody string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultSendTimeout)
		defer cancel()
	}

	var lastErr error
	for attempt := 1; attempt <= maxSendAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = m.sendOnce(ctx, to, subject, htmlBody)
		if lastErr == nil {
			return nil
		}

		// Backoff before the next attempt, but never past the context deadline.
		if attempt < maxSendAttempts {
			backoff := time.Duration(attempt) * 500 * time.Millisecond
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("smtp: send failed after %d attempts: %w", maxSendAttempts, lastErr)
}

func (m *SMTPMailer) sendOnce(ctx context.Context, to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}

	msg := []byte(
		"From: " + m.cfg.From + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" +
			htmlBody,
	)

	// Dial with the context so connection setup respects the deadline.
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	// Apply the context deadline to all subsequent socket I/O.
	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	var conn net.Conn = rawConn
	if m.cfg.Mode == config.SMTPImplicitTLS {
		conn = tls.Client(rawConn, tlsCfg)
	}

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	// For STARTTLS, upgrade the plaintext connection before doing anything that
	// transmits credentials. Refuse to continue if the server won't upgrade.
	secured := m.cfg.Mode == config.SMTPImplicitTLS
	if m.cfg.Mode == config.SMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp: server does not advertise STARTTLS (mode=%s)", m.cfg.Mode)
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
		secured = true
	}

	// Never send credentials over an unencrypted connection.
	if m.cfg.Password != "" {
		if !secured {
			return fmt.Errorf("smtp: refusing to authenticate over plaintext (mode=%s); use starttls or implicit_tls", m.cfg.Mode)
		}
		auth := smtp.PlainAuth("", m.cfg.From, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
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
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return client.Quit()
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
