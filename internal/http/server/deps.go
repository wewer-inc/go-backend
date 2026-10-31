package httpserver

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/email"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/objectstore"
	redisstore "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/redis"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/worker"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type Deps struct {
	Cfg      config.Config
	Log      zerolog.Logger
	DB       *gorm.DB
	ObjStore objectstore.Store
	Redis    *redisstore.Client
	Worker   *worker.Worker
	Mailer   email.Mailer
}
