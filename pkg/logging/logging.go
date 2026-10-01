package logging

import (
	"os"
	"time"

	"github.com/charmbracelet/log"
)

var (
	consoleLogger *log.Logger
)

func InitLogger(verbose int) {
	logLevel := log.InfoLevel
	if verbose > 0 {
		logLevel = log.DebugLevel
	}

	consoleLogger = log.NewWithOptions(os.Stderr, log.Options{
		Level:      logLevel,
		TimeFormat: time.Kitchen,
	})
}

func GetLogger() *log.Logger {
	if consoleLogger == nil {
		consoleLogger = log.New(os.Stderr)
	}
	return consoleLogger
}
