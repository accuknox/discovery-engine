package logging

import (
	"io"
	"os"
	"path"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config - Custom application config
type Config struct {
	ConsoleLoggingEnabled bool   // Enable console logging
	EncodeLogsAsJSON      bool   // EncodeLogsAsJSON makes the log framework log JSON
	FileLoggingEnabled    bool   // FileLoggingEnabled makes the framework log to a file, the fields below can be skipped if this value is false!
	Directory             string // Directory to log to to when filelogging is enabled
	Filename              string // Filename is the name of the logfile which will be placed inside the directory
	MaxSize               int    // MaxSize the max size in MB of the logfile before it's rolled
	MaxBackups            int    // MaxBackups the max number of rolled files to keep
	MaxAge                int    // MaxAge the max age in days to keep a logfile
	Compress              bool   // Compress the rotated files
}

func configure(config Config) *zerolog.Logger {
	var writers []io.Writer

	if config.ConsoleLoggingEnabled {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true})
	}
	if config.FileLoggingEnabled {
		writers = append(writers, newRollingFile(config))
	}
	mw := io.MultiWriter(writers...)

	logger := zerolog.New(mw).With().Timestamp().Caller().Logger()

	logger.Info().
		Bool("fileLogging", config.FileLoggingEnabled).
		Bool("jsonLogOutput", config.EncodeLogsAsJSON).
		Str("logDirectory", config.Directory).
		Str("fileName", config.Filename).
		Int("maxSizeMB", config.MaxSize).
		Int("maxBackups", config.MaxBackups).
		Int("maxAgeInDays", config.MaxAge).
		Msg("logging configured")

	return &logger
}

func newRollingFile(config Config) io.Writer {
	if err := os.MkdirAll(config.Directory, 0744); err != nil {
		log.Error().Err(err).Str("path", config.Directory).Msg("can't create log directory")
		return nil
	}

	return &lumberjack.Logger{
		Filename:   path.Join(config.Directory, config.Filename),
		MaxBackups: config.MaxBackups, // files
		MaxSize:    config.MaxSize,    // megabytes
		MaxAge:     config.MaxAge,     // days
		Compress:   config.Compress,
	}
}

var customLogger *zerolog.Logger
var once sync.Once

func SetLogLevel(logLevel string) {
	switch logLevel {
	case "TRACE":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "DEBUG":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "INFO":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "ERROR":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "FATAL":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "PANIC":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "NO":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case "DISABLED":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}

func GetInstance() *zerolog.Logger {
	once.Do(func() {
		config := Config{
			ConsoleLoggingEnabled: true,
			EncodeLogsAsJSON:      false,
			FileLoggingEnabled:    false,
			Directory:             "log",
			Filename:              "service.log",
			MaxSize:               10,
			MaxBackups:            5,
			MaxAge:                5,
			Compress:              true,
		}
		customLogger = configure(config)
	})
	return customLogger
}
