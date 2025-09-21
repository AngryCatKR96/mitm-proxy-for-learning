package global

import (
	"sync"

	"vpn-mitm-proxy/internal/logger"
)

// Global logger instance
var (
	globalLogger *logger.Logger
	once         sync.Once
	mu           sync.RWMutex
)

// InitLogger initializes the global logger
func InitLogger(level string, logFile string) error {
	var err error
	once.Do(func() {
		globalLogger, err = logger.NewLogger(level, logFile)
	})
	return err
}

// GetLogger returns the global logger instance
func GetLogger() *logger.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return globalLogger
}

// SetLogger sets the global logger instance (for testing)
func SetLogger(l *logger.Logger) {
	mu.Lock()
	defer mu.Unlock()
	globalLogger = l
}

// Convenience functions for logging
func Debug(format string, args ...interface{}) {
	if l := GetLogger(); l != nil {
		l.Debug(format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if l := GetLogger(); l != nil {
		l.Info(format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if l := GetLogger(); l != nil {
		l.Warn(format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if l := GetLogger(); l != nil {
		l.Error(format, args...)
	}
}

// Close closes the global logger
func Close() error {
	if l := GetLogger(); l != nil {
		return l.Close()
	}
	return nil
}

// IsInitialized checks if the logger is initialized
func IsInitialized() bool {
	return GetLogger() != nil
}
