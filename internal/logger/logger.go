package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

type Logger struct {
	level    LogLevel
	infoLog  *log.Logger
	errorLog *log.Logger
	file     *os.File
	mutex    sync.Mutex
}

func NewLogger(level string, logFile string) (*Logger, error) {
	var logLevel LogLevel
	switch level {
	case "DEBUG":
		logLevel = DEBUG
	case "INFO":
		logLevel = INFO
	case "WARN":
		logLevel = WARN
	case "ERROR":
		logLevel = ERROR
	default:
		logLevel = INFO
	}

	logger := &Logger{
		level: logLevel,
	}

	if logFile != "" {
		// 로그 디렉토리가 없으면 생성
		dir := filepath.Dir(logFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %v", err)
		}

		// 로그 파일 열기
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}

		logger.file = file
		logger.infoLog = log.New(file, "", 0)
		logger.errorLog = log.New(file, "", 0)
	} else {
		// 콘솔 로깅을 위해 stdout/stderr 사용
		logger.infoLog = log.New(os.Stdout, "", 0)
		logger.errorLog = log.New(os.Stderr, "", 0)
	}

	return logger, nil
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf(format, args...)
	logLine := fmt.Sprintf("[%s] [%s] %s", timestamp, level.String(), message)

	if level >= ERROR {
		l.errorLog.Println(logLine)
	} else {
		l.infoLog.Println(logLine)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// HTTPTrafficLogger는 HTTP/HTTPS 트래픽을 위한 전문 로깅을 제공합니다
type HTTPTrafficLogger struct {
	logger     *Logger
	trafficLog *log.Logger
	file       *os.File
	mutex      sync.Mutex
}

func NewHTTPTrafficLogger(logFile string) (*HTTPTrafficLogger, error) {
	if logFile != "" {
		// 로그 디렉토리가 없으면 생성
		dir := filepath.Dir(logFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create traffic log directory: %v", err)
		}

		// 트래픽 로그 파일 열기
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open traffic log file: %v", err)
		}

		return &HTTPTrafficLogger{
			file:       file,
			trafficLog: log.New(file, "", 0),
		}, nil
	}

	return &HTTPTrafficLogger{
		trafficLog: log.New(os.Stdout, "", 0),
	}, nil
}

func (t *HTTPTrafficLogger) LogRequest(method, url, userAgent, clientIP string, headers map[string][]string, body []byte) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	logEntry := fmt.Sprintf("\n=== HTTP REQUEST [%s] ===\n", timestamp)
	logEntry += fmt.Sprintf("Method: %s\n", method)
	logEntry += fmt.Sprintf("URL: %s\n", url)
	logEntry += fmt.Sprintf("Client IP: %s\n", clientIP)
	logEntry += fmt.Sprintf("User-Agent: %s\n", userAgent)

	logEntry += "Headers:\n"
	for name, values := range headers {
		for _, value := range values {
			// 민감한 헤더 마스킹
			if t.isSensitiveHeader(name) {
				logEntry += fmt.Sprintf("  %s: [REDACTED]\n", name)
			} else {
				logEntry += fmt.Sprintf("  %s: %s\n", name, value)
			}
		}
	}

	if len(body) > 0 {
		if len(body) > 1024 {
			logEntry += fmt.Sprintf("Body: [%d bytes - truncated]\n", len(body))
			logEntry += fmt.Sprintf("Body Preview: %s...\n", string(body[:1024]))
		} else {
			logEntry += fmt.Sprintf("Body: %s\n", string(body))
		}
	}

	logEntry += "=====================\n"

	t.trafficLog.Print(logEntry)
}

func (t *HTTPTrafficLogger) LogResponse(statusCode int, status, contentType string, headers map[string][]string, body []byte) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	logEntry := fmt.Sprintf("\n=== HTTP RESPONSE [%s] ===\n", timestamp)
	logEntry += fmt.Sprintf("Status: %d %s\n", statusCode, status)
	logEntry += fmt.Sprintf("Content-Type: %s\n", contentType)

	logEntry += "Headers:\n"
	for name, values := range headers {
		for _, value := range values {
			logEntry += fmt.Sprintf("  %s: %s\n", name, value)
		}
	}

	if len(body) > 0 {
		if len(body) > 1024 {
			logEntry += fmt.Sprintf("Body: [%d bytes - truncated]\n", len(body))
			if t.isTextContent(contentType) {
				logEntry += fmt.Sprintf("Body Preview: %s...\n", string(body[:1024]))
			} else {
				logEntry += "Body Preview: [Binary content]\n"
			}
		} else {
			if t.isTextContent(contentType) {
				logEntry += fmt.Sprintf("Body: %s\n", string(body))
			} else {
				logEntry += fmt.Sprintf("Body: [Binary content - %d bytes]\n", len(body))
			}
		}
	}

	logEntry += "=====================\n"

	t.trafficLog.Print(logEntry)
}

func (t *HTTPTrafficLogger) isSensitiveHeader(headerName string) bool {
	sensitiveHeaders := []string{
		"authorization",
		"cookie",
		"set-cookie",
		"x-api-key",
		"x-auth-token",
		"x-access-token",
		"x-csrf-token",
	}

	headerLower := fmt.Sprintf("%s", headerName)
	for i := 0; i < len(headerLower); i++ {
		if headerLower[i] >= 'A' && headerLower[i] <= 'Z' {
			headerLower = headerLower[:i] + string(headerLower[i]+32) + headerLower[i+1:]
		}
	}

	for _, sensitive := range sensitiveHeaders {
		if headerLower == sensitive {
			return true
		}
	}

	return false
}

func (t *HTTPTrafficLogger) isTextContent(contentType string) bool {
	textTypes := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/x-www-form-urlencoded",
		"application/javascript",
	}

	for _, textType := range textTypes {
		if t.containsString(contentType, textType) {
			return true
		}
	}

	return false
}

func (t *HTTPTrafficLogger) containsString(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}

func (t *HTTPTrafficLogger) Close() error {
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}
