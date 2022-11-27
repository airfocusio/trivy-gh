package internal

import (
	"io"
	"log"
	"os"
	"strings"
)

const (
	loggerIndent = "    "
	loggerFlags  = 0 // log.Ltime | log.Lshortfile
)

type Logger struct {
	Debug *log.Logger
	Info  *log.Logger

	debugWriter io.Writer
	infoWriter  io.Writer
	indent      int
}

func NewLogger(withDebug bool) Logger {
	debugWriter := io.Discard
	if withDebug {
		debugWriter = os.Stdout
	}
	infoWriter := (io.Writer)(os.Stdout)
	return Logger{
		Debug:       log.New(debugWriter, "", loggerFlags),
		Info:        log.New(infoWriter, "", loggerFlags),
		debugWriter: debugWriter,
		infoWriter:  infoWriter,
		indent:      0,
	}
}

func NewNullLogger() Logger {
	debugWriter := io.Discard
	infoWriter := io.Discard
	return Logger{
		Debug:       log.New(debugWriter, "", loggerFlags),
		Info:        log.New(infoWriter, "", loggerFlags),
		debugWriter: debugWriter,
		infoWriter:  infoWriter,
		indent:      0,
	}
}

func (l *Logger) Nest() func() {
	l.indent = l.indent + 1
	l.Debug = log.New(l.debugWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	l.Info = log.New(l.infoWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	return func() {
		l.indent = l.indent - 1
		l.Debug = log.New(l.debugWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
		l.Info = log.New(l.infoWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	}
}

func (l *Logger) CloneNested() *Logger {
	indent := l.indent + 1
	return &Logger{
		Debug:       log.New(l.debugWriter, strings.Repeat(loggerIndent, indent), loggerFlags),
		Info:        log.New(l.infoWriter, strings.Repeat(loggerIndent, indent), loggerFlags),
		debugWriter: l.debugWriter,
		infoWriter:  l.infoWriter,
		indent:      indent,
	}
}
