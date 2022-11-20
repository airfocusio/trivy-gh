package internal

import (
	"io"
	"io/ioutil"
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
	Warn  *log.Logger
	Error *log.Logger

	debugWriter io.Writer
	infoWriter  io.Writer
	warnWriter  io.Writer
	errorWriter io.Writer
	indent      int
}

func NewLogger(withDebug bool) Logger {
	debugWriter := ioutil.Discard
	if withDebug {
		debugWriter = os.Stderr
	}
	infoWriter := (io.Writer)(os.Stderr)
	warnWriter := (io.Writer)(os.Stderr)
	errorWriter := (io.Writer)(os.Stderr)
	return Logger{
		Debug:       log.New(debugWriter, "", loggerFlags),
		Info:        log.New(infoWriter, "", loggerFlags),
		Warn:        log.New(warnWriter, "", loggerFlags),
		Error:       log.New(errorWriter, "", loggerFlags),
		debugWriter: debugWriter,
		infoWriter:  infoWriter,
		warnWriter:  warnWriter,
		errorWriter: errorWriter,
		indent:      0,
	}
}

func NewNullLogger() Logger {
	debugWriter := ioutil.Discard
	infoWriter := ioutil.Discard
	warnWriter := ioutil.Discard
	errorWriter := ioutil.Discard
	return Logger{
		Debug:       log.New(debugWriter, "", loggerFlags),
		Info:        log.New(infoWriter, "", loggerFlags),
		Warn:        log.New(warnWriter, "", loggerFlags),
		Error:       log.New(errorWriter, "", loggerFlags),
		debugWriter: debugWriter,
		infoWriter:  infoWriter,
		warnWriter:  warnWriter,
		errorWriter: errorWriter,
		indent:      0,
	}
}

func (l *Logger) Nest() func() {
	l.indent = l.indent + 1
	l.Debug = log.New(l.debugWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	l.Info = log.New(l.infoWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	l.Warn = log.New(l.warnWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	l.Error = log.New(l.errorWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	return func() {
		l.indent = l.indent - 1
		l.Debug = log.New(l.debugWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
		l.Info = log.New(l.infoWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
		l.Warn = log.New(l.warnWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
		l.Error = log.New(l.errorWriter, strings.Repeat(loggerIndent, l.indent), loggerFlags)
	}
}

func (l *Logger) CloneNested() *Logger {
	indent := l.indent + 1
	return &Logger{
		Debug:       log.New(l.debugWriter, strings.Repeat(loggerIndent, indent), loggerFlags),
		Info:        log.New(l.infoWriter, strings.Repeat(loggerIndent, indent), loggerFlags),
		Warn:        log.New(l.warnWriter, strings.Repeat(loggerIndent, indent), loggerFlags),
		Error:       log.New(l.errorWriter, strings.Repeat(loggerIndent, indent), loggerFlags),
		debugWriter: l.debugWriter,
		infoWriter:  l.infoWriter,
		warnWriter:  l.warnWriter,
		errorWriter: l.errorWriter,
		indent:      indent,
	}
}
