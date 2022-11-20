package internal

import (
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const loggerFlags = 0 // log.Ltime | log.Lshortfile

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
	l.Debug = log.New(l.debugWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
	l.Info = log.New(l.infoWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
	l.Warn = log.New(l.warnWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
	l.Error = log.New(l.errorWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
	return func() {
		l.indent = l.indent - 1
		l.Debug = log.New(l.debugWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
		l.Info = log.New(l.infoWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
		l.Warn = log.New(l.warnWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
		l.Error = log.New(l.errorWriter, strings.Repeat(" ", l.indent*4), loggerFlags)
	}
}
