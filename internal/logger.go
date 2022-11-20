package internal

import (
	"io/ioutil"
	"log"
	"os"
)

type Logger struct {
	Debug *log.Logger
	Info  *log.Logger
	Warn  *log.Logger
	Error *log.Logger
}

const loggerFlags = 0 // log.Ltime | log.Lshortfile

func NewLogger(withDebug bool) Logger {
	debugWriter := ioutil.Discard
	if withDebug {
		debugWriter = os.Stderr
	}
	return Logger{
		Debug: log.New(debugWriter, "DEBUG: ", loggerFlags),
		Info:  log.New(os.Stderr, "INFO:  ", loggerFlags),
		Warn:  log.New(os.Stderr, "WARN:  ", loggerFlags),
		Error: log.New(os.Stderr, "ERROR: ", loggerFlags),
	}
}

func NewNullLogger() Logger {
	return Logger{
		Debug: log.New(ioutil.Discard, "DEBUG: ", loggerFlags),
		Info:  log.New(ioutil.Discard, "INFO:  ", loggerFlags),
		Warn:  log.New(ioutil.Discard, "WARN:  ", loggerFlags),
		Error: log.New(ioutil.Discard, "ERROR: ", loggerFlags),
	}
}
