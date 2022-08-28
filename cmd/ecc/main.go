package main

import (
    "os"
    log "github.com/sirupsen/logrus"
    "github.com/thepax/ecc/cmd/ecc/commands"
)

type PlainFormatter struct {
}

func (f *PlainFormatter) Format(entry *log.Entry) ([]byte, error) {
    return []byte(entry.Message + "\n"), nil
}

func main() {
    log.SetFormatter(&PlainFormatter{})
    log.SetOutput(os.Stderr)
    commands.RootCmd(nil).Execute()
}
