package eccutil

import (
    "os"
    "github.com/pkg/errors"
    "golang.org/x/term"
)

var (
    ErrPasswordsDontMatch = errors.New("passwords don't match")
    ErrTerminalNotAvailable = errors.New("terminal is not available")
)

func GetPassword(prompt string) ([]byte, error) {
    if !term.IsTerminal(int(os.Stdin.Fd())) {
	return nil, ErrTerminalNotAvailable
    }
    out := os.Stdout
    if !term.IsTerminal(int(out.Fd())) {
	out = os.Stderr
	if !term.IsTerminal(int(out.Fd())) {
	    return nil, ErrTerminalNotAvailable
	}
    }
    if _, err := out.Write([]byte(prompt)); err != nil {
	return nil, err
    }
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    out.Write([]byte("\n"))
    return password, err
}

func NewPassword(prompt string) ([]byte, error) {
    password1, err := GetPassword(prompt)
    if err != nil {
	return nil, err
    }
    password2, err := GetPassword("Again - " + prompt)
    if err != nil {
	return nil, err
    }
    if len(password1) != len(password2) {
	return nil, ErrPasswordsDontMatch
    }
    for i := 0; i < len(password1); i++ {
	if password1[i] != password2[i] {
	    return nil, ErrPasswordsDontMatch
	}
    }
    return password1, nil
}
