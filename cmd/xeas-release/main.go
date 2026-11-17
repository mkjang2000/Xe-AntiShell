package main

import (
	"os"
	"xe-antishell/internal/releasepublish"
)

func main() { os.Exit(releasepublish.Run(os.Args[1:], os.Stdout, os.Stderr)) }
