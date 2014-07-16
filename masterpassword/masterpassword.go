package main

import (
	"flag"
	"fmt"
	MP "github.com/deniswernert/masterpassword"
	"os"
)

func usage() {
	fmt.Printf("Usage: %s [user name] [site name]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	var user, masterPassword, siteName string
	var Type MP.PasswordType = MP.PasswordTypeBasic
	var counter = 1
	helpRequested := flag.Bool("h", false, "Displays this help message")
	flag.IntVar(&counter, "counter", 1, "Site password counter")
	flag.Var(&Type, "type", "Password type")
	flag.Parse()

	if *helpRequested || flag.NArg() != 2 {
		usage()
	}

	user = flag.Arg(0)
	siteName = flag.Arg(1)
	masterPassword = "abcd1234"
	fmt.Print("Password (will echo): ")
	fmt.Scanln(&masterPassword)

	session := MP.NewSession(user, masterPassword)
	site := session.NewSite(siteName)
	const expected string = "oM18WKb2"
	fmt.Println(site.Password(Type))
}
