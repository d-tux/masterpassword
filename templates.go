package masterpassword

import (
	"errors"
	"strings"
)

const prefix string = "com.lyndir.masterpassword"
const saltFormat string = prefix + "%d%s"
const seedFormat string = prefix + "%d%s%d"

const (
	PasswordTypeMaximumSecurity = iota
	PasswordTypeLong
	PasswordTypeMedium
	PasswordTypeShort
	PasswordTypeBasic
	PasswordTypePIN
)

type PasswordType int

type templateType rune

var templateCharacters = map[templateType]string{
	'V': "AEIOU",
	'C': "BCDFGHJKLMNPQRSTVWXYZ",
	'v': "aeiou",
	'c': "bcdfghjklmnpqrstvwxyz",
	'A': "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
	'a': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
	'n': "0123456789",
	'o': "@&%?,=[]_:-+*$#!'^~;()/.",
	'X': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789@&%?,=[]_:-+*$#!'^~;()/.",
}

var passwordTypeTemplates = map[PasswordType][]string{
	PasswordTypeMaximumSecurity: {
		"anoxxxxxxxxxxxxxxxxx",
		"axxxxxxxxxxxxxxxxxno",
	},

	PasswordTypeLong: {
		"CvcvnoCvcvCvcv",
		"CvcvCvcvnoCvcv",
		"CvcvCvcvCvcvno",
		"CvccnoCvcvCvcv",
		"CvccCvcvnoCvcv",
		"CvccCvcvCvcvno",
		"CvcvnoCvccCvcv",
		"CvcvCvccnoCvcv",
		"CvcvCvccCvcvno",
		"CvcvnoCvcvCvcc",
		"CvcvCvcvnoCvcc",
		"CvcvCvcvCvccno",
		"CvccnoCvccCvcv",
		"CvccCvccnoCvcv",
		"CvccCvccCvcvno",
		"CvcvnoCvccCvcc",
		"CvcvCvccnoCvcc",
		"CvcvCvccCvccno",
		"CvccnoCvcvCvcc",
		"CvccCvcvnoCvcc",
		"CvccCvcvCvccno",
	},

	PasswordTypeMedium: {
		"CvcnoCvc",
		"CvcCvcno",
	},

	PasswordTypeShort: {
		"Cvcn",
	},

	PasswordTypeBasic: {
		"aaanaaan",
		"aannaaan",
		"aaannaaa",
	},

	PasswordTypePIN: {
		"nnnn",
	},
}

// charOfTemplate returns the resulting character given a template.
func charOfTemplate(value byte, template string) rune {
	if 0 == len(template) {
		panic(errors.New("Template is empty"))
	}
	return rune(template[int(value)%len(template)])
}

// charOfClass returns the character for a given class
func charOfClass(value byte, class templateType) rune {
	return charOfTemplate(value, templateCharacters[class])
}

func (t *PasswordType) String() (s string) {
	switch *t {
	case PasswordTypeBasic:
		s = "basic"
	case PasswordTypeShort:
		s = "short"
	case PasswordTypePIN:
		s = "PIN"
	case PasswordTypeMedium:
		s = "medium"
	case PasswordTypeLong:
		s = "long"
	case PasswordTypeMaximumSecurity:
		s = "maximum security"
	}

	return
}

func (t *PasswordType) Set(value string) (err error) {
	switch strings.ToLower(value) {
	default:
		err = errors.New("Invalid password type")
	case "basic", "b":
		*t = PasswordTypeBasic
	case "short", "s":
		*t = PasswordTypeShort
	case "pin", "p":
		*t = PasswordTypePIN
	case "medium", "med", "m":
		*t = PasswordTypeMedium
	case "long", "l":
		*t = PasswordTypeLong
	case "maximum", "max", "x":
		*t = PasswordTypeMaximumSecurity
	}
	return
}
