package masterpassword

// Site is a site seed with site information
type Site struct {
	Seed    []byte
	Session *Session
	Name    string
	Counter int
}

// Password returns the password of type pwdType for this site
func (site *Site) Password(pwdType PasswordType) string {
	templates := passwordTypeTemplates[pwdType]
	template := templates[int(site.Seed[0])%len(templates)]
	return site.passwordFromTemplate(template)
}

func (site *Site) passwordFromTemplate(template string) (password string) {
	for i, char := range template {
		password += string(charOfClass(site.Seed[i+1], templateType(char)))
	}
	return
}

// PasswordSheet ignores the first seed byte and returns all password variations for this site
func (site *Site) PasswordSheet(pwdType PasswordType) (passwords []string) {
	templates := passwordTypeTemplates[pwdType]
	passwords = make([]string, len(templates))
	for i, template := range templates {
		passwords[i] = site.passwordFromTemplate(template)
	}
	return
}
