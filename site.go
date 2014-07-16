package masterpassword

type Site struct {
	Seed    []byte
	Session *Session
	Name    string
	Counter int
}

func (site *Site) Password(pwdType PasswordType) string {
	templates := PasswordTypeTemplates[pwdType]
	template := templates[int(site.Seed[0])%len(templates)]
	return site.PasswordFromTemplate(template)
}

func (site *Site) PasswordFromTemplate(template string) (password string) {
	for i, char := range template {
		password += string(CharOfClass(site.Seed[i+1], TemplateType(char)))
	}
	return
}

func (site *Site) PasswordSheet(pwdType PasswordType) (passwords []string) {
	templates := PasswordTypeTemplates[pwdType]
	passwords = make([]string, len(templates))
	for i, template := range templates {
		passwords[i] = site.PasswordFromTemplate(template)
	}
	return
}

func (site *Site) PickTemplate(templates []string) string {
	i := int(site.Seed[0]) % len(templates)
	return templates[i]
}
