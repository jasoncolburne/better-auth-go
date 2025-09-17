package storageinterfaces

type RegistrationTokenStore interface {
	Generate() (token string, err error)
	Validate(token string) (accountId string, err error)
	Invalidate(token string)
}

type PassphraseRegistrationTokenStore interface {
	Generate(salt, parameters string) (token string, err error)
	Validate(token string) (accountId, salt, parameters string, err error)
	Invalidate(token string)
}
