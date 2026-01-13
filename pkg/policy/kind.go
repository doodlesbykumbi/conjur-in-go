package policy

//go:generate go run github.com/dmarkham/enumer -type Kind -trimprefix Kind -transform lower -yaml -output kind.gen.go

type Kind int

const (
	KindPolicy Kind = iota
	KindVariable
	KindUser
	KindGroup
	KindLayer
	KindGrant
	KindHost
	KindDelete
	KindPermit
	KindDeny
	KindHostFactory
	KindWebservice
)

func (t Kind) Tag() string {
	// Special cases for tags that don't match the lowercase enum name
	switch t {
	case KindHostFactory:
		return "!host_factory"
	case KindWebservice:
		return "!webservice"
	default:
		return "!" + t.String()
	}
}
