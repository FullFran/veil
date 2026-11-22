package domain

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A Spanish postal address of a person: a street type, the street name and
// a house number (or s/n), then the floor/door and postal code + city that
// follow in the same comma-separated address. One span covers all of it,
// so the whole address gets one token. A street with no number is a public
// place ("la calle Alcalá estará cortada") and is left alone. A city that
// is not introduced by a postal code ("…, Valladolid") is not part of the
// span: on its own it does not locate anyone.

const (
	// streetType is the lexicon of street types, full and abbreviated.
	streetType = `(?i:calle|c/|avenida|avda\.|av\.|plaza|pza\.|paseo|pº|ronda|travesía|camino|carretera|ctra\.|glorieta|pasaje|rambla|callejón|urbanización|urb\.)`
	// streetWord is one word of a street name: letters, apostrophes and
	// joined parts ("Ruiz-Picasso"). Roman numerals ("Alfonso I") are words.
	streetWord = `\pL[\pL'’-]*`
	streetName = streetWord + `(?:[ \t]+` + streetWord + `){0,5}`
	// houseNumber is a number of one to three digits, with an optional
	// letter glued to it, or "s/n" (sin número).
	houseNumber = `(?:[0-9]{1,3}[A-Za-z]?|(?i:s/n))`
	// floorDoor is one floor/door element: "3º izq.", "1ºA", "2º", "bajo",
	// "portal 2".
	floorDoor = `(?:[0-9]{1,2}[ \t]?[ºª°](?:[ \t]?(?:(?i:izq(?:da)?\.|izquierda|dcha\.|derecha|centro)|[A-Za-z]\b))?|(?i:bajo|entresuelo|ático)(?:[ \t][A-Z]\b)?|(?i:portal|escalera|esc\.|bloque|puerta|pta\.|parcela|local|casa)[ \t][0-9]{1,3}[A-Za-z]?)`
	// postalCity is a Spanish postal code (provinces 01-52) and the city
	// that follows it, if any.
	postalCity  = `(?:0[1-9]|[1-4][0-9]|5[0-2])[0-9]{3}(?:[ \t]+\p{Lu}\pL+(?:(?:[ \t]+(?:de|del|la|las|los|el|de[ \t]+la|de[ \t]+los|de[ \t]+las))?[ \t]+\p{Lu}\pL+){0,3})?`
	addressTail = `(?:,[ \t]+(?:` + floorDoor + `|` + postalCity + `)){0,3}`
)

var (
	addressPattern = regexp.MustCompile(`(?:` +
		// Calle Mayor 15 / Calle Mayor, 15
		streetType + `[ \t]+` + streetName + `,?[ \t]+` + houseNumber +
		// Urb. Los Pinos, parcela 14
		`|(?i:urbanización|urb\.)[ \t]+` + streetName + `,[ \t]+(?i:parcela|portal|casa|nº|número)[ \t]+[0-9]{1,3}[A-Za-z]?` +
		// número 14 de la calle Larios
		`|(?i:número|nº|n\.º)[ \t]+[0-9]{1,3}[ \t]+(?:(?i:de)[ \t]+(?:(?i:la)[ \t]+)?)?` + streetType + `[ \t]+` + streetName +
		`)` + addressTail)

	// streetTypeBefore matches text that ends with a street type and its
	// particles ("Calle ", "avenida de "), so a catalog name right after
	// it is read as a street name, not a person.
	streetTypeBefore = regexp.MustCompile(`(?:^|[^\pL])` + streetType + `[ \t]+(?:(?i:de|del|la|las|los|el)[ \t]+)*$`)
)

// streetParticles may stand in a street name but are not a name by
// themselves: "Paseo de 20 minutos" has no name.
var streetParticles = map[string]bool{"de": true, "del": true, "la": true, "las": true, "los": true, "el": true, "y": true, "i": true}

// notStreetWords are words a street name never holds; seeing one means the
// street type was an ordinary noun ("plaza para 3 personas").
var notStreetWords = map[string]bool{
	"para": true, "por": true, "con": true, "sin": true, "en": true, "que": true, "a": true, "al": true,
	"es": true, "son": true, "hay": true, "tiene": true, "como": true, "más": true, "menos": true,
	"un": true, "una": true, "unos": true, "unas": true, "mi": true, "tu": true, "su": true, "sus": true,
	"este": true, "esta": true, "ese": true, "esa": true, "cada": true, "todo": true, "todos": true,
}

// streetTypeWords are the street types (and "número") as words, which do
// not count as a street name.
var streetTypeWords = map[string]bool{
	"calle": true, "c/": true, "avenida": true, "avda": true, "av": true, "plaza": true, "pza": true,
	"paseo": true, "pº": true, "ronda": true, "travesía": true, "camino": true, "carretera": true,
	"ctra": true, "glorieta": true, "pasaje": true, "rambla": true, "callejón": true,
	"urbanización": true, "urb": true, "número": true, "nº": true, "n.º": true,
}

// unitWords after a number make it a quantity, not a house number.
var unitWords = map[string]bool{
	"km": true, "kms": true, "kilómetros": true, "m": true, "metros": true, "min": true, "minutos": true,
	"h": true, "horas": true, "días": true, "años": true, "meses": true, "semanas": true, "veces": true,
	"personas": true, "plazas": true, "euros": true, "eur": true, "€": true, "%": true, "kg": true,
	"kilos": true, "unidades": true, "coches": true,
}

// AddressDetector finds Spanish postal addresses of people.
type AddressDetector struct{}

// NewAddressDetector builds an AddressDetector.
func NewAddressDetector() *AddressDetector { return &AddressDetector{} }

// Name identifies this detector.
func (d *AddressDetector) Name() string { return "address" }

// Detect scans event.Text for postal addresses.
func (d *AddressDetector) Detect(event Event) []Finding {
	text := event.Text
	var findings []Finding
	for _, s := range findSeparated(text, addressPattern, func(start, end int) bool {
		return addressAt(text, start, end)
	}) {
		findings = append(findings, Finding{
			Detector: "address",
			Reason:   "postal address detected",
			Redacted: "[DIRECCION]",
			Match:    text[s[0]:s[1]],
			Category: "DIRECCION",
		})
	}
	return findings
}

// addressAt checks the boundaries of a candidate and that its street name
// is a name: at least one word that is not a particle, and no word a
// street name never holds. A number followed by a unit is a quantity.
func addressAt(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == '_' {
			return false
		}
	}
	if end < len(text) {
		r, _ := utf8.DecodeRuneInString(text[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == '_' {
			return false
		}
	}
	if next := strings.ToLower(firstWord(text[end:])); unitWords[next] {
		return false
	}
	named := false
	for _, w := range strings.Fields(text[start:end]) {
		w = strings.ToLower(strings.Trim(w, ",."))
		if notStreetWords[w] {
			return false
		}
		if !streetParticles[w] && !streetTypeWords[w] && strings.IndexFunc(w, unicode.IsLetter) >= 0 {
			named = true
		}
	}
	return named
}

// firstWord returns the first whitespace-separated word of s, without
// trailing punctuation.
func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimRight(fields[0], ",.;:")
}

// afterStreetType reports whether text ends with a street type and its
// particles, so what follows is a street name.
func afterStreetType(text string) bool {
	return streetTypeBefore.MatchString(text)
}
