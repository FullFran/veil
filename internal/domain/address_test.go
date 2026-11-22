package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Every address below is invented (shapes from the research set
// research/ner-benchmark/data/es-ext-v1).

func TestAddressDetector_PersonalAddresses_AreOneSpan(t *testing.T) {
	cases := []struct{ text, want string }{
		{"Envíalo a Calle de Santa Engracia 112, 3º izq., 28003 Madrid.", "Calle de Santa Engracia 112, 3º izq., 28003 Madrid"},
		{"Domicilio: C/ Mayor 15, 1ºA, Valladolid.", "C/ Mayor 15, 1ºA"},
		{"Vive en Avda. de la Constitución 8, portal 2.", "Avda. de la Constitución 8, portal 2"},
		{"La entrega es en Plaza del Pilar 3, bajo a las 10.", "Plaza del Pilar 3, bajo"},
		{"Dirección de facturación: Paseo de Gracia 55, 08007 Barcelona", "Paseo de Gracia 55, 08007 Barcelona"},
		{"mi casa es en calle ancha 27, 4º d, pásate luego", "calle ancha 27, 4º d"},
		{"Vivo en Camino de los Molinos s/n, 41500 Alcalá de Guadaíra.", "Camino de los Molinos s/n, 41500 Alcalá de Guadaíra"},
		{"Nueva dirección: Urb. Los Pinos, parcela 14, 29600 Marbella.", "Urb. Los Pinos, parcela 14, 29600 Marbella"},
		{"Notificar en Travesía del Carmen 2, 3º dcha., 33201 Gijón.", "Travesía del Carmen 2, 3º dcha., 33201 Gijón"},
		{"Estoy en el número 14 de la calle Larios, en Málaga.", "número 14 de la calle Larios"},
		{"Datos de envío:\nEmilio Navarro\nC/ Real 9, 37001 Salamanca", "C/ Real 9, 37001 Salamanca"},
		{"Recoger en Calle Alfonso I 17, 50003 Zaragoza; gracias.", "Calle Alfonso I 17, 50003 Zaragoza"},
	}
	for _, c := range cases {
		wantOne(t, detectWith(t, domain.NewAddressDetector(), c.text), "address", "DIRECCION", c.want, "")
	}
}

// A street with no house number is a public place, not where someone
// lives: it stays in clear, which keeps sentences about traffic, works or
// parades untouched.
func TestAddressDetector_PublicStreetsAndNearMisses_DoNotFire(t *testing.T) {
	for _, text := range []string{
		"La calle Alcalá estará cortada el domingo por la maratón.",
		"El desfile recorre la Gran Vía y termina en la Plaza de España.",
		"Hay obras en la Avenida de la Constitución durante todo el mes.",
		"grep -rn 'calle' src/ | head -n 20",
		"Tenemos plaza para 3 personas en el coche.",
		"El Camino de Santiago 2024 bate récords.",
		"Un paseo de 20 minutos por la Plaza Mayor 3 veces al día.",
		"Escribe tu dirección completa en el formulario de envío.",
	} {
		wantNone(t, detectWith(t, domain.NewAddressDetector(), text))
	}
}

// A catalog name that is the name of a street is not a person: the
// address detector owns it when there is a number, and nobody when there
// is not.
func TestNameCatalogDetector_NameAfterStreetType_DoesNotFire(t *testing.T) {
	d := domain.NewNameCatalogDetector([]string{"María Pérez"})
	wantNone(t, detectWith(t, d, "Calle María Pérez de la Rosa no aplica: es una calle."))
	wantNone(t, detectWith(t, d, "El paquete va a la avenida de María Pérez 12."))
	wantOne(t, detectWith(t, d, "María Pérez vive en la calle de al lado."), "name-catalog", "NOMBRE", "María Pérez", "")
}

func TestRegistry_AddressContainingCatalogName_IsOneAddress(t *testing.T) {
	r := domain.NewRegistry(domain.NewAddressDetector(), domain.NewNameCatalogDetector([]string{"María Pérez"}))
	findings, err := r.DetectAll(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode,
		Text: "El paquete va a Calle María Pérez de la Rosa 12, segundo piso."})
	if err != nil {
		t.Fatal(err)
	}
	wantOne(t, findings, "address", "DIRECCION", "Calle María Pérez de la Rosa 12", "")
}
