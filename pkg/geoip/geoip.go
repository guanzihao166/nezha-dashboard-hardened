package geoip

import (
	_ "embed"
	"errors"
	"net"
	"strings"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

//go:embed geoip.db
var db []byte

var (
	dbOnce = sync.OnceValues(func() (*maxminddb.Reader, error) {
		db, err := maxminddb.FromBytes(db)
		if err != nil {
			return nil, err
		}
		return db, nil
	})
)

type IPInfo struct {
	Country       string `maxminddb:"country"`
	CountryName   string `maxminddb:"country_name"`
	Continent     string `maxminddb:"continent"`
	ContinentName string `maxminddb:"continent_name"`
}

// Lookup resolves an IP to a country code. The embedded database may be either
// the upstream IPInfo country database (flat fields) or a MaxMind GeoLite2
// country database (nested country/continent records), so the record is
// decoded dynamically instead of pinning one schema.
func Lookup(ip net.IP) (string, error) {
	db, err := dbOnce()
	if err != nil {
		return "", err
	}

	var raw map[string]any
	err = db.Lookup(ip, &raw)
	if err != nil {
		return "", err
	}

	switch v := raw["country"].(type) {
	case string:
		if v != "" {
			return strings.ToLower(v), nil
		}
	case map[string]any:
		if code, ok := v["iso_code"].(string); ok && code != "" {
			return strings.ToLower(code), nil
		}
	}

	switch v := raw["continent"].(type) {
	case string:
		if v != "" {
			return strings.ToLower(v), nil
		}
	case map[string]any:
		if code, ok := v["code"].(string); ok && code != "" {
			return strings.ToLower(code), nil
		}
	}

	return "", errors.New("IP not found")
}
