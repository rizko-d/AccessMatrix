package accessmatrix

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Preserve exact decimal equality without floats or allocating 10^exponent.
func canonicalNumber(s string) json.Number {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	exponent := new(big.Int)
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent.SetString(strings.TrimPrefix(s[i+1:], "+"), 10)
		s = s[:i]
	}
	fraction := 0
	if i := strings.IndexByte(s, '.'); i >= 0 {
		fraction = len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return json.Number("0")
	}
	digits := strings.TrimRight(s, "0")
	exponent.Add(exponent, big.NewInt(int64(len(s)-len(digits)-fraction)))
	if negative {
		digits = "-" + digits
	}
	return json.Number(digits + "e" + exponent.String())
}

// Decode tokens rather than maps first, so duplicate keys cannot disappear.
func decodeJSON(b []byte) (any, error) {
	if !utf8.Valid(b) || !validSurrogates(b) {
		return nil, errors.New("invalid JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	remaining := 65536 // Bound allocation growth even for compact arrays and objects.
	value, err := jsonValue(d, 0, &remaining)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

// Reject lone UTF-16 escapes instead of silently replacing them with U+FFFD.
func validSurrogates(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			n, err = strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if err != nil || n < 0xdc00 || n > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func jsonValue(d *json.Decoder, depth int, remaining *int) (any, error) {
	if *remaining == 0 {
		return nil, errors.New("JSON value limit exceeded")
	}
	*remaining -= 1
	if depth > 128 {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		m := make(map[string]any)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			k, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid JSON key")
			}
			if _, ok := m[k]; ok {
				return nil, errors.New("duplicate JSON key")
			}
			v, err := jsonValue(d, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return m, nil
	case json.Delim('['):
		values := []any{}
		for d.More() {
			v, err := jsonValue(d, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return values, nil
	default:
		if n, ok := t.(json.Number); ok {
			if len(n) > 4096 {
				return nil, errors.New("JSON number limit exceeded")
			}
			return canonicalNumber(string(n)), nil
		}
		if _, ok := t.(json.Delim); ok {
			return nil, errors.New("invalid JSON delimiter")
		}
		return t, nil
	}
}
