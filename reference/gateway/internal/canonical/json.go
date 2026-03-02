// Package canonical implements RFC 8785 JSON Canonicalization Scheme (JCS).
//
// This is used for computing deterministic hashes over JSON objects for
// Merkle chain integrity, signature verification, and audit event hashing.
//
// Key rules from RFC 8785:
//   - Object keys are sorted lexicographically by their Unicode code points
//   - Numbers use minimal representation (no trailing zeros, no leading zeros)
//   - Strings use minimal escape sequences
//   - No whitespace between tokens
//   - null, true, false are lowercase literals
package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Marshal produces the RFC 8785 canonical JSON form of a value.
// The input can be any Go value that is JSON-serializable, or a
// pre-parsed interface{} from json.Unmarshal.
func Marshal(v interface{}) ([]byte, error) {
	// If v is a struct/pointer, first round-trip through encoding/json
	// to get an untyped representation we can sort.
	var raw interface{}
	switch v.(type) {
	case map[string]interface{}, []interface{}, nil, bool, float64, string, json.Number:
		raw = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("canonical: pre-marshal failed: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("canonical: pre-decode failed: %w", err)
		}
	}

	var buf bytes.Buffer
	if err := writeCanonical(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalFromJSON re-canonicalizes existing JSON bytes.
func MarshalFromJSON(data []byte) ([]byte, error) {
	var raw interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("canonical: decode failed: %w", err)
	}
	return Marshal(raw)
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")

	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}

	case json.Number:
		n, err := canonicalNumber(val)
		if err != nil {
			return err
		}
		buf.WriteString(n)

	case float64:
		buf.WriteString(canonicalFloat(val))

	case string:
		writeCanonicalString(buf, val)

	case map[string]interface{}:
		if err := writeCanonicalObject(buf, val); err != nil {
			return err
		}

	case []interface{}:
		if err := writeCanonicalArray(buf, val); err != nil {
			return err
		}

	default:
		// Fallback: use standard JSON encoding.
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("canonical: cannot marshal %T: %w", val, err)
		}
		buf.Write(b)
	}
	return nil
}

func writeCanonicalObject(buf *bytes.Buffer, obj map[string]interface{}) error {
	// Sort keys lexicographically by Unicode code points.
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeCanonicalString(buf, k)
		buf.WriteByte(':')
		if err := writeCanonical(buf, obj[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeCanonicalArray(buf *bytes.Buffer, arr []interface{}) error {
	buf.WriteByte('[')
	for i, elem := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, elem); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

// writeCanonicalString writes a JSON-escaped string with minimal escaping per RFC 8785.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			// Control characters use \u00XX form.
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// canonicalNumber converts a json.Number to its RFC 8785 canonical form.
// Integers are output without a decimal point. Floating-point numbers use
// minimal representation.
func canonicalNumber(n json.Number) (string, error) {
	s := n.String()

	// Try integer first.
	if !strings.Contains(s, ".") && !strings.Contains(s, "e") && !strings.Contains(s, "E") {
		// Validate it parses as an integer.
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return s, nil
		}
		// Could be a very large integer; try float.
	}

	// Parse as float64 for canonical representation.
	f, err := n.Float64()
	if err != nil {
		return "", fmt.Errorf("canonical: invalid number %q: %w", s, err)
	}
	return canonicalFloat(f), nil
}

// canonicalFloat produces the RFC 8785 canonical representation of a float64.
// Per the spec, this uses the ECMAScript number-to-string algorithm:
//   - No positive sign
//   - Integers are output without decimal point (if <= 10^21)
//   - Use exponential notation for very small/large numbers
//   - Minimal digits
func canonicalFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		// RFC 8785 does not define NaN/Inf; JSON does not support them.
		return "null"
	}

	if f == 0 {
		// -0 and +0 both serialize as "0".
		return "0"
	}

	// If the number is an exact integer and within safe range, emit without decimal.
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatInt(int64(f), 10)
	}

	// Use Go's %g-style minimal representation, then clean up.
	// strconv.FormatFloat with 'G' and -1 precision gives shortest representation.
	s := strconv.FormatFloat(f, 'E', -1, 64)

	// Parse into parts: mantissa, exponent.
	parts := strings.SplitN(s, "E", 2)
	mantissa := parts[0]
	exp := 0
	if len(parts) == 2 {
		exp, _ = strconv.Atoi(parts[1])
	}

	// Remove trailing zeros from mantissa decimal part.
	if strings.Contains(mantissa, ".") {
		mantissa = strings.TrimRight(mantissa, "0")
		mantissa = strings.TrimRight(mantissa, ".")
	}

	// Count digits after removing sign and decimal point.
	digits := mantissa
	negative := false
	if strings.HasPrefix(digits, "-") {
		digits = digits[1:]
		negative = true
	}
	digits = strings.Replace(digits, ".", "", 1)
	nDigits := len(digits)

	// Determine the adjusted exponent.
	// mantissa is of the form "d.ddd" so the value is mantissa * 10^exp.
	// ECMAScript uses: if -6 < exp <= 20 in base-10, use fixed notation.
	adjustedExp := exp

	if adjustedExp >= 0 && adjustedExp < 21 && nDigits <= adjustedExp+1 {
		// Can represent as integer.
		result := digits
		for len(result) < adjustedExp+1 {
			result += "0"
		}
		if negative {
			return "-" + result
		}
		return result
	}

	// Use Go's built-in shortest representation which is close to ES spec.
	return strconv.FormatFloat(f, 'f', -1, 64)
}
