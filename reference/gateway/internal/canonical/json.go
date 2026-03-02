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
	// Structs/pointers must be round-tripped through encoding/json to get
	// an untyped map representation that we can sort by key.
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
func canonicalNumber(n json.Number) (string, error) {
	s := n.String()

	if !strings.Contains(s, ".") && !strings.Contains(s, "e") && !strings.Contains(s, "E") {
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return s, nil
		}
		// Could be a very large integer; try float.
	}

	f, err := n.Float64()
	if err != nil {
		return "", fmt.Errorf("canonical: invalid number %q: %w", s, err)
	}
	return canonicalFloat(f), nil
}

// canonicalFloat produces the RFC 8785 canonical representation of a float64
// using the ECMAScript number-to-string algorithm.
func canonicalFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		// RFC 8785 does not define NaN/Inf; JSON does not support them.
		return "null"
	}

	if f == 0 {
		return "0" // -0 and +0 both serialize as "0".
	}

	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatInt(int64(f), 10)
	}

	s := strconv.FormatFloat(f, 'E', -1, 64)
	parts := strings.SplitN(s, "E", 2)
	mantissa := parts[0]
	exp := 0
	if len(parts) == 2 {
		exp, _ = strconv.Atoi(parts[1])
	}

	if strings.Contains(mantissa, ".") {
		mantissa = strings.TrimRight(mantissa, "0")
		mantissa = strings.TrimRight(mantissa, ".")
	}

	digits := mantissa
	negative := false
	if strings.HasPrefix(digits, "-") {
		digits = digits[1:]
		negative = true
	}
	digits = strings.Replace(digits, ".", "", 1)
	nDigits := len(digits)

	// ECMAScript: if -6 < exp <= 20, use fixed notation.
	adjustedExp := exp

	if adjustedExp >= 0 && adjustedExp < 21 && nDigits <= adjustedExp+1 {
		result := digits
		for len(result) < adjustedExp+1 {
			result += "0"
		}
		if negative {
			return "-" + result
		}
		return result
	}

	return strconv.FormatFloat(f, 'f', -1, 64)
}
