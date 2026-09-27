package pactidentity

// RFC 4180, strictly, in both directions, as the Rust core's export/csv.rs has it. Hand-written, not
// encoding/csv: that reader skips a blank line and rewrites a quoted CRLF to LF (measured), and a
// reader that repairs what it reads is not the rule both ports hold.
//
// Reading: records end with CRLF or LF; a field is quoted or not; a quoted field may hold commas,
// quotes (doubled) and line breaks, kept byte for byte; an unquoted field holds no quote and no
// carriage return. A blank record, a bare carriage return, a quote inside an unquoted field, a
// character after a closing quote and an unterminated quote are refused, never repaired. Writing:
// CRLF after every record, and a field quoted exactly when it holds `,`, `"`, CR or LF.

import "strings"

// csvRefusal is the record a refusal is in (1 is the header) and why.
type csvRefusal struct {
	record int
	why    string
}

func csvRead(text string) ([][]string, *csvRefusal) {
	b := []byte(text)
	var records [][]string
	i, n := 0, 0
	for i < len(b) {
		n++
		var fields []string
		for {
			var field []byte
			if i < len(b) && b[i] == '"' {
				i++
				for {
					if i >= len(b) {
						return nil, &csvRefusal{n, "a quoted field is never closed"}
					}
					if b[i] == '"' {
						if i+1 < len(b) && b[i+1] == '"' {
							field = append(field, '"')
							i += 2
							continue
						}
						i++
						break
					}
					field = append(field, b[i])
					i++
				}
				if i < len(b) && b[i] != ',' && b[i] != '\r' && b[i] != '\n' {
					return nil, &csvRefusal{n, "a character follows a closing quote"}
				}
			} else {
				for i < len(b) && b[i] != ',' && b[i] != '\r' && b[i] != '\n' {
					if b[i] == '"' {
						return nil, &csvRefusal{n, "a quote inside an unquoted field"}
					}
					field = append(field, b[i])
					i++
				}
			}
			fields = append(fields, string(field))
			if i < len(b) && b[i] == ',' {
				i++
				continue
			}
			break
		}
		if i < len(b) && b[i] == '\r' {
			if i+1 < len(b) && b[i+1] == '\n' {
				i += 2
			} else {
				return nil, &csvRefusal{n, "a carriage return that ends no line"}
			}
		} else if i < len(b) && b[i] == '\n' {
			i++
		}
		if len(fields) == 1 && fields[0] == "" {
			return nil, &csvRefusal{n, "a blank row"}
		}
		records = append(records, fields)
	}
	return records, nil
}

// csvWriteRecord appends one record, CRLF-terminated, each field quoted exactly when it must be.
func csvWriteRecord(out *strings.Builder, fields []string) {
	for k, f := range fields {
		if k > 0 {
			out.WriteByte(',')
		}
		if strings.ContainsAny(f, ",\"\r\n") {
			out.WriteByte('"')
			out.WriteString(strings.ReplaceAll(f, `"`, `""`))
			out.WriteByte('"')
		} else {
			out.WriteString(f)
		}
	}
	out.WriteString("\r\n")
}

// csvGuard is SPEC §9.2's spreadsheet guard: a cell that begins with `=`, `+`, `-`, `@`, `'`, a tab
// or a carriage return is written with one `'` before it.
func csvGuard(cell string) string {
	if cell != "" && strings.ContainsRune("=+-@'\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}

// csvUnguard is the reader's half: one leading `'` stripped.
func csvUnguard(cell string) string { return strings.TrimPrefix(cell, "'") }
