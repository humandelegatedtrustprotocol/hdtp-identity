//! RFC 4180, strictly, in both directions, written here so the Wasm core takes no dependency for it.
//!
//! Reading: records end with CRLF or LF; a field is quoted or not; a quoted field may hold commas,
//! quotes (doubled) and line breaks, kept byte for byte; an unquoted field holds no quote and no
//! carriage return. A blank record, a bare carriage return, a quote inside an unquoted field, a
//! character after a closing quote and an unterminated quote are refused, never repaired. Writing:
//! CRLF after every record, and a field quoted exactly when it holds `,`, `"`, CR or LF.

use std::borrow::Cow;

/// One refusal: the record it is in (1 is the header) and why.
pub type Refusal = (usize, &'static str);

/// The records of a CSV text, one at a time, each field borrowed from the text unless it had to be
/// unescaped (a quoted field holding a doubled quote): a reader of a 16 MiB member holds the text
/// and one record, never a copy of every cell. The first refusal ends the records.
pub struct Records<'a> {
    text: &'a str,
    i: usize,
    n: usize,
    done: bool,
}

impl<'a> Records<'a> {
    pub fn new(text: &'a str) -> Records<'a> {
        Records { text, i: 0, n: 0, done: false }
    }

    fn record(&mut self) -> Result<Vec<Cow<'a, str>>, Refusal> {
        let (text, b, n) = (self.text, self.text.as_bytes(), self.n);
        let mut i = self.i;
        let mut fields = Vec::new();
        loop {
            if i < b.len() && b[i] == b'"' {
                i += 1;
                let start = i;
                let mut owned: Option<String> = None;
                loop {
                    if i >= b.len() {
                        return Err((n, "a quoted field is never closed"));
                    }
                    if b[i] == b'"' {
                        if i + 1 < b.len() && b[i + 1] == b'"' {
                            // A doubled quote: the field is not a slice of the text any more.
                            let o = owned.get_or_insert_with(String::new);
                            if o.is_empty() {
                                o.push_str(&text[start..i]);
                            }
                            o.push('"');
                            i += 2;
                            let run = i;
                            while i < b.len() && b[i] != b'"' {
                                i += 1;
                            }
                            o.push_str(&text[run..i]);
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                // The text is split only at ASCII bytes, so every slice is at a char boundary.
                fields.push(match owned {
                    Some(o) => Cow::Owned(o),
                    None => Cow::Borrowed(&text[start..i]),
                });
                i += 1;
                if i < b.len() && !matches!(b[i], b',' | b'\r' | b'\n') {
                    return Err((n, "a character follows a closing quote"));
                }
            } else {
                let start = i;
                while i < b.len() && !matches!(b[i], b',' | b'\r' | b'\n') {
                    if b[i] == b'"' {
                        return Err((n, "a quote inside an unquoted field"));
                    }
                    i += 1;
                }
                fields.push(Cow::Borrowed(&text[start..i]));
            }
            if i < b.len() && b[i] == b',' {
                i += 1;
                continue;
            }
            break;
        }
        if i < b.len() && b[i] == b'\r' {
            if i + 1 < b.len() && b[i + 1] == b'\n' {
                i += 2;
            } else {
                return Err((n, "a carriage return that ends no line"));
            }
        } else if i < b.len() && b[i] == b'\n' {
            i += 1;
        }
        if fields.len() == 1 && fields[0].is_empty() {
            return Err((n, "a blank row"));
        }
        self.i = i;
        Ok(fields)
    }
}

impl<'a> Iterator for Records<'a> {
    /// The record's number (1 is the header) and its fields.
    type Item = Result<(usize, Vec<Cow<'a, str>>), Refusal>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.i >= self.text.len() {
            return None;
        }
        self.n += 1;
        let r = self.record().map(|f| (self.n, f));
        self.done = r.is_err();
        Some(r)
    }
}

/// Every record, owned.
pub fn read(text: &str) -> Result<Vec<Vec<String>>, Refusal> {
    Records::new(text).map(|r| r.map(|(_, f)| f.into_iter().map(Cow::into_owned).collect())).collect()
}

/// One record, CRLF-terminated, each field quoted exactly when it must be.
pub fn write_record(out: &mut String, fields: &[String]) {
    for (k, f) in fields.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        if f.contains([',', '"', '\r', '\n']) {
            out.push('"');
            out.push_str(&f.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(f);
        }
    }
    out.push_str("\r\n");
}

/// The spreadsheet guard of SPEC §9.2: a cell that begins with `=`, `+`, `-`, `@`, `'`, a tab or a
/// carriage return is written with one `'` before it.
pub fn guard(cell: &str) -> String {
    if cell.starts_with(['=', '+', '-', '@', '\'', '\t', '\r']) {
        format!("'{cell}")
    } else {
        cell.to_string()
    }
}

/// And the reader strips one.
pub fn unguard(cell: &str) -> &str {
    cell.strip_prefix('\'').unwrap_or(cell)
}

/// The same, keeping a borrowed cell borrowed.
pub fn unguard_cow(cell: Cow<'_, str>) -> Cow<'_, str> {
    match cell {
        Cow::Borrowed(c) => Cow::Borrowed(unguard(c)),
        Cow::Owned(c) => match c.strip_prefix('\'') {
            Some(rest) => Cow::Owned(rest.to_string()),
            None => Cow::Owned(c),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_reads_rfc_4180_strictly_and_refuses_what_it_would_have_to_repair() {
        let rows = read("a,b\r\n\"x,\"\"y\"\"\r\nz\",\r\n").unwrap();
        assert_eq!(rows, vec![vec!["a".to_string(), "b".into()], vec!["x,\"y\"\r\nz".into(), "".into()]]);
        assert_eq!(read("a,b\nc,d").unwrap().len(), 2);
        assert_eq!(read("a,b\r\n\r\nc,d\r\n"), Err((2, "a blank row")));
        assert_eq!(read("a,b\rc,d\n"), Err((1, "a carriage return that ends no line")));
        assert_eq!(read("a,b\"c\r\n"), Err((1, "a quote inside an unquoted field")));
        assert_eq!(read("\"a\"b,c\r\n"), Err((1, "a character follows a closing quote")));
        assert_eq!(read("a\r\n\"b"), Err((2, "a quoted field is never closed")));
    }

    #[test]
    fn csv_writes_what_it_reads_back_and_guards_every_formula_prefix() {
        let fields: Vec<String> = ["=1+1", "+1", "-1", "@SUM", "'Tis", "\tx", "\rx", "plain", "a,b", "say \"hi\"", "two\nlines"]
            .iter()
            .map(|c| guard(c))
            .collect();
        let mut out = String::new();
        write_record(&mut out, &fields);
        let back: Vec<String> = read(&out).unwrap()[0].iter().map(|c| unguard(c).to_string()).collect();
        assert_eq!(back, ["=1+1", "+1", "-1", "@SUM", "'Tis", "\tx", "\rx", "plain", "a,b", "say \"hi\"", "two\nlines"]);
        assert_eq!(guard("MIIB"), "MIIB");
    }
}
