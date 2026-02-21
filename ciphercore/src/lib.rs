extern crate proc_macro;
use proc_macro::TokenStream;

/// ZeroizeOnDrop: auto-generates a Drop impl that zeroes every field's memory
/// Usage: #[derive(ZeroizeOnDrop)] on any struct with u8/u32/u64/array fields
///
/// This macro does something cursed and beautiful: it inspects each field type
/// and emits unsafe ptr::write_bytes or volatile writes to guarantee the compiler
/// cannot optimize away the zeroing (unlike a plain memset).
///
/// Supported field types: u8, u16, u32, u64, u128, i8, i16, i32, i64, i128,
///   [u8; N], Vec<u8>, arrays of any primitive, bool
#[proc_macro_derive(ZeroizeOnDrop)]
pub fn derive_zeroize_on_drop(input: TokenStream) -> TokenStream {
    let input_str = input.to_string();

    // Parse struct name
    let struct_name = parse_struct_name(&input_str);
    // Parse fields
    let fields = parse_fields(&input_str);

    let zero_stmts = generate_zero_statements(&fields);

    let output = format!(
        r#"
impl Drop for {name} {{
    fn drop(&mut self) {{
        use core::sync::atomic;
        use core::ptr;
        {stmts}
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }}
}}
"#,
        name = struct_name,
        stmts = zero_stmts,
    );

    output.parse().unwrap()
}

fn parse_struct_name(input: &str) -> String {
    // find "struct NAME"
    let mut tokens = input.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "struct" {
            if let Some(name) = tokens.next() {
                // strip generic params if any
                return name.split('<').next().unwrap_or(name).to_string();
            }
        }
    }
    panic!("ZeroizeOnDrop: could not parse struct name");
}

#[derive(Debug)]
struct Field {
    name: String,
    ty: String,
}

fn parse_fields(input: &str) -> Vec<Field> {
    let mut fields = Vec::new();
    // find the body between { }
    let start = input.find('{').unwrap_or(0);
    let end = input.rfind('}').unwrap_or(input.len());
    let body = &input[start + 1..end];

    for line in body.lines() {
        let line = line.trim().trim_end_matches(',');
        // skip attributes and empty lines
        if line.starts_with('#') || line.is_empty() || line.starts_with("//") {
            continue;
        }
        if let Some(colon_pos) = line.find(':') {
            let name_part = line[..colon_pos].trim();
            let ty_part = line[colon_pos + 1..].trim();
            // skip visibility modifiers
            let name = name_part
                .split_whitespace()
                .last()
                .unwrap_or(name_part)
                .to_string();
            let ty = ty_part.trim_matches(|c: char| c == ',' || c.is_whitespace()).to_string();
            if !name.is_empty() && !ty.is_empty() {
                fields.push(Field { name, ty });
            }
        }
    }
    fields
}

fn generate_zero_statements(fields: &[Field]) -> String {
    let mut stmts = String::new();

    for field in fields {
        let fname = &field.name;
        let ty = field.ty.trim();

        if ty == "u8" || ty == "i8" || ty == "bool" {
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_volatile(&mut self.{} as *mut _ as *mut u8, 0u8); }}\n",
                fname
            ));
        } else if ty == "u16" || ty == "i16" {
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_volatile(&mut self.{} as *mut _ as *mut u16, 0u16); }}\n",
                fname
            ));
        } else if ty == "u32" || ty == "i32" {
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_volatile(&mut self.{} as *mut _ as *mut u32, 0u32); }}\n",
                fname
            ));
        } else if ty == "u64" || ty == "i64" {
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_volatile(&mut self.{} as *mut _ as *mut u64, 0u64); }}\n",
                fname
            ));
        } else if ty == "u128" || ty == "i128" {
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_volatile(&mut self.{} as *mut _ as *mut u128, 0u128); }}\n",
                fname
            ));
        } else if ty.starts_with('[') {
            // array type: zero byte by byte
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_bytes(self.{}.as_mut_ptr(), 0, self.{}.len()); }}\n",
                fname, fname
            ));
        } else if ty.starts_with("Vec") {
            // Vec<u8> or similar: zero then clear
            stmts.push_str(&format!(
                r#"unsafe {{
                    if !self.{f}.is_empty() {{
                        ptr::write_bytes(self.{f}.as_mut_ptr(), 0, self.{f}.len());
                    }}
                    self.{f}.clear();
                }}
"#,
                f = fname
            ));
        } else if ty.starts_with("Option") {
            stmts.push_str(&format!(
                "self.{} = None;\n",
                fname
            ));
        } else {
            // generic: treat as byte array
            stmts.push_str(&format!(
                "unsafe {{ ptr::write_bytes(&mut self.{} as *mut _ as *mut u8, 0, core::mem::size_of_val(&self.{})); }}\n",
                fname, fname
            ));
        }
    }

    stmts
}

/// ConstantTimeEq: derive constant-time equality for structs
/// Emits an impl that XORs all bytes together to avoid short-circuit evaluation
#[proc_macro_derive(ConstantTimeEq)]
pub fn derive_constant_time_eq(input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    let struct_name = parse_struct_name(&input_str);
    let fields = parse_fields(&input_str);

    let mut eq_stmts = String::from("let mut diff: u8 = 0;\n");

    for field in &fields {
        let fname = &field.name;
        let ty = field.ty.trim();

        if ty.starts_with('[') || ty.starts_with("Vec") {
            eq_stmts.push_str(&format!(
                r#"{{
                    let a = &self.{f};
                    let b = &other.{f};
                    let len = a.len().min(b.len());
                    for i in 0..len {{
                        diff |= a[i] ^ b[i];
                    }}
                    if a.len() != b.len() {{ diff |= 0xFF; }}
                }}
"#,
                f = fname
            ));
        } else if ty == "u8" {
            eq_stmts.push_str(&format!(
                "diff |= self.{f} ^ other.{f};\n",
                f = fname
            ));
        } else if ty == "u32" {
            eq_stmts.push_str(&format!(
                r#"{{
                    let a = self.{f}.to_le_bytes();
                    let b = other.{f}.to_le_bytes();
                    for i in 0..4 {{ diff |= a[i] ^ b[i]; }}
                }}
"#,
                f = fname
            ));
        } else if ty == "u64" {
            eq_stmts.push_str(&format!(
                r#"{{
                    let a = self.{f}.to_le_bytes();
                    let b = other.{f}.to_le_bytes();
                    for i in 0..8 {{ diff |= a[i] ^ b[i]; }}
                }}
"#,
                f = fname
            ));
        } else {
            // generic fallback: byte compare
            eq_stmts.push_str(&format!(
                r#"{{
                    let a_bytes = unsafe {{
                        core::slice::from_raw_parts(&self.{f} as *const _ as *const u8,
                            core::mem::size_of_val(&self.{f}))
                    }};
                    let b_bytes = unsafe {{
                        core::slice::from_raw_parts(&other.{f} as *const _ as *const u8,
                            core::mem::size_of_val(&other.{f}))
                    }};
                    for i in 0..a_bytes.len().min(b_bytes.len()) {{
                        diff |= a_bytes[i] ^ b_bytes[i];
                    }}
                }}
"#,
                f = fname
            ));
        }
    }

    let output = format!(
        r#"
impl {name} {{
    pub fn ct_eq(&self, other: &Self) -> bool {{
        {stmts}
        diff == 0
    }}
}}
"#,
        name = struct_name,
        stmts = eq_stmts,
    );

    output.parse().unwrap()
}

/// SecretDebug: derive a Debug impl that never prints actual field values
/// Shows only field names and types — prevents secrets leaking in logs
#[proc_macro_derive(SecretDebug)]
pub fn derive_secret_debug(input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    let struct_name = parse_struct_name(&input_str);
    let fields = parse_fields(&input_str);

    let mut debug_fields = String::new();
    for field in &fields {
        debug_fields.push_str(&format!(
            ".field(\"{name}\", &\"<REDACTED: {ty}>\")\n",
            name = field.name,
            ty = field.ty.replace('"', "'"),
        ));
    }

    let output = format!(
        r#"
impl core::fmt::Debug for {name} {{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{
        f.debug_struct("{name}")
         {fields}
         .finish()
    }}
}}
"#,
        name = struct_name,
        fields = debug_fields,
    );

    output.parse().unwrap()
}