//! What `databases` hands out of an entry, and what may be done with it
//! (`docs/threat-model.md` G-3).
//!
//! A [`Value`] is one of two things. A [`Shareable`](Value::Shareable) value
//! may leave the process as it is, as `copy` puts a password on the
//! clipboard. A [`DeriveOnly`](Value::DeriveOnly) value, a one-time-password
//! seed or an attachment, may only be used to make something new from it: a
//! code, a signature. Its bytes are behind [`Secret::reveal`], which a clippy
//! lint (`clippy.toml`) allows only in the places that derive.

/// A value of an entry: a field's text or an attachment's bytes.
pub enum Value<'a, T: ?Sized> {
    /// May leave the process as it is.
    Shareable(&'a T),
    /// May only be used to derive something new.
    DeriveOnly(Secret<'a, T>),
}

impl<'a, T: ?Sized> Value<'a, T> {
    /// The value, if it may leave the process as it is.
    pub fn shareable(&self) -> Option<&'a T> {
        match self {
            Value::Shareable(value) => Some(value),
            Value::DeriveOnly(_) => None,
        }
    }
}

/// A value that only derives. It is not a reference to its contents, and it
/// has no `Debug`, `Display`, `Serialize` or `Clone`: the contents come out
/// through [`Secret::reveal`] and nowhere else.
pub struct Secret<'a, T: ?Sized>(&'a T);

impl<'a, T: ?Sized> Secret<'a, T> {
    pub(super) fn new(contents: &'a T) -> Secret<'a, T> {
        Secret(contents)
    }

    /// The contents. Derive from them; never hand them out. Calling this is
    /// disallowed by clippy except under an `#[allow(clippy::disallowed_methods)]`
    /// that says why the reader derives.
    pub fn reveal(&self) -> &'a T {
        self.0
    }
}
