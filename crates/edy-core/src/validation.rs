use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorKind {
    Empty,
    TooLong,
    InvalidFormat,
    OutOfRange,
    Incoherent,
    Duplicate,
    InvalidTransition,
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    pub field: &'static str,
    pub kind: ValidationErrorKind,
}

impl DomainError {
    pub(crate) const fn new(field: &'static str, kind: ValidationErrorKind) -> Self {
        Self { field, kind }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid domain field {} ({:?})",
            self.field, self.kind
        )
    }
}

impl std::error::Error for DomainError {}

pub(crate) fn bounded_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        return Err(DomainError::new(field, ValidationErrorKind::Empty));
    }
    if value.len() > maximum {
        return Err(DomainError::new(field, ValidationErrorKind::TooLong));
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::new(field, ValidationErrorKind::InvalidFormat));
    }
    Ok(())
}

pub(crate) fn canonical_token(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), DomainError> {
    bounded_text(field, value, maximum)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
    }) || value.starts_with(['-', '_', '.'])
        || value.ends_with(['-', '_', '.'])
        || value.contains("..")
    {
        return Err(DomainError::new(field, ValidationErrorKind::InvalidFormat));
    }
    Ok(())
}

pub(crate) fn normalized_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let number = |start: usize, end: usize| -> Option<u32> { value.get(start..end)?.parse().ok() };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1970 && (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}
