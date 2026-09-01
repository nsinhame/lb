//! Coercion helpers for reading loosely-typed BSON fields.

use mongodb::bson::Bson;

/// Coerce a BSON value that may be Long/Int/Double/String into i64.
pub fn bson_to_i64(v: Option<&Bson>) -> Option<i64> {
    match v? {
        Bson::Int64(n) => Some(*n),
        Bson::Int32(n) => Some(*n as i64),
        Bson::Double(f) => Some(*f as i64),
        Bson::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Coerce a BSON value that may be Double/Long/Int/String into f64.
pub fn bson_to_f64(v: Option<&Bson>) -> Option<f64> {
    match v? {
        Bson::Double(f) => Some(*f),
        Bson::Int64(n) => Some(*n as f64),
        Bson::Int32(n) => Some(*n as f64),
        Bson::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Like `bson_to_f64`, but also accepts a genuine BSON DateTime (telethon-plgb
/// stores `join_date` as a real datetime, unlike plgb's numeric join_date).
pub fn bson_datetime_to_f64(v: Option<&Bson>) -> Option<f64> {
    match v? {
        Bson::DateTime(dt) => Some(dt.timestamp_millis() as f64 / 1000.0),
        other => bson_to_f64(Some(other)),
    }
}
