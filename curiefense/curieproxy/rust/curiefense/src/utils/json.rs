use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

/// newtype for the BT format
pub struct NameValue<'t, K: Eq + std::hash::Hash, V> {
    inner: &'t HashMap<K, V>,
}

impl<'t, K: Eq + std::hash::Hash, V> NameValue<'t, K, V> {
    pub fn new(inner: &'t HashMap<K, V>) -> Self {
        NameValue { inner }
    }
}

impl<'t, K: Eq + std::hash::Hash + std::fmt::Display, V: Serialize> Serialize for NameValue<'t, K, V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.inner.iter().map(|(k, v)| {
            let mut inner = serde_json::Map::new();
            inner.insert("name".into(), Value::String(k.to_string()));
            inner.insert(
                "value".into(),
                serde_json::to_value(v).unwrap_or_else(|rr| Value::String(rr.to_string())),
            );
            Value::Object(inner)
        }))
    }
}