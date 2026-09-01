//! Special-hash sync: MongoDB `file` collection -> in-memory DashMap.

use std::collections::HashMap;

use tracing::debug;

use crate::state::AppState;

/// Full sync from MongoDB into the in-memory DashMap.
/// Uses a streaming cursor so there is NO timeout: 200k+ docs will all be
/// loaded, as long as MongoDB keeps sending data.  The old map contents are
/// replaced atomically only after the cursor is exhausted, so in-flight
/// requests always see a consistent snapshot.
pub async fn load_special_hashes(state: &AppState) {
    let Some(col) = &state.mongo_col else {
        return; // MongoDB not configured – nothing to do
    };
    match col.find(None, None).await {
        Ok(mut cursor) => {
            let mut fresh: HashMap<String, String> = HashMap::new();
            loop {
                match cursor.advance().await {
                    Ok(true) => {
                        if let Ok(doc) = cursor.deserialize_current() {
                            let id = doc
                                .get_object_id("_id")
                                .map(|oid| oid.to_hex())
                                .or_else(|_| doc.get_str("_id").map(|s| s.to_string()));
                            let stype = doc.get_str("special_type").map(|s| s.to_string());
                            if let (Ok(id), Ok(stype)) = (id, stype) {
                                fresh.insert(id, stype);
                            }
                        }
                    }
                    _ => break,
                }
            }
            // Swap in the fresh snapshot atomically
            state.special_hashes.retain(|k, _| fresh.contains_key(k.as_str()));
            for (k, v) in fresh {
                state.special_hashes.insert(k, v);
            }
            debug!("Loaded {} special hashes from MongoDB", state.special_hashes.len());
        }
        Err(e) => tracing::error!("MongoDB error loading special hashes: {}", e),
    }
}
