use serde::{Deserialize, Serialize};

pub trait Entity: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static {
    fn entity_id(&self) -> &str;
}
