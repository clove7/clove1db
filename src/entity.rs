use serde::{Deserialize, Serialize};

pub trait Entity: Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static {
    fn entity_id(&self) -> &str;
    /// Declare the serialized field that is always equal to the repository row key.
    /// Writes reject mismatches atomically; existing rows are checked when registering.
    /// Leave None if keys are independent.
    fn id_field() -> Option<crate::fields::Field<Self,String>> { None }

}
