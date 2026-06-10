use serde::{Deserialize, Serialize};
use crate::{entity::Entity, units::Result};

pub trait InputDto<E: Entity>: for<'de> Deserialize<'de> + Sized {
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    fn into_entity(self) -> Result<E>;
}

pub trait OutputDto<E: Entity>: Serialize + Sized {
    fn from_entity(entity: E) -> Self;

    fn from_entities(entities: Vec<E>) -> Vec<Self> {
        entities.into_iter().map(Self::from_entity).collect()
    }
}
