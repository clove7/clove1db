use crate::{
    backup::view::HistoryDisplayMode,
    dto::{InputDto, OutputDto},
    entity::Entity,
    repository::{BackupRecordRepository, Repository},
    units::Result,
};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Domain<E: Entity> {
    repository: Repository<E>,
    _marker: PhantomData<E>,
}

impl<E: Entity> Domain<E> {
    pub fn query(&self) -> crate::query::Query<E> {
        let query = crate::query::Query::new(self.repository.database_manager.clone(),self.repository.table.into());
        #[cfg(feature = "encryption")]
        let query = query.with_sealed(self.repository.sealed.clone());
        query
    }
    pub fn new(repository: Repository<E>) -> Self {
        Self {
            repository,
            _marker: PhantomData,
        }
    }

    pub fn create<I, O>(&self, input: I) -> Result<O>
    where
        I: InputDto<E>,
        O: OutputDto<E>,
    {
        input.validate()?;
        let entity = input.into_entity()?;
        self.repository.set(entity.entity_id(), &entity)?;
        Ok(O::from_entity(entity))
    }

    pub fn get<O: OutputDto<E>>(&self, id: &str) -> Result<O> {
        let entity = self.repository.get(id)?;
        Ok(O::from_entity(entity))
    }

    /// [`Self::get`], but the cache is neither read nor written.
    ///
    /// Use it when walking many keys once — a range scan, a report, an export.
    /// Those fill the cache with rows that are never reused and evict the small
    /// hot rows that justified having one.
    pub fn get_uncached<O: OutputDto<E>>(&self, id: &str) -> Result<O> {
        let entity = self.repository.get_uncached(id)?;
        Ok(O::from_entity(entity))
    }

    pub fn list<O: OutputDto<E>>(&self) -> Result<Vec<O>> {
        let entities = self.repository.list()?;
        Ok(O::from_entities(entities))
    }

    pub fn update<I, O>(&self, id: &str, input: I) -> Result<O>
    where
        I: InputDto<E>,
        O: OutputDto<E>,
    {
        input.validate()?;
        let entity = input.into_entity()?;
        self.repository.set(id, &entity)?;
        Ok(O::from_entity(entity))
    }

    pub fn update_bulk<I, O>(&self, inputs: Vec<(String, I)>) -> Result<(Vec<O>, String)>
    where
        I: InputDto<E>,
        O: OutputDto<E>,
    {
        for (_, input) in &inputs {
            input.validate()?;
        }

        let mut results = Vec::new();
        let mut bulk_ids = Vec::new();

        for (id, input) in inputs {
            let current_version = self.repository.current_version(&id).unwrap_or(0);
            let entity = input.into_entity()?;
            self.repository.set(&id, &entity)?;
            bulk_ids.push((id, current_version));
            results.push(O::from_entity(entity));
        }

        let bulk_id = self.repository.set_bulk(bulk_ids)?;

        Ok((results, bulk_id))
    }

    pub fn create_with_blob<I, O>(&self, input: I, blob: Vec<u8>) -> Result<O>
    where
        I: InputDto<E>,
        O: OutputDto<E>,
    {
        input.validate()?;
        let entity = input.into_entity()?;
        self.repository.create_with_blob(&entity, &blob)?;
        Ok(O::from_entity(entity))
    }

    pub fn set_with_blob(&self, id: &str, meta: &E, blob: &[u8]) -> Result<()> {
        self.repository.set_with_blob(id, meta, blob)
    }

    pub fn open_blob(&self, id: &str) -> Result<crate::blob::BlobReader> {
        self.repository.open_blob(id)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        self.repository.delete(id)?;
        Ok(())
    }

    pub fn restore_by_version(&self, id: &str, version: u64) -> Result<()> {
        self.repository.restore_by_version(id, version)?;
        Ok(())
    }

    pub fn get_by_version(
        &self,
        id: &str,
        version: u64,
    ) -> Result<BackupRecordRepository<E>> {
        self.get_by_version_with_mode(id, version, HistoryDisplayMode::AsStored)
    }

    pub fn get_by_version_with_mode(
        &self,
        id: &str,
        version: u64,
        mode: HistoryDisplayMode,
    ) -> Result<BackupRecordRepository<E>> {
        self.repository.get_by_version(id, version, mode)
    }

    pub fn restore_at(&self, id: &str, timestamp: i64) -> Result<()> {
        self.repository.restore_at(id, timestamp)?;
        Ok(())
    }

    pub fn get_version_by_at(
        &self,
        id: &str,
        timestamp: i64,
    ) -> Result<BackupRecordRepository<E>> {
        self.get_version_by_at_with_mode(id, timestamp, HistoryDisplayMode::AsStored)
    }

    pub fn get_version_by_at_with_mode(
        &self,
        id: &str,
        timestamp: i64,
        mode: HistoryDisplayMode,
    ) -> Result<BackupRecordRepository<E>> {
        self.repository.get_version_by_at(id, timestamp, mode)
    }

    pub fn restore_bulk(&self, bulk_id: &str) -> Result<()> {
        self.repository.restore_bulk(bulk_id)?;
        Ok(())
    }

    pub fn history(&self, id: &str) -> Result<Vec<BackupRecordRepository<E>>> {
        self.history_with_mode(id, HistoryDisplayMode::AsStored)
    }

    pub fn history_with_mode(
        &self,
        id: &str,
        mode: HistoryDisplayMode,
    ) -> Result<Vec<BackupRecordRepository<E>>> {
        self.repository.history(id, mode)
    }

    pub fn history_typed<O: OutputDto<E>>(&self, id: &str) -> Result<Vec<O>> {
        let records = self.repository.history(id, HistoryDisplayMode::AsStored)?;
        let mut out = Vec::new();
        for r in records {
            if r.restorable {
                if let Some(json) = r.data.as_json() {
                    #[cfg(feature = "encryption")]
                    let mut entity: E = serde_json::from_value(json.clone())?;
                    #[cfg(not(feature = "encryption"))]
                    let entity: E = serde_json::from_value(json.clone())?;
                    #[cfg(feature = "encryption")]
                    self.repository.bind_entity(id, &mut entity);
                    out.push(O::from_entity(entity));
                }
            }
        }
        Ok(out)
    }

    pub fn current_version(&self, id: &str) -> Result<u64> {
        self.repository.current_version(id)
    }

    /// A permission to open protected values of this entity's database, for the request in hand.
    /// See [`DatabaseManager::read_grant`](crate::repository::DatabaseManager::read_grant).
    #[cfg(feature = "encryption")]
    pub fn read_grant(&self) -> Result<crate::field_crypto::ReadGrant> {
        self.repository.database_manager.read_grant()
    }

    /// A permission to search the fingerprinted fields of this entity, for the request in hand. It
    /// needs the search key, not the read key. See [`PrintHandle`](crate::field_crypto::PrintHandle).
    #[cfg(feature = "encryption")]
    pub fn search_grant(&self) -> Result<crate::field_crypto::SearchGrant<E>> {
        match &self.repository.sealed {
            Some(hooks) => hooks.search_grant(self.repository.database_manager.event_sink.clone()),
            None => Err(crate::units::ClError::Validation(
                "this entity has no protected fields".into(),
            )),
        }
    }

    /// A checker of secrets against the verification hashes of this entity's database.
    #[cfg(feature = "encryption")]
    pub fn verifier(&self) -> Result<crate::field_crypto::Verifier> {
        self.repository.database_manager.verifier()
    }

    pub fn repo(&self) -> &Repository<E> {
        &self.repository
    }
}
