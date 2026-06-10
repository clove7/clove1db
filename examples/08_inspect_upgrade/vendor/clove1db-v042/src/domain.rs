use itertools::Itertools;

use crate::{
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

    pub fn delete(&self, id: &str) -> Result<()> {
        self.repository.delete(id)?;
        Ok(())
    }

    pub fn restore_by_version(&self, id: &str, version: u64) -> Result<()> {
        self.repository.restore_by_version(id, version)?;
        Ok(())
    }

    pub fn get_by_version<O: OutputDto<E>>(
        &self,
        id: &str,
        version: u64,
    ) -> Result<BackupRecordRepository<O>> {
        let entity = self.repository.get_by_version(id, version)?;

        let data = if let Some(data) = entity.data {
            let value = O::from_entity(data);
            Some(value)
        } else {
            None
        };

        Ok(BackupRecordRepository::<O> {
            version: entity.version,
            timestamp: entity.timestamp,
            date: entity.date,
            operation: entity.operation,
            table: entity.table,
            key: entity.key,
            data: data,
            restored_version: entity.restored_version,
            bulk_id: entity.bulk_id,
        })
    }

    pub fn restore_at(&self, id: &str, timestamp: i64) -> Result<()> {
        self.repository.restore_at(id, timestamp)?;
        Ok(())
    }

    pub fn get_version_by_at<O: OutputDto<E>>(
        &self,
        id: &str,
        timestamp: i64,
    ) -> Result<BackupRecordRepository<O>> {
        let entity = self.repository.get_version_by_at(id, timestamp)?;

        let data = if let Some(data) = entity.data {
            let value = O::from_entity(data);
            Some(value)
        } else {
            None
        };

        Ok(BackupRecordRepository::<O> {
            version: entity.version,
            timestamp: entity.timestamp,
            date: entity.date,
            operation: entity.operation,
            table: entity.table,
            key: entity.key,
            data: data,
            restored_version: entity.restored_version,
            bulk_id: entity.bulk_id,
        })
    }

    pub fn restore_bulk(&self, bulk_id: &str) -> Result<()> {
        self.repository.restore_bulk(bulk_id)?;
        Ok(())
    }

    pub fn history<O: OutputDto<E>>(&self, id: &str) -> Result<Vec<BackupRecordRepository<O>>> {
        let entities = self.repository.history(id)?;

        let history = entities
            .into_iter()
            .map(|record| {
                let data = if let Some(data) = record.data {
                    let value = O::from_entity(data);
                    Some(value)
                } else {
                    None
                };

                BackupRecordRepository::<O> {
                    version: record.version,
                    timestamp: record.timestamp,
                    date: record.date,
                    operation: record.operation,
                    table: record.table,
                    key: record.key,
                    data: data,
                    restored_version: record.restored_version,
                    bulk_id: record.bulk_id,
                }
            })
            .collect_vec();

        Ok(history)
    }

    pub fn current_version(&self, id: &str) -> Result<u64> {
        self.repository.current_version(id)
    }

    pub fn repo(&self) -> &Repository<E> {
        &self.repository
    }
}
