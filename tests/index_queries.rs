use clove1db::{CloveFields,entity::Entity,query::{Desc,optimizer::Plan},storage::{Storage,StorageConfig,DatabaseConfig}};
use serde::{Serialize,Deserialize};use std::{time::{Instant,Duration},thread};
#[derive(Clone,Default,Debug,Serialize,Deserialize,CloveFields)] struct Note{id:String,n:i64,title:String,labels:Vec<String>}
impl Entity for Note{fn entity_id(&self)->&str{&self.id}}
fn setup()->Storage {Storage::builder(StorageConfig::default()).add_database(DatabaseConfig::new("records","store").dir_path(std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())).has_cache(false).register::<Note>("notes")).build().unwrap()}
#[test] fn automatic_value_text_and_multikey_queries() {
 let s=setup();let db=s.db_manager("store");let entries=(0..3000).map(|i|("notes".into(),format!("{i:05}"),serde_json::to_vec(&Note{id:format!("{i:05}"),n:i%7,title:format!("alpha note {i}"),labels:vec!["blue".into(),"blue".into()]}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
 let q=s.domain::<Note>().query().filter(Note::n.eq(3)).order_by(Note::id,Desc).limit(11);
 for _ in 0..30{assert_eq!(q.count().unwrap(),429);}
 let start=Instant::now();loop {if q.explain().unwrap().selected==Plan::IndexEquality{break}assert!(start.elapsed()<Duration::from_secs(10),"automatic index did not become usable");let _=q.count().unwrap();thread::sleep(Duration::from_millis(10));}
 assert_eq!(q.collect().unwrap().len(),11);assert_eq!(q.collect().unwrap()[0].id,"02999");
 for _ in 0..30 {assert_eq!(s.domain::<Note>().query().filter(Note::title.text("alpha note")).count().unwrap(),3000);assert_eq!(s.domain::<Note>().query().filter(Note::labels.any().eq("blue")).count().unwrap(),3000);}
 assert_eq!(s.domain::<Note>().query().filter(Note::n.ge(5).and(Note::n.le(6))).count().unwrap(),856);
 assert_eq!(s.domain::<Note>().query().filter(Note::n.eq(0).or(Note::n.eq(1))).count().unwrap(),858);
 s.close();
}

#[test] fn fuzzy_distance_unicode_and_similarity_order() {
 let s=setup();let db=s.db_manager("store");let entries=[("a","alpha"),("b","alphi"),("c","beta"),("d","ALPHA note")].into_iter().map(|(id,title)|("notes".into(),id.into(),serde_json::to_vec(&Note{id:id.into(),n:0,title:title.into(),labels:vec![]}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
 assert_eq!(s.domain::<Note>().query().filter(Note::title.fuzzy("alpha",1)).count().unwrap(),3);
 assert_eq!(s.domain::<Note>().query().filter(Note::title.fuzzy("alpha",0)).count().unwrap(),2);
 assert!(s.domain::<Note>().query().filter(Note::title.fuzzy("alpha",3)).count().is_err());
 let rows=s.domain::<Note>().query().order_by(Note::title.similarity("alpha"),Desc).collect().unwrap();assert_eq!(rows[0].id,"a");assert_eq!(rows[1].id,"b");s.close();
}

#[cfg(feature="crash-inject")]
#[test]fn lifecycle_uses_injected_uptime_and_report_is_read_only(){
 let s=setup();let db=s.db_manager("store");let entries=(0..1000).map(|i|("notes".into(),format!("{i:05}"),serde_json::to_vec(&Note{id:format!("{i:05}"),n:i%7,title:"plain".into(),labels:vec![]}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();let q=s.domain::<Note>().query().filter(Note::n.eq(3));
 for _ in 0..30{assert_eq!(q.count().unwrap(),143);}let started=Instant::now();let first=loop {if let Some(report)=s.index_report().into_iter().find(|r|r.ready){break report}assert!(started.elapsed()<Duration::from_secs(10));thread::sleep(Duration::from_millis(10));};
 thread::sleep(Duration::from_millis(50));let settled=s.index_report().into_iter().find(|r|r.id==first.id).unwrap();let reads=settled.reads;for _ in 0..50{let _=s.index_report();}thread::sleep(Duration::from_millis(30));let before=s.index_report().into_iter().find(|r|r.id==first.id).unwrap();assert_eq!(before.reads,reads);
 s.test_advance_index_clock(Duration::from_millis(before.idle_after_ms+100));let started=Instant::now();loop{if s.index_report().iter().any(|r|r.id==first.id&&r.state==clove1db::indexes::IndexState::Idle){break}assert!(started.elapsed()<Duration::from_secs(5));thread::sleep(Duration::from_millis(10));}
 assert_eq!(q.count().unwrap(),143);let started=Instant::now();let active=loop{if let Some(report)=s.index_report().into_iter().find(|r|r.id!=first.id&&r.replacement==Some(first.id)&&r.ready){break report}assert!(started.elapsed()<Duration::from_secs(10));let _=q.count().unwrap();thread::sleep(Duration::from_millis(10));};
 assert!(s.index_report().iter().any(|r|r.id==first.id&&r.state==clove1db::indexes::IndexState::Merged&&r.replacement==Some(active.id)));s.test_advance_index_clock(Duration::from_millis(active.abandon_after_ms+100));let started=Instant::now();loop{if s.index_report().iter().any(|r|r.id==active.id&&r.state==clove1db::indexes::IndexState::Abandoned){break}assert!(started.elapsed()<Duration::from_secs(5));thread::sleep(Duration::from_millis(10));}s.close();
}

#[cfg(feature="crash-inject")]
#[test]fn allow_stale_page_marks_older_index_and_fresh_query_catches_up(){
 use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};use std::sync::Arc;
 let s=setup();let db=s.db_manager("store");let entries=(0..5000).map(|i|("notes".into(),format!("{i:06}"),serde_json::to_vec(&Note{id:format!("{i:06}"),n:i%7,title:"seed".into(),labels:vec![]}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();let q=s.domain::<Note>().query().filter(Note::n.eq(3));for _ in 0..40{let _=q.count().unwrap();}let started=Instant::now();loop{if q.explain().unwrap().selected==Plan::IndexEquality{break}assert!(started.elapsed()<Duration::from_secs(10));thread::sleep(Duration::from_millis(5));}
 let limited=q.clone().limit(20);let hint=limited.test_plans(false).unwrap().into_iter().find(|p|p.plan==Plan::IndexEquality).unwrap();let running=Arc::new(AtomicBool::new(true));let flag=running.clone();let inserted=Arc::new(AtomicUsize::new(0));let inserted_writer=inserted.clone();let writer=db.clone();let join=thread::spawn(move||{for batch in 0..400 {if !flag.load(Ordering::Acquire){break}let base=5000+batch*50;let extra=(base..base+50).map(|i|("notes".into(),format!("{i:06}"),serde_json::to_vec(&Note{id:format!("{i:06}"),n:3,title:"new".into(),labels:vec![]}).unwrap())).collect::<Vec<_>>();writer.commit_batch_atomic(&extra,&[]).unwrap();inserted_writer.fetch_add(50,Ordering::Release);thread::sleep(Duration::from_millis(1));}flag.store(false,Ordering::Release);});let started=Instant::now();let page=loop{let page=limited.clone().test_force_plan(hint.clone()).allow_stale().page().unwrap();if page.stale{break page}assert!(running.load(Ordering::Acquire)&&started.elapsed()<Duration::from_secs(10),"writer finished before an older index page was observed");thread::sleep(Duration::from_millis(1));};running.store(false,Ordering::Release);join.join().unwrap();assert!(page.index_sequence.unwrap()<page.sequence);assert_eq!(page.items.len(),20);let expected=(0..5000).filter(|i|i%7==3).count() as u64+inserted.load(Ordering::Acquire) as u64;assert_eq!(q.count().unwrap(),expected);s.close();
}
