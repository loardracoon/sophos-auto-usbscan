//! Receives new USB volumes, applies the cache and runs scans in worker threads.

use crate::cache::Cache;
use crate::config::Config;
use crate::{platform, scan, Device};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Engine {
    cfg: Arc<Config>,
    cache: Mutex<Cache>,
    busy: Mutex<HashSet<PathBuf>>,
}

impl Engine {
    pub fn new(cfg: Arc<Config>) -> Arc<Engine> {
        let cache = Cache::load(cfg.cache_file.clone(), cfg.cache_ttl, cfg.cache_max);
        Arc::new(Engine { cfg, cache: Mutex::new(cache), busy: Mutex::new(HashSet::new()) })
    }

    pub fn submit(self: &Arc<Self>, dev: Device) {
        if !self.busy.lock().unwrap().insert(dev.mount.clone()) {
            debug!("scan already running on {}", dev.mount.display());
            return;
        }
        let me = self.clone();
        let spawned = std::thread::Builder::new()
            .name("scan".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                me.process(&dev);
                platform::release(&dev);
                me.busy.lock().unwrap().remove(&dev.mount);
            });
        if let Err(e) = spawned {
            error!("cannot spawn scan thread: {e}");
        }
    }

    fn process(&self, dev: &Device) {
        if self.cache.lock().unwrap().hit(&dev.id) {
            info!("BYPASS {} [{}]: scanned clean within cache_ttl", dev.mount.display(), dev.id);
            return;
        }
        if self.cfg.settle > 0 {
            std::thread::sleep(Duration::from_secs(self.cfg.settle));
        }
        if !dev.mount.exists() {
            warn!("{} disappeared before scan", dev.mount.display());
            return;
        }
        match scan::run(&self.cfg, dev) {
            Ok(summary) => {
                info!("CLEAN {} [{}] {summary}", dev.mount.display(), dev.id);
                self.cache.lock().unwrap().add(&dev.id);
            }
            Err(e) => warn!("ALERT/FAIL {} [{}] {e}", dev.mount.display(), dev.id),
        }
    }
}
