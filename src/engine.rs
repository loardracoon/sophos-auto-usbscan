//! Receives new USB volumes, applies the cache and runs scans in worker
//! threads named `scan-<id>` (the correlation id seen in every log line).

use crate::cache::Cache;
use crate::config::Config;
use crate::scan::ScanError;
use crate::status::{self, Counter};
use crate::{platform, scan, Device};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Engine {
    cfg: Arc<Config>,
    /// Serialises cache read-modify-write between workers.
    cache_lock: Mutex<()>,
    busy: Mutex<HashSet<PathBuf>>,
    next_id: AtomicU64,
}

impl Engine {
    pub fn new(cfg: Arc<Config>) -> Arc<Engine> {
        Arc::new(Engine { cfg, cache_lock: Mutex::new(()), busy: Mutex::new(HashSet::new()), next_id: AtomicU64::new(1) })
    }

    /// The cache is re-read on every decision so `usbscan cache clear`
    /// takes effect on the running service immediately.
    fn cache(&self) -> Cache {
        Cache::load(self.cfg.cache_file.clone(), self.cfg.cache_ttl, self.cfg.cache_max)
    }

    pub fn submit(self: &Arc<Self>, dev: Device) {
        if !self.busy.lock().unwrap().insert(dev.mount.clone()) {
            debug!("scan already running on {}, ignoring duplicate event", dev.mount.display());
            return;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mount = dev.mount.clone();
        let me = self.clone();
        let spawned = std::thread::Builder::new().name(format!("scan-{id}")).stack_size(256 * 1024).spawn(move || {
            me.process(id, &dev);
            platform::release(&dev);
            me.busy.lock().unwrap().remove(&dev.mount);
        });
        if let Err(e) = spawned {
            error!("cannot spawn scan thread: {e}");
            self.busy.lock().unwrap().remove(&mount);
        }
    }

    fn process(&self, id: u64, dev: &Device) {
        let mount = dev.mount.display().to_string();
        {
            let _g = self.cache_lock.lock().unwrap();
            let cache = self.cache();
            if cache.hit(&dev.id) {
                ev!(Info, "scan_bypass", scan = id, mount = mount, device = dev.id, reason = "scanned clean within cache_ttl");
                status::inc(Counter::Bypassed);
                status::flush();
                return;
            }
            if !cache.enabled() {
                debug!("cache disabled (cache_ttl=0)");
            } else if dev.id.is_empty() {
                debug!("device has no stable id, cache not used");
            } else {
                debug!("cache miss for {}", dev.id);
            }
        }
        if self.cfg.settle > 0 {
            debug!("waiting settle={}s before scanning", self.cfg.settle);
            std::thread::sleep(Duration::from_secs(self.cfg.settle));
        }
        if !dev.mount.exists() {
            ev!(Warn, "scan_skipped", scan = id, mount = mount, reason = "volume disappeared before scan");
            return;
        }

        ev!(Info, "scan_start", scan = id, mount = mount, device = dev.id, desc = dev.desc);
        status::scan_begin(id, &mount);
        let t = Instant::now();
        let res = scan::run(&self.cfg, dev);
        let ms = t.elapsed().as_millis();
        match res {
            Ok(summary) => {
                ev!(Info, "scan_clean", scan = id, mount = mount, device = dev.id, duration_ms = ms, result = summary);
                status::inc(Counter::Clean);
                let _g = self.cache_lock.lock().unwrap();
                self.cache().add(&dev.id);
            }
            Err(ScanError::Threat(e)) => {
                ev!(Error, "scan_alert", scan = id, mount = mount, device = dev.id, duration_ms = ms, result = e);
                status::inc(Counter::Alert);
                status::alert(format!("{} scan-{id} {mount} {}: {e}", crate::log::timestamp(), dev.id));
            }
            Err(ScanError::Failed(e)) => {
                ev!(Warn, "scan_failed", scan = id, mount = mount, device = dev.id, duration_ms = ms, result = e);
                status::inc(Counter::Failed);
            }
        }
        status::scan_end(id);
    }
}
