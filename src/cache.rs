//! FIFO cache of recently scanned devices: `id<TAB>epoch` per line.

use crate::log::now_secs;
use std::path::PathBuf;

pub struct Cache {
    path: PathBuf,
    ttl: u64,
    max: usize,
    entries: Vec<(String, u64)>,
}

impl Cache {
    pub fn load(path: PathBuf, ttl: u64, max: usize) -> Cache {
        let entries = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let (id, t) = l.rsplit_once('\t')?;
                Some((id.to_string(), t.parse().ok()?))
            })
            .collect();
        Cache { path, ttl, max, entries }
    }

    pub fn entries(&self) -> &[(String, u64)] {
        &self.entries
    }

    pub fn ttl(&self) -> u64 {
        self.ttl
    }

    pub fn clear(&mut self) -> std::io::Result<()> {
        self.entries.clear();
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.ttl > 0 && self.max > 0
    }

    pub fn hit(&self, id: &str) -> bool {
        if !self.enabled() || id.is_empty() {
            return false;
        }
        let now = now_secs();
        self.entries.iter().any(|(i, t)| i == id && now.saturating_sub(*t) < self.ttl)
    }

    pub fn add(&mut self, id: &str) {
        if !self.enabled() || id.is_empty() {
            return;
        }
        let now = now_secs();
        let ttl = self.ttl;
        self.entries.retain(|(i, t)| i != id && now.saturating_sub(*t) < ttl);
        self.entries.push((id.to_string(), now));
        if self.entries.len() > self.max {
            let drop = self.entries.len() - self.max;
            self.entries.drain(..drop);
        }
        self.save();
    }

    fn save(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let body: String = self.entries.iter().map(|(i, t)| format!("{i}\t{t}\n")).collect();
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &self.path)).is_err() {
            warn!("cannot write cache {}", self.path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fifo_and_ttl() {
        let p = std::env::temp_dir().join(format!("usbscan-cache-{}", std::process::id()));
        let mut c = Cache::load(p.clone(), 100, 2);
        assert!(!c.hit("a"));
        c.add("a");
        c.add("b");
        c.add("c"); // evicts "a"
        assert!(!c.hit("a") && c.hit("b") && c.hit("c"));
        let c2 = Cache::load(p.clone(), 100, 2); // persisted
        assert!(c2.hit("c"));
        let off = Cache::load(p.clone(), 0, 2); // ttl 0 = disabled
        assert!(!off.hit("c"));
        let _ = std::fs::remove_file(p);
    }
}
