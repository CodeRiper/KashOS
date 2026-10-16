//! Spring physics + id-keyed animation store.
//! Springs are parameterised like SwiftUI/UIKit: `response` (seconds, ≈ period) and `damping` ratio ζ.
use alloc::collections::BTreeMap;
use crate::mathf::*;

#[derive(Clone, Copy, Debug)]
pub struct Spring {
    pub x: f32,
    pub v: f32,
    pub target: f32,
    k: f32,
    c: f32,
}

impl Spring {
    pub fn new(x: f32, response: f32, damping: f32) -> Spring {
        let w = TAU / response.max(0.02);
        Spring { x, v: 0.0, target: x, k: w * w, c: 2.0 * damping * w }
    }
    pub fn smooth(x: f32) -> Spring { Spring::new(x, 0.35, 1.0) }
    pub fn snappy(x: f32) -> Spring { Spring::new(x, 0.22, 0.92) }
    pub fn bouncy(x: f32) -> Spring { Spring::new(x, 0.42, 0.62) }
    pub fn set(&mut self, t: f32) { self.target = t; }
    pub fn snap(&mut self, x: f32) { self.x = x; self.target = x; self.v = 0.0; }
    pub fn kick(&mut self, v: f32) { self.v += v; }
    pub fn settled(&self) -> bool { fabs(self.x - self.target) < 0.002 && fabs(self.v) < 0.02 }
    pub fn update(&mut self, dt: f32) {
        let dt = dt.min(0.05);
        let n = ((dt / 0.004) as i32 + 1).min(16);
        let h = dt / n as f32;
        for _ in 0..n {
            let a = self.k * (self.target - self.x) - self.c * self.v;
            self.v += a * h;
            self.x += self.v * h;
        }
        if self.settled() { self.x = self.target; self.v = 0.0; }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Preset { Smooth, Snappy, Bouncy, Slow }

/// Per-owner store of springs, addressed by a u32 id (hash of widget label etc.).
#[derive(Default)]
pub struct Anims {
    map: BTreeMap<u32, Spring>,
}

pub fn id_of(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.bytes() { h ^= b as u32; h = h.wrapping_mul(0x0100_0193); }
    h
}
pub fn id2(a: u32, b: u32) -> u32 { (a ^ b.wrapping_mul(0x9e37_79b1)).rotate_left(7).wrapping_mul(0x85eb_ca6b) }

impl Anims {
    pub fn new() -> Anims { Anims { map: BTreeMap::new() } }
    /// Move toward `target` with a spring; returns the current value. First call snaps.
    pub fn follow(&mut self, id: u32, target: f32, p: Preset) -> f32 {
        let sp = self.map.entry(id).or_insert_with(|| match p {
            Preset::Smooth => Spring::smooth(target),
            Preset::Snappy => Spring::snappy(target),
            Preset::Bouncy => Spring::bouncy(target),
            Preset::Slow => Spring::new(target, 0.6, 1.0),
        });
        sp.target = target;
        sp.x
    }
    pub fn get(&self, id: u32) -> Option<f32> { self.map.get(&id).map(|s| s.x) }
    pub fn kick(&mut self, id: u32, v: f32) { if let Some(s) = self.map.get_mut(&id) { s.kick(v); } }
    pub fn snap(&mut self, id: u32, x: f32) { if let Some(s) = self.map.get_mut(&id) { s.snap(x); } }
    pub fn step(&mut self, dt: f32) { for s in self.map.values_mut() { s.update(dt); } }
    pub fn animating(&self) -> bool { self.map.values().any(|s| !s.settled()) }
    pub fn unsettled(&self) -> alloc::vec::Vec<(u32, f32, f32, f32)> { self.map.iter().filter(|(_, s)| !s.settled()).map(|(k, s)| (*k, s.x, s.target, s.v)).collect() }
    pub fn len(&self) -> usize { self.map.len() }
}

pub fn ease_out_cubic(t: f32) -> f32 { let u = 1.0 - saturate(t); 1.0 - u * u * u }
pub fn ease_in_out(t: f32) -> f32 { let t = saturate(t); t * t * (3.0 - 2.0 * t) }
