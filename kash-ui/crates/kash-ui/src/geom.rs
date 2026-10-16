//! Geometry primitives (all f32 so layout and animation can be sub-pixel smooth).
use crate::mathf::*;

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct Pt { pub x: f32, pub y: f32 }
impl Pt { pub const fn new(x: f32, y: f32) -> Pt { Pt { x, y } } }

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct Rect { pub x: f32, pub y: f32, pub w: f32, pub h: f32 }

impl Rect {
    pub const ZERO: Rect = Rect { x: 0.0, y: 0.0, w: 0.0, h: 0.0 };
    #[inline] pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Rect { Rect { x, y, w, h } }
    #[inline] pub fn right(&self) -> f32 { self.x + self.w }
    #[inline] pub fn bottom(&self) -> f32 { self.y + self.h }
    #[inline] pub fn cx(&self) -> f32 { self.x + self.w * 0.5 }
    #[inline] pub fn cy(&self) -> f32 { self.y + self.h * 0.5 }
    #[inline] pub fn center(&self) -> Pt { Pt::new(self.cx(), self.cy()) }
    #[inline] pub fn contains(&self, x: f32, y: f32) -> bool { x >= self.x && y >= self.y && x < self.right() && y < self.bottom() }
    #[inline] pub fn inset(&self, d: f32) -> Rect { Rect::new(self.x + d, self.y + d, (self.w - 2.0 * d).max(0.0), (self.h - 2.0 * d).max(0.0)) }
    #[inline] pub fn inset_xy(&self, dx: f32, dy: f32) -> Rect { Rect::new(self.x + dx, self.y + dy, (self.w - 2.0 * dx).max(0.0), (self.h - 2.0 * dy).max(0.0)) }
    #[inline] pub fn offset(&self, dx: f32, dy: f32) -> Rect { Rect::new(self.x + dx, self.y + dy, self.w, self.h) }
    #[inline] pub fn with_size(&self, w: f32, h: f32) -> Rect { Rect::new(self.x, self.y, w, h) }
    pub fn intersect(&self, o: &Rect) -> Rect {
        let x0 = self.x.max(o.x); let y0 = self.y.max(o.y);
        let x1 = self.right().min(o.right()); let y1 = self.bottom().min(o.bottom());
        Rect::new(x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0))
    }
    pub fn union(&self, o: &Rect) -> Rect {
        let x0 = self.x.min(o.x); let y0 = self.y.min(o.y);
        let x1 = self.right().max(o.right()); let y1 = self.bottom().max(o.bottom());
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }
    pub fn is_empty(&self) -> bool { self.w <= 0.0 || self.h <= 0.0 }
    pub fn split_top(&self, h: f32) -> (Rect, Rect) { (Rect::new(self.x, self.y, self.w, h), Rect::new(self.x, self.y + h, self.w, self.h - h)) }
    pub fn split_bottom(&self, h: f32) -> (Rect, Rect) { (Rect::new(self.x, self.bottom() - h, self.w, h), Rect::new(self.x, self.y, self.w, self.h - h)) }
    pub fn split_left(&self, w: f32) -> (Rect, Rect) { (Rect::new(self.x, self.y, w, self.h), Rect::new(self.x + w, self.y, self.w - w, self.h)) }
    pub fn split_right(&self, w: f32) -> (Rect, Rect) { (Rect::new(self.right() - w, self.y, w, self.h), Rect::new(self.x, self.y, self.w - w, self.h)) }
    pub fn lerp(&self, o: &Rect, t: f32) -> Rect {
        Rect::new(lerp(self.x, o.x, t), lerp(self.y, o.y, t), lerp(self.w, o.w, t), lerp(self.h, o.h, t))
    }
}

/// Integer pixel rect (half-open), used for clipping.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IRect { pub x0: i32, pub y0: i32, pub x1: i32, pub y1: i32 }
impl IRect {
    pub fn new(x0: i32, y0: i32, x1: i32, y1: i32) -> IRect { IRect { x0, y0, x1, y1 } }
    pub fn intersect(&self, o: &IRect) -> IRect {
        IRect { x0: self.x0.max(o.x0), y0: self.y0.max(o.y0), x1: self.x1.min(o.x1).max(self.x0.max(o.x0)), y1: self.y1.min(o.y1).max(self.y0.max(o.y0)) }
    }
    pub fn is_empty(&self) -> bool { self.x1 <= self.x0 || self.y1 <= self.y0 }
    pub fn w(&self) -> i32 { self.x1 - self.x0 }
    pub fn h(&self) -> i32 { self.y1 - self.y0 }
    pub fn from_rect_outer(r: &Rect) -> IRect {
        IRect { x0: floor(r.x) as i32, y0: floor(r.y) as i32, x1: ceil(r.right()) as i32, y1: ceil(r.bottom()) as i32 }
    }
}
