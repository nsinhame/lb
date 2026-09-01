//! Shared /dl vs /watch discriminant used by both the plgb route handlers
//! and the ad-callback token signing code.

#[derive(Clone, Copy)]
pub enum LinkKind {
    Dl,
    Watch,
}

impl LinkKind {
    pub fn path(self) -> &'static str {
        match self {
            LinkKind::Dl => "dl",
            LinkKind::Watch => "watch",
        }
    }
}
