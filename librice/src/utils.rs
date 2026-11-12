// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Clone)]
pub(crate) struct DebugWrapper<T>(&'static str, T);

impl<T> std::fmt::Debug for DebugWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl<T> std::ops::Deref for DebugWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.1
    }
}
impl<T> std::ops::DerefMut for DebugWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}
impl<T> DebugWrapper<T> {
    pub(crate) fn wrap(obj: T, name: &'static str) -> Self {
        Self(name, obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_wrapper() {
        let mut wrapped = DebugWrapper::wrap(10i32, "counter");
        // Deref reads through to the inner value
        assert_eq!(*wrapped, 10);
        // DerefMut writes through to the inner value
        *wrapped = 42;
        assert_eq!(*wrapped, 42);
        // Debug formatting uses the provided name, not the inner value
        assert_eq!(format!("{wrapped:?}"), "counter");
    }
}
