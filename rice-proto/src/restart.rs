// Copyright (C) 2026 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Configuration for what to reset when restarting.
#[derive(Debug, Default, Clone)]
pub struct RestartConfig {
    pub(crate) local_role_change: RoleChange,
    pub(crate) local_remove_candidates: bool,
}

/// Possible role changes for ICE-restart.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RoleChange {
    /// No role change.
    #[default]
    None,
    /// Change role to Lite.
    Lite,
    /// Change role to Full.
    Full,
}

impl RestartConfig {
    /// Construct a new [`RestartConfig`] for initiating a restart of a stream.
    pub fn new() -> Self {
        Default::default()
    }

    /// We are changing roles to the specified role.
    pub fn set_local_role_change(mut self, role_change: RoleChange) -> Self {
        self.local_role_change = role_change;
        self
    }

    /// We are changing roles to the specified role.
    pub fn local_role_change(&self) -> RoleChange {
        self.local_role_change
    }

    /// Configure whether any existing local candidates are removed from the agent.
    ///
    /// If local candidates are removed, then this will allow restarting of the gathering process.
    pub fn set_remove_local_candidates(mut self, remove: bool) -> Self {
        self.local_remove_candidates = remove;
        self
    }

    /// Retrieve whether any existing local candidates are removed from the agent.
    pub fn remove_local_candidates(&self) -> bool {
        self.local_remove_candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = RestartConfig::new();
        assert_eq!(config.local_role_change(), RoleChange::None);
        assert!(!config.remove_local_candidates());
    }

    #[test]
    fn config_getters_setters() {
        let config = RestartConfig::new()
            .set_local_role_change(RoleChange::Lite)
            .set_remove_local_candidates(true);
        assert_eq!(config.local_role_change(), RoleChange::Lite);
        assert!(config.remove_local_candidates());

        let config = RestartConfig::new()
            .set_local_role_change(RoleChange::Full)
            .set_remove_local_candidates(false);
        assert_eq!(config.local_role_change(), RoleChange::Full);
        assert!(!config.remove_local_candidates());
    }
}
