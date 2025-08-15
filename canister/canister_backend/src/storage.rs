use std::cell::RefCell;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    DefaultMemoryImpl, StableBTreeMap, StableCell,
};

use crate::state::CanisterState;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub static STATE: RefCell<CanisterState> = RefCell::new(
        CanisterState {
            domains: StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))),
            last_change: StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), 0),
        }
    );
}
