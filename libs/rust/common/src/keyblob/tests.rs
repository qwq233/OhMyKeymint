// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
    sdd_mem::InMemorySlotManager, SecureDeletionSecretManager, SecureDeletionSlot, SlotHolder,
    SlotPurpose,
};

#[derive(Default)]
struct FakeRng(u8);

impl crate::crypto::Rng for FakeRng {
    fn add_entropy(&mut self, _data: &[u8]) {}
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.0;
            self.0 += 1;
        }
    }
}

#[test]
fn test_sdd_slot_holder() {
    let mut sdd_mgr = InMemorySlotManager::<10>::default();
    let mut rng = FakeRng::default();
    let (slot_holder0, sdd0) =
        SlotHolder::new(&mut sdd_mgr, &mut rng, SlotPurpose::KeyGeneration).unwrap();
    let slot0 = slot_holder0.consume();
    assert_eq!(slot0, SecureDeletionSlot(0));
    assert!(sdd_mgr.get_secret(slot0).unwrap() == sdd0);

    let (slot_holder1, sdd1) =
        SlotHolder::new(&mut sdd_mgr, &mut rng, SlotPurpose::KeyGeneration).unwrap();
    let slot1 = slot_holder1.consume();
    assert_eq!(slot1, SecureDeletionSlot(1));
    assert!(sdd_mgr.get_secret(slot1).unwrap() == sdd1);

    assert!(sdd_mgr.get_secret(slot0).unwrap() == sdd0);
    assert!(sdd_mgr.get_secret(slot1).unwrap() == sdd1);
    assert!(sdd0 != sdd1);

    // If the slot holder is dropped rather than consumed, it should free the slot.
    let (slot_holder2, _sdd2a) =
        SlotHolder::new(&mut sdd_mgr, &mut rng, SlotPurpose::KeyGeneration).unwrap();
    drop(slot_holder2);
    assert!(sdd_mgr.get_secret(SecureDeletionSlot(2)).is_err());

    // Slot 2 is available again.
    let (slot_holder2, sdd2b) =
        SlotHolder::new(&mut sdd_mgr, &mut rng, SlotPurpose::KeyGeneration).unwrap();
    let slot2 = slot_holder2.consume();
    assert_eq!(slot2, SecureDeletionSlot(2));
    assert!(sdd_mgr.get_secret(slot2).unwrap() == sdd2b);
}

#[test]
fn test_sdd_factory_secret() {
    let mut sdd_mgr = InMemorySlotManager::<10>::default();
    let mut rng = FakeRng::default();
    assert!(sdd_mgr.get_factory_reset_secret().is_err());
    let secret1 = sdd_mgr.get_or_create_factory_reset_secret(&mut rng).unwrap();
    let secret2 = sdd_mgr.get_factory_reset_secret().unwrap();
    assert!(secret1 == secret2);
    let secret3 = sdd_mgr.get_or_create_factory_reset_secret(&mut rng).unwrap();
    assert!(secret1 == secret3);
}

#[test]
fn test_sdd_exhaustion() {
    let mut sdd_mgr = InMemorySlotManager::<2>::default();
    let mut rng = FakeRng::default();
    let (_slot0, _sdd0) = sdd_mgr.new_secret(&mut rng, SlotPurpose::KeyGeneration).unwrap();
    let (slot1a, sdd1a) = sdd_mgr.new_secret(&mut rng, SlotPurpose::KeyGeneration).unwrap();
    assert!(sdd_mgr.new_secret(&mut rng, SlotPurpose::KeyGeneration).is_err());
    sdd_mgr.delete_secret(slot1a).unwrap();
    let (slot1b, sdd1b) = sdd_mgr.new_secret(&mut rng, SlotPurpose::KeyGeneration).unwrap();
    assert_eq!(slot1a, slot1b);
    assert!(sdd1a != sdd1b);
}
