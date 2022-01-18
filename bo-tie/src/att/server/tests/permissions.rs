//! Tests of permissions checks of the attribute server

use super::DummyConnection;
use crate::{
    att::{server::*, *},
    UUID,
};
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tinymt::TinyMT64;

const ALL_ATT_PERM_SIZE: usize = 12;

const MAX_VEC_SIZE: usize = 10_000;

type AllAttributePermissions = [AttributePermissions; ALL_ATT_PERM_SIZE];

#[derive(Clone, Debug)]
struct PermVec {
    len: usize,
    permissions: MaybeUninit<AllAttributePermissions>,
}

impl PermVec {
    fn new() -> Self {
        Self {
            len: 0,
            permissions: MaybeUninit::uninit(),
        }
    }

    /// Push an item, panics if `self.len > size_of<AllAttributePermissions>()`
    fn push(&mut self, p: AttributePermissions) {
        unsafe { (*self.permissions.as_mut_ptr())[self.len] = p };
        self.len += 1;
    }
}

impl From<&'_ [AttributePermissions]> for PermVec {
    fn from(ap: &[AttributePermissions]) -> Self {
        let mut permissions: MaybeUninit<AllAttributePermissions> = MaybeUninit::uninit();

        let perm_ref = unsafe { &mut *permissions.as_mut_ptr() };

        perm_ref[..ap.len()].copy_from_slice(ap);

        Self {
            len: ap.len(),
            permissions,
        }
    }
}

impl Deref for PermVec {
    type Target = [AttributePermissions];

    fn deref(&self) -> &Self::Target {
        unsafe { &(*self.permissions.as_ptr())[..self.len] }
    }
}

impl DerefMut for PermVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut (*self.permissions.as_mut_ptr())[..self.len] }
    }
}

/// Calculate factorial, panics on overflow
fn factorial(v: usize) -> usize {
    (2..=v).fold(1, |c, v| c * v)
}

fn permutations(n: usize, r: usize) -> usize {
    factorial(n) / factorial(n - r)
}

fn all_sized_permutations_cnt(list_size: usize) -> usize {
    (0..=list_size).fold(0, |c, k| c + permutations(list_size, k))
}

/// This returns a boolean indicating if the permission should be added to the set of
/// permissions to be tested.
///
/// This generates a random integer between 0 up to `chance_max`. If the randomly generated
/// number is 0 then this function returns true.
///
/// This function is a helper function for `permutation_step`.
///
/// An implementation of the Mersenne Twister is used to generate the 'random' chance.
fn add_permission_set(rng: Arc<Mutex<tinymt::TinyMT64>>, chance_max: usize) -> bool {
    use rand::Rng;

    if chance_max != 0 {
        0 == rng.lock().unwrap().gen_range(0, chance_max)
    } else {
        true
    }
}

/// This is used to calculate if an entire recursion branch should be skipped.
///
/// This calculates the odds where every generated set of permissions by a recursion branch
/// would not be included as part of a returned set. The point of this is to speed up the
/// function `permutation_step` by reducing the number of recursion calls made.
///
/// The input `do_not_add_chance_max` is the upward bound when generating a random number in
///  a range between zero and it. When zero is the randomly generated number, then it would
/// indicate that the permission set would not be added to the list of generated
/// permissions.
fn do_recursion_branch(
    rng: Arc<Mutex<tinymt::TinyMT64>>,
    do_not_add_chance_max: f64,
    perms_size: usize,
    step_size: usize,
) -> bool {
    use rand::Rng;

    // the exponent for calculating the odds that no members of a branch are added to the
    // eventual tests list.
    let exponent = (1..=(perms_size - step_size)).fold(0usize, |exp, s_size| exp + permutations(perms_size, s_size));

    let v = match std::convert::TryFrom::try_from(exponent) {
        Ok(exp) => do_not_add_chance_max.powi(exp),
        Err(_) => do_not_add_chance_max.powf(exponent as f64),
    };

    if v <= 1000f64 {
        // boost numbers by 100_000 for resolution in the random number generation
        let max = (v * 100_000f64) as usize;

        100_000 < rng.lock().unwrap().gen_range(0, max)
    } else if v >= (u64::MAX as f64) {
        true
    } else {
        0 != rng.lock().unwrap().gen_range(0, v as u64)
    }
}

fn permutation_step(
    permutations: Arc<Mutex<Vec<PermVec>>>,
    perms: &[AttributePermissions],
    step: &[AttributePermissions],
    rand_generator: Arc<Mutex<tinymt::TinyMT64>>,
    add_chance_max: usize,
    do_not_add_chance_max: f64,
    added_cnt: Arc<AtomicUsize>,
) {
    use rayon::prelude::*;

    perms.par_iter().enumerate().for_each(|(cnt, permission)| {
        if added_cnt.load(Ordering::Acquire) >= MAX_VEC_SIZE {
            return;
        }

        let step_permutation = {
            let mut s = PermVec::from(step);
            s.push(*permission);
            s
        };

        if do_recursion_branch(
            rand_generator.clone(),
            do_not_add_chance_max,
            ALL_ATT_PERM_SIZE,
            step_permutation.len(),
        ) {
            let rotated_perms = {
                let mut v = PermVec::from(perms);
                v.rotate_left(cnt);
                v
            };

            permutation_step(
                permutations.clone(),
                &rotated_perms[1..],
                &step_permutation,
                rand_generator.clone(),
                add_chance_max,
                do_not_add_chance_max,
                added_cnt.clone(),
            );
        }

        if add_permission_set(rand_generator.clone(), add_chance_max)
            && added_cnt.fetch_add(1, Ordering::Release) < MAX_VEC_SIZE
        {
            permutations.lock().unwrap().push(step_permutation);
        }
    });
}

fn permissions_permutations(all_permissions: &AllAttributePermissions) -> Vec<PermVec> {
    use rand::SeedableRng;

    let all_permutations = all_sized_permutations_cnt(all_permissions.len());

    let add_chance_max = all_permutations / MAX_VEC_SIZE;

    let do_not_add_chance_max = all_permutations as f64 / (all_permutations - MAX_VEC_SIZE) as f64;

    let output = Arc::new(Mutex::new(Vec::with_capacity(MAX_VEC_SIZE)));

    let tiny_mt_64 = Arc::new(Mutex::new(TinyMT64::from_entropy()));

    // Determine whether to add the empty set or not.
    let cnt = if add_permission_set(tiny_mt_64.clone(), add_chance_max) {
        output.lock().unwrap().push(PermVec::new());

        Arc::new(AtomicUsize::new(1))
    } else {
        Arc::new(AtomicUsize::default())
    };

    permutation_step(
        output.clone(),
        all_permissions,
        &[],
        tiny_mt_64,
        add_chance_max,
        do_not_add_chance_max,
        cnt.clone(),
    );

    Arc::try_unwrap(output).unwrap().into_inner().unwrap()
}

fn expected_permissions_result(
    operation_permissions: &[AttributePermissions],
    attribute_permissions: &[AttributePermissions],
    client_permissions: &[AttributePermissions],
) -> Result<(), pdu::Error> {
    use AttributePermissions::*;
    use AttributeRestriction::{Authentication, Authorization, Encryption};
    use EncryptionKeySize::*;

    match operation_permissions.iter().find(|&&op| {
        attribute_permissions.iter().find(|&&ap| ap == op).is_some()
            && client_permissions.iter().find(|&&cp| cp == op).is_some()
    }) {
        Some(_) => Ok(()),
        None => Err(
            match operation_permissions
                .iter()
                .find(|&p| attribute_permissions.contains(p))
            {
                Some(Read(AttributeRestriction::None)) => pdu::Error::ReadNotPermitted,

                Some(Write(AttributeRestriction::None)) => pdu::Error::WriteNotPermitted,

                Some(Read(Encryption(_))) => {
                    if client_permissions.contains(&Read(Encryption(Bits128)))
                        || client_permissions.contains(&Read(Encryption(Bits192)))
                        || client_permissions.contains(&Read(Encryption(Bits256)))
                    {
                        pdu::Error::InsufficientEncryptionKeySize
                    } else {
                        pdu::Error::InsufficientEncryption
                    }
                }

                Some(Write(Encryption(_))) => {
                    if client_permissions.contains(&Write(Encryption(Bits128)))
                        || client_permissions.contains(&Write(Encryption(Bits192)))
                        || client_permissions.contains(&Write(Encryption(Bits256)))
                    {
                        pdu::Error::InsufficientEncryptionKeySize
                    } else {
                        pdu::Error::InsufficientEncryption
                    }
                }

                Some(Read(Authentication)) | Some(Write(Authentication)) => pdu::Error::InsufficientAuthentication,

                Some(Read(Authorization)) | Some(Write(Authorization)) | None => pdu::Error::InsufficientAuthorization,
            },
        ),
    }
}

/// This is an 'entropy' tests as it doesn't tests every permission combination between
/// server operations, client granted permissions, and the permissions of the attributes
/// themselves. It selects a random number of permissions (up to 10k, but probably 10k) and
/// tests only those. Every time this tests is run it is highly, highly, highly likely that
/// the sets of tested permissions are different. Re-running the tests will probably produce
/// different results.
#[test]
#[cfg(target_pointer_width = "64")]
#[ignore]
fn check_permissions_entropy_test() {
    use rayon::prelude::*;
    use AttributePermissions::*;
    use AttributeRestriction::*;
    use EncryptionKeySize::*;

    let all_permissions: AllAttributePermissions = [
        Read(None),
        Read(Encryption(Bits128)),
        Read(Encryption(Bits192)),
        Read(Encryption(Bits256)),
        Read(Authentication),
        Read(Authorization),
        Write(None),
        Write(Encryption(Bits128)),
        Write(Encryption(Bits192)),
        Write(Encryption(Bits256)),
        Write(Authentication),
        Write(Authorization),
    ];

    let all_tested_permission_permutations = &permissions_permutations(&all_permissions);

    all_tested_permission_permutations.par_iter().for_each(|perm_client| {
        let mut server_attributes = ServerAttributes::default();

        all_tested_permission_permutations.iter().for_each(|permissions| {
            let attribute = Attribute::new(UUID::from(1u16), permissions.to_vec(), ());

            server_attributes.push(attribute);
        });

        let mut server = Server::new(&DummyConnection, server_attributes, NoQueuedWrites);

        server.revoke_permissions_of_client(all_permissions.as_ref());

        server.give_permissions_to_client(perm_client.as_ref());

        all_tested_permission_permutations.iter().for_each(move |perm_op| {
            all_tested_permission_permutations
                .iter()
                .enumerate()
                .for_each(|(cnt, perm_att)| {
                    // 'cnt + 1' because attributes start at handle 1
                    let calculated = server.check_permissions((cnt + 1) as u16, perm_op);

                    let expected = expected_permissions_result(&perm_op, &perm_att, &perm_client);

                    assert_eq!(
                        expected,
                        calculated,
                        "Permissions check failed, mismatch in return\n\
                            (Please note: this tests is a comparison between two algorithms, and the \
                            expected result may be incorrect)\n\n\
                            Operation permissions {:#?}\nAttribute permissions {:#?}\n\
                            Client permissions {:#?}",
                        perm_op.to_vec(),
                        perm_att.to_vec(),
                        perm_client.to_vec()
                    );
                });
        });
    })
}
