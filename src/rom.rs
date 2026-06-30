use cryptoxide::{
    hashing::blake2b::Blake2b,
    kdf::argon2,
};

pub const DATASET_ACCESS_SIZE: usize = 64;

pub(crate) struct RomDigest(pub(crate) [u8; 64]);

/// The **R**ead **O**only **M**emory used to generate the proram.
///
/// The **ROM** is a read-only memory that contains a random program.
/// The program is generated using a random seed and a random generation type.
/// The random generation type can be either [`RomGenerationType::FullRandom`] or [`RomGenerationType::TwoStep`].
///
/// [`hash`]: crate::hash
pub struct Rom {
    pub(crate) digest: RomDigest,
    data: Vec<u8>,
}

/// The generation type of the **ROM**.
///
/// This is used to drive the generation of the **ROM**. It can be
/// either fully random or use a two step approach.
///
#[derive(Clone, Copy, Debug)]
pub enum RomGenerationType {
    /// this is the simplest approach and it uses a blake2b to
    /// generate the whole ROM. However it is slower than the
    /// [`TwoSetp`] option
    FullRandom,
    /// This option is faster to execute and not necessarily
    /// weaker than [`FullRandom`].
    TwoStep {
        /// the pre-memory size in bytes
        ///
        /// Must be a non-zero multiple of 64 (the cacheline size) and at
        /// most the ROM `size`. Otherwise [`Rom::new`] panics.
        pre_size: usize,
        /// number of chunks to randomly combine (e.g. 4)
        mixing_numbers: usize,
    },
}

impl Rom {
    /// create a new [`Rom`] using the given data as `key` to initilise
    /// the _seed_ that will be used for the [`Rom`] generation
    ///
    /// This function is deterministic and will produce the same outputs
    /// for the same given inputs.
    ///
    /// # Panic
    ///
    /// Panics if `size` is not a non-zero multiple of 64 bytes that fits in
    /// 32 bits, or if [`RomGenerationType::TwoStep`]'s `pre_size` is not a
    /// non-zero multiple of 64 bytes that is at most `size`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ashmaize::{Rom, RomGenerationType};
    /// # const KB: usize = 1_024;
    /// let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 256 * KB);
    /// ```
    ///
    /// ```
    /// # use ashmaize::{Rom, RomGenerationType};
    /// # const KB: usize = 1_024;
    /// let gen_type = RomGenerationType::TwoStep {
    ///     pre_size: 16 * KB,
    ///     mixing_numbers: 4,
    /// };
    /// let rom = Rom::new(b"seed", gen_type, 256 * KB);
    /// ```
    ///
    pub fn new(key: &[u8], gen_type: RomGenerationType, size: usize) -> Self {
        assert!(
            size >= DATASET_ACCESS_SIZE && size.is_multiple_of(DATASET_ACCESS_SIZE),
            "ROM size must be a non-zero multiple of 64 bytes"
        );
        assert!(size <= u32::MAX as usize, "ROM size must fit in 32 bits");
        let mut data = vec![0; size];

        let seed = Blake2b::<512>::new()
            .update(&(size as u32).to_le_bytes())
            .update(key)
            .finalize();
        let digest = random_gen(gen_type, seed, &mut data);

        Self { digest, data }
    }

    pub(crate) fn at(&self, i: u32) -> &[u8; DATASET_ACCESS_SIZE] {
        let nb_lines = self.data.len() / DATASET_ACCESS_SIZE;
        let start = (i as usize % nb_lines) * DATASET_ACCESS_SIZE;
        <&[u8; DATASET_ACCESS_SIZE]>::try_from(&self.data[start..start + DATASET_ACCESS_SIZE])
            .unwrap()
    }
}

fn random_gen(gen_type: RomGenerationType, seed: [u8; 64], output: &mut [u8]) -> RomDigest {
    const CHUNK: usize = DATASET_ACCESS_SIZE; // 64-byte cacheline

    if let RomGenerationType::TwoStep {
        pre_size,
        mixing_numbers,
    } = gen_type
    {
        assert!(
            pre_size >= CHUNK && pre_size.is_multiple_of(CHUNK),
            "pre_size must be a non-zero multiple of 64 bytes"
        );
        assert!(
            pre_size <= output.len(),
            "pre_size must not exceed the ROM size"
        );
        assert!(mixing_numbers >= 1, "mixing_numbers must be at least 1");

        // 1. build the small, strictly-sequential pre-ROM
        let mut pre_rom = vec![0; pre_size];
        argon2::hprime(&mut pre_rom, &seed);

        const OFFSET_LOOPS: u32 = 4;

        // generate a 32-u16 iterator from a 64-byte digest
        fn digest_to_u16s(digest: &[u8; 64]) -> impl Iterator<Item = u16> {
            digest
                .chunks(2)
                .map(|c| u16::from_le_bytes(*<&[u8; 2]>::try_from(c).unwrap()))
        }

        // 2. relative offsets, shared across all output chunks
        let mut offsets_diff = vec![];
        for i in 0u32..OFFSET_LOOPS {
            let command = Blake2b::<512>::new()
                .update(&seed)
                .update(b"generation offset")
                .update(&i.to_le_bytes())
                .finalize();
            offsets_diff.extend(digest_to_u16s(&command))
        }
        assert_eq!(offsets_diff.len(), 32 * OFFSET_LOOPS as usize);

        // 3. one base-offset byte per output chunk
        let nb_out_chunks = output.len() / CHUNK;
        let mut offset_base = vec![0u8; nb_out_chunks];
        let offset_base_input = Blake2b::<512>::new()
            .update(&seed)
            .update(b"generation base")
            .finalize();
        argon2::hprime(&mut offset_base, &offset_base_input);

        // 4. assemble each output chunk from XOR-combined pre-ROM chunks
        let nb_source_chunks = pre_size / CHUNK;
        let mut digest = Blake2b::<512>::new();
        for (i, chunk) in output.chunks_mut(CHUNK).enumerate() {
            let base = (i % nb_source_chunks) * CHUNK;
            chunk.copy_from_slice(&pre_rom[base..base + CHUNK]);

            for d in 1..mixing_numbers {
                let src = (i
                    + offset_base[i] as usize
                    + offsets_diff[(d - 1) % offsets_diff.len()] as usize)
                    % nb_source_chunks;
                let off = src * CHUNK;
                xorbuf(chunk, &pre_rom[off..off + CHUNK]);
            }

            digest.update_mut(chunk);
        }
        RomDigest(digest.finalize())
    } else {
        argon2::hprime(output, &seed);
        RomDigest(Blake2b::<512>::new().update(output).finalize())
    }
}

// XOR `input` into `out` byte-by-byte. Both slices must have equal length.
// The straightforward loop auto-vectorizes and avoids the unaligned `u64`
// reads (undefined behavior) of the previous hand-rolled version.
fn xorbuf(out: &mut [u8], input: &[u8]) {
    debug_assert_eq!(out.len(), input.len());
    for (o, i) in out.iter_mut().zip(input.iter()) {
        *o ^= *i;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rom_random_distribution() {
        let mut distribution = [0; 256];

        const SIZE: usize = 10 * 1_024 * 1_024;

        let rom = Rom::new(
            b"password",
            RomGenerationType::TwoStep {
                pre_size: 256 * 1024,
                mixing_numbers: 4,
            },
            SIZE,
        );

        for byte in rom.data {
            let index = byte as usize;
            distribution[index] += 1;
        }

        const R: usize = 3; // expect 3% range difference with the perfect average
        const AVG: usize = SIZE / 256;
        const MIN: usize = AVG * (100 - R) / 100;
        const MAX: usize = AVG * (100 + R) / 100;

        dbg!(&distribution);
        dbg!(MIN);
        dbg!(AVG);
        dbg!(MAX);

        assert!(
            distribution
                .iter()
                .take(u8::MAX as usize)
                .all(|&count| count > MIN && count < MAX)
        );
    }
}
