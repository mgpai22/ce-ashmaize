/*!
# Ashmaize: a widely portable ASIC resistant hash algorithm

AshMaize is a simple PoW that is somewhat ASIC resistant, yet relative simple to implement

# How to use

## The [`Rom`]

First you need to initialise the [`Rom`]. It is the _Read Only Memory_
and it is generated once and can be reused for different hash program.

```
use ashmaize::{Rom, RomGenerationType};

let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 16 * 1_024);
```

## [`hash`]

Now you can use the [`hash`] function to execute a random program against
the [`Rom`] that will generate a Digest.

```
use ashmaize::hash;
# use ashmaize::{Rom, RomGenerationType};
# let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 16 * 1_024);

let digest = hash(b"salt", &rom, 8, 256);
# assert_eq!(
#      digest,
#      [42, 210, 239, 12, 214, 251, 233, 4, 197, 100, 95, 113, 166, 237, 111, 169, 32, 5, 72, 109, 92, 228, 39, 145, 24, 72, 183, 43, 35, 169, 243, 99, 149, 36, 221, 187, 18, 191, 160, 215, 58, 250, 22, 134, 181, 182, 39, 96, 170, 75, 207, 180, 51, 25, 64, 232, 189, 26, 226, 52, 76, 78, 100, 235]
# );```

*/

mod rom;

use cryptoxide::{
    hashing::blake2b::{self, Blake2b},
    kdf::argon2,
};

use self::rom::RomDigest;
pub use self::rom::{Rom, RomGenerationType};

// instruction layout (20 bytes):
//   opcode(1) | src-operand nibbles(1) | packed register indices(2) | lit1(8) | lit2(8)
const INSTR_SIZE: usize = 20;
const NB_REGS: usize = 1 << REGS_BITS;
const REGS_BITS: usize = 5;
const REGS_INDEX_MASK: u8 = NB_REGS as u8 - 1;

type Register = u64;

const REGISTER_SIZE: usize = std::mem::size_of::<Register>();

/// The `Ashmaize`'s virtual machine
struct VM {
    program: Program,
    regs: [Register; NB_REGS],
    ip: u32,
    prog_digest: blake2b::Context<512>,
    mem_digest: blake2b::Context<512>,
    prog_seed: [u8; 64],
    memory_counter: u32,
    loop_counter: u32,
}

#[derive(Clone, Copy)]
enum Instr {
    Op3(Op3),
    Op2(Op2),
}

#[derive(Clone, Copy)]
enum Op3 {
    Add,
    Mul,
    MulH,
    Xor,
    Div,
    Mod,
    And,
    RotL,
    RotR,
    Hash(u8),
}

#[derive(Clone, Copy)]
enum Op2 {
    ISqrt,
    Neg,
    BitRev,
}

// special encoding

impl From<u8> for Instr {
    fn from(value: u8) -> Self {
        match value {
            0..40 => Instr::Op3(Op3::Add),                   // 40
            40..80 => Instr::Op3(Op3::Mul),                  // 40
            80..96 => Instr::Op3(Op3::MulH),                 // 16
            96..112 => Instr::Op3(Op3::Div),                 // 16
            112..128 => Instr::Op3(Op3::Mod),                // 16
            128..138 => Instr::Op2(Op2::ISqrt),              // 10
            138..148 => Instr::Op2(Op2::BitRev),             // 10
            148..188 => Instr::Op3(Op3::Xor),                // 40
            188..204 => Instr::Op3(Op3::RotL),               // 16
            204..220 => Instr::Op3(Op3::RotR),               // 16
            220..240 => Instr::Op2(Op2::Neg),                // 20
            240..248 => Instr::Op3(Op3::And),                // 8
            248..=255 => Instr::Op3(Op3::Hash(value - 248)), // 8
        }
    }
}

#[derive(Clone, Copy)]
enum Operand {
    Reg,
    Memory,
    Literal,
    Special1,
    Special2,
}

impl From<u8> for Operand {
    fn from(value: u8) -> Self {
        assert!(value <= 0x0f);
        match value {
            0..4 => Self::Reg,
            4..8 => Self::Memory,
            8..12 => Self::Literal,
            12..14 => Self::Special1,
            14.. => Self::Special2,
        }
    }
}

impl VM {
    /// Create a new VM which is specific to the ROM by using the RomDigest,
    /// but mainly dependent on the salt which is an arbitrary byte content
    pub fn new(rom_digest: &RomDigest, nb_instrs: u32, salt: &[u8]) -> Self {
        const DIGEST_INIT_SIZE: usize = 64;
        const REGS_CONTENT_SIZE: usize = REGISTER_SIZE * NB_REGS;

        let mut init_buffer = [0; REGS_CONTENT_SIZE + 3 * DIGEST_INIT_SIZE];

        let mut init_buffer_input = rom_digest.0.to_vec();
        init_buffer_input.extend_from_slice(salt);
        argon2::hprime(&mut init_buffer, &init_buffer_input);

        let (init_buffer_regs, init_buffer_digests) = init_buffer.split_at(REGS_CONTENT_SIZE);

        let mut regs = [0; NB_REGS];
        for (reg, reg_bytes) in regs.iter_mut().zip(init_buffer_regs.chunks(REGISTER_SIZE)) {
            *reg = u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_bytes).unwrap());
        }

        let mut digests = init_buffer_digests.chunks(DIGEST_INIT_SIZE);
        let prog_digest = Blake2b::<512>::new().update(digests.next().unwrap());
        let mem_digest = Blake2b::<512>::new().update(digests.next().unwrap());
        let prog_seed = *<&[u8; 64]>::try_from(digests.next().unwrap()).unwrap();

        assert_eq!(digests.next(), None);

        let program = Program::new(nb_instrs);

        Self {
            program,
            regs,
            prog_digest,
            mem_digest,
            prog_seed,
            ip: 0,
            loop_counter: 0,
            memory_counter: 0,
        }
    }

    pub fn step(&mut self, rom: &Rom) {
        execute_one_instruction(self, rom);
        self.ip = self.ip.wrapping_add(1);
    }

    fn sum_regs(&self) -> u64 {
        self.regs.iter().fold(0, |acc, r| acc.wrapping_add(*r))
    }

    pub fn post_instructions(&mut self) {
        let sum_regs = self.sum_regs();

        self.prog_digest.update_mut(&sum_regs.to_le_bytes());
        let prog_value = self.prog_digest.clone().finalize();
        self.mem_digest.update_mut(&sum_regs.to_le_bytes());
        let mem_value = self.mem_digest.clone().finalize();

        let mixing_value = Blake2b::<512>::new()
            .update(&prog_value)
            .update(&mem_value)
            .update(&self.loop_counter.to_le_bytes())
            .finalize();
        let mut mixing_out = vec![0; NB_REGS * REGISTER_SIZE * 32];
        argon2::hprime(&mut mixing_out, &mixing_value);

        for mem_chunks in mixing_out.chunks(NB_REGS * REGISTER_SIZE) {
            for (reg, reg_chunk) in self.regs.iter_mut().zip(mem_chunks.chunks(8)) {
                *reg ^= u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_chunk).unwrap())
            }
        }

        self.prog_seed = prog_value;
        self.loop_counter = self.loop_counter.wrapping_add(1)
    }

    pub fn execute(&mut self, rom: &Rom, instr: u32) {
        self.program.shuffle(&self.prog_seed);
        for _ in 0..instr {
            self.step(rom)
        }
        self.post_instructions()
    }

    pub fn finalize(self) -> [u8; 64] {
        let prog_digest = self.prog_digest.finalize();
        let mem_digest = self.mem_digest.finalize();
        let mut context = Blake2b::<512>::new()
            .update(&prog_digest)
            .update(&mem_digest)
            .update(&self.memory_counter.to_le_bytes());
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        context.finalize()
    }

    #[allow(dead_code)]
    pub(crate) fn debug(&self) -> String {
        let mut out = String::new();
        for (i, r) in self.regs.iter().enumerate() {
            out.push_str(&format!("[{i:02x}] {r:016x} "));
            if (i % 4) == 3 {
                out.push('\n');
            }
        }
        out.push_str(&format!("ip {:08x}\n", self.ip,));
        out
    }
}

struct Program {
    instructions: Vec<u8>,
}

impl Program {
    pub fn new(nb_instrs: u32) -> Self {
        let size = (nb_instrs as usize)
            .checked_mul(INSTR_SIZE)
            .expect("program byte size overflows usize");
        let instructions = vec![0; size];
        Self { instructions }
    }

    pub fn at(&self, i: u32) -> &[u8; INSTR_SIZE] {
        // reduce the index modulo the instruction count BEFORE scaling so the
        // result is identical on 32-bit (wasm) and 64-bit targets; scaling first
        // could overflow `usize` on wasm32 once `i` (the never-reset ip) grows.
        let nb_instructions = self.instructions.len() / INSTR_SIZE;
        let start = (i as usize % nb_instructions) * INSTR_SIZE;
        <&[u8; INSTR_SIZE]>::try_from(&self.instructions[start..start + INSTR_SIZE]).unwrap()
    }

    pub fn shuffle(&mut self, seed: &[u8; 64]) {
        argon2::hprime(&mut self.instructions, seed)
    }
}

#[derive(Clone)]
pub struct Instruction {
    opcode: Instr,
    op1: Operand,
    op2: Operand,
    r1: u8,
    r2: u8,
    r3: u8,
    lit1: u64,
    lit2: u64,
}

#[inline]
fn decode_instruction(instruction: &[u8; INSTR_SIZE]) -> Instruction {
    let opcode = Instr::from(instruction[0]);
    let op1 = Operand::from(instruction[1] >> 4);
    let op2 = Operand::from(instruction[1] & 0x0f);

    let rs = ((instruction[2] as u16) << 8) | (instruction[3] as u16);
    let r1 = ((rs >> (2 * REGS_BITS)) as u8) & REGS_INDEX_MASK;
    let r2 = ((rs >> REGS_BITS) as u8) & REGS_INDEX_MASK;
    let r3 = (rs as u8) & REGS_INDEX_MASK;

    let lit1 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&instruction[4..12]).unwrap());
    let lit2 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&instruction[12..20]).unwrap());

    Instruction {
        opcode,
        op1,
        op2,
        r1,
        r2,
        r3,
        lit1,
        lit2,
    }
}

fn execute_one_instruction(vm: &mut VM, rom: &Rom) {
    let prog_chunk = *vm.program.at(vm.ip);

    macro_rules! mem_access64 {
        ($vm:ident, $rom:ident, $addr:ident) => {{
            let mem = rom.at($addr as u32);
            $vm.mem_digest.update_mut(mem);

            // use the i'th 8-byte chunk of the 64-byte line selected by the
            // current counter, THEN increment (spec: counter incremented after read)
            let idx = (($vm.memory_counter % (64 / 8)) as usize) * 8;
            $vm.memory_counter = $vm.memory_counter.wrapping_add(1);
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&mem[idx..idx + 8]).unwrap())
        }};
    }

    macro_rules! special1_value64 {
        ($vm:ident) => {{
            let r = $vm.prog_digest.clone().finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
        }};
    }

    macro_rules! special2_value64 {
        ($vm:ident) => {{
            let r = $vm.mem_digest.clone().finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
        }};
    }

    // resolve a divisor: if zero, the divisor is replaced by special-value1
    // (and a zero special-value1 falls back to 1 to avoid division by zero)
    macro_rules! nonzero_divisor {
        ($vm:ident, $src2:ident) => {{
            if $src2 == 0 {
                let s = special1_value64!($vm);
                if s == 0 { 1 } else { s }
            } else {
                $src2
            }
        }};
    }

    let Instruction {
        opcode,
        op1,
        op2,
        r1,
        r2,
        r3,
        lit1,
        lit2,
    } = decode_instruction(&prog_chunk);

    match opcode {
        Instr::Op3(operator) => {
            let src1 = match op1 {
                Operand::Reg => vm.regs[r1 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };
            let src2 = match op2 {
                Operand::Reg => vm.regs[r2 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit2),
                Operand::Literal => lit2,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op3::Add => src1.wrapping_add(src2),
                Op3::Mul => src1.wrapping_mul(src2),
                Op3::MulH => ((src1 as u128 * src2 as u128) >> 64) as u64,
                Op3::Xor => src1 ^ src2,
                Op3::Div => src1 / nonzero_divisor!(vm, src2),
                Op3::Mod => src1 % nonzero_divisor!(vm, src2),
                Op3::And => src1 & src2,
                Op3::RotL => src1.rotate_left(src2 as u32),
                Op3::RotR => src1.rotate_right(src2 as u32),
                Op3::Hash(v) => {
                    assert!(v < 8);
                    let out = Blake2b::<512>::new()
                        .update(&src1.to_le_bytes())
                        .update(&src2.to_le_bytes())
                        .finalize();
                    if let Some(chunk) = out.chunks(8).nth(v as usize) {
                        u64::from_le_bytes(*<&[u8; 8]>::try_from(chunk).unwrap())
                    } else {
                        panic!("chunk doesn't exist")
                    }
                }
            };

            vm.regs[r3 as usize] = result;
        }
        Instr::Op2(operator) => {
            let src1 = match op1 {
                Operand::Reg => vm.regs[r1 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op2::Neg => !src1,
                Op2::ISqrt => src1.isqrt(),
                Op2::BitRev => src1.reverse_bits(),
            };
            vm.regs[r3 as usize] = result;
        }
    }
    vm.prog_digest.update_mut(&prog_chunk);
}

/// For the given [`Rom`] and parameter, compute the digest of the given `salt`
///
/// # Example
///
/// ```
/// # use ashmaize::{Rom, RomGenerationType, hash};
/// # const KB: usize = 1_024;
/// # let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 16 * KB);
/// const NB_LOOPS: u32 = 8;
/// const NB_INSTRS: u32 = 256;
/// let digest = hash(b"salt", &rom, NB_LOOPS, NB_INSTRS);
/// ```
///
pub fn hash(salt: &[u8], rom: &Rom, nb_loops: u32, nb_instrs: u32) -> [u8; 64] {
    assert!(nb_loops >= 2);
    assert!(nb_instrs >= 128);
    let mut vm = VM::new(&rom.digest, nb_instrs, salt);
    for _ in 0..nb_loops {
        vm.execute(rom, nb_instrs);
    }
    vm.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_count_diff() {
        let rom = Rom::new(
            b"password1",
            RomGenerationType::TwoStep {
                pre_size: 1024,
                mixing_numbers: 4,
            },
            10_240,
        );

        let h1 = hash(&0u128.to_be_bytes(), &rom, 8, 256);
        let h2 = hash(&0u128.to_be_bytes(), &rom, 8, 257);

        assert_ne!(h1, h2);
    }

    #[test]
    fn min_size_and_min_instrs() {
        // smallest legal ROM (one 64-byte cacheline) plus the spec minimums
        // (nb_loops = 2, nb_instrs = 128) must run without panicking.
        let rom = Rom::new(b"k", RomGenerationType::FullRandom, 64);
        let a = hash(b"s", &rom, 2, 128);
        let b = hash(b"s", &rom, 2, 128);
        assert_eq!(a, b);
    }

    #[test]
    fn twostep_non_power_of_two_pre_size() {
        // pre_size = 192 (3 * 64) is a valid multiple of 64 but not a power of
        // two; this used to be rejected by an over-strict assertion.
        let rom = Rom::new(
            b"k",
            RomGenerationType::TwoStep {
                pre_size: 192,
                mixing_numbers: 4,
            },
            64 * 64,
        );
        let a = hash(b"s", &rom, 2, 128);
        let b = hash(b"s", &rom, 2, 128);
        assert_eq!(a, b);
    }

    #[test]
    #[should_panic]
    fn rejects_non_multiple_of_64_size() {
        let _ = Rom::new(b"k", RomGenerationType::FullRandom, 100);
    }

    #[test]
    #[should_panic]
    fn rejects_pre_size_larger_than_rom() {
        let _ = Rom::new(
            b"k",
            RomGenerationType::TwoStep {
                pre_size: 128,
                mixing_numbers: 4,
            },
            64,
        );
    }

    /*
    #[test]
    fn check_ip_stale() {
        let rom = Rom::new(b"password1", 1024, 10_240);

        let salt = &0u128.to_be_bytes();
        let nb_instrs = 100_000;
        let mut vm = VM::new(&rom.digest, nb_instrs, salt);
        for i in 0..nb_instrs {
            let prev = vm.debug();
            vm.step(&rom);
        }
    }
    */

    #[test]
    fn test() {
        const PRE_SIZE: usize = 16 * 1024;
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: u32 = 256;

        let rom = Rom::new(
            b"123",
            RomGenerationType::TwoStep {
                pre_size: PRE_SIZE,
                mixing_numbers: 4,
            },
            SIZE,
        );

        let h = hash(b"hello", &rom, 8, NB_INSTR);
        println!("{:?}", h);
    }

    #[test]
    fn test_eq() {
        const PRE_SIZE: usize = 16 * 1024;
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: u32 = 256;

        const EXPECTED: [u8; 64] = [
            118, 142, 59, 19, 242, 229, 217, 97, 115, 38, 167, 56, 121, 151, 183, 246, 214, 145,
            208, 104, 222, 217, 220, 208, 73, 247, 247, 175, 107, 193, 179, 137, 99, 168, 68, 177,
            2, 71, 92, 42, 62, 95, 219, 229, 255, 221, 116, 101, 163, 104, 95, 252, 165, 44, 215,
            109, 62, 126, 71, 158, 82, 151, 210, 127,
        ];

        let rom = Rom::new(
            b"123",
            RomGenerationType::TwoStep {
                pre_size: PRE_SIZE,
                mixing_numbers: 4,
            },
            SIZE,
        );

        let h = hash(b"hello", &rom, 8, NB_INSTR);
        assert_eq!(h, EXPECTED);
    }
}
