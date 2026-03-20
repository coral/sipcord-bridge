//! Self-contained fax TIFF decoder.
//!
//! Handles CCITT Group 3 (1D + 2D) and Group 4 compressed TIFFs as written
//! by SpanDSP, including FillOrder=2 (LSB-first) and T4Options with 2D encoding.
//!
//! Huffman table data derived from the ITU-T T.4 standard.
//! Bit-reading approach inspired by the `fax` crate (MIT licensed).

use anyhow::{Result, bail};
use image::GrayImage;
use std::path::Path;
use std::sync::OnceLock;
use tracing::debug;

// Public API

/// Maximum TIFF file size (50 MB). Well above any reasonable fax output from SpanDSP,
/// but prevents OOM from malformed files.
const MAX_TIFF_SIZE: u64 = 50 * 1024 * 1024;

/// Decode all pages of a fax TIFF file into grayscale images.
pub fn decode_fax_tiff(path: &Path) -> Result<Vec<GrayImage>> {
    if !path.exists() {
        bail!("TIFF file not found: {}", path.display());
    }
    let file_size = std::fs::metadata(path)?.len();
    if file_size > MAX_TIFF_SIZE {
        bail!(
            "TIFF file too large: {} bytes (max {} bytes)",
            file_size,
            MAX_TIFF_SIZE
        );
    }
    let data = std::fs::read(path)?;
    let pages = parse_tiff_ifds(&data)?;
    let mut images = Vec::with_capacity(pages.len());

    for (i, page) in pages.iter().enumerate() {
        debug!(
            "TIFF page {}: {}x{}, compression={}, fill_order={}, t4_options={}",
            i + 1,
            page.width,
            page.height,
            page.compression,
            page.fill_order,
            page.t4_options
        );

        let mut strip_data = Vec::new();
        for (off, len) in page.strip_offsets.iter().zip(&page.strip_byte_counts) {
            let start = *off as usize;
            let end = start + *len as usize;
            if end > data.len() {
                bail!(
                    "TIFF strip extends past file: offset={}, count={}, file_len={}",
                    off,
                    len,
                    data.len()
                );
            }
            strip_data.extend_from_slice(&data[start..end]);
        }

        // FillOrder=2: reverse bits in every byte
        if page.fill_order == 2 {
            for b in strip_data.iter_mut() {
                *b = BIT_REVERSE_LUT[*b as usize];
            }
        }

        let transitions_per_line = match page.compression {
            3 => decode_group3(&strip_data, page.width, page.height, page.t4_options)?,
            4 => decode_group4(&strip_data, page.width, page.height)?,
            other => bail!("Unsupported TIFF compression: {}", other),
        };

        let img = assemble_image(
            &transitions_per_line,
            page.width,
            page.height,
            page.photometric,
        );

        // Correct aspect ratio for non-square pixels (e.g., 204×98 DPI standard fax)
        let img = correct_aspect_ratio(img, page.x_resolution, page.y_resolution);
        images.push(img);
    }

    Ok(images)
}

// TIFF IFD Parser

struct TiffPage {
    width: u32,
    height: u32,
    compression: u32,
    fill_order: u32,
    t4_options: u32,
    photometric: u32,
    strip_offsets: Vec<u32>,
    strip_byte_counts: Vec<u32>,
    x_resolution: Option<(u32, u32)>, // numerator, denominator (RATIONAL)
    y_resolution: Option<(u32, u32)>, // numerator, denominator (RATIONAL)
}

fn parse_tiff_ifds(data: &[u8]) -> Result<Vec<TiffPage>> {
    if data.len() < 8 {
        bail!("TIFF file too short");
    }
    let le = match (data[0], data[1]) {
        (0x49, 0x49) => true,
        (0x4D, 0x4D) => false,
        _ => bail!("Not a TIFF file"),
    };
    let magic = read_u16(data, 2, le);
    if magic != 42 {
        bail!("Bad TIFF magic: {}", magic);
    }

    let mut ifd_offset = read_u32(data, 4, le) as usize;
    let mut pages = Vec::new();

    while ifd_offset != 0 {
        if ifd_offset + 2 > data.len() {
            break;
        }
        let num_entries = read_u16(data, ifd_offset, le) as usize;
        let mut width = 0u32;
        let mut height = 0u32;
        let mut compression = 1u32;
        let mut fill_order = 1u32;
        let mut t4_options = 0u32;
        let mut photometric = 0u32;
        let mut strip_offsets = Vec::new();
        let mut strip_byte_counts = Vec::new();
        let mut x_resolution: Option<(u32, u32)> = None;
        let mut y_resolution: Option<(u32, u32)> = None;

        for i in 0..num_entries {
            let entry_off = ifd_offset + 2 + i * 12;
            if entry_off + 12 > data.len() {
                break;
            }
            let tag = read_u16(data, entry_off, le);
            let typ = read_u16(data, entry_off + 2, le);
            let count = read_u32(data, entry_off + 4, le);
            let val_off = entry_off + 8;

            match tag {
                256 => width = read_ifd_value(data, val_off, typ, le),
                257 => height = read_ifd_value(data, val_off, typ, le),
                259 => compression = read_ifd_value(data, val_off, typ, le),
                262 => photometric = read_ifd_value(data, val_off, typ, le),
                266 => fill_order = read_ifd_value(data, val_off, typ, le),
                273 => strip_offsets = read_ifd_array(data, val_off, typ, count, le),
                278 => { /* rows_per_strip — not needed */ }
                279 => strip_byte_counts = read_ifd_array(data, val_off, typ, count, le),
                282 => x_resolution = read_ifd_rational(data, val_off, le),
                283 => y_resolution = read_ifd_rational(data, val_off, le),
                292 => t4_options = read_ifd_value(data, val_off, typ, le),
                _ => {}
            }
        }

        pages.push(TiffPage {
            width,
            height,
            compression,
            fill_order,
            t4_options,
            photometric,
            strip_offsets,
            strip_byte_counts,
            x_resolution,
            y_resolution,
        });

        let next_off_pos = ifd_offset + 2 + num_entries * 12;
        if next_off_pos + 4 > data.len() {
            break;
        }
        ifd_offset = read_u32(data, next_off_pos, le) as usize;
    }

    if pages.is_empty() {
        bail!("No IFDs found in TIFF");
    }
    Ok(pages)
}

fn read_u16(data: &[u8], off: usize, le: bool) -> u16 {
    if le {
        u16::from_le_bytes([data[off], data[off + 1]])
    } else {
        u16::from_be_bytes([data[off], data[off + 1]])
    }
}

fn read_u32(data: &[u8], off: usize, le: bool) -> u32 {
    if le {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    } else {
        u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    }
}

fn read_ifd_value(data: &[u8], val_off: usize, typ: u16, le: bool) -> u32 {
    match typ {
        1 | 6 => data[val_off] as u32,               // BYTE / SBYTE
        3 | 8 => read_u16(data, val_off, le) as u32, // SHORT / SSHORT
        4 | 9 => read_u32(data, val_off, le),        // LONG / SLONG
        _ => read_u32(data, val_off, le),
    }
}

fn read_ifd_array(data: &[u8], val_off: usize, typ: u16, count: u32, le: bool) -> Vec<u32> {
    let item_size = match typ {
        1 | 6 => 1,
        3 | 8 => 2,
        4 | 9 => 4,
        _ => 4,
    };
    let total_bytes = count as usize * item_size;
    // If data fits in the 4-byte value field, read inline; otherwise follow the pointer
    let base = if total_bytes <= 4 {
        val_off
    } else {
        read_u32(data, val_off, le) as usize
    };

    let mut result = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = base + i * item_size;
        let v = match typ {
            1 | 6 => data.get(off).copied().unwrap_or(0) as u32,
            3 | 8 => {
                if off + 2 <= data.len() {
                    read_u16(data, off, le) as u32
                } else {
                    0
                }
            }
            _ => {
                if off + 4 <= data.len() {
                    read_u32(data, off, le)
                } else {
                    0
                }
            }
        };
        result.push(v);
    }
    result
}

/// Read a TIFF RATIONAL value (type=5): two u32s (numerator, denominator) at an offset.
/// The IFD value field contains an offset pointer to the 8-byte rational data.
fn read_ifd_rational(data: &[u8], val_off: usize, le: bool) -> Option<(u32, u32)> {
    let offset = read_u32(data, val_off, le) as usize;
    if offset + 8 > data.len() {
        return None;
    }
    let numerator = read_u32(data, offset, le);
    let denominator = read_u32(data, offset + 4, le);
    if denominator == 0 {
        return None;
    }
    Some((numerator, denominator))
}

// FillOrder=2 bit-reversal LUT

const BIT_REVERSE_LUT: [u8; 256] = {
    let mut lut = [0u8; 256];
    let mut i = 0u16;
    while i < 256 {
        let b = i as u8;
        lut[i as usize] = ((b & 0x80) >> 7)
            | ((b & 0x40) >> 5)
            | ((b & 0x20) >> 3)
            | ((b & 0x10) >> 1)
            | ((b & 0x08) << 1)
            | ((b & 0x04) << 3)
            | ((b & 0x02) << 5)
            | ((b & 0x01) << 7);
        i += 1;
    }
    lut
};

// Bit Reader

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    partial: u32,
    valid: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut r = BitReader {
            data,
            pos: 0,
            partial: 0,
            valid: 0,
        };
        r.fill();
        r
    }

    fn fill(&mut self) {
        while self.valid <= 24 && self.pos < self.data.len() {
            self.partial |= (self.data[self.pos] as u32) << (24 - self.valid);
            self.valid += 8;
            self.pos += 1;
        }
    }

    /// Look at the next `n` bits (MSB-aligned, returned in lower bits).
    fn peek(&self, n: u8) -> Option<u16> {
        if self.valid >= n {
            Some((self.partial >> (32 - n)) as u16)
        } else {
            None
        }
    }

    /// Consume `n` bits and refill.
    fn consume(&mut self, n: u8) {
        self.partial <<= n;
        self.valid -= n;
        self.fill();
    }

    /// Scan for EOL pattern: at least 11 zero bits followed by a 1 bit.
    /// Returns true if found, false if data exhausted.
    fn scan_for_eol(&mut self) -> bool {
        loop {
            match self.peek(12) {
                Some(1) => {
                    self.consume(12);
                    return true;
                }
                Some(_) => self.consume(1),
                None => {
                    // Try consuming remaining zeros
                    if self.valid > 0 {
                        self.consume(1);
                    } else {
                        return false;
                    }
                }
            }
        }
    }
}

// Huffman Lookup Tables

/// Entry in a flat LUT: (decoded_value, bits_to_consume). 0xFFFF = invalid.
type LutEntry = (u16, u8);

const INVALID_ENTRY: LutEntry = (0xFFFF, 0);

/// White terminating + makeup codes from T.4 standard.
/// Format: (bit_pattern, bit_length, run_length)
const WHITE_CODES: &[(u16, u8, u16)] = &[
    (0b00110101, 8, 0),
    (0b000111, 6, 1),
    (0b0111, 4, 2),
    (0b1000, 4, 3),
    (0b1011, 4, 4),
    (0b1100, 4, 5),
    (0b1110, 4, 6),
    (0b1111, 4, 7),
    (0b10011, 5, 8),
    (0b10100, 5, 9),
    (0b00111, 5, 10),
    (0b01000, 5, 11),
    (0b001000, 6, 12),
    (0b000011, 6, 13),
    (0b110100, 6, 14),
    (0b110101, 6, 15),
    (0b101010, 6, 16),
    (0b101011, 6, 17),
    (0b0100111, 7, 18),
    (0b0001100, 7, 19),
    (0b0001000, 7, 20),
    (0b0010111, 7, 21),
    (0b0000011, 7, 22),
    (0b0000100, 7, 23),
    (0b0101000, 7, 24),
    (0b0101011, 7, 25),
    (0b0010011, 7, 26),
    (0b0100100, 7, 27),
    (0b0011000, 7, 28),
    (0b00000010, 8, 29),
    (0b00000011, 8, 30),
    (0b00011010, 8, 31),
    (0b00011011, 8, 32),
    (0b00010010, 8, 33),
    (0b00010011, 8, 34),
    (0b00010100, 8, 35),
    (0b00010101, 8, 36),
    (0b00010110, 8, 37),
    (0b00010111, 8, 38),
    (0b00101000, 8, 39),
    (0b00101001, 8, 40),
    (0b00101010, 8, 41),
    (0b00101011, 8, 42),
    (0b00101100, 8, 43),
    (0b00101101, 8, 44),
    (0b00000100, 8, 45),
    (0b00000101, 8, 46),
    (0b00001010, 8, 47),
    (0b00001011, 8, 48),
    (0b01010010, 8, 49),
    (0b01010011, 8, 50),
    (0b01010100, 8, 51),
    (0b01010101, 8, 52),
    (0b00100100, 8, 53),
    (0b00100101, 8, 54),
    (0b01011000, 8, 55),
    (0b01011001, 8, 56),
    (0b01011010, 8, 57),
    (0b01011011, 8, 58),
    (0b01001010, 8, 59),
    (0b01001011, 8, 60),
    (0b00110010, 8, 61),
    (0b00110011, 8, 62),
    (0b00110100, 8, 63),
    // Makeup codes
    (0b11011, 5, 64),
    (0b10010, 5, 128),
    (0b010111, 6, 192),
    (0b0110111, 7, 256),
    (0b00110110, 8, 320),
    (0b00110111, 8, 384),
    (0b01100100, 8, 448),
    (0b01100101, 8, 512),
    (0b01101000, 8, 576),
    (0b01100111, 8, 640),
    (0b011001100, 9, 704),
    (0b011001101, 9, 768),
    (0b011010010, 9, 832),
    (0b011010011, 9, 896),
    (0b011010100, 9, 960),
    (0b011010101, 9, 1024),
    (0b011010110, 9, 1088),
    (0b011010111, 9, 1152),
    (0b011011000, 9, 1216),
    (0b011011001, 9, 1280),
    (0b011011010, 9, 1344),
    (0b011011011, 9, 1408),
    (0b010011000, 9, 1472),
    (0b010011001, 9, 1536),
    (0b010011010, 9, 1600),
    (0b011000, 6, 1664),
    (0b010011011, 9, 1728),
    // Extended makeup (shared with black)
    (0b00000001000, 11, 1792),
    (0b00000001100, 11, 1856),
    (0b00000001101, 11, 1920),
    (0b000000010010, 12, 1984),
    (0b000000010011, 12, 2048),
    (0b000000010100, 12, 2112),
    (0b000000010101, 12, 2176),
    (0b000000010110, 12, 2240),
    (0b000000010111, 12, 2304),
    (0b000000011100, 12, 2368),
    (0b000000011101, 12, 2432),
    (0b000000011110, 12, 2496),
    (0b000000011111, 12, 2560),
];

const BLACK_CODES: &[(u16, u8, u16)] = &[
    (0b0000110111, 10, 0),
    (0b010, 3, 1),
    (0b11, 2, 2),
    (0b10, 2, 3),
    (0b011, 3, 4),
    (0b0011, 4, 5),
    (0b0010, 4, 6),
    (0b00011, 5, 7),
    (0b000101, 6, 8),
    (0b000100, 6, 9),
    (0b0000100, 7, 10),
    (0b0000101, 7, 11),
    (0b0000111, 7, 12),
    (0b00000100, 8, 13),
    (0b00000111, 8, 14),
    (0b000011000, 9, 15),
    (0b0000010111, 10, 16),
    (0b0000011000, 10, 17),
    (0b0000001000, 10, 18),
    (0b00001100111, 11, 19),
    (0b00001101000, 11, 20),
    (0b00001101100, 11, 21),
    (0b00000110111, 11, 22),
    (0b00000101000, 11, 23),
    (0b00000010111, 11, 24),
    (0b00000011000, 11, 25),
    (0b000011001010, 12, 26),
    (0b000011001011, 12, 27),
    (0b000011001100, 12, 28),
    (0b000011001101, 12, 29),
    (0b000001101000, 12, 30),
    (0b000001101001, 12, 31),
    (0b000001101010, 12, 32),
    (0b000001101011, 12, 33),
    (0b000011010010, 12, 34),
    (0b000011010011, 12, 35),
    (0b000011010100, 12, 36),
    (0b000011010101, 12, 37),
    (0b000011010110, 12, 38),
    (0b000011010111, 12, 39),
    (0b000001101100, 12, 40),
    (0b000001101101, 12, 41),
    (0b000011011010, 12, 42),
    (0b000011011011, 12, 43),
    (0b000001010100, 12, 44),
    (0b000001010101, 12, 45),
    (0b000001010110, 12, 46),
    (0b000001010111, 12, 47),
    (0b000001100100, 12, 48),
    (0b000001100101, 12, 49),
    (0b000001010010, 12, 50),
    (0b000001010011, 12, 51),
    (0b000000100100, 12, 52),
    (0b000000110111, 12, 53),
    (0b000000111000, 12, 54),
    (0b000000100111, 12, 55),
    (0b000000101000, 12, 56),
    (0b000001011000, 12, 57),
    (0b000001011001, 12, 58),
    (0b000000101011, 12, 59),
    (0b000000101100, 12, 60),
    (0b000001011010, 12, 61),
    (0b000001100110, 12, 62),
    (0b000001100111, 12, 63),
    // Makeup codes
    (0b0000001111, 10, 64),
    (0b000011001000, 12, 128),
    (0b000011001001, 12, 192),
    (0b000001011011, 12, 256),
    (0b000000110011, 12, 320),
    (0b000000110100, 12, 384),
    (0b000000110101, 12, 448),
    (0b0000001101100, 13, 512),
    (0b0000001101101, 13, 576),
    (0b0000001001010, 13, 640),
    (0b0000001001011, 13, 704),
    (0b0000001001100, 13, 768),
    (0b0000001001101, 13, 832),
    (0b0000001110010, 13, 896),
    (0b0000001110011, 13, 960),
    (0b0000001110100, 13, 1024),
    (0b0000001110101, 13, 1088),
    (0b0000001110110, 13, 1152),
    (0b0000001110111, 13, 1216),
    (0b0000001010010, 13, 1280),
    (0b0000001010011, 13, 1344),
    (0b0000001010100, 13, 1408),
    (0b0000001010101, 13, 1472),
    (0b0000001011010, 13, 1536),
    (0b0000001011011, 13, 1600),
    (0b0000001100100, 13, 1664),
    (0b0000001100101, 13, 1728),
    // Extended makeup (shared with white)
    (0b00000001000, 11, 1792),
    (0b00000001100, 11, 1856),
    (0b00000001101, 11, 1920),
    (0b000000010010, 12, 1984),
    (0b000000010011, 12, 2048),
    (0b000000010100, 12, 2112),
    (0b000000010101, 12, 2176),
    (0b000000010110, 12, 2240),
    (0b000000010111, 12, 2304),
    (0b000000011100, 12, 2368),
    (0b000000011101, 12, 2432),
    (0b000000011110, 12, 2496),
    (0b000000011111, 12, 2560),
];

/// 2D mode codes from T.4 standard.
/// Format: (bit_pattern, bit_length, Mode)
#[derive(Copy, Clone, Debug)]
enum Mode {
    Pass,
    Horizontal,
    Vertical(i8),
}

const MODE_CODES: &[(u16, u8, Mode)] = &[
    (0b0001, 4, Mode::Pass),
    (0b001, 3, Mode::Horizontal),
    (0b1, 1, Mode::Vertical(0)),
    (0b011, 3, Mode::Vertical(1)),
    (0b000011, 6, Mode::Vertical(2)),
    (0b0000011, 7, Mode::Vertical(3)),
    (0b010, 3, Mode::Vertical(-1)),
    (0b000010, 6, Mode::Vertical(-2)),
    (0b0000010, 7, Mode::Vertical(-3)),
];

const WHITE_LUT_BITS: u8 = 12;
const BLACK_LUT_BITS: u8 = 13;
const MODE_LUT_BITS: u8 = 7;

fn white_lut() -> &'static [LutEntry] {
    static LUT: OnceLock<Vec<LutEntry>> = OnceLock::new();
    LUT.get_or_init(|| build_lut(WHITE_CODES, WHITE_LUT_BITS))
}

fn black_lut() -> &'static [LutEntry] {
    static LUT: OnceLock<Vec<LutEntry>> = OnceLock::new();
    LUT.get_or_init(|| build_lut(BLACK_CODES, BLACK_LUT_BITS))
}

fn mode_lut() -> &'static [(u8, Mode)] {
    static LUT: OnceLock<Vec<(u8, Mode)>> = OnceLock::new();
    LUT.get_or_init(|| {
        let size = 1usize << MODE_LUT_BITS;
        let mut lut = vec![(0u8, Mode::Pass); size];
        // Mark all as invalid first (len=0)
        for entry in lut.iter_mut() {
            entry.0 = 0;
        }
        for &(pattern, len, mode) in MODE_CODES {
            let shift = MODE_LUT_BITS - len;
            let base = (pattern as usize) << shift;
            for suffix in 0..(1usize << shift) {
                lut[base | suffix] = (len, mode);
            }
        }
        lut
    })
}

fn build_lut(codes: &[(u16, u8, u16)], lut_bits: u8) -> Vec<LutEntry> {
    let size = 1usize << lut_bits;
    let mut lut = vec![INVALID_ENTRY; size];
    for &(pattern, len, value) in codes {
        if len > lut_bits {
            continue;
        }
        let shift = lut_bits - len;
        let base = (pattern as usize) << shift;
        for suffix in 0..(1usize << shift) {
            lut[base | suffix] = (value, len);
        }
    }
    lut
}

// Huffman Decoders

#[derive(Copy, Clone, PartialEq)]
enum Color {
    White,
    Black,
}

impl Color {
    fn flip(self) -> Self {
        match self {
            Color::White => Color::Black,
            Color::Black => Color::White,
        }
    }
}

/// Decode a single run-length code (terminating or makeup).
fn decode_run(reader: &mut BitReader, color: Color) -> Option<u16> {
    match color {
        Color::White => {
            let bits = reader.peek(WHITE_LUT_BITS)?;
            let (val, len) = white_lut()[bits as usize];
            if val == 0xFFFF {
                return None;
            }
            reader.consume(len);
            Some(val)
        }
        Color::Black => {
            let bits = reader.peek(BLACK_LUT_BITS)?;
            let (val, len) = black_lut()[bits as usize];
            if val == 0xFFFF {
                return None;
            }
            reader.consume(len);
            Some(val)
        }
    }
}

/// Decode a full run: sum makeup codes until a terminating code (< 64).
fn decode_full_run(reader: &mut BitReader, color: Color) -> Option<u16> {
    let mut total = 0u16;
    loop {
        let n = decode_run(reader, color)?;
        total += n;
        if n < 64 {
            return Some(total);
        }
    }
}

/// Decode a 2D mode code.
fn decode_mode(reader: &mut BitReader) -> Option<Mode> {
    let bits = reader.peek(MODE_LUT_BITS)?;
    let (len, mode) = mode_lut()[bits as usize];
    if len == 0 {
        return None;
    }
    reader.consume(len);
    Some(mode)
}

// Reference Line Helpers (for 2D decoding)

/// Find b1: the next transition on the reference line of the opposite color,
/// at or after position `a0`.
fn find_b1(reference: &[u16], a0: u16, current_color: Color, width: u16) -> u16 {
    // Reference transitions alternate white->black (index 0), black->white (index 1), ...
    // We need the first transition in reference that is > a0 and corresponds to the opposite color.
    // Color at position 0 is White. Transition at index i flips to:
    //   i even -> Black (end of white run)
    //   i odd  -> White (end of black run)
    // The color AFTER transition[i] is: even=Black, odd=White
    // We want opposite of current_color.
    // b1 is the first changing element on the reference line to the right of a0
    // whose color is opposite to the current color on the coding line.

    let want_black_transition = current_color == Color::White;
    // If want_black_transition, we want an even-indexed transition (white->black)
    // If want_white_transition, we want an odd-indexed transition (black->white)

    for (i, &t) in reference.iter().enumerate() {
        if t <= a0 {
            continue;
        }
        let is_even = i % 2 == 0;
        if is_even == want_black_transition {
            return t;
        }
    }
    width
}

/// Find b2: the next transition after b1 on the reference line.
fn find_b2(reference: &[u16], b1: u16, width: u16) -> u16 {
    for &t in reference {
        if t > b1 {
            return t;
        }
    }
    width
}

// 1D Line Decoder (Modified Huffman)

fn decode_line_1d(reader: &mut BitReader, width: u16) -> Option<Vec<u16>> {
    let mut transitions = Vec::new();
    let mut a0 = 0u16;
    let mut color = Color::White;

    while a0 < width {
        let run = decode_full_run(reader, color)?;
        a0 += run;
        if a0 < width {
            transitions.push(a0);
        }
        color = color.flip();
    }
    Some(transitions)
}

// 2D Line Decoder (Modified READ)

fn decode_line_2d(reader: &mut BitReader, reference: &[u16], width: u16) -> Option<Vec<u16>> {
    let mut transitions = Vec::new();
    let mut a0 = 0u16;
    let mut color = Color::White;

    loop {
        if a0 >= width {
            break;
        }

        let mode = decode_mode(reader)?;
        match mode {
            Mode::Pass => {
                let b1 = find_b1(reference, a0, color, width);
                let b2 = find_b2(reference, b1, width);
                a0 = b2;
                // Color doesn't change after pass
            }
            Mode::Vertical(delta) => {
                let b1 = find_b1(reference, a0, color, width);
                let a1 = (b1 as i32 + delta as i32).max(0) as u16;
                if a1 >= width {
                    // Line ends
                    break;
                }
                transitions.push(a1);
                a0 = a1;
                color = color.flip();
            }
            Mode::Horizontal => {
                let run1 = decode_full_run(reader, color)?;
                let run2 = decode_full_run(reader, color.flip())?;
                let a1 = a0 + run1;
                let a2 = a1 + run2;
                transitions.push(a1);
                if a2 >= width {
                    break;
                }
                transitions.push(a2);
                a0 = a2;
                // Color returns to original after horizontal
            }
        }
    }

    Some(transitions)
}

// Group 3 Image Driver

fn decode_group3(data: &[u8], width: u32, height: u32, t4_options: u32) -> Result<Vec<Vec<u16>>> {
    let w = width as u16;
    let is_2d = (t4_options & 1) != 0;
    let has_fill_bits = (t4_options & 4) != 0;
    let mut reader = BitReader::new(data);
    let mut lines: Vec<Vec<u16>> = Vec::with_capacity(height as usize);
    let mut reference: Vec<u16> = Vec::new();

    // Scan for the first EOL
    if !reader.scan_for_eol() {
        bail!("No EOL found at start of Group 3 data");
    }

    for _ in 0..height {
        // After EOL, if 2D, read the tag bit: 1=1D, 0=2D
        let use_2d = if is_2d {
            match reader.peek(1) {
                Some(tag) => {
                    reader.consume(1);
                    tag == 0
                }
                None => break,
            }
        } else {
            false
        };

        let line = if use_2d {
            match decode_line_2d(&mut reader, &reference, w) {
                Some(l) => l,
                None => break,
            }
        } else {
            match decode_line_1d(&mut reader, w) {
                Some(l) => l,
                None => break,
            }
        };

        reference = line.clone();
        lines.push(line);

        // Skip fill bits (zero-pad to byte boundary before EOL) if enabled
        if has_fill_bits {
            // Consume zeros until we see the EOL pattern
            loop {
                match reader.peek(12) {
                    Some(0x001) => break,                           // Found EOL (000000000001)
                    Some(v) if (v >> 11) == 0 => reader.consume(1), // Leading zero
                    _ => break,
                }
            }
        }

        // Try to read EOL
        match reader.peek(12) {
            Some(0x001) => {
                reader.consume(12);
                let mut consecutive_eols = 1u32;

                // Check for RTC (Return To Control): 6 consecutive EOLs
                // In 2D mode each EOL has a tag bit, so check EOL+tag sequences
                loop {
                    if is_2d {
                        // Peek EOL (12 bits) + tag (1 bit) = 13 bits
                        match reader.peek(13) {
                            Some(v) if (v >> 1) == 0x001 => {
                                reader.consume(13);
                                consecutive_eols += 1;
                                if consecutive_eols >= 6 {
                                    return Ok(lines);
                                }
                            }
                            _ => break,
                        }
                    } else {
                        match reader.peek(12) {
                            Some(0x001) => {
                                reader.consume(12);
                                consecutive_eols += 1;
                                if consecutive_eols >= 6 {
                                    return Ok(lines);
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }
            _ => {
                // No EOL found — might be end of data
            }
        }
    }

    if lines.is_empty() {
        bail!("Group 3 decoder produced no lines");
    }
    Ok(lines)
}

// Group 4 Image Driver

fn decode_group4(data: &[u8], width: u32, height: u32) -> Result<Vec<Vec<u16>>> {
    let w = width as u16;
    let mut reader = BitReader::new(data);
    let mut lines: Vec<Vec<u16>> = Vec::with_capacity(height as usize);
    let mut reference: Vec<u16> = Vec::new();

    for _ in 0..height {
        // Check for EOFB (End Of Facsimile Block): two consecutive EOL codes
        if let Some(v) = reader.peek(12)
            && v == 0x001
        {
            // Possible EOFB — check for second EOL
            break;
        }

        let line = match decode_line_2d(&mut reader, &reference, w) {
            Some(l) => l,
            None => break,
        };

        reference = line.clone();
        lines.push(line);
    }

    if lines.is_empty() {
        bail!("Group 4 decoder produced no lines");
    }
    Ok(lines)
}

// Pixel Assembly

/// Scale image to correct for non-square pixel aspect ratios.
///
/// Fax standard resolution uses 204×98 DPI (non-square pixels). Without correction,
/// the image appears vertically compressed (stretched when rendered at 1:1).
fn correct_aspect_ratio(
    img: GrayImage,
    x_res: Option<(u32, u32)>,
    y_res: Option<(u32, u32)>,
) -> GrayImage {
    let (x_num, x_den) = match x_res {
        Some(r) => r,
        None => return img,
    };
    let (y_num, y_den) = match y_res {
        Some(r) => r,
        None => return img,
    };

    let x_dpi = x_num as f64 / x_den as f64;
    let y_dpi = y_num as f64 / y_den as f64;
    let ratio = x_dpi / y_dpi;

    // Skip scaling if pixels are approximately square (within 5%)
    if ratio > 0.95 && ratio < 1.05 {
        return img;
    }

    let (w, h) = img.dimensions();
    if ratio > 1.0 {
        // X resolution higher than Y — scale height up to match
        let new_height = (h as f64 * ratio).round() as u32;
        debug!(
            "Correcting fax aspect ratio: {:.0}×{:.0} DPI, scaling {}×{} → {}×{}",
            x_dpi, y_dpi, w, h, w, new_height
        );
        image::imageops::resize(&img, w, new_height, image::imageops::FilterType::Lanczos3)
    } else {
        // Y resolution higher than X — scale width up to match
        let new_width = (w as f64 / ratio).round() as u32;
        debug!(
            "Correcting fax aspect ratio: {:.0}×{:.0} DPI, scaling {}×{} → {}×{}",
            x_dpi, y_dpi, w, h, new_width, h
        );
        image::imageops::resize(&img, new_width, h, image::imageops::FilterType::Lanczos3)
    }
}

fn assemble_image(lines: &[Vec<u16>], width: u32, height: u32, photometric: u32) -> GrayImage {
    // photometric 0 = WhiteIsZero (normal for fax: 0=white, 1=black)
    // photometric 1 = BlackIsZero
    let invert = photometric == 1;

    let actual_height = lines.len().min(height as usize);
    let white = if invert { 0u8 } else { 255u8 };
    let mut img = GrayImage::from_pixel(width, actual_height as u32, image::Luma([white]));
    let w = width as usize;

    for (y, transitions) in lines.iter().enumerate().take(actual_height) {
        let row_start = y * w;
        let row = &mut img.as_mut()[row_start..row_start + w];
        let mut color = white;
        let mut x = 0usize;
        for &t in transitions {
            let t = (t as usize).min(w);
            if t > x {
                row[x..t].fill(color);
                x = t;
            }
            color = if color == 255 { 0 } else { 255 };
        }
        if x < w {
            row[x..].fill(color);
        }
    }

    img
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test against the example fax TIFF bundled in src/fax/.
    /// This is a real SpanDSP-produced TIFF: compression=3, FillOrder=2, T4Options=5 (2D + fill bits).
    #[test]
    fn test_decode_example_tiff() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fax/example.tiff");
        let images = decode_fax_tiff(&path).expect("Failed to decode example.tiff");

        assert_eq!(images.len(), 1, "Expected 1 page");
        let img = &images[0];

        // Width stays at standard fax width; height may be scaled by aspect ratio correction
        assert_eq!(img.width(), 1728, "Standard fax width");
        // Original pixel height is 2199. If resolution tags indicate non-square pixels
        // (e.g., 204×98 DPI), the image will be scaled up vertically.
        assert!(
            img.height() >= 2199,
            "Height should be >= original 2199 (may be scaled for aspect ratio), got {}",
            img.height()
        );

        // Spot-check: top-left area should be mostly white (header region)
        let white_count: usize = (0..100)
            .flat_map(|y| (0..100).map(move |x| (x, y)))
            .filter(|&(x, y)| img.get_pixel(x, y).0[0] == 255)
            .count();
        assert!(
            white_count > 9000,
            "Top-left 100x100 should be mostly white, got {} white pixels",
            white_count
        );

        // There should be some black pixels (the fax has content)
        let total_black: usize = img.pixels().filter(|p| p.0[0] == 0).count();
        assert!(
            total_black > 1000,
            "Image should contain black pixels (fax content), got {}",
            total_black
        );
    }

    /// Verify that resolution tags are parsed from example.tiff.
    #[test]
    fn test_parse_resolution_tags() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fax/example.tiff");
        let data = std::fs::read(&path).expect("Failed to read example.tiff");
        let pages = parse_tiff_ifds(&data).expect("Failed to parse IFDs");

        assert_eq!(pages.len(), 1);
        let page = &pages[0];

        // SpanDSP writes resolution tags for fax TIFFs
        assert!(
            page.x_resolution.is_some(),
            "Expected XResolution tag in example.tiff"
        );
        assert!(
            page.y_resolution.is_some(),
            "Expected YResolution tag in example.tiff"
        );

        let (x_num, x_den) = page.x_resolution.unwrap();
        let (y_num, y_den) = page.y_resolution.unwrap();
        let x_dpi = x_num as f64 / x_den as f64;
        let y_dpi = y_num as f64 / y_den as f64;

        // Standard fax resolutions: 204 or 200 DPI horizontal, 98 or 196 or 200 DPI vertical
        assert!(
            x_dpi > 100.0 && x_dpi < 300.0,
            "XResolution {:.1} DPI out of expected range",
            x_dpi
        );
        assert!(
            y_dpi > 50.0 && y_dpi < 400.0,
            "YResolution {:.1} DPI out of expected range",
            y_dpi
        );
    }

    // BIT_REVERSE_LUT tests

    #[test]
    fn bit_reverse_lut_spot_checks() {
        assert_eq!(BIT_REVERSE_LUT[0x00], 0x00);
        assert_eq!(BIT_REVERSE_LUT[0xFF], 0xFF);
        assert_eq!(BIT_REVERSE_LUT[0x80], 0x01);
        assert_eq!(BIT_REVERSE_LUT[0x01], 0x80);
        assert_eq!(BIT_REVERSE_LUT[0xAA], 0x55);
        assert_eq!(BIT_REVERSE_LUT[0x55], 0xAA);
    }

    #[test]
    fn bit_reverse_lut_double_reverse_is_identity() {
        for i in 0..=255u8 {
            assert_eq!(
                BIT_REVERSE_LUT[BIT_REVERSE_LUT[i as usize] as usize], i,
                "Double reverse should be identity for {}",
                i
            );
        }
    }

    // BitReader tests

    #[test]
    fn bit_reader_peek_and_consume() {
        // 0xA5 = 10100101
        let data = [0xA5];
        let mut reader = BitReader::new(&data);

        // Peek first 4 bits: 1010 = 10
        assert_eq!(reader.peek(4), Some(0b1010));

        // Consume 4, then peek next 4: 0101 = 5
        reader.consume(4);
        assert_eq!(reader.peek(4), Some(0b0101));
    }

    #[test]
    fn bit_reader_peek_more_than_available() {
        let data = [0xFF]; // 8 bits
        let reader = BitReader::new(&data);
        // 8 bits available, asking for 9 should fail
        assert!(reader.peek(9).is_none());
    }

    #[test]
    fn bit_reader_scan_for_eol_found() {
        // EOL = 000000000001 (11 zeros + 1)
        // Byte-aligned: 0x00 0x01 = 00000000 00000001
        // That's 15 zeros then 1 — contains the 11+1 EOL pattern
        let data = [0x00, 0x01];
        let mut reader = BitReader::new(&data);
        assert!(reader.scan_for_eol());
    }

    #[test]
    fn bit_reader_scan_for_eol_not_found() {
        // All ones — no EOL pattern
        let data = [0xFF, 0xFF];
        let mut reader = BitReader::new(&data);
        assert!(!reader.scan_for_eol());
    }

    #[test]
    fn bit_reader_scan_for_eol_empty() {
        let data: [u8; 0] = [];
        let mut reader = BitReader::new(&data);
        assert!(!reader.scan_for_eol());
    }

    // assemble_image tests

    #[test]
    fn assemble_image_white_is_zero_transitions() {
        // photometric=0 (WhiteIsZero): white=255, black=0
        // Width 300, transitions at [100, 200]: white 0-99, black 100-199, white 200-299
        let lines = vec![vec![100u16, 200u16]];
        let img = assemble_image(&lines, 300, 1, 0);

        assert_eq!(img.width(), 300);
        assert_eq!(img.height(), 1);

        // White region: 0-99
        assert_eq!(img.get_pixel(0, 0).0[0], 255);
        assert_eq!(img.get_pixel(99, 0).0[0], 255);
        // Black region: 100-199
        assert_eq!(img.get_pixel(100, 0).0[0], 0);
        assert_eq!(img.get_pixel(199, 0).0[0], 0);
        // White region: 200-299
        assert_eq!(img.get_pixel(200, 0).0[0], 255);
        assert_eq!(img.get_pixel(299, 0).0[0], 255);
    }

    #[test]
    fn assemble_image_black_is_zero_inverted() {
        // photometric=1 (BlackIsZero): white=0, black=255
        // Same transitions — colors should be inverted
        let lines = vec![vec![100u16, 200u16]];
        let img = assemble_image(&lines, 300, 1, 1);

        // "White" region (value 0): 0-99
        assert_eq!(img.get_pixel(0, 0).0[0], 0);
        assert_eq!(img.get_pixel(99, 0).0[0], 0);
        // "Black" region (value 255): 100-199
        assert_eq!(img.get_pixel(100, 0).0[0], 255);
        assert_eq!(img.get_pixel(199, 0).0[0], 255);
        // "White" region (value 0): 200-299
        assert_eq!(img.get_pixel(200, 0).0[0], 0);
        assert_eq!(img.get_pixel(299, 0).0[0], 0);
    }

    #[test]
    fn assemble_image_empty_transitions_all_white() {
        // No transitions = entire row is white
        let lines = vec![vec![]];
        let img = assemble_image(&lines, 100, 1, 0);

        for x in 0..100 {
            assert_eq!(img.get_pixel(x, 0).0[0], 255, "Pixel {} should be white", x);
        }
    }

    // decode_fax_tiff error cases

    #[test]
    fn decode_fax_tiff_missing_file() {
        let path = Path::new("/tmp/nonexistent_fax_test_file_12345.tiff");
        let result = decode_fax_tiff(path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "Error should mention file not found: {}",
            err
        );
    }

    #[test]
    fn test_assemble_image_uses_actual_height_not_declared() {
        // Simulate a short fax: declared height is 100, but only 30 lines decoded
        let width = 10u32;
        let declared_height = 100u32;
        let lines: Vec<Vec<u16>> = (0..30)
            .map(|_| vec![5, 10]) // each line: 5 white pixels, 5 black pixels
            .collect();

        let img = assemble_image(&lines, width, declared_height, 0);

        // Image height should be the actual line count, not the declared height
        assert_eq!(
            img.height(),
            30,
            "Image height should match actual decoded lines (30), not declared height (100)"
        );
        assert_eq!(img.width(), width);
    }

    #[test]
    fn test_assemble_image_full_page_unchanged() {
        // When lines.len() == declared height, nothing changes
        let width = 10u32;
        let height = 50u32;
        let lines: Vec<Vec<u16>> = (0..50).map(|_| vec![5, 10]).collect();

        let img = assemble_image(&lines, width, height, 0);
        assert_eq!(img.height(), 50);
        assert_eq!(img.width(), width);
    }
}
