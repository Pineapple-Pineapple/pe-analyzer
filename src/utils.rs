use crate::error::{PeError, Result};
use std::{mem, time};

pub fn relative_time(timestamp: u64, short: bool, len: u8) -> Result<String> {
  if len > 7 {
    return Err(PeError::InvalidArguments("Not enough units (len <= 7)".to_string()));
  }

  let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();
  let diff =
    if timestamp < now { now.saturating_sub(timestamp) } else { timestamp.saturating_sub(now) };
  let past = timestamp <= now;

  let units = [
    (60 * 60 * 24 * 7 * 30 * 12, "years", "y"),
    (60 * 60 * 24 * 7 * 30, "months", "M"),
    (60 * 60 * 24 * 7, "weeks", "w"),
    (60 * 60 * 24, "days", "d"),
    (60 * 60, "hours", "h"),
    (60, "minute", "m"),
    (1, "second", "s"),
  ];

  let mut remaining = diff;
  let mut parts = Vec::new();

  for (secs, l_unit, s_unit) in units.iter() {
    if parts.len() as u8 >= len {
      break;
    }

    let count = remaining / secs;
    if count > 0 {
      remaining %= secs;
      let part = if short {
        format!("{}{}", count, s_unit)
      } else {
        format!("{} {}{}", count, l_unit, if count > 1 { "s" } else { "" })
      };
      parts.push(part);
    }
  }

  if parts.len() == 0 {
    if short {
      return Ok("0s".to_string());
    } else {
      return Ok("0 seconds".to_string());
    }
  }

  let joined = parts.join(if short { " " } else { ", " });

  Ok(if past { format!("{} ago", joined) } else { format!("in {}", joined) })
}

pub struct BinaryReader<'a> {
  data: &'a [u8],
  position: usize,
}

impl<'a> BinaryReader<'a> {
  pub fn new(data: &'a [u8]) -> Self {
    Self { data, position: 0 }
  }

  pub fn position(&self) -> usize {
    self.position
  }

  pub fn remaining(&self) -> usize {
    self.data.len().saturating_sub(self.position)
  }

  pub fn seek(&mut self, position: usize) -> Result<()> {
    if position <= self.data.len() {
      self.position = position;
      Ok(())
    } else {
      Err(PeError::CorruptedFile(format!(
        "Seek position {} out of bounds {}",
        position,
        self.data.len()
      )))
    }
  }

  pub fn read_bytes(&mut self, length: usize) -> Result<&'a [u8]> {
    if self.position + length <= self.data.len() {
      let bytes = &self.data[self.position..self.position + length];
      self.position += length;
      Ok(bytes)
    } else {
      Err(PeError::CorruptedFile(format!(
        "Not enough data: Need {} bytes, have {}",
        length,
        self.remaining()
      )))
    }
  }

  fn read_le<T>(&mut self) -> Result<T>
  where
    T: FromLeBytes,
  {
    let size = mem::size_of::<T>();
    if self.position + size <= self.data.len() {
      let bytes = &self.data[self.position..self.position + size];
      self.position += size;
      Ok(T::from_le_bytes(bytes))
    } else {
      Err(PeError::CorruptedFile(format!(
        "Not enough data: Need {} bytes, have {}",
        size,
        self.remaining()
      )))
    }
  }

  pub fn read_u8(&mut self) -> Result<u8> {
    self.read_le()
  }
  pub fn read_u16(&mut self) -> Result<u16> {
    self.read_le()
  }
  pub fn read_u32(&mut self) -> Result<u32> {
    self.read_le()
  }
  pub fn read_u64(&mut self) -> Result<u64> {
    self.read_le()
  }
  pub fn read_i8(&mut self) -> Result<i8> {
    self.read_le()
  }
  pub fn read_i16(&mut self) -> Result<i16> {
    self.read_le()
  }
  pub fn read_i32(&mut self) -> Result<i32> {
    self.read_le()
  }
  pub fn read_i64(&mut self) -> Result<i64> {
    self.read_le()
  }

  pub fn read_cstring(&mut self, max_length: usize) -> Result<String> {
    let mut bytes = Vec::new();
    let start_pos = self.position;

    while self.position < self.data.len() && self.position - start_pos < max_length {
      let byte = self.data[self.position];
      self.position += 1;

      if byte == 0 {
        break;
      }

      bytes.push(byte);
    }

    String::from_utf8(bytes)
      .map_err(|_| PeError::CorruptedFile("Invalid UTF-8 in string".to_string()))
  }
}

trait FromLeBytes: Sized {
  fn from_le_bytes(bytes: &[u8]) -> Self;
}

impl FromLeBytes for u8 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    bytes[0]
  }
}

impl FromLeBytes for u16 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    u16::from_le_bytes([bytes[0], bytes[1]])
  }
}

impl FromLeBytes for u32 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
  }
}

impl FromLeBytes for u64 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    u64::from_le_bytes([
      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
  }
}

impl FromLeBytes for i8 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    bytes[0] as i8
  }
}

impl FromLeBytes for i16 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    i16::from_le_bytes([bytes[0], bytes[1]])
  }
}

impl FromLeBytes for i32 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
  }
}

impl FromLeBytes for i64 {
  fn from_le_bytes(bytes: &[u8]) -> Self {
    i64::from_le_bytes([
      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
  }
}
