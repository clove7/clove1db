//! Exact signed base-ten accumulation from validated JSON tokens.
use crate::{
    fields::codec,
    units::{ClError, Result},
};
use std::fmt;
/// The exact sum. Decimal tokens are canonical base-ten scientific notation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sum {
    Integer(i128),
    Decimal(String),
}
impl fmt::Display for Sum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(v) => v.fmt(f),
            Self::Decimal(s) => s.fmt(f),
        }
    }
}
/// Bounds memory/precision, independently of the number of rows aggregated.
pub const MAX_SUM_DIGITS: usize = 4096;
pub const MAX_SUM_EXPONENT: i128 = 4096;
#[derive(Default)]
pub(crate) struct Accumulator {
    digits: Vec<u8>,
    negative: bool,
    power: i128,
    fractional: bool,
}
impl Accumulator {
    pub fn add(&mut self, token: &str) -> Result<()> {
        let value = codec::Decimal::parse(token)?;
        if value.digits.is_empty() {
            return Ok(());
        }
        let power = value
            .exponent
            .checked_sub(value.digits.len() as i128)
            .ok_or(ClError::DecimalSumLimit)?;
        if !(-MAX_SUM_EXPONENT..=MAX_SUM_EXPONENT).contains(&power)
            || value.digits.len() > MAX_SUM_DIGITS
        {
            return Err(ClError::DecimalSumLimit);
        }
        self.fractional |= power < 0;
        let mut right = value
            .digits
            .bytes()
            .rev()
            .map(|d| d - b'0')
            .collect::<Vec<_>>();
        if self.digits.is_empty() {
            self.digits = right;
            self.power = power;
            self.negative = value.negative;
            return Ok(());
        }
        let common = self.power.min(power);
        let left_padding =
            usize::try_from(self.power - common).map_err(|_| ClError::DecimalSumLimit)?;
        let right_padding =
            usize::try_from(power - common).map_err(|_| ClError::DecimalSumLimit)?;
        if (self.digits.len() + left_padding).max(right.len() + right_padding) > MAX_SUM_DIGITS {
            return Err(ClError::DecimalSumLimit);
        }
        self.digits
            .splice(0..0, std::iter::repeat_n(0, left_padding));
        right.splice(0..0, std::iter::repeat_n(0, right_padding));
        self.power = common;
        if self.negative == value.negative {
            let mut carry = 0;
            self.digits.resize(self.digits.len().max(right.len()), 0);
            for (i, d) in self.digits.iter_mut().enumerate() {
                let n = *d + right.get(i).copied().unwrap_or(0) + carry;
                *d = n % 10;
                carry = n / 10;
            }
            if carry > 0 {
                self.digits.push(carry)
            }
        } else {
            let order = self
                .digits
                .len()
                .cmp(&right.len())
                .then_with(|| self.digits.iter().rev().cmp(right.iter().rev()));
            if order == std::cmp::Ordering::Less {
                std::mem::swap(&mut self.digits, &mut right);
                self.negative = value.negative;
            }
            let mut borrow = 0i8;
            for (i, d) in self.digits.iter_mut().enumerate() {
                let n = *d as i8 - right.get(i).copied().unwrap_or(0) as i8 - borrow;
                *d = if n < 0 { (n + 10) as u8 } else { n as u8 };
                borrow = i8::from(n < 0);
            }
        }
        while self.digits.last() == Some(&0) {
            self.digits.pop();
        }
        let zeros = self.digits.iter().take_while(|v| **v == 0).count();
        self.digits.drain(..zeros);
        self.power += zeros as i128;
        if self.digits.len() > MAX_SUM_DIGITS {
            return Err(ClError::DecimalSumLimit);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<Sum> {
        if self.digits.is_empty() {
            return Ok(if self.fractional {
                Sum::Decimal("0".into())
            } else {
                Sum::Integer(0)
            });
        }
        if !(-MAX_SUM_EXPONENT..=MAX_SUM_EXPONENT).contains(&self.power) {
            return Err(ClError::DecimalSumLimit);
        }
        let digits = self
            .digits
            .iter()
            .rev()
            .map(|v| char::from(b'0' + *v))
            .collect::<String>();
        let token = format!(
            "{}{digits}e{}",
            if self.negative { "-" } else { "" },
            self.power
        );
        if self.fractional {
            Ok(Sum::Decimal(codec::canonical_number(&token)?))
        } else {
            Ok(Sum::Integer(codec::integer(&token)?))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sum(values: &[&str]) -> Result<Sum> {
        let mut a = Accumulator::default();
        for v in values {
            a.add(v)?
        }
        a.finish()
    }
    #[test]
    fn exact_decimals_signs_cancellation_and_exponents() {
        for (values, expected) in [
            (&["0.1", "0.2"][..], "3e-1"),
            (&["1.000000000000000000000000000000000001", "-1"], "1e-36"),
            (&["-0.9", "0.1"], "-8e-1"),
            (&["9e-5", "1e-5"], "1e-4"),
            (&["-0.2", "0.2"], "0"),
            (&["1e-40", "1e40", "-1e40"], "1e-40"),
        ] {
            assert_eq!(sum(values).unwrap(), Sum::Decimal(expected.into()));
        }
    }
    #[test]
    fn integer_overflow_limits_and_non_finite() {
        assert_eq!(sum(&["1.0", "2e0"]).unwrap(), Sum::Integer(3));
        assert_eq!(
            sum(&["-170141183460469231731687303715884105728"]).unwrap(),
            Sum::Integer(i128::MIN)
        );
        assert!(matches!(
            sum(&["170141183460469231731687303715884105727", "1"]),
            Err(ClError::SumOverflow)
        ));
        assert!(matches!(sum(&["1e-4097"]), Err(ClError::DecimalSumLimit)));
        assert!(matches!(
            sum(&["1e-4096", "1e4096"]),
            Err(ClError::DecimalSumLimit)
        ));
        assert!(sum(&["NaN"]).is_err());
        assert!(sum(&["Infinity"]).is_err());
    }
}
