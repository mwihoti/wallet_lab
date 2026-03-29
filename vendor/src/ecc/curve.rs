
use crate::ecc::field::{FieldElement, Pow};
use crate::ecc::scalar::Scalar;
use crate::ecc::constants::{SECP256K1_GX, SECP256K1_GY, SECP256K1_B};
use num_bigint::BigUint;
use std::ops::{Add, Mul};

#[derive(Debug, Clone)]
pub struct Point {
    x: Option<FieldElement>,
    y: Option<FieldElement>,
}

impl Point {
    pub fn new(
        x: Option<FieldElement>,
        y: Option<FieldElement>,
    ) -> Self {
        match (&x, &y) {
            (Some(x_val), Some(y_val)) => {
                // Verify point is on secp256k1: y² = x³ + 7
                let x_cubed: FieldElement = Pow::pow(x_val, BigUint::from(3u32));
                let b = FieldElement::new(SECP256K1_B.clone());
                let right_side = &x_cubed + &b;
                let y_squared: FieldElement = Pow::pow(y_val, BigUint::from(2u32));
                if y_squared != right_side {
                    panic!("({x_val:?}, {y_val:?}) is not on the secp256k1 curve")
                }
                Self { x, y }
            }
            (None, None) => Self { x: None, y: None },
            _ => {
                panic!("Invalid parameters to Point::new()")
            }
        }
    }

    // Returns the secp256k1 generator point G
    pub fn generator() -> Self {
        let gx = FieldElement::new(SECP256K1_GX.clone());
        let gy = FieldElement::new(SECP256K1_GY.clone());
        Self { x: Some(gx), y: Some(gy) }
    }

    // Returns the point at infinity (identity element)
    pub fn infinity() -> Self {
        Self { x: None, y: None }
    }

    pub fn x(&self) -> &Option<FieldElement> {
        &self.x
    }

    pub fn y(&self) -> &Option<FieldElement> {
        &self.y
    }

    pub fn a(&self) -> FieldElement {
        FieldElement::zero()
    }

    pub fn b(&self) -> FieldElement {
        FieldElement::new(SECP256K1_B.clone())
    }

    // Returns the point at infinity with same curve parameters
    pub fn new_infinity(&self) -> Self {
        Self { x: None, y: None }
    }

    pub fn is_infinity(&self) -> bool {
        self.x.is_none() && self.y.is_none()
    }

    // Scalar multiplication using the Scalar type
    pub fn multiply(&self, scalar: &Scalar) -> Self {
        let coef = scalar.value().clone();
        self * coef
    }

    // Check if this point is the same as another (coordinates only)
    pub fn same_point(&self, other: &Point) -> bool {
        match (&self.x, &other.x, &self.y, &other.y) {
            (Some(x1), Some(x2), Some(y1), Some(y2)) => x1 == x2 && y1 == y2,
            (None, None, None, None) => true,
            _ => false,
        }
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        let x_eq = match (&self.x, &other.x) {
            (Some(x1), Some(x2)) => x1 == x2,
            (None, None) => true,
            _ => false,
        };
        let y_eq = match (&self.y, &other.y) {
            (Some(y1), Some(y2)) => y1 == y2,
            (None, None) => true,
            _ => false,
        };
        x_eq && y_eq
    }
}

impl Add for Point {
    type Output = Point;
    fn add(self, other: Point) -> Point { &self + &other }
}

impl Add<&Point> for Point {
    type Output = Point;
    fn add(self, other: &Point) -> Point { &self + other }
}

impl Add<Point> for &Point {
    type Output = Point;
    fn add(self, other: Point) -> Point { self + &other }
}

impl Add for &Point {
    type Output = Point;

    fn add(self, other: Self) -> Point {
        if self.x.is_none() {
            return other.clone();
        }

        if other.x.is_none() {
            return self.clone();
        }

        let x1 = self.x.clone().unwrap();
        let y1 = self.y.clone().unwrap();
        let x2 = other.x.clone().unwrap();
        let y2 = other.y.clone().unwrap();

        // Vertical line case: P + (-P) = infinity
        if x1 == x2 && y1 != y2 {
            return self.new_infinity();
        }

        // Point addition for p1 != p2
        if x1 != x2 {
            let s = &(&y2 - &y1) / &(&x2 - &x1);
            let x3 = &(&Pow::pow(&s, BigUint::from(2u32)) - &x1) - &x2;
            let y3 = &(&s * &(&x1 - &x3)) - &y1;
            return Point { x: Some(x3), y: Some(y3) };
        }

        // Point doubling: p1 == p2
        // If y == 0, the tangent is vertical → infinity
        if y1.is_zero() {
            return self.new_infinity();
        }

        // secp256k1: a = 0, so slope s = (3x²) / (2y)
        let two = FieldElement::new(BigUint::from(2u32));
        let three = FieldElement::new(BigUint::from(3u32));
        let s = &(&three * &Pow::pow(&x1, BigUint::from(2u32))) / &(&two * &y1);
        let x3 = &(&Pow::pow(&s, BigUint::from(2u32)) - &x1) - &x1;
        let y3 = &(&s * &(&x1 - &x3)) - &y1;
        Point { x: Some(x3), y: Some(y3) }
    }
}

impl Mul<BigUint> for Point {
    type Output = Point;
    fn mul(self, coefficient: BigUint) -> Self::Output { &self * coefficient }
}

impl Mul<&BigUint> for Point {
    type Output = Point;
    fn mul(self, coefficient: &BigUint) -> Self::Output { &self * coefficient.clone() }
}

impl Mul<BigUint> for &Point {
    type Output = Point;

    fn mul(self, coefficient: BigUint) -> Self::Output {
        let mut coef = coefficient;
        let mut current = self.clone();
        let mut result = self.new_infinity();

        while coef > BigUint::from(0u32) {
            if &coef & BigUint::from(1u32) == BigUint::from(1u32) {
                result = &result + &current;
            }
            current = &current + &current;
            coef >>= 1;
        }
        result
    }
}

impl Mul<&BigUint> for &Point {
    type Output = Point;
    fn mul(self, coefficient: &BigUint) -> Self::Output { self * coefficient.clone() }
}

impl Mul<Scalar> for Point {
    type Output = Point;
    fn mul(self, scalar: Scalar) -> Self::Output { &self * scalar.value().clone() }
}

impl Mul<&Scalar> for Point {
    type Output = Point;
    fn mul(self, scalar: &Scalar) -> Self::Output { &self * scalar.value().clone() }
}

impl Mul<Scalar> for &Point {
    type Output = Point;
    fn mul(self, scalar: Scalar) -> Self::Output { self * scalar.value().clone() }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;
    fn mul(self, scalar: &Scalar) -> Self::Output { self * scalar.value().clone() }
}
