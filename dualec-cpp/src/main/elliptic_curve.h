#pragma once
#include "affine_point.h"
#include "forward.h"
#include "givaro/givintsqrootmod.h"
#include <gmp++/gmp++_int.h>
#include <ostream>

// y^2 = x^3 + a*x + b
// defined over field Z_p
class EllipticCurve {
public:
    EllipticCurve(std::string name, BigInt prime, BigInt a, BigInt b)
        : m_field(prime)
        , m_name(name)
    {
        m_field.init(m_a, a);
        m_field.init(m_b, b);
    }

    BigInt prime() const
    {
        return m_field.residu();
    }

private:
    void negate(AffinePoint& out, AffinePoint const& in) const;
    void _double(AffinePoint& out, AffinePoint const& in) const;
    void add(AffinePoint& out, AffinePoint const& p1, AffinePoint const& p2) const;

public:
    void scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const;

    void lift_x(AffinePoint& r1, AffinePoint& r2, BigInt inp_x) const;

    std::string to_string() const
    {
        return "EllipticCurve(Z_" + bigint_hex(m_field.residu())
            + ", y^2 = x^3 + " + bigint_hex(m_a) + "*x + " + bigint_hex(m_b) + ")";
    }

private:
    void sqrt(BigInt& s1, BigInt& s2, BigInt const& z) const;

    Element m_a;
    Element m_b;
    Zp m_field;
    std::string m_name;
};
