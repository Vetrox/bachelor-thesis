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
    EllipticCurve(BigInt prime, BigInt a, BigInt b)
        : m_field(prime)
    {
        m_field.init(m_a, a);
        m_field.init(m_b, b);
    }

    BigInt prime() const
    {
        return m_field.residu();
    }

    void negate(AffinePoint& out, AffinePoint const& in) const;
    void _double(AffinePoint& out, AffinePoint const& in) const;
    void add(AffinePoint& out, AffinePoint const& p1, AffinePoint const& p2) const;
    virtual void scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const;

    void lift_x(AffinePoint& r1, AffinePoint& r2, BigInt inp_x) const;

    virtual std::string to_string(size_t indent_level = 0) const
    {
        std::string indent = std::string(" ", indent_level);
        return "EllipticCurve(\n" + indent
            + " prime: " + bigint_hex(m_field.residu()) + "\n" + indent
            + " y^2 = x^3 + " + bigint_hex(m_a) + "*x + " + bigint_hex(m_b) + ")";
    }

protected:
    Zp m_field;

private:
    void sqrt(BigInt& s1, BigInt& s2, BigInt const& z) const;

    Element m_a;
    Element m_b;
};
