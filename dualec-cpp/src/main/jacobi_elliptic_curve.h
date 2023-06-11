#pragma once

#include "affine_point.h"
#include "forward.h"
#include "jacobi_point.h"
#include <optional>

/* Defined over Y^2 = X^3 + (-3)*X*Z^4 + b*Z^6 */
class JacobiEllipticCurve {
public:
    JacobiEllipticCurve(Zp field)
        : m_field(field)
    {
    }
    JacobiPoint scalar(JacobiPoint const& P, BigInt k) const;

private:
    JacobiPoint _double(JacobiPoint const& P) const;
    JacobiPoint add(JacobiPoint const& P, AffinePoint const& Q) const;
    Zp m_field;

    std::optional<BigInt> inv_of_2;
};
