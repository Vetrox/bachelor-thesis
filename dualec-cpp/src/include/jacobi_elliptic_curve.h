#pragma once

#include "affine_point.h"
#include "elliptic_curve.h"
#include "forward.h"
#include "jacobi_point.h"
#include <optional>

/* Defined over Y^2 = X^3 + (-3)*X*Z^4 + b*Z^6 */
class JacobiEllipticCurve : public EllipticCurve {
public:
    JacobiEllipticCurve(BigInt const& prime, BigInt const& b)
        : EllipticCurve(prime, BigInt("-3"), b)
    {
    }
    virtual void scalar(JacobiPoint& out, AffinePoint const& p, BigInt k) const override;
    virtual void scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const override
    {
        auto o = JacobiPoint(m_field);
        scalar(o, p, std::move(k));
        out = AffinePoint(o.x(), o.y());
    }


    virtual std::string to_string(size_t indent_level = 0) const override
    {
        return "Jacobi" + EllipticCurve::to_string(indent_level);
    }

    JacobiPoint _double(JacobiPoint const& P) const;
    JacobiPoint add(JacobiPoint const& P, AffinePoint const& Q) const;

private:
    std::optional<BigInt> inv_of_2;
};
