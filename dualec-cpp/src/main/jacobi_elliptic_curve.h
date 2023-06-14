#pragma once

#include "affine_point.h"
#include "elliptic_curve.h"
#include "forward.h"
#include "jacobi_point.h"
#include <optional>

/* Defined over Y^2 = X^3 + (-3)*X*Z^4 + b*Z^6 */
class JacobiEllipticCurve : public EllipticCurve {
public:
    JacobiEllipticCurve(std::string const& name, BigInt const& prime, BigInt const& b)
        : EllipticCurve(name,
            prime,
            BigInt("-3"),
            b)
    {
    }
    virtual void scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const override;

    virtual std::string to_string() const override
    {
        return "Jacobi" + EllipticCurve::to_string();
    }

private:
    JacobiPoint _double(JacobiPoint const& P) const;
    JacobiPoint add(JacobiPoint const& P, AffinePoint const& Q) const;

    std::optional<BigInt> inv_of_2;
};
