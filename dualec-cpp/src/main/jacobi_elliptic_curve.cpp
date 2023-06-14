#include "jacobi_elliptic_curve.h"
#include "affine_point.h"
#include <cstdlib>
#include <ios>
#include <sys/types.h>
JacobiPoint JacobiEllipticCurve::_double(JacobiPoint const& P) const
{
    if (P.is_identity())
        return JacobiPoint(m_field);

    Element T1, T2, T3, X3, Y3, Z3;
    // 2. T1 <- Z1^2
    m_field.mul(T1, P.z(), P.z());

    // 3. T2 <- X1 - T1
    m_field.sub(T2, P.x(), T1);

    // 4. T1 <- X1 + T1
    m_field.addin(T1, P.x());

    // 5. T2 <- T2 * T1
    m_field.mulin(T2, T1);

    // 6. T2 <- 3 * T2
    m_field.mulin(T2, 3);

    // 7. Y3 <- 2 * Y1
    m_field.mul(Y3, 2, P.y());

    // 8. Z3 <- Y3 * Z1
    m_field.mul(Z3, Y3, P.z());

    // 9. Y3 <- Y3^2
    {
        Element y3_sqr;
        m_field.mul(y3_sqr, Y3, Y3);
        Y3 = y3_sqr;
    }

    // 10. T3 <- Y3 * X1
    m_field.mul(T3, Y3, P.x());

    // 11. Y3 <- Y3^2
    {
        Element y3_sqr;
        m_field.mul(y3_sqr, Y3, Y3);
        Y3 = y3_sqr;
    }

    // 12. Y3 <- Y3 / 2
    if (!inv_of_2.has_value()) {
        Element i = 2;
        m_field.invin(i);
        const_cast<JacobiEllipticCurve*>(this)->inv_of_2.emplace(std::move(i));
    }
    m_field.mulin(Y3, inv_of_2.value());

    // 13. X3 <- T2^2
    m_field.mul(X3, T2, T2);

    // 14. T1 <- 2 * T3
    m_field.mul(T1, 2, T3);

    // 15. X3 <- X3 − T1
    m_field.subin(X3, T1);

    // 16. T1 <- T3 − X3
    m_field.sub(T1, T3, X3);

    // 17. T1 <- T1 * T2
    m_field.mulin(T1, T2);

    // 18. Y3 <- T1 − Y3
    m_field.negin(Y3);
    m_field.addin(Y3, T1);

    return JacobiPoint(X3, Y3, Z3, m_field);
}

JacobiPoint JacobiEllipticCurve::add(JacobiPoint const& P, AffinePoint const& Q) const
{
    if (Q.identity())
        return JacobiPoint(P);
    if (P.is_identity())
        return JacobiPoint(Q.x(), Q.y(), 1, m_field);

    Element T1, T2, T3, T4, X3, Y3, Z3;

    // 3. T1 <- Z1^2
    m_field.mul(T1, P.z(), P.z());

    // 4. T2 <- T1 * Z1
    m_field.mul(T2, T1, P.z());

    // 5. T1 <- T1 * x2
    m_field.mulin(T1, Q.x());

    // 6. T2 <- T2 * y2
    m_field.mulin(T2, Q.y());

    // 7. T1 <- T1 − X1
    m_field.subin(T1, P.x());

    // 8. T2 <- T2 − Y1
    m_field.subin(T2, P.y());

    // 9. If T1 = 0 then
    if (T1 == 0) {
        // 9.1 If T2 = 0
        if (T2 == 0) {
            // then use Algorithm 3.21 to compute (X3 : Y3 : Z3 ) = 2(x2 : y2 : 1) and return(X3 : Y3 : Z3 ).
            return _double(JacobiPoint(Q.x(), Q.y(), 1, m_field));
        } else {
            // else return Infinity.
            return JacobiPoint(m_field);
        }
    }

    // 10. Z3 <- Z1 * T1
    m_field.mul(Z3, P.z(), T1);

    // 11. T3 <- T1^2
    m_field.mul(T3, T1, T1);

    // 12. T4 <- T3 * T1
    m_field.mul(T4, T3, T1);

    // 13. T3 <- T3 * X1
    m_field.mulin(T3, P.x());

    // 14. T1 <- 2 * T3
    m_field.mul(T1, 2, T3);

    // 15. X3 <- T2^2
    m_field.mul(X3, T2, T2);

    // 16. X3 <- X3 − T1
    m_field.subin(X3, T1);

    // 17. X3 <- X3 − T4
    m_field.subin(X3, T4);

    // 18. T3 <- T3 − X3
    m_field.subin(T3, X3);

    // 19. T3 <- T3 * T2
    m_field.mulin(T3, T2);

    // 20. T4 <- T4 * Y1
    m_field.mulin(T4, P.y());

    // 21. Y3 <- T3 − T4
    m_field.sub(Y3, T3, T4);

    return JacobiPoint(X3, Y3, Z3, m_field);
}

void JacobiEllipticCurve::scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const
{
    auto tmp = JacobiPoint(m_field); // identity
    size_t n = k.bitsize();
    if (p.identity() || n < 1) {
        out = tmp.to_affine();
        return;
    }

    for (ssize_t i = n - 1; i >= 0; --i) {
        auto mask = BigInt(1) << i;
        tmp = _double(tmp);
        if (k.operator&(mask) != 0) {
            tmp = add(tmp, p);
        }
    }
    out = tmp.to_affine();
    return;
}
