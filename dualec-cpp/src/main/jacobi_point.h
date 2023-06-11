#pragma once

#include "affine_point.h"
#include "forward.h"

class JacobiPoint {
public:
    JacobiPoint(Element const& x, Element const& y, Element const& z, Zp field)
        : m_field(field)
    {
        m_field.init(m_X, x);
        m_field.init(m_Y, y);
        m_field.init(m_Z, z);
    }

    JacobiPoint(Element const& x, Element const& y, Zp field)
        : JacobiPoint(x, y, 1, field)
    {
    }
    void negate()
    {
        m_field.negin(m_Y);
    }

    AffinePoint to_affine()
    {
        if (m_Z == 0)
            return AffinePoint();

        Element z_tmp;
        m_field.mul(z_tmp, m_Z, m_Z);

        Element res_x;
        m_field.div(res_x, m_X, z_tmp);

        Element res_y;
        m_field.mulin(z_tmp, m_Z);
        m_field.div(res_y, m_Y, z_tmp);

        return AffinePoint(res_x, res_y);
    }

private:
    /* c = 2, d = 3. a (in the elliptic curve) = -3 */
    Element m_X;
    Element m_Y;
    Element m_Z;

    Zp m_field;
};
