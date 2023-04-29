#pragma once
#include "affine_point.h"
#include "forward.h"

// y^2 = x^3 + a*x + b
// defined over field Z_p
class EllipticCurve {
public:
    EllipticCurve(BigInt prime, BigInt n, BigInt a, BigInt b)
        : m_field(prime)
    {
        (void)n; // the order of the elliptic curve group, e.g. the base Point G
        m_field.init(m_a, a);
        m_field.init(m_b, b);
    }

    void inv(AffinePoint& out, AffinePoint const& in) const
    {
        if (in.identity()) {
            out.setIdentity(true);
            return;
        }
        out.setIdentity(false);
        out.setX(in.x());
        Element tmp;
        m_field.sub(tmp, m_field.zero, in.y());
        out.setY(tmp);
    }

    void _double(AffinePoint& out, AffinePoint const& in) const
    {
        if (in.identity()) {
            out.setIdentity(true);
            return;
        }
        out.setIdentity(false);
        Element tmp_element;
        Element _3x_sq;                      // 3 * x^2
        m_field.mul(_3x_sq, in.x(), in.x()); // x^2
        m_field.init(tmp_element, 3);
        m_field.mulin(_3x_sq, tmp_element);

        Element _2y; // 2 * y
        m_field.init(tmp_element, 2);
        m_field.mul(_2y, tmp_element, in.y());

        Element slope; // l = (3 * x^2 + a) / (2 * y)
        m_field.add(tmp_element, _3x_sq, m_a);
        m_field.div(slope, tmp_element, _2y);

        Element slope_sq; // l^2
        m_field.mul(slope_sq, slope, slope);

        Element _2x; // x+x
        m_field.add(_2x, in.x(), in.x());

        Element out_x; // l^2 - x - x
        m_field.sub(out_x, slope_sq, _2x);

        Element out_y;
        m_field.sub(tmp_element, in.x(), out_x); // x - out_x
        m_field.mulin(tmp_element, slope);       // l * (x - out_x)
        m_field.sub(out_y, tmp_element, in.y()); // l * (x - out_x) - y

        out.setX(out_x);
        out.setY(out_y);
    }

    void add(AffinePoint& out, AffinePoint const& p1, AffinePoint const& p2) const
    {
        if (p1.identity() && p2.identity()) {
            out.setIdentity(true);
            return;
        }

        if (p1.identity()) {
            out = p2;
            return;
        }

        if (p2.identity()) {
            out = p1;
            return;
        }

        {
            AffinePoint tmp1;
            inv(tmp1, p1);

            if (tmp1 == p2) {
                out.setIdentity(true);
                return;
            }
        }

        if (p1 == p2)
            return _double(out, p1);

        out.setIdentity(false);
        Element tmp;
        Element num; // y2 - y1
        m_field.sub(num, p2.y(), p1.y());

        Element den; // x2 - x1
        m_field.sub(den, p2.x(), p1.x());

        Element slope; // l = (y2-y1) / (x2-x1)
        m_field.div(slope, num, den);

        Element slope_sq; // l^2
        m_field.mul(slope_sq, slope, slope);

        Element out_x; // out_x = l^2 - (x1 + x2)
        m_field.add(tmp, p1.x(), p2.x());
        m_field.sub(out_x, slope_sq, tmp);

        Element sub_x1_out_x; // x1 - out_x
        m_field.sub(sub_x1_out_x, p1.x(), out_x);

        Element out_y;                         // out_y = l * (x1 - out_x) - y1
        m_field.mul(tmp, slope, sub_x1_out_x); // l * (x1 - out_x)
        m_field.sub(out_y, tmp, p1.y());

        out.setX(out_x);
        out.setY(out_y);
    }

    void scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const
    {
        out.setIdentity(true);
        if (p.identity()) {
            return;
        }
        AffinePoint tmp1, tmp2;
        AffinePoint pp = p;
        while (k > 0) {
            if (k % 2 == 1) {
                add(tmp1, out, pp);
                out = tmp1; // out = out + pp
            }

            _double(tmp2, pp);
            pp = tmp2; // pp = 2*pp
            k >>= 1;   // k = k / 2
        }
    }

    std::string to_string() const
    {
        return "EllipticCurve(Z_" + bigint_hex(m_field.residu())
            + ", y^2 = x^3 + " + bigint_hex(m_a) + "*x + " + bigint_hex(m_b) + ")";
    }

private:
    Element m_a;
    Element m_b;
    Zp m_field;
};
