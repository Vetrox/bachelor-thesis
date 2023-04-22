#pragma once
#include "forward.h"
#include "affine_point.h"

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

    void inv(AffinePoint& out, AffinePoint const& in) {
        if (in.identity()) {
            out.setIdentity(true);
            return;
        }
        out.setIdentity(false);
        out.setX(in.x());
        Element tmp;
        m_field.sub(tmp, m_field.zero, in.y());
        out.setX(tmp);
    }

    void _double(AffinePoint& out, AffinePoint const& in) {
        AffinePoint tmp_point;
        inv(tmp_point, in);
        if (in.identity() || tmp_point == in) {
            out.setIdentity(true);
            return;
        }
        out.setIdentity(false);
        Element tmp_element;
        Element xs;
        m_field.mul(xs, in.x(), in.x()); // x^2
        m_field.init(tmp_element, 3);
        m_field.mulin(xs, tmp_element);

        Element ty; // y*2
        m_field.init(tmp_element, 2);
        m_field.mul(ty, tmp_element, in.y());

        Element slope; // m
        m_field.add(tmp_element, xs, m_a);
        m_field.div(slope, tmp_element, ty);

        Element slope2; // m^2
        m_field.mul(slope2, slope, slope);

        Element xpx; // 2*x
        m_field.add(xpx, in.x(), in.x());

        Element out_x;
        m_field.sub(out_x, slope2, xpx);

        Element out_y;
        m_field.sub(tmp_element, in.x(), out_x);
        m_field.sub(out_y, m_field.mulin(tmp_element, slope), in.y());

        out.setX(out_x);
        out.setY(out_y);
    }

    void add(AffinePoint& out, AffinePoint const& p1, AffinePoint const& p2) {
        AffinePoint tmp1, tmp2;
        inv(tmp1, p1);
        inv(tmp2, p2);

        if ((p1.identity() && p2.identity()) || (tmp1 == p2) || (tmp2 == p1)) {
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

        if (p1 == p2)
            return _double(out, p1);

        out.setIdentity(false);
	    Element tmp;
        Element num; // y2 - y1
        m_field.sub(num, p2.y(), p1.y());

        Element den; // x2 - x1
        m_field.sub(den, p2.x(), p1.x());

        Element slope; // m
        m_field.div(slope, num, den);

        Element slope2; // m^2
        m_field.mul(slope2, slope, slope);

        Element x3; // x_3
        m_field.sub(x3, slope2, m_field.add(tmp, p2.x(), p1.x()));

        Element diffx3; // x_1 - x_3
        m_field.sub(diffx3, p1.x(), x3);

        Element y3; // y_3
        m_field.mul(tmp, slope, diffx3);
        m_field.sub(y3, tmp, p1.y());
        out.setX(x3);
        out.setY(y3);
    }

    void scalar(AffinePoint& out, AffinePoint const& p, BigInt k) {
        out.setIdentity(true);
        if (p.identity()) {
            return;
        }
        AffinePoint tmp1, tmp2;
        AffinePoint pp = p;
        while(k > 0) {
            if (k % 2 == 1) {
                add(tmp1, out, pp);
                out = tmp1; // out = out + pp
            }

            _double(tmp2, pp);
            pp = tmp2; // pp = 2*pp
            k >>= 1; // k = k / 2
        }
    }

    std::string to_string() {
       return "EllipticCurve(Z_" + std::string(m_field.residu())
           + ", y^2 = x^3 + " + std::string(m_a) + "*x + " + std::string(m_b) + ")";
    }
private:
    Element m_a;
    Element m_b;
    Zp m_field;
};
