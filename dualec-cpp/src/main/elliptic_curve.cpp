#include "elliptic_curve.h"

void EllipticCurve::sqrt(BigInt& s1, BigInt& s2, BigInt const& z) const
{
    // ASSUMES Givaro::legendre(z, m_field.residu()) == 1
    auto abx = Givaro::IntSqrtModDom<>();
    abx.sqrootmod(s1, z, m_field.residu());
    m_field.sub(s2, m_field.zero, s1);
}

void EllipticCurve::lift_x(AffinePoint& r1, AffinePoint& r2, BigInt inp_x) const
{
    BigInt x;
    m_field.init(x, inp_x);
    // x^3 + a*x + b (mod p)
    BigInt xxx = x;
    m_field.mulin(xxx, x);
    m_field.mulin(xxx, x);
    BigInt ax;
    m_field.mul(ax, m_a, x);

    m_field.addin(xxx, ax);
    m_field.addin(xxx, m_b);
    if (!Givaro::isOne(Givaro::legendre(xxx, m_field.residu()))) {
        r1 = r2 = AffinePoint();
        return;
    }
    BigInt y1, y2;
    sqrt(y1, y2, xxx);
    r1 = AffinePoint(x, y1);
    r2 = AffinePoint(x, y2);
}

void EllipticCurve::scalar(AffinePoint& out, AffinePoint const& p, BigInt k) const
{
    out.setIdentity(true);
    if (p.identity()) {
        return;
    }
    AffinePoint tmp1, tmp2;
    AffinePoint _2p = p;
    while (k > 0) {
        if (k.operator&(static_cast<size_t>(0b1)) == 1) {
            add(tmp1, out, _2p);
            out = tmp1; // out = out + pp
        }

        _double(tmp2, _2p);
        _2p = tmp2; // pp = 2*pp
        k >>= 1;    // k = k / 2
    }
}

void EllipticCurve::add(AffinePoint& out, AffinePoint const& p1, AffinePoint const& p2) const
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
        negate(tmp1, p1);

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

void EllipticCurve::negate(AffinePoint& out, AffinePoint const& in) const
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

void EllipticCurve::_double(AffinePoint& out, AffinePoint const& in) const
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
