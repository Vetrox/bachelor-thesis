#pragma once
#include "forward.h"


// y^2 = x^3 + a*x + b
// defined over field Z_p
class WeierstrassCurve {
public:
    WeierstrassCurve(BigInt prime, BigInt a, BigInt b)
        : m_field(prime)
    {
        m_field.init(m_a, a);
        m_field.init(m_b, b);
    }

    std::string to_string() {
       return "WeierstrassCurve(Z_" + std::string(m_field.residu())
           + ", y^2 = x^3 + " + std::string(m_a) + "*x + " + std::string(m_b) + ")";
    }
private:
    Element m_a;
    Element m_b;
    Zp m_field;
};
