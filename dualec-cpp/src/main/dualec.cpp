#include "dualec.h"
#include <iostream>
#include "affine_point.h"
#include "elliptic_curve.h"

int main() {
    auto ffield = Zp(123);
    Element element_mod_zp;
    ffield.init(element_mod_zp, 325);
    Element product;
    std::cout << "325 % 123 = 79, actual: " << element_mod_zp << std::endl;
    ffield.mul(product, element_mod_zp, Element(2));
    std::cout << "79 * 2 % 123 = 35, actual: " << product << std::endl;


    auto point = AffinePoint(99, 59);
    std::cout << point.to_string() << std::endl;
    auto point2 = point;
    std::cout << std::to_string((point == point2)) << std::endl;

    auto p256_p = BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    auto p256_a = BigInt(-3);
    auto p256_b = BigInt("41058363725152142129326129780047268409114441015993725554835256314039467401291");

    auto elliptic_curve = EllipticCurve(p256_p, p256_a, p256_b);
    std::cout << elliptic_curve.to_string() << std::endl;

    AffinePoint tmp;
    elliptic_curve._double(tmp, point);

    std::cout << tmp.to_string() << std::endl;

    AffinePoint G(BigInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"), BigInt("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
    elliptic_curve.scalar(tmp, G, 3);

    std::cout << tmp.to_string() << std::endl;
}
