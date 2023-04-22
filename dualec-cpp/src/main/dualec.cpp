#include "dualec.h"
#include <iostream>
#include "affine_point.h"
#include "weierstrass_curve.h"

int main() {
    auto ffield = Zp(123);
    Element element_mod_zp;
    ffield.init(element_mod_zp, 325);
    std::cout << "325 % 123 = 79, actual: " << element_mod_zp << std::endl;
    Element product;
    ffield.mul(product, element_mod_zp, Element(2));
    std::cout << "79 * 2 % 123 = 35, actual: " << product << std::endl;


    auto point = AffinePoint(99, 59);
    std::cout << point.to_string() << std::endl;
    auto point2 = point;
    std::cout << std::to_string((point == point2)) << std::endl;

    auto weierstrass_curve = WeierstrassCurve(89, 552, 111);
    std::cout << weierstrass_curve.to_string() << std::endl;
}
