#include "dualec.h"
#include <iostream>
#include <givaro/modular-integer.h>

typedef Givaro::Modular<Givaro::Integer> Zp;
typedef Zp::Element Element; // an element in Zp
int main() {
    auto ffield = Zp(123);
    Element element_mod_zp;
    ffield.init(element_mod_zp, 325);
    std::cout << "325 % 123 = 79, actual: " << element_mod_zp << std::endl;
    Element product;
    ffield.mul(product, element_mod_zp, Element(2));
    std::cout << "79 * 2 % 123 = 35, actual: " << product << std::endl;
}
